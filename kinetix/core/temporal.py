import ipaddress
import random
import logging
import uuid
from datetime import datetime, timedelta
from typing import Optional, Dict
from kinetix.schemas.base import BaseLogEvent
from kinetix.schemas.temporal import TimingProfile, MarkovTransition

logger = logging.getLogger(__name__)


# The site's own address space. Anything outside it is egress and crosses the
# perimeter. Deliberately not ipaddress.is_private/is_global: both classify the
# TEST-NET documentation ranges (203.0.113.0/24, 198.51.100.0/24) that the
# scenarios use to stand in for internet hosts as private, which would route
# every flow back to the internal appliance.
_INTERNAL_NETS = tuple(ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
    "127.0.0.0/8", "169.254.0.0/16", "fc00::/7", "::1/128",
))


def _is_internal(ip: Optional[str]) -> bool:
    """True when the address is inside the site (or unknown)."""
    if not ip:
        return True
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return any(addr in net for net in _INTERNAL_NETS if net.version == addr.version)


def _appliance_for(source_ip: Optional[str], dest_ip: Optional[str]) -> str:
    """Pick the appliance a flow crosses from the endpoints it connects.

    A perimeter ASA sees anything with one foot outside the site — egress to
    the internet and inbound scanning alike; east-west traffic never leaves
    the internal FortiGates. Routing on topology keeps both vendor feeds
    populated without a magic ratio, and matches what each appliance would
    really have logged. A flow whose endpoints are unknown has not been shown
    to leave the site, so it stays internal.
    """
    if _is_internal(source_ip) and _is_internal(dest_ip):
        return "fortigate"
    return "cisco"

class TemporalEngine:
    def __init__(self, profile: Optional[TimingProfile] = None):
        self.profile = profile or TimingProfile()
        self.transitions: Dict[str, Dict[str, float]] = {}
        self._set_default_transitions()

    def _set_default_transitions(self):
        self.add_transitions([
            MarkovTransition(
                current_event="SigninLogs",
                next_event_probabilities={"DeviceProcessEvents": 0.5, "OfficeActivity": 0.3, "AzureActivity": 0.1}
            ),
            MarkovTransition(
                current_event="DeviceProcessEvents",
                next_event_probabilities={"CommonSecurityLog": 0.35, "DeviceFileEvents": 0.3, "DnsEvents": 0.15}
            ),
            MarkovTransition(
                current_event="DeviceFileEvents",
                next_event_probabilities={"CommonSecurityLog": 0.2, "DeviceRegistryEvents": 0.2, "DeviceProcessEvents": 0.1}
            ),
            MarkovTransition(
                current_event="OfficeActivity",
                next_event_probabilities={"SigninLogs": 0.2, "DeviceProcessEvents": 0.15}
            ),
            MarkovTransition(
                current_event="CommonSecurityLog",
                next_event_probabilities={"DeviceProcessEvents": 0.3, "DnsEvents": 0.2}
            ),
            MarkovTransition(
                current_event="AzureActivity",
                next_event_probabilities={"SigninLogs": 0.3, "CloudAppEvents": 0.2}
            ),
        ])

    def add_transitions(self, transitions: list[MarkovTransition]):
        for t in transitions:
            self.transitions[t.current_event] = t.next_event_probabilities

    def calculate_delay(self, current_time: datetime) -> float:
        """
        Calculate next delay based on Gaussian distribution and Time-of-Day profile.
        """
        # 1. Base Delay
        base = self.profile.avg_delay_seconds

        # Events are UTC-stamped; working_hours_* describe the simulated
        # organisation's local clock, so shift before shaping. Both the
        # time-of-day and day-of-week tests must read the same frame,
        # otherwise a local Friday evening counts as a UTC Saturday.
        offset = self.profile.business_utc_offset_hours
        local_time = current_time + timedelta(hours=offset) if offset else current_time

        # 2. Time-of-Day Multiplier
        hour = local_time.hour
        if not (self.profile.working_hours_start <= hour < self.profile.working_hours_end):
            # Outside working hours
            base = base / self.profile.after_hours_multiplier

        # 2b. Day-of-Week Multiplier (Sat=5, Sun=6)
        if self.profile.weekend_shaping and local_time.weekday() >= 5:
            base = base / self.profile.weekend_multiplier

        # 3. Gaussian Jitter
        # Mean = base, StdDev = base * jitter_percent
        std_dev = base * self.profile.jitter_percent
        delay = random.gauss(base, std_dev)
        
        # Ensure we don't return negative or extreme delays
        return max(0.01, delay)

    def get_next_event_type(self, current_event_type: str) -> Optional[str]:
        """
        Predict next event type using Markov probabilities.
        """
        if current_event_type not in self.transitions:
            return None
            
        probs = self.transitions[current_event_type]
        choices = list(probs.keys())
        weights = list(probs.values())
        
        return random.choices(choices, weights=weights, k=1)[0]

    def create_follow_up(self, parent_event: 'BaseLogEvent', next_type: str) -> Optional['BaseLogEvent']:
        """
        Creates a new event based on the parent's context.
        This is a basic factory approach for Phase 2.
        """
        from kinetix.schemas.endpoint import ProcessEvent, FileEvent, RegistryEvent
        from kinetix.schemas.network import FirewallEvent, DNSEvent
        from kinetix.schemas.cloud_auth import AuthenticationEvent, CloudActivityEvent, O365ActivityEvent
        from kinetix.schemas.cloud_app import CloudAppEvent
        
        # Clone base context
        context = {
            "correlation_id": parent_event.correlation_id,
            "user_name": parent_event.user_name,
            "hostname": parent_event.hostname,
            "source_ip": parent_event.source_ip,
            "dest_ip": parent_event.dest_ip,
            "severity": parent_event.severity,
            "is_malicious": parent_event.is_malicious,
            "scenario_id": parent_event.scenario_id,
            "killchain_phase": parent_event.killchain_phase,
        }
        
        try:
            if next_type == "DeviceProcessEvents":
                return ProcessEvent(
                    **context,
                    action_type="ProcessCreated",
                    file_name="cmd.exe",
                    folder_path="C:\\Windows\\System32",
                    process_id=random.randint(1000, 9999),
                    command_line="cmd.exe /c echo 'Follow-up action verified'",
                    parent_process_name=parent_event.file_name if hasattr(parent_event, "file_name") else "explorer.exe",
                    integrity_level="Medium"
                )
            elif next_type == "CommonSecurityLog":
                return FirewallEvent(
                    **context,
                    vendor=_appliance_for(context["source_ip"], context["dest_ip"]),
                    action="allowed",
                    protocol="TCP",
                    source_port=random.randint(49152, 65535),
                    dest_port=80 if not context["dest_ip"] else 443
                )
            elif next_type == "DeviceFileEvents":
                return FileEvent(
                    **context,
                    action_type="FileModified",
                    file_name="config.ini",
                    folder_path="C:\\Users\\Public",
                    sha1="a94a8fe5ccb19ba61c4c0873d391e987982fbbd3"
                )
            elif next_type == "DeviceRegistryEvents":
                return RegistryEvent(
                    **context,
                    action_type="RegistryValueSet",
                    key_path="HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                    value_name="Updater",
                    value_data="C:\\Users\\Public\\updater.exe"
                )
            elif next_type == "DnsEvents":
                return DNSEvent(
                    **context,
                    query_name="update.microsoft.com",
                    query_type="A",
                )
            elif next_type == "SigninLogs":
                # AuthenticationEvent.user_principal_name accepts "user_name" via
                # AliasChoices, and that alias is checked before "user_principal_name"
                # itself -- so a None in context["user_name"] would win over an
                # explicit user_principal_name= kwarg. Override it in the context
                # copy instead of adding a separate kwarg.
                signin_context = {**context, "user_name": context["user_name"] or "unknown@corp.local"}
                return AuthenticationEvent(
                    **signin_context,
                    app_display_name="Office 365",
                    client_app_used="Browser",
                    result_type="0",
                )
            elif next_type == "OfficeActivity":
                return O365ActivityEvent(
                    **context,
                    workload="Exchange",
                    operation="MailItemsAccessed",
                    item_type="Message",
                    user_key=context["user_name"] or "unknown@corp.local",
                    client_ip=context["source_ip"] or "127.0.0.1",
                )
            elif next_type == "AzureActivity":
                return CloudActivityEvent(
                    **context,
                    operation_name="Microsoft.Resources/subscriptions/resourceGroups/read",
                    resource_id=f"/subscriptions/{uuid.uuid4()}/resourceGroups/default",
                    caller=context["user_name"] or "unknown@corp.local",
                )
            elif next_type == "CloudAppEvents":
                return CloudAppEvent(
                    **context,
                    app_name="Microsoft Office 365",
                    activity_type="FileAccessed",
                    action_type="FileAccessed",
                )
        except Exception as e:
            logger.error(f"Failed to create follow-up event of type {next_type}: {e}")
            
        return None
