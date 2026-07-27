import random
import math
import logging
from datetime import datetime
from typing import Optional, Dict
from kinetix.schemas.base import BaseLogEvent
from kinetix.schemas.temporal import TimingProfile, MarkovTransition

logger = logging.getLogger(__name__)

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
        
        # 2. Time-of-Day Multiplier
        hour = current_time.hour
        if not (self.profile.working_hours_start <= hour < self.profile.working_hours_end):
            # Outside working hours
            base = base / self.profile.after_hours_multiplier
            
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
        from kinetix.schemas.network import FirewallEvent
        from kinetix.schemas.cloud_auth import AuthenticationEvent
        
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
                    action="allowed",
                    protocol="TCP",
                    source_port=random.randint(49152, 65535),
                    dest_port=443 if not context["dest_ip"] else 80
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
        except Exception as e:
            logger.error(f"Failed to create follow-up event of type {next_type}: {e}")
            
        return None
