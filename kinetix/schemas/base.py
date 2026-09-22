from typing import Optional, List, Dict, Any, Tuple
import html
from pydantic import BaseModel, Field
from datetime import datetime, timezone
import uuid
import itertools
import shlex

# RFC 3164 syslog helpers
_SYSLOG_FACILITY = {"kern": 0, "user": 1, "mail": 2, "daemon": 3, "auth": 4, "syslog": 5, "authpriv": 10, "cron": 9,
                    # Network appliances log to the local facilities; FortiOS and
                    # Cisco ASA both default to local7.
                    "local0": 16, "local1": 17, "local2": 18, "local3": 19,
                    "local4": 20, "local5": 21, "local6": 22, "local7": 23}
_SYSLOG_SEVERITY = {"emerg": 0, "alert": 1, "crit": 2, "err": 3, "warning": 4, "notice": 5, "info": 6, "debug": 7}

# Kinetix's own severity vocabulary (used in scenario JSON and BaseLogEvent.severity)
# mapped onto the RFC 3164 severity keywords above, so a scenario's "critical"/"high"/
# "medium"/"low"/"informational" (any casing) actually affects PRI/EVT level output
# instead of silently falling back to "info" for everything.
_APP_SEVERITY_TO_SYSLOG = {
    "critical": "crit",
    "high": "err",
    "medium": "warning",
    "low": "notice",
    "informational": "info",
}

def normalize_severity(severity: str) -> str:
    """Map any Kinetix severity string onto an RFC 3164 severity keyword."""
    key = (severity or "info").strip().lower()
    if key in _SYSLOG_SEVERITY:
        return key
    return _APP_SEVERITY_TO_SYSLOG.get(key, "info")

def syslog_priority(facility: str = "user", severity: str = "info") -> int:
    return _SYSLOG_FACILITY.get(facility, 1) * 8 + _SYSLOG_SEVERITY.get(normalize_severity(severity), 6)

def syslog_timestamp(dt: Optional[datetime] = None) -> str:
    if dt is None:
        dt = datetime.now(timezone.utc)
    return dt.strftime("%b %d %H:%M:%S")

# Wire format for every to_syslog() implementation. RFC 3164 stays the default
# because Wazuh's built-in decoders are written against it, but its timestamp
# carries no year, so a backdated window (--sim-start in a prior year) is
# silently re-dated to the ingest year by the collector. RFC 5424 timestamps
# are full ISO 8601 and survive that. Set once at startup via main().
_SYSLOG_FORMAT = "rfc3164"


def set_syslog_format(fmt: str) -> None:
    global _SYSLOG_FORMAT
    if fmt not in ("rfc3164", "rfc5424"):
        raise ValueError(f"Unsupported syslog format: {fmt}")
    _SYSLOG_FORMAT = fmt


def format_syslog(priority: int, dt: datetime, hostname: str, proc: str, pid: int, msg: str) -> str:
    if _SYSLOG_FORMAT == "rfc5424":
        # <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
        ts = (dt or datetime.now(timezone.utc)).isoformat()
        return f"<{priority}>1 {ts} {hostname} {proc} {pid} - - {msg}"
    return f"<{priority}>{syslog_timestamp(dt)} {hostname} {proc}[{pid}]: {msg}"

# Windows Event Log helpers
_WIN_EVENT_SEVERITY = {"emerg": 1, "alert": 1, "crit": 2, "err": 2, "warning": 3, "notice": 4, "info": 4, "debug": 5}

def evt_level(severity: str = "info") -> int:
    return _WIN_EVENT_SEVERITY.get(normalize_severity(severity), 4)

# CEF requires an integer 0-10 Severity field (not a free-text keyword)
_APP_SEVERITY_TO_CEF = {
    "critical": 10, "crit": 10, "emerg": 10, "alert": 10,
    "high": 8, "err": 8,
    "medium": 5, "warning": 5, "notice": 5,
    "low": 3,
    "informational": 1, "info": 1, "debug": 0,
}

def cef_severity(severity: str) -> int:
    """Map a Kinetix severity string onto the CEF-mandated integer 0-10 scale."""
    return _APP_SEVERITY_TO_CEF.get((severity or "info").strip().lower(), 1)

def format_evt_xml(event_id: int, provider: str, channel: str, computer: str,
                   timestamp: datetime, level: int, event_data: List[Tuple[str, str]]) -> str:
    """Build a compact single-line Windows Event XML string."""
    time_str = timestamp.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    data_xml = "".join(f"<Data Name='{html.escape(k)}'>{html.escape(v)}</Data>"
                       for k, v in event_data if v is not None)
    return (f"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
            f"<System><Provider Name='{html.escape(provider)}'/>"
            f"<EventID>{event_id}</EventID><Version>0</Version><Level>{level}</Level>"
            f"<TimeCreated SystemTime='{time_str}'/>"
            f"<Channel>{html.escape(channel)}</Channel>"
            f"<Computer>{html.escape(computer)}</Computer>"
            f"<Security/></System>"
            f"<EventData>{data_xml}</EventData></Event>")

# H2: Workspace-level TenantId — same for all events in a session
# --- auditd wire format -------------------------------------------------
# Wazuh 5.0's auditd decoder (decoder/auditd/0) gates on:
#   starts_with($event.original, "node=") OR starts_with($event.original, "type=")
# A line failing that gate is silently discarded by the manager, so every
# auditd record Kinetix emits must lead with `type=`.
_AUDIT_SERIAL = itertools.count(1)


def next_audit_serial() -> int:
    """Monotonic audit event serial. next() on itertools.count is atomic in
    CPython, which matters because LogWorkers emit concurrently."""
    return next(_AUDIT_SERIAL)


def format_auditd(record_type: str, dt: datetime, serial: int, fields: str) -> str:
    """One auditd record: `type=X msg=audit(<epoch>.<ms>:<serial>): <fields>`.

    The timestamp comes from the event, not wall clock, so --sim-clock
    backdating carries through to the feed.
    """
    return f"type={record_type} msg=audit({dt.timestamp():.3f}:{serial}): {fields}"


def audit_hex(value: str) -> str:
    """Real auditd hex-encodes command strings containing whitespace."""
    return value.encode("utf-8").hex()


_WORKSPACE_TENANT_ID = str(uuid.uuid4())

class MitreMapping(BaseModel):
    tactic: str
    technique_id: str  # e.g., T1486
    technique_name: str

class D3fendMapping(BaseModel):
    id: str  # e.g., d3f:FileAnalysis
    description: str

class AtlasMapping(BaseModel):
    id: str  # e.g., AML.T0051.001 (MITRE ATLAS technique/sub-technique ID)
    name: str

class BaseLogEvent(BaseModel):
    """
    Internal representation of a log event before formatting.
    This is what flows through the producer-consumer queue.
    """
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()), alias="Id")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), alias="TimeGenerated")
    source: str = Field(..., alias="SourceSystem")  # e.g., "endpoint", "firewall"
    event_type: str = Field(..., alias="Type")  # e.g., "process_creation", "network_connection"
    severity: str = Field("informational", alias="AlertSeverity")
    
    # H2: Common Sentinel Metadata — singleton per workspace
    tenant_id: str = Field(default=_WORKSPACE_TENANT_ID, alias="TenantId")
    
    # Universal Investigation Anchors (Essential for Pivot)
    correlation_id: str = Field(default_factory=lambda: str(uuid.uuid4()), alias="CorrelationId")
    
    # Device context
    os_platform: str = Field("Windows", alias="OSPlatform")
    device_category: str = Field("Workstation", alias="DeviceCategory")
    is_managed: bool = Field(True, alias="IsManaged")
    
    # User context
    user_name: Optional[str] = Field(None, alias="AccountName")
    user_sid: Optional[str] = Field(None, alias="AccountSid")
    
    # Source / Destination Context
    hostname: Optional[str] = Field(None, alias="DeviceName")
    source_ip: Optional[str] = Field(None, alias="IPAddress")
    dest_ip: Optional[str] = Field(None, alias="DestinationIP")
    
    # Framework Mapping
    mitre: Optional[MitreMapping] = None
    d3fend: Optional[D3fendMapping] = None
    atlas: Optional[AtlasMapping] = None  # MITRE ATLAS (AI/ML-specific TTPs); complements mitre for AI-native techniques
    
    # Dynamic Data
    data: Dict[str, Any] = Field(default_factory=dict, alias="ExtendedProperties")
    
    # Metadata for the generator
    is_malicious: bool = False
    scenario_id: str = "default"
    depth: int = 0  # To prevent infinite Markov loops
    killchain_phase: str = ""  # e.g. "reconnaissance", "initial-access", "execution", "persistence", "exfiltration", "impact"

    def to_syslog(self) -> str:
        """RFC 3164 syslog representation. Override in subclasses for fidelity."""
        prio = syslog_priority("user", "info")
        return format_syslog(prio, self.timestamp, self.hostname or "-",
                             self.source, 0, f"{self.event_type}: severity={self.severity}")

    def to_evt(self) -> str:
        """Windows Event Log XML representation. Override in subclasses for fidelity."""
        return format_evt_xml(0, self.source, self.source, self.hostname or "-",
                              self.timestamp, evt_level(self.severity),
                              [("Type", self.event_type), ("Severity", self.severity)])

    def to_vendor_feeds(self) -> List[Tuple[str, str]]:
        """(feed filename, line) pairs in vendor-native wire formats.

        Wazuh 5.0 only indexes what an enabled integration claims, and the
        Sentinel-shaped JSON feeds are claimed by nothing. Emitting the format
        the real appliance emits — FortiOS key=value, Cisco's %ASA- syslog,
        Okta's System Log JSON — lets the shipped vendor decoders do the work,
        with correct provenance rather than telemetry disguised as some other
        product's.

        Self-gating like to_auditd(): an event with no vendor equivalent
        returns [], so the feeds skip it and there is no source list to keep
        in sync. One event can yield several pairs, but never two flavours of
        the same device — a session came off one appliance.
        """
        return []

    def to_auditd(self) -> List[str]:
        """Linux auditd records for this event, one string per line.

        Empty list means the event has no auditd equivalent (the default for
        every non-Linux source), and the auditd feed skips it entirely. Linux
        subclasses override. Returning a list rather than a str is what lets a
        single event emit a SYSCALL/EXECVE pair under one serial, as auditd does.
        """
        return []

    class Config:
        populate_by_name = True
