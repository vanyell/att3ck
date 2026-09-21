from typing import Optional, List, Dict, Any, Tuple
import html
from pydantic import BaseModel, Field
from datetime import datetime, timezone
import uuid

# RFC 3164 syslog helpers
_SYSLOG_FACILITY = {"kern": 0, "user": 1, "mail": 2, "daemon": 3, "auth": 4, "syslog": 5, "authpriv": 10, "cron": 9}
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

def format_syslog(priority: int, dt: datetime, hostname: str, proc: str, pid: int, msg: str) -> str:
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
            f"<Channel>{html.escape(channel)}</Channel>"
            f"<Computer>{html.escape(computer)}</Computer>"
            f"<Security/></System>"
            f"<EventData>{data_xml}</EventData></Event>")

# H2: Workspace-level TenantId — same for all events in a session
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

    class Config:
        populate_by_name = True
