from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime, timezone
import uuid

# H2: Workspace-level TenantId — same for all events in a session
_WORKSPACE_TENANT_ID = str(uuid.uuid4())

class MitreMapping(BaseModel):
    tactic: str
    technique_id: str  # e.g., T1486
    technique_name: str

class D3fendMapping(BaseModel):
    id: str  # e.g., d3f:FileAnalysis
    description: str

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
    
    # Dynamic Data
    data: Dict[str, Any] = Field(default_factory=dict, alias="ExtendedProperties")
    
    # Metadata for the generator
    is_malicious: bool = False
    scenario_id: str = "default"
    depth: int = 0  # To prevent infinite Markov loops

    class Config:
        populate_by_name = True
        json_encoders = {
            datetime: lambda dt: dt.isoformat()
        }
