from typing import Optional, List, Dict, Any, Literal
from pydantic import Field
from kinetix.schemas.base import BaseLogEvent
from datetime import datetime, timezone
import uuid

class SecurityAlert(BaseLogEvent):
    source: Literal["SecurityInsights"] = Field("SecurityInsights", alias="SourceSystem")
    event_type: Literal["SecurityAlert"] = Field("SecurityAlert", alias="Type")
    
    alert_name: str = Field(..., alias="AlertName")
    alert_type: str = Field("MaliciousActivity", alias="AlertType")
    description: Optional[str] = Field(None, alias="Description")
    provider_name: str = Field("Kinetix", alias="ProviderName")
    product_name: str = Field("Kinetix", alias="ProductName")
    
    start_time: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), alias="StartTime")
    end_time: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), alias="EndTime")
    
    compromised_entity: Optional[str] = Field(None, alias="CompromisedEntity")
    entities: str = Field("[]", alias="Entities")  # JSON string of entities
    
    confidence_level: str = Field("High", alias="ConfidenceLevel")
    confidence_score: float = Field(1.0, alias="ConfidenceScore")
    
    remediation_steps: Optional[str] = Field(None, alias="RemediationSteps")
    
    tactics: Optional[str] = Field(None, alias="Tactics")
    techniques: Optional[str] = Field(None, alias="Techniques")

class SecurityIncident(BaseLogEvent):
    source: Literal["SecurityInsights"] = Field("SecurityInsights", alias="SourceSystem")
    event_type: Literal["SecurityIncident"] = Field("SecurityIncident", alias="Type")
    
    incident_number: str = Field(default_factory=lambda: str(uuid.uuid4().int)[:8], alias="IncidentNumber")
    title: str = Field(..., alias="Title")
    description: Optional[str] = Field(None, alias="Description")
    status: str = Field("New", alias="Status")
    owner: str = Field("Unassigned", alias="Owner")
    
    last_modified_time: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), alias="LastModifiedTime")
    
    related_analytic_rule_ids: List[str] = Field(default_factory=list, alias="RelatedAnalyticRuleIds")
