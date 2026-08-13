from typing import Optional, List, Literal
from pydantic import Field
from kinetix.schemas.base import BaseLogEvent, syslog_priority, format_syslog, format_evt_xml, evt_level
from datetime import datetime, timezone
import uuid
import random

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
    entities: str = Field("[]", alias="Entities")
    
    confidence_level: str = Field("High", alias="ConfidenceLevel")
    confidence_score: float = Field(1.0, alias="ConfidenceScore")
    
    remediation_steps: Optional[str] = Field(None, alias="RemediationSteps")
    
    tactics: Optional[str] = Field(None, alias="Tactics")
    techniques: Optional[str] = Field(None, alias="Techniques")

    def to_syslog(self) -> str:
        prio = syslog_priority("authpriv", "crit" if self.severity in ("High", "Critical") else "warning")
        return format_syslog(prio, self.timestamp, self.compromised_entity or "-", "Kinetix", 0,
                              f"ALERT: {self.alert_name} [{self.alert_type}] confidence={self.confidence_level}")

    def to_evt(self) -> str:
        return format_evt_xml(1102, "Microsoft-Windows-Security-Auditing", "Security",
                              self.compromised_entity or "-", self.timestamp,
                              evt_level("crit" if self.severity in ("High", "Critical") else "warning"),
                              [("AlertName", self.alert_name), ("AlertType", self.alert_type),
                               ("Severity", self.severity),
                               ("Confidence", str(self.confidence_score))])

class SecurityIncident(BaseLogEvent):
    source: Literal["SecurityInsights"] = Field("SecurityInsights", alias="SourceSystem")
    event_type: Literal["SecurityIncident"] = Field("SecurityIncident", alias="Type")
    
    incident_number: str = Field(default_factory=lambda: f"INC{random.randint(100000, 999999)}", alias="IncidentNumber")
    title: str = Field(..., alias="Title")
    description: Optional[str] = Field(None, alias="Description")
    status: str = Field("New", alias="Status")
    owner: str = Field("Unassigned", alias="Owner")
    
    last_modified_time: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), alias="LastModifiedTime")
    
    related_analytic_rule_ids: List[str] = Field(default_factory=list, alias="RelatedAnalyticRuleIds")

    def to_evt(self) -> str:
        return format_evt_xml(1102, "Microsoft-Windows-Security-Auditing", "Security",
                              self.hostname or "-", self.timestamp, evt_level(self.severity),
                              [("IncidentNumber", self.incident_number), ("Title", self.title),
                               ("Status", self.status)])
