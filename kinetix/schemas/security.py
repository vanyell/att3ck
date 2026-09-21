from typing import Optional, List, Literal
from pydantic import Field, AliasChoices
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
        prio = syslog_priority("authpriv", self.severity)
        return format_syslog(prio, self.timestamp, self.compromised_entity or "-", "Kinetix", 0,
                              f"ALERT: {self.alert_name} [{self.alert_type}] confidence={self.confidence_level}")

    def to_evt(self) -> str:
        # SecurityAlert is a Sentinel-native construct with no real Windows EVTX
        # form — use a distinct synthetic provider/ID rather than impersonating
        # a real (and differently-meaning) Security-Auditing event ID.
        return format_evt_xml(9101, "Kinetix-SentinelAlert", "Application",
                              self.compromised_entity or "-", self.timestamp,
                              evt_level(self.severity),
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
        # SecurityIncident is likewise Sentinel-native — synthetic provider/ID.
        return format_evt_xml(9102, "Kinetix-SentinelIncident", "Application",
                              self.hostname or "-", self.timestamp, evt_level(self.severity),
                              [("IncidentNumber", self.incident_number), ("Title", self.title),
                               ("Status", self.status)])


class AuditLogEvent(BaseLogEvent):
    """Azure AD directory audit trail (real Sentinel 'AuditLogs' table) —
    e.g. user/group/role management operations."""
    source: Literal["Azure AD"] = Field("Azure AD", alias="SourceSystem")
    event_type: Literal["AuditLogs"] = Field("AuditLogs", alias="Type")

    operation_name: str = Field(..., alias="OperationName", validation_alias=AliasChoices("OperationName", "operation_name"))
    category: str = Field("UserManagement", alias="Category")
    result: str = Field("success", alias="Result")
    initiated_by: Optional[str] = Field(None, alias="InitiatedBy", validation_alias=AliasChoices("InitiatedBy", "initiated_by"))
    target_resources: Optional[str] = Field(None, alias="TargetResources", validation_alias=AliasChoices("TargetResources", "target_resources"))

    def to_syslog(self) -> str:
        prio = syslog_priority("authpriv", self.severity)
        return format_syslog(prio, self.timestamp, self.hostname or "AAD", "AzureADAudit", 0,
                              f"{self.operation_name} result={self.result} by={self.initiated_by or self.user_name or '-'}")

    def to_evt(self) -> str:
        # AuditLogs is a Sentinel-native (Azure AD) construct with no real
        # Windows EVTX form — synthetic provider/ID, not impersonating a real one.
        return format_evt_xml(9104, "Kinetix-AzureADAudit", "Application",
                              self.hostname or "-", self.timestamp, evt_level(self.severity),
                              [("OperationName", self.operation_name), ("Result", self.result),
                               ("TargetResources", self.target_resources or "")])


class WorkspaceAuditEvent(BaseLogEvent):
    """Sentinel/Log Analytics workspace-level configuration audit trail
    (fabricated 'SentinelAudit' table — no real single Sentinel table name
    covers this; kept distinct from AuditLogEvent's real Azure AD AuditLogs)."""
    source: Literal["sentinel_audit"] = Field("sentinel_audit", alias="SourceSystem")
    event_type: Literal["audit"] = Field("audit", alias="Type")

    action: str = Field(..., alias="Action", validation_alias=AliasChoices("Action", "action"))

    def to_syslog(self) -> str:
        prio = syslog_priority("authpriv", self.severity)
        return format_syslog(prio, self.timestamp, self.hostname or "SENTINEL", "SentinelAudit", 0, self.action)

    def to_evt(self) -> str:
        return format_evt_xml(9105, "Kinetix-SentinelAudit", "Application",
                              self.hostname or "-", self.timestamp, evt_level(self.severity),
                              [("Action", self.action)])
