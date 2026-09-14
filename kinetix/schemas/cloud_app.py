from typing import Optional, Literal, Dict, Any
from pydantic import Field, AliasChoices
from kinetix.schemas.base import BaseLogEvent, syslog_priority, format_syslog, format_evt_xml, evt_level

class CloudAppEvent(BaseLogEvent):
    source: Literal["Cloud App Security"] = Field("Cloud App Security", alias="SourceSystem")
    event_type: Literal["CloudAppEvents"] = Field("CloudAppEvents", alias="Type")

    app_name: str = Field(..., alias="AppName", validation_alias=AliasChoices("AppName", "app_name"))
    activity_type: str = Field("Access", alias="ActivityType", validation_alias=AliasChoices("ActivityType", "activity_type"))
    action_type: str = Field(..., alias="ActionType", validation_alias=AliasChoices("ActionType", "action_type"))
    risk_level: str = Field("None", alias="RiskLevel", validation_alias=AliasChoices("RiskLevel", "risk_level"))
    policy_name: Optional[str] = Field(None, alias="PolicyName", validation_alias=AliasChoices("PolicyName", "policy_name"))

    app_permissions: Optional[str] = Field(None, alias="AppPermissions", validation_alias=AliasChoices("AppPermissions", "permissions"))
    oauth_consent_scope: Optional[str] = Field(None, alias="OAuthConsentScope", validation_alias=AliasChoices("OAuthConsentScope", "consent_scope"))
    app_id: Optional[str] = Field(None, alias="AppId", validation_alias=AliasChoices("AppId", "app_id"))
    object_id: Optional[str] = Field(None, alias="ObjectId", validation_alias=AliasChoices("ObjectId", "object_id"))
    is_admin_operation: bool = Field(False, alias="IsAdminOperation")
    is_third_party_app: bool = Field(True, alias="IsThirdPartyApp")

    # Real CloudAppEvents.AdditionalFields is "dynamic" type (a JSON object),
    # unlike the "string" AdditionalFields on the DeviceProcessEvents/
    # EmailEvents family -- verified against Microsoft Learn's advanced-
    # hunting schema reference, so this is a Dict, not a JSON-string field.
    additional_fields: Dict[str, Any] = Field(default_factory=dict, alias="AdditionalFields", validation_alias=AliasChoices("AdditionalFields", "additional_fields"))

    def to_syslog(self) -> str:
        prio = syslog_priority("daemon", "warning" if self.is_malicious else "info")
        return format_syslog(prio, self.timestamp, self.hostname or "-", "CAS", 0,
                             f"App={self.app_name} Activity={self.action_type} User={self.user_name} Risk={self.risk_level}")

    def to_evt(self) -> str:
        return format_evt_xml(1102, "Microsoft-Windows-Security-Auditing", "Security",
                              self.hostname or "-", self.timestamp,
                              evt_level("err" if self.is_malicious else "info"),
                              [("AppName", self.app_name), ("ActionType", self.action_type),
                               ("RiskLevel", self.risk_level)])
