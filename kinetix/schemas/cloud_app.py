from typing import Optional, Literal, Dict, Any
from pydantic import Field, AliasChoices
from kinetix.schemas.base import BaseLogEvent, syslog_priority, format_syslog, format_evt_xml, evt_level

class CloudAppEvent(BaseLogEvent):
    source: Literal["Cloud App Security"] = Field("Cloud App Security", alias="SourceSystem")
    event_type: Literal["CloudAppEvents"] = Field("CloudAppEvents", alias="Type")

    # Real CloudAppEvents field names are Application/ApplicationId, not
    # AppName/AppId. validation_alias keeps accepting the shorter authoring
    # keys used throughout scenarios/*.json.
    app_name: str = Field(..., alias="Application", validation_alias=AliasChoices("Application", "AppName", "app_name"))
    activity_type: str = Field("Access", alias="ActivityType", validation_alias=AliasChoices("ActivityType", "activity_type"))
    action_type: str = Field(..., alias="ActionType", validation_alias=AliasChoices("ActionType", "action_type"))
    risk_level: str = Field("None", alias="RiskLevel", validation_alias=AliasChoices("RiskLevel", "risk_level"))
    policy_name: Optional[str] = Field(None, alias="PolicyName", validation_alias=AliasChoices("PolicyName", "policy_name"))

    app_permissions: Optional[str] = Field(None, alias="AppPermissions", validation_alias=AliasChoices("AppPermissions", "permissions"))
    oauth_consent_scope: Optional[str] = Field(None, alias="OAuthConsentScope", validation_alias=AliasChoices("OAuthConsentScope", "consent_scope"))
    app_id: Optional[str] = Field(None, alias="ApplicationId", validation_alias=AliasChoices("ApplicationId", "AppId", "app_id"))
    object_id: Optional[str] = Field(None, alias="ObjectId", validation_alias=AliasChoices("ObjectId", "object_id"))
    object_name: Optional[str] = Field(None, alias="ObjectName", validation_alias=AliasChoices("ObjectName", "object_name"))
    object_type: Optional[str] = Field(None, alias="ObjectType", validation_alias=AliasChoices("ObjectType", "object_type"))
    is_admin_operation: bool = Field(False, alias="IsAdminOperation")
    is_third_party_app: bool = Field(True, alias="IsThirdPartyApp")
    country_code: Optional[str] = Field(None, alias="CountryCode", validation_alias=AliasChoices("CountryCode", "country_code"))
    isp: Optional[str] = Field(None, alias="ISP", validation_alias=AliasChoices("ISP", "isp"))

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
        # CloudAppEvents is a cloud-native Defender for Cloud Apps table with no
        # real Windows EVTX equivalent — use a synthetic provider/ID rather than
        # a real (and differently-meaning) Security-Auditing event ID.
        return format_evt_xml(9103, "Kinetix-CloudAppEvent", "Application",
                              self.hostname or "-", self.timestamp,
                              evt_level("high" if self.is_malicious else "informational"),
                              [("AppName", self.app_name), ("ActionType", self.action_type),
                               ("RiskLevel", self.risk_level)])
