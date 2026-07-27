from typing import Optional, Literal
import uuid
from pydantic import Field, AliasChoices
from kinetix.schemas.base import BaseLogEvent, syslog_priority, format_syslog, format_evt_xml, evt_level

class AuthenticationEvent(BaseLogEvent):
    source: Literal["Azure AD"] = Field("Azure AD", alias="SourceSystem")
    event_type: Literal["SigninLogs"] = Field("SigninLogs", alias="Type")
    
    user_principal_name: str = Field(..., alias="UserPrincipalName", validation_alias=AliasChoices("UserPrincipalName", "user_name", "user_principal_name", "AccountName"))
    app_display_name: str = Field("Office 365", alias="AppDisplayName", validation_alias=AliasChoices("AppDisplayName", "app_name"))
    client_app_used: str = Field("Browser", alias="ClientAppUsed", validation_alias=AliasChoices("ClientAppUsed", "client_app"))
    
    result_type: str = Field("0", alias="ResultType", validation_alias=AliasChoices("ResultType", "status"))
    result_description: Optional[str] = Field("Success", alias="ResultDescription", validation_alias=AliasChoices("ResultDescription", "failure_reason"))
    
    mfa_method: str = Field("Push", alias="MfaMethod")
    risk_level: str = Field("None", alias="RiskLevelDuringSignIn")
    user_agent: str = Field("Mozilla/5.0", alias="UserAgent")
    
    location: str = Field("US", alias="Location")
    city: str = Field("Seattle", alias="City")
    conditional_access_status: str = Field("success", alias="ConditionalAccessStatus")

    def to_syslog(self) -> str:
        result = "accepted" if self.result_type == "0" else "failed"
        return format_syslog(syslog_priority("authpriv", "info"), self.timestamp, self.hostname or "SERVER",
                              "sshd", 0, f"Authentication {result} for {self.user_principal_name} from {self.source_ip}")

    def to_evt(self) -> str:
        eid = 4624 if self.result_type == "0" else 4625
        return format_evt_xml(eid, "Microsoft-Windows-Security-Auditing", "Security",
                              self.hostname or "SERVER", self.timestamp,
                              evt_level("info" if self.result_type == "0" else "err"),
                              [("TargetUser", self.user_principal_name),
                               ("LogonType", self.client_app_used),
                               ("IpAddress", self.source_ip or ""),
                               ("MfaMethod", self.mfa_method)])

class VPNEvent(BaseLogEvent):
    source: Literal["Firewall"] = Field("Firewall", alias="SourceSystem")
    event_type: Literal["CommonSecurityLog"] = Field("CommonSecurityLog", alias="Type")
    
    action: str = Field("connect", alias="DeviceAction", validation_alias=AliasChoices("DeviceAction", "action"))
    client_ip: str = Field(..., alias="SourceIP", validation_alias=AliasChoices("SourceIP", "client_ip"))
    assigned_ip: Optional[str] = Field(None, alias="DeviceCustomString1", validation_alias=AliasChoices("DeviceCustomString1", "assigned_ip"))
    session_duration: Optional[int] = Field(3600, alias="DeviceCustomNumber1", validation_alias=AliasChoices("DeviceCustomNumber1", "session_duration"))

    def to_syslog(self) -> str:
        return format_syslog(syslog_priority("daemon", "info"), self.timestamp, self.hostname or "VPN",
                              "openvpn", 0, f"client {self.client_ip} -> {self.assigned_ip} action={self.action}")

    def to_evt(self) -> str:
        return format_evt_xml(20224, "Microsoft-Windows-Security-Auditing", "Security",
                              self.hostname or "VPN", self.timestamp, evt_level("info"),
                              [("ClientIP", self.client_ip),
                               ("AssignedIP", self.assigned_ip or ""),
                               ("SessionDuration", str(self.session_duration or 0))])

class CloudActivityEvent(BaseLogEvent):
    source: Literal["Azure"] = Field("Azure", alias="SourceSystem")
    event_type: Literal["AzureActivity"] = Field("AzureActivity", alias="Type")
    
    operation_name: str = Field(..., alias="OperationName", validation_alias=AliasChoices("OperationName", "operation_name"))
    resource_id: str = Field(..., alias="ResourceId", validation_alias=AliasChoices("ResourceId", "resource_id"))
    caller: str = Field(..., alias="Caller", validation_alias=AliasChoices("Caller", "user_identity_type", "caller"))
    correlation_id: str = Field(default_factory=lambda: str(uuid.uuid4()), alias="CorrelationId")
    
class O365ActivityEvent(BaseLogEvent):
    source: Literal["Office 365"] = Field("Office 365", alias="SourceSystem")
    event_type: Literal["OfficeActivity"] = Field("OfficeActivity", alias="Type")
    
    workload: str = Field(..., alias="Workload", validation_alias=AliasChoices("Workload", "workload"))
    operation: str = Field(..., alias="Operation", validation_alias=AliasChoices("Operation", "operation"))
    item_type: str = Field(..., alias="ItemType", validation_alias=AliasChoices("ItemType", "item_type"))
    user_key: str = Field(..., alias="UserId", validation_alias=AliasChoices("UserId", "user_key", "UserId"))
    client_ip: str = Field("127.0.0.1", alias="ClientIP", validation_alias=AliasChoices("ClientIP", "client_ip"))
