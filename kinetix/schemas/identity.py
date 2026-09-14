from typing import Optional, Literal
from pydantic import Field, AliasChoices
from kinetix.schemas.base import BaseLogEvent, syslog_priority, format_syslog, format_evt_xml, evt_level

class IdentityLogonEvent(BaseLogEvent):
    source: Literal["Identity Protection"] = Field("Identity Protection", alias="SourceSystem")
    event_type: Literal["IdentityLogonEvents"] = Field("IdentityLogonEvents", alias="Type")

    logon_type: str = Field("Interactive", alias="LogonType", validation_alias=AliasChoices("LogonType", "logon_type"))
    protocol: str = Field("Kerberos", alias="Protocol", validation_alias=AliasChoices("Protocol", "protocol"))
    target_device: Optional[str] = Field(None, alias="TargetDevice", validation_alias=AliasChoices("TargetDevice", "target_device"))
    target_device_ip: Optional[str] = Field(None, alias="TargetDeviceIP", validation_alias=AliasChoices("TargetDeviceIP", "target_ip"))

    logon_result: str = Field("Success", alias="LogonResult", validation_alias=AliasChoices("LogonResult", "logon_result"))
    failure_reason: Optional[str] = Field(None, alias="FailureReason", validation_alias=AliasChoices("FailureReason", "failure_reason"))

    is_admin_logon: bool = Field(False, alias="IsAdminLogon")
    is_service_account: bool = Field(False, alias="IsServiceAccount")
    account_domain: Optional[str] = Field(None, alias="AccountDomain", validation_alias=AliasChoices("AccountDomain", "account_domain"))

    def to_syslog(self) -> str:
        prio = syslog_priority("authpriv", "info" if self.logon_result == "Success" else "err")
        return format_syslog(prio, self.timestamp, self.hostname or "DC",
                             "lsass", 0,
                             f"Logon {self.logon_type} via {self.protocol} for {self.user_name} from {self.source_ip} result={self.logon_result}")

    def to_evt(self) -> str:
        eid = 4624 if self.logon_result == "Success" else 4625
        return format_evt_xml(eid, "Microsoft-Windows-Security-Auditing", "Security",
                              self.hostname or "DC", self.timestamp,
                              evt_level("info" if self.logon_result == "Success" else "err"),
                              [("LogonType", self.logon_type), ("AccountName", self.user_name or ""),
                               ("IpAddress", self.source_ip or ""),
                               ("TargetDevice", self.target_device or "")])


class AADNonInteractiveSignIn(BaseLogEvent):
    source: Literal["Azure AD"] = Field("Azure AD", alias="SourceSystem")
    event_type: Literal["AADNonInteractiveUserSignInLogs"] = Field("AADNonInteractiveUserSignInLogs", alias="Type")

    service_principal_name: Optional[str] = Field(None, alias="ServicePrincipalName", validation_alias=AliasChoices("ServicePrincipalName", "service_principal_name", "app_name"))
    app_id: str = Field(..., alias="AppId", validation_alias=AliasChoices("AppId", "app_id"))
    resource_id: str = Field(..., alias="ResourceId", validation_alias=AliasChoices("ResourceId", "resource_id"))
    resource_display_name: Optional[str] = Field(None, alias="ResourceDisplayName", validation_alias=AliasChoices("ResourceDisplayName", "resource_name"))

    result_type: str = Field("0", alias="ResultType", validation_alias=AliasChoices("ResultType", "status"))
    result_description: Optional[str] = Field("Success", alias="ResultDescription", validation_alias=AliasChoices("ResultDescription", "failure_reason"))
    error_code: Optional[int] = Field(None, alias="ErrorCode")

    service_principal_id: Optional[str] = Field(None, alias="ServicePrincipalId")

    user_agent: str = Field("MicrosoftGraph/1.0", alias="UserAgent")
    is_service_principal: bool = Field(True, alias="IsServicePrincipal")
    client_app: str = Field("Other", alias="ClientAppUsed", validation_alias=AliasChoices("ClientAppUsed", "client_app"))
    conditional_access_status: str = Field("notApplied", alias="ConditionalAccessStatus")

    # Real AADNonInteractiveUserSignInLogs columns (verified against Azure
    # Monitor's table reference) previously missing from this schema. Note:
    # this table has no AdditionalFields column at all -- unlike the Defender
    # XDR advanced-hunting tables, it's a fully-enumerated fixed schema, so
    # one isn't added here.
    location_details: Optional[str] = Field(None, alias="LocationDetails", validation_alias=AliasChoices("LocationDetails", "location_details"))
    device_detail: Optional[str] = Field(None, alias="DeviceDetail", validation_alias=AliasChoices("DeviceDetail", "device_detail"))
    authentication_requirement: str = Field("singleFactorAuthentication", alias="AuthenticationRequirement", validation_alias=AliasChoices("AuthenticationRequirement", "authentication_requirement"))
    risk_level_during_signin: str = Field("none", alias="RiskLevelDuringSignIn", validation_alias=AliasChoices("RiskLevelDuringSignIn", "risk_level_during_signin"))
    risk_level_aggregated: str = Field("none", alias="RiskLevelAggregated", validation_alias=AliasChoices("RiskLevelAggregated", "risk_level_aggregated"))
    # Docs: "For authentications that use protocols other than the possible
    # values listed, the protocol type is listed as none" -- "none" is a real
    # documented value here, not a placeholder default.
    authentication_protocol: str = Field("none", alias="AuthenticationProtocol", validation_alias=AliasChoices("AuthenticationProtocol", "authentication_protocol"))
    token_issuer_type: str = Field("Azure AD", alias="TokenIssuerType", validation_alias=AliasChoices("TokenIssuerType", "token_issuer_type"))

    def to_syslog(self) -> str:
        result = "accepted" if self.result_type == "0" else "failed"
        return format_syslog(syslog_priority("authpriv", "info"), self.timestamp, self.hostname or "SERVER",
                              "MicrosoftGraph", 0,
                              f"Non-interactive sign-in {result} for {self.service_principal_name or self.app_id} resource={self.resource_id}")

    def to_evt(self) -> str:
        eid = 4624 if self.result_type == "0" else 4625
        return format_evt_xml(eid, "Microsoft-Windows-Security-Auditing", "Security",
                              self.hostname or "SERVER", self.timestamp,
                              evt_level("info" if self.result_type == "0" else "err"),
                              [("ServicePrincipal", self.service_principal_name or ""),
                               ("AppId", self.app_id),
                               ("Resource", self.resource_display_name or self.resource_id),
                               ("Result", self.result_type)])
