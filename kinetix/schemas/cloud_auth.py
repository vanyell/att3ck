from typing import Optional, Literal, List, Tuple
import uuid
import json
from pydantic import Field, AliasChoices, computed_field
from kinetix.schemas.base import BaseLogEvent, syslog_priority, format_syslog, format_evt_xml, evt_level

class AuthenticationEvent(BaseLogEvent):
    source: Literal["Azure AD"] = Field("Azure AD", alias="SourceSystem")
    event_type: Literal["SigninLogs"] = Field("SigninLogs", alias="Type")

    user_principal_name: str = Field(..., alias="UserPrincipalName", validation_alias=AliasChoices("UserPrincipalName", "user_name", "user_principal_name", "AccountName"))
    app_display_name: str = Field("Office 365", alias="AppDisplayName", validation_alias=AliasChoices("AppDisplayName", "app_name"))
    client_app_used: str = Field("Browser", alias="ClientAppUsed", validation_alias=AliasChoices("ClientAppUsed", "client_app"))

    result_type: str = Field("0", alias="ResultType", validation_alias=AliasChoices("ResultType", "status"))
    result_description: Optional[str] = Field("Success", alias="ResultDescription", validation_alias=AliasChoices("ResultDescription", "failure_reason"))

    # Real SigninLogs has no top-level MfaMethod — MFA detail lives inside the
    # dynamic AuthenticationDetails/MfaDetail columns. Kept as an authoring
    # input (exclude=True) rather than serialized under a fake column name.
    mfa_method: str = Field("Push", alias="MfaMethod", exclude=True)
    risk_level: str = Field("None", alias="RiskLevelDuringSignIn")
    user_agent: str = Field("Mozilla/5.0", alias="UserAgent")

    # Real SigninLogs nests geo under the dynamic LocationDetails column
    # (countryOrRegion/city/state), not flat Location/City strings. Keep the
    # flat fields as authoring inputs and expose the real nested shape below.
    location: str = Field("US", alias="Location", exclude=True)
    city: str = Field("Seattle", alias="City", exclude=True)
    conditional_access_status: str = Field("success", alias="ConditionalAccessStatus")

    @computed_field(alias="LocationDetails")
    @property
    def location_details(self) -> dict:
        return {"countryOrRegion": self.location, "city": self.city}

    def to_vendor_feeds(self) -> List[Tuple[str, str]]:
        return [("Kinetix_Okta.json", self._to_okta_system_log())]

    def _to_okta_system_log(self) -> str:
        """One Okta System Log record, JSON, one line.

        decoder/okta-system/0 gates on eventType, uuid and published all
        existing, then reads outcome.result, outcome.reason, severity, actor
        and client. Okta is the identity provider these sign-in scenarios are
        really modelling, and unlike the Sentinel-shaped SigninLogs JSON it is
        a shape an enabled 5.0 integration can claim.
        """
        success = self.result_type == "0"
        record = {
            "uuid": str(uuid.uuid4()),
            "published": self.timestamp.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
            "eventType": "user.session.start",
            "version": "0",
            "displayMessage": "User login to Okta",
            "severity": "INFO" if success else "WARN",
            "legacyEventType": "core.user_auth.login_success" if success
                               else "core.user_auth.login_failed",
            "outcome": {
                "result": "SUCCESS" if success else "FAILURE",
                # result_description defaults to "Success" on the Sentinel
                # schema, so a failure that never overrode it would otherwise
                # report FAILURE with reason "Success".
                "reason": (self.result_description or "Success") if success
                          else (self.result_description
                                if self.result_description not in (None, "Success")
                                else "INVALID_CREDENTIALS"),
            },
            "actor": {
                "id": f"00u{uuid.uuid5(uuid.NAMESPACE_DNS, self.user_principal_name).hex[:17]}",
                "type": "User",
                "alternateId": self.user_principal_name,
                "displayName": self.user_principal_name.split("@")[0],
            },
            "client": {
                "userAgent": {"rawUserAgent": self.user_agent, "browser": self.client_app_used},
                "ipAddress": self.source_ip or "0.0.0.0",
                "device": "Computer",
                "geographicalContext": {"country": self.location, "city": self.city},
            },
            "authenticationContext": {"authenticationStep": 0},
            "securityContext": {},
            "target": [{"id": self.app_display_name, "type": "AppInstance",
                        "displayName": self.app_display_name}],
        }
        return json.dumps(record, separators=(",", ":"))

    def to_syslog(self) -> str:
        result = "accepted" if self.result_type == "0" else "failed"
        return format_syslog(syslog_priority("authpriv", "info"), self.timestamp, self.hostname or "SERVER",
                              "AzureAD", 0, f"Authentication {result} for {self.user_principal_name} from {self.source_ip}")

    def to_evt(self) -> str:
        # Real 4624/4625 field is "TargetUserName", not "TargetUser" (verified
        # against a live Wazuh 5.0 engine's decoder/windows-security/0 asset).
        eid = 4624 if self.result_type == "0" else 4625
        return format_evt_xml(eid, "Microsoft-Windows-Security-Auditing", "Security",
                              self.hostname or "SERVER", self.timestamp,
                              evt_level("info" if self.result_type == "0" else "err"),
                              [("TargetUserName", self.user_principal_name),
                               ("LogonType", self.client_app_used),
                               ("IpAddress", self.source_ip or "")])

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
