from typing import Optional, Literal
from pydantic import Field
from kinetix.schemas.base import BaseLogEvent, syslog_priority, format_syslog


class MacOSLogEvent(BaseLogEvent):
    source: Literal["macos"] = Field("macos", alias="SourceSystem")
    event_type: Literal["macos_log"] = Field("macos_log", alias="Type")
    os_platform: str = Field("macOS", alias="OSPlatform")
    device_category: str = Field("Workstation", alias="DeviceCategory")

    pid: int = Field(..., alias="ProcessId")
    proc: str = Field(..., alias="ProcessName")
    subsystem: str = Field("com.apple.authd", alias="Subsystem")
    category: str = Field("default", alias="Category")
    log_message: str = Field(..., alias="Message")
    sender_image: str = Field("/usr/libexec/authd", alias="SenderImage")

    def to_syslog(self) -> str:
        prio = syslog_priority("auth", self.severity)
        return format_syslog(prio, self.timestamp, self.hostname or "MacBook-Pro",
                             self.proc, self.pid, self.log_message)


class MacOSAuthEvent(BaseLogEvent):
    source: Literal["macos"] = Field("macos", alias="SourceSystem")
    event_type: Literal["macos_auth"] = Field("macos_auth", alias="Type")
    os_platform: str = Field("macOS", alias="OSPlatform")
    device_category: str = Field("Workstation", alias="DeviceCategory")

    pid: int = Field(..., alias="ProcessId")
    proc: str = Field("authd", alias="ProcessName")
    log_message: str = Field(..., alias="Message")
    user: str = Field(..., alias="AccountName")

    def to_syslog(self) -> str:
        prio = syslog_priority("auth", self.severity)
        return format_syslog(prio, self.timestamp, self.hostname or "MacBook-Pro",
                             self.proc, self.pid, self.log_message)


class MacOSAppExecEvent(BaseLogEvent):
    source: Literal["macos"] = Field("macos", alias="SourceSystem")
    event_type: Literal["macos_exec"] = Field("macos_exec", alias="Type")
    os_platform: str = Field("macOS", alias="OSPlatform")
    device_category: str = Field("Workstation", alias="DeviceCategory")

    pid: int = Field(..., alias="ProcessId")
    proc: str = Field("kernel", alias="ProcessName")
    bundle_id: str = Field(..., alias="BundleId")
    app_path: str = Field(..., alias="AppPath")
    signer: str = Field("Not signed", alias="Signer")
    log_message: str = Field(..., alias="Message")

    def to_syslog(self) -> str:
        prio = syslog_priority("user", self.severity)
        return format_syslog(prio, self.timestamp, self.hostname or "MacBook-Pro",
                             self.proc, self.pid, self.log_message)
