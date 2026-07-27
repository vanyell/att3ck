from typing import Optional, Literal
from pydantic import Field
from kinetix.schemas.base import BaseLogEvent, syslog_priority, format_syslog


class LinuxAuthEvent(BaseLogEvent):
    source: Literal["linux"] = Field("linux", alias="SourceSystem")
    event_type: Literal["linux_auth"] = Field("linux_auth", alias="Type")
    os_platform: str = Field("Linux", alias="OSPlatform")
    device_category: str = Field("Server", alias="DeviceCategory")

    pid: int = Field(..., alias="ProcessId")
    proc: str = Field("sshd", alias="ProcessName")
    log_message: str = Field(..., alias="Message")

    def to_syslog(self) -> str:
        prio = syslog_priority("auth", self.severity)
        return format_syslog(prio, self.timestamp, self.hostname or "localhost",
                             self.proc, self.pid, self.log_message)


class LinuxSudoEvent(BaseLogEvent):
    source: Literal["linux"] = Field("linux", alias="SourceSystem")
    event_type: Literal["linux_sudo"] = Field("linux_sudo", alias="Type")
    os_platform: str = Field("Linux", alias="OSPlatform")
    device_category: str = Field("Server", alias="DeviceCategory")

    pid: int = Field(..., alias="ProcessId")
    user: str = Field(..., alias="AccountName")
    target_user: str = Field("root", alias="TargetUser")
    command: str = Field(..., alias="Command")
    pwd: str = Field("/home/user", alias="WorkingDirectory")
    tty: str = Field("/dev/pts/0", alias="TTY")

    def to_syslog(self) -> str:
        msg = f"   {self.user} : TTY={self.tty} ; PWD={self.pwd} ; USER={self.target_user} ; COMMAND={self.command}"
        prio = syslog_priority("authpriv", self.severity)
        return format_syslog(prio, self.timestamp, self.hostname or "localhost", "sudo", self.pid, msg)


class LinuxAuditdEvent(BaseLogEvent):
    source: Literal["linux"] = Field("linux", alias="SourceSystem")
    event_type: Literal["linux_audit"] = Field("linux_audit", alias="Type")
    os_platform: str = Field("Linux", alias="OSPlatform")
    device_category: str = Field("Server", alias="DeviceCategory")

    pid: int = Field(..., alias="ProcessId")
    audit_type: str = Field("SYSCALL", alias="AuditType")
    audit_msg: str = Field(..., alias="Message")
    auid: int = Field(1000, alias="Auid")
    ses: int = Field(1, alias="Session")

    def to_syslog(self) -> str:
        msg = f"type={self.audit_type} msg=audit({int(self.timestamp.timestamp())}.000:{self.pid}): {self.audit_msg}"
        prio = syslog_priority("kern", self.severity)
        return format_syslog(prio, self.timestamp, self.hostname or "localhost", "kernel", self.pid, msg)


class LinuxKernelEvent(BaseLogEvent):
    source: Literal["linux"] = Field("linux", alias="SourceSystem")
    event_type: Literal["linux_kernel"] = Field("linux_kernel", alias="Type")
    os_platform: str = Field("Linux", alias="OSPlatform")
    device_category: str = Field("Server", alias="DeviceCategory")

    pid: int = Field(0, alias="ProcessId")
    log_message: str = Field(..., alias="Message")

    def to_syslog(self) -> str:
        prio = syslog_priority("kern", self.severity)
        return format_syslog(prio, self.timestamp, self.hostname or "localhost", "kernel", self.pid, self.log_message)


class LinuxCronEvent(BaseLogEvent):
    source: Literal["linux"] = Field("linux", alias="SourceSystem")
    event_type: Literal["linux_cron"] = Field("linux_cron", alias="Type")
    os_platform: str = Field("Linux", alias="OSPlatform")
    device_category: str = Field("Server", alias="DeviceCategory")

    pid: int = Field(..., alias="ProcessId")
    user: str = Field("root", alias="AccountName")
    command: str = Field(..., alias="Command")

    def to_syslog(self) -> str:
        prio = syslog_priority("cron", "info")
        return format_syslog(prio, self.timestamp, self.hostname or "localhost", "CRON", self.pid,
                             f"({self.user}) CMD ({self.command})")


class LinuxProcessEvent(BaseLogEvent):
    source: Literal["linux"] = Field("linux", alias="SourceSystem")
    event_type: Literal["linux_process"] = Field("linux_process", alias="Type")
    os_platform: str = Field("Linux", alias="OSPlatform")
    device_category: str = Field("Server", alias="DeviceCategory")

    pid: int = Field(..., alias="ProcessId")
    ppid: int = Field(1, alias="ParentProcessId")
    exe: str = Field(..., alias="Executable")
    args: str = Field(..., alias="CommandLine")
    uid: int = Field(1000, alias="Uid")
    gid: int = Field(1000, alias="Gid")
    user: str = Field(..., alias="AccountName")

    def to_syslog(self) -> str:
        msg = f"audit: execve pid={self.pid} ppid={self.ppid} exe=\"{self.exe}\" args=\"{self.args}\" uid={self.uid} gid={self.gid}"
        prio = syslog_priority("authpriv", "info")
        return format_syslog(prio, self.timestamp, self.hostname or "localhost", "auditd", self.pid, msg)
