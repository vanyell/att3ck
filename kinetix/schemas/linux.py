from typing import Optional, Literal
from pydantic import Field
import shlex
from pathlib import PurePosixPath

from kinetix.schemas.base import (
    BaseLogEvent, syslog_priority, format_syslog,
    format_auditd, next_audit_serial, audit_hex,
)


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

    def to_auditd(self) -> list[str]:
        failed = "fail" in self.log_message.lower() or "invalid" in self.log_message.lower()
        record = "USER_AUTH" if failed else "USER_LOGIN"
        result = "failed" if failed else "success"
        fields = (
            f"pid={self.pid} uid=0 auid=4294967295 ses=4294967295 "
            f"msg='op=login exe=\"/usr/sbin/{self.proc}\" "
            f"hostname={self.hostname or 'localhost'} terminal=ssh res={result}'"
        )
        return [format_auditd(record, self.timestamp, next_audit_serial(), fields)]


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

    def to_auditd(self) -> list[str]:
        fields = (
            f"pid={self.pid} uid=1000 auid=1000 ses=1 "
            f"msg='cwd=\"{self.pwd}\" cmd={audit_hex(self.command)} "
            f"terminal={self.tty} res=success'"
        )
        return [format_auditd("USER_CMD", self.timestamp, next_audit_serial(), fields)]


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

    def to_auditd(self) -> list[str]:
        fields = f"{self.audit_msg} pid={self.pid} auid={self.auid} ses={self.ses}"
        return [format_auditd(self.audit_type, self.timestamp, next_audit_serial(), fields)]


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

    def to_auditd(self) -> list[str]:
        fields = (
            f"pid={self.pid} uid=0 auid=0 ses=1 "
            f"msg='op=PAM:setcred grantors=pam_env,pam_unix acct=\"{self.user}\" "
            f"exe=\"/usr/sbin/cron\" terminal=cron res=success'"
        )
        return [format_auditd("CRED_ACQ", self.timestamp, next_audit_serial(), fields)]


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

    def to_auditd(self) -> list[str]:
        # One execve produces a SYSCALL and an EXECVE record sharing a serial;
        # that shared serial is how auditd groups them into a single event.
        serial = next_audit_serial()
        comm = PurePosixPath(self.exe).name
        syscall = (
            f"arch=c000003e syscall=59 success=yes exit=0 "
            f"ppid={self.ppid} pid={self.pid} auid={self.uid} uid={self.uid} gid={self.gid} "
            f"ses=1 comm=\"{comm}\" exe=\"{self.exe}\" key=\"exec\""
        )
        try:
            argv = shlex.split(self.args)
        except ValueError:
            argv = self.args.split()
        if not argv:
            argv = [comm]
        execve = f"argc={len(argv)} " + " ".join(f'a{i}="{a}"' for i, a in enumerate(argv))
        return [
            format_auditd("SYSCALL", self.timestamp, serial, syscall),
            format_auditd("EXECVE", self.timestamp, serial, execve),
        ]
