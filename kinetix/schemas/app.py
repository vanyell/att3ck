from typing import Optional, Literal
from pydantic import Field
from kinetix.schemas.base import BaseLogEvent, syslog_priority, format_syslog, format_evt_xml, evt_level

class webServerEvent(BaseLogEvent):
    source: Literal["Web"] = Field("Web", alias="SourceSystem")
    event_type: Literal["W3CIISLog"] = Field("W3CIISLog", alias="Type")
    
    url: str = Field(..., alias="RequestURL")
    http_method: str = Field(..., alias="Method")
    status_code: int = Field(..., alias="Status")
    user_agent: str = Field(..., alias="UserAgent")
    referrer: Optional[str] = Field(None, alias="Referrer")
    response_time_ms: int = Field(..., alias="TimeTaken")

    def to_syslog(self) -> str:
        sev = "err" if self.status_code >= 500 else "warning" if self.status_code >= 400 else "info"
        return format_syslog(syslog_priority("daemon", sev), self.timestamp, self.hostname or "WEB",
                              "httpd", 0, f"{self.source_ip} - \"{self.http_method} {self.url}\" {self.status_code} {self.response_time_ms}ms")

    def to_evt(self) -> str:
        return format_evt_xml(1, "Microsoft-Windows-W3CIISLog", "W3CIISLog",
                              self.hostname or "WEB", self.timestamp,
                              evt_level("err" if self.status_code >= 500 else "warning" if self.status_code >= 400 else "info"),
                              [("cs-uri-stem", self.url), ("cs-method", self.http_method),
                               ("sc-status", str(self.status_code)), ("cs-user-agent", self.user_agent),
                               ("time-taken", str(self.response_time_ms))])

class GenericSyslogEvent(BaseLogEvent):
    """Catch-all for arbitrary daemon/service syslog lines with no dedicated
    Sentinel schema (e.g. scenario 'system_event' entries) — routes to the
    real generic 'Syslog' Log Analytics table instead of BaseLogEvent."""
    source: Literal["syslog"] = Field("syslog", alias="SourceSystem")
    event_type: Literal["Syslog"] = Field("Syslog", alias="Type")

    facility: str = Field("user", alias="Facility")
    proc: str = Field("system", alias="ProcessName")
    log_message: str = Field(..., alias="Message")

    def to_syslog(self) -> str:
        prio = syslog_priority(self.facility.lower(), self.severity)
        return format_syslog(prio, self.timestamp, self.hostname or "localhost", self.proc, 0, self.log_message)


class DatabaseEvent(BaseLogEvent):
    source: Literal["Azure"] = Field("Azure", alias="SourceSystem")
    event_type: Literal["AzureDiagnostics"] = Field("AzureDiagnostics", alias="Type")
    
    db_name: str = Field(..., alias="LogicalServerName")
    query_text: str = Field(..., alias="QueryText")
    operation: str = Field(..., alias="OperationName")  # SELECT, INSERT, UPDATE, DELETE, DROP
    rows_affected: Optional[int] = Field(None, alias="NumAffectedRows")
    status: str = Field("success", alias="ResultType")

    def to_syslog(self) -> str:
        sev = "err" if self.status != "success" else "info"
        return format_syslog(syslog_priority("daemon", sev), self.timestamp, self.hostname or "DB",
                              "postgres", 0, f"{self.operation} on {self.db_name}: {self.query_text[:120]} [{self.status}]")

    def to_evt(self) -> str:
        return format_evt_xml(33205, "MSSQLSERVER", "Application",
                              self.hostname or "DB", self.timestamp,
                              evt_level("err" if self.status != "success" else "info"),
                              [("Database", self.db_name), ("Query", self.query_text),
                               ("Operation", self.operation), ("Status", self.status)])
