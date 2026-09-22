from typing import Optional, Literal
from pydantic import Field, AliasChoices
from kinetix.schemas.base import BaseLogEvent, syslog_priority, format_syslog, format_evt_xml, evt_level

class FirewallEvent(BaseLogEvent):
    source: Literal["Firewall"] = Field("Firewall", alias="SourceSystem")
    event_type: Literal["CommonSecurityLog"] = Field("CommonSecurityLog", alias="Type")
    
    action: str = Field(..., alias="DeviceAction", validation_alias=AliasChoices("DeviceAction", "action"))
    protocol: str = Field(..., alias="Protocol", validation_alias=AliasChoices("Protocol", "protocol"))
    source_port: int = Field(..., alias="SourcePort", validation_alias=AliasChoices("SourcePort", "source_port"))
    dest_port: int = Field(..., alias="DestinationPort", validation_alias=AliasChoices("DestinationPort", "dest_port"))
    
    direction: str = Field("Outbound", alias="NetworkDirection", validation_alias=AliasChoices("NetworkDirection", "direction"))
    remote_country: str = Field("US", alias="RemoteCountry")
    remote_asn: str = Field("MSFT", alias="RemoteASN")
    
    bytes_sent: Optional[int] = Field(None, alias="SentBytes", validation_alias=AliasChoices("SentBytes", "bytes_sent"))
    bytes_received: Optional[int] = Field(None, alias="ReceivedBytes", validation_alias=AliasChoices("ReceivedBytes", "bytes_received"))

    def to_syslog(self) -> str:
        prio = syslog_priority("kern", "warning" if self.action == "blocked" else "info")
        return format_syslog(prio, self.timestamp, self.hostname or "FW", "firewalld",
                               0, f"ACTION={self.action} PROTO={self.protocol} SRC={self.source_ip}:{self.source_port} DST={self.dest_ip}:{self.dest_port}")

    def to_evt(self) -> str:
        # Not 5156/5157: both Windows Filtering Platform codes sit on
        # decoder/windows-event/0's discard list and were ingest-verified as
        # zero indexed documents. Sysmon 3 (NetworkConnect) decodes instead.
        # Sysmon 3 has no allow/block field — it only ever records connections
        # that happened — so the action rides in RuleName, which is Sysmon's
        # own tagging field. Note this shapes appliance firewall telemetry as
        # endpoint telemetry; the JSON/CEF/syslog feeds keep the firewall
        # framing for consumers that model it properly.
        return format_evt_xml(3, "Microsoft-Windows-Sysmon",
                              "Microsoft-Windows-Sysmon/Operational",
                              self.hostname or "FW", self.timestamp,
                              evt_level("warning" if self.action == "blocked" else "info"),
                              [("RuleName", self.action),
                               ("UtcTime", self.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]),
                               ("Protocol", self.protocol.lower()),
                               ("Initiated", "true" if self.direction == "Outbound" else "false"),
                               ("SourceIp", self.source_ip or ""),
                               ("SourcePort", str(self.source_port)),
                               ("DestinationIp", self.dest_ip or ""),
                               ("DestinationPort", str(self.dest_port))])

class DNSEvent(BaseLogEvent):
    source: Literal["DNS"] = Field("DNS", alias="SourceSystem")
    event_type: Literal["DnsEvents"] = Field("DnsEvents", alias="Type")
    
    query_name: str = Field(..., alias="Name", validation_alias=AliasChoices("Name", "query_name"))
    query_type: str = Field("A", alias="QueryType", validation_alias=AliasChoices("QueryType", "query_type"))
    response_code: str = Field("0", alias="ResultCode", validation_alias=AliasChoices("ResultCode", "response_code"))
    resolved_ip: Optional[str] = Field(None, alias="IPAddresses", validation_alias=AliasChoices("IPAddresses", "resolved_ip"))

    def to_syslog(self) -> str:
        rc = "NOERROR" if self.response_code == "0" else "NXDOMAIN"
        return format_syslog(syslog_priority("daemon", "info"), self.timestamp, self.hostname or "NS",
                              "named", 0, f"query: {self.query_name} IN {self.query_type} {rc}")

    def to_evt(self) -> str:
        return format_evt_xml(3008, "Microsoft-Windows-DNS-Client", "DNS Client",
                              self.hostname or "NS", self.timestamp, evt_level("info"),
                              [("QueryName", self.query_name), ("QueryType", self.query_type),
                               ("ResultCode", self.response_code)])

class ProxyEvent(BaseLogEvent):
    source: Literal["Proxy"] = Field("Proxy", alias="SourceSystem")
    event_type: Literal["W3CIISLog"] = Field("W3CIISLog", alias="Type")
    
    url: str = Field(..., alias="RequestURL", validation_alias=AliasChoices("RequestURL", "url"))
    http_method: str = Field(..., alias="Method", validation_alias=AliasChoices("Method", "http_method"))
    http_status: int = Field(..., alias="Status", validation_alias=AliasChoices("Status", "http_status"))
    user_agent: str = Field(..., alias="UserAgent", validation_alias=AliasChoices("UserAgent", "user_agent"))
    content_type: Optional[str] = Field(None, alias="ContentType")

    def to_syslog(self) -> str:
        return format_syslog(syslog_priority("daemon", "info"), self.timestamp, self.hostname or "PROXY",
                              "squid", 0, f"{self.http_method} {self.url} -> {self.http_status}")

    def to_evt(self) -> str:
        return format_evt_xml(1, "Microsoft-Windows-W3CIISLog", "W3CIISLog",
                              self.hostname or "PROXY", self.timestamp, evt_level("info"),
                              [("cs-uri-stem", self.url), ("cs-method", self.http_method),
                               ("sc-status", str(self.http_status)),
                               ("cs-user-agent", self.user_agent)])
