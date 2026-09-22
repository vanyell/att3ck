from typing import Optional, Literal, List, Tuple
import hashlib
from pydantic import Field, AliasChoices
from kinetix.schemas.base import (BaseLogEvent, syslog_priority, format_syslog,
                                  format_evt_xml, evt_level, syslog_timestamp)

# IANA protocol numbers — FortiOS and Cisco both log the number, not the name.
_PROTO_NUMBER = {"TCP": 6, "UDP": 17, "ICMP": 1, "ICMPV6": 58, "GRE": 47, "ESP": 50}

# Kinetix's action vocabulary mapped onto FortiOS's. FortiOS only ever writes
# accept/deny/close/timeout in a traffic log; "blocked" is not a value it uses.
_FORTIOS_DENY_ACTIONS = {"blocked", "denied", "dropped", "deny", "drop", "reset"}

# Spellings a scenario might use for the same appliance.
_ASA_VENDORS = {"asa", "cisco", "cisco-asa", "cisco_asa"}

# DNS RR types as their numeric codes. The DNS Server analytical channel logs
# QTYPE numerically and Wazuh resolves it through the
# windows_dns_type_id_and_task_code_to_type KVDB, so a name here would look up
# to nothing.
_DNS_QTYPE = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15,
              "TXT": 16, "AAAA": 28, "SRV": 33, "ANY": 255}


def _fortigate_serial(hostname: str) -> str:
    """A stable per-device serial. Real FortiGates carry one and Wazuh keeps it
    as observer.serial_number, so it has to be the same on every event from a
    given host — hence a digest of the hostname rather than a random value."""
    digest = hashlib.md5(hostname.encode("utf-8")).hexdigest()[:10].upper()
    return f"FG100E{digest}"

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

    # Which appliance this session came off. It picks the vendor-native feed,
    # because a session is logged by one device in one format — emitting both
    # flavours for the same event would fabricate a second appliance.
    vendor: str = Field("fortigate", alias="DeviceVendor",
                        validation_alias=AliasChoices("DeviceVendor", "vendor"))

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

    def to_vendor_feeds(self) -> List[Tuple[str, str]]:
        if self.vendor.lower() in _ASA_VENDORS:
            return [("Kinetix_CiscoASA.log", self._to_asa_syslog())]
        return [("Kinetix_Fortinet.log", self._to_fortios_traffic())]

    def _to_asa_syslog(self) -> str:
        """A Cisco ASA syslog line.

        decoder/cisco-asa/0 hangs off decoder/syslog/0 and parses
        '%ASA<_tmp.asa_codes>: <message>' out of the syslog *message*, so the
        %ASA-level-id has to start the message — and the line needs a real
        syslog tag in front of it. syslog/0 parses the tag as
        '<_TAG/alphanumeric/->:', and '%ASA-4-106023' cannot serve as that tag
        because the leading % is not alphanumeric: the syslog parse fails and
        cisco-asa/0 never sees a $message. Ingest-verified 2026-09-22 — the
        tagged shape indexed, the untagged one produced zero documents with
        the agent reading it at drops=0. The decoder also refuses anything
        containing %FTD, which is the Firepower variant.
        """
        deny = self.action.lower() in _FORTIOS_DENY_ACTIONS
        prio = syslog_priority("local7", "warning" if deny else "info")
        host = self.hostname or "ASA-01"
        stamp = syslog_timestamp(self.timestamp)
        proto = self.protocol.lower()
        src = f"{self.source_ip or '0.0.0.0'}/{self.source_port}"
        dst = f"{self.dest_ip or '0.0.0.0'}/{self.dest_port}"
        inbound = self.direction.lower() == "inbound"
        src_if, dst_if = ("outside", "inside") if inbound else ("inside", "outside")
        if deny:
            # 106023: denied by an access-list — the ASA message a blocked
            # flow actually produces. There is no "blocked" 302013.
            body = (f"%ASA-4-106023: Deny {proto} src {src_if}:{src} "
                    f'dst {dst_if}:{dst} by access-group "{dst_if.upper()}_IN" [0x0, 0x0]')
        else:
            session = self.report_id if hasattr(self, "report_id") else 0
            body = (f"%ASA-6-302013: Built {'inbound' if inbound else 'outbound'} "
                    f"{self.protocol.upper()} connection {session} for "
                    f"{dst_if}:{dst} ({dst}) to {src_if}:{src} ({src})")
        return f"<{prio}>{stamp} {host} asa: {body}"

    def _to_fortios_traffic(self) -> str:
        """A FortiOS 7.x traffic log line.

        decoder/fortinet-start/0 gates on the line containing " type=",
        " time=" and " subtype=", and parses '$PRIORITY<_tmp_log>' — so the
        syslog priority prefix is load-bearing, not decoration. The child
        decoder is then selected by string_equal() on the type field, which is
        what routes a session to decoder/fortinet-traffic/0.
        """
        deny = self.action.lower() in _FORTIOS_DENY_ACTIONS
        prio = syslog_priority("local7", "warning" if deny else "notice")
        host = self.hostname or "FGT-01"
        inbound = self.direction.lower() == "inbound"
        src_intf, dst_intf = ("wan1", "internal") if inbound else ("internal", "wan1")
        src_role, dst_role = ("wan", "lan") if inbound else ("lan", "wan")
        fields = [
            f"date={self.timestamp.strftime('%Y-%m-%d')}",
            f"time={self.timestamp.strftime('%H:%M:%S')}",
            f'devname="{host}"',
            f'devid="{_fortigate_serial(host)}"',
            'logid="0000000013"',
            'type="traffic"',
            'subtype="forward"',
            f'level="{"warning" if deny else "notice"}"',
            'vd="root"',
            f"eventtime={int(self.timestamp.timestamp() * 10**9)}",
            f"srcip={self.source_ip or '0.0.0.0'}",
            f"srcport={self.source_port}",
            f'srcintf="{src_intf}"',
            f'srcintfrole="{src_role}"',
            f"dstip={self.dest_ip or '0.0.0.0'}",
            f"dstport={self.dest_port}",
            f'dstintf="{dst_intf}"',
            f'dstintfrole="{dst_role}"',
            f"proto={_PROTO_NUMBER.get(self.protocol.upper(), 6)}",
            f'action="{"deny" if deny else "accept"}"',
            "policyid=1",
            f'service="{self.protocol.upper()}-{self.dest_port}"',
            f'dstcountry="{self.remote_country}"',
            f"sentbyte={self.bytes_sent if self.bytes_sent is not None else 0}",
            f"rcvdbyte={self.bytes_received if self.bytes_received is not None else 0}",
        ]
        return f"<{prio}>" + " ".join(fields)

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
        # DNS Server analytical (256 = QUERY_RECEIVED), not DNS Client 3008.
        # decoder/microsoft-dnsserver-analytical/0 selects on
        # event.dataset == 'microsoft-windows-dnsserver/analytical', which
        # decoder/windows-event/0 derives from downcase(Channel), and then
        # reads QNAME/QTYPE/XID/Destination out of EventData. Server-side
        # analytical logging is also the DNS telemetry a SOC collects; the
        # client channel is endpoint-local and rarely forwarded.
        qtype = _DNS_QTYPE.get(self.query_type.upper(), 1)
        return format_evt_xml(256, "Microsoft-Windows-DNSServer",
                              "Microsoft-Windows-DNSServer/Analytical",
                              self.hostname or "NS", self.timestamp, evt_level("info"),
                              [("QNAME", self.query_name),
                               ("QTYPE", str(qtype)),
                               ("XID", str(int(hashlib.md5(
                                   f"{self.query_name}{self.timestamp.isoformat()}".encode("utf-8")
                               ).hexdigest()[:4], 16))),
                               ("Source", self.source_ip or "0.0.0.0"),
                               ("Destination", self.resolved_ip or "0.0.0.0"),
                               ("RCODE", self.response_code),
                               ("InterfaceIP", self.dest_ip or "0.0.0.0")])

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
