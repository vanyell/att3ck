from typing import Optional, List, Dict, Any, Literal
from pydantic import Field, AliasChoices
from kinetix.schemas.base import BaseLogEvent

class FirewallEvent(BaseLogEvent):
    source: Literal["Firewall"] = Field("Firewall", alias="SourceSystem")
    event_type: Literal["CommonSecurityLog"] = Field("CommonSecurityLog", alias="Type")
    
    action: str = Field(..., alias="DeviceAction", validation_alias=AliasChoices("DeviceAction", "action"))
    protocol: str = Field(..., alias="Protocol", validation_alias=AliasChoices("Protocol", "protocol"))
    source_port: int = Field(..., alias="SourcePort", validation_alias=AliasChoices("SourcePort", "source_port"))
    dest_port: int = Field(..., alias="DestinationPort", validation_alias=AliasChoices("DestinationPort", "dest_port"))
    
    # --- Analyst Pivot Fields ---
    direction: str = Field("Outbound", alias="NetworkDirection", validation_alias=AliasChoices("NetworkDirection", "direction"))
    remote_country: str = Field("US", alias="RemoteCountry")
    remote_asn: str = Field("MSFT", alias="RemoteASN")
    
    bytes_sent: Optional[int] = Field(None, alias="SentBytes", validation_alias=AliasChoices("SentBytes", "bytes_sent"))
    bytes_received: Optional[int] = Field(None, alias="ReceivedBytes", validation_alias=AliasChoices("ReceivedBytes", "bytes_received"))

class DNSEvent(BaseLogEvent):
    source: Literal["DNS"] = Field("DNS", alias="SourceSystem")
    event_type: Literal["DnsEvents"] = Field("DnsEvents", alias="Type")
    
    query_name: str = Field(..., alias="Name", validation_alias=AliasChoices("Name", "query_name"))
    query_type: str = Field("A", alias="QueryType", validation_alias=AliasChoices("QueryType", "query_type"))
    response_code: str = Field("0", alias="ResultCode", validation_alias=AliasChoices("ResultCode", "response_code"))
    resolved_ip: Optional[str] = Field(None, alias="IPAddresses", validation_alias=AliasChoices("IPAddresses", "resolved_ip"))

class ProxyEvent(BaseLogEvent):
    source: Literal["Proxy"] = Field("Proxy", alias="SourceSystem")
    event_type: Literal["W3CIISLog"] = Field("W3CIISLog", alias="Type")
    
    url: str = Field(..., alias="RequestURL", validation_alias=AliasChoices("RequestURL", "url"))
    http_method: str = Field(..., alias="Method", validation_alias=AliasChoices("Method", "http_method"))
    http_status: int = Field(..., alias="Status", validation_alias=AliasChoices("Status", "http_status"))
    user_agent: str = Field(..., alias="UserAgent", validation_alias=AliasChoices("UserAgent", "user_agent"))
    content_type: Optional[str] = Field(None, alias="ContentType")
