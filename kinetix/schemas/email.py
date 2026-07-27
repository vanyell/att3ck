from typing import Optional, Literal
from pydantic import Field, AliasChoices
from kinetix.schemas.base import BaseLogEvent, syslog_priority, format_syslog, format_evt_xml, evt_level

class EmailEvent(BaseLogEvent):
    source: Literal["Microsoft Defender for Office 365"] = Field("Microsoft Defender for Office 365", alias="SourceSystem")
    event_type: Literal["EmailEvents"] = Field("EmailEvents", alias="Type")

    sender: str = Field(..., alias="SenderFrom", validation_alias=AliasChoices("SenderFrom", "sender", "Sender"))
    recipient: str = Field(..., alias="Recipient", validation_alias=AliasChoices("Recipient", "recipient"))
    subject: str = Field(..., alias="Subject", validation_alias=AliasChoices("Subject", "subject"))
    attachment_verdict: str = Field("NoAttachment", alias="AttachmentVerdict", validation_alias=AliasChoices("AttachmentVerdict", "attachment_verdict"))
    threat_types: Optional[str] = Field(None, alias="ThreatTypes", validation_alias=AliasChoices("ThreatTypes", "threat_types"))
    detection_method: str = Field("None", alias="DetectionMethod", validation_alias=AliasChoices("DetectionMethod", "detection_method"))
    latest_delivery_location: str = Field("Inbox", alias="LatestDeliveryLocation", validation_alias=AliasChoices("LatestDeliveryLocation", "delivery_location"))
    email_direction: str = Field("Inbound", alias="EmailDirection", validation_alias=AliasChoices("EmailDirection", "direction"))

    spf_pass: bool = Field(True, alias="SPFPass")
    dkim_pass: bool = Field(True, alias="DKIMPass")
    dmarc_pass: bool = Field(True, alias="DMARCPass")
    sender_ip: Optional[str] = Field(None, alias="SenderIP", validation_alias=AliasChoices("SenderIP", "sender_ip"))

    phish_score: Optional[int] = Field(None, alias="PhishScore")
    malware_score: Optional[int] = Field(None, alias="MalwareScore")

    def to_syslog(self) -> str:
        prio = syslog_priority("mail", "warning" if self.is_malicious else "info")
        return format_syslog(prio, self.timestamp, self.hostname or "MAIL", "msexchange",
                             0, f"Email from={self.sender} to={self.recipient} subject={self.subject} verdict={self.attachment_verdict}")

    def to_evt(self) -> str:
        return format_evt_xml(1033, "MSExchange Messaging", "Application",
                              self.hostname or "MAIL", self.timestamp,
                              evt_level("err" if self.is_malicious else "info"),
                              [("Sender", self.sender), ("Recipient", self.recipient),
                               ("Subject", self.subject),
                               ("AttachmentVerdict", self.attachment_verdict)])
