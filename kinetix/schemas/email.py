import uuid
from typing import Optional, Literal
from pydantic import Field, AliasChoices, computed_field
from kinetix.schemas.base import BaseLogEvent, syslog_priority, format_syslog, format_evt_xml, evt_level

class EmailEvent(BaseLogEvent):
    source: Literal["Microsoft Defender for Office 365"] = Field("Microsoft Defender for Office 365", alias="SourceSystem")
    event_type: Literal["EmailEvents"] = Field("EmailEvents", alias="Type")

    # Real EmailEvents table field names (SenderFromAddress/RecipientEmailAddress/
    # DetectionMethods) — validation_alias keeps accepting the shorter authoring
    # keys used throughout scenarios/*.json.
    sender: str = Field(..., alias="SenderFromAddress", validation_alias=AliasChoices("SenderFromAddress", "SenderFrom", "sender", "Sender"))
    recipient: str = Field(..., alias="RecipientEmailAddress", validation_alias=AliasChoices("RecipientEmailAddress", "Recipient", "recipient"))
    subject: str = Field(..., alias="Subject", validation_alias=AliasChoices("Subject", "subject"))
    attachment_verdict: str = Field("NoAttachment", alias="AttachmentVerdict", validation_alias=AliasChoices("AttachmentVerdict", "attachment_verdict"))
    threat_types: Optional[str] = Field(None, alias="ThreatTypes", validation_alias=AliasChoices("ThreatTypes", "threat_types"))
    detection_method: str = Field("None", alias="DetectionMethods", validation_alias=AliasChoices("DetectionMethods", "DetectionMethod", "detection_method"))
    latest_delivery_location: str = Field("Inbox", alias="LatestDeliveryLocation", validation_alias=AliasChoices("LatestDeliveryLocation", "delivery_location"))
    email_direction: str = Field("Inbound", alias="EmailDirection", validation_alias=AliasChoices("EmailDirection", "direction"))

    # Real EmailEvents has no SPFPass/DKIMPass/DMARCPass booleans — auth results
    # are string verdicts packed into AuthenticationDetails. Keep the booleans as
    # authoring-friendly inputs (exclude=True: not serialized under a fake name)
    # and expose the real field as a computed property below.
    spf_pass: bool = Field(True, alias="SPFPass", exclude=True)
    dkim_pass: bool = Field(True, alias="DKIMPass", exclude=True)
    dmarc_pass: bool = Field(True, alias="DMARCPass", exclude=True)
    sender_ip: Optional[str] = Field(None, alias="SenderIP", validation_alias=AliasChoices("SenderIP", "sender_ip"))

    phish_score: Optional[int] = Field(None, alias="PhishScore")
    malware_score: Optional[int] = Field(None, alias="MalwareScore")

    network_message_id: str = Field(default_factory=lambda: str(uuid.uuid4()), alias="NetworkMessageId", validation_alias=AliasChoices("NetworkMessageId", "network_message_id"))
    internet_message_id: Optional[str] = Field(None, alias="InternetMessageId", validation_alias=AliasChoices("InternetMessageId", "internet_message_id"))
    attachment_count: int = Field(0, alias="AttachmentCount", validation_alias=AliasChoices("AttachmentCount", "attachment_count"))
    url_count: int = Field(0, alias="UrlCount", validation_alias=AliasChoices("UrlCount", "url_count"))

    # Real EmailEvents columns (verified against Microsoft Learn's advanced-
    # hunting schema reference) previously missing from this schema.
    recipient_object_id: Optional[str] = Field(None, alias="RecipientObjectId", validation_alias=AliasChoices("RecipientObjectId", "recipient_object_id"))
    sender_object_id: Optional[str] = Field(None, alias="SenderObjectId", validation_alias=AliasChoices("SenderObjectId", "sender_object_id"))
    sender_display_name: Optional[str] = Field(None, alias="SenderDisplayName", validation_alias=AliasChoices("SenderDisplayName", "sender_display_name"))
    threat_names: Optional[str] = Field(None, alias="ThreatNames", validation_alias=AliasChoices("ThreatNames", "threat_names"))
    confidence_level: Optional[str] = Field(None, alias="ConfidenceLevel", validation_alias=AliasChoices("ConfidenceLevel", "confidence_level"))
    bulk_complaint_level: Optional[int] = Field(None, alias="BulkComplaintLevel", validation_alias=AliasChoices("BulkComplaintLevel", "bulk_complaint_level"))
    email_cluster_id: Optional[int] = Field(None, alias="EmailClusterId", validation_alias=AliasChoices("EmailClusterId", "email_cluster_id"))
    additional_fields: Optional[str] = Field(None, alias="AdditionalFields", validation_alias=AliasChoices("AdditionalFields", "additional_fields"))

    @computed_field(alias="AuthenticationDetails")
    @property
    def authentication_details(self) -> str:
        def verdict(passed: bool) -> str:
            return "pass" if passed else "fail"
        return f"SPF: {verdict(self.spf_pass)}; DKIM: {verdict(self.dkim_pass)}; DMARC: {verdict(self.dmarc_pass)}"

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


class EmailAttachmentEvent(BaseLogEvent):
    """Microsoft Defender for Office 365 'EmailAttachmentInfo' table — per-
    attachment verdict, decoupled from the parent EmailEvents record."""
    source: Literal["Microsoft Defender for Office 365"] = Field("Microsoft Defender for Office 365", alias="SourceSystem")
    event_type: Literal["EmailAttachmentInfo"] = Field("EmailAttachmentInfo", alias="Type")

    file_name: str = Field(..., alias="FileName", validation_alias=AliasChoices("FileName", "file_name"))
    verdict: str = Field("Clean", alias="Verdict", validation_alias=AliasChoices("Verdict", "verdict"))
    sha256: Optional[str] = Field(None, alias="SHA256")
    network_message_id: str = Field(default_factory=lambda: str(uuid.uuid4()), alias="NetworkMessageId")

    def to_syslog(self) -> str:
        prio = syslog_priority("mail", "warning" if self.verdict.lower() != "clean" else "info")
        return format_syslog(prio, self.timestamp, self.hostname or "MAIL", "msexchange", 0,
                              f"Attachment {self.file_name} verdict={self.verdict}")

    def to_evt(self) -> str:
        return format_evt_xml(1034, "MSExchange Messaging", "Application",
                              self.hostname or "MAIL", self.timestamp,
                              evt_level("err" if self.verdict.lower() != "clean" else "info"),
                              [("FileName", self.file_name), ("Verdict", self.verdict)])
