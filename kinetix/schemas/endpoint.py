from typing import Optional, List, Dict, Any, Literal
import uuid
import random
from pydantic import Field, AliasChoices
from kinetix.schemas.base import BaseLogEvent, syslog_priority, format_syslog, format_evt_xml, evt_level

class EndpointEvent(BaseLogEvent):
    device_id: str = Field(default_factory=lambda: str(uuid.uuid4()), alias="DeviceId")
    report_id: int = Field(default_factory=lambda: random.randint(10000, 99999), alias="ReportId")
    action_type: str = Field(..., alias="ActionType", validation_alias=AliasChoices("ActionType", "action"))

    # Real column on every Device* advanced-hunting table (DeviceProcessEvents,
    # DeviceFileEvents, DeviceRegistryEvents, DeviceEvents): "string" type,
    # "Additional information about the entity or event" (verified against
    # Microsoft Learn's advanced-hunting schema reference for these tables).
    additional_fields: Optional[str] = Field(None, alias="AdditionalFields", validation_alias=AliasChoices("AdditionalFields", "additional_fields"))

class ProcessEvent(EndpointEvent):
    source: Literal["endpoint"] = Field("endpoint", alias="SourceSystem")
    event_type: Literal["DeviceProcessEvents"] = Field("DeviceProcessEvents", alias="Type")
    action_type: str = Field("ProcessCreated", alias="ActionType", validation_alias=AliasChoices("ActionType", "action"))
    
    file_name: str = Field(..., alias="FileName", validation_alias=AliasChoices("FileName", "process_name", "file_name"))
    folder_path: str = Field("C:\\Windows\\System32", alias="FolderPath", validation_alias=AliasChoices("FolderPath", "image_path", "folder_path"))
    process_id: int = Field(..., alias="ProcessId", validation_alias=AliasChoices("ProcessId", "process_id"))
    command_line: str = Field(..., alias="ProcessCommandLine", validation_alias=AliasChoices("ProcessCommandLine", "command_line"))
    
    integrity_level: str = Field("Medium", alias="ProcessIntegrityLevel")
    token_elevation: str = Field("TokenElevationTypeLimited", alias="TokenElevationType")
    is_signed: bool = Field(True, alias="IsSigned")
    signer: Optional[str] = Field("Microsoft Windows", alias="Signer")
    
    parent_process_name: Optional[str] = Field(None, alias="InitiatingProcessFileName", validation_alias=AliasChoices("InitiatingProcessFileName", "parent_process_name"))
    parent_process_id: Optional[int] = Field(None, alias="InitiatingProcessId", validation_alias=AliasChoices("InitiatingProcessId", "parent_process_id"))
    parent_command_line: Optional[str] = Field(None, alias="InitiatingProcessCommandLine", validation_alias=AliasChoices("InitiatingProcessCommandLine", "parent_command_line"))
    parent_integrity_level: Optional[str] = Field(None, alias="InitiatingProcessIntegrityLevel")
    
    sha1: Optional[str] = Field(None, alias="SHA1", validation_alias=AliasChoices("SHA1", "sha1"))
    sha256: Optional[str] = Field(None, alias="SHA256")

    def to_syslog(self) -> str:
        prio = syslog_priority("user", "info")
        return format_syslog(prio, self.timestamp, self.hostname or "WKS", "Microsoft-Windows-Security-Auditing",
                              self.process_id, f"Process Created: {self.file_name} Cmd={self.command_line} User={self.user_name}")

    def to_evt(self) -> str:
        # Real 4688 semantics (verified against a live Wazuh 5.0 engine's
        # decoder/windows-security/0 asset): NewProcessId is the created
        # process's PID, ProcessId is the CREATOR/parent's PID, and both are
        # hex strings — the engine applies hex_to_number() to them. The
        # decoder also expects ParentProcessName, not CreatorProcessName.
        parent_pid = self.parent_process_id if self.parent_process_id is not None else 0
        return format_evt_xml(4688, "Microsoft-Windows-Security-Auditing", "Security",
                              self.hostname or "WKS", self.timestamp, evt_level("info"),
                              [("NewProcessId", f"0x{self.process_id:x}"),
                               ("NewProcessName", f"{self.folder_path}\\{self.file_name}"),
                               ("ProcessId", f"0x{parent_pid:x}"),
                               ("ParentProcessName", self.parent_process_name or ""),
                               ("CommandLine", self.command_line)])

class DeviceGenericEvent(EndpointEvent):
    """Catch-all Defender for Endpoint 'DeviceEvents' table — heterogeneous
    action types (USB plug/unplug, tamper protection, etc.) with no single
    dedicated schema."""
    source: Literal["endpoint"] = Field("endpoint", alias="SourceSystem")
    event_type: Literal["DeviceEvents"] = Field("DeviceEvents", alias="Type")

    def to_syslog(self) -> str:
        prio = syslog_priority("user", "info")
        return format_syslog(prio, self.timestamp, self.hostname or "WKS", "Microsoft-Windows-Security-Auditing",
                              0, f"DeviceEvent: {self.action_type}")

    def to_evt(self) -> str:
        # DeviceEvents covers many unrelated action types with no single real
        # EVTX ID — synthetic provider/ID, not impersonating a specific real event.
        return format_evt_xml(9106, "Kinetix-DeviceEvents", "Application",
                              self.hostname or "WKS", self.timestamp, evt_level("info"),
                              [("ActionType", self.action_type)])


class FileEvent(EndpointEvent):
    source: Literal["endpoint"] = Field("endpoint", alias="SourceSystem")
    event_type: Literal["DeviceFileEvents"] = Field("DeviceFileEvents", alias="Type")
    action_type: str = Field("FileModified", alias="ActionType", validation_alias=AliasChoices("ActionType", "action"))
    
    file_name: str = Field(..., alias="FileName", validation_alias=AliasChoices("FileName", "file_name"))
    folder_path: str = Field(..., alias="FolderPath", validation_alias=AliasChoices("FolderPath", "file_path", "folder_path"))
    sha1: Optional[str] = Field(None, alias="SHA1", validation_alias=AliasChoices("SHA1", "sha1"))
    file_size: Optional[int] = Field(None, alias="FileSize", validation_alias=AliasChoices("FileSize", "file_size"))
    
    initiating_process_file_name: Optional[str] = Field(None, alias="InitiatingProcessFileName")

    def to_syslog(self) -> str:
        prio = syslog_priority("user", "info")
        return format_syslog(prio, self.timestamp, self.hostname or "WKS", "Microsoft-Windows-Security-Auditing",
                               0, f"File {self.action_type}: {self.folder_path}\\{self.file_name}")

    def to_evt(self) -> str:
        # Not 4663: decoder/windows-event/0 carries the ruleset's only
        # discard_events() block and 4663 is on it, so the engine drops the
        # event after decoding it — ingest-verified as zero indexed documents
        # for four separate 4663 shapes, including a fully Microsoft-faithful
        # one. Sysmon's file events are not on that list and decode through
        # decoder/windows-sysmon/0, which gates on the provider name.
        deleted = "delete" in self.action_type.lower()
        return format_evt_xml(23 if deleted else 11, "Microsoft-Windows-Sysmon",
                              "Microsoft-Windows-Sysmon/Operational",
                              self.hostname or "WKS", self.timestamp, evt_level("info"),
                              [("RuleName", self.action_type),
                               ("UtcTime", self.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]),
                               ("Image", self.initiating_process_file_name or ""),
                               ("TargetFilename", f"{self.folder_path}\\{self.file_name}"),
                               ("User", self.user_name or "")])

class RegistryEvent(EndpointEvent):
    source: Literal["endpoint"] = Field("endpoint", alias="SourceSystem")
    event_type: Literal["DeviceRegistryEvents"] = Field("DeviceRegistryEvents", alias="Type")
    action_type: str = Field("RegistryValueSet", alias="ActionType", validation_alias=AliasChoices("ActionType", "action"))
    
    key_path: str = Field(..., alias="RegistryKey", validation_alias=AliasChoices("RegistryKey", "key_path"))
    value_name: Optional[str] = Field(None, alias="RegistryValueName", validation_alias=AliasChoices("RegistryValueName", "value_name"))
    value_data: Optional[str] = Field(None, alias="RegistryValueData", validation_alias=AliasChoices("RegistryValueData", "value_data"))
    
    initiating_process_file_name: Optional[str] = Field(None, alias="InitiatingProcessFileName")

    def to_syslog(self) -> str:
        prio = syslog_priority("user", "info")
        return format_syslog(prio, self.timestamp, self.hostname or "WKS", "Microsoft-Windows-Security-Auditing",
                               0, f"Registry {self.action_type}: Key={self.key_path} Name={self.value_name}")

    def to_evt(self) -> str:
        # Real 4657 field is "NewValue", not "ObjectValue" (verified against
        # a live Wazuh 5.0 engine's decoder/windows-security/0 asset, which
        # maps registry.data.strings from EventData.NewValue).
        return format_evt_xml(4657, "Microsoft-Windows-Security-Auditing", "Security",
                              self.hostname or "WKS", self.timestamp, evt_level("info"),
                              [("ObjectName", self.key_path),
                               ("ObjectValueName", self.value_name or ""),
                               ("NewValue", self.value_data or "")])
