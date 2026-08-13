from typing import Optional, List, Dict, Any, Literal
import uuid
import random
from pydantic import Field, AliasChoices
from kinetix.schemas.base import BaseLogEvent, syslog_priority, format_syslog, format_evt_xml, evt_level

class EndpointEvent(BaseLogEvent):
    device_id: str = Field(default_factory=lambda: str(uuid.uuid4()), alias="DeviceId")
    report_id: int = Field(default_factory=lambda: random.randint(10000, 99999), alias="ReportId")
    action_type: str = Field(..., alias="ActionType", validation_alias=AliasChoices("ActionType", "action"))

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
        return format_evt_xml(4688, "Microsoft-Windows-Security-Auditing", "Security",
                              self.hostname or "WKS", self.timestamp, evt_level("info"),
                              [("NewProcessName", self.file_name),
                               ("CreatorProcessName", self.parent_process_name or ""),
                               ("ProcessId", str(self.process_id)),
                               ("CommandLine", self.command_line)])

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
        return format_evt_xml(4663, "Microsoft-Windows-Security-Auditing", "Security",
                              self.hostname or "WKS", self.timestamp, evt_level("info"),
                              [("ObjectName", f"{self.folder_path}\\{self.file_name}"),
                               ("AccessMask", self.action_type)])

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
        return format_evt_xml(4657, "Microsoft-Windows-Security-Auditing", "Security",
                              self.hostname or "WKS", self.timestamp, evt_level("info"),
                              [("ObjectName", self.key_path),
                               ("ObjectValueName", self.value_name or ""),
                               ("ObjectValue", self.value_data or "")])
