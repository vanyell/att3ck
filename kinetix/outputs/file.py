import os
import threading
import orjson
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime
from kinetix.outputs.base import OutputProvider
from kinetix.schemas.base import BaseLogEvent, cef_severity

logger = logging.getLogger(__name__)

# L4: Internal generator metadata that should NOT appear in SIEM output
_INTERNAL_FIELDS = {"is_malicious", "scenario_id", "depth", "killchain_phase"}

class FileOutput(OutputProvider):
    def __init__(self, output_dir: str, max_bytes: int = 10 * 1024 * 1024, backup_count: int = 5):
        """
        output_dir: Directory where separate log files will be created.
        max_bytes: Max size of each log file (default 10MB).
        backup_count: Number of rotated backup files to keep.
        """
        self.output_dir = output_dir
        self.max_bytes = max_bytes
        self.backup_count = backup_count
        self.loggers = {}
        self._lock = threading.Lock()  # C1: Thread-safe logger creation
        
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
            
        # Unified feeds for SIEMS (Splunk/ELK/Sentinel/Arcsight)
        self.unified_json_logger = self._get_rotating_logger("Unified_JSON", "Kinetix_Unified.json")
        self.unified_cef_logger = self._get_rotating_logger("Unified_CEF", "Kinetix_Unified.log")
        self.unified_syslog_logger = self._get_rotating_logger("Unified_Syslog", "Kinetix_Syslog.log")
        self.unified_evt_logger = self._get_rotating_logger("Unified_EVT", "Kinetix_EVTX.log")
        self.unified_auditd_logger = self._get_rotating_logger("Unified_Auditd", "Kinetix_Auditd.log")

    def _get_rotating_logger(self, name: str, filename: str) -> logging.Logger:
        """Creates a logger with a RotatingFileHandler and no formatting."""
        log_path = os.path.join(self.output_dir, filename)
        lgr = logging.getLogger(f"kinetix.output.{name}")
        lgr.setLevel(logging.INFO)
        lgr.propagate = False
        
        # Clear existing handlers if any (re-init safety)
        if lgr.hasHandlers():
            lgr.handlers.clear()
            
        handler = RotatingFileHandler(
            log_path, 
            maxBytes=self.max_bytes, 
            backupCount=self.backup_count, 
            encoding="utf-8"
        )
        # Use a formatter that only outputs the message (raw JSON)
        handler.setFormatter(logging.Formatter("%(message)s"))
        lgr.addHandler(handler)
        return lgr

    def _get_logger(self, event: BaseLogEvent) -> logging.Logger:
        table_name = self._map_to_table_name(event)
        key = f"{table_name}_json"
        
        # C1: Double-checked locking for thread-safe lazy initialization
        if key not in self.loggers:
            with self._lock:
                if key not in self.loggers:
                    full_filename = f"{table_name}.json"
                    self.loggers[key] = self._get_rotating_logger(key, full_filename)
        return self.loggers[key]

    def _map_to_table_name(self, event: BaseLogEvent) -> str:
        # If the event_type is already a recognized Sentinel table name, use it directly
        # For specialized models, event_type is forced via Literal (e.g. DeviceProcessEvents)
        sentinel_tables = [
            "DeviceProcessEvents", "DeviceFileEvents", "DeviceNetworkEvents",
            "DeviceRegistryEvents", "DeviceLogonEvents", "DeviceEvents",
            "SecurityAlert", "SecurityIncident", "SigninLogs", "AuditLogs",
            "AADNonInteractiveUserSignInLogs", "IdentityLogonEvents",
            "OfficeActivity", "AzureActivity", "CloudAppEvents",
            "CommonSecurityLog", "DnsEvents", "W3CIISLog", "AzureDiagnostics",
            "DatabaseAuditExport_CL", "LinuxAuditLog", "Syslog",
            "EmailEvents", "EmailAttachmentInfo",
        ]
        
        if event.event_type in sentinel_tables:
            return event.event_type

        source = event.source.lower()
        mapping = {
            "incident": "SecurityIncident",
            "alert": "SecurityAlert",
            "sentinel_audit": "SentinelAudit",
            "firewall": "CommonSecurityLog",
            "proxy": "W3CIISLog",
            "vpn": "CommonSecurityLog",
            "auth": "SecurityEvent",
            "signin": "SigninLogs",
            "office365": "OfficeActivity",
            "dns": "DnsEvents",
            "syslog": "Syslog",
            "web": "W3CIISLog",
            "db": "AzureDiagnostics",
            "linux": "LinuxAuditLog",
            "macos": "Syslog",
            "mdo_email": "EmailEvents",
            "email": "EmailEvents",
            "cloud_app": "CloudAppEvents",
            "identity": "IdentityLogonEvents",
            "non_interactive": "AADNonInteractiveUserSignInLogs",
        }
        if source in mapping:
            return mapping[source]

        # Neither event_type nor source matched a known table -- this means a
        # schema was added without a corresponding entry here. Silently
        # guessing a filename (the old `source.capitalize()` fallback) hid
        # that gap and could scatter events into an arbitrary, likely-wrong
        # table file. Log it loudly and use an unmistakable fallback name so
        # the gap gets noticed and fixed instead of silently accepted.
        logger.warning(
            "No table mapping for event_type=%r source=%r -- add an entry to "
            "sentinel_tables or the source->table mapping in _map_to_table_name(). "
            "Writing to Unmapped_%s.json in the meantime.",
            event.event_type, event.source, source.capitalize()
        )
        return f"Unmapped_{source.capitalize()}"

    def write(self, event: BaseLogEvent):
        # 1. Write to individual Sentinel-ready JSON tables
        lgr = self._get_logger(event)
        json_entry = self._format_json(event)
        lgr.info(json_entry)
        
        # 2. Write to Unified JSON feed (Splunk/ELK/Sentinel generic ingestion)
        self.unified_json_logger.info(json_entry)
        
        # 3. Write to Unified CEF feed (Legacy SIEMs like Arcsight/QRadar)
        cef_entry = self._format_cef(event)
        self.unified_cef_logger.info(cef_entry)

        # 4. Write to Unified Syslog feed (Wazuh/Linux/Mac/Network syslog)
        syslog_entry = self._format_syslog(event)
        self.unified_syslog_logger.info(syslog_entry)

        # 5. Write to EVT feed (Windows Event XML for Wazuh/SIEM)
        # Windows-native events only: endpoint, auth, security, db.
        # Non-Windows appliance/service sources (linux, macos, firewall, dns,
        # proxy, web) skip EVT — they'd never emit real Windows Event Log entries.
        if not self._is_syslog_event(event):
            evt_entry = self._format_evt(event)
            self.unified_evt_logger.info(evt_entry)

        # 6. Write to auditd feed (Linux auditd wire format for Wazuh).
        # Self-gating: to_auditd() returns [] for every source with no auditd
        # equivalent, so unlike the EVT feed there is no source list to keep
        # in sync. Wazuh 5.0's auditd decoder only accepts lines starting
        # `type=` or `node=`; anything else it silently discards.
        for auditd_entry in event.to_auditd():
            self.unified_auditd_logger.info(auditd_entry)

    # Sources backed by non-Windows appliances/services that never emit native
    # Windows Event Log entries in real life (network appliances, DNS servers,
    # web/proxy servers) — these should only appear in JSON/CEF/syslog output.
    _NON_WINDOWS_SOURCES = {"linux", "macos", "firewall", "proxy", "dns", "web", "azure", "cloud app security"}

    def _is_syslog_event(self, event: BaseLogEvent) -> bool:
        """Return True if event should only go to syslog/CEF/JSON, never fabricated EVTX."""
        return event.source.lower() in self._NON_WINDOWS_SOURCES

    def _format_json(self, event: BaseLogEvent) -> str:
        # L4: Exclude internal generator metadata from SIEM output
        event_dict = event.model_dump(by_alias=True, exclude=_INTERNAL_FIELDS)
        json_bytes = orjson.dumps(event_dict)
        return json_bytes.decode("utf-8")

    def _format_cef(self, event: BaseLogEvent) -> str:
        """
        Dynamic CEF implementation. Automatically maps any fields not in the 
        standard header to csN / csNLabel extensions.
        """
        vendor = "Kinetix"
        product = event.source.capitalize()
        dev_version = "1.1"
        event_class_id = event.event_type
        name = f"Kinetix {event.event_type} event"
        severity = cef_severity(event.severity)  # CEF requires an integer 0-10
        
        # 1. Base Extensions (Standard CEF keys)
        # rt = reception time (epoch ms)
        extensions = [
            f"rt={int(event.timestamp.timestamp() * 1000)}",
            f"src={event.source_ip or ''}",
            f"dst={event.dest_ip or ''}",
            f"suser={event.user_name or ''}",
            f"shost={event.hostname or ''}",
            f"msg={event.scenario_id or ''}",
            f"externalId={event.correlation_id or ''}" # Pivot anchor
        ]
        
        # 2. Identify fields to exclude (already in header or fixed extensions)
        # We use ALIASED names because that's what the models dump
        consumed_fields = {
            "TimeGenerated", "SourceSystem", "Type", "AlertSeverity",
            "IPAddress", "DestinationIP", "AccountName", "DeviceName",
            "CorrelationId", "Id", "TenantId",
            "OSPlatform", "DeviceCategory", "IsManaged", "AccountSid"
        }
        
        # 3. Dynamic Field Mapping
        # Use model_dump to get ALL fields (including those from subclasses)
        full_data = event.model_dump(by_alias=True, exclude=_INTERNAL_FIELDS)
        
        cs_index = 1
        
        # MITRE ATT&CK Info (Special handling for legacy consistency)
        if event.mitre:
            extensions.append(f"cs{cs_index}Label=MitreTactic cs{cs_index}={event.mitre.tactic}")
            cs_index += 1
            extensions.append(f"cs{cs_index}Label=MitreTechniqueId cs{cs_index}={event.mitre.technique_id}")
            cs_index += 1
            extensions.append(f"cs{cs_index}Label=MitreTechniqueName cs{cs_index}={event.mitre.technique_name}")
            cs_index += 1
            consumed_fields.add("mitre")

        # Generic Loop over remaining fields.
        # CEF (ArcSight Common Event Format) defines exactly 6 custom-string
        # extensions (cs1-cs6) -- this is a real spec limit, not an arbitrary
        # cap, so it must not be widened (cs7+ would be non-standard and could
        # break real CEF parsers/Sentinel-CEF or Wazuh CEF ingestion). Any
        # field-heavy schema (e.g. email/identity) will genuinely lose fields
        # in CEF output; the full data is still available via JSON output.
        # What was silent before was the truncation itself -- log it instead
        # so it's visible which fields were dropped for which event.
        dropped = []
        for field_name, value in full_data.items():
            if field_name in consumed_fields or value is None:
                continue

            # Skip complex objects (except we already excluded mitre/d3fend/data if empty)
            if isinstance(value, (dict, list)):
                continue

            if cs_index > 6:
                dropped.append(field_name)
                continue

            # Formatting value: ensure no pipes or newlines which break CEF
            clean_val = str(value).replace("|", "\\|").replace("\n", " ").replace("\r", " ")
            extensions.append(f"cs{cs_index}Label={field_name} cs{cs_index}={clean_val}")
            cs_index += 1

        if dropped:
            logger.debug(
                "CEF cs1-cs6 limit reached for %s event %s; dropped fields not "
                "representable in CEF: %s (full data still in JSON output)",
                event.event_type, event.event_id, dropped
            )

        # Flatten string
        ext_str = " ".join([e for e in extensions if "=" in e and e.split("=")[1]])
        
        cef_line = f"CEF:0|{vendor}|{product}|{dev_version}|{event_class_id}|{name}|{severity}|{ext_str}"
        return cef_line

    def _format_syslog(self, event: BaseLogEvent) -> str:
        return event.to_syslog()

    def _format_evt(self, event: BaseLogEvent) -> str:
        return event.to_evt()

    def flush(self):
        pass

    def close(self):
        all_loggers = list(self.loggers.values()) + [self.unified_json_logger, self.unified_cef_logger, self.unified_syslog_logger, self.unified_evt_logger, self.unified_auditd_logger]
        for lgr in all_loggers:
            for handler in lgr.handlers:
                handler.close()
        self.loggers = {}
