"""
Offline corpus mining tool for Kinetix (Phase 2.1).

Ingests public/sample log corpora (Splunk BOTS exports, EVTX-ATTACK-SAMPLES
converted to JSON, Sentinel sample-data-connector exports, Wazuh alerts.json,
etc.) and extracts per-table field-value distributions and vendor quirks into
versioned "corpus profiles" under kinetix/intelligence/corpus_profiles/.

This is a one-way, offline extraction step. It never runs as part of the live
simulation (main.py / KinetixEngine) and it never stores raw records. Fields
classified as identifiers (IPs, hostnames, usernames, emails, GUIDs, etc.) are
reduced to a structural signature before anything is counted or written to
disk -- only "freeform" fields (user agents, command-line shapes, file paths,
ports, protocols, rule groups) have their actual values pooled, since those
carry format realism without carrying entity identity.

Input formats supported: JSON array, JSON Lines (one object per line), and CSV
(rows are treated as flat dicts). Nested dicts/lists in JSON/JSONL records are
flattened with "." join for classification purposes.

Usage:
    python3 scripts/mine_corpus.py --input samples/bots_v3_notable.jsonl \\
        --format jsonl --table-field EventType \\
        --output-dir kinetix/intelligence/corpus_profiles

    python3 scripts/mine_corpus.py --input samples/wazuh_alerts.json \\
        --format json --table SecurityAlert \\
        --output-dir kinetix/intelligence/corpus_profiles

Each run merges into any existing profile file for the same table rather than
overwriting it, so multiple corpora can be mined incrementally.
"""

import csv
import json
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

import click

# --- Field classification -------------------------------------------------
# "identifier" fields are never stored verbatim -- only a structural shape
# token is counted, so mined profiles can't leak real entities from a corpus.
# "freeform" fields are stored as a weighted value pool (bounded, most-common
# values only) since their format/cardinality is what makes noise realistic.

IDENTIFIER_NAME_HINTS = (
    "ip", "addr", "host", "hostname", "user", "account", "email", "sender",
    "recipient", "guid", "sid", "domain", "workstation", "device", "tenant",
    "objectid", "object", "upn", "computer",
)

_IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_IPV4_PORT_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}:\d+$")
_IPV6_PORT_RE = re.compile(r"^\[[0-9a-fA-F:.]+\]:\d+$")
_GUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_FQDN_RE = re.compile(r"^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$")
_SID_RE = re.compile(r"^S-1-5-[\d-]+$")
# Windows "DOMAIN\user" / "HOST\user" account form -- exactly one backslash,
# and neither side looks like a filesystem path or command segment (no dots,
# since real NetBIOS domain/host/account names never contain one, but
# executables/scripts/paths reliably do -- e.g. "cmd.exe\1" or "Import-Module
# .\Invoke-Obfuscation.psd1" would otherwise false-positive here). Confirmed
# against mined DeviceNetworkEvents data during development:
# EventData.jobOwner/username carried real account names like
# "MSEDGEWIN10\IEUser" that the name-hint check alone missed.
_ACCOUNT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _-]{0,63}\\[A-Za-z0-9][A-Za-z0-9 _-]{0,63}$")

# Freeform fields that should be pooled by *value* even though the name might
# look identifier-ish (e.g. "user_agent" contains no PII by itself).
FREEFORM_NAME_OVERRIDES = (
    "agent", "url", "uri", "path", "command", "cmdline", "process", "port",
    "protocol", "method", "status", "action", "rule", "group", "severity",
    "category", "type", "extension", "mime",
)

MAX_POOL_SIZE = 200  # cap on distinct freeform values retained per field

_TOKEN_RE = re.compile(r"[A-Z]+(?=[A-Z][a-z])|[A-Z][a-z]*|[a-z]+|[0-9]+")


def _tokenize(name: str) -> List[str]:
    """Split a dotted/PascalCase/snake_case field path into lowercase words.

    Whole-word matching (vs. naive substring containment) avoids false
    positives like "ip" matching inside "Description" or "sid" inside
    "Inside"/"Consider" -- confirmed against real EVTX field names during
    development (EventData.Description was misclassified as an identifier
    before this fix).
    """
    return [t.lower() for t in _TOKEN_RE.findall(name.replace(".", " ").replace("_", " "))]


def classify_field(name: str, value: Any) -> str:
    """Return "identifier" or "freeform" for a flattened field name/value.

    Structural value shape (GUID/IPv4/email/SID) is checked before name-based
    hints/overrides and always wins: a field like "ParentProcessGuid" contains
    the freeform-override token "process" (from "ProcessCommandLine"-style
    fields), but its *value* is GUID-shaped, so it must still be treated as an
    identifier -- confirmed against real EVTX Sysmon data during development,
    where the override token was otherwise winning and pooling raw GUIDs.
    """
    if isinstance(value, str):
        if (
            _IPV4_RE.match(value)
            or _IPV4_PORT_RE.match(value)
            or _IPV6_PORT_RE.match(value)
            or _GUID_RE.match(value)
            or _EMAIL_RE.match(value)
            or _SID_RE.match(value)
            or _ACCOUNT_RE.match(value)
        ):
            return "identifier"
    tokens = set(_tokenize(name))
    if tokens & set(FREEFORM_NAME_OVERRIDES):
        return "freeform"
    if tokens & set(IDENTIFIER_NAME_HINTS):
        return "identifier"
    if isinstance(value, str) and _FQDN_RE.match(value) and "." in value and len(value.split(".")) <= 4:
        return "identifier"
    return "freeform"


def shape_token(value: Any) -> str:
    """Reduce an identifier value to a structural signature, never the raw value."""
    if not isinstance(value, str):
        return type(value).__name__
    if _IPV4_RE.match(value):
        return "ipv4"
    if _IPV4_PORT_RE.match(value):
        return "ipv4:port"
    if _IPV6_PORT_RE.match(value):
        return "ipv6:port"
    if _ACCOUNT_RE.match(value):
        return "account:domain_user"
    if _GUID_RE.match(value):
        return "guid"
    if _EMAIL_RE.match(value):
        local, _, dom = value.partition("@")
        return f"email:local_len={len(local)}:domain_labels={len(dom.split('.'))}"
    if _SID_RE.match(value):
        return f"sid:parts={len(value.split('-'))}"
    if _FQDN_RE.match(value):
        return f"fqdn:labels={len(value.split('.'))}"
    return f"str:len_bucket={_len_bucket(len(value))}"


def _len_bucket(n: int) -> str:
    for edge in (8, 16, 32, 64, 128, 256):
        if n <= edge:
            return f"<={edge}"
    return ">256"


# --- Ingestion --------------------------------------------------------------

def flatten(record: Dict[str, Any], prefix: str = "") -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for k, v in record.items():
        key = f"{prefix}.{k}" if prefix else str(k)
        if isinstance(v, dict):
            out.update(flatten(v, key))
        elif isinstance(v, list):
            # Represent list length/shape only; don't pool per-element values.
            out[f"{key}[]"] = f"list_len={len(v)}"
        else:
            out[key] = v
    return out


def load_records(path: Path, fmt: str) -> Iterator[Dict[str, Any]]:
    if fmt == "jsonl":
        with path.open("r", encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError as e:
                    click.echo(f"  [skip] line {lineno}: {e}", err=True)
    elif fmt == "json":
        data = json.loads(path.read_text(encoding="utf-8"))
        records = data if isinstance(data, list) else [data]
        for r in records:
            if isinstance(r, dict):
                yield r
    elif fmt == "csv":
        with path.open("r", encoding="utf-8", newline="") as fh:
            for row in csv.DictReader(fh):
                yield dict(row)
    elif fmt == "evtx":
        yield from load_evtx_records(path)
    else:
        raise ValueError(f"unsupported format: {fmt}")


def load_evtx_records(path: Path) -> Iterator[Dict[str, Any]]:
    """Parse a binary .evtx file, yielding one flattened Event dict per record.

    Requires the 'evtx' package (Rust-backed, pip install evtx) -- not a core
    Kinetix runtime dependency, only needed when mining EVTX corpora such as
    sbousseaden/evtx-attack-samples, Yamato-Security/hayabusa-sample-evtx, or
    NextronSystems/evtx-baseline.
    """
    try:
        from evtx import PyEvtxParser
    except ImportError as e:
        raise click.ClickException(
            "the 'evtx' package is required for --format evtx (pip install evtx)"
        ) from e
    parser = PyEvtxParser(str(path))
    for rec in parser.records_json():
        try:
            data = json.loads(rec["data"])
        except (json.JSONDecodeError, KeyError, TypeError):
            continue
        yield data.get("Event", data)


# Public EVTX sample corpora (evtx-attack-samples, hayabusa-sample-evtx,
# evtx-baseline) mix many providers/EventIDs in one file, so EVTX records are
# auto-routed to a Kinetix/Sentinel table by (Provider, EventID) instead of
# requiring --table-field. Anything outside this map gets an explicit
# "Unclassified_<provider>_<id>" table rather than silently merging into the
# wrong profile -- extend this map as new providers/IDs are encountered.
EVTX_TABLE_MAP: Dict[Any, str] = {
    # --- Sysmon ---
    ("Microsoft-Windows-Sysmon", 1): "DeviceProcessEvents",    # process creation
    ("Microsoft-Windows-Sysmon", 2): "DeviceFileEvents",       # file creation time changed
    ("Microsoft-Windows-Sysmon", 3): "DeviceNetworkEvents",    # network connection
    ("Microsoft-Windows-Sysmon", 4): "DeviceEvents",           # Sysmon service state change
    ("Microsoft-Windows-Sysmon", 5): "DeviceProcessEvents",    # process terminated
    ("Microsoft-Windows-Sysmon", 6): "DeviceEvents",           # driver loaded
    ("Microsoft-Windows-Sysmon", 7): "DeviceEvents",           # image/DLL load
    ("Microsoft-Windows-Sysmon", 8): "DeviceEvents",           # CreateRemoteThread
    ("Microsoft-Windows-Sysmon", 10): "DeviceEvents",          # process access
    ("Microsoft-Windows-Sysmon", 11): "DeviceFileEvents",      # file create
    ("Microsoft-Windows-Sysmon", 12): "DeviceRegistryEvents",  # registry object create/delete
    ("Microsoft-Windows-Sysmon", 13): "DeviceRegistryEvents",  # registry value set
    ("Microsoft-Windows-Sysmon", 14): "DeviceRegistryEvents",  # registry rename
    ("Microsoft-Windows-Sysmon", 15): "DeviceFileEvents",      # FileCreateStreamHash (ADS)
    ("Microsoft-Windows-Sysmon", 16): "DeviceEvents",          # Sysmon config change
    ("Microsoft-Windows-Sysmon", 17): "DeviceEvents",          # named pipe created
    ("Microsoft-Windows-Sysmon", 18): "DeviceEvents",          # named pipe connected
    ("Microsoft-Windows-Sysmon", 19): "DeviceEvents",          # WMI event filter
    ("Microsoft-Windows-Sysmon", 20): "DeviceEvents",          # WMI event consumer
    ("Microsoft-Windows-Sysmon", 21): "DeviceEvents",          # WMI event consumer-to-filter binding
    ("Microsoft-Windows-Sysmon", 22): "DnsEvents",             # DNS query
    ("Microsoft-Windows-Sysmon", 23): "DeviceFileEvents",      # file delete (archived)
    # --- Security-Auditing: authentication / credential / Kerberos ---
    ("Microsoft-Windows-Security-Auditing", 4611): "IdentityLogonEvents",  # trusted logon process registered
    ("Microsoft-Windows-Security-Auditing", 4624): "IdentityLogonEvents",  # successful logon
    ("Microsoft-Windows-Security-Auditing", 4625): "IdentityLogonEvents",  # failed logon
    ("Microsoft-Windows-Security-Auditing", 4634): "IdentityLogonEvents",  # logoff
    ("Microsoft-Windows-Security-Auditing", 4648): "IdentityLogonEvents",  # logon with explicit credentials
    ("Microsoft-Windows-Security-Auditing", 4672): "IdentityLogonEvents",  # special privileges assigned
    ("Microsoft-Windows-Security-Auditing", 4768): "IdentityLogonEvents",  # Kerberos TGT requested
    ("Microsoft-Windows-Security-Auditing", 4769): "IdentityLogonEvents",  # Kerberos service ticket requested
    ("Microsoft-Windows-Security-Auditing", 4771): "IdentityLogonEvents",  # Kerberos pre-auth failed
    ("Microsoft-Windows-Security-Auditing", 4776): "IdentityLogonEvents",  # NTLM credential validation
    ("Microsoft-Windows-Security-Auditing", 4794): "IdentityLogonEvents",  # DSRM password change attempt
    ("Microsoft-Windows-Security-Auditing", 4798): "IdentityLogonEvents",  # user's local group membership enumerated
    ("Microsoft-Windows-Security-Auditing", 4799): "IdentityLogonEvents",  # security-enabled group membership enumerated
    ("Microsoft-Windows-Security-Auditing", 4627): "IdentityLogonEvents",  # group membership info
    # --- Security-Auditing: account/group management ---
    ("Microsoft-Windows-Security-Auditing", 4720): "IdentityLogonEvents",  # user account created
    ("Microsoft-Windows-Security-Auditing", 4722): "IdentityLogonEvents",  # user account enabled
    ("Microsoft-Windows-Security-Auditing", 4724): "IdentityLogonEvents",  # password reset attempt
    ("Microsoft-Windows-Security-Auditing", 4732): "IdentityLogonEvents",  # member added to local group
    ("Microsoft-Windows-Security-Auditing", 4738): "IdentityLogonEvents",  # user account changed
    ("Microsoft-Windows-Security-Auditing", 4741): "IdentityLogonEvents",  # computer account created
    ("Microsoft-Windows-Security-Auditing", 4742): "IdentityLogonEvents",  # computer account changed
    ("Microsoft-Windows-Security-Auditing", 4765): "IdentityLogonEvents",  # SID history added
    ("Microsoft-Windows-Security-Auditing", 4781): "IdentityLogonEvents",  # account name changed
    ("NETLOGON", 5805): "IdentityLogonEvents",                             # netlogon authentication failure
    # --- Security-Auditing: object/file/handle/network access ---
    ("Microsoft-Windows-Security-Auditing", 4656): "DeviceEvents",         # handle to object requested
    ("Microsoft-Windows-Security-Auditing", 4658): "DeviceEvents",         # handle to object closed
    ("Microsoft-Windows-Security-Auditing", 4661): "DeviceEvents",         # handle to object requested (kernel)
    ("Microsoft-Windows-Security-Auditing", 4662): "DeviceEvents",         # operation performed on object
    ("Microsoft-Windows-Security-Auditing", 4663): "DeviceFileEvents",     # attempt to access object
    ("Microsoft-Windows-Security-Auditing", 4673): "DeviceEvents",        # privileged service called
    ("Microsoft-Windows-Security-Auditing", 5136): "DeviceEvents",        # directory service object modified
    ("Microsoft-Windows-Security-Auditing", 5140): "DeviceNetworkEvents", # network share object accessed
    ("Microsoft-Windows-Security-Auditing", 5142): "DeviceNetworkEvents", # network share added
    ("Microsoft-Windows-Security-Auditing", 5145): "DeviceNetworkEvents", # detailed file share check
    ("Microsoft-Windows-Security-Auditing", 5156): "DeviceNetworkEvents", # filtering platform connection permitted
    ("Microsoft-Windows-Security-Auditing", 5158): "DeviceNetworkEvents", # filtering platform bind
    # --- Security-Auditing: policy / scheduled tasks / misc ---
    ("Microsoft-Windows-Security-Auditing", 4698): "DeviceEvents",  # scheduled task created
    ("Microsoft-Windows-Security-Auditing", 4699): "DeviceEvents",  # scheduled task deleted
    ("Microsoft-Windows-Security-Auditing", 4702): "DeviceEvents",  # scheduled task updated
    ("Microsoft-Windows-Security-Auditing", 4703): "DeviceEvents",  # token right adjusted
    ("Microsoft-Windows-Security-Auditing", 4719): "DeviceEvents",  # audit policy changed
    ("Microsoft-Windows-Security-Auditing", 4826): "DeviceEvents",  # boot config data
    ("Microsoft-Windows-Security-Auditing", 4985): "DeviceEvents",  # transaction state changed
    ("Microsoft-Windows-Eventlog", 1102): "DeviceEvents",           # audit log cleared
    ("Microsoft-Windows-Eventlog", 104): "DeviceEvents",            # log file cleared
    # --- Remote sessions (RDP/WinRM) ---
    ("Microsoft-Windows-TerminalServices-RemoteConnectionManager", 1149): "IdentityLogonEvents",
    ("Microsoft-Windows-TerminalServices-RemoteConnectionManager", 1136): "IdentityLogonEvents",
    ("Microsoft-Windows-TerminalServices-RemoteConnectionManager", 1155): "IdentityLogonEvents",
    ("Microsoft-Windows-TerminalServices-RemoteConnectionManager", 258): "IdentityLogonEvents",
    ("Microsoft-Windows-TerminalServices-RemoteConnectionManager", 261): "IdentityLogonEvents",
    ("Microsoft-Windows-WinRM", 91): "DeviceNetworkEvents",
    ("Microsoft-Windows-WinRM", 169): "DeviceNetworkEvents",
    ("Microsoft-Windows-WinRM", 193): "DeviceNetworkEvents",
    # RdpCoreTS emits dozens of session lifecycle IDs (connect/disconnect/reconnect
    # phases); route the whole provider through one lambda-style fallback below
    # instead of enumerating every ID individually.
    # --- Lateral movement / remote execution support ---
    ("Microsoft-Windows-Bits-Client", 3): "DeviceNetworkEvents",
    ("Microsoft-Windows-Bits-Client", 4): "DeviceNetworkEvents",
    ("Microsoft-Windows-Bits-Client", 5): "DeviceNetworkEvents",
    ("Microsoft-Windows-Bits-Client", 59): "DeviceNetworkEvents",
    ("Microsoft-Windows-Bits-Client", 60): "DeviceNetworkEvents",
    ("Microsoft-Windows-Bits-Client", 61): "DeviceNetworkEvents",
    ("Microsoft-Windows-Bits-Client", 209): "DeviceNetworkEvents",
    ("Microsoft-Windows-Bits-Client", 306): "DeviceNetworkEvents",
    ("Microsoft-Windows-Bits-Client", 310): "DeviceNetworkEvents",
    ("PowerShell", 800): "DeviceEvents",                       # classic PSv2 pipeline execution
    ("Microsoft-Windows-PowerShell", 4104): "DeviceEvents",    # ScriptBlockLogging
    ("Microsoft-Windows-PowerShell", 40961): "DeviceEvents",
    ("Microsoft-Windows-PowerShell", 40962): "DeviceEvents",
    ("Microsoft-Windows-PowerShell", 53504): "DeviceEvents",
    ("Microsoft-Windows-Security-Auditing", 4688): "DeviceProcessEvents",
    # --- Detections / AV ---
    ("Microsoft-Windows-Windows Defender", 1116): "SecurityAlert",  # malware detected
    ("Microsoft-Windows-Windows Defender", 1117): "SecurityAlert",  # remediation action taken
    # --- Sysmon (goodware baseline corpus surfaced these) ---
    ("Microsoft-Windows-Sysmon", 9): "DeviceEvents",   # RawAccessRead
    ("Microsoft-Windows-Sysmon", 26): "DeviceFileEvents",  # FileDeleteDetected (archived)
    # --- Security-Auditing (goodware baseline corpus surfaced these) ---
    ("Microsoft-Windows-Security-Auditing", 4907): "DeviceEvents",  # object auditing settings changed
    ("Microsoft-Windows-Security-Auditing", 4674): "DeviceEvents",  # privileged operation attempted on object
    ("Microsoft-Windows-Security-Auditing", 5447): "DeviceNetworkEvents",  # WFP filter added
    # --- App/package install lifecycle (Store, AppX, MSI-Agent) ---
    ("Microsoft-Windows-Install-Agent", 2005): "DeviceEvents",
    ("Microsoft-Windows-Install-Agent", 2006): "DeviceEvents",
    ("Microsoft-Windows-Install-Agent", 2007): "DeviceEvents",
    ("Microsoft-Windows-Store", 8001): "DeviceEvents",
    ("Microsoft-Windows-Store", 8002): "DeviceEvents",
    ("Microsoft-Windows-Store", 8011): "DeviceEvents",
    ("Microsoft-Windows-AppXDeployment", 325): "DeviceEvents",
    ("Microsoft-Windows-AppXDeployment-Server", 603): "DeviceEvents",
    ("Microsoft-Windows-AppXDeployment-Server", 607): "DeviceEvents",
    ("Microsoft-Windows-AppXDeployment-Server", 10001): "DeviceEvents",
    ("Microsoft-Windows-StateRepository", 271): "DeviceEvents",
    ("Microsoft-Windows-Windows Firewall With Advanced Security", 2004): "DeviceNetworkEvents",  # firewall rule added
    ("Service Control Manager", 7036): "DeviceEvents",  # service started/stopped
    ("Service Control Manager", 7040): "DeviceEvents",  # service start type changed
    ("Service Control Manager", 7045): "DeviceEvents",  # service installed
    # --- Low-signal system/service noise -> generic catch-all ---
    ("Microsoft-Windows-RPC", 1): "DeviceEvents",
    ("Microsoft-Windows-RPC", 5): "DeviceEvents",
    ("Microsoft-Windows-RPC", 6): "DeviceEvents",
    ("Microsoft-Windows-RPC", 9): "DeviceEvents",
    ("Microsoft-Windows-RPC", 14): "DeviceEvents",
    ("Microsoft-Windows-RPC", 16): "DeviceEvents",
    ("MsiInstaller", 1040): "DeviceEvents",
    ("MsiInstaller", 1042): "DeviceEvents",
    ("Microsoft-Windows-DistributedCOM", 10016): "DeviceEvents",
    ("Microsoft-Windows-Program-Compatibility-Assistant", 17): "DeviceEvents",
    ("Microsoft-Windows-Application-Experience", 500): "DeviceEvents",
    ("Microsoft-Windows-Security-SPP", 1040): "DeviceEvents",
    ("Microsoft-Windows-Winsock-WS2HELP", 1): "DeviceEvents",
    ("Office Software Protection Platform Service", 1040): "DeviceEvents",
    ("Microsoft-Windows-ProcessExitMonitor", 3001): "DeviceEvents",
    ("ESENT", 325): "AzureDiagnostics",
    ("ESENT", 326): "AzureDiagnostics",
    ("ESENT", 327): "AzureDiagnostics",
    ("MSSQLSERVER", 15457): "AzureDiagnostics",
    ("MSSQLSERVER", 18454): "AzureDiagnostics",
    ("MSSQLSERVER", 18456): "AzureDiagnostics",
    ("MSSQLSERVER", 33205): "AzureDiagnostics",
    ("MSSQL$SQLEXPRESS", 15281): "AzureDiagnostics",
}

# RdpCoreTS alone emits dozens of distinct session-lifecycle EventIDs across
# this corpus; rather than hardcode every one, any (RdpCoreTS, id) not already
# in EVTX_TABLE_MAP is routed to IdentityLogonEvents by the fallback in
# infer_evtx_table() below.
_RDPCORETS_PROVIDER = "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS"


def _extract_event_id(system: Dict[str, Any]) -> Optional[int]:
    event_id = system.get("EventID")
    if isinstance(event_id, dict):
        event_id = event_id.get("#text")
    try:
        return int(event_id)
    except (TypeError, ValueError):
        return None


def infer_evtx_table(event: Dict[str, Any], default_table: Optional[str]) -> str:
    if default_table:
        return default_table
    system = event.get("System", {})
    provider = (system.get("Provider") or {}).get("#attributes", {}).get("Name", "Unknown")
    event_id = _extract_event_id(system)
    table = EVTX_TABLE_MAP.get((provider, event_id))
    if table:
        return table
    if provider == _RDPCORETS_PROVIDER:
        return "IdentityLogonEvents"
    safe_provider = re.sub(r"[^A-Za-z0-9]+", "_", provider)
    return f"Unclassified_{safe_provider}_{event_id}"


# --- Profile accumulation ----------------------------------------------------

class FieldProfile:
    __slots__ = ("kind", "value_counts", "shape_counts", "n")

    def __init__(self) -> None:
        self.kind: Optional[str] = None
        self.value_counts: Counter = Counter()
        self.shape_counts: Counter = Counter()
        self.n = 0

    def observe(self, name: str, value: Any) -> None:
        kind = classify_field(name, value)
        self.kind = kind
        self.n += 1
        if kind == "identifier":
            self.shape_counts[shape_token(value)] += 1
        else:
            if len(self.value_counts) < MAX_POOL_SIZE or value in self.value_counts:
                self.value_counts[str(value)] += 1

    def to_dict(self) -> Dict[str, Any]:
        if self.kind == "identifier":
            total = sum(self.shape_counts.values()) or 1
            return {
                "kind": "identifier",
                "n": self.n,
                "shapes": [
                    {"shape": s, "count": c, "weight": round(c / total, 4)}
                    for s, c in self.shape_counts.most_common(20)
                ],
            }
        total = sum(self.value_counts.values()) or 1
        return {
            "kind": "freeform",
            "n": self.n,
            "values": [
                {"value": v, "count": c, "weight": round(c / total, 4)}
                for v, c in self.value_counts.most_common(MAX_POOL_SIZE)
            ],
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "FieldProfile":
        fp = cls()
        fp.kind = d.get("kind")
        fp.n = d.get("n", 0)
        if fp.kind == "identifier":
            for row in d.get("shapes", []):
                fp.shape_counts[row["shape"]] = row["count"]
        else:
            for row in d.get("values", []):
                fp.value_counts[row["value"]] = row["count"]
        return fp

    def merge(self, other: "FieldProfile") -> None:
        self.n += other.n
        self.shape_counts.update(other.shape_counts)
        self.value_counts.update(other.value_counts)
        if len(self.value_counts) > MAX_POOL_SIZE:
            self.value_counts = Counter(dict(self.value_counts.most_common(MAX_POOL_SIZE)))


class TableProfile:
    def __init__(self, table: str) -> None:
        self.table = table
        self.fields: Dict[str, FieldProfile] = defaultdict(FieldProfile)
        self.record_count = 0
        self.sources: Counter = Counter()

    def observe(self, record: Dict[str, Any], source_label: str) -> None:
        self.record_count += 1
        self.sources[source_label] += 1
        for k, v in flatten(record).items():
            if v is None or v == "":
                continue
            self.fields[k].observe(k, v)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "table": self.table,
            "record_count": self.record_count,
            "sources": dict(self.sources),
            "mined_at": datetime.now(timezone.utc).isoformat(),
            "fields": {name: fp.to_dict() for name, fp in self.fields.items()},
        }

    @classmethod
    def load(cls, path: Path, table: str) -> "TableProfile":
        tp = cls(table)
        if path.exists():
            raw = json.loads(path.read_text(encoding="utf-8"))
            tp.record_count = raw.get("record_count", 0)
            tp.sources = Counter(raw.get("sources", {}))
            for name, fdict in raw.get("fields", {}).items():
                tp.fields[name] = FieldProfile.from_dict(fdict)
        return tp

    def merge_new(self, records: Iterator[Dict[str, Any]], source_label: str) -> int:
        count = 0
        for r in records:
            self.observe(r, source_label)
            count += 1
        return count


# --- Table routing ------------------------------------------------------

def infer_table(record: Dict[str, Any], table_field: Optional[str], default_table: Optional[str]) -> str:
    if table_field:
        flat = flatten(record)
        val = flat.get(table_field) or record.get(table_field)
        if val:
            return str(val)
    if default_table:
        return default_table
    return "Unclassified"


@click.command()
@click.option("--input", "input_path", required=True, type=click.Path(exists=True, path_type=Path),
              help="Path to the corpus sample file (json / jsonl / csv / evtx).")
@click.option("--format", "fmt", type=click.Choice(["json", "jsonl", "csv", "evtx"]), required=True)
@click.option("--table", "default_table", default=None,
              help="Force all records in this file into a single table profile "
                   "(use when the file is already one homogeneous event type, "
                   "e.g. --table SecurityAlert for a Wazuh alerts.json export). "
                   "For --format evtx this is optional -- omit it to auto-route "
                   "each record by (Provider, EventID) via EVTX_TABLE_MAP.")
@click.option("--table-field", default=None,
              help="Flattened field name to read the table/event-type from per-record "
                   "(e.g. --table-field EventID for a mixed EVTX-derived JSON export). "
                   "Ignored if --table is set. Not used for --format evtx, which routes "
                   "via EVTX_TABLE_MAP instead (see --table to override).")
@click.option("--source-label", default=None,
              help="Label recorded in the profile's 'sources' tally (defaults to the input filename).")
@click.option("--output-dir", type=click.Path(path_type=Path), default=Path("kinetix/intelligence/corpus_profiles"),
              help="Directory to write/merge corpus_profiles/<table>.json into.")
@click.option("--dry-run", is_flag=True, help="Parse and report without writing any profile files.")
@click.option("--include-unclassified", is_flag=True,
              help="Also write one profile file per unmapped (Provider, EventID) combo. "
                   "Off by default: a broad EVTX corpus (esp. a goodware baseline full of "
                   "installed-software telemetry) can surface hundreds of one-off providers "
                   "that clutter corpus_profiles/ without ever being sampled -- confirmed "
                   "against a real ~1000-file corpus during development, which produced "
                   "~960 such one- or two-record files. Records are still counted and "
                   "reported (stderr) either way so you know what to extend EVTX_TABLE_MAP with.")
def main(input_path: Path, fmt: str, default_table: Optional[str], table_field: Optional[str],
         source_label: Optional[str], output_dir: Path, dry_run: bool, include_unclassified: bool) -> None:
    """Mine field-value distributions out of a sample log corpus file."""
    if fmt != "evtx" and not default_table and not table_field:
        raise click.UsageError("pass either --table (homogeneous file) or --table-field (mixed file)")

    label = source_label or input_path.name
    per_table_records: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

    click.echo(f"Reading {input_path} as {fmt} ...")
    total = 0
    unclassified = Counter()
    for record in load_records(input_path, fmt):
        if fmt == "evtx":
            table = infer_evtx_table(record, default_table)
        else:
            table = infer_table(record, table_field, default_table)
        if table.startswith("Unclassified"):
            unclassified[table] += 1
            if not include_unclassified:
                total += 1
                continue
        per_table_records[table].append(record)
        total += 1
    click.echo(f"Loaded {total} records across {len(per_table_records) + (0 if include_unclassified else len(unclassified))} table(s).")
    if unclassified:
        verb = "written as separate profiles" if include_unclassified else "skipped, not written (pass --include-unclassified to keep them)"
        click.echo(f"  Unmapped (Provider, EventID) combos -- {verb}. Extend EVTX_TABLE_MAP for these:", err=True)
        for table, count in unclassified.most_common():
            click.echo(f"    {table}: {count} records", err=True)

    if dry_run:
        for table, records in per_table_records.items():
            click.echo(f"  [dry-run] {table}: {len(records)} records (not written)")
        return

    output_dir.mkdir(parents=True, exist_ok=True)
    for table, records in per_table_records.items():
        profile_path = output_dir / f"{table}.json"
        profile = TableProfile.load(profile_path, table)
        added = profile.merge_new(iter(records), label)
        profile_path.write_text(json.dumps(profile.to_dict(), indent=2, sort_keys=True), encoding="utf-8")
        click.echo(f"  {table}: merged {added} records -> {profile_path} "
                   f"(total record_count={profile.record_count}, fields={len(profile.fields)})")


if __name__ == "__main__":
    main()
