import os
import json
import logging
import copy
import click
import time
import signal
import sys
import threading
import random
import orjson
from logging.handlers import RotatingFileHandler
from rich.console import Console
from rich.logging import RichHandler

from kinetix.core.engine import KinetixEngine
from kinetix.core.scenario import AttackChain
from kinetix.outputs.file import FileOutput
from kinetix.outputs.syslog import SyslogOutput
from kinetix.core.temporal import TemporalEngine
from kinetix.schemas.temporal import TimingProfile
from kinetix.core.vars import VariableManager

# Setup logging (M6: use RotatingFileHandler for debug.log)
if not os.path.exists("logs"):
    os.makedirs("logs")

log_formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
file_handler = RotatingFileHandler(
    "logs/debug.log", mode="a", encoding="utf-8",
    maxBytes=5 * 1024 * 1024, backupCount=3
)
file_handler.setFormatter(log_formatter)
file_handler.setLevel(logging.DEBUG)

logging.basicConfig(
    level="INFO",
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(rich_tracebacks=True), file_handler]
)
logger = logging.getLogger("kinetix")
console = Console()

# --- H1: Event type → Model class registry (replaces brittle if/elif chain) ---
def _build_event_registry() -> dict:
    from kinetix.schemas.base import BaseLogEvent
    from kinetix.schemas.endpoint import ProcessEvent, FileEvent, RegistryEvent, DeviceGenericEvent
    from kinetix.schemas.network import FirewallEvent, DNSEvent, ProxyEvent
    from kinetix.schemas.cloud_auth import AuthenticationEvent, VPNEvent, CloudActivityEvent, O365ActivityEvent
    from kinetix.schemas.security import SecurityAlert, SecurityIncident, AuditLogEvent, WorkspaceAuditEvent
    from kinetix.schemas.app import WebServerEvent, DatabaseEvent, GenericSyslogEvent
    from kinetix.schemas.linux import LinuxAuthEvent, LinuxSudoEvent, LinuxAuditdEvent, LinuxKernelEvent, LinuxCronEvent, LinuxProcessEvent
    from kinetix.schemas.macos import MacOSLogEvent, MacOSAuthEvent, MacOSAppExecEvent
    from kinetix.schemas.email import EmailEvent, EmailAttachmentEvent
    from kinetix.schemas.cloud_app import CloudAppEvent
    from kinetix.schemas.identity import IdentityLogonEvent, AADNonInteractiveSignIn

    return {
        "authentication": AuthenticationEvent,
        "process_creation": ProcessEvent,
        "file_system": FileEvent,
        "registry": RegistryEvent,
        "device_event": DeviceGenericEvent,
        "network_connection": FirewallEvent,
        "dns_query": DNSEvent,
        "proxy": ProxyEvent,
        "web_proxy": ProxyEvent,
        "vpn": VPNEvent,
        "vpn_session": VPNEvent,
        "web_request": WebServerEvent,
        "db_query": DatabaseEvent,
        "office_activity": O365ActivityEvent,
        "cloud_activity": CloudActivityEvent,
        "security_alert": SecurityAlert,
        "security_incident": SecurityIncident,
        "directory_audit": AuditLogEvent,
        "audit": WorkspaceAuditEvent,
        "system_event": GenericSyslogEvent,
        "linux_auth": LinuxAuthEvent,
        "linux_sudo": LinuxSudoEvent,
        "linux_audit": LinuxAuditdEvent,
        "linux_kernel": LinuxKernelEvent,
        "linux_cron": LinuxCronEvent,
        "linux_process": LinuxProcessEvent,
        "macos_log": MacOSLogEvent,
        "macos_process": MacOSLogEvent,
        "macos_auth": MacOSAuthEvent,
        "macos_exec": MacOSAppExecEvent,
        "email_event": EmailEvent,
        "email_attachment": EmailAttachmentEvent,
        "cloud_app": CloudAppEvent,
        "cloud_app_event": CloudAppEvent,
        "identity_logon": IdentityLogonEvent,
        "non_interactive_signin": AADNonInteractiveSignIn,
    }

# Source-based fallback for ambiguous event types (e.g. "alert", "incident")
_SOURCE_FALLBACK = {
    "alert": "security_alert",
    "incident": "security_incident",
}


def load_scenario(filepath: str, var_manager: VariableManager = None) -> list:
    """Load and parse the scenario JSON."""
    if not var_manager:
        var_manager = VariableManager()

    from kinetix.schemas.base import BaseLogEvent
    event_registry = _build_event_registry()

    with open(filepath, "r") as f:
        data = json.load(f)

    stages = []
    for stage_data in data:
        stage = {
            "name": stage_data["name"],
            "delay": stage_data.get("delay", 1.0),
            "events": []
        }

        for e_raw in stage_data["events"]:
            # Volume Multiplication support
            count = e_raw.get("multiply", 1)

            # --- C2 FIX: resolve templates INSIDE the multiply loop ---
            # Each instance gets unique RANDOM_IP, RANDOM_PID, timestamps, etc.
            for _ in range(count):
                e = var_manager.resolve(copy.deepcopy(e_raw))

                # Flatten 'data' into top-level for easier model mapping/validation
                if "data" in e and isinstance(e["data"], dict):
                    e.update(e.pop("data"))

                source = e.get("source", "").lower()
                etype = e.get("event_type", "").lower()

                # Sanitize: Remove source/event_type/multiply before passing to model
                params = e.copy()
                params.pop("source", None)
                params.pop("event_type", None)
                params.pop("multiply", None)

                # H1: Registry-based routing
                resolved_etype = _SOURCE_FALLBACK.get(source, etype)
                model_class = event_registry.get(resolved_etype, None)

                # For BaseLogEvent fallback, we need to pass the source/type back
                if model_class is None:
                    model_class = BaseLogEvent
                    params["SourceSystem"] = source
                    params["Type"] = etype

                stage["events"].append(model_class(**params))

        stages.append(stage)
    return stages

from kinetix.schemas.endpoint import ProcessEvent
from kinetix.schemas.network import DNSEvent, FirewallEvent
from kinetix.schemas.cloud_auth import AuthenticationEvent


_BENIGN_NOISE_TEMPLATES = [
    {"event_type": "process_creation", "source": "endpoint", "FileName": "explorer.exe", "FolderPath": "C:\\Windows", "ProcessId": "{{RANDOM_PID}}", "ProcessCommandLine": "C:\\Windows\\explorer.exe", "severity": "informational"},
    {"event_type": "process_creation", "source": "endpoint", "FileName": "svchost.exe", "FolderPath": "C:\\Windows\\System32", "ProcessId": "{{RANDOM_PID}}", "ProcessCommandLine": "C:\\Windows\\System32\\svchost.exe -k netsvcs", "severity": "informational"},
    {"event_type": "process_creation", "source": "endpoint", "FileName": "chrome.exe", "FolderPath": "C:\\Program Files\\Google\\Chrome\\Application", "ProcessId": "{{RANDOM_PID}}", "ProcessCommandLine": "\"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\" --start-maximized", "severity": "informational"},
    {"event_type": "dns_query", "source": "dns", "Name": "login.microsoftonline.com", "QueryType": "A", "ResultCode": "0", "IPAddresses": "20.70.250.20", "severity": "informational"},
    {"event_type": "dns_query", "source": "dns", "Name": "www.bing.com", "QueryType": "A", "ResultCode": "0", "IPAddresses": "13.107.21.200", "severity": "informational"},
    {"event_type": "authentication", "source": "Azure AD", "UserPrincipalName": "{{RANDOM_EMAIL}}", "ClientAppUsed": "Browser", "ResultType": "0", "ResultDescription": "Success", "location": "US", "city": "Seattle", "severity": "informational"},
    {"event_type": "authentication", "source": "Azure AD", "UserPrincipalName": "{{RANDOM_EMAIL}}", "ClientAppUsed": "Browser", "ResultType": "0", "ResultDescription": "Success", "location": "US", "city": "Redmond", "severity": "informational"},
    {"event_type": "network_connection", "source": "Firewall", "DeviceAction": "allowed", "Protocol": "TCP", "SourcePort": "{{RANDOM_PORT}}", "DestinationPort": 443, "DestinationIP": "13.107.21.200", "severity": "informational"},
    {"event_type": "network_connection", "source": "Firewall", "DeviceAction": "allowed", "Protocol": "TCP", "SourcePort": "{{RANDOM_PORT}}", "DestinationPort": 80, "DestinationIP": "13.107.21.200", "severity": "informational"},
    {"event_type": "file_system", "source": "endpoint", "ActionType": "FileCreated", "FileName": "report.docx", "FolderPath": "C:\\Users\\Public\\Documents", "severity": "informational"},
    {"event_type": "file_system", "source": "endpoint", "ActionType": "FileModified", "FileName": "budget.xlsx", "FolderPath": "C:\\Users\\Public\\Documents", "severity": "informational"},
    # Corpus-backed noise: pulls real mined command-line/file-path/script-block
    # shapes (see kinetix/core/vars.py:CORPUS_FIELD_CANDIDATES) instead of a
    # single fixed value, so repeated baseline noise generation doesn't
    # produce identical process/file/script content every run.
    {"event_type": "process_creation", "source": "endpoint", "FileName": "cmd.exe", "FolderPath": "C:\\Windows\\System32", "ProcessId": "{{RANDOM_PID}}", "ProcessCommandLine": "{{RANDOM_COMMANDLINE}}", "severity": "informational"},
    {"event_type": "file_system", "source": "endpoint", "ActionType": "FileCreated", "FileName": "{{RANDOM_FILE_PATH}}", "FolderPath": "C:\\ProgramData", "severity": "informational"},
    {"event_type": "process_creation", "source": "endpoint", "FileName": "powershell.exe", "FolderPath": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0", "ProcessId": "{{RANDOM_PID}}", "ProcessCommandLine": "{{RANDOM_SCRIPT_BLOCK}}", "severity": "informational"},
    {"event_type": "registry", "source": "endpoint", "action_type": "RegistryValueSet", "key_path": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "value_name": "Updater", "value_data": "{{RANDOM_REGISTRY_VALUE}}", "severity": "informational"},
]


# Additional benign-noise sources: full scenario files with richer, more
# varied event shapes (cross-platform + collaboration/SaaS noise) than the
# small inline pool above. Loaded once and cached so --baseline-ratio draws
# from a much wider corpus instead of cycling the same ~15 templates.
_NOISE_SCENARIO_FILES = ["scenarios/benign_noise.json", "scenarios/cross_platform_noise.json"]
_EXTRA_NOISE_TEMPLATES_CACHE = None
_REPO_ROOT = os.path.dirname(os.path.abspath(__file__))

_DEFAULT_MAX_BYTES = 10 * 1024 * 1024
_DEFAULT_BACKUP_COUNT = 5


def _rotation_limits(sim_clock: bool) -> tuple:
    """Rotation sizing for the file outputs.

    Real-time runs are open-ended, so they keep the bounded ~60MB-per-feed
    rotation. A --sim-clock run instead generates a finite window the caller
    explicitly asked for; rotating mid-run would delete the oldest part of
    that window, and would do so per-feed, leaving high-volume tables covering
    fewer days than low-volume ones. maxBytes=0 disables rotation entirely.
    """
    if sim_clock:
        return 0, 0
    return _DEFAULT_MAX_BYTES, _DEFAULT_BACKUP_COUNT


_SORT_CHUNK_LINES = 200_000


def _sort_jsonl_by_timestamp(path: str) -> None:
    """Rewrite a JSON-lines log file in TimeGenerated order.

    Workers write in completion order, not timestamp order, so a sim-clock
    run's files come out ~11% inverted with backward jumps of minutes. This
    is a chunked external merge sort: each chunk is sorted in memory and
    spilled to a temp file, then the chunks are merged back, so peak memory
    is bounded by _SORT_CHUNK_LINES rather than the file size. Lines that
    cannot be parsed keep their position relative to the preceding record
    instead of being dropped.
    """
    import heapq
    import tempfile

    def key_of(line: str, previous):
        try:
            return orjson.loads(line).get("TimeGenerated") or previous
        except orjson.JSONDecodeError:
            return previous

    spills = []
    try:
        with open(path, "r", encoding="utf-8") as src:
            chunk, seq, previous = [], 0, ""
            def flush():
                nonlocal chunk
                if not chunk:
                    return
                chunk.sort(key=lambda r: (r[0], r[1]))
                tmp = tempfile.NamedTemporaryFile(
                    mode="w", encoding="utf-8", delete=False,
                    dir=os.path.dirname(path) or ".", suffix=".sorttmp")
                for k, i, ln in chunk:
                    tmp.write(f"{k}\t{i}\t{ln}\n")
                tmp.close()
                spills.append(tmp.name)
                chunk = []

            for line in src:
                line = line.rstrip("\n")
                if not line.strip():
                    continue
                previous = key_of(line, previous)
                chunk.append((previous, seq, line))
                seq += 1
                if len(chunk) >= _SORT_CHUNK_LINES:
                    flush()
            flush()

        if not spills:
            return

        streams = [open(s, "r", encoding="utf-8") for s in spills]
        try:
            def rows(fh):
                for raw in fh:
                    k, i, ln = raw.rstrip("\n").split("\t", 2)
                    yield (k, int(i), ln)
            merged = heapq.merge(*(rows(fh) for fh in streams), key=lambda r: (r[0], r[1]))
            with open(path, "w", encoding="utf-8") as dst:
                for _, _, ln in merged:
                    dst.write(ln + "\n")
        finally:
            for fh in streams:
                fh.close()
    finally:
        for s in spills:
            try:
                os.unlink(s)
            except OSError:
                pass


def _sort_output_logs(output_dir: str) -> int:
    """Sort every JSON-lines feed in output_dir. Returns the file count."""
    import glob
    count = 0
    for path in sorted(glob.glob(os.path.join(output_dir, "*.json"))):
        try:
            _sort_jsonl_by_timestamp(path)
            count += 1
        except OSError as e:
            logger.warning(f"Could not sort {path}: {e}")
    return count


def _load_noise_scenario_templates(paths: list) -> list:
    """Flatten stage events from noise scenario JSON files into a weighted
    template pool. 'multiply' on an event is treated as a sampling weight
    (expanded by duplication) rather than a literal event count.

    Relative paths resolve against this file's directory, not the process
    working directory: invoking main.py by absolute path from elsewhere
    otherwise found nothing and silently fell back to the small inline pool.
    """
    templates = []
    for path in paths:
        if not os.path.isabs(path):
            path = os.path.join(_REPO_ROOT, path)
        if not os.path.exists(path):
            logging.getLogger(__name__).warning(f"Noise scenario not found, skipping: {path}")
            continue
        try:
            with open(path, "r") as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            logging.getLogger(__name__).warning(f"Failed to load noise scenario {path}: {e}")
            continue
        for stage_data in data:
            for e_raw in stage_data.get("events", []):
                weight = max(1, min(e_raw.get("multiply", 1), 20))
                tpl = {k: v for k, v in e_raw.items() if k != "multiply"}
                templates.extend([tpl] * weight)
    return templates


def _get_noise_template_pool() -> list:
    global _EXTRA_NOISE_TEMPLATES_CACHE
    if _EXTRA_NOISE_TEMPLATES_CACHE is None:
        _EXTRA_NOISE_TEMPLATES_CACHE = _load_noise_scenario_templates(_NOISE_SCENARIO_FILES)
    return _BENIGN_NOISE_TEMPLATES + _EXTRA_NOISE_TEMPLATES_CACHE


def _generate_baseline_noise(count: int, var_manager: VariableManager) -> list:
    import copy
    from kinetix.schemas.base import BaseLogEvent
    from kinetix.schemas.endpoint import ProcessEvent, FileEvent, RegistryEvent
    from kinetix.schemas.network import FirewallEvent, DNSEvent, ProxyEvent
    from kinetix.schemas.cloud_auth import AuthenticationEvent, VPNEvent, CloudActivityEvent, O365ActivityEvent
    from kinetix.schemas.security import SecurityAlert, SecurityIncident
    from kinetix.schemas.app import WebServerEvent, DatabaseEvent

    event_registry = _build_event_registry()
    pool = _get_noise_template_pool()
    events = []
    for _ in range(count):
        tpl = random.choice(pool)
        resolved = var_manager.resolve(copy.deepcopy(tpl))
        params = resolved.copy()
        params.pop("source", None)
        params.pop("event_type", None)
        etype = resolved.get("event_type", "")
        model_class = event_registry.get(etype, BaseLogEvent)
        try:
            events.append(model_class(**params))
        except Exception as e:
            logging.getLogger(__name__).debug(f"Baseline noise event skipped: {e}")
    return events


def _build_timing_profile(delay: float, sim_clock: bool) -> TimingProfile:
    """Build the timing profile for a run.

    Weekend shaping only applies to the simulated timeline — on the real-time
    path it would compound with the after-hours divisor and throttle a weekend
    run to near silence.

    The diurnal curve is evaluated in the simulated organisation's local time.
    A real-time run models the operator's own workday, so it takes the host's
    UTC offset; without it a UTC-8 operator running at 14:50 local is read as
    06:50 "after hours" and every delay is multiplied by 1/after_hours (10x),
    capping drain at ~1 event/sec and making --baseline-ratio undrainable.
    Simulated-clock runs stay UTC-native, which is the frame their virtual
    timeline is generated in.
    """
    from datetime import datetime

    offset = 0.0
    if not sim_clock:
        local_offset = datetime.now().astimezone().utcoffset()
        if local_offset is not None:
            offset = local_offset.total_seconds() / 3600

    return TimingProfile(
        avg_delay_seconds=delay,
        weekend_shaping=bool(sim_clock),
        business_utc_offset_hours=offset,
    )


def _interleave_baseline_noise(all_stages: list, noise_events: list) -> list:
    """Spread one cycle's benign noise batch across the attack chain.

    The batch is split into contiguous slices, one per attack stage, so the
    chain emits exactly `len(noise_events)` benign events per cycle. Appending
    a single shared stage after every attack stage instead would replay the
    whole batch once per stage and multiply the cycle's volume by the stage
    count, overflowing the engine queue.
    """
    total = len(noise_events)
    stage_count = len(all_stages)
    if not total or not stage_count:
        return list(all_stages)

    interleaved = []
    for i, stage in enumerate(all_stages):
        interleaved.append(stage)
        # Integer boundaries distribute the remainder without losing events.
        start = i * total // stage_count
        end = (i + 1) * total // stage_count
        chunk = noise_events[start:end]
        if chunk:
            interleaved.append({"name": "Baseline Noise", "delay": 0.05, "events": chunk})
    return interleaved


@click.command()
@click.option("--scenario", multiple=True, default=["scenarios/ransomware_v1.json"], help="Path(s) to scenario JSON files to execute.")
@click.option("--output-dir", default="logs", help="Directory where JSON and CEF logs will be saved.")
@click.option("--temporal/--no-temporal", default=True, help="Enable realistic temporal spacing between events (Markov chains + Gaussian jitter).")
@click.option("--stress", is_flag=True, help="Enable high-throughput mode (ignores scenario delays, increases worker count).")
@click.option("--duration", type=int, default=0, help="Simulation duration in seconds. If 0 (default), the generator runs indefinitely until interrupted.")
@click.option("--baseline-ratio", type=float, default=0.0, help="Ratio of benign noise events to inject alongside attack events (0.0 = off, 0.95 = 95% benign).")
@click.option("--syslog-host", default=None, help="If set, also stream events as real RFC 3164 syslog over the network to this host (e.g. a Wazuh manager's syslog collector, or a local rsyslog instance).")
@click.option("--syslog-port", type=int, default=514, help="Destination port for --syslog-host.")
@click.option("--syslog-proto", type=click.Choice(["udp", "tcp"]), default="udp", help="Transport for --syslog-host.")
@click.option("--sim-clock", is_flag=True, help="Simulated-clock mode: stamp events across a virtual multi-day window (diurnal + weekend-aware pacing) instead of real wall-clock time, so a realistic historical baseline can be generated in a short run.")
@click.option("--sim-days", type=float, default=7.0, help="Span of simulated time to generate when --sim-clock is set (default 7 days).")
@click.option("--sim-start", default=None, help="ISO start timestamp for --sim-clock (e.g. 2026-09-01 or 2026-09-01T00:00:00). Defaults to (now - sim-days), so the window ends at the current time.")
@click.option("--syslog-format", type=click.Choice(["rfc3164", "rfc5424"]), default="rfc3164", help="Wire format for syslog output. rfc3164 (default) matches Wazuh's built-in decoders but carries no year, so a backdated --sim-start is re-dated to the ingest year; rfc5424 uses full ISO 8601 timestamps and preserves it.")
@click.option("--sort-output/--no-sort-output", default=None, help="Rewrite each JSON feed in TimeGenerated order once the run finishes. Defaults on for --sim-clock (workers write in completion order, leaving the window ~11%% inverted) and off otherwise.")
def main(scenario, output_dir, temporal, stress, duration, baseline_ratio, syslog_host, syslog_port, syslog_proto, sim_clock, sim_days, sim_start, syslog_format, sort_output):
    """
    Kinetix: High-Performance Synthetic Log Generator for SIEM Validation.
    Generates JSON (Azure Sentinel parity) and CEF logs simultaneously.
    """
    console.print("[bold blue]Kinetix Log Generator[/bold blue]")

    from kinetix.schemas.base import set_syslog_format
    set_syslog_format(syslog_format)
    if sort_output is None:
        sort_output = bool(sim_clock)

    start_time = time.time()
    if duration > 0 and duration < 5:
        logger.warning(f"Requested duration {duration}s is below minimum for stability. Bumping to 5s.")
        duration = 5

    # 1. Initialize Global Assets
    max_bytes, backup_count = _rotation_limits(sim_clock)
    file_output = FileOutput(output_dir=output_dir, max_bytes=max_bytes, backup_count=backup_count)
    output_providers = [file_output]

    if syslog_host:
        try:
            syslog_output = SyslogOutput(host=syslog_host, port=syslog_port, protocol=syslog_proto)
            output_providers.append(syslog_output)
            console.print(f"[dim]Streaming syslog to {syslog_host}:{syslog_port}/{syslog_proto}[/dim]")
        except OSError as e:
            logger.error(f"Failed to initialize syslog output ({syslog_host}:{syslog_port}/{syslog_proto}): {e}")
            console.print(f"[bold red]Syslog output disabled: {e}[/bold red]")

    var_manager = VariableManager()

    # 2. Initialize Temporal Engine
    temporal_engine = None
    if temporal:
        delay = 0.01 if stress else 0.2
        temporal_engine = TemporalEngine(
            profile=_build_timing_profile(delay=delay, sim_clock=bool(sim_clock))
        )

    # 2b. Initialize Simulated Clock (multi-day baseline mode)
    clock = None
    if sim_clock:
        from datetime import datetime, timedelta, timezone
        from kinetix.core.simclock import SimulatedClock
        if sim_days <= 0:
            console.print(f"[bold red]Invalid --sim-days '{sim_days}'; must be greater than 0.[/bold red]")
            sys.exit(1)
        if sim_start:
            try:
                start_dt = datetime.fromisoformat(sim_start)
            except ValueError:
                console.print(f"[bold red]Invalid --sim-start '{sim_start}'; expected ISO format, e.g. 2026-09-01 or 2026-09-01T00:00:00[/bold red]")
                sys.exit(1)
            if start_dt.tzinfo is None:
                start_dt = start_dt.replace(tzinfo=timezone.utc)
        else:
            start_dt = datetime.now(timezone.utc) - timedelta(days=sim_days)
        end_dt = start_dt + timedelta(days=sim_days)
        clock = SimulatedClock(start=start_dt, end=end_dt)
        console.print(f"[bold magenta]Simulated clock: {start_dt.isoformat()} -> {end_dt.isoformat()} ({sim_days}d simulated, diurnal + weekend pacing)[/bold magenta]")
        if not temporal_engine:
            console.print("[yellow]--sim-clock without --temporal has no diurnal/weekend shaping; falling back to a fixed per-event delay.[/yellow]")
        # RFC 3164 has no year field, so a window outside the current year is
        # silently re-dated to the ingest year by the receiving collector.
        current_year = datetime.now(timezone.utc).year
        if syslog_format == "rfc3164" and (start_dt.year != current_year or end_dt.year != current_year):
            console.print(
                f"[bold yellow]Window spans {start_dt.year}–{end_dt.year} but RFC 3164 syslog carries no year: "
                f"the syslog feed will be re-dated to {current_year} on ingest. "
                f"Pass --syslog-format rfc5424 to preserve it (JSON and CEF are unaffected).[/bold yellow]"
            )

    # 3. Initialize Engine
    engine = KinetixEngine(
        output_providers=output_providers,
        worker_count=8 if stress else 2,
        temporal_engine=temporal_engine,
        sim_clock=clock
    )

    engine.start()

    # Used to signal graceful shutdown from signal handler or duration expiry
    shutdown_requested = threading.Event()
    
    # 4. Graceful Shutdown Handler — signals the main loop, does NOT block
    def signal_handler(sig, frame):
        if not shutdown_requested.is_set():
            console.print("\n[bold red]Interrupted! Shutting down gracefully...[/bold red]")
            shutdown_requested.set()
            engine._stop_event.set()

    signal.signal(signal.SIGINT, signal_handler)
    
    try:
        # 5. Execute Simulation Loop
        
        if clock:
            console.print(f"[bold cyan]Mode: Simulated clock ({sim_days}d virtual, runs until the window is filled{f' or {duration}s real time elapses' if duration > 0 else ''})[/bold cyan]")
        elif duration == 0:
            console.print("[bold yellow]Mode: Infinite (Run until Ctrl+C)[/bold yellow]")
        else:
            console.print(f"[bold cyan]Mode: Timed ({duration}s)[/bold cyan]")

        while not shutdown_requested.is_set():
            # --- Dynamic Session Rotation ---
            # Roll new SessionID, CNC_IP, etc. for each iteration
            var_manager._set_session_vars()
            var_manager._set_persona_vars()
            
            # Re-load and re-resolve scenarios to ensure new RANDOM_* values
            all_stages = []
            for s_path in scenario:
                if os.path.exists(s_path):
                    all_stages.extend(load_scenario(s_path, var_manager))
            
            if not all_stages:
                logger.error("No valid stages loaded. Breaking loop.")
                break

            # Inject benign baseline noise if ratio > 0
            if baseline_ratio > 0 and all_stages:
                malicious_count = sum(len(s["events"]) for s in all_stages if any(
                    getattr(e, "is_malicious", False) for e in s["events"]
                ))
                noise_count = int(malicious_count * (baseline_ratio / (1 - baseline_ratio))) if baseline_ratio < 1 else 0
                if noise_count > 0:
                    noise_events = _generate_baseline_noise(noise_count, var_manager)
                    all_stages = _interleave_baseline_noise(all_stages, noise_events)
                    console.print(f"[dim]Injected {len(noise_events)} benign noise events[/dim]")

            attack_chain = AttackChain(
                scenario_id=var_manager.session_vars["SESSION_ID"][:8],
                name=f"Simulation Cycle ({time.strftime('%H:%M:%S')})",
                stages=all_stages,
                # Simulated-clock mode paces via the virtual clock, not real
                # sleeps, so skip the real-time inter-stage delay too.
                stress=stress or bool(clock),
            )

            console.print(f"[green]Executing chain: {attack_chain.name}[/green]")
            attack_chain.run(engine, stop_event=shutdown_requested)

            if clock:
                # Drain this cycle's events before checking/advancing further so
                # clock.current reflects what's actually been timestamped and
                # written, not just enqueued — otherwise cycles would keep
                # generating far past the simulated window before we noticed.
                engine.wait_for_completion()
                console.print(f"[dim]Simulated clock at {clock.current.isoformat()} ({clock.progress() * 100:.1f}% of window)[/dim]")
                if clock.finished():
                    console.print("[bold yellow]Simulated window filled. Draining queue and shutting down...[/bold yellow]")
                    shutdown_requested.set()
                    engine._stop_event.set()
                    break

            elapsed = time.time() - start_time
            if duration > 0 and elapsed >= duration:
                console.print("[bold yellow]Duration reached. Draining queue and shutting down...[/bold yellow]")
                shutdown_requested.set()
                engine._stop_event.set()
                break

            if not clock and duration == 0 and not shutdown_requested.is_set():
                # Interruptible breather between cycles
                for _ in range(10):
                    if shutdown_requested.is_set():
                        break
                    time.sleep(0.1)

        # Let workers drain remaining events; timeout prevents permanent hang
        console.print("[bold yellow]Waiting for remaining events to be written...[/bold yellow]")
        engine.wait_for_completion(timeout=5)
        console.print("[bold green]Simulation complete![/bold green]")

        if sort_output:
            console.print("[dim]Sorting output by timestamp...[/dim]")
            sorted_count = _sort_output_logs(output_dir)
            console.print(f"[dim]Sorted {sorted_count} JSON feed(s) into TimeGenerated order.[/dim]")

        console.print(f"Logs saved to: [cyan]{output_dir}/[/cyan]")

    except KeyboardInterrupt:
        shutdown_requested.set()
        engine._stop_event.set()
        console.print("\n[bold red]Shutting down...[/bold red]")
    except Exception as e:
        logger.exception(f"Critical failure: {e}")
    finally:
        engine.stop()

if __name__ == "__main__":
    main()
