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
from logging.handlers import RotatingFileHandler
from rich.console import Console
from rich.logging import RichHandler

from kinetix.core.engine import KinetixEngine
from kinetix.core.scenario import AttackChain
from kinetix.outputs.file import FileOutput
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
    from kinetix.schemas.endpoint import ProcessEvent, FileEvent, RegistryEvent
    from kinetix.schemas.network import FirewallEvent, DNSEvent, ProxyEvent
    from kinetix.schemas.cloud_auth import AuthenticationEvent, VPNEvent, CloudActivityEvent, O365ActivityEvent
    from kinetix.schemas.security import SecurityAlert, SecurityIncident
    from kinetix.schemas.app import webServerEvent, DatabaseEvent
    from kinetix.schemas.linux import LinuxAuthEvent, LinuxSudoEvent, LinuxAuditdEvent, LinuxKernelEvent, LinuxCronEvent, LinuxProcessEvent
    from kinetix.schemas.macos import MacOSLogEvent, MacOSAuthEvent, MacOSAppExecEvent
    from kinetix.schemas.email import EmailEvent
    from kinetix.schemas.cloud_app import CloudAppEvent
    from kinetix.schemas.identity import IdentityLogonEvent, AADNonInteractiveSignIn

    return {
        "authentication": AuthenticationEvent,
        "process_creation": ProcessEvent,
        "file_system": FileEvent,
        "registry": RegistryEvent,
        "network_connection": FirewallEvent,
        "dns_query": DNSEvent,
        "proxy": ProxyEvent,
        "vpn": VPNEvent,
        "web_request": webServerEvent,
        "db_query": DatabaseEvent,
        "office_activity": O365ActivityEvent,
        "cloud_activity": CloudActivityEvent,
        "security_alert": SecurityAlert,
        "security_incident": SecurityIncident,
        "linux_auth": LinuxAuthEvent,
        "linux_sudo": LinuxSudoEvent,
        "linux_audit": LinuxAuditdEvent,
        "linux_kernel": LinuxKernelEvent,
        "linux_cron": LinuxCronEvent,
        "linux_process": LinuxProcessEvent,
        "macos_log": MacOSLogEvent,
        "macos_auth": MacOSAuthEvent,
        "macos_exec": MacOSAppExecEvent,
        "email_event": EmailEvent,
        "cloud_app": CloudAppEvent,
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


def _generate_baseline_noise(count: int, var_manager: VariableManager) -> list:
    import copy
    from kinetix.schemas.base import BaseLogEvent
    from kinetix.schemas.endpoint import ProcessEvent, FileEvent, RegistryEvent
    from kinetix.schemas.network import FirewallEvent, DNSEvent, ProxyEvent
    from kinetix.schemas.cloud_auth import AuthenticationEvent, VPNEvent, CloudActivityEvent, O365ActivityEvent
    from kinetix.schemas.security import SecurityAlert, SecurityIncident
    from kinetix.schemas.app import webServerEvent, DatabaseEvent

    event_registry = _build_event_registry()
    events = []
    for _ in range(count):
        tpl = random.choice(_BENIGN_NOISE_TEMPLATES)
        resolved = var_manager.resolve(copy.deepcopy(tpl))
        params = resolved.copy()
        params.pop("source", None)
        params.pop("event_type", None)
        etype = resolved.get("event_type", "")
        model_class = event_registry.get(etype, BaseLogEvent)
        try:
            events.append(model_class(**params))
        except Exception:
            pass
    return events


@click.command()
@click.option("--scenario", multiple=True, default=["scenarios/ransomware_v1.json"], help="Path(s) to scenario JSON files to execute.")
@click.option("--output-dir", default="logs", help="Directory where JSON and CEF logs will be saved.")
@click.option("--temporal/--no-temporal", default=True, help="Enable realistic temporal spacing between events (Markov chains + Gaussian jitter).")
@click.option("--stress", is_flag=True, help="Enable high-throughput mode (ignores scenario delays, increases worker count).")
@click.option("--duration", type=int, default=0, help="Simulation duration in seconds. If 0 (default), the generator runs indefinitely until interrupted.")
@click.option("--baseline-ratio", type=float, default=0.0, help="Ratio of benign noise events to inject alongside attack events (0.0 = off, 0.95 = 95% benign).")
@click.option("--annotate", is_flag=True, help="Write a .annotations.json sidecar file mapping event_id to expected detections for SOC training.")
def main(scenario, output_dir, temporal, stress, duration, baseline_ratio, annotate):
    """
    Kinetix: High-Performance Synthetic Log Generator for SIEM Validation.
    Generates JSON (Azure Sentinel parity) and CEF logs simultaneously.
    """
    console.print("[bold blue]Kinetix Log Generator[/bold blue]")
    
    start_time = time.time()
    if duration > 0 and duration < 5:
        logger.warning(f"Requested duration {duration}s is below minimum for stability. Bumping to 5s.")
        duration = 5

    # 1. Initialize Global Assets
    file_output = FileOutput(output_dir=output_dir)
    var_manager = VariableManager()
    
    # 2. Initialize Temporal Engine
    temporal_engine = None
    if temporal:
        delay = 0.01 if stress else 0.2
        temporal_engine = TemporalEngine(profile=TimingProfile(avg_delay_seconds=delay))
    
    # 3. Initialize Engine
    engine = KinetixEngine(
        output_providers=[file_output], 
        worker_count=8 if stress else 2,
        temporal_engine=temporal_engine
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
        
        if duration == 0:
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
                    noise_stage = {"name": "Baseline Noise", "delay": 0.05, "events": noise_events}
                    interleave = []
                    for s in all_stages:
                        interleave.append(s)
                        interleave.append(noise_stage)
                    all_stages = interleave
                    console.print(f"[dim]Injected {noise_count} benign noise events[/dim]")

            attack_chain = AttackChain(
                scenario_id=var_manager.session_vars["SESSION_ID"][:8], 
                name=f"Simulation Cycle ({time.strftime('%H:%M:%S')})", 
                stages=all_stages,
                stress=stress,
            )
            
            console.print(f"[green]Executing chain: {attack_chain.name}[/green]")
            attack_chain.run(engine, stop_event=shutdown_requested)
            
            elapsed = time.time() - start_time
            if duration > 0 and elapsed >= duration:
                console.print("[bold yellow]Duration reached. Draining queue and shutting down...[/bold yellow]")
                shutdown_requested.set()
                engine._stop_event.set()
                break
            
            if duration == 0 and not shutdown_requested.is_set():
                # Interruptible breather between cycles
                for _ in range(10):
                    if shutdown_requested.is_set():
                        break
                    time.sleep(0.1)

        # Let workers drain remaining events; timeout prevents permanent hang
        console.print("[bold yellow]Waiting for remaining events to be written...[/bold yellow]")
        engine.wait_for_completion(timeout=5)
        console.print("[bold green]Simulation complete![/bold green]")
        console.print(f"Logs saved to: [cyan]{output_dir}/[/cyan]")

        if annotate:
            annotation_path = os.path.join(output_dir, "Kinetix_Annotations.json")
            annotations = []
            unified_path = os.path.join(output_dir, "Kinetix_Unified.json")
            if os.path.exists(unified_path):
                with open(unified_path, "r") as af:
                    for line in af:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            evt = orjson.loads(line)
                        except orjson.JSONDecodeError:
                            continue
                        if evt.get("expected_detection") or evt.get("is_malicious"):
                            annotations.append({
                                "event_id": evt.get("Id", ""),
                                "event_type": evt.get("Type", ""),
                                "scenario_id": evt.get("ScenarioId", evt.get("scenario_id", "")),
                                "is_malicious": evt.get("is_malicious", False),
                                "expected_detection": evt.get("expected_detection", False),
                                "detection_guidance": evt.get("detection_guidance", None),
                                "killchain_phase": evt.get("killchain_phase", ""),
                                "mitre": evt.get("mitre", None),
                            })
            if annotations:
                with open(annotation_path, "w") as af:
                    af.write(orjson.dumps(annotations, option=orjson.OPT_APPEND_NEWLINE).decode("utf-8"))
                console.print(f"[yellow]Wrote {len(annotations)} annotations to {annotation_path}[/yellow]")
            else:
                console.print("[yellow]No annotated events found (use 'expected_detection: true' in scenarios)[/yellow]")
        
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
