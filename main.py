import os
import json
import logging
import copy
import click
import time
import signal
import sys
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
    from kinetix.schemas.network import FirewallEvent, DNSEvent
    from kinetix.schemas.cloud_auth import AuthenticationEvent, CloudActivityEvent, O365ActivityEvent
    from kinetix.schemas.security import SecurityAlert, SecurityIncident

    return {
        "authentication": AuthenticationEvent,
        "process_creation": ProcessEvent,
        "file_system": FileEvent,
        "registry": RegistryEvent,
        "network_connection": FirewallEvent,
        "dns_query": DNSEvent,
        "office_activity": O365ActivityEvent,
        "cloud_activity": CloudActivityEvent,
        "security_alert": SecurityAlert,
        "security_incident": SecurityIncident,
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

@click.command()
@click.option("--scenario", multiple=True, default=["scenarios/ransomware_v1.json"], help="Path(s) to scenario JSON files to execute.")
@click.option("--output-dir", default="logs", help="Directory where JSON and CEF logs will be saved.")
@click.option("--temporal/--no-temporal", default=True, help="Enable realistic temporal spacing between events (Markov chains + Gaussian jitter).")
@click.option("--stress", is_flag=True, help="Enable high-throughput mode (ignores scenario delays, increases worker count).")
@click.option("--duration", type=int, default=0, help="Simulation duration in seconds. If 0 (default), the generator runs indefinitely until interrupted.")
def main(scenario, output_dir, temporal, stress, duration):
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

    # 4. Graceful Shutdown Handler
    def signal_handler(sig, frame):
        console.print("\n[bold red]Interrupted! Shutting down gracefully...[/bold red]")
        engine.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    
    engine.start()
    
    try:
        # 5. Execute Simulation Loop
        
        if duration == 0:
            console.print("[bold yellow]Mode: Infinite (Run until Ctrl+C)[/bold yellow]")
        else:
            console.print(f"[bold cyan]Mode: Timed ({duration}s)[/bold cyan]")

        while True:
            # --- Dynamic Session Rotation ---
            # Roll new SessionID, CNC_IP, etc. for each iteration
            var_manager._set_session_vars()
            
            # Re-load and re-resolve scenarios to ensure new RANDOM_* values
            all_stages = []
            for s_path in scenario:
                if os.path.exists(s_path):
                    all_stages.extend(load_scenario(s_path, var_manager))
            
            if not all_stages:
                logger.error("No valid stages loaded. Breaking loop.")
                break

            attack_chain = AttackChain(
                scenario_id=var_manager.session_vars["SESSION_ID"][:8], 
                name=f"Simulation Cycle ({time.strftime('%H:%M:%S')})", 
                stages=all_stages
            )
            
            console.print(f"[green]Executing chain: {attack_chain.name}[/green]")
            attack_chain.run(engine)
            
            elapsed = time.time() - start_time
            if duration > 0 and elapsed >= duration:
                break
            
            if duration == 0:
                # Small breather between cycles
                time.sleep(1) 

        engine.wait_for_completion()
        console.print("[bold green]Simulation complete![/bold green]")
        console.print(f"Logs saved to: [cyan]{output_dir}/[/cyan]")
        
    except Exception as e:
        logger.exception(f"Critical failure: {e}")
    finally:
        engine.stop()

if __name__ == "__main__":
    main()
