import os
import sys
import subprocess
import json
import time
import logging
from pathlib import Path

# Configure Verification Logger for Integration Loop
logging.basicConfig(
    filename="debug.log",
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(message)s",
    filemode="w"
)
logger = logging.getLogger("verify")

def run_verification():
    logger.info("Starting Kinetix Verification Test")
    print("🚀 Starting Kinetix Verification Test...")
    
    # 1. Environment & Setup
    log_dir = Path("logs")
    if log_dir.exists():
        import shutil
        shutil.rmtree(log_dir)
    log_dir.mkdir()
    logger.debug(f"Cleared and recreated {log_dir}")

    # 2. Stress/Throughput Benchmarking
    scenario = "scenarios/total_coverage.json"
    logger.info(f"Running benchmark with scenario: {scenario}")
    print(f"📦 Running benchmark: {scenario}")
    
    start_time = time.time()
    try:
        # Run with --stress for true performance benchmark
        result = subprocess.run(
            [sys.executable, "main.py", "--scenario", scenario, "--stress"], 
            check=True,
            capture_output=True,
            text=True
        )
        logger.debug("Simulation subprocess completed successfully")
    except subprocess.CalledProcessError as e:
        logger.error(f"Simulation failed with exit code {e.returncode}")
        logger.error(f"Stderr: {e.stderr}")
        print(f"❌ Simulation failed. Check debug.log for details.")
        sys.exit(1)
    
    end_time = time.time()
    duration = end_time - start_time

    # 3. Validation & Behavioral Mapping verification
    expected_files = [
        "CommonSecurityLog.log",
        "DeviceProcessEvents.json",
        "SecurityIncident.json",
        "SigninLogs.json",
        "Kinetix_Unified.json",
        "Kinetix_Unified.log"
    ]
    
    missing = []
    for f in expected_files:
        p = log_dir / f
        if not p.exists() or p.stat().st_size == 0:
            missing.append(f)
            
    if missing:
        logger.error(f"Missing or empty expected files: {missing}")
        print(f"❌ Verification failed. Missing files: {missing}")
        sys.exit(1)
    
    # 4. LPS Calculation (Throughput)
    unified_json = log_dir / "Kinetix_Unified.json"
    with open(unified_json, "r") as f:
        lines = f.readlines()
        event_count = len(lines)
    
    lps = event_count / duration if duration > 0 else 0
    
    logger.info(f"Throughput: {lps:.2f} Lines Per Second (LPS)")
    logger.info(f"Total Events: {event_count} in {duration:.4f}s")
    
    print(f"📊 Throughput: {lps:.2f} LPS ({event_count} events in {duration:.2f}s)")

    if event_count < 20:
        logger.error(f"Low event count: {event_count}")
        print(f"❌ Sanity check failed: Expected >= 20 events.")
        sys.exit(1)

    logger.info("Verification Successful")
    print("✅ Verification Successful! Performance metrics saved to debug.log")

if __name__ == "__main__":
    try:
        run_verification()
    except Exception as e:
        logger.exception(f"Unexpected error in verification loop: {e}")
        print("❌ Critical failure. See debug.log")
        sys.exit(1)
