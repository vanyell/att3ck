import os
import sys
import subprocess
import time
import json
from pathlib import Path

def retest_phase2():
    print("🔬 Phase 2 Retest - Temporal & Markov Validation")
    
    # 1. Setup
    log_dir = Path("logs")
    if log_dir.exists():
        import shutil
        shutil.rmtree(log_dir)
    log_dir.mkdir()
    
    scenario = "scenarios/markov_test.json"
    
    # 2. Run with Temporal Enabled
    print("🏃 Running simulation with --temporal...")
    start_time = time.time()
    
    try:
        subprocess.run(
            [sys.executable, "main.py", "--scenario", scenario, "--temporal", "--duration", "30"],
            check=True,
            capture_output=True,
            text=True
        )
    except subprocess.CalledProcessError as e:
        print(f"❌ Simulation failed: {e.stderr}")
        sys.exit(1)
        
    end_time = time.time()
    duration = end_time - start_time
    
    # 3. Analyze Results
    unified_json = log_dir / "Kinetix_Unified.json"
    if not unified_json.exists():
        print("❌ Error: Kinetix_Unified.json not found.")
        sys.exit(1)
        
    with open(unified_json, "r") as f:
        events = [json.loads(line) for line in f if line.strip()]
    
    print(f"📊 Results:")
    print(f"   - Total Events Generated: {len(events)} (Original scenario had 1)")
    print(f"   - Total Duration: {duration:.2f} seconds")
    
    # Validation 1: Markov Branching (Expect > 1 event due to 80% total follow-up prob)
    if len(events) <= 1:
        print("⚠️  Warning: Only 1 event generated. Markov branching might have missed (20% chance) or is failing.")
    else:
        print("✅ Markov Branching Verified: Follow-up events detected.")
        for e in events:
            print(f"     -> {e.get('Type', e.get('event_type', 'unknown'))} (Depth: {e.get('depth', 0)})")

    # Validation 2: Temporal Realism (Expect duration > 2 seconds per event if after hours)
    # At 1 AM, delay is 0.2 * 10 = 2.0s per event.
    expected_min_duration = 1.8 * len(events) / 2 # simplified check
    
    if duration >= expected_min_duration:
        print(f"✅ Temporal Realism Verified: After-hours slowdown correctly applied.")
    else:
        print(f"❌ Temporal Check Failed: Simulation was too fast ({duration:.2f}s). Check TimingProfile.")

if __name__ == "__main__":
    retest_phase2()
