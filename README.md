# Kinetix Log Generator

Kinetix is a high-performance, modular synthetic log generator designed for SOC engineering, SIEM validation, and adversarial simulation testing.

It generates high-fidelity telemetry that mimics real-world enterprise environments, supporting both modern JSON formats (with 1:1 schema parity for **Microsoft Sentinel**) and legacy **CEF** (Common Event Format) for traditional SIEMs like Splunk, QRadar, and ArcSight.

## 🚀 Key Features

- **Multi-SIEM Output**: Simultaneous generation of per-table JSON files and a unified CEF stream.
- **Sentinel Parity**: Log schemas are mapped 1:1 to Azure Monitor/Sentinel tables (DeviceProcessEvents, SigninLogs, etc.).
- **Adversarial Realism**: Scenarios are mapped to **MITRE ATT&CK** TTPs and include dynamic variables for realism.
- **Variable Engine**: Use templates like `{{RANDOM_IP}}`, `{{RANDOM_USER}}`, and `{{RANDOM_PID}}` to ensure sessions are unique.
- **Temporal Realism**: Implements Markov-chain based event sequencing and Gaussian jitter for realistic timing.
- **Stress Testing**: Scalable volume multiplication (`multiply` key) for high-throughput stress and flood testing.
- **Flexible Scenarios**: JSON-based scenario files allow for easy creation of custom attack chains or benign noise profiles.

## 🛠️ Usage

### Installation

```bash
# Clone the repository
git clone https://github.com/your-repo/kinetix.git
cd kinetix

# Install dependencies (requires Python 3.12+)
pip install -r requirements.txt
```

### Basic Execution

Run the default ransomware scenario:
```bash
python3 main.py
```

### Advanced Execution

Run multiple scenarios with a minimum duration of 30 seconds:
```bash
python3 main.py --scenario scenarios/apt_volt_typhoon_style.json \
               --scenario scenarios/benign_noise.json \
               --duration 30
```

Enable stress testing (high throughput, ignores delays):
```bash
python3 main.py --stress --scenario scenarios/flood_test.json
```

### CLI Options

| Option | Shortcut | Description |
| :--- | :--- | :--- |
| `--scenario` | None | Path to scenario JSON file (can be specified multiple times). |
| `--output-dir` | None | Directory where logs will be saved (default: `logs`). |
| `--temporal` | None | Enable realistic timing (default: True). Use `--no-temporal` to disable. |
| `--stress` | None | Execute at maximum speed with increased worker threads. |
| `--duration` | None | Simulation time in seconds. If 0 (default), it runs indefinitely by looping scenarios. |
| `--help` | `-h` | Show all available options and usage help. |

## 📁 Project Structure

- `kinetix/schemas/`: Pydantic models (source-of-truth for all log formats).
- `kinetix/core/`: The core engine, worker pool, and temporal logic.
- `kinetix/outputs/`: Providers for file-based JSON and CEF output.
- `scenarios/`: A library of pre-built attack chains and background noise.
- `tools/`: Utility scripts (e.g., `to_dcr.py` for Azure ingestion).

## 🛡️ License

MIT License - See LICENSE file for details.
