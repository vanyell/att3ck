# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Commands
- **Run Simulation**: `python3 main.py`
- **Run Specific Scenarios**: `python3 main.py --scenario scenarios/name.json`
- **Run with Duration**: `python3 main.py --duration <seconds>`
- **SOC Training Mode**: `python3 main.py --baseline-ratio 0.95 --scenario scenarios/name.json`
- **Stress Test**: `python3 main.py --stress --scenario scenarios/name.json`
- **Simulated-Clock Baseline** (multi-day history in a short run): `python3 main.py --sim-clock --sim-days 14 --baseline-ratio 0.95 --scenario scenarios/name.json`
  - Disables log rotation and sorts each JSON feed by `TimeGenerated` on completion (`--no-sort-output` to skip).
  - Backdated windows (`--sim-start` in a prior year) need `--syslog-format rfc5424`; RFC 3164 carries no year.
- **Run Tests**: `pytest`
- **Run Single Test Class**: `pytest tests/test_kinetix.py -k "TestEmailEvent or TestCloudAppEvent"`
- **Full Test Suite**: `pytest -v`

## Architecture
Kinetix is a modular synthetic log generator designed for SIEM validation and adversarial simulation.

### Core Components
- **`main.py`**: Entry point; handles CLI arguments (--scenario, --duration, --stress, --baseline-ratio, --sim-clock, --syslog-format, --sort-output) and initializes the simulation.
- **`kinetix/core/`**: 
    - `engine.py`: Orchestrates scenario execution and worker management.
    - `scenario.py`: Parses and manages JSON-based attack/noise profiles.
    - `temporal.py`: Implements Markov-chain sequencing and Gaussian jitter for timing realism.
    - `vars.py`: Variable engine for template substitution (e.g., `{{RANDOM_IP}}`, `{{PERSONA_USER}}`).
    - `worker.py`: Handles concurrent event generation.
- **`kinetix/schemas/`**: Pydantic models serving as the source-of-truth for log formats, maintaining 1:1 parity with Microsoft Sentinel tables (e.g., `DeviceProcessEvents`, `SigninLogs`, `EmailEvents`, `CloudAppEvents`, `IdentityLogonEvents`).
- **`kinetix/outputs/`**: Providers for exporting logs to JSON files, CEF streams, syslog (RFC 3164), and Windows Event XML (EVT).
- **`kinetix/intelligence/`**: Context-aware generators including `context.py` (user persona system with 10 role-based identities).
- **`scenarios/`**: 31 JSON definitions of event sequences mapped to MITRE ATT&CK TTPs (4 AI-powered scenarios added on top of the existing AI category: Shadow AI/GenAI data exfiltration, agentic AI/tool-invocation abuse, AI supply-chain/model compromise, LLM-assisted malware development — cross-tagged with MITRE ATLAS via the `atlas` field where ATT&CK Enterprise has no AI-native technique).

### Log Flow
Scenario JSON $\rightarrow$ Variable Substitution (incl. persona resolution) $\rightarrow$ Baseline Noise Interleave $\rightarrow$ Temporal Timing $\rightarrow$ Pydantic Schema Validation $\rightarrow$ Output Provider (JSON/CEF/Syslog/EVT)

### Template Variables
- **Persona templates** (session-stable): `{{PERSONA_USER}}`, `{{PERSONA_HOST}}`, `{{PERSONA_EMAIL}}`, `{{PERSONA_ROLE}}`, `{{PERSONA_DEPT}}`, `{{PERSONA_DOMAIN}}`, `{{PERSONA_IS_ADMIN}}`, `{{PERSONA_IS_SENSITIVE}}`
- **Random generators** (per-call): `{{RANDOM_IP}}`, `{{RANDOM_USER}}`, `{{RANDOM_HOST}}`, `{{RANDOM_EMAIL}}`, `{{RANDOM_UA}}`, `{{RANDOM_URL}}`, `{{RANDOM_AI_MODEL}}`, `{{RANDOM_AI_APP}}`, `{{RANDOM_LOCATION}}`, `{{RANDOM_CITY}}`, `{{RANDOM_ORG}}`, `{{RANDOM_PID}}`, `{{RANDOM_PORT}}`, `{{RANDOM_GUID}}`, `{{RANDOM_INT}}`, `{{RANDOM_LINUX_HOST}}`, `{{RANDOM_MAC_HOST}}`, `{{RANDOM_COMMANDLINE}}`, `{{RANDOM_FILE_PATH}}`, `{{RANDOM_REGISTRY_VALUE}}`, `{{RANDOM_SCRIPT_BLOCK}}`
- **Corpus-backed generators**: `RANDOM_UA`, `RANDOM_URL`, `RANDOM_COMMANDLINE`, `RANDOM_FILE_PATH`, `RANDOM_REGISTRY_VALUE`, and `RANDOM_SCRIPT_BLOCK` prefer real mined EVTX corpus values (see `kinetix/intelligence/corpus_profiles/`, `kinetix/core/vars.py:CORPUS_FIELD_CANDIDATES`) and fall back to a small static pool when the corpus has no data for that field.
- **Session variables**: `{{SESSION_ID}}`, `{{CNC_IP}}`, `{{MALICIOUS_DOMAIN}}`, `{{MALICIOUS_URL}}`, `{{DEEPFAKE_PHONE}}`

### Key Files for Phase 4
- `kinetix/schemas/email.py` — EmailEvent schema
- `kinetix/schemas/cloud_app.py` — CloudAppEvent schema
- `kinetix/schemas/identity.py` — IdentityLogonEvent + AADNonInteractiveSignIn schemas
- `kinetix/schemas/base.py` — BaseLogEvent
- `kinetix/intelligence/context.py` — ContextGenerator with 10 user personas
- `kinetix/core/vars.py` — VariableManager with persona template resolution
- `kinetix/outputs/file.py` — Table mapping + internal field filtering
