# Kinetix — Synthetic Log Generator for SIEM Validation & SOC Training

Kinetix is a high-performance, modular synthetic log generator designed for SOC engineering, SIEM validation, adversarial simulation, and analyst training. It produces high-fidelity telemetry that mimics real-world enterprise environments, supporting modern JSON (Azure Sentinel 1:1 parity) and legacy CEF formats for Splunk, QRadar, ArcSight, Wazuh, and any SIEM.

## Key Features

- **31 MITRE ATT&CK-Mapped Scenarios** — Ransomware, APT (LockBit, BEC, SolarWinds, LAPSUS$, Volt Typhoon), AI-powered attacks, OAuth spoofing, RMM/C2 abuse, AD certificate attacks, cloud lateral movement, Linux/macOS threats, and benign noise baselines
- **AI-Enabled Attack Coverage** — AI-generated spear-phishing, LLM prompt injection, deepfake social engineering (CEO fraud/vishing), AI-assisted recon & credential theft, Shadow AI/GenAI data exfiltration, agentic AI/tool-invocation abuse, AI supply-chain (model) compromise, LLM-assisted malware development — cross-tagged to MITRE ATLAS where ATT&CK has no AI-native equivalent
- **Modern Cloud Attack Scenarios** — OAuth consent phishing, device code phishing, SSO session token theft (AiTM), cross-tenant synchronization abuse, RMM tool abuse for C2 (ClickFix + BeyondTrust)
- **Active Directory Attack Scenarios** — ADCS certificate abuse (ESC1), Kerberos PKINIT certificate authentication, DCSync
- **Sentinel Schema Parity** — 19 Pydantic models mapped 1:1 to Azure Monitor/Sentinel tables (DeviceProcessEvents, SigninLogs, CommonSecurityLog, OfficeActivity, EmailEvents, CloudAppEvents, IdentityLogonEvents, etc.)
- **Cross-Platform Coverage** — Linux (auth, sudo, auditd, kernel, cron, process) and macOS (unified log, authd, app execution) schemas with variable substitution
- **Five Output Feeds** — Simultaneous per-table JSON files + unified CEF stream + RFC 3164 syslog + Windows Event XML (EVT) + Linux auditd wire format (all rotated at 10MB)
- **Variable Template Engine** — 30+ template variables including user persona templates for identity-consistent event generation
- **Temporal Realism** — Markov-chain event sequencing, Gaussian jitter, time-of-day traffic scaling
- **Killchain Labeling** — Every event tagged with killchain phase for SOC training & detection gap analysis
- **Volume Multiplication** — `multiply` key on any event for high-throughput stress/flood testing
- **Baseline Noise Injection** — `--baseline-ratio` flag to automatically interleave benign noise with attack events
- **Identity Persona System** — Consistent user personas (role, department, domain, typical host) for cross-event identity correlation
- **Scalable Architecture** — Producer-consumer pattern with configurable worker threads, thread-safe lazy logger initialization

## Quick Start

### Installation

```bash
git clone <repo-url> && cd att3ck
bash setup_env.sh          # Creates venv + installs dependencies
```

Or manually:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -e .
```

> **Important**: Always use `./venv/bin/python` (or activate the venv with `source venv/bin/activate` first). Running `python3 main.py` directly uses the system interpreter which lacks the required dependencies.

### Run a Scenario

```bash
./venv/bin/python main.py
```
Default: runs `scenarios/ransomware_v1.json` indefinitely.

Run a single pass of an AI-powered attack:

```bash
./venv/bin/python main.py --scenario scenarios/ai_phishing_campaign.json --duration 30
```

### Run Modern Attack Scenarios

```bash
# OAuth consent phishing (2026 top cloud threat)
./venv/bin/python main.py --scenario scenarios/oauth_consent_phishing.json --duration 60

# OAuth device code phishing (active campaigns per Microsoft/Okta)
./venv/bin/python main.py --scenario scenarios/oauth_device_code_phishing.json --duration 60

# RMM tool abuse for C2 (ClickFix → BeyondTrust → ransomware)
./venv/bin/python main.py --scenario scenarios/rmm_tool_abuse_c2.json --duration 60

# SSO session token theft via AiTM phishing proxy
./venv/bin/python main.py --scenario scenarios/sso_session_token_theft.json --duration 60

# ADCS certificate abuse (ESC1 → PKINIT → DCSync)
./venv/bin/python main.py --scenario scenarios/adcs_certificate_abuse.json --duration 60

# Cross-tenant sync attack (lateral movement across Azure tenants)
./venv/bin/python main.py --scenario scenarios/cross_tenant_sync_attack.json --duration 60
```

### SOC Training Mode (with noise)

```bash
./venv/bin/python main.py \
  --scenario scenarios/oauth_consent_phishing.json \
  --scenario scenarios/sso_session_token_theft.json \
  --baseline-ratio 0.95 \
  --duration 120
```

This generates 95% benign noise interleaved with attacks. Malicious events stay
identifiable by their `killchain_phase` and `mitre` tags.

### Stress Test

```bash
./venv/bin/python main.py --stress --scenario scenarios/total_coverage.json --duration 10
```

### Verify Engine (Script)

```bash
./venv/bin/python scripts/verify_engine.py
```

## CLI Options

| Option | Default | Description |
|--------|---------|-------------|
| `--scenario` | `scenarios/ransomware_v1.json` | Path to scenario JSON (repeatable) |
| `--output-dir` | `logs` | Output directory for JSON/CEF files |
| `--temporal` / `--no-temporal` | `True` | Enable Markov-chain timing with Gaussian jitter |
| `--stress` | `False` | High-throughput mode (8 workers, 0.01s delay, bypasses stage delays) |
| `--duration` | `0` (infinite) | Simulation duration in seconds. Enforced as a hard deadline *during* a cycle, not just between cycles — values below 5s are bumped to 5s for stability |
| `--baseline-ratio` | `0.0` | Ratio of benign noise to attack events (0.0 = off, 0.95 = 95% benign) |
| `--syslog-host` | `None` | If set, also stream every event's RFC 3164 syslog representation live over the network to this host (e.g. a Wazuh manager's `<remote>` syslog collector, or a local rsyslog instance) |
| `--syslog-port` | `514` | Destination port for `--syslog-host` |
| `--syslog-proto` | `udp` | Transport for `--syslog-host` — `udp` or `tcp` |
| `--sim-clock` | `False` | Simulated-clock mode: stamp events across a virtual multi-day window (diurnal + weekend-aware pacing via `TemporalEngine`) instead of real wall-clock time, so a realistic historical baseline can be generated in a short run |
| `--sim-days` | `7.0` | Span of simulated time to generate when `--sim-clock` is set |
| `--sim-start` | `None` (= now − `--sim-days`) | ISO start timestamp for `--sim-clock`, e.g. `2026-09-01` or `2026-09-01T00:00:00` |
| `--syslog-format` | `rfc3164` | Wire format for syslog output — `rfc3164` or `rfc5424` |
| `--sort-output` | on for `--sim-clock`, else off | Rewrite each JSON feed in `TimeGenerated` order after the run |
| `--help` | | Show full usage |

### Simulated-Clock Baseline Generation

By default, event timestamps are wall-clock (`datetime.now()`), so building a
realistic multi-day/multi-week baseline for Wazuh threshold tuning would mean
running the generator continuously for that many real days. `--sim-clock`
decouples timestamps from wall-clock time: each event is stamped with a
virtual timestamp that advances by `TemporalEngine`'s diurnal- and
weekend-aware delay (business hours vs. after-hours vs. Sat/Sun), while the
generator itself runs at full throughput with no artificial sleeps. This lets
you produce a full week (or more) of realistically-paced historical log data
in minutes instead of days.

```bash
# Generate 14 simulated days of 95% benign / 5% attack traffic, ending "now"
./venv/bin/python main.py \
  --sim-clock --sim-days 14 \
  --scenario scenarios/linux_ssh_bruteforce.json \
  --baseline-ratio 0.95
```

`--duration` still acts as a real-time safety cap if set; otherwise the run
stops once the simulated window is fully filled.

Weekend shaping (Sat/Sun suppression) applies **only** in `--sim-clock` mode.
On the real-time path it would compound with the after-hours divisor — 66×
combined at the defaults — and throttle an ordinary weekend-evening run down
to a handful of events, so `TimingProfile.weekend_shaping` defaults to off and
`--sim-clock` turns it on.

**Disk usage.** Because the virtual clock advances by exactly the delay
`TemporalEngine` computes per event, the event count for a given `--sim-days`
is *inversely* proportional to `avg_delay_seconds`: **raise**
`avg_delay_seconds` (via a custom `TimingProfile`) or shrink `--sim-days` to
generate less. Lowering it makes the run substantially larger.

**Output ordering.** Workers write in completion order, not timestamp order,
so a sim-clock run's files come out inverted — measured at 11.3% of lines with
backward jumps of up to 11 minutes on a 3-day window. Sentinel, Splunk and
Wazuh all index on the timestamp field and don't care, but anything that reads
the file as a stream does. `--sort-output` (on by default under `--sim-clock`)
rewrites each JSON feed in `TimeGenerated` order once the run finishes, using a
chunked external merge sort so peak memory stays bounded regardless of window
size. Verified at 0 inversions across 449,260 lines. Pass `--no-sort-output`
to skip it; the CEF, syslog, EVTX and auditd feeds keep write order either way.

**Backdated windows and syslog.** RFC 3164's timestamp (`%b %d %H:%M:%S`) has
no year, so a `--sim-start` in a prior year is silently re-dated to the ingest
year by the receiving collector, while the JSON and CEF feeds from the same run
carry the correct year. Kinetix warns when the window falls outside the current
year; pass `--syslog-format rfc5424` for full ISO 8601 timestamps that survive
ingest. RFC 3164 remains the default because Wazuh's built-in decoders are
written against it.

`--sim-clock` also disables log rotation, because rotating mid-run would
delete the oldest part of the very window you asked for — and would do it
per-feed, leaving high-volume tables covering fewer days than low-volume ones
and skewing any cross-table correlation. Budget accordingly: a completed
`--sim-days 3` run at the default pacing writes ~225k events / ~380 MB across
all feeds in about 40 seconds, and volume scales with the window. Real-time
runs keep the bounded ~60 MB per-feed rotation (10 MB × 5) as before.

## Scenario Catalog

### Modern Cloud & Identity Attack Scenarios

| Scenario File | Description | Key TTPs |
|---------------|-------------|----------|
| `oauth_consent_phishing.json` | Malicious OAuth app registration → consent grant → Graph API mailbox enumeration → data exfiltration via OAuth app | T1525, T1114.002, T1048.002 |
| `oauth_device_code_phishing.json` | Device code phishing email → token theft → refresh token harvesting → persistence via service principal creation | T1566.002, T1525, T1528, T1136.003 |
| `sso_session_token_theft.json` | AiTM phishing proxy → SSO session cookie theft → session replay from attacker infrastructure → privilege escalation to Global Admin → SharePoint exfiltration | T1557, T1539, T1098.002, T1567.002 |
| `cross_tenant_sync_attack.json` | Source tenant compromise → cross-tenant sync policy creation → user synchronization → privilege escalation in target tenant → data exfiltration | T1078.004, T1098.005, T1526, T1098.002 |

### Active Directory & Certificate Attack Scenarios

| Scenario File | Description | Key TTPs |
|---------------|-------------|----------|
| `adcs_certificate_abuse.json` | Certify template enumeration → Certipy ESC1 SAN certificate request → Rubeus PKINIT authentication as Domain Admin → DCSync | T1649, T1520, T1003.006 |

### RMM / C2 Abuse Scenarios

| Scenario File | Description | Key TTPs |
|---------------|-------------|----------|
| `rmm_tool_abuse_c2.json` | ClickFix social engineering → BeyondTrust RMM deployment → LSASS credential dump → lateral movement via PsExec → ransomware deployment | T1219, T1003.001, T1021.002, T1486, T1490 |

### Traditional APT Scenarios

| Scenario File | Description | Key TTPs |
|---------------|-------------|----------|
| `ransomware_v1.json` | Initial access → execution → file encryption + registry | T1078.002, T1204.002, T1486 |
| `apt_lockbit_style.json` | Log clearing → rclone exfiltration (50x) → shadow copy deletion | T1070.001, T1567.002, T1490 |
| `apt_bec_fraud.json` | New location sign-in → Outlook inbox rule → mass mail collection (100x) | T1078.004, T1137.005, T1114.002 |
| `apt_solarwinds_style.json` | Supply chain compromise → C2 DNS beaconing → internal AD discovery | T1195.002, T1071.001, T1087.002 |
| `apt_lapsus_style.json` | MFA fatigue (20x) → service principal persistence → KeyVault secret access | T1621, T1136.003, T1528 |
| `apt_volt_typhoon_style.json` | Netsh proxy → NTDS credential dump → WMIC lateral movement | T1090, T1003.003, T1047 |
| `network_recon.json` | Single blocked SMB connection (T1046/T1595) | T1046 |

### AI-Powered Attack Scenarios

| Scenario File | Description | Key TTPs |
|---------------|-------------|----------|
| `ai_phishing_campaign.json` | AI-gen spear-phishing → credential harvesting page → contextual deepfake follow-up → mailbox exfiltration | T1566.001/2, T1056.004, T1078.004, T1114.002, T1048.002 |
| `ai_prompt_injection_attack.json` | Discovery of AI tooling in use → indirect prompt injection executes attacker payload → direct prompt injection generates AMSI-evading PowerShell → crypto-wallet theft via model-generated commands | T1518, T1059.006, T1587.001, T1059.001, T1071.001, T1565.002, T1528 (+ ATLAS AML.T0051.000/.001) |
| `ai_deepfake_social_engineering.json` | Social media recon for voice cloning → deepfake vishing (cloned CFO voice) → fraudulent wire transfer → SIEM detection alert | T1593.001, T1566.004, T1565.001 |
| `ai_assisted_recon.json` | AI-steered LinkedIn scraping + DNS sweep → adaptive credential stuffing (30x) → MFA fatigue with AI-optimized timing → token theft → service principal persistence → rclone exfiltration | T1593.001, T1590, T1110.001, T1621, T1528, T1136.003, T1567.002 |
| `shadow_ai_data_exfiltration.json` | Employee browses to a consumer GenAI app → pastes confidential data into chat → uploads proprietary source code → CASB/DLP detects the policy violation | T1567 |
| `agentic_ai_abuse.json` | Over-permissioned support-agent service principal ingests a crafted ticket (indirect prompt injection) → invokes KeyVault tool out of scope → grants itself additional credentials → leaks the secret via its own legitimate channel | T1078.004, T1098.001, T1567.002 (+ ATLAS AML.T0051.001, AML.T0053) |
| `ai_supply_chain_compromise.json` | Backdoored model pulled from a public model hub → pickle deserialization spawns a payload on load → registry persistence → C2 beaconing → EDR detection | T1195.002, T1059.006, T1059.001, T1547.001, T1071.001 (+ ATLAS AML.T0010) |
| `llm_assisted_malware_development.json` | Attacker jailbreaks an AI coding assistant under their own account → model generates obfuscated defense-evasion PowerShell → payload disables EDR → executes and beacons out | T1587.001, T1027, T1562.001, T1059.001, T1071.001 (+ ATLAS AML.T0043) |

### Linux Attack Scenarios

| Scenario File | Description | Key TTPs |
|---------------|-------------|----------|
| `linux_ssh_bruteforce.json` | SSH brute force (20x) → password spray success → post-exploit lateral movement via SSH → wget backdoor download | T1110.001, T1078.002, T1021.004, T1105 |
| `linux_privilege_escalation.json` | Linux recon (uname/cat passwd) → kernel exploit (CVE) with auditd SYSCALL → sudo misconfiguration → SSH authorized keys + cron persistence | T1082, T1548.001, T1548.003, T1098.004, T1053.003 |
| `linux_malware.json` | Cryptominer dropper (curl pipe bash) → xmrig download & process → log tampering (rm auth.log) → kernel module removal → cron persistence | T1059.004, T1105, T1496, T1070.002, T1562.004, T1053.003 |

### macOS Attack Scenarios

| Scenario File | Description | Key TTPs |
|---------------|-------------|----------|
| `macos_threats.json` | Pirated software download → Gatekeeper rejection → TCC bypass → keychain credential dump → HTTPS exfiltration → security alert | T1566.001, T1204.002, T1555.003, T1555.001, T1041 |

### Cross-Platform Noise

| Scenario File | Description |
|---------------|-------------|
| `cross_platform_noise.json` | Blended corporate baseline: Linux SSH/sudo/cron/kernel, Windows Chrome/Outlook/Signin/DNS/Firewall, macOS Terminal/VSCode/TouchID/OD, Docker audit events |

### Coverage & Noise

| Scenario File | Description |
|---------------|-------------|
| `benign_noise.json` | 6-stage corporate baseline: logins, Outlook/Teams, Chrome, SaaS networking, Windows Update, SharePoint/OneDrive sync, DB activity |
| `full_soc_demo.json` | Single-stage composite: incident alert → phishing → 50x failed auth → PowerShell C2 → file encryption → ransomware note |
| `sentinel_coverage.json` | One event per Sentinel table category (auth, cloud, DNS, process, firewall, office) |
| `total_coverage.json` | 31 events covering every Sentinel table family (incident, alert, firewall, proxy, vpn, process, file, network, registry, logon, device, AAD, signin, audit, identity, office, sharepoint, MDO, cloud, DNS, syslog, web, db) |
| `markov_test.json` | Single signin event to exercise Markov branching engine |

## Template Variables

| Variable | Scope | Example Output |
|----------|-------|---------------|
| `{{SESSION_ID}}` | Session | `a1b2c3d4-...` |
| `{{CNC_IP}}` | Session | `91.228.37.142` |
| `{{MALICIOUS_DOMAIN}}` | Session | `evil-cnc.net` |
| `{{MALICIOUS_URL}}` | Session | `https://portal-auth-verify.com/login.php` |
| `{{DEEPFAKE_PHONE}}` | Session | `+1-415-555-0199` |
| **Persona Templates** | | |
| `{{PERSONA_USER}}` | Session | `ceo_office` |
| `{{PERSONA_HOST}}` | Session | `CEO-LAPTOP-01` |
| `{{PERSONA_EMAIL}}` | Session | `ceo_office@litware.com` |
| `{{PERSONA_ROLE}}` | Session | `CEO` |
| `{{PERSONA_DEPT}}` | Session | `Executive` |
| `{{PERSONA_DOMAIN}}` | Session | `litware.com` |
| `{{PERSONA_IS_ADMIN}}` | Session | `true` |
| `{{PERSONA_IS_SENSITIVE}}` | Session | `true` |
| **Random Generators** | | |
| `{{RANDOM_IP}}` | Per-call | `192.168.1.42` |
| `{{RANDOM_HOST}}` | Per-call | `WS-PROD-042` |
| `{{RANDOM_SERVER}}` | Per-call | `SRV-015` |
| `{{RANDOM_USER}}` | Per-call | `jsmith` |
| `{{RANDOM_EMAIL}}` | Per-call | `jsmith@litware.com` |
| `{{RANDOM_UA}}` | Per-call | `Mozilla/5.0 (Windows NT 10.0; Win64; x64) ...` |
| `{{RANDOM_URL}}` | Per-call | `https://login.microsoftonline.com/...` |
| `{{RANDOM_AI_MODEL}}` | Per-call | `GPT-4o`, `Claude-3.5-Sonnet`, `Gemini-2.0-Flash` |
| `{{RANDOM_AI_APP}}` | Per-call | `ChatGPT`, `Claude.ai`, `Google Gemini` |
| `{{RANDOM_LOCATION}}` | Per-call | `US`, `GB`, `DE`, `JP`, `SG` |
| `{{RANDOM_CITY}}` | Per-call | `Seattle`, `London`, `Tokyo` |
| `{{RANDOM_ORG}}` | Per-call | `Litware Inc` |
| `{{RANDOM_PID}}` | Per-call | `12345` |
| `{{RANDOM_PORT}}` | Per-call | `54321` |
| `{{RANDOM_GUID}}` | Per-call | UUID v4 |
| `{{RANDOM_INT}}` | Per-call | `483920` |
| `{{RANDOM_LINUX_HOST}}` | Per-call | `web-01.prod`, `db-02.prod` |
| `{{RANDOM_MAC_HOST}}` | Per-call | `MBP-Jsmith`, `Mac-mini-03` |
| `{{RANDOM_COMMANDLINE}}` | Per-call, corpus-backed | `"C:\Windows\system32\cmd.exe" /c ...` |
| `{{RANDOM_FILE_PATH}}` | Per-call, corpus-backed | `C:\ProgramData\USOPrivate\UpdateStore\store.db-journal` |
| `{{RANDOM_REGISTRY_VALUE}}` | Per-call, corpus-backed | `QWORD (0x00000000-0x000556c2)` |
| `{{RANDOM_SCRIPT_BLOCK}}` | Per-call, corpus-backed | `Get-Process \| Where-Object {$_.CPU -gt 100}` |

Persona templates (`{{PERSONA_*}}`) return consistent identity attributes across all events within a single simulation cycle. Use these for scenarios where user identity correlation is important (e.g., the same user who received a phishing email later authenticates from an attacker IP). Random generators (`{{RANDOM_*}}`) produce a new value per template call.

### Corpus-Backed Realism & Data Sources

`{{RANDOM_UA}}`, `{{RANDOM_URL}}`, `{{RANDOM_COMMANDLINE}}`, `{{RANDOM_FILE_PATH}}`, `{{RANDOM_REGISTRY_VALUE}}`, and `{{RANDOM_SCRIPT_BLOCK}}` preferentially sample from a corpus of field-value distributions mined from real EVTX telemetry, falling back to a small static pool when the corpus has no data for that field (see `kinetix/core/vars.py:CORPUS_FIELD_CANDIDATES`). The mined corpus lives at `kinetix/intelligence/corpus_profiles/*.json` and was produced offline by `scripts/mine_corpus.py` from three public sample corpora:

| Source | License (per GitHub, checked 2026-09-21) |
|--------|---------|
| [sbousseaden/EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) | GPL-3.0 |
| [Yamato-Security/hayabusa-sample-evtx](https://github.com/Yamato-Security/hayabusa-sample-evtx) | None declared — accepted for internal-only use, see below |
| [NextronSystems/evtx-baseline](https://github.com/NextronSystems/evtx-baseline) | Apache-2.0 |

Only aggregated, weighted field-value pools are shipped in `corpus_profiles/*.json` — never raw EVTX records. Fields the miner classifies as identifiers (IPs, `ip:port`, hostnames, usernames, `DOMAIN\user` account strings, emails, GUIDs, SIDs) are reduced to a structural shape token before counting, never stored as real values; `tests/test_kinetix.py::TestCorpusIntegrity` enforces this as a regression guard against any future re-mining run reintroducing a leak.

**hayabusa-sample-evtx licensing — resolved for internal use (2026-09-21).** Its repository carries no LICENSE file or SPDX identifier, so GitHub's default terms apply: viewing/forking is permitted, but no redistribution or derivative-work rights are granted absent an explicit license. `DeviceEvents.json` includes data mined from this source.

GSEC has decided this is acceptable **for internal use only**, on this reasoning:
- `corpus_profiles/*.json` never contains raw EVTX records or literal log text — it holds aggregated, weighted field-value frequency counts, a statistical transformation derived from the source data rather than a reproduction of it.
- The source material itself is machine-generated Windows Event Log output from a sandboxed test VM; the log content carries at most thin copyright protection, and Yamato-Security's own contribution is curating/publishing the sample set, not authoring the log text.
- Nothing derived from this source is distributed, sold, or delivered outside GSEC — it stays inside an internal tool used for GSEC's own SOC training and SIEM validation work.

This determination is a risk-based internal call, not a legal opinion, and it does **not** carry over automatically if the scope changes. Re-open this question (and get qualified legal/licensing sign-off before proceeding) if this tool, its output, or `corpus_profiles/DeviceEvents.json` specifically is ever: shared with or delivered to a client, open-sourced or published externally, or incorporated into a commercial product or paid service.

## Scenario JSON Format

```json
[
  {
    "name": "Stage Name",
    "delay": 1.0,
    "events": [
      {
        "source": "endpoint|auth|firewall|linux|macos|office_activity|mdo_email|cloud_app|...",
        "event_type": "process_creation|authentication|dns_query|email_event|cloud_app|identity_logon|...",
        "multiply": 5,
        "mitre": {
          "tactic": "Execution",
          "technique_id": "T1059.001",
          "technique_name": "Command and Scripting Interpreter: PowerShell"
        },
        "d3fend": {
          "id": "d3f:FileAnalysis",
          "description": "Detect encryption patterns"
        },
        "atlas": {
          "id": "AML.T0051.001",
          "name": "LLM Prompt Injection: Indirect"
        },
        "is_malicious": true,
        "killchain_phase": "execution",
        "data": { ... }
      }
    ]
  }
]
```

All fields directly in the event body are passed to the Pydantic model. A `"data"` key is auto-flattened into top-level fields for flexibility. The `"multiply"` key replicates the event N times with unique template resolution per instance.

## Event Type Reference

| event_type | Source(s) | Sentinel Table | Model |
|------------|-----------|----------------|-------|
| `process_creation` | `endpoint` | DeviceProcessEvents | ProcessEvent |
| `file_system` | `endpoint` | DeviceFileEvents | FileEvent |
| `registry` | `endpoint` | DeviceRegistryEvents | RegistryEvent |
| `network_connection` | `firewall` | CommonSecurityLog | FirewallEvent |
| `dns_query` | `dns` | DnsEvents | DNSEvent |
| `proxy` | `proxy` | W3CIISLog | ProxyEvent |
| `web_request` | `web` | W3CIISLog | webServerEvent |
| `authentication` | `Azure AD`, `signin` | SigninLogs | AuthenticationEvent |
| `vpn` | `vpn`, `Firewall` | CommonSecurityLog | VPNEvent |
| `office_activity` | `office_activity`, `office365` | OfficeActivity | O365ActivityEvent |
| `cloud_activity` | `cloud_activity` | AzureActivity | CloudActivityEvent |
| `db_query` | `db` | AzureDiagnostics | DatabaseEvent |
| `security_alert` | `alert` | SecurityAlert | SecurityAlert |
| `security_incident` | `incident` | SecurityIncident | SecurityIncident |
| `email_event` | `mdo_email`, `email` | EmailEvents | EmailEvent |
| `cloud_app` | `cloud_app` | CloudAppEvents | CloudAppEvent |
| `identity_logon` | `identity` | IdentityLogonEvents | IdentityLogonEvent |
| `non_interactive_signin` | `non_interactive` | AADNonInteractiveUserSignInLogs | AADNonInteractiveSignIn |
| `linux_auth` | `linux` | LinuxAuditLog | LinuxAuthEvent |
| `linux_sudo` | `linux` | LinuxAuditLog | LinuxSudoEvent |
| `linux_audit` | `linux` | LinuxAuditLog | LinuxAuditdEvent |
| `linux_kernel` | `linux` | LinuxAuditLog | LinuxKernelEvent |
| `linux_cron` | `linux` | LinuxAuditLog | LinuxCronEvent |
| `linux_process` | `linux` | LinuxAuditLog | LinuxProcessEvent |
| `macos_log` | `macos` | Syslog | MacOSLogEvent |
| `macos_auth` | `macos` | Syslog | MacOSAuthEvent |
| `macos_exec` | `macos` | Syslog | MacOSAppExecEvent |

When `event_type` is not found in the registry, it falls back to `BaseLogEvent` with the source preserved as `SourceSystem` for SIEM routing.

## Killchain Phases

Each event can carry a `killchain_phase` label for SOC training and detection gap analysis:

- `reconnaissance` — Target identification & profiling
- `initial-access` — Phishing, compromised credentials, supply chain
- `execution` — Malicious code, PowerShell, LOLBins
- `persistence` — Registry run keys, service principals, inbox rules, OAuth app consent
- `defense-evasion` — Log clearing, AMSI bypass, proxy
- `credential-access` — Password guessing, MFA fatigue, token theft, NTDS dump, certificate abuse
- `discovery` — AD enumeration, network scanning, certificate template enumeration
- `collection` — Mailbox search, data aggregation
- `lateral-movement` — Cross-tenant sync, RMM tunneling, PsExec
- `privilege-escalation` — ADCS certificate abuse, cloud role assignment
- `command-and-control` — C2 beaconing, DNS tunneling, RMM proxy
- `exfiltration` — Rclone, OAuth app exfiltration, cloud storage
- `impact` — Encryption, shadow copy deletion, wire fraud

## Project Structure

```
att3ck/
├── main.py                      # CLI entry point (click)
├── setup_env.sh                 # Environment bootstrap
├── pyproject.toml               # Project metadata & dependencies
├── kinetix/
│   ├── core/
│   │   ├── engine.py            # KinetixEngine — worker pool orchestrator
│   │   ├── scenario.py          # AttackChain, Scenario ABC
│   │   ├── worker.py            # LogWorker (consumer thread, Markov branching)
│   │   ├── temporal.py          # TemporalEngine — Markov + Gaussian jitter
│   │   └── vars.py              # VariableManager — {{PLACEHOLDER}} resolution
│   ├── schemas/
│   │   ├── base.py              # BaseLogEvent, MitreMapping, D3fendMapping
│   │   ├── endpoint.py          # ProcessEvent, FileEvent, RegistryEvent
│   │   ├── network.py           # FirewallEvent, DNSEvent, ProxyEvent
│   │   ├── security.py          # SecurityAlert, SecurityIncident
│   │   ├── cloud_auth.py        # AuthenticationEvent, VPNEvent, CloudActivityEvent, O365ActivityEvent
│   │   ├── app.py               # webServerEvent, DatabaseEvent
│   │   ├── email.py             # EmailEvent (EmailEvents table)
│   │   ├── cloud_app.py         # CloudAppEvent (CloudAppEvents table)
│   │   ├── identity.py          # IdentityLogonEvent, AADNonInteractiveSignIn
│   │   ├── linux.py             # LinuxAuthEvent, LinuxSudoEvent, LinuxAuditdEvent, LinuxKernelEvent, LinuxCronEvent, LinuxProcessEvent
│   │   ├── macos.py             # MacOSLogEvent, MacOSAuthEvent, MacOSAppExecEvent
│   │   └── temporal.py          # TimingProfile, MarkovTransition
│   ├── outputs/
│   │   ├── base.py              # OutputProvider ABC
│   │   └── file.py              # FileOutput — JSON + CEF + Syslog + EVT + auditd with 10MB rotation
│   └── intelligence/
│       └── context.py           # ContextGenerator — identity personas and network helpers
├── scenarios/                   # 31 scenario JSON definitions
│   ├── oauth_consent_phishing.json  # (new) OAuth consent grant attack
│   ├── oauth_device_code_phishing.json # (new) Device code flow phishing
│   ├── rmm_tool_abuse_c2.json       # (new) RMM/C2 abuse via ClickFix
│   ├── sso_session_token_theft.json # (new) AiTM session cookie theft
│   ├── adcs_certificate_abuse.json  # (new) ADCS ESC1 exploitation
│   ├── cross_tenant_sync_attack.json # (new) Azure CTS lateral movement
│   ├── ransomware_v1.json       # (traditional)
│   ├── apt_*.json               # (5 APT scenarios)
│   ├── ai_*.json                # (4 AI-powered attack scenarios)
│   ├── linux_*.json             # (3 Linux attack scenarios)
│   ├── macos_threats.json       # (macOS attack scenario)
│   ├── cross_platform_noise.json # (blended Windows/Linux/Mac noise)
│   ├── benign_noise.json        # (6-stage corporate baseline)
│   └── ...
├── tests/
│   └── test_kinetix.py          # 100+ tests across 22 test classes
├── scripts/
│   ├── verify_engine.py         # Integration benchmark
│   └── retest_phase2.py         # Markov/temporal validation
└── tools/
    └── to_dcr.py                # NDJSON → Azure DCR JSON array converter
```

## Output Format

### JSON (Azure Sentinel-ready)

Per-table files like `DeviceProcessEvents.json`, `SigninLogs.json`, `EmailEvents.json`, `CloudAppEvents.json`, and `Kinetix_Unified.json` — all newline-delimited JSON with Sentinel alias field names (`TimeGenerated`, `SourceSystem`, `AccountName`, etc.).

### CEF (Legacy SIEM)

`Kinetix_Unified.log` — Common Event Format with dynamic `csN`/`csNLabel` extension mapping for fields beyond the standard header, including MITRE ATT&CK and D3FEND metadata.

### Windows Event XML (EVT — verified against a live Wazuh engine)

`Kinetix_EVTX.log` — Single-line Windows Event XML per event, matching the standard `Event` schema. Each event carries a Windows Event ID, Provider, Channel, and structured `EventData`. Only genuinely Windows-native event sources are emitted here — event types backed by non-Windows appliances/cloud services (firewalls, DNS servers, proxies, IIS-style web logs, Azure PaaS resources, Cloud App Security) are excluded, since those products never produce real Windows Event Log entries:

| Schema | EventID | Provider | Channel |
|--------|---------|----------|---------|
| ProcessEvent | 4688 | Microsoft-Windows-Security-Auditing | Security |
| FileEvent (create/modify) | 11 | Microsoft-Windows-Sysmon | Microsoft-Windows-Sysmon/Operational |
| FileEvent (delete) | 23 | Microsoft-Windows-Sysmon | Microsoft-Windows-Sysmon/Operational |
| RegistryEvent | 4657 | Microsoft-Windows-Security-Auditing | Security |
| AuthenticationEvent (success) | 4624 | Microsoft-Windows-Security-Auditing | Security |
| AuthenticationEvent (failure) | 4625 | Microsoft-Windows-Security-Auditing | Security |
| SecurityAlert | 9101 | Kinetix-SentinelAlert (synthetic) | Application |
| SecurityIncident | 9102 | Kinetix-SentinelIncident (synthetic) | Application |
| EmailEvent | 1033 | MSExchange Messaging | Application |
| IdentityLogonEvent (success) | 4624 | Microsoft-Windows-Security-Auditing | Security |
| IdentityLogonEvent (failure) | 4625 | Microsoft-Windows-Security-Auditing | Security |
| AADNonInteractiveSignIn | 4624/4625 | Microsoft-Windows-Security-Auditing | Security |

`SecurityAlert`/`SecurityIncident` use a synthetic provider and event ID rather than a real Windows event ID, because Sentinel-native alerts/incidents have no genuine Windows EVTX equivalent to impersonate.

Every event carries `<TimeCreated SystemTime='...'/>` in its `System` block. Wazuh's `decoder/windows-event/0` maps `event.start` from exactly that attribute; an earlier version of `format_evt_xml()` computed the timestamp and never emitted it, so all EVTX documents were stamped with ingest time and `--sim-clock` backdating was silently void for this feed (measured: 0 of 75,434 indexed documents carried `event.start`).

**Why FileEvent is Sysmon-shaped and not 4663.** `decoder/windows-event/0` carries the 5.0 ruleset's only `discard_events()` block, which drops thirteen codes outright, after decoding and before any integration gating: 4656, 4658, 4660, **4663**, 4670, 4690, 4703, 4907, 5145, 5152, **5156**, **5157**, 5447. Ingest-verified 2026-09-22 — four separate 4663 shapes, including one with a complete `System` block and the full twelve-field Microsoft `EventData`, each produced zero indexed documents, while a minimal-shape 4657 control indexed normally. Content is irrelevant; only the code matters. Sysmon's file events are not on the list and decode through `decoder/windows-sysmon/0`, which gates on the provider name. A 2,093-line batch replayed after the change indexed 2,093/2,093, including all 378 Sysmon file events, with `file.path` and `event.start` populated.

Linux, macOS, firewall/VPN, DNS, proxy/web, database (AzureDiagnostics), and Cloud App Security events are excluded from EVT output — they use JSON/CEF/syslog only (`FileOutput._NON_WINDOWS_SOURCES`). `FirewallEvent.to_evt()` exists and now emits Sysmon 3 (NetworkConnect) rather than the discarded 5156/5157 pair, with the allow/block distinction carried in `RuleName`, but that exclusion means it is not reachable from the file output as shipped.

> **Verified against a live Wazuh manager (5.0.0-beta5).** An earlier draft of this README assumed Wazuh's Windows Event ingestion only happens through the agent's live `eventchannel` API subscription, and that raw EVTX text would need custom decoders to be useful. That assumption turned out to be wrong for how Wazuh's engine actually decodes this data — pulling the manager's real decoder asset (`decoder/windows-event/0`, `decoder/windows-security/0`, from `/var/wazuh-manager/data/ruleset/*/decoders/`) shows its `check` condition is literally `starts_with($event.original, '<Event xmlns=') AND contains($event.original, 'http://schemas.microsoft.com/win/2004/08/events/event')` — i.e. it parses the raw XML text directly (via a built-in `parse_xml()` function) regardless of how that text arrived. Feeding a `Kinetix_EVTX.log` line through the engine's real event-tester API (`/_internal/tester/run/post`, the 5.0 successor to `wazuh-logtest`) confirmed full decoding: `event.code`, `process.executable`, `process.command_line`, `process.parent.*`, `user.name`, etc. all populated correctly, with `wazuh.integration.decoders` showing `["decoder/core-wazuh-message/0", "decoder/windows-event/0", "decoder/windows-security/0"]`. **No custom decoder is needed** — point `<log_format>syslog</log_format>` at this file (see the Wazuh integration section below) and it works out of the box.
>
> Getting there also surfaced and fixed real field-naming bugs verified against that same live decoder: `ProcessEvent` now emits `NewProcessId` (hex, the created process) and `ProcessId` (hex, the **parent's** PID — real 4688 semantics, the opposite of what an earlier draft of this code did) plus `ParentProcessName` (not `CreatorProcessName`); `RegistryEvent` emits `NewValue` (not `ObjectValue`); `AuthenticationEvent`/`IdentityLogonEvent` emit `TargetUserName` (not `TargetUser`/`AccountName`). One residual quirk is Wazuh's own, not Kinetix's: a later unconditional block in `decoder/windows-security/0` re-assigns `process.pid` from the native `ProcessId` field for *every* event, which stomps the correct 4688-specific assignment — so `process.pid` in the final decoded output can show the parent's PID instead of the child's, regardless of what any 4688 producer emits. Confirmed via the decoder's own asset trace, not a claim to take on faith.
>
> This does **not** confirm anything about Wazuh 4.x's classic `analysisd`/XML-ruleset architecture, which is a different codebase — the verification above is specific to the 5.0 engine.

### Vendor-native feeds (ingest-verified on a live Wazuh 5.0 engine)

Wazuh 5.0 only indexes what an **enabled integration** claims, and the
Sentinel-shaped JSON is claimed by nothing. Rather than disguise telemetry as
some other product's, Kinetix emits the wire format the real appliance emits
and lets the shipped vendor decoders do the work. Each vendor gets its own
feed file so an agent tails a stream whose every line one decoder claims.

| Feed | Source schema | Integration | Wire format |
|------|---------------|-------------|-------------|
| `Kinetix_Fortinet.log` | `FirewallEvent` (`vendor=fortigate`, default) | `fortinet` | FortiOS 7.x traffic log, RFC 3164 + `key=value` |
| `Kinetix_CiscoASA.log` | `FirewallEvent` (`vendor=asa`) | `cisco-asa` | RFC 3164 with an `asa:` tag, message leading `%ASA-level-id:` |
| `Kinetix_Okta.json` | `AuthenticationEvent` | `okta` | Okta System Log JSON, one record per line |
| `Kinetix_EVTX.log` | `DNSEvent` | `microsoft-dnsserver` | Windows Event XML on the `Microsoft-Windows-DNSServer/Analytical` channel |

DNS needs no feed of its own: `decoder/microsoft-dnsserver-analytical/0`
selects on `event.dataset`, which `decoder/windows-event/0` derives from
`downcase(Channel)`, so the records ride the existing EVTX file.

**Measured 2026-09-22** against Wazuh 5.0.0-beta5, agent reading at `drops=0`:

| Integration | Lines fed | Documents indexed |
|-------------|-----------|-------------------|
| `fortinet` | 100 | **100** |
| `okta` | 100 | **100** |
| `cisco-asa` | 60 | **60** |
| `microsoft-dnsserver` | 50 | **50** |

Decoded fields confirm the decoders do real work: `observer.vendor`/`product`/
`serial_number` and ingress/egress interfaces for FortiGate; `event.code`
`302013`/`106023` plus `source.ip`/`destination.port`/`network.transport` for
ASA; `dns.question.name` and a `dns.question.type` of `AAAA` resolved from the
numeric QTYPE through Wazuh's own KVDB; `user.name`/`client.ip`/`event.outcome`
and `event.dataset: okta.system` for Okta.

**Two things these formats are strict about**, both found by feeding a live
manager rather than by reading docs:

- **Cisco ASA needs a syslog tag.** The chain is `decoder/syslog/0` →
  `decoder/cisco-asa/0`, and syslog/0 parses the tag as
  `<_TAG/alphanumeric/->:`. `%ASA-4-106023` cannot *be* that tag — the leading
  `%` is not alphanumeric, so the syslog parse fails and cisco-asa/0 never
  receives a `$message`. The line needs a real tag (`asa:`) with the
  `%ASA-level-id` starting the message after it. Untagged lines produced
  **zero** documents while the agent read them at `drops=0`.
- **FortiOS needs its priority prefix.** `decoder/fortinet-start/0` gates on
  the line containing `" type="`, `" time="` and `" subtype="` *and* parses
  `$PRIORITY<_tmp_log>`, so the `<PRI>` prefix is load-bearing.

**Enabling the integrations.** Wazuh 5.0 has no standalone integrations page —
it is **Security analytics → Overview → Integrations** (`/app/sa-integrations`),
where each integration's own page has Actions → Enable. All `network-activity`
integrations ship disabled: this lab went from 19 to 23 enabled. Note the
namespace directory under `data/ruleset/` is renamed on every change
(`cmsync_standard_<hash>`), so a path captured before a change reads stale.
The same page carries space-level **Index discarded events** and **Index
unclassified events** toggles, both off by default.

### Linux auditd wire format (verified end to end on a live Wazuh 5.0 engine)

`Kinetix_Auditd.log` — one real auditd record per line:
`type=<RECORD> msg=audit(<epoch>.<ms>:<serial>): <fields>`. Only Linux event
sources emit here; every other schema returns no auditd representation and is
skipped entirely (`BaseLogEvent.to_auditd()` returns an empty list by default,
so the feed is self-gating — there is no source allow-list to keep in sync).

| Kinetix Linux event | auditd record(s) | Notes |
|---------------------|------------------|-------|
| `LinuxAuthEvent` (success) | `USER_LOGIN` | `res=success`, `terminal=ssh` |
| `LinuxAuthEvent` (failure) | `USER_AUTH` | `res=failed`; failure inferred from the message text |
| `LinuxSudoEvent` | `USER_CMD` | `cmd=` is hex-encoded, as real auditd does for commands containing whitespace |
| `LinuxAuditdEvent` | its own `audit_type` (default `SYSCALL`) | Passes the scenario's `audit_msg` through with `pid`/`auid`/`ses` appended |
| `LinuxCronEvent` | `CRED_ACQ` | `op=PAM:setcred`, `terminal=cron` |
| `LinuxProcessEvent` | `SYSCALL` **+** `EXECVE` | Two lines sharing one serial — that shared serial is how auditd groups a single execve; `EXECVE` splits the command line into `argc`/`a0`/`a1`/… via `shlex` |
| `LinuxKernelEvent` | *(none)* | Kernel ring-buffer messages have no auditd equivalent |

Serials come from a process-wide monotonic counter (`itertools.count`, whose
`next()` is atomic in CPython — this matters because LogWorkers emit
concurrently). Timestamps come from the event, not wall clock, so `--sim-clock`
backdating carries through into the feed.

> **Verified end to end against a live Wazuh 5.0.0-beta5 deployment (2026-09-22),
> not just through the decoder tester.** 5,207 generated lines were tailed by a
> `wazuh-agent` and **5,207 documents were indexed** with
> `wazuh.integration.name: auditd` and decoder chain
> `["decoder/core-wazuh-message/0", "decoder/auditd/0"]` — zero drops at the
> agent, zero loss at the engine. Record-type counts in the indexer matched the
> generated file exactly (`USER_AUTH` 2400, `SYSCALL` 975, `EXECVE` 895,
> `USER_LOGIN` 461, `CRED_ACQ` 246, `USER_CMD` 230). Decoded ECS fields include
> `event.code`, `event.sequence` (the auditd serial), `event.category`
> (`authentication` / `process`), `event.start`, `process.executable`,
> `process.pid`, `user.id` and `host.name`. `event.start` preserved the
> simulated clock (records landed on the backdated days, not the run date).

### Syslog (RFC 3164)

`Kinetix_Syslog.log` — RFC 3164 format: `<PRI>timestamp hostname proc[pid]: msg`. Verified against Wazuh's actual shipped ruleset (`wazuh/wazuh-ruleset`, decoders directory):

| Process tag | Wazuh decoder support | Notes |
|-------------|------------------------|-------|
| `sshd` | Real built-in decoder, confirmed field match | `Failed/Accepted password for X from IP port N ssh2` matches Wazuh's `0310-ssh_decoders.xml` regex exactly |
| `sudo` | Real built-in decoder, confirmed field match | `user : TTY=... ; PWD=... ; USER=... ; COMMAND=...` matches `0320-sudo_decoders.xml` exactly |
| `kernel` (auditd messages) | Real built-in decoder, partial extraction | Base `auditd`/`kernel` decoders classify the event, but the field-extracting child decoders require the full real `auditd` SYSCALL record shape (`arch=... syscall=... exit=... comm="..." exe="..."`, in that order) — most scenario `audit_msg` values won't populate every field, so rich extraction is inconsistent |

`CRON`, `authd`, `opendirectoryd`, `installer`, `syspolicyd`, `tccd` (macOS), `msexchange`, `CAS`, `MicrosoftGraph` (Email/CloudApp/Identity events), `AzureADAudit` (`AuditLogEvent`), `SentinelAudit` (`WorkspaceAuditEvent`) are **not** Wazuh built-in decoder names — there is no such decoder in Wazuh's default ruleset (verified against the full `decoders/` file listing in `wazuh/wazuh-ruleset`). Those events still reach Wazuh (the generic syslog collector ingests any line) but arrive as unparsed `full_log` text with no extracted fields until you write custom decoders for them (see the Wazuh section below). `GenericSyslogEvent` (`Syslog` table, scenario-authored `system_event` entries) uses whatever process tag the scenario supplies — treat it the same way unless that tag happens to match a real decoder.


## SIEM Ingestion Guides

Kinetix generates up to five output formats simultaneously (JSON, CEF, Syslog, EVT XML, auditd), all rotated at 10MB. Each SIEM has a preferred ingestion path:

| Output Format | File(s) | Best For |
|---------------|---------|----------|
| **JSON** (NDJSON per table) | `DeviceProcessEvents.json`, `SigninLogs.json`, `EmailEvents.json`, `CloudAppEvents.json`, etc. | Splunk, Elastic, Sentinel, Chronicle |
| **CEF** (unified stream) | `Kinetix_Unified.log` | Splunk, QRadar, ArcSight, Sentinel |
| **Syslog** (RFC 3164) | `Kinetix_Syslog.log` | Wazuh (sshd/sudo/auditd/kernel out of the box), QRadar, ArcSight, Chronicle |
| **EVT XML** (Windows Event XML) | `Kinetix_EVTX.log` | Splunk (Windows TA); Wazuh (verified against a live 5.0 engine — no custom decoder needed, see caveat above) |
| **auditd** (Linux audit wire format) | `Kinetix_Auditd.log` | Wazuh 5.0 (verified end to end — 5,207/5,207 indexed via the `auditd` integration); any auditd/`audispd` consumer |

---

### Splunk

#### Option A: CEF via TCP input (recommended — richest field extraction)

Splunk's Splunk TA for CEF automatically parses CEF headers and extensions:

```bash
# Tail the CEF file into Splunk's TCP input port
tail -f logs/Kinetix_Unified.log | nc <splunk-indexer> 1514
```

1. Install **Splunk Add-on for Common Event Format** on your indexers or heavy forwarder
2. Create a TCP input on port 1514 (Settings → Data inputs → TCP)
3. Set source type to `cef` or let auto-detection handle it
4. Fields like `src`, `dhost`, `duser`, `csN`/`csNLabel` pairs (MITRE tactic, technique ID, killchain phase) will auto-extract

#### Option B: JSON via HTTP Event Collector (HEC)

```bash
# Stream JSON logs to Splunk HEC
tail -f logs/Kinetix_Unified.json | while read line; do
  curl -k -X POST "https://<splunk-hec>:8088/services/collector" \
    -H "Authorization: Splunk <HEC_TOKEN>" \
    -d "$line"
done
```

1. Enable HEC in Splunk (Settings → Data inputs → HTTP Event Collector)
2. Create a new token, set source type to `_json`
3. Use the script above to stream per-table JSON files
4. Indexed fields map directly to Splunk field search (e.g., `AccountName="jsmith"`)

#### Option C: EVT XML via Splunk Universal Forwarder (Windows TA)

Place the EVT XML file in a directory monitored by Splunk UF with the Windows TA:

```xml
<!-- inputs.conf on forwarder -->
[monitor:///path/to/att3ck/logs/Kinetix_EVTX.log]
sourcetype = XmlWinEventLog
index = winevent
```

The Windows TA parses EventID, Provider, Channel, and EventData into native Windows event fields.

#### Option D: Monitor files directly

```xml
<!-- inputs.conf -->
[monitor:///path/to/att3ck/logs/*.json]
sourcetype = _json
index = kinetix

[monitor:///path/to/att3ck/logs/Kinetix_Unified.log]
sourcetype = cef
index = kinetix
```

---

### Wazuh

Two different verification methods were used here, and they matter for reading the table below correctly:

- **Live-verified**: confirmed by feeding real Kinetix output through a live Wazuh manager's actual event-decoding API (`wazuh-manager` 5.0.0-beta5, via its engine's internal tester endpoint, `/_internal/tester/run/post` — the 5.0 successor to `wazuh-logtest`) and inspecting the real decoded output.
- **Static-verified (4.x ruleset)**: checked against the classic `wazuh/wazuh-ruleset` GitHub repo (the 4.x-era decoder/rule XML files), *not* run against a live manager. **Wazuh 5.0's decoder/rule content turned out to be organized completely differently** — no `sshd`/`sudo`/`CRON`-named decoders exist in the 5.0 ruleset at all (confirmed by listing `/var/wazuh-manager/data/ruleset/*/decoders/` on the live box) — so treat any claim marked static-verified as informative for 4.x specifically, not assumed to carry over to 5.0.
- **Ingest-verified (end to end)**: the strongest tier — lines were written to a file a real `wazuh-agent` was tailing, and the resulting documents were then counted in the indexer. Only two Kinetix feeds currently reach this tier: `Kinetix_EVTX.log` and `Kinetix_Auditd.log`.

> **Wazuh 5.0 gates ingestion on enabled integrations — decoding alone is not enough.** The 5.0 engine only emits an event that an **enabled integration** claims; anything else is discarded silently, with no error anywhere. There is no 4.x-style archive-everything path. On the reference lab manager only **19 of 126** integrations were enabled, nearly all `mode: protected` internals; the enabled user-managed ones were `apache-http`, `cloud-detection` and `auditd`, alongside `windows` and `linux`. The practical consequence: a feed can decode perfectly in the engine's tester API and still produce **zero indexed documents**, because the tester bypasses the gate. Every live-verified claim below was made with the tester and confirms decoding only — treat the ingest-verified feeds as the ones proven to actually land.
>
> **Corollary for verification: never judge Kinetix ingest by raw document counts.** Aggregate on `wazuh.integration.name`, or query a distinctive field value. `wazuh-rootcheck` alone produced ~39k documents in a single afternoon on an idle lab box and will happily mask a total Kinetix ingest failure:
>
> ```bash
> # on the manager (indexer port 9200 is loopback-only by default)
> curl -sk --cert admin.pem --key admin-key.pem \
>   -H 'Content-Type: application/json' \
>   'https://localhost:9200/wazuh-events-v5-*/_search?ignore_unavailable=true' -d '{
>     "size": 0,
>     "aggs": {"integ": {"terms": {"field": "wazuh.integration.name", "size": 30}}}
>   }'
> ```
>
> Also worth knowing: `msg_sent` in `wazuh-agentd.state` reads `0` even for healthy traffic on this beta — it is vestigial, not a signal. Use `wazuh-logcollector.state` (`events`/`bytes`/`drops` per file) for the agent side and the aggregation above for the engine side.

#### Option: live network syslog (no file tailing needed)

Kinetix can stream every event's RFC 3164 representation directly to a Wazuh manager over UDP/TCP as it's generated, using `--syslog-host`/`--syslog-port`/`--syslog-proto` (`kinetix/outputs/syslog.py`). This runs *alongside* the JSON/CEF/EVT file outputs (it does not replace them) and sends **every** event type, not just the Linux ones — non-Linux schemas fall back to `BaseLogEvent.to_syslog()`, which Wazuh's generic syslog collector still accepts as unparsed `full_log` text if no decoder recognizes the tag:

```bash
./venv/bin/python main.py \
  --scenario scenarios/linux_ssh_bruteforce.json \
  --syslog-host <wazuh-manager-ip> \
  --syslog-port 514 \
  --syslog-proto udp
```

On the Wazuh manager side, enable a `<remote>` syslog collector in `/var/ossec/etc/ossec.conf` (this is a manager-wide listener, separate from the agent-based `<localfile>` config below):

```xml
<remote>
  <connection>syslog</connection>
  <port>514</port>
  <protocol>udp</protocol>
  <allowed-ips>0.0.0.0/0</allowed-ips>  <!-- restrict to the Kinetix host's IP in practice -->
</remote>
```

Restart the manager (`systemctl restart wazuh-manager`) after editing. This path was not run against a live manager this session — the RFC 3164 framing and content are the same as the file-based `Kinetix_Syslog.log` output (verified below), but the `<remote>` listener itself wasn't exercised. Delivery to a local test listener (loopback, both UDP and TCP) was confirmed: all events arrived intact, correctly framed, matching the expected RFC 3164 format.

**Agent-based file ingestion vs. this network path — which to use:** Prefer the agent-based `<localfile>` approach (JSON and/or syslog file tailing, below) as the default. It's what the live-verification against Wazuh 5.0 in this section is actually based on, and it mirrors how real production endpoints report to Wazuh — the agent handles TLS, compression, and local queuing if the manager is briefly unreachable. `--syslog-host` has none of that: `SyslogOutput` sends plaintext UDP/TCP with no encryption or authentication, and drops a message on delivery failure rather than queuing it (best-effort single reconnect on TCP only, see `kinetix/outputs/syslog.py`). Reach for `--syslog-host` for a quick smoke test without installing an agent, or when simulating a source that's naturally network-delivered in real deployments (firewalls, network appliances) — not as a stand-in for how endpoint/identity/cloud telemetry actually reaches Wazuh in production, and not across an untrusted network segment.

#### Syslog events (Linux) — live-verified on Wazuh 5.0

```xml
<!-- /var/ossec/etc/ossec.conf -->
<localfile>
  <log_format>syslog</log_format>
  <location>/path/to/att3ck/logs/Kinetix_Syslog.log</location>
</localfile>
```

| Message type | Result on live Wazuh 5.0 engine | Notes |
|---------------|------|-------|
| `sshd` failed/accepted password | Decodes fully | Chain is `decoder/syslog/0` → `decoder/system-auth/0` (not a decoder literally named `sshd` — that name doesn't exist in 5.0). Extracts `event.action: authentication-failure`, `source.ip`, `user.name`, `process.name` correctly |
| `sudo` command execution | Decodes fully | Same `syslog`→`system-auth` chain. Extracts `user.name`, `user.effective.name`, `process.command_line`, `process.working_directory` correctly |
| `CRON` job execution | Decodes fully | Same chain. Extracts `process.name: CRON`, `message` correctly |
| `auditd` (`kernel` process tag) | Decoder asset exists (`decoder_auditd_0.json`) — not deeply tested | Present in the live ruleset; field extraction depth wasn't verified this session |

**Not decoded specially on the live 5.0 box** — `authd`, `opendirectoryd`, `installer`, `syspolicyd`, `tccd` (macOS), `msexchange`, `CAS`, `MicrosoftGraph` (Email/CloudApp/Identity). No decoder asset for these process tags was found in `/var/wazuh-manager/data/ruleset/*/decoders/`. These events still arrive via the generic syslog collector, but as unparsed `full_log` text — write custom decoders (see `documentation.wazuh.com/current/user-manual/ruleset/decoders/custom.html`) keyed on the process tag if you need structured fields from them.

#### Linux auditd events — ingest-verified end to end on Wazuh 5.0 (recommended for Linux)

```xml
<!-- /var/ossec/etc/ossec.conf -->
<localfile>
  <log_format>syslog</log_format>
  <location>/path/to/att3ck/logs/Kinetix_Auditd.log</location>
  <label key="source">kinetix-auditd</label>
</localfile>
```

`log_format` is `syslog`, not `audit`: `syslog` passes the line through verbatim
as `$event.original`, which is exactly what `decoder/auditd/0` inspects. Its
`check` expression gates on the line starting with `type=` or `node=` — every
line Kinetix writes to this feed leads with `type=`, and
`tests/test_kinetix.py::TestAuditdOutput::test_every_auditd_line_satisfies_wazuh_decoder_gate`
enforces that as a regression guard.

This is the **preferred path for Linux telemetry on Wazuh 5.0**, because the
`auditd` integration is enabled by default and the syslog feed's Linux content
is not claimed by any enabled integration (see the gating note above). Measured
on 2026-09-22: 5,207 lines fed at ~400 lines/sec → 5,207 indexed documents,
`drops=0`, record-type counts matching the source file exactly. See the Output
Format section above for the full record mapping and decoded field list.

Feed rate matters. `--sim-clock` writes roughly 6,400 lines/sec, which wedges
the agent's HTTPS accumulator (`Agent buffer is full` warnings, then loss).
Stage the run with `--output-dir` and replay into the tailed path at ~400
lines/sec:

```bash
python3 main.py --sim-clock --sim-days 1 --baseline-ratio 0.8 --output-dir /tmp/staging \
  --scenario scenarios/linux_ssh_bruteforce.json \
  --scenario scenarios/linux_privilege_escalation.json \
  --scenario scenarios/linux_malware.json

# then replay at a pace the agent can absorb
awk '{print; system("")}' /tmp/staging/Kinetix_Auditd.log \
  | while IFS= read -r l; do printf '%s\n' "$l" >> logs/Kinetix_Auditd.log; sleep 0.0025; done
```

#### JSON events (Windows endpoint, cloud, identity) — works on 4.x; yields nothing on 5.0

> **This path produces zero indexed documents on Wazuh 5.0.** `log_format json` parses the NDJSON correctly — the problem is downstream: the field names are Sentinel-shaped, no enabled 5.0 integration claims them, and the engine therefore discards every event (see the gating note above). Measured on the reference lab: 65,354 lines read by logcollector with `drops=0`, **0 documents indexed**. The guidance below remains valid for Wazuh 4.x, whose `analysisd` will surface the fields for `<field name="...">` rules. On 5.0, use `Kinetix_EVTX.log` for Windows telemetry and `Kinetix_Auditd.log` for Linux; cloud/identity tables have no enabled-integration path and need a custom integration authored on the manager.

Rather than fighting the syslog/EVTX limitations below, point Wazuh's JSON collector at the per-table files or the unified feed:

```xml
<localfile>
  <log_format>json</log_format>
  <location>/path/to/att3ck/logs/Kinetix_Unified.json</location>
</localfile>
```

Wazuh's JSON decoder exposes every top-level key (`ProcessCommandLine`, `AccountName`, `AppDisplayName`, etc.) as a queryable field, which rules can match with `<field name="...">`. This is the most reliable path for `DeviceProcessEvents`, `SigninLogs`, `EmailEvents`, `CloudAppEvents`, `DeviceEvents`, `AuditLogs`, `EmailAttachmentInfo`, and similar tables — it doesn't depend on any decoder recognizing a fabricated syslog process tag.

#### Windows Security events — ingest-verified end to end, no custom decoder needed

```xml
<localfile>
  <log_format>syslog</log_format>
  <location>/path/to/att3ck/logs/Kinetix_EVTX.log</location>
</localfile>
```

Point this straight at `Kinetix_EVTX.log` — no custom decoder required. The `windows` integration is enabled by default, so this feed clears the 5.0 gating rule described above: measured on 2026-09-21, 300 lines fed to a tailing agent produced 288 indexed documents with `wazuh.integration.name: windows`, `event.code` values of 4688/4624/4657/9101 and `host.name` carrying the synthetic Windows hostnames. Note that nothing in `decoder/windows-event/0` depends on the agent's operating system — a Linux agent tailing the file reaches the same decoder a Windows agent does. The decoding itself was also confirmed on the live Wazuh 5.0.0-beta5 engine: its `decoder/windows-event/0` and `decoder/windows-security/0` assets parse the raw `<Event xmlns=...>` XML directly (via a built-in `parse_xml()` function keyed on `event.original`), so the manager doesn't need the data pre-shaped by a live agent's `eventchannel` collection — the raw XML text is exactly what it expects. Feeding real `Kinetix_EVTX.log` lines through the engine's tester API confirmed correct decoding of `ProcessEvent` (4688), `RegistryEvent` (4657), and `AuthenticationEvent`/`IdentityLogonEvent` (4624/4625) — `event.code`, `process.executable`, `process.command_line`, `process.parent.*`, `user.name`, `registry.value`, `registry.data.strings`, etc. all populated correctly. See the Output Format section above for the specific field-naming fixes this testing surfaced (`NewProcessId`/`ParentProcessName`/`NewValue`/`TargetUserName`) and the one residual quirk that's on Wazuh's side, not Kinetix's (a later unconditional block in `decoder/windows-security/0` can overwrite `process.pid` with the parent's PID for 4688 events).

This was verified specifically against the 5.0 engine — Wazuh 4.x's classic `analysisd` is a different codebase and wasn't tested this session.

#### Custom rules for Kinetix scenarios

Add to `/var/ossec/etc/rules/local_rules.xml`. Verified against Wazuh's real rule IDs — the SSH rule below chains off `if_sid 5716` (`^Failed|^error: PAM: Authentication` — Wazuh's actual "sshd: authentication failed" rule; `5710` is a different rule scoped to nonexistent-username attempts, not password failures). The other four rules key off JSON-decoded fields rather than an `if_sid` chain, since there's no real syslog decoder for the process-creation/consent content they're matching:

```xml
<group name="kinetix">
  <!-- SSH brute force simulation (via Kinetix_Syslog.log) -->
  <rule id="100001" level="12">
    <if_sid>5716</if_sid>
    <match>Failed password for root</match>
    <description>Kinetix: SSH brute force targeting root</description>
  </rule>

  <!-- RMM tool deployment (T1219) — via JSON-ingested DeviceProcessEvents -->
  <rule id="100002" level="14">
    <field name="ProcessCommandLine">BeyondTrust|ScreenConnect|AnyDesk</field>
    <description>Kinetix: RMM tool abuse — suspicious remote management install</description>
  </rule>

  <!-- ADCS certificate request (T1649) -->
  <rule id="100003" level="14">
    <field name="ProcessCommandLine">Certipy|Certify</field>
    <description>Kinetix: ADCS certificate abuse — unauthorized certificate request</description>
  </rule>

  <!-- OAuth app consent (T1525) — via JSON-ingested CloudAppEvents -->
  <rule id="100004" level="13">
    <field name="ActionType">Consent to application</field>
    <description>Kinetix: OAuth consent grant — suspicious application authorized</description>
  </rule>

  <!-- Shadow copy deletion -->
  <rule id="100005" level="14">
    <field name="ProcessCommandLine">vssadmin.*delete shadows</field>
    <description>Kinetix: Shadow copy deletion — ransomware precursor</description>
  </rule>
</group>
```

These four JSON-field rules assume `<log_format>json</log_format>` is pointed at `Kinetix_Unified.json` (or the relevant per-table file) as shown above — they will not fire against the syslog feed.

---

### Azure Sentinel

#### Option A: Azure Monitor Agent (AMA) with Data Collection Rule (recommended)

1. Run Kinetix to generate per-table JSON files in `logs/`:

```bash
./venv/bin/python main.py --scenario scenarios/oauth_consent_phishing.json --duration 60
```

2. Configure Azure Monitor Agent on the log host to tail the JSON files:

   - Install the AMA extension on your VM or Arc-enabled server
   - Create a **Data Collection Rule (DCR)** in Azure portal:
     - **Data source**: Custom JSON logs
     - **File pattern**: `/path/to/att3ck/logs/[!Kinetix]*.json` (per-table files only — excludes the `Kinetix_Unified.*` feeds, which would double-ingest every event)
     - **Transform**: `source` (passthrough — fields already match Sentinel schema aliases)
     - **Destination**: Select the target table (`DeviceProcessEvents`, `SigninLogs`, `EmailEvents`, etc.)

3. Each JSON field uses Sentinel alias names (`TimeGenerated`, `AccountName`, `SourceSystem`), so no transformation is needed.

#### Option B: Logs Ingestion API via DCR (for non-VM or API-driven environments)

> The legacy HTTP Data Collector API (`ods.opinsights.azure.com`) is deprecated as of 2026. Use the DCR-based Logs Ingestion API instead.

1. Create a custom table in your Log Analytics workspace (or target an existing Sentinel table)
2. Create a Data Collection Rule (DCR) with the table's schema and a KQL transformation (use `source` for passthrough)
3. Collect the DCR's `immutableId` and the `endpoint` URI from the DCE (Data Collection Endpoint)
4. Upload logs via the Ingestion API:

```bash
# Convert NDJSON to DCR-ready JSON arrays
./venv/bin/python tools/to_dcr.py logs/Kinetix_Unified.json > logs/for_sentinel.json

# Upload via Logs Ingestion API (DCR-based)
# (Requires Azure AD app registration with Monitoring Metrics Publisher role)
curl -X POST "https://<dce-endpoint>/dataCollectionRules/<dcr-immutable-id>/streams/Custom-Kinetix_CL?api-version=2023-01-01" \
  -H "Authorization: Bearer <access-token>" \
  -H "Content-Type: application/json" \
  -d @logs/for_sentinel.json
```

For built-in Sentinel tables (DeviceProcessEvents, SigninLogs, etc.), Option A (AMA/DCR) is preferred as it maps fields directly to the native schema.

#### Covered Sentinel Tables

| Table Name | Schema | Source | Maps Via |
|------------|--------|--------|----------|
| DeviceProcessEvents | ProcessEvent | endpoint | `source="endpoint"` |
| DeviceFileEvents | FileEvent | endpoint | `source="endpoint"` |
| DeviceRegistryEvents | RegistryEvent | endpoint | `source="endpoint"` |
| CommonSecurityLog | FirewallEvent, VPNEvent | Firewall | `source="firewall"` |
| DnsEvents | DNSEvent | DNS | `source="dns"` |
| W3CIISLog | ProxyEvent, webServerEvent | Proxy, Web | `source="proxy"`/`"web"` |
| SigninLogs | AuthenticationEvent | Azure AD | `event_type="authentication"` |
| OfficeActivity | O365ActivityEvent | Office 365 | `event_type="office_activity"` |
| AzureActivity | CloudActivityEvent | Azure | `event_type="cloud_activity"` |
| AzureDiagnostics | DatabaseEvent | Azure | `event_type="db_query"` |
| SecurityAlert | SecurityAlert | SecurityInsights | `event_type="security_alert"` |
| SecurityIncident | SecurityIncident | SecurityInsights | `event_type="security_incident"` |
| EmailEvents | EmailEvent | Microsoft Defender for Office 365 | `event_type="email_event"` |
| CloudAppEvents | CloudAppEvent | Cloud App Security | `event_type="cloud_app"` |
| IdentityLogonEvents | IdentityLogonEvent | Identity Protection | `event_type="identity_logon"` |
| AADNonInteractiveUserSignInLogs | AADNonInteractiveSignIn | Azure AD | `event_type="non_interactive_signin"` |
| LinuxAuditLog | Linux+ events | linux | `source="linux"` |
| Syslog | macOS events | macos | `source="macos"` |

---

### Elastic Security (ELK Stack)

#### Option A: Filebeat watching JSON files (recommended)

```yaml
# filebeat.yml
filebeat.inputs:
  - type: filestream
    id: kinetix-json
    enabled: true
    paths:
      - /path/to/att3ck/logs/DeviceProcessEvents.json
      - /path/to/att3ck/logs/SigninLogs.json
      - /path/to/att3ck/logs/EmailEvents.json
      - /path/to/att3ck/logs/CloudAppEvents.json
      - /path/to/att3ck/logs/IdentityLogonEvents.json
      # Add other per-table files as needed
    parsers:
      - ndjson:
          target: ""
          overwrite_keys: true
          add_error_key: true
    fields:
      event_module: kinetix
    fields_under_root: true

output.elasticsearch:
  hosts: ["https://<elastic-host>:9200"]
  username: "elastic"
  password: "<password>"
  index: "kinetix-%{+yyyy.MM.dd}"
```

Each JSON field maps to a top-level Elastic field. Use an index template to set `TimeGenerated` as `date` and `EventID` as `long`.

#### Option B: Unified JSON stream via Filebeat

```yaml
filebeat.inputs:
  - type: filestream
    id: kinetix-unified
    paths:
      - /path/to/att3ck/logs/Kinetix_Unified.json
    parsers:
      - ndjson:
          target: ""
          overwrite_keys: true
          add_error_key: true
```

#### Option C: Syslog via Logstash

```bash
# Logstash pipeline (syslog input → elasticsearch output)
input {
  file {
    path => "/path/to/att3ck/logs/Kinetix_Syslog.log"
    type => "syslog"
    start_position => "beginning"
    sincedb_path => "/dev/null"
  }
}

filter {
  if [type] == "syslog" {
    grok {
      match => { "message" => "<%{POSINT:priority}>%{SYSLOGTIMESTAMP:timestamp} %{SYSLOGHOST:hostname} %{DATA:program}(?:\[%{POSINT:pid}\])?: %{GREEDYDATA:message}" }
    }
    syslog_pri { }
    date {
      match => [ "timestamp", "MMM  d HH:mm:ss", "MMM dd HH:mm:ss" ]
    }
  }
}

output {
  elasticsearch {
    hosts => ["https://<elastic-host>:9200"]
    index => "kinetix-syslog-%{+yyyy.MM.dd}"
  }
}
```

---

### QRadar

#### Option A: CEF via syslog (recommended — native CEF parser)

QRadar's DSM for ArcSight Common Event Format (CEF) automatically parses CEF messages:

1. Configure Kinetix to write CEF to a file or pipe to a remote syslog:
   ```bash
   tail -f logs/Kinetix_Unified.log | nc <qradar-console> 514
   ```
2. In QRadar Admin → Log Sources:
   - **Log Source Type**: Universal LEEF or ArcSight CEF
   - **Protocol**: TCP/UDP Syslog
   - **Port**: 514 (or custom)
3. QRadar extracts CEF header fields (`Device Vendor`, `Device Product`, `Device Version`, `Signature ID`, `Name`, `Severity`) and extension key-value pairs into custom properties
4. Create custom QRadar rules using `AQL` queries referencing the extracted CEF properties

> Note: The CEF extension fields include MITRE ATT&CK data (`cs1`=technique_id, `cs2`=tactic, `cs3`=killchain phase) for rule creation.

#### Option B: Syslog via Log Source

```bash
tail -f logs/Kinetix_Syslog.log | nc <qradar-console> 514
```

1. Add a syslog log source in QRadar
2. Use the appropriate DSM (Linux/Unix, Windows, or custom)
3. Apply parsing rules for sshd, sudo, and authentication events

---

### ArcSight ESM

#### Option A: CEF via syslog (ArcSight-native format)

ArcSight was designed for CEF — Kinetix CEF output maps directly:

1. Send the CEF stream to an ArcSight SmartConnector:
   ```bash
   tail -f logs/Kinetix_Unified.log | nc <arcsight-connector> 514
   ```
2. The **ArcSight CEF Syslog Connector** parses all fields automatically:
   - CEF header → `DeviceVendor`, `DeviceProduct`, `DeviceVersion`, `SignatureId`, `Name`, `Severity`
   - CEF extensions → `dhost`, `duser`, `src`, `spt`, `dpt`, `proto`, `csN`/`csNLabel` pairs
3. MITRE ATT&CK mappings in `cs1`/`cs1Label` (technique_id), `cs2`/`cs2Label` (tactic), `cs3`/`cs3Label` (killchain_phase) are available as ArcSight event fields
4. Create ArcSight rules, filters, and dashboards against these fields

#### Option B: Syslog for Linux/Mac events

Use the syslog output for Linux/macOS events with a Syslog SmartConnector. Apply flex connectors or regex mappings for the structured syslog formats.

---

### Google SecOps (Chronicle)

> **Forwarder is End of Life:** The legacy Chronicle Forwarder was deprecated as of 2026 and will stop working in 2027. Google recommends **OpenTelemetry with Bindplane** or the **Ingestion API** instead. See the [Google SecOps ingestion overview](https://docs.cloud.google.com/chronicle/docs/secops/secops-ingestion).

#### Option A: CEF via syslog to Bindplane agent (recommended)

Deploy a Bindplane (OpenTelemetry Collector) agent on the log host and configure it to tail the CEF file and forward to Google SecOps:

```yaml
# bindplane.yaml — Bindplane/OTel agent config
receivers:
  filelog:
    include: [ /path/to/att3ck/logs/Kinetix_Unified.log ]
    start_at: beginning

processors:
  googlesecops:
    log_type: "CEF"

exporters:
  googlecloudlogging:
    project: <gcp-project>

service:
  pipelines:
    logs:
      receivers: [filelog]
      processors: [googlesecops]
      exporters: [googlecloudlogging]
```

Run the Bindplane agent:

```bash
bindplane agent start --config bindplane.yaml
```

Google SecOps auto-parses the CEF fields into UDM:
- `src` → `target.ip`
- `dhost` → `principal.hostname`
- `duser` → `principal.user.userid`
- `cs1` (technique_id) → `metadata.mitre_technique_id`
- `cs2` (tactic) → `metadata.mitre_tactic`

Then create **Detection Rules** (YARA-L) against the MITRE UDM fields:

```yaml
rule kinetix_oauth_consent_phishing {
  meta:
    mitre_technique_id = "T1525"
  events:
    $e.metadata.mitre_technique_id = "T1525"
    $e.metadata.event_type = "USER_LOGIN"
  match:
    $e.principal.hostname over 5m
  outcome:
    $risk_score = 85
  condition:
    $e
}
```

#### Option B: Ingestion API (raw log or UDM)

For scripted or CI/CD-driven ingestion, use the `ImportLogs` endpoint directly:

```bash
# Send raw CEF logs via the Ingestion API
curl -X POST "https://<region>-chronicle.googleapis.com/v2/projects/<project>/locations/<region>/instances/<instance>/logTypes/CEF:inlineSource" \
  -H "Authorization: Bearer <access-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "inlineSource": {
      "logs": [
        {
          "data": "'"$(base64 -w0 logs/Kinetix_Unified.log)"'",
          "logEntryTime": "'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'",
          "collectionTime": "'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'"
        }
      ],
      "sourceFilename": "Kinetix_Unified.log"
    }
  }'
```

For maximum field fidelity, convert events to UDM JSON and use `ImportEvents` instead. The `logType` parameter determines which parser Google SecOps applies. See the [Ingestion methods docs](https://docs.cloud.google.com/chronicle/docs/reference/ingestion-methods) for the full list of supported log types.

#### Option C: Syslog for Linux/Mac events

Send `Kinetix_Syslog.log` via syslog for Chronicle's syslog parser to map to UDM `USER_LOGIN`, `PROCESS_LAUNCH`, `FILE_EVENT` event types.

## Testing

```bash
./venv/bin/python -m pytest tests/ -v
```

Runs 100+ tests covering schema validation, variable resolution (including persona templates), multiply uniqueness, output formats, CEF correctness, scenario loading, Markov transitions, killchain propagation, Linux/macOS schemas, syslog/EVT output, table name mapping, and all registered schema types.

To run a specific test class:
```bash
# New schema tests
./venv/bin/python -m pytest tests/ -v -k "TestEmailEvent or TestCloudAppEvent or TestIdentityLogonEvent or TestAADNonInteractiveSignIn"

# Persona integration tests
./venv/bin/python -m pytest tests/ -v -k "TestPersonaVariables"

# New scenario loading tests
./venv/bin/python -m pytest tests/ -v -k "TestNewScenarioLoading"
```

## Adding New Scenarios

1. Choose a `source` and `event_type` from the Event Type Reference table above
2. Create a JSON file following the Scenario JSON Format
3. Each event can optionally include `mitre`, `d3fend`, `atlas` (MITRE ATLAS — use for AI-native techniques, e.g. LLM prompt injection, that ATT&CK Enterprise has no dedicated technique for; pair with the closest defensible ATT&CK `mitre` tag rather than force-fitting an unrelated one), `is_malicious`, and `killchain_phase`
4. Use template variables (`{{RANDOM_*}}`, `{{PERSONA_*}}`, `{{CNC_IP}}`) for dynamic values
5. Load with `--scenario scenarios/your_scenario.json`

For custom schema types not in the registry, the engine falls back to `BaseLogEvent` with fields stored in `ExtendedProperties`.

## Adding New Schema Models

1. Create a new file in `kinetix/schemas/` (or add to an existing file)
2. Subclass `BaseLogEvent` with a `source` Literal and `event_type` Literal for your Sentinel table
3. Add Pydantic fields with `Field(..., alias="SentinelFieldName")` and `AliasChoices` for flexible input naming
4. Optionally implement `to_syslog()` and `to_evt()` for multi-format output
5. Register in `main.py:_build_event_registry()` and `kinetix/outputs/file.py:_map_to_table_name()`

## Library

MIT
