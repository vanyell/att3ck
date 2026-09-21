# Kinetix — Project State

## Overview
Kinetix is a modular, high-performance synthetic log generator for adversarial simulation, SIEM validation, and SOC analyst training. It bridges the gap between static attack scripts and dynamic, realistic telemetry.

## Current Phase: Phase 4 — Modern Cloud/AD Threats & SOC Training Infrastructure

### Phase 3 Legacy (AI-Enabled Threat Coverage & SOC Readiness)
- **16 Scenarios**: 7 traditional APT, 4 AI-powered attacks, 2 coverage/sentinel, noise, markov test
- **15 Pydantic models**, 22 template variables, Markov temporal engine, dual output (JSON+CEF)
- 47 tests across 10 classes

### Phase 4 Completed

#### 6 New Attack Scenarios (2026 Threat Landscape)

| Scenario | Attack | Key TTPs | Stages | Events |
|----------|--------|----------|--------|--------|
| OAuth Consent Phishing | Malicious OAuth app → Graph API mailbox enumeration → exfiltration | T1525, T1114.002, T1048.002 | 5 | 8 |
| OAuth Device Code Phishing | Device code phishing → token theft → refresh token harvest → service principal persistence | T1566.002, T1525, T1528, T1136.003 | 5 | 108 |
| RMM Tool Abuse / ClickFix | ClickFix → BeyondTrust RMM → LSASS dump → PsExec lateral → ransomware | T1219, T1003.001, T1021.002, T1486, T1490 | 5 | 11 |
| SSO Session Token Theft | AiTM phishing → session cookie replay → Global Admin → SharePoint exfiltration | T1557, T1539, T1098.002, T1567.002 | 5 | 9 |
| ADCS Certificate Abuse | Certify enumeration → Certipy ESC1 SAN request → PKINIT auth → DCSync | T1649, T1520, T1003.006 | 5 | 9 |
| Cross-Tenant Sync Attack | Tenant compromise → sync policy creation → user sync → privilege escalation → exfiltration | T1078.004, T1098.005, T1526 | 5 | 59 |

Total scenarios: 22 (+6), total event templates: 204 across all new scenarios.

#### 4 New Pydantic Schemas (Sentinel Table Parity)

| Schema | File | Sentinel Table | Source |
|--------|------|----------------|--------|
| EmailEvent | `kinetix/schemas/email.py` | EmailEvents | Microsoft Defender for Office 365 |
| CloudAppEvent | `kinetix/schemas/cloud_app.py` | CloudAppEvents | Microsoft Cloud App Security (CASB) |
| IdentityLogonEvent | `kinetix/schemas/identity.py` | IdentityLogonEvents | Azure AD Identity Protection |
| AADNonInteractiveSignIn | `kinetix/schemas/identity.py` | AADNonInteractiveUserSignInLogs | Azure AD |

Total Pydantic models: 19 (+4).

#### SOC Training Engine Features

1. **Identity Persona System** (`kinetix/intelligence/context.py`):
   - ContextGenerator with 10 user personas (CEO, IT Admin, Help Desk, Developer, etc.)
   - Each persona has consistent role, department, host, domain, email, admin/sensitive flags
   - 8 persona template variables: `{{PERSONA_USER}}`, `{{PERSONA_HOST}}`, `{{PERSONA_EMAIL}}`, `{{PERSONA_ROLE}}`, `{{PERSONA_DEPT}}`, `{{PERSONA_DOMAIN}}`, `{{PERSONA_IS_ADMIN}}`, `{{PERSONA_IS_SENSITIVE}}`

2. **Baseline Noise Injection** (`--baseline-ratio` CLI flag):
   - Accepts 0.0–1.0 ratio to interleave benign events with attack events
   - 11 benign event templates: Outlook browse, Teams chat, Chrome browsing, OneDrive sync, etc.
   - Events interleaved in main loop with uniform random distribution

#### Variable Engine Enhancements
- `VariableManager` in `kinetix/core/vars.py` now calls `ContextGenerator._set_persona_vars()` at session start
- Persona templates resolve to role-consistent values across all events in a cycle
- Random generators (`{{RANDOM_*}}`) remain per-call; persona templates are session-stable

#### CLI Options Added
| Flag | Default | Description |
|------|---------|-------------|
| `--baseline-ratio` | `0.0` | Ratio of benign noise to attack events |

#### Test Coverage
- 27 new tests across 6 new test classes:
  - TestEmailEvent (5), TestCloudAppEvent (3), TestIdentityLogonEvent (4), TestAADNonInteractiveSignIn (3)
  - TestPersonaVariables (2), TestNewScenarioLoading (6)
- Full suite: 100+ tests, all Phase 4 additions passing
- 2 pre-existing failures remain (import from `main` in test file, not module-package compat)

### Sentinel Table Coverage
| Category | Tables |
|----------|--------|
| Endpoint | DeviceProcessEvents, DeviceFileEvents, DeviceNetworkEvents, DeviceRegistryEvents, DeviceLogonEvents, DeviceEvents |
| Identity | SigninLogs, AADNonInteractiveUserSignInLogs, IdentityLogonEvents, SecurityEvent |
| Cloud | AzureActivity, CloudAppEvents |
| Office 365 | OfficeActivity |
| Email | EmailEvents **(new)** |
| Security | SecurityAlert, SecurityIncident, SentinelAudit |
| Network | CommonSecurityLog, DnsEvents, W3CIISLog, Syslog |
| App/DB | WebServerEvent, DatabaseEvent + custom fields |

### Architecture
```
main.py → VariableManager (w/ ContextGenerator persona resolution)
         → JSON.load → resolve templates → Pydantic validation
         → AttackChain.run() → engine.emit() → Queue → LogWorker threads
         → Baseline noise interleave (--baseline-ratio)
         → TemporalEngine (delay + Markov branching)
         → FileOutput (JSON + CEF + Syslog + EVT)
```

## Next Steps
1. **Network Output Provider** — Direct TCP/UDP syslog, Splunk HEC, or Elastic Filebeat shipping
2. **Scenario Variator** — Randomize user/host/timing assignments across runs to avoid identical outputs
3. **LLM Integration Hook** — Connect local LLM to dynamically generate command-line and phishing variations
4. **Real-Time SOC Dashboard** — Grafana or Kibana dashboard template pre-configured for ingested Kinetix logs
5. **More AI Scenarios** — Model poisoning supply chain, autonomous agent attacks, AI-AI C2 communication
