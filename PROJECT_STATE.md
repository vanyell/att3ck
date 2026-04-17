# Kinetix Log Generator - Project State

## Project Overview
Kinetix is a modular, high-performance log generation engine designed for adversarial simulation and defensive validation. It bridges the gap between static attack scripts and dynamic, realistic telemetry needed for SOC training and SIEM testing.

## Phase Progress

### Key Accomplishments (Phase 2 - Core Implementation)
*   **Temporal Realism Engine**: 
    - Implemented `TemporalEngine` with Gaussian jitter support.
    - Integrated **Time-of-Day Activity Scaling** (automatically slows down during non-working hours).
    - Updated `LogWorker` to apply realistic inter-event spacing.
*   **Markov Foundations**: Schema and engine support for state-aware transitions added.
*   **SOC Table Expansion**: Successfully mapped 18+ critical Sentinel tables (Identity, Endpoint/MDE, Network, Cloud, and MDO/Email).
*   **Log Rotation**: Implemented 10MB rotating logs for all outputs.

### Architecture
- **Performance**: Producer-Consumer pattern with worker threads for modular event processing.
- **Serialization**: `orjson` utilized for high-performance, zero-copy serialization.
- **Randomness**: Context-aware generators for identities (users, hosts) and network context (IPs, subnets).
- **Synthetic IOCs**: Strict avoidance of real-world IOCs; focus on replicating TTP methods.

### Sentinel Integration
- **AMA-Ready Output**: Logs are saved locally for tailing by the Azure Monitor Agent (AMA).
- **1:1 Correspondence**: Events are routed to separate files per Sentinel table to meet DCR requirements.
- **SOC Coverage**: Includes standard tables for:
    - **Incident Management**: `SecurityIncident`, `SecurityAlert`, `SentinelAudit`.
    - **Endpoint (MDE/XDR)**: `DeviceProcessEvents`, `DeviceFileEvents`, `DeviceNetworkEvents`, `DeviceRegistryEvents`, `DeviceLogonEvents`.
    - **Identity**: `SigninLogs`, `SecurityEvent`, `AuditLogs`, `IdentityLogonEvents`.
    - **Cloud/M365**: `OfficeActivity`, `EmailEvents`, `EmailAttachmentInfo`, `AzureActivity`, `CloudAppEvents`.
    - **Network/Infrastructure**: `CommonSecurityLog`, `DnsEvents`, `Syslog`, `W3CIISLog`.

## Next Steps (Phase 2 Continued)
1.  **Markov State Generator**: Use transition probabilities to automatically generate "follow-up" events (e.g., cmd.exe followed by network connection).
2.  **Scenario Variator**: Randomize user/host selection within scenarios to ensure no two runs are identical.
3.  **Intelligence Layer**: Integration points for Local LLMs to generate "stealth" command-line variations.
