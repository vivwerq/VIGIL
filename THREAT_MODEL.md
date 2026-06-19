# VIGIL // Security Architecture & Threat Model

This document outlines the security posture, trust boundaries, threat vectors, and mitigation strategies implemented in VIGIL (Verified Intelligent Ground-station Infrastructure Liaison) for ISRO's secure, air-gapped MPLS networks.

---

## ─── 1. Security Architecture & Trust Boundaries ──────────────────────────

VIGIL operates under a strict **Zero-Trust Inner-Perimeter** model. Even inside an air-gapped ground station network, no source is inherently trusted, and all external entities (telemetry probes, LLM outputs, operator inputs) must be validated.

```
       [ UNTRUSTED NETWORK PERIMETER ]
                     │
                     ▼  (Telemetry Stream)
 ┌─────────────────────────────────────────────────────────┐
 │ Ingestion Pipeline (HMAC-SHA256 Verification Gate)      │  ◄── Boundary 1: Crypto Trust
 └───────────────────┬─────────────────────────────────────┘
                     │ (Verified & Clean Envelopes)
                     ▼
 ┌─────────────────────────────────────────────────────────┐
 │ Anomaly Detection Engine (In-Memory Processing)         │
 └───────────────────┬─────────────────────────────────────┘
                     │
                     ▼ (Persistence Layer)
 ┌─────────────────────────────────────────────────────────┐
 │ redb ACID Storage (Targeted File System Permissions)    │  ◄── Boundary 2: Storage Access
 └───────────────────┬─────────────────────────────────────┘
                     │
                     ▼ (LLM Diagnostic Trigger)
 ┌─────────────────────────────────────────────────────────┐
 │ LLM Copilot (Untrusted Llama-cli/Ollama Subprocess)     │  ◄── Boundary 3: Inference Containment
 └───────────────────┬─────────────────────────────────────┘
                     │ (Raw Response Text)
                     ▼
 ┌─────────────────────────────────────────────────────────┐
 │ Zero-Trust Output Sanitizer (Regex + Allow-List)        │  ◄── Boundary 4: Presentation Safety
 └───────────────────┬─────────────────────────────────────┘
                     │ (Sanitized Markdown)
                     ▼
 ┌─────────────────────────────────────────────────────────┐
 │ Axum NOC Dashboard Dashboard (No Unsafe Script Tags)    │
 └─────────────────────────────────────────────────────────┘
```

---

## ─── 2. Threat Analysis (STRIDE Model) ──────────────────────────────────

### Spooﬁng (Identity Theft)
- **Threat Vector**: A malicious actor or compromised internal node crafts synthetic telemetry packets pretending to be a core MPLS router (e.g., `mcf-core-rtr-01`) to trick the system into false alerts or disguise traffic filtration.
- **VIGIL Mitigation**: Enforces strict cryptographic **HMAC-SHA256 verification** for all ingestion pipeline inputs. Packets missing or possessing incorrect HMAC tags are discarded immediately before parsing.

### Tampering (Data Manipulation)
- **Threat Vector**: Attackers attempt to alter historical telemetry or anomaly reports stored in the database to erase tracks of an intrusion.
- **VIGIL Mitigation**: Persistence uses `redb` (a pure Rust embedded DB) configured with tight file permissions (`0600` - read/write owner only). The daemon runs under a dedicated, unprivileged system user (`vigil-daemon`), denying access to other processes.

### Repudiation (Denying Actions)
- **Threat Vector**: An operator changes the active scenario or changes configurations, causing critical telemetry monitoring to halt, and subsequently denies taking the action.
- **VIGIL Mitigation**: Structured logging records every system configuration validation, database transaction, on-demand diagnostic report call, and simulator scenario injection with exact timestamps and caller metadata.

### Information Disclosure (Data Leakage)
- **Threat Vector**: Secret cryptographic keys or sensitive ground-station IP ranges leak via logs or error messages.
- **VIGIL Mitigation**: Sensitive fields in structures implement custom `Debug` and `Display` formatters that redact key data. The memory-safe compilation prevents buffer overflows from disclosing adjacent stack/heap memory.

### Denial of Service (Outage Invalidation)
- **Threat Vector**: A telemetry probe floods the ingestion pipeline with garbage data, consuming memory and causing a daemon crash.
- **VIGIL Mitigation**: Implemented bounded `tokio::mpsc` channels to enforce structural backpressure. The system uses pre-allocated memory pools where applicable, dropping oversized payloads before they are parsed.

### Elevation of Privilege (Unauthorized Execution)
- **Threat Vector**: A prompt injection attack on the local LLM generates a diagnostic recommendation containing shell scripts or system commands (e.g., `sudo rm -rf /`) that run when presented to the console or browser.
- **VIGIL Mitigation**: The **Zero-Trust Sanitizer** runs regular expressions using `OnceLock` compiled state machines alongside strict character allow-list filters. Suspicious shell syntax, pipeline redirection symbols, and script tags are completely replaced with `[REDACTED]` before UI rendering.

---

## ─── 3. Air-Gapped Specific Vulnerability Matrix ────────────────────────

| Threat Vector | Risk Level | Target Subsystem | Mitigation Controls |
| :--- | :--- | :--- | :--- |
| **Model Hijacking / Poisoning** | Medium | LLM Copilot | Only pre-signed GGUF models stored locally in `/var/lib/vigil/models/` with SHA-256 checks are allowed to load. |
| **Supply Chain Dependency Vulnerability** | High | Cargo Dependencies | Strict `Cargo.lock` pinning + workspace-wide `deny.toml` limits dependencies only to verified, zero-unsafe, open-source packages. |
| **Clock-Skew Replay Attacks** | Low | Ingestion Pipeline | Ingestion checks verify packet timestamps against ground station master NTP clocks, rejecting telemetry older than a configured tolerance. |
| **Memory Exhaustion on Large telemetry** | High | Detection Engine | Sliding windows use fixed-size circular vectors, preventing memory allocation growth during heavy traffic spikes. |
