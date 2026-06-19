# VIGIL // Verified Intelligent Ground-station Infrastructure Liaison

> **Air-Gapped Predictive AI NOC Copilot for Secure MPLS Networks**  
> *Developed for the Bharatiya Antariksh Hackathon 2026 (Challenge 13) — Production Hardened Version*

---

VIGIL is an enterprise-grade, memory-safe network observability and predictive anomaly detection system built specifically for air-gapped critical aerospace ground station infrastructure. Operating entirely offline under a zero-trust architecture, VIGIL monitors telemetry streams, detects anomalous deviations before they cause outages, generates detailed natural language root-cause diagnoses, and presents remediations via a real-time, interactive NOC dashboard.

---

## 🛰️ ISRO Challenge 13: 4 Building Blocks Mapping

VIGIL is built from the ground up to address all 4 core building blocks of **ISRO Challenge 13 (Ground-station Network Resilience)**:

| Building Block | VIGIL Component | Implementation Details |
| :--- | :--- | :--- |
| **1. Telemetry Ingestion & Simulation** | `vigil-synth` & `vigil-ingest` | Simulates 3 distinct ground-station topologies (**Branch (Mumbai)**, **Hub (Bangalore)**, and **Datacenter (Sriharikota)**). Generates high-fidelity time-series telemetry for BGP, LSP tunnels, physical Interfaces, and SNMP traps. Ingests all telemetry over an asynchronous, multithreaded pipeline secured with **HMAC-SHA256 verification**. |
| **2. Anomaly Detection & Forecasting** | `vigil-detect` | Utilizes a hybrid scoring model combining statistical metrics (**Z-Score**, **IQR**, **Rate of Change**) over sliding windows with an embedded **Isolation Forest ML algorithm** (pure-Rust). Features linear regression trend analysis to calculate **Time-to-Impact** forecasting and predict breach metrics. |
| **3. Air-Gapped AI Diagnostics** | `vigil-llm` | Executes local LLM inference (via `llama-cli`/`ollama`) and triggers a rule-based **Expert System fallback** if offline CPU/memory constraints restrict inference. Produces structured output fields (**Predicted Issue**, **Confidence**, **Root Cause**, **Recommended Action**, **Lead Time**) sanitized through a **Zero-Trust Input/Output Sanitizer** to block prompt-injection attacks. |
| **4. NOC Workflow & Playbooks** | `vigil-daemon/web` | Provides a premium NOC-style interactive dashboard with **Alert Prioritization** (sorting/P1-P2-P3 badges), **Incident Summary Cards**, and a custom **Playbook Engine** suggesting copy-pasteable Cisco/Juniper CLI remediation commands based on active event profiles. |

---

## 🏢 Easy Features
- **Zero-Hassle Automated Deployment:** The interactive `install.sh` wizard configures paths, auto-detects running Ollama/llama-cli instances, and performs real-time downloading of pre-optimized GGUF models. It gets you from `git clone` to a running NOC dashboard in under 5 minutes.
- **Dynamic Playbook Engine:** Beyond identifying anomalies, VIGIL produces actionable, copy-pasteable CLI commands (Cisco IOS/Juniper Junos) tailored to the specific failure to reduce Mean Time to Repair (MTTR).
- **Incident Audit Export:** Generate cryptographically signed, timestamped incident summaries in standard text formats, allowing operators to securely export logs for post-mortem reporting.
- **Multi-Site Capability & Presets:** Native tracking of branch (Mumbai), hub (Bangalore), and datacenter (Sriharikota) profiles seamlessly. 
- **Production Systemd Integration:** Included `vigil.service` daemon configuration and secure `/etc/vigil/vigil.toml` bindings ensure the agent can run silently and securely in the background.

---

## 🛡️ xcomrade.tech Security Excellence
As a cybersecurity firm, we engineered VIGIL to be the most resilient NOC tool possible:
- **Maximum Performance:** The hybrid anomaly engine (Z-Score + IQR + RoC + Isolation Forest) runs entirely in circular memory buffers. It detects issues in under 1ms before generating the intelligent LLM report.
- **Strict Cryptographic Ingestion:** Real-time telemetry is validated using HMAC-SHA256 tokens to instantly drop spoofed packets or perimeter breaches.
- **Zero-Trust LLM Sanitizer:** LLM outputs are notoriously unpredictable. VIGIL intercepts all inference output and applies multiple regex constraints to strip shell escapes, script tags, and dangerous binaries (`sudo`, `rm`, `mkfs`) before they reach the operator console.
- **Adversarial Prompt Guard:** Active telemetry is scanned for prompt-injection attacks (e.g., "ignore previous instructions").
- **TPM 2.0 Attestation Stub:** Verifies GGUF model hashes on startup to ensure the inference engine hasn't been backdoored or tampered with.
- **Memory Safety:** The entire codebase is enforced with `#![deny(unsafe_code)]`, protecting the air-gapped system from buffer overflows and use-after-free vulnerabilities.

---

## 🛠️ The Dev's Journey (Why & How I Built This)

Hi, I'm **Vivek**. I'm a 20-year-old B.Tech student, and I also run [xcomrade.tech](https://xcomrade.tech), a cybersecurity startup. Building VIGIL was a wild ride. I've been architecting and coding this core engine for the past few weeks, mostly late at night, trying to balance building my company, prepping for this hackathon, and managing B.Tech exams. I want to give a shoutout to my awesome teammates, **Sanskar Singh** and **Aaryan Sharma**, who helped with testing, QA, and brainstorming while I put this system together.

Why Rust? I originally thought about building this in Go or Python because it's faster to write, but when you're looking at Challenge 13 for ISRO's ground-station networks, memory safety isn't a "nice-to-have" — it's a mission-critical requirement. If a parser crashes because of a null-pointer dereference or an attacker exploits a buffer overflow in an air-gapped NOC, satellite links go down. So, I bit the bullet and decided to use pure Rust with `#![deny(unsafe_code)]` enabled. (Honestly, fighting the borrow checker at 3 AM while drinking black coffee took me back to my first-year coding labs, but it was 100% worth it).

A few realistic notes on the system:
- **No external API calls:** Ground stations are air-gapped. This meant I couldn't just use OpenAI or external cloud APIs. I had to build local inference via `llama-cli`/Ollama and build a deterministic, rule-based expert fallback system so that it still gives accurate playbooks even if the local LLM process gets killed due to OOM or CPU bottlenecks.
- **Embedded Database:** Setting up SQL servers in an air-gapped sandbox is a nightmare. I chose `redb` because it's a pure-Rust embedded key-value DB that compiles right into the binary. It's fast, single-file, and doesn't require setting up any database daemons.
- **Pure CSS/Vanilla JS NOC Dashboard:** I didn't want to deal with React/Tailwind dependency hell, `node_modules` bloated by 400MB, or build-step issues when deploying offline. The dashboard is written in vanilla JS and custom CSS. It's lightweight, extremely fast, and renders low-overhead sparklines directly on an HTML5 canvas.

---

## 🛰️ Architecture & System Design

VIGIL is architected as a Rust-based monorepo containing multiple focused, decoupled crates for maximum maintainability, auditability, and safety:

```
VIGIL (Workspace Root)
├── Cargo.toml                  # Workspace dependencies and hardening build profile
├── flake.nix                   # Reproducible Nix package and dev shell definition
├── deny.toml                   # Supply-chain dependency security policy
├── bin/
│   └── vigil-daemon/           # The central agent coordinating ingestion, analysis, and dashboard server
│       └── web/                # HTML5/CSS3/Vanilla JS assets for the NOC Dashboard
└── crates/
    ├── vigil-core/             # Shared types, error definitions, and HMAC verification
    ├── vigil-synth/            # Telemetry generator simulating real-world and failure scenarios
    ├── vigil-ingest/           # Multithreaded ingestion pipeline with HMAC validation
    ├── vigil-detect/           # Statistical anomaly detection engine (Z-Score, IQR, sliding window)
    ├── vigil-store/            # ACID-compliant persistence layer using redb embedded database
    └── vigil-llm/              # Air-gapped AI Copilot diagnostics and Zero-Trust sanitizer
```

---

## 🛠️ Phase Implementations

### 1. Ingestion Pipeline & Telemetry Types (`vigil-core` & `vigil-ingest`)
- **Strict Parsing**: Ingests JSON telemetry envelopes over an asynchronous pipeline.
- **HMAC Verification**: Enforces zero-trust cryptographic tags (using HMAC-SHA256) for every incoming packet to prevent spoofing inside the ground network.
- **Robust Schema**: Supports `Interface` utilization/speed, `Lsp` latency/reroutes, `Bgp` peer states/prefix counts, `Snmp` traps, and `Ospf` neighbor transitions.

### 2. Multi-Metric Anomaly Detection & Storage (`vigil-detect` & `vigil-store`)
- **Statistical Scoring**: Tracks telemetry streams over sliding windows. Combines **Z-Score** (mean-variance deviation), **IQR** (Interquartile Range for extreme outliers), and **Rate of Change** (abrupt metric jumps).
- **Persistent Storage**: Utilizes `redb` (a pure Rust, ACID-compliant embedded database) to persist telemetry and flagged anomaly reports.

### 3. Air-Gapped AI Diagnostics Copilot (`vigil-llm`)
- **Local LLM Inference**: Invokes local model GGUF files via `llama-cli` or `ollama` CLI subprocesses with optimized ground-station prompts.
- **Rule-Based Expert Fallback**: Executes deterministic routing heuristics if local LLM processes are unavailable.
- **Zero-Trust Sanitizer**: Applies compile-once regular expressions via `OnceLock` combined with an allow-list character filter. Suspicious commands (`sudo`, `rm`, etc.), shell escapes (`>`, `|`, backticks), and HTML script tags are redacted (`[REDACTED]`) before presentation.
- **API integration**: Exposes the standard async diagnostic API: `pub async fn diagnose_anomaly(anomaly: &AnomalyEvent, context: &TelemetryContext) -> Result<DiagnosticReport, VigilError>`.

### 4. Interactive NOC Dashboard (`vigil-daemon/web`)
- **Real-Time Observability**: Displays active anomaly counters, network statistics, and live telemetry log tables.
- **Custom Visuals**: Implements responsive, low-overhead HTML5 Canvas sparklines for real-time bandwidth, latency, BGP prefixes, and errors.
- **Incident Inspector**: Clicking any anomaly immediately queries the backend database and loads the AI Copilot's diagnostic report.

### 5. Production Hardening (`Cargo.toml` & `flake.nix`)
- **Safety**: Rejects all `unsafe` code at compilation level (`#![deny(unsafe_code)]`).
- **Optimization**: Heavy release optimizations (LTO, minimized codegen units, panic abort) and runtime overflow checks enabled.
- **Reproducibility**: Nix flake pinning for a fully deterministic compiler and runtime environment.

---

## 📂 Project Documentation

For advanced details regarding architecture, security hardening, and submissions, refer to:
- **[THREAT_MODEL.md](THREAT_MODEL.md)**: Security boundaries, STRIDE threat matrices, and mitigation controls.
- **[PROPOSAL.md](PROPOSAL.md)**: Full project proposal and implementation details for the Hackathon.
- **[DEMO_SCRIPT.md](DEMO_SCRIPT.md)**: Step-by-step narration guide for the 3-minute video presentation.

---


## 🚀 Quick Start for New Users (One-Command Setup)

Getting VIGIL up and running on a local machine takes just a few steps:

1. **Clone and Run Setup**:
   **Linux / macOS:**
   ```bash
   git clone <repo-url>
   cd VIGIL
   bash install.sh
   ```
   **Windows (PowerShell):**
   ```powershell
   git clone <repo-url>
   cd VIGIL
   .\install.ps1
   ```
2. **Setup Wizard Options**:
   * **Choose Installation Mode**: Choose **1) Local Developer Mode** (runs completely without root, creating local configuration and model files in the workspace).
   * **Choose LLM Model**: Option **1 (Qwen-2.5-1.5B)** is highly recommended as it is lightweight (~1.1 GB), has no licensing blocks, and downloads directly via `curl`/`wget` with a real-time progress bar.
   * **Alternative (No-Download)**: If you want a quick zero-download setup, select **5 (Mock / Rule-Based Expert System Fallback)**.
3. **Start the Dashboard**:
   Once the compiler finishes building the Rust executable, launch the central daemon in synthetic simulation mode:
   ```bash
   cargo run --bin vigil-daemon -- --mode synthetic --events 150
   ```
4. **Open the Console**:
   Open your browser to `http://localhost:3000` to interact with the NOC dashboard!

---

### Prerequisites (Advanced)
If you prefer deterministic system packages, VIGIL provides a Nix-based flake environment:
```bash
nix develop
```
This supplies Rust `1.85.0`, `mold`, `pkg-config`, `openssl`, and security audit utilities.

To execute the test suite (69 tests):
```bash
cargo test --workspace
```

---

## 💻 Running the NOC Dashboard

Launch the central daemon in synthetic simulation mode to spin up the web dashboard:
```bash
cargo run --bin vigil-daemon -- --mode synthetic --events 100 --log-level info
```

Or run it in production mode with a specific configuration file (VIGIL will automatically look for `vigil.toml` in the current directory or `/etc/vigil/vigil.toml` if not specified):
```bash
cargo run --bin vigil-daemon -- --mode production --config /etc/vigil/vigil.toml
```

The terminal will print the telemetry pipeline state, and launch the web server:
```
🚀 Starting VIGIL NOC Dashboard UI on http://127.0.0.1:3000
```

Open your browser to `http://localhost:3000` to interact with the dashboard.

### CLI Parameters
- `--mode <mode>`: Supports `"synthetic"` (live scenario simulation) and `"production"` (listens for remote telemetry submission).
- `--config <path>`: Optional path to a custom TOML configuration file.
- `--events <count>`: Limit of events to stream per scenario in synthetic mode (default: `100`).
- `--anomaly-rate <0.0-1.0>`: Probability of random anomalies during Normal Ops in synthetic mode.
- `--scenario <scenario-name>`: Pre-load a scenario on start in synthetic mode (`normal`, `fiber-cut`, `route-leak`, `degraded-optics`, `security-incident`).
- `--bind-address <ip:port>`: Address for the HTTP dashboard server (default: `127.0.0.1:3000`).

---

## 🎛️ Simulation Scenarios

VIGIL can inject specific, complex network faults dynamically from the dashboard interface or at startup:

1. **Normal Operations**: Clean telemetry baseline with rare random anomalies.
2. **Fiber Cut**: Simulates physical fiber severance. Triggers massive interface utilization drops, packet loss spikes on LSPs, and rapid path rerouting.
3. **BGP Route Leak**: Simulates a prefix leak/flood. Triggers massive increases in advertised prefixes, local preference alterations, and session degradation.
4. **Degraded Optics**: Simulates physical transceiver degradation. Triggers a slow rise in interface CRC alignment errors and interface state changes.
5. **Security Incident**: Simulates rogue network operations. Flags unauthorized BGP state changes, unrecognized SNMP traps, or suspicious routing modifications.

---

## 📡 REST API Reference

The embedded Axum server hosts a light, high-performance REST API:

- `GET /`: Serves the static NOC dashboard page.
- `GET /api/status`: Returns current status, total events ingested, and active anomalies.
- `GET /api/telemetry`: Retrieves the last 50 historical telemetry events.
- `GET /api/anomalies`: Retrieves the last 30 flagged anomaly events.
- `GET /api/anomalies/{id}`: Loads detailed metadata and on-demand LLM diagnostics for a specific anomaly ID.
- `POST /api/simulate`: Accepts `{"scenario": "scenario-name"}` to dynamically switch the active telemetry generator.

---

## 🔒 Hardening & Security Profile

VIGIL is built for high-security, air-gapped zones:

- **Cryptographic Trust**: Ingestion rejects any packet failing the HMAC signature match (when HMAC enforcement is active).
- **Zero-Trust AI Output**: LLM outputs are treated as untrusted text. The sanitization regex strips dangerous command patterns before they render on NOC screens, neutralizing prompt-injection style attacks.
- **No Unsafe Code**: The workspace denies `unsafe` compiler blocks, ensuring no raw memory corruption vulnerabilities exist.
- **Deterministic Deployment**: Config file parameters are immutable during runtime. Dynamic changes require a process restart, maintaining auditability logs.

---

## 🚀 Production Deployment Guide

VIGIL is fully plug-and-play and packaged for secure enterprise/ISRO deployments.

### 1. Automated System Installer (`install.sh`)
For standard Debian/RedHat Linux platforms, run the production installer:
```bash
sudo ./install.sh
```
This script automates:
* Creation of the system-isolated `vigil-daemon` user and group.
* Provisioning of file paths: `/etc/vigil`, `/var/lib/vigil`, and `/var/log/vigil`.
* Setup of strict POSIX file-permissions (`chmod 770` for data folders; `chmod 600` for configs).
* Copying and hardening of systemd services.

### 2. systemd Service Configuration (`vigil.service`)
The daemon runs as a hardened systemd service under strict constraints:
```ini
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
NoNewPrivileges=yes
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
```
To control the daemon:
```bash
sudo systemctl start vigil
sudo systemctl enable vigil
sudo systemctl status vigil
```

### 3. Interactive Configuration Wizard
Generate custom TOML configurations with secure, randomly generated HMAC keys using the CLI wizard:
```bash
cargo run --bin vigil-daemon -- --wizard
# or in production:
vigil-daemon --wizard
```

### 4. NixOS Flake Module Deployment
If deploying in NixOS environments, VIGIL exports a structured NixOS module in `flake.nix`. Import the flake and enable it:
```nix
services.vigil = {
  enable = true;
  bindAddress = "127.0.0.1:3000";
  configPath = "/etc/vigil/vigil.toml";
};
```

---

## 🔒 Advanced Security Features

### 🛡️ TPM 2.0 Model Attestation Stub (`crates/vigil-core/src/tpm.rs`)
Ensures local GGUF models running in air-gapped environments have not been swapped or tampered with. It hashes the model binary on startup and generates a simulated PCR 12 quote verified against an Attestation Identity Key (AIK).

### 🛡️ LLM Adversarial Input Monitoring (`crates/vigil-llm/src/lib.rs`)
Aggressively monitors incoming telemetry logs for adversarial prompt injections, instructions overrides, or jailbreak attempts (e.g. "ignore previous instructions") prior to LLM compilation, preventing LLM hijacks.

### 🛡️ HMAC-SHA256 Signed Audit Log Export (`crates/vigil-core/src/audit.rs`)
Cryptographically signs JSON exports of telemetry histories utilizing HMAC-SHA256 to ensure data authenticity and detect any off-disk tampering of historical records.

