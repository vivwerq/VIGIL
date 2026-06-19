# DEMO SCRIPT // VIGIL NOC Copilot Walkthrough

This script provides a step-by-step roadmap for a 3-minute video demonstration of VIGIL's capabilities.

---

## ⏱️ Video Breakdown (180 Seconds Total)

### 🎬 Part 1: Introduction & Architecture (0:00 - 0:30)
- **Visual**: Show the terminal workspace, Cargo.toml, and the crate layout.
- **Narrative**:
  > *"Hi everyone, I'm Vivek, B.Tech student and founder of xcomrade.tech. I built VIGIL: Verified Intelligent Ground-station Infrastructure Liaison, to tackle Challenge 13: Ground-station Network Resilience. I wanted to build something that could run in ISRO's most secure, air-gapped NOCs. So I wrote the entire system in pure Rust with zero unsafe code, utilizing a local, embedded database called redb, and running local model inference entirely offline."*

### 🔨 Part 2: Quick compilation & Test Suite (0:30 - 0:50)
- **Action**: Run `cargo test --workspace` in the terminal to show all tests passing.
- **Visual**: Fast execution, highlighting 69 unit tests green.
- **Narrative**:
  > *"Because we are handling mission-critical ground station telemetry, code correctness is everything. VIGIL has a comprehensive suite of 69 tests that cover cryptographical validations, sliding window statistics, and even our Isolation Forest machine learning engine. Everything compiles and passes in seconds."*

### 🚀 Part 3: Dashboard Launch & Ingestion (0:50 - 1:20)
- **Action**: Start the daemon:
  ```bash
  cargo run --bin vigil-daemon -- --events 100 --scenario normal --log-level info
  ```
- **Visual**: Show the server starting up and binding to `http://127.0.0.1:3000`. Switch to the web browser showing the dark-themed dashboard UI.
- **Narrative**:
  > *"Now we start the VIGIL daemon. If we head over to our NOC dashboard, we can see live telemetry streams flowing in real-time. I built the frontend using vanilla JS and custom CSS to keep it lightweight. The sparklines you see are rendered directly on HTML5 canvases so it won't crash or lag even on low-spec NOC terminals."*

### ⚡ Part 4: Dynamic Scenario Injection (1:20 - 2:00)
- **Action**: Click the "Simulate Fiber Cut" button on the scenario control header.
- **Visual**: Watch the metrics cards show latency spikes, and the "Detected Anomalies" count jump to red.
- **Narrative**:
  > *"Let's simulate a physical fiber-cut scenario. The statistical detectors immediately catch the drop in bandwidth and spike in packet loss. Under the hood, our hybrid engine combines statistical Z-Score and IQR with an unsupervised Isolation Forest ML model to compute an ensemble score, minimizing false positives."*

### 🧠 Part 5: Offline AI Copilot & Sanitization (2:00 - 2:45)
- **Action**: Click on one of the critical anomalies in the left panel to load the diagnostic report.
- **Visual**: The right-hand panel populates with Root Cause Diagnosis, Expert Reasoning, Impact Assessment, and an Action Plan. Highlight the metadata fields at the bottom showing ID, severity, and score.
- **Narrative**:
  > *"When we inspect an anomaly, VIGIL queries the local database and fires up our offline AI Copilot. It runs a local model like Phi-3.5 or Mistral completely locally, extracting root causes and mitigation playbooks. If the model is offline or CPU limits are hit, it gracefully falls back to a deterministic rule-based expert system I coded. And to keep the NOC secure, our zero-trust output sanitizer redacts any dangerous shell injection attempts automatically."*

### 🏁 Part 6: Summary & Impact (2:45 - 3:00)
- **Visual**: Show the full dashboard view with sparklines flowing.
- **Narrative**:
  > *"That is VIGIL. It's a memory-safe, air-gapped predictive NOC copilot designed to keep space communications online. Thanks for watching, and hope you enjoyed the demo!"*
