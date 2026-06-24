# VIGIL: Unified Presentation Master Deck (ISRO Challenge 13)

This artifact consolidates all required slides into a clean, compact, and highly structured format tailored for small-sized presentation slides. 

---

## Slide 1: The Opportunity & Strategic Differentiation

### **Core Content**
*   **Existing Ideas Limitations:** Traditional Network Management Systems (NMS) are reactive (alerting only *after* outages), depend on external cloud connections, and lack cryptographic validation for telemetry.
*   **How VIGIL Solves This:** Implements double exponential smoothing (Holt's Linear Trend) to forecast threshold breaches (e.g., satellite rain fade) ahead of time, allowing preemptive handovers. It runs 100% locally in air-gapped ground stations.
*   **The USP:** 
    > *"A zero-allocation, cryptographically-anchored predictive defense engine that operates entirely within air-gapped ground networks to forecast link failures and automate local playbooks before service degradation occurs."*

### **Operational Shift Comparison**
```mermaid
graph TD
    classDef default fill:#111,stroke:#333,stroke-width:1px,color:#eee;
    classDef red fill:#3b1e1e,stroke:#f44336,stroke-width:2px,color:#fff;
    classDef green fill:#152b1e,stroke:#00c853,stroke-width:2px,color:#fff;

    A["❌ Traditional NMS (Reactive)"]:::red --> B["Alarms trigger AFTER outage"]:::red
    B --> C["Manual diagnostics & downtime"]:::red

    D["🚀 VIGIL Engine (Predictive)"]:::green --> E["Holt Trend forecasts breach window"]:::green
    E --> F["Air-gapped LLM + Auto-playbooks mitigate"]:::green
```

---

## Slide 2: List of Features Offered by the Solution

### **Core Content**
*   **Multi-Horizon Detection Engine:** Integrates fast statistical detectors (Z-Score, IQR, RoC) with double exponential smoothing and Isolation Forest ML.
*   **Predictive Time-to-Impact Analytics:** Calculates estimated lead time ($\Delta t = \text{distance} / \text{slope}$) to link breach, allowing proactive routing and dish control.
*   **Hardware-Anchored Security:** Remote TPM 2.0 attestation verifies platform state; HMAC-SHA256 validates telemetry frames to prevent rogue injection.
*   **Air-Gapped Copilot & Local Playbooks:** Runs local GGUF models on ground servers for offline diagnostic reasoning and automated router configuration.

### **Feature Integration Schema**
```mermaid
graph LR
    classDef box fill:#111,stroke:#00a3ff,stroke-width:1.5px,color:#eee;
    classDef sec fill:#1a237e,stroke:#3f51b5,stroke-width:1.5px,color:#fff;
    
    Raw["📡 Telemetry Ingest"]:::box --> Sec["🛡️ Cryptographic Verification <br> (TPM + HMAC)"]:::sec
    Sec --> Det["🔍 Multi-Horizon Detection <br> (Stat + Holt Trend + ML)"]:::box
    Det --> Anal["⏳ Time-to-Impact <br> (Predictive Lead Time)"]:::box
    Anal --> Mit["🤖 Local Playbook Engine <br> (Offline Diagnostic & Action)"]:::box
```

---

## Slide 3: Process Flow Diagram (Use Case)

### **Core Scenario: Preemptive Rain Fade Mitigation**
1.  **Ingestion & Verification:** Ground station dish telemetry (SNR, Eb/No) is received, signed with HMAC-SHA256, and verified.
2.  **Trend Analysis:** Holt's Linear Trend detects a steady decline in SNR due to approaching rain fade.
3.  **Impact Estimation:** The engine calculates that the SNR will cross the critical threshold ($6.0 \text{ dB}$) in 8 minutes.
4.  **Local Diagnostic:** The Local LLM identifies the root cause as satellite link attenuation and schedules a handover.
5.  **Mitigation Action:** The Playbook Engine automatically reroutes traffic to a neighboring ground station before the active link drops.

### **Telemetry Evaluation Sequence**
```mermaid
sequenceDiagram
    autonumber
    participant Ground Station as Ground Station Telemetry
    participant Ingestion as Cryptographic Ingest
    participant Engine as Detection Engine
    participant LLM as Local LLM Copilot
    participant Playbook as Playbook & Router

    Ground Station->>Ingestion: Send signed telemetry (SNR / EbNo)
    Ingestion->>Ingestion: Verify HMAC & TPM integrity
    Ingestion->>Engine: Process verified telemetry
    Engine->>Engine: Run Holt double smoothing forecast
    Note over Engine: Forecasts breach in 8 mins (Slope > 0)
    Engine->>LLM: Trigger Warning + Telemetry context
    LLM->>LLM: Generate Offline Diagnosis (Rain Attenuation)
    LLM->>Playbook: Match & execute mitigation playbook
    Playbook->>Playbook: Reroute traffic to backup station
```

---

## Slide 4: System Architecture Diagram

### **System Layers**
*   **Data Layer:** Raw telemetry streams (BGP session events, interface stats, SNMP traps, MPLS LSP status) from routers and satellite antennas.
*   **Security Gateway:** Air-gapped boundary performing signature checks and hardware-anchored trust checks.
*   **Detection Layer:** Welford’s algorithm for stats, Holt's linear trend forecast, Isolation Forest ML models, and the Weighted Ensemble Scorer.
*   **Mitigation Layer:** Local SQLite configuration storage, local LLaMA/GGUF runtime, and SSH/NETCONF script dispatch.

```mermaid
graph TD
    %% Styling
    classDef default fill:#111,stroke:#333,stroke-width:1px,color:#eee;
    classDef security fill:#1b1b3a,stroke:#3f51b5,stroke-width:1.5px,color:#fff;
    classDef core fill:#0f3057,stroke:#00a3ff,stroke-width:1.5px,color:#fff;
    classDef mitigation fill:#1b3b22,stroke:#00c853,stroke-width:1.5px,color:#fff;

    subgraph Data Layer
        Router["🌐 Edge & Core Routers"]:::default
        Antenna["📡 Satellite Dishes"]:::default
    end

    subgraph Security Layer ["🛡️ Security Gateway"]
        HMAC["HMAC-SHA256 Ingestion Verification"]:::security
        TPM["TPM 2.0 Remote Attestation"]:::security
    end

    Router & Antenna --> HMAC
    HMAC --> TPM

    subgraph Detection Layer ["🔍 Multi-Horizon Detection Engine"]
        Stat["Statistical Detectors <br> (Z-Score / IQR / RoC)"]:::core
        Holt["Double Smoothing Forecast <br> (Holt's Linear Trend)"]:::core
        ML["Unsupervised ML <br> (Isolation Forest)"]:::core
        Ensemble["Weighted Ensemble Scorer"]:::core
    end

    TPM --> Stat & Holt & ML
    Stat & Holt & ML --> Ensemble

    subgraph Mitigation Layer ["🤖 Local Playbook & Copilot"]
        LLM["Local GGUF LLM Runtime <br> (Offline Diagnoses)"]:::mitigation
        Playbook["Playbook Dispatcher <br> (NETCONF/CLI scripts)"]:::mitigation
    end

    Ensemble --> LLM
    LLM --> Playbook
```

---

## Slide 5: Dashboard Wireframe & Interface Mockup

### **Dashboard Visual Layout Overview**
*   **System Status Header:** Displays uptime, total anomalies, and cryptographic engine health.
*   **Predictive Lead-Time Panel:** Highlights impending link failures, showing the metric, threshold, estimated time-to-impact, and trend confidence.
*   **Real-Time Metrics Grid:** Visualizes current vs. forecasted levels for key telemetry streams.
*   **Active Incidents Console:** Lists current anomalies, model confidence, and the status of automated playbooks.

### **ASCII Wireframe Illustration**
```
+-----------------------------------------------------------------------------+
| VIGIL | GROUND STATION TELEMETRY ENGINE | [SECURE: TPM OK]  [Uptime: 99.98%] |
+-----------------------------------------------------------------------------+
| [⚠️ PREDICTIVE ALERTS]                                                       |
| >> Warning: Rain Fade degradation detected on Antenna-Dish-01               |
|    - Current SNR: 7.2 dB | Threshold Limit: 6.0 dB                         |
|    - Forecasted Breach: In 8 Minutes | Trend Slope: -0.15 dB/min            |
|    - Action Scheduled: Automated link handover to backup site               |
+-----------------------------------------------------------------------------+
| [📈 ACTIVE METRICS MONITOR]                  | [⚙️ ENGINE STATUS]            |
| - latency_us       [ ||||||......... ] 5ms   | - Stats Engine:   RUNNING     |
| - packet_loss_pct  [ ............... ] 0%    | - Holt Smoothing: ACTIVE      |
| - utilization_pct  [ ||||||||||||... ] 72%   | - Isolation Forest: TRAINED   |
+-----------------------------------------------------------------------------+
| [🤖 CO-PILOT DIAGNOSTICS & PLAYBOOKS]                                        |
| Anomaly Event ID: #9822 | Source: Antenna-Dish-01 | Score: 0.72             |
| Diagnosis: "Atmospheric attenuation (rain fade) is degrading signal SNR."   |
| Mitigation Action: Executing Playbook #44 - Switch satellite link to SDSC.  |
| Playbook Status: SUCCESSFUL | Target Link Rerouted                          |
+-----------------------------------------------------------------------------+
```
*(Reference: Visual Mockup saved in workspace as [wireframe_dashboard.md](file:///home/xc0mrade/.gemini/antigravity/brain/c77e5350-4586-43eb-82ef-a92f331cb764/artifacts/wireframe_dashboard.md))*

---

## Slide 6: Technologies to be Used in the Solution

### **Core Stack Components**
*   **Backend & Processing Core (Rust):** Low-overhead, zero-heap allocations. Guarantees memory safety and deterministic CPU usage.
*   **ML Engine (Linfa + Ndarray):** Zero-dependency Rust machine learning framework for Isolation Forest fitting on sliding windows.
*   **Offline LLM Integration (LLaMA.cpp / GGUF):** Quantized open-source models (e.g., Llama-3-8B-Instruct) compiled directly for local CPU execution.
*   **Security Layer (TPM2-TSS):** Platform configuration registers verification combined with ring-buffer cryptographic signatures.
*   **Frontend UI (Vite + React + TypeScript + TailwindCSS):** Modern single-page web app styled with glassmorphic dark-mode dashboards and real-time WebSockets integration.

---

## Slide 7: Estimated Implementation Cost (Development Breakdown)

### **Resource & Timeline Summary**
*   **Estimated Development Time:** 12 Weeks (3 Months).
*   **Personnel:** 2 Backend/Systems Engineers, 1 Frontend/UI Engineer, 1 Space Operations Specialist.

### **Cost Breakdown Matrix**
| Phase | Focus Areas | Est. Hours | Target Cost (USD) |
| :--- | :--- | :--- | :--- |
| **Phase 1: Ingestion & Security** | TPM 2.0 drivers, HMAC signature validations, and message queues. | 160 hrs | $12,000 |
| **Phase 2: Detection & Holt Trend** | Rust maths core, Holt trend calculations, and Isolation Forest integrations. | 240 hrs | $18,000 |
| **Phase 3: Copilot & Playbooks** | GGUF runtime compilation, playbook engines, and router script dispatchers. | 200 hrs | $15,000 |
| **Phase 4: Dashboard UI** | Vite dashboard, real-time plotting, and WebSockets configuration. | 160 hrs | $10,000 |
| **Phase 5: Integration & Validation** | Edge hardware validation, simulated satellite runs, and penetration tests. | 120 hrs | $8,000 |
| **Total Project Estimate** | **Integrated Deployable Solution** | **880 hrs** | **$63,000** |
