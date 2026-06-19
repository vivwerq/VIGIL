//! # VIGIL Daemon
//!
//! Main entry point for the VIGIL system. Orchestrates:
//! 1. Synthetic telemetry generation (dev mode) or real ingestion
//! 2. Telemetry parsing and validation pipeline
//! 3. Event processing and forwarding to detection engine
//! 4. Storage of telemetry envelopes and anomaly reports in the local database
//! 5. Offline LLM-based NOC diagnostics and remediation generation
//! 6. Axum-based HTTP server for the VIGIL NOC Dashboard UI

#![allow(
    clippy::too_many_lines,
    clippy::similar_names,
    clippy::needless_raw_string_hashes,
    clippy::single_match_else
)]

use anyhow::Result;
use clap::Parser;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::Mutex;
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

use vigil_core::config::VigilConfig;
use vigil_ingest::pipeline::IngestionPipeline;
use vigil_synth::generator::{GeneratorConfig, TelemetryGenerator};
use vigil_synth::scenarios;

// Integration of Phase 2 + Phase 3 components
use vigil_detect::engine::{DetectionEngine, DetectionEngineConfig};
use vigil_llm::{CopilotReport, LlmCopilot};
use vigil_store::VigilStore;

// Axum web server imports
use axum::{
    Json, Router,
    extract::{Path, State},
    http::{StatusCode, header},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};

/// VIGIL — Air-Gapped Predictive AI NOC Copilot
#[derive(Parser, Debug)]
#[command(name = "vigil", version, about, long_about = None)]
struct Cli {
    /// Operating mode
    #[arg(long, default_value = "synthetic")]
    mode: String,

    /// Number of events to generate per scenario run (synthetic mode)
    #[arg(long, default_value = "100")]
    events: usize,

    /// Anomaly injection rate (0.0-1.0)
    #[arg(long, default_value = "0.05")]
    anomaly_rate: f64,

    /// Pre-built failure scenario
    #[arg(long)]
    scenario: Option<String>,

    /// Log level (trace, debug, info, warn, error)
    #[arg(long, default_value = "info")]
    log_level: String,

    /// Dashboard web server bind address
    #[arg(long, default_value = "127.0.0.1:3000")]
    bind_address: String,

    /// Path to custom TOML configuration file
    #[arg(long)]
    config: Option<String>,

    /// Launch interactive TOML configuration wizard (xcomrade.tech Edition)
    #[arg(long)]
    wizard: bool,
}

/// Shared state for the HTTP server
struct SharedState {
    store: VigilStore,
    copilot: LlmCopilot,
    copilot_reports: Arc<Mutex<HashMap<Uuid, CopilotReport>>>,
    scenario_tx: std::sync::mpsc::Sender<String>,
    total_ingested: Arc<AtomicU64>,
    total_anomalies: Arc<AtomicU64>,
    raw_ingest_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
}

fn ask_prompt(question: &str, default: &str) -> String {
    print!("{} [{}]: ", question, default);
    use std::io::Write;
    std::io::stdout().flush().expect("Flush stdout failed");
    let mut input = String::new();
    std::io::stdin()
        .read_line(&mut input)
        .expect("Read line failed");
    let trimmed = input.trim();
    if trimmed.is_empty() {
        default.to_string()
    } else {
        trimmed.to_string()
    }
}

fn run_config_wizard() -> Result<()> {
    println!("\n🔧 VIGIL Configuration Wizard (xcomrade.tech Edition)");
    println!("====================================================");
    let bind_address = ask_prompt("Dashboard bind address", "127.0.0.1:3000");
    let db_path = ask_prompt("Database storage path", "data/vigil.db");
    let model_path = ask_prompt("GGUF model path", "models/phi-3.5-mini-instruct.gguf");
    let enforce_hmac_str = ask_prompt("Enforce HMAC verification (true/false)", "true");
    let enforce_hmac = enforce_hmac_str.trim().to_lowercase() == "true";
    let source_name = ask_prompt("Telemetry source name", "ground-station-1");

    // Auto-generate secure 32-byte key
    let mut key_bytes = [0u8; 32];
    for byte in &mut key_bytes {
        *byte = rand::random::<u8>();
    }
    let hmac_hex = key_bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>();
    println!(
        "Generated secure 32-byte HMAC key for {}: {}",
        source_name, hmac_hex
    );

    let toml_content = format!(
        r#"[ingestion]
max_events_per_second = 1000
channel_capacity = 10000
max_event_age_seconds = 60
enforce_hmac = {}
bind_address = "{}"

[storage]
db_path = "{}"
max_db_size_bytes = 1073741824
compaction_interval_secs = 3600

[detection]
model_path = "models/isolation_forest.model"
anomaly_threshold = 0.8
window_size = 100

[llm]
model_path = "{}"
max_tokens = 512
temperature = 0.1
n_threads = 4

[hmac_keys]
{} = "{}"
"#,
        enforce_hmac, bind_address, db_path, model_path, source_name, hmac_hex
    );

    let dest = "vigil.toml";
    std::fs::write(dest, toml_content)?;
    println!("\nSUCCESS: Configuration written to {}", dest);
    println!(
        "You can now deploy VIGIL using: vigil-daemon --mode production --config {}",
        dest
    );
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    if cli.wizard {
        run_config_wizard()?;
        return Ok(());
    }

    // Initialize structured logging
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&cli.log_level)),
        )
        .with_target(true)
        .with_thread_ids(true)
        .with_file(true)
        .with_line_number(true)
        .init();

    tracing::info!(
        r#"
╔═══════════════════════════════════════════════════════════════╗
║  ██╗   ██╗██╗ ██████╗ ██╗██╗                                ║
║  ██║   ██║██║██╔════╝ ██║██║                                ║
║  ██║   ██║██║██║  ███╗██║██║                                ║
║  ╚██╗ ██╔╝██║██║   ██║██║██║                                ║
║   ╚████╔╝ ██║╚██████╔╝██║███████╗                           ║
║    ╚═══╝  ╚═╝ ╚═════╝ ╚═╝╚══════╝                           ║
║  Verified Intelligent Ground-station Infrastructure Liaison  ║
║  Air-Gapped Predictive AI NOC Copilot                        ║
╚═══════════════════════════════════════════════════════════════╝"#
    );

    // Load and validate configuration
    let mut config = if let Some(ref config_path) = cli.config {
        VigilConfig::load_from_file(config_path)?
    } else if std::path::Path::new("vigil.toml").exists() {
        VigilConfig::load_from_file("vigil.toml")?
    } else if std::path::Path::new("/etc/vigil/vigil.toml").exists() {
        VigilConfig::load_from_file("/etc/vigil/vigil.toml")?
    } else {
        VigilConfig::default()
    };

    if cli.mode == "synthetic" {
        config.ingestion.enforce_hmac = false; // Synthetic mode doesn't use HMAC
    }
    config.validate()?;

    match cli.mode.as_str() {
        "synthetic" | "production" => run_daemon(&cli, &config).await?,
        _ => {
            tracing::error!(mode = %cli.mode, "Unknown mode — only 'synthetic' and 'production' are available");
            std::process::exit(1);
        }
    }

    Ok(())
}

async fn run_daemon(cli: &Cli, config: &VigilConfig) -> Result<()> {
    // Open VigilStore database
    let store_path = &config.storage.db_path;
    let store = match VigilStore::open(store_path) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(
                "Failed to open database at {:?}: {}. Falling back to target/vigil-dev.redb",
                store_path,
                e
            );
            std::fs::create_dir_all("target")?;
            VigilStore::open("target/vigil-dev.redb")?
        }
    };

    // Initialize Anomaly Detection Engine
    let detect_config = DetectionEngineConfig {
        window_size: config.detection.window_size,
        anomaly_threshold: config.detection.anomaly_threshold,
        ..Default::default()
    };
    let mut detection_engine = DetectionEngine::new(detect_config);

    // Initialize LLM Copilot Interface
    let copilot = LlmCopilot::new(config.llm.clone());

    // Parse HMAC keys
    let mut hmac_keys = std::collections::HashMap::new();
    for (source, hex_key) in &config.hmac_keys {
        if let Some(key_bytes) = hex_to_bytes(hex_key) {
            match vigil_core::crypto::HmacKey::new(&key_bytes) {
                Ok(hmac_key) => {
                    hmac_keys.insert(source.clone(), hmac_key);
                }
                Err(e) => {
                    tracing::error!(source = %source, "Invalid HMAC key size in config: {:?}", e);
                }
            }
        } else {
            tracing::error!(source = %source, "HMAC key is not a valid hex string");
        }
    }

    // Create the pipeline
    let pipeline = IngestionPipeline::new(config, hmac_keys);

    // Channels for telemetry ingestion and generator control
    let (raw_ingest_tx, mut raw_ingest_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(10000);
    let (scenario_tx, scenario_rx) = std::sync::mpsc::channel::<String>();

    if cli.mode == "synthetic" {
        tracing::info!(
            events = cli.events,
            anomaly_rate = cli.anomaly_rate,
            scenario = ?cli.scenario,
            "Starting synthetic telemetry generation"
        );

        // Select initial generator config based on scenario parameter
        let gen_config = match cli.scenario.as_deref() {
            Some("fiber-cut") => {
                tracing::warn!(
                    "🔥 Scenario: FIBER CUT — simulating physical infrastructure failure"
                );
                scenarios::fiber_cut_scenario()
            }
            Some("route-leak") => {
                tracing::warn!("🔥 Scenario: BGP ROUTE LEAK — simulating prefix flood");
                scenarios::bgp_route_leak_scenario()
            }
            Some("degraded-optics") => {
                tracing::warn!("⚠️  Scenario: DEGRADED OPTICS — simulating gradual failure");
                scenarios::degraded_optics_scenario()
            }
            Some("congestion-buildup") => {
                tracing::warn!("⚠️  Scenario: CONGESTION BUILDUP — simulating progressive traffic growth");
                scenarios::progressive_congestion_scenario()
            }
            Some("security-incident") => {
                tracing::warn!("🔴 Scenario: SECURITY INCIDENT — simulating unauthorized access");
                scenarios::security_incident_scenario()
            }
            Some("normal") => {
                tracing::info!("✅ Scenario: NORMAL OPERATIONS — baseline traffic");
                scenarios::normal_operations_scenario()
            }
            Some(unknown) => {
                tracing::error!(scenario = unknown, "Unknown scenario");
                std::process::exit(1);
            }
            None => GeneratorConfig {
                anomaly_rate: cli.anomaly_rate,
                ..Default::default()
            },
        };

        let raw_ingest_tx_clone = raw_ingest_tx.clone();
        let events_count = cli.events;
        // Dedicated generator thread to support dynamic scenario switching via web UI
        std::thread::spawn(move || {
            let mut generator = TelemetryGenerator::new(gen_config);
            let mut count = 0;
            let interval = std::time::Duration::from_millis(500);

            loop {
                // Check for new scenario request
                while let Ok(new_scenario) = scenario_rx.try_recv() {
                    tracing::info!("Dynamic scenario switch to: {}", new_scenario);
                    let new_config = match new_scenario.as_str() {
                        "fiber-cut" => scenarios::fiber_cut_scenario(),
                        "route-leak" => scenarios::bgp_route_leak_scenario(),
                        "degraded-optics" => scenarios::degraded_optics_scenario(),
                        "congestion-buildup" => scenarios::progressive_congestion_scenario(),
                        "security-incident" => scenarios::security_incident_scenario(),
                        _ => scenarios::normal_operations_scenario(),
                    };
                    generator = TelemetryGenerator::new(new_config);
                    count = 0; // Reset event counter for the new scenario run
                }

                if count < events_count {
                    let envelope = generator.generate_event();
                    if let Ok(json) = serde_json::to_vec(&envelope) {
                        if raw_ingest_tx_clone.blocking_send(json).is_err() {
                            break;
                        }
                    }
                    count += 1;
                }

                std::thread::sleep(interval);
            }
        });
    } else {
        tracing::info!(
            "Starting VIGIL in PRODUCTION mode. Listening for incoming remote telemetry."
        );
    }

    // Share state variables with web server
    let total_ingested = Arc::new(AtomicU64::new(0));
    let total_anomalies = Arc::new(AtomicU64::new(0));
    let copilot_reports = Arc::new(Mutex::new(HashMap::new()));

    let shared_state = Arc::new(SharedState {
        store: store.clone(),
        copilot: copilot.clone(),
        copilot_reports: copilot_reports.clone(),
        scenario_tx,
        total_ingested: total_ingested.clone(),
        total_anomalies: total_anomalies.clone(),
        raw_ingest_tx: raw_ingest_tx.clone(),
    });

    // Build the Axum router
    let app = Router::new()
        .route("/", get(index_handler))
        .route("/style.css", get(css_handler))
        .route("/dashboard.css", get(css_handler))
        .route("/app.js", get(js_handler))
        .route("/dashboard.js", get(js_handler))
        .route("/fonts/outfit-latin.woff2", get(font_outfit_handler))
        .route("/fonts/firacode-400.woff2", get(font_firacode_400_handler))
        .route("/fonts/firacode-600.woff2", get(font_firacode_600_handler))
        .route("/api/status", get(get_status))
        .route("/api/telemetry", get(get_telemetry_history))
        .route("/api/telemetry/submit", post(post_telemetry_submit))
        .route("/api/anomalies", get(get_anomalies_history))
        .route("/api/anomalies/{id}", get(get_anomaly_report_details))
        .route("/api/simulate", post(post_simulate))
        .with_state(shared_state);

    // Bind and start the web server
    let addr: SocketAddr = cli.bind_address.parse().unwrap_or_else(|_| {
        tracing::warn!("Failed to parse bind address, using default 127.0.0.1:3000");
        SocketAddr::from(([127, 0, 0, 1], 3000))
    });

    tracing::info!("🚀 Starting VIGIL NOC Dashboard UI on http://{}", addr);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app).await {
            tracing::error!("Dashboard UI server error: {:?}", e);
        }
    });

    // Main Ingestion & Analysis Loop
    while let Some(raw_bytes) = raw_ingest_rx.recv().await {
        // Submit to validation pipeline
        if let Err(e) = pipeline.submit(raw_bytes).await {
            tracing::error!("Pipeline submission failed: {:?}", e);
            continue;
        }

        // Receive validated envelope
        if let Ok(validated) = pipeline.recv().await {
            total_ingested.fetch_add(1, Ordering::Relaxed);

            // 1. Persist to redb database
            if let Err(e) = store.insert_telemetry(&validated) {
                tracing::error!(event_id = %validated.id, "Failed to persist telemetry: {:?}", e);
            }

            // 2. Perform statistical anomaly scoring
            let report = detection_engine.analyze(&validated);

            // 3. Process anomaly report if flagged
            if report.is_anomalous {
                total_anomalies.fetch_add(1, Ordering::Relaxed);

                tracing::warn!(
                    protocol = validated.event.protocol_name(),
                    severity = %validated.event.severity(),
                    source = %validated.source.hostname,
                    id = %validated.id,
                    score = %report.score,
                    "🚨 ANOMALY DETECTED BY ENGINE"
                );

                // Persist Anomaly Report and update index
                if let Err(e) = store.insert_anomaly_report(&report) {
                    tracing::error!(report_id = %report.id, "Failed to persist anomaly report: {:?}", e);
                }

                // Spawn LLM Diagnostics generation asynchronously to avoid pipeline blocking
                let copilot_clone = copilot.clone();
                let reports_clone = copilot_reports.clone();
                let validated_clone = validated.clone();
                let report_clone = report.clone();
                let store_clone = store.clone();

                tokio::spawn(async move {
                    match copilot_clone
                        .diagnose_anomaly(&report_clone, &validated_clone)
                        .await
                    {
                        Ok(copilot_report) => {
                            print_copilot_report(&copilot_report);

                            // Cache in memory for quick dashboard lookup
                            let mut cache = reports_clone.lock().await;
                            cache.insert(report_clone.id, copilot_report.clone());

                            // Persist full DiagnosticReport in vigil-store
                            if let Ok(serialized) = serde_json::to_vec(&copilot_report) {
                                if let Err(e) = store_clone
                                    .insert_diagnostic_report(&report_clone.id, &serialized)
                                {
                                    tracing::error!(report_id = %report_clone.id, "Failed to persist diagnostic report in database: {:?}", e);
                                } else {
                                    tracing::info!(report_id = %report_clone.id, "Successfully persisted diagnostic report to vigil-store");
                                }
                            }
                        }
                        Err(e) => {
                            tracing::error!(event_id = %validated_clone.id, "LLM Copilot diagnostics failed: {:?}", e);
                        }
                    }
                });
            }
        }
    }

    // Keep process alive if telemetry ends but HTTP server is running
    tracing::info!("🏁 Initial telemetry generation complete. Dashboard remaining online.");
    std::future::pending::<()>().await;

    Ok(())
}

// --- Axum Response Handlers ---

async fn index_handler() -> impl IntoResponse {
    Html(include_str!("../web/index.html"))
}

async fn css_handler() -> impl IntoResponse {
    Response::builder()
        .header(header::CONTENT_TYPE, "text/css")
        .body(include_str!("../web/dashboard.css").to_string())
        .unwrap()
}

async fn js_handler() -> impl IntoResponse {
    Response::builder()
        .header(header::CONTENT_TYPE, "application/javascript")
        .body(include_str!("../web/dashboard.js").to_string())
        .unwrap()
}

async fn font_outfit_handler() -> impl IntoResponse {
    Response::builder()
        .header(header::CONTENT_TYPE, "font/woff2")
        .header(header::CACHE_CONTROL, "public, max-age=31536000, immutable")
        .body(axum::body::Body::from(
            &include_bytes!("../web/fonts/outfit-latin.woff2")[..],
        ))
        .unwrap()
}

async fn font_firacode_400_handler() -> impl IntoResponse {
    Response::builder()
        .header(header::CONTENT_TYPE, "font/woff2")
        .header(header::CACHE_CONTROL, "public, max-age=31536000, immutable")
        .body(axum::body::Body::from(
            &include_bytes!("../web/fonts/firacode-400.woff2")[..],
        ))
        .unwrap()
}

async fn font_firacode_600_handler() -> impl IntoResponse {
    Response::builder()
        .header(header::CONTENT_TYPE, "font/woff2")
        .header(header::CACHE_CONTROL, "public, max-age=31536000, immutable")
        .body(axum::body::Body::from(
            &include_bytes!("../web/fonts/firacode-600.woff2")[..],
        ))
        .unwrap()
}

async fn get_status(State(state): State<Arc<SharedState>>) -> impl IntoResponse {
    let telemetry_count = state.total_ingested.load(Ordering::Relaxed);
    let anomaly_count = state.total_anomalies.load(Ordering::Relaxed);

    // Count anomalies in the last 5 minutes from DB
    let filter = vigil_store::AnomalyQueryFilter {
        start_time: Some(chrono::Utc::now() - chrono::Duration::minutes(5)),
        limit: Some(100),
        ..Default::default()
    };
    let active_anomalies = state
        .store
        .query_anomalies(filter)
        .map(|list| list.len())
        .unwrap_or(0);

    Json(serde_json::json!({
        "total_ingested": telemetry_count,
        "total_anomalies": anomaly_count,
        "active_anomalies": active_anomalies,
        "status": "online"
    }))
}

async fn get_telemetry_history(
    State(state): State<Arc<SharedState>>,
) -> Result<impl IntoResponse, StatusCode> {
    let filter = vigil_store::TelemetryQueryFilter {
        limit: Some(50), // Return last 50 events
        ..Default::default()
    };
    match state.store.query_telemetry(filter) {
        Ok(events) => Ok(Json(events)),
        Err(e) => {
            tracing::error!("Failed to query telemetry: {:?}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn get_anomalies_history(
    State(state): State<Arc<SharedState>>,
) -> Result<impl IntoResponse, StatusCode> {
    let filter = vigil_store::AnomalyQueryFilter {
        limit: Some(30), // Return last 30 anomalies
        ..Default::default()
    };
    match state.store.query_anomalies(filter) {
        Ok(anomalies) => Ok(Json(anomalies)),
        Err(e) => {
            tracing::error!("Failed to query anomalies: {:?}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn generate_copilot_ondemand(
    state: &SharedState,
    anomaly_report: &vigil_detect::results::AnomalyReport,
) -> Result<CopilotReport, StatusCode> {
    let envelope = match state.store.get_telemetry(anomaly_report.envelope_id) {
        Ok(Some(env)) => env,
        Ok(None) => return Err(StatusCode::NOT_FOUND),
        Err(e) => {
            tracing::error!("DB error fetching telemetry: {:?}", e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    tracing::info!(
        "Generating Copilot report on-demand for anomaly ID {}",
        anomaly_report.id
    );
    match state
        .copilot
        .diagnose_anomaly(anomaly_report, &envelope)
        .await
    {
        Ok(report) => {
            // Cache in memory
            let mut cache = state.copilot_reports.lock().await;
            cache.insert(anomaly_report.id, report.clone());

            // Persist to store
            if let Ok(serialized) = serde_json::to_vec(&report) {
                if let Err(e) = state
                    .store
                    .insert_diagnostic_report(&anomaly_report.id, &serialized)
                {
                    tracing::error!(
                        "Failed to persist on-demand diagnostic report to store: {:?}",
                        e
                    );
                }
            }

            Ok(report)
        }
        Err(e) => {
            tracing::error!("Failed to generate copilot report on-demand: {:?}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn get_anomaly_report_details(
    State(state): State<Arc<SharedState>>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, StatusCode> {
    // 1. Fetch anomaly from DB (always needed for metadata)
    let anomaly_report = match state.store.get_anomaly_report(id) {
        Ok(Some(rep)) => rep,
        Ok(None) => return Err(StatusCode::NOT_FOUND),
        Err(e) => {
            tracing::error!("DB error fetching anomaly: {:?}", e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    // 2. Fetch associated telemetry envelope to query playbooks
    let envelope = match state.store.get_telemetry(anomaly_report.envelope_id) {
        Ok(Some(env)) => env,
        _ => {
            tracing::error!("Failed to fetch telemetry context for anomaly ID {}", id);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    // 3. Check copilot report in memory cache
    let copilot_report = {
        let cache = state.copilot_reports.lock().await;
        cache.get(&id).cloned()
    };

    // 4. Retrieve from store or generate on-demand if cache/db missed
    let copilot = if let Some(report) = copilot_report {
        report
    } else if let Ok(Some(bytes)) = state.store.get_diagnostic_report(id) {
        if let Ok(report) = serde_json::from_slice::<CopilotReport>(&bytes) {
            // Populate cache for subsequent requests
            let mut cache = state.copilot_reports.lock().await;
            cache.insert(id, report.clone());
            report
        } else {
            generate_copilot_ondemand(&state, &anomaly_report).await?
        }
    } else {
        generate_copilot_ondemand(&state, &anomaly_report).await?
    };

    // 5. Query the Playbook Engine
    let playbook = vigil_core::playbook::suggest_playbook(&envelope.event);

    // 6. Merge anomaly metadata + copilot report + playbook suggestions into a single response
    Ok(Json(serde_json::json!({
        "id": anomaly_report.id,
        "score": anomaly_report.score,
        "severity": format!("{}", anomaly_report.severity),
        "analyzed_at": anomaly_report.analyzed_at,
        "time_to_impact_secs": anomaly_report.time_to_impact_secs,
        "predicted_breach_metric": anomaly_report.predicted_breach_metric,
        "diagnosis": copilot.diagnosis,
        "reasoning": copilot.reasoning,
        "impact": copilot.impact,
        "mitigation": copilot.mitigation,
        "predicted_issue": copilot.predicted_issue,
        "confidence": copilot.confidence,
        "root_cause": copilot.root_cause,
        "recommended_action": copilot.recommended_action,
        "estimated_lead_time": copilot.estimated_lead_time,
        "playbook": {
            "name": playbook.name,
            "suggested_commands": playbook.suggested_commands,
            "reasoning": playbook.reasoning
        }
    })))
}

#[derive(serde::Deserialize)]
struct SimulateRequest {
    scenario: String,
}

async fn post_simulate(
    State(state): State<Arc<SharedState>>,
    Json(payload): Json<SimulateRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    tracing::info!("Scenario switch request: {}", payload.scenario);
    if state.scenario_tx.send(payload.scenario).is_err() {
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }
    Ok(StatusCode::OK)
}

async fn post_telemetry_submit(
    State(state): State<Arc<SharedState>>,
    body: axum::body::Bytes,
) -> Result<impl IntoResponse, StatusCode> {
    tracing::debug!("Received telemetry submit request ({} bytes)", body.len());
    if state.raw_ingest_tx.send(body.to_vec()).await.is_err() {
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }
    Ok(StatusCode::ACCEPTED)
}

#[allow(clippy::cast_possible_truncation)]
fn hex_to_bytes(s: &str) -> Option<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut chars = s.chars();
    while let Some(c1) = chars.next() {
        let c2 = chars.next()?;
        let val1 = c1.to_digit(16)?;
        let val2 = c2.to_digit(16)?;
        bytes.push((val1 * 16 + val2) as u8);
    }
    Some(bytes)
}

/// Print structured diagnosis report with dark hacker terminal aesthetic (ANSI colors)
fn print_copilot_report(report: &CopilotReport) {
    println!("\n\x1b[1;91m VIGIL AUTOMATED NOC DIAGNOSTIC REPORT \x1b[0m");
    println!(
        "\x1b[1;36m════════════════════════════════════════════════════════════════════════════════\x1b[0m"
    );
    println!("\x1b[1;93mDIAGNOSIS:\x1b[0m {}", report.diagnosis);
    println!("\x1b[1;93mREASONING:\x1b[0m {}", report.reasoning);
    println!("\x1b[1;93mIMPACT ASSESSMENT:\x1b[0m {}", report.impact);
    println!("\x1b[1;93mACTIONABLE MITIGATION ACTIONS:\x1b[0m");
    for (idx, step) in report.mitigation.iter().enumerate() {
        println!("  {}. \x1b[1;92m[{}]\x1b[0m", idx + 1, step);
    }
    println!(
        "\x1b[1;36m════════════════════════════════════════════════════════════════════════════════\x1b[0m\n"
    );
}
