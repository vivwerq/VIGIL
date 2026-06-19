//! # Anomaly Detection Engine
//!
//! The composite engine that orchestrates feature extraction, sliding
//! window management, and multi-detector anomaly scoring.
//!
//! ## How It Works
//!
//! 1. Receive a `TelemetryEnvelope`.
//! 2. Extract numerical features → `Vec<MetricSample>`.
//! 3. For each metric, look up (or create) its sliding window.
//! 4. Run all detectors against the sample and its window.
//! 5. Combine detector verdicts into a weighted composite score.
//! 6. Produce an `AnomalyReport` with explanation and recommendations.
//! 7. Update the sliding window with the new value.

use std::collections::HashMap;

use chrono::Utc;
use uuid::Uuid;
use vigil_core::types::TelemetryEnvelope;

use crate::detectors::*;
use crate::features::{MetricKey, extract_features};
use crate::results::*;
use crate::stats::SlidingWindow;

/// Configuration for the detection engine.
#[derive(Debug, Clone)]
pub struct DetectionEngineConfig {
    /// Sliding window capacity (number of samples per metric).
    pub window_size: usize,
    /// Anomaly score threshold. Events scoring above this are flagged.
    pub anomaly_threshold: f64,
    /// Z-Score detector config.
    pub zscore: ZScoreConfig,
    /// IQR detector config.
    pub iqr: IqrConfig,
    /// Rate-of-Change detector config.
    pub rate_of_change: RateOfChangeConfig,
    /// Weight for Z-Score detector in composite score.
    pub zscore_weight: f64,
    /// Weight for IQR detector in composite score.
    pub iqr_weight: f64,
    /// Weight for Rate-of-Change detector in composite score.
    pub rate_of_change_weight: f64,
    /// Weight for ML (Isolation Forest) detector in ensemble composite score.
    pub ml_weight: f64,
    /// Number of trees in the Isolation Forest.
    pub ml_num_trees: usize,
    /// Subsample size for each Isolation Tree.
    pub ml_subsample_size: usize,
}

impl Default for DetectionEngineConfig {
    fn default() -> Self {
        Self {
            window_size: 200,
            anomaly_threshold: 0.5,
            zscore: ZScoreConfig::default(),
            iqr: IqrConfig::default(),
            rate_of_change: RateOfChangeConfig::default(),
            // Ensemble weights: Stats (70%) and ML (30%)
            zscore_weight: 0.35,
            iqr_weight: 0.35,
            rate_of_change_weight: 0.10,
            ml_weight: 0.20,
            ml_num_trees: 50,
            ml_subsample_size: 64,
        }
    }
}

/// The main anomaly detection engine.
///
/// Maintains per-(source, metric) sliding windows and runs all
/// configured detectors against each incoming telemetry event.
///
/// ## Thread Safety
///
/// This engine is NOT thread-safe. For concurrent access, wrap in
/// `tokio::sync::Mutex` or run on a single dedicated task.
pub struct DetectionEngine {
    config: DetectionEngineConfig,
    /// Per-metric sliding windows: MetricKey → SlidingWindow.
    windows: HashMap<MetricKey, SlidingWindow>,
    /// Z-Score detector instance.
    zscore_detector: ZScoreDetector,
    /// IQR detector instance.
    iqr_detector: IqrDetector,
    /// Rate-of-Change detector instance.
    roc_detector: RateOfChangeDetector,
    /// Total events processed.
    events_processed: u64,
    /// Total anomalies detected.
    anomalies_detected: u64,
}

impl DetectionEngine {
    /// Create a new detection engine with the given configuration.
    pub fn new(config: DetectionEngineConfig) -> Self {
        let zscore_detector = ZScoreDetector::new(config.zscore.clone());
        let iqr_detector = IqrDetector::new(config.iqr.clone());
        let roc_detector = RateOfChangeDetector::new(config.rate_of_change.clone());

        Self {
            config,
            windows: HashMap::new(),
            zscore_detector,
            iqr_detector,
            roc_detector,
            events_processed: 0,
            anomalies_detected: 0,
        }
    }

    pub fn analyze(&mut self, envelope: &TelemetryEnvelope) -> AnomalyReport {
        self.events_processed += 1;

        // Step 1: Extract numerical features from the event.
        let samples = extract_features(envelope);

        // Capture references and values to avoid borrow checker conflicts.
        let zscore = &self.zscore_detector;
        let iqr = &self.iqr_detector;
        let roc = &self.roc_detector;

        let w_zscore = self.config.zscore_weight;
        let w_iqr = self.config.iqr_weight;
        let w_roc = self.config.rate_of_change_weight;

        // Step 2: Run detectors on each metric sample.
        let mut all_verdicts: Vec<DetectorVerdict> = Vec::new();
        let mut max_composite_score: f64 = 0.0;
        let mut max_ml_score: f64 = 0.0;
        let mut _max_stat_score: f64 = 0.0;
        let mut overall_confidence: f64 = 1.0;

        for sample in &samples {
            // Get or create the sliding window for this metric.
            let window = self
                .windows
                .entry(sample.key.clone())
                .or_insert_with(|| SlidingWindow::new(self.config.window_size));

            // Run statistical detectors.
            let mut verdicts = Vec::with_capacity(4);
            if let Some(v) = zscore.analyze(sample, window) {
                verdicts.push(v);
            }
            if let Some(v) = iqr.analyze(sample, window) {
                verdicts.push(v);
            }
            if let Some(v) = roc.analyze(sample, window) {
                verdicts.push(v);
            }

            // Compute statistical score.
            let mut stat_sum = 0.0;
            let mut stat_weight = 0.0;
            for v in &verdicts {
                let weight = match v.detector_type {
                    DetectorType::ZScore => w_zscore,
                    DetectorType::Iqr => w_iqr,
                    DetectorType::RateOfChange => w_roc,
                    _ => 0.0,
                };
                stat_sum += v.score * weight;
                stat_weight += weight;
            }
            let stat_score = if stat_weight > 0.0 {
                (stat_sum / stat_weight).clamp(0.0, 1.0)
            } else {
                0.0
            };

            // Run Machine Learning Isolation Forest detector
            let mut ml_score = 0.0;
            if let Some(dataset) = crate::ml::window_to_dataset(window) {
                let mut forest = crate::ml::IsolationForest::new(
                    self.config.ml_num_trees,
                    self.config.ml_subsample_size,
                );
                forest.fit(&dataset);
                ml_score = forest.predict(sample.value);
            }

            let ml_verdict = DetectorVerdict {
                detector_type: DetectorType::IsolationForest,
                metric_key: sample.key.clone(),
                score: ml_score,
                observed_value: sample.value,
                expected_value: window.median(),
                threshold: self.config.anomaly_threshold,
                deviation: ml_score,
                baseline_stats: window.stats(),
                explanation: format!(
                    "Isolation Forest ML score is {:.3} (ensemble weight={:.2})",
                    ml_score, self.config.ml_weight
                ),
            };
            verdicts.push(ml_verdict);

            // NOTE (Vivek): Fusing the traditional statistical engine with linfa's Isolation Forest
            // took me a whole night to calibrate. Originally, the ML model was overpowering the
            // stats and raising false alarms on startup. Added the warmup factor and settled on
            // a 80/20 stats/ML split to make it rock solid.
            let ensemble_score = ((1.0 - self.config.ml_weight) * stat_score
                + self.config.ml_weight * ml_score)
                .clamp(0.0, 1.0);

            if ensemble_score > max_composite_score {
                max_composite_score = ensemble_score;
                max_ml_score = ml_score;
                _max_stat_score = stat_score;

                // Confidence: agreement between statistical and ML detectors + window warmup factor
                let agreement = 1.0 - (stat_score - ml_score).abs();
                let warmup_factor = if window.len() >= 20 {
                    1.0
                } else {
                    window.len() as f64 / 20.0
                };
                overall_confidence = (agreement * warmup_factor).clamp(0.0, 1.0);
            }

            all_verdicts.extend(verdicts);

            // Step 3: Update the window AFTER detection (so the current
            // value doesn't influence its own baseline).
            window.push(sample.value);
        }

        // Step 3.5: Run linear regression trend projection for predictive time-to-impact estimation.
        let mut min_time_to_impact: Option<u64> = None;
        let mut predicted_breach_metric: Option<String> = None;

        for sample in &samples {
            if let Some(window) = self.windows.get(&sample.key) {
                let vals = window.values();
                if vals.len() >= 10 {
                    let n = 10;
                    let last_10 = &vals[vals.len() - n..];
                    
                    let sum_x: f64 = 45.0;
                    let sum_y: f64 = last_10.iter().sum();
                    let sum_xy: f64 = last_10.iter().enumerate().map(|(i, &y)| i as f64 * y).sum();
                    let denominator = 825.0;
                    let slope = (10.0 * sum_xy - sum_x * sum_y) / denominator;

                    let (threshold, metric_label) = match sample.key.metric_name.as_str() {
                        "latency_us" => (15000.0, "Path Latency"),
                        "packet_loss_pct" => (10.0, "Packet Loss"),
                        "utilization_pct" => (85.0, "Link Utilization"),
                        "crc_errors" => (100.0, "CRC Errors"),
                        "in_errors" => (50.0, "Inbound Interface Errors"),
                        "out_errors" => (50.0, "Outbound Interface Errors"),
                        "affected_prefixes" => (500.0, "BGP Prefix Count"),
                        "reroute_count" => (10.0, "Active LSP Reroutes"),
                        "lsa_count" => (200.0, "OSPF LSA Flood"),
                        _ => (100.0, "Metric"),
                    };

                    let curr_val = sample.value;
                    if slope > 1e-5 && curr_val < threshold {
                        let distance = threshold - curr_val;
                        let intervals = distance / slope;
                        let est_secs = intervals.round() as u64;
                        if est_secs > 0 && est_secs < 300 {
                            if min_time_to_impact.map_or(true, |t| est_secs < t) {
                                min_time_to_impact = Some(est_secs);
                                predicted_breach_metric = Some(metric_label.to_string());
                            }
                        }
                    }
                }
            }
        }

        // Step 4: Build the final report.
        let is_anomalous = max_composite_score >= self.config.anomaly_threshold;
        if is_anomalous {
            self.anomalies_detected += 1;
        }

        let severity = AnomalyReport::classify_severity(max_composite_score);
        let explanation = self.build_explanation(&all_verdicts, max_composite_score, is_anomalous);
        let recommendations = self.generate_recommendations(&all_verdicts, envelope);

        AnomalyReport {
            id: Uuid::now_v7(),
            envelope_id: envelope.id,
            analyzed_at: Utc::now(),
            score: max_composite_score,
            ml_score: max_ml_score,
            confidence: overall_confidence,
            is_anomalous,
            severity,
            verdicts: all_verdicts,
            explanation,
            recommendations,
            time_to_impact_secs: min_time_to_impact,
            predicted_breach_metric,
        }
    }

    /// Build a human-readable explanation from the detector verdicts.
    fn build_explanation(
        &self,
        verdicts: &[DetectorVerdict],
        score: f64,
        is_anomalous: bool,
    ) -> String {
        if !is_anomalous {
            return format!("All metrics within normal bounds (score={:.3}).", score);
        }

        // Collect the top contributing anomalies.
        let mut anomalous: Vec<&DetectorVerdict> =
            verdicts.iter().filter(|v| v.score > 0.3).collect();
        anomalous.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        if anomalous.is_empty() {
            return format!("Marginal anomaly detected (score={:.3}).", score);
        }

        let mut explanation = format!(
            "ANOMALY DETECTED (score={:.3}, severity={}):\n",
            score,
            AnomalyReport::classify_severity(score)
        );

        for (i, v) in anomalous.iter().take(5).enumerate() {
            explanation.push_str(&format!(
                "  {}. [{}] {}\n",
                i + 1,
                v.detector_type,
                v.explanation
            ));
        }

        explanation
    }

    /// Generate actionable recommendations based on the anomaly type.
    fn generate_recommendations(
        &self,
        verdicts: &[DetectorVerdict],
        envelope: &TelemetryEnvelope,
    ) -> Vec<String> {
        let mut recs = Vec::new();

        for v in verdicts {
            if v.score < self.config.anomaly_threshold {
                continue;
            }

            match v.metric_key.metric_name.as_str() {
                "latency_us" => {
                    recs.push("Check for congestion on the LSP path".to_string());
                    recs.push("Verify fiber optic signal levels on intermediate links".to_string());
                    recs.push(
                        "Run traceroute to identify the latency-contributing hop".to_string(),
                    );
                }
                "packet_loss_pct" => {
                    recs.push("Check interface error counters on all hops".to_string());
                    recs.push("Verify buffer utilization on intermediate routers".to_string());
                    recs.push("Consider enabling FEC if not already active".to_string());
                }
                "utilization_pct" => {
                    recs.push("Investigate top talkers using NetFlow/sFlow".to_string());
                    recs.push("Consider traffic engineering to redistribute load".to_string());
                    recs.push("Evaluate capacity upgrade if sustained saturation".to_string());
                }
                "crc_errors" | "in_errors" | "out_errors" => {
                    recs.push("Inspect physical cabling and SFP/optic modules".to_string());
                    recs.push("Check for EMI sources near the affected link".to_string());
                    recs.push("Schedule fiber cleaning/replacement if errors persist".to_string());
                }
                "affected_prefixes" => {
                    recs.push("Verify BGP prefix filters on the affected peer".to_string());
                    recs.push("Check for route leak using AS path analysis".to_string());
                    recs.push("Consider implementing RPKI/ROA validation".to_string());
                }
                "reroute_count" => {
                    recs.push("Investigate root cause of LSP instability".to_string());
                    recs.push("Check RSVP-TE signaling on the affected path".to_string());
                    recs.push("Review MPLS FRR configuration for the tunnel".to_string());
                }
                "jitter_us" => {
                    recs.push("Check QoS policies on intermediate hops".to_string());
                    recs.push("Verify traffic shaping configuration".to_string());
                }
                "lsa_count" => {
                    recs.push("Investigate OSPF topology changes".to_string());
                    recs.push("Check for link flapping in the affected area".to_string());
                }
                "trap_count" => {
                    recs.push(format!(
                        "Investigate SNMP trap burst from {}",
                        envelope.source.hostname
                    ));
                    recs.push("Check for authentication failures (possible intrusion)".to_string());
                }
                _ => {
                    recs.push(format!(
                        "Investigate anomalous {} on {}",
                        v.metric_key.metric_name, envelope.source.hostname
                    ));
                }
            }
        }

        recs.dedup();
        recs
    }

    /// Get the number of active metric windows.
    pub fn active_metrics(&self) -> usize {
        self.windows.len()
    }

    /// Get total events processed.
    pub fn events_processed(&self) -> u64 {
        self.events_processed
    }

    /// Get total anomalies detected.
    pub fn anomalies_detected(&self) -> u64 {
        self.anomalies_detected
    }

    /// Get the anomaly detection rate (anomalies / total events).
    pub fn anomaly_rate(&self) -> f64 {
        if self.events_processed == 0 {
            0.0
        } else {
            self.anomalies_detected as f64 / self.events_processed as f64
        }
    }

    /// Get the current configuration.
    pub fn config(&self) -> &DetectionEngineConfig {
        &self.config
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use vigil_core::types::*;
    use vigil_synth::generator::{GeneratorConfig, TelemetryGenerator};

    fn make_lsp_envelope(latency_us: u64) -> TelemetryEnvelope {
        TelemetryEnvelope {
            id: Uuid::now_v7(),
            timestamp: Utc::now(),
            source: TelemetrySource {
                hostname: "test-rtr-01".into(),
                ip_address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                device_type: DeviceType::CoreRouter,
                site_id: "TEST".into(),
            },
            hmac_tag: vec![0; 32],
            event: NetworkEvent::Lsp(LspMetrics {
                lsp_name: "LSP-TEST".into(),
                source: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                destination: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                status: LspStatus::Up,
                latency_us,
                jitter_us: 200,
                packet_loss_pct: 0.0,
                bandwidth_bps: 1_000_000_000,
                reroute_count: 0,
            }),
            sequence_number: 0,
            ground_truth_label: None,
        }
    }

    #[test]
    fn engine_detects_latency_spike() {
        let config = DetectionEngineConfig {
            window_size: 100,
            anomaly_threshold: 0.3,
            zscore: ZScoreConfig {
                threshold: 3.0,
                min_samples: 20,
            },
            iqr: IqrConfig {
                multiplier: 1.5,
                min_samples: 20,
            },
            rate_of_change: RateOfChangeConfig {
                min_samples: 5,
                ..Default::default()
            },
            ..Default::default()
        };
        let mut engine = DetectionEngine::new(config);

        // Build baseline: 50 events with latency ~5000μs
        for _ in 0..50 {
            let envelope = make_lsp_envelope(5000);
            let report = engine.analyze(&envelope);
            assert!(
                !report.is_anomalous,
                "Baseline events should not be anomalous"
            );
        }

        // Inject a latency spike: 50,000μs (10× baseline)
        let spike = make_lsp_envelope(50_000);
        let report = engine.analyze(&spike);

        assert!(report.is_anomalous, "Latency spike should be detected");
        assert!(
            report.score > 0.5,
            "Score should be significant, got {}",
            report.score
        );
        assert!(!report.verdicts.is_empty(), "Should have detector verdicts");
        assert!(!report.explanation.is_empty(), "Should have explanation");
        assert!(
            !report.recommendations.is_empty(),
            "Should have recommendations"
        );

        tracing::info!(
            score = report.score,
            severity = %report.severity,
            explanation = %report.explanation,
            "Detection result"
        );
    }

    #[test]
    fn engine_normal_traffic_not_anomalous() {
        let mut engine = DetectionEngine::new(DetectionEngineConfig::default());

        // Feed 100 normal events
        for _ in 0..100 {
            let envelope = make_lsp_envelope(5000);
            let report = engine.analyze(&envelope);
            // After warmup, all should be non-anomalous
            if engine.events_processed() > 50 {
                assert!(
                    !report.is_anomalous,
                    "Normal traffic should not trigger anomaly (score={})",
                    report.score
                );
            }
        }

        assert_eq!(engine.events_processed(), 100);
    }

    #[test]
    fn engine_tracks_multiple_metrics() {
        let mut engine = DetectionEngine::new(DetectionEngineConfig::default());
        let envelope = make_lsp_envelope(5000);
        engine.analyze(&envelope);

        // LSP events produce 4 metrics (latency, jitter, loss, reroutes)
        // Each metric has source.lsp_name prefix
        assert!(
            engine.active_metrics() >= 4,
            "Should track at least 4 metrics, got {}",
            engine.active_metrics()
        );
    }

    #[test]
    fn engine_with_synthetic_generator() {
        let mut engine = DetectionEngine::new(DetectionEngineConfig {
            window_size: 100,
            anomaly_threshold: 0.4,
            zscore: ZScoreConfig {
                min_samples: 15,
                ..Default::default()
            },
            iqr: IqrConfig {
                min_samples: 15,
                ..Default::default()
            },
            ..Default::default()
        });

        // Use the synthetic generator with high anomaly rate
        let gen_config = GeneratorConfig {
            anomaly_rate: 0.15,
            ..Default::default()
        };
        let mut generator = TelemetryGenerator::new(gen_config);

        let mut total_anomalies = 0;
        let total_events = 500;

        for _ in 0..total_events {
            let envelope = generator.generate_event();
            let report = engine.analyze(&envelope);
            if report.is_anomalous {
                total_anomalies += 1;
            }
        }

        // With warmup period and 15% injection rate, we should detect some anomalies
        // but not too many (detectors need to warm up first).
        assert!(engine.events_processed() == total_events as u64);
        tracing::info!(
            total = total_events,
            anomalies = total_anomalies,
            rate = format!(
                "{:.1}%",
                (total_anomalies as f64 / total_events as f64) * 100.0
            ),
            active_metrics = engine.active_metrics(),
            "Synthetic generator test complete"
        );
    }

    #[test]
    fn engine_detects_outliers_using_ml() {
        let config = DetectionEngineConfig {
            window_size: 50,
            anomaly_threshold: 0.4,
            ml_weight: 0.30,
            ml_num_trees: 30,
            ml_subsample_size: 20,
            ..Default::default()
        };
        let mut engine = DetectionEngine::new(config);

        // Build baseline: 30 events with latency ~5000
        for _ in 0..30 {
            let envelope = make_lsp_envelope(5000);
            engine.analyze(&envelope);
        }

        // Now inject a spike
        let spike = make_lsp_envelope(25000);
        let report = engine.analyze(&spike);

        assert!(
            report.ml_score > 0.3,
            "ML score should be non-zero and significant"
        );
        assert!(
            report.confidence > 0.0,
            "Confidence should be populated and valid"
        );
        assert!(report.score > 0.0, "Composite score should be non-zero");
        assert!(
            report
                .verdicts
                .iter()
                .any(|v| v.detector_type == DetectorType::IsolationForest),
            "Should contain an IsolationForest verdict"
        );
    }
}
