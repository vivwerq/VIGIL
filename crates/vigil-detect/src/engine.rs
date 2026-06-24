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
    /// Cache of fitted Isolation Forests for each metric.
    ml_forests: HashMap<MetricKey, crate::ml::IsolationForest>,
    /// Number of samples observed since last model fit per metric.
    ml_updates: HashMap<MetricKey, usize>,
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
            ml_forests: HashMap::new(),
            ml_updates: HashMap::new(),
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
        let mut max_trend_score: f64 = 0.0;
        let mut overall_confidence: f64 = 1.0;

        let mut min_time_to_impact_secs: Option<u64> = None;
        let mut min_time_to_impact_mins: Option<f64> = None;
        let mut predicted_breach_metric: Option<String> = None;

        for sample in &samples {
            // Get or create the sliding window for this metric.
            let window = self
                .windows
                .entry(sample.key.clone())
                .or_insert_with(|| SlidingWindow::new(self.config.window_size));

            // Precompute stats once for the window.
            let stats = window.stats();

            // Run statistical detectors.
            let mut verdicts = Vec::with_capacity(4);
            if let Some(v) = zscore.analyze(sample, window, &stats) {
                verdicts.push(v);
            }
            if let Some(v) = iqr.analyze(sample, window, &stats) {
                verdicts.push(v);
            }
            if let Some(v) = roc.analyze(sample, window, &stats) {
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

            // Run Machine Learning Isolation Forest detector with caching
            let mut ml_score = 0.0;
            let updates = self.ml_updates.entry(sample.key.clone()).or_insert(0);
            *updates += 1;

            let forest_exists = self.ml_forests.contains_key(&sample.key);
            let needs_refit = !forest_exists || *updates >= 25;

            if needs_refit {
                if let Some(dataset) = crate::ml::window_to_dataset(window) {
                    let mut forest = crate::ml::IsolationForest::new(
                        self.config.ml_num_trees,
                        self.config.ml_subsample_size,
                    );
                    forest.fit(&dataset);
                    self.ml_forests.insert(sample.key.clone(), forest);
                    *updates = 0;
                }
            }

            if let Some(forest) = self.ml_forests.get(&sample.key) {
                if (sample.value - stats.median).abs() < 1e-9 {
                    ml_score = 0.0;
                } else {
                    ml_score = forest.predict(sample.value);
                }
            }

            let ml_verdict = DetectorVerdict {
                detector_type: DetectorType::IsolationForest,
                metric_key: sample.key.clone(),
                score: ml_score,
                observed_value: sample.value,
                expected_value: stats.median,
                threshold: self.config.anomaly_threshold,
                deviation: ml_score,
                baseline_stats: stats.clone(),
                explanation: format!(
                    "Isolation Forest ML score is {:.3} (ensemble weight={:.2})",
                    ml_score, self.config.ml_weight
                ),
            };
            verdicts.push(ml_verdict);

            // Holt's Linear Trend / Double Exponential Smoothing
            let mut trend_score = 0.0;
            let mut time_to_impact_mins: Option<f64> = None;
            let mut time_to_impact_secs: Option<u64> = None;
            let mut trend_confidence = 0.5;

            let (threshold, metric_label, is_lower_bound) = match sample.key.metric_name.as_str() {
                "latency_us" => (15000.0, "Path Latency", false),
                "packet_loss_pct" => (10.0, "Packet Loss", false),
                "utilization_pct" => (85.0, "Link Utilization", false),
                "crc_errors" => (100.0, "CRC Errors", false),
                "in_errors" => (50.0, "Inbound Interface Errors", false),
                "out_errors" => (50.0, "Outbound Interface Errors", false),
                "affected_prefixes" => (500.0, "BGP Prefix Count", false),
                "reroute_count" => (10.0, "Active LSP Reroutes", false),
                "lsa_count" => (200.0, "OSPF LSA Flood", false),
                "snr_db" | "ebno_db" => (6.0, "Receiver Link SNR", true),
                _ => (0.0, "Metric", false), // 0.0 means not monitored for trend
            };

            let vals = window.values();
            if threshold > 0.0 && vals.len() >= 15 {
                // alpha = 0.3, beta = 0.1, forecast 10 steps ahead
                if let Some((_level, trend_slope, forecast)) =
                    calculate_holt_trend(&vals, 0.3, 0.1, 10)
                {
                    let current = sample.value;
                    if is_lower_bound {
                        if forecast < threshold {
                            trend_score = 1.0;
                        } else if current > threshold {
                            let range = current - threshold;
                            if range > 1e-9 {
                                trend_score =
                                    ((current - forecast).max(0.0) / range).clamp(0.0, 1.0);
                            }
                        } else {
                            trend_score = 1.0;
                        }
                    } else {
                        if forecast > threshold {
                            trend_score = 1.0;
                        } else if current < threshold {
                            let range = threshold - current;
                            if range > 1e-9 {
                                trend_score =
                                    ((forecast - current).max(0.0) / range).clamp(0.0, 1.0);
                            }
                        } else {
                            trend_score = 1.0;
                        }
                    }

                    // Time-to-Impact calculation based on trend slope (using a standard 5s polling interval)
                    let interval_secs = 5.0;
                    if is_lower_bound {
                        if trend_slope < -1e-5 && current > threshold {
                            let distance = current - threshold;
                            let est_intervals = distance / trend_slope.abs();
                            let secs = est_intervals * interval_secs;
                            time_to_impact_secs = Some(secs.round() as u64);
                            time_to_impact_mins = Some((secs / 60.0).round().max(1.0));
                        }
                    } else {
                        if trend_slope > 1e-5 && current < threshold {
                            let distance = threshold - current;
                            let est_intervals = distance / trend_slope;
                            let secs = est_intervals * interval_secs;
                            time_to_impact_secs = Some(secs.round() as u64);
                            time_to_impact_mins = Some((secs / 60.0).round().max(1.0));
                        }
                    }

                    // Confidence score from trend slope signal-to-noise ratio
                    let stddev = stats.stddev;
                    if stddev > 1e-9 {
                        let snr = trend_slope.abs() / stddev;
                        let base_conf = (snr / 2.0).clamp(0.5, 0.95);
                        let warmup = if vals.len() >= 20 {
                            1.0
                        } else {
                            vals.len() as f64 / 20.0
                        };
                        trend_confidence = base_conf * warmup;
                    } else {
                        trend_confidence = 0.8;
                    }
                }
            }

            // Find maximum critical spike from Z-Score, IQR, or Rate of Change
            let critical_spikes = verdicts
                .iter()
                .filter(|v| v.detector_type != DetectorType::IsolationForest)
                .map(|v| v.score)
                .fold(0.0, f64::max);

            // Weighted Ensemble Score:
            // final_score = max(critical_spikes, 0.4*trend_score + 0.3*ml_score + 0.3*stat_score)
            let ensemble_score = (critical_spikes)
                .max(0.4 * trend_score + 0.3 * ml_score + 0.3 * stat_score)
                .clamp(0.0, 1.0);

            if ensemble_score > max_composite_score {
                max_composite_score = ensemble_score;
                max_ml_score = ml_score;
                _max_stat_score = stat_score;
                max_trend_score = trend_score;

                if let Some(secs) = time_to_impact_secs {
                    min_time_to_impact_secs = Some(secs);
                }
                if let Some(mins) = time_to_impact_mins {
                    min_time_to_impact_mins = Some(mins);
                    predicted_breach_metric = Some(metric_label.to_string());
                }

                // Overall confidence combines detector agreement and trend confidence
                let agreement = 1.0 - (stat_score - ml_score).abs();
                overall_confidence = (0.5 * trend_confidence + 0.5 * agreement).clamp(0.0, 1.0);
            }

            all_verdicts.extend(verdicts);

            // Step 3: Update the window AFTER detection (so the current
            // value doesn't influence its own baseline).
            window.push(sample.value);
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
            time_to_impact_secs: min_time_to_impact_secs,
            time_to_impact_minutes: min_time_to_impact_mins,
            trend_score: max_trend_score,
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

/// Computes Double Exponential Smoothing (Holt's Linear Trend) over a slice of observations.
/// Returns the estimated level, trend, and the forecasted value at step `m`.
fn calculate_holt_trend(
    values: &[f64],
    alpha: f64,
    beta: f64,
    m: usize,
) -> Option<(f64, f64, f64)> {
    let n = values.len();
    if n < 2 {
        return None;
    }

    let mut level = values[0];
    let mut trend = values[1] - values[0];

    for &val in values.iter().skip(1) {
        let prev_level = level;
        level = alpha * val + (1.0 - alpha) * (level + trend);
        trend = beta * (level - prev_level) + (1.0 - beta) * trend;
    }

    let forecast = level + (m as f64) * trend;
    Some((level, trend, forecast))
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
