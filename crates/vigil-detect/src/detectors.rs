//! # Anomaly Detectors
//!
//! Individual detector implementations. Each detector analyzes a single
//! metric value against its sliding window baseline and produces a
//! `DetectorVerdict` with a score in [0.0, 1.0].
//!
//! ## Detector Descriptions
//!
//! ### Z-Score Detector
//! Measures how many standard deviations a value is from the window mean.
//! Maps |z| → [0, 1] using a sigmoid-like curve. Best for normally
//! distributed metrics (latency, bandwidth).
//!
//! ### IQR Detector  
//! Uses the 1.5×IQR fence rule (Tukey's method). Robust to non-normal
//! distributions and existing outliers in the baseline. Best for
//! error counts, packet loss, skewed metrics.
//!
//! ### Rate-of-Change Detector
//! Detects sudden jumps/drops between consecutive values. Catches
//! step-function anomalies that Z-score/IQR might miss during
//! gradual window drift.

use crate::features::MetricSample;
use crate::results::*;
use crate::stats::SlidingWindow;

/// Configuration for a Z-Score detector.
#[derive(Debug, Clone)]
pub struct ZScoreConfig {
    /// Z-score threshold for flagging anomalies.
    /// Typical: 2.0 (95%), 2.5 (99%), 3.0 (99.7%).
    pub threshold: f64,
    /// Minimum number of samples before detection activates.
    /// Too few samples = unreliable statistics.
    pub min_samples: usize,
}

impl Default for ZScoreConfig {
    fn default() -> Self {
        Self {
            threshold: 3.0,  // 3σ = 99.7% confidence
            min_samples: 30, // Statistical significance requires ≥30
        }
    }
}

/// Z-Score anomaly detector.
///
/// Computes: z = (x - μ) / σ
///
/// Maps the absolute z-score to [0, 1] using:
/// score = 1 - e^(-0.5 * max(0, |z| - threshold + 1)^2)
/// This gives 0 for normal values and approaches 1 for extreme outliers.
pub struct ZScoreDetector {
    config: ZScoreConfig,
}

impl ZScoreDetector {
    pub fn new(config: ZScoreConfig) -> Self {
        Self { config }
    }

    /// Analyze a metric sample against its sliding window baseline.
    ///
    /// Returns `None` if the window doesn't have enough samples yet.
    pub fn analyze(
        &self,
        sample: &MetricSample,
        window: &SlidingWindow,
    ) -> Option<DetectorVerdict> {
        if window.len() < self.config.min_samples {
            tracing::trace!(
                metric = %sample.key,
                samples = window.len(),
                needed = self.config.min_samples,
                "Z-Score detector: insufficient samples, skipping"
            );
            return None;
        }

        let stats = window.stats();
        let mean = stats.mean;
        let stddev = stats.stddev;

        // Guard against zero stddev (all values identical).
        // If stddev is near zero and the value differs at all, it's anomalous.
        if stddev < 1e-10 {
            if (sample.value - mean).abs() < 1e-10 {
                // Value matches the constant baseline — not anomalous.
                return Some(DetectorVerdict {
                    detector_type: DetectorType::ZScore,
                    metric_key: sample.key.clone(),
                    score: 0.0,
                    observed_value: sample.value,
                    expected_value: mean,
                    threshold: self.config.threshold,
                    deviation: 0.0,
                    baseline_stats: stats,
                    explanation: format!(
                        "{} is {:.1}{} — matches constant baseline",
                        sample.label, sample.value, sample.unit
                    ),
                });
            } else {
                // Value differs from a constant baseline — definitely anomalous.
                return Some(DetectorVerdict {
                    detector_type: DetectorType::ZScore,
                    metric_key: sample.key.clone(),
                    score: 1.0,
                    observed_value: sample.value,
                    expected_value: mean,
                    threshold: self.config.threshold,
                    deviation: f64::INFINITY,
                    baseline_stats: stats,
                    explanation: format!(
                        "{} is {:.1}{} — deviates from constant baseline of {:.1}{}",
                        sample.label, sample.value, sample.unit, mean, sample.unit
                    ),
                });
            }
        }

        let z_score = (sample.value - mean) / stddev;
        let abs_z = z_score.abs();

        // Map z-score to anomaly score [0, 1].
        // Below threshold → 0.
        // At threshold → ~0.39.
        // At 2× threshold → ~0.99.
        let score = if abs_z <= self.config.threshold - 1.0 {
            0.0
        } else {
            let exponent = -0.5 * (abs_z - self.config.threshold + 1.0).powi(2);
            1.0 - exponent.exp()
        };

        let explanation = explain_zscore(
            &sample.label,
            sample.value,
            mean,
            stddev,
            z_score,
            &sample.unit,
        );

        Some(DetectorVerdict {
            detector_type: DetectorType::ZScore,
            metric_key: sample.key.clone(),
            score,
            observed_value: sample.value,
            expected_value: mean,
            threshold: self.config.threshold,
            deviation: z_score,
            baseline_stats: stats,
            explanation,
        })
    }
}

// ─── IQR Detector ───────────────────────────────────────────────────────────

/// Configuration for an IQR detector.
#[derive(Debug, Clone)]
pub struct IqrConfig {
    /// IQR multiplier for fence calculation.
    /// 1.5 = standard outlier, 3.0 = extreme outlier.
    pub multiplier: f64,
    /// Minimum number of samples before detection activates.
    pub min_samples: usize,
}

impl Default for IqrConfig {
    fn default() -> Self {
        Self {
            multiplier: 1.5, // Standard Tukey fence
            min_samples: 20, // Need enough for meaningful quartiles
        }
    }
}

/// IQR (Interquartile Range) anomaly detector.
///
/// Uses Tukey's fence method:
/// - Lower fence = Q1 - k × IQR
/// - Upper fence = Q3 + k × IQR
///
/// Values outside the fences are anomalous. The score scales with
/// how far beyond the fence the value falls.
pub struct IqrDetector {
    config: IqrConfig,
}

impl IqrDetector {
    pub fn new(config: IqrConfig) -> Self {
        Self { config }
    }

    /// Analyze a metric sample against its sliding window baseline.
    pub fn analyze(
        &self,
        sample: &MetricSample,
        window: &SlidingWindow,
    ) -> Option<DetectorVerdict> {
        if window.len() < self.config.min_samples {
            return None;
        }

        let stats = window.stats();
        let q1 = stats.q1;
        let q3 = stats.q3;
        let iqr = stats.iqr;

        // Handle zero IQR (all values in the middle 50% are identical).
        if iqr < 1e-10 {
            let deviation = (sample.value - stats.median).abs();
            let score = if deviation < 1e-10 { 0.0 } else { 0.8 };
            return Some(DetectorVerdict {
                detector_type: DetectorType::Iqr,
                metric_key: sample.key.clone(),
                score,
                observed_value: sample.value,
                expected_value: stats.median,
                threshold: self.config.multiplier,
                deviation,
                baseline_stats: stats.clone(),
                explanation: format!(
                    "{} is {:.1}{} — IQR is near zero (median={:.1}{})",
                    sample.label, sample.value, sample.unit, stats.median, sample.unit
                ),
            });
        }

        let lower_fence = q1 - self.config.multiplier * iqr;
        let upper_fence = q3 + self.config.multiplier * iqr;

        // Calculate how far outside the fence the value is,
        // normalized by the IQR.
        let (deviation, is_outside) = if sample.value > upper_fence {
            ((sample.value - upper_fence) / iqr, true)
        } else if sample.value < lower_fence {
            ((lower_fence - sample.value) / iqr, true)
        } else {
            (0.0, false)
        };

        // Map deviation to score [0, 1].
        // 0 IQR outside → 0.0
        // 1 IQR outside → ~0.63
        // 2 IQR outside → ~0.86
        // 3 IQR outside → ~0.95
        let score = if is_outside {
            1.0 - (-deviation).exp()
        } else {
            0.0
        };

        let explanation = explain_iqr(&sample.label, sample.value, q1, q3, iqr, &sample.unit);

        Some(DetectorVerdict {
            detector_type: DetectorType::Iqr,
            metric_key: sample.key.clone(),
            score,
            observed_value: sample.value,
            expected_value: stats.median,
            threshold: self.config.multiplier,
            deviation,
            baseline_stats: stats,
            explanation,
        })
    }
}

// ─── Rate-of-Change Detector ────────────────────────────────────────────────

/// Configuration for a rate-of-change detector.
#[derive(Debug, Clone)]
pub struct RateOfChangeConfig {
    /// Percentage change threshold to flag as anomalous.
    /// 0.5 = 50% change, 1.0 = 100% change (doubling).
    pub pct_change_threshold: f64,
    /// Minimum absolute change to trigger (prevents noise on small values).
    pub min_absolute_change: f64,
    /// Minimum samples before activation.
    pub min_samples: usize,
}

impl Default for RateOfChangeConfig {
    fn default() -> Self {
        Self {
            pct_change_threshold: 0.5, // 50% change
            min_absolute_change: 1.0,  // Ignore tiny absolute changes
            min_samples: 5,            // Just need a few recent values
        }
    }
}

/// Rate-of-change detector.
///
/// Compares the current value to the previous value and flags
/// sudden jumps or drops that exceed the configured threshold.
/// This catches step-function anomalies that smooth baselines miss.
pub struct RateOfChangeDetector {
    config: RateOfChangeConfig,
}

impl RateOfChangeDetector {
    pub fn new(config: RateOfChangeConfig) -> Self {
        Self { config }
    }

    /// Analyze the rate of change between the current value and the
    /// previous value in the sliding window.
    pub fn analyze(
        &self,
        sample: &MetricSample,
        window: &SlidingWindow,
    ) -> Option<DetectorVerdict> {
        if window.len() < self.config.min_samples {
            return None;
        }

        let previous = window.latest()?;
        let stats = window.stats();

        // Calculate percentage change.
        let abs_change = (sample.value - previous).abs();

        // Skip if the absolute change is below noise threshold.
        if abs_change < self.config.min_absolute_change {
            return Some(DetectorVerdict {
                detector_type: DetectorType::RateOfChange,
                metric_key: sample.key.clone(),
                score: 0.0,
                observed_value: sample.value,
                expected_value: previous,
                threshold: self.config.pct_change_threshold,
                deviation: 0.0,
                baseline_stats: stats,
                explanation: format!(
                    "{} is {:.1}{} — minimal change from {:.1}{}",
                    sample.label, sample.value, sample.unit, previous, sample.unit
                ),
            });
        }

        // Use max(|previous|, 1.0) as denominator to avoid division by zero.
        let denominator = previous.abs().max(1.0);
        let pct_change = abs_change / denominator;

        // Map to score: 0 at threshold, approaching 1 at 3× threshold.
        let score = if pct_change <= self.config.pct_change_threshold {
            0.0
        } else {
            let excess = pct_change / self.config.pct_change_threshold - 1.0;
            1.0 - (-excess).exp()
        };

        let explanation = explain_rate_of_change(
            &sample.label,
            sample.value,
            previous,
            pct_change * 100.0,
            &sample.unit,
        );

        Some(DetectorVerdict {
            detector_type: DetectorType::RateOfChange,
            metric_key: sample.key.clone(),
            score,
            observed_value: sample.value,
            expected_value: previous,
            threshold: self.config.pct_change_threshold,
            deviation: pct_change,
            baseline_stats: stats,
            explanation,
        })
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::features::MetricKey;
    use chrono::Utc;

    fn make_sample(value: f64) -> MetricSample {
        MetricSample {
            key: MetricKey::new("test-rtr", "LSP", "latency_us"),
            value,
            timestamp: Utc::now(),
            label: "Test latency".into(),
            unit: "μs".into(),
        }
    }

    fn build_baseline(values: &[f64], capacity: usize) -> SlidingWindow {
        let mut window = SlidingWindow::new(capacity);
        for &v in values {
            window.push(v);
        }
        window
    }

    // ── Z-Score tests ───────────────────────────────────────────────────

    #[test]
    fn zscore_normal_value_scores_zero() {
        let detector = ZScoreDetector::new(ZScoreConfig::default());
        // Build a baseline around 100 with stddev ~5
        let baseline: Vec<f64> = (0..50).map(|i| 100.0 + (i % 10) as f64 - 5.0).collect();
        let window = build_baseline(&baseline, 100);

        let sample = make_sample(102.0); // Within 1σ
        let verdict = detector.analyze(&sample, &window).unwrap();
        assert!(
            verdict.score < 0.1,
            "Normal value should score near 0, got {}",
            verdict.score
        );
    }

    #[test]
    fn zscore_extreme_value_scores_high() {
        let detector = ZScoreDetector::new(ZScoreConfig::default());
        let baseline: Vec<f64> = (0..50).map(|i| 100.0 + (i % 10) as f64 - 5.0).collect();
        let window = build_baseline(&baseline, 100);

        let sample = make_sample(200.0); // ~20σ above mean
        let verdict = detector.analyze(&sample, &window).unwrap();
        assert!(
            verdict.score > 0.9,
            "Extreme value should score near 1, got {}",
            verdict.score
        );
    }

    #[test]
    fn zscore_insufficient_samples_returns_none() {
        let detector = ZScoreDetector::new(ZScoreConfig {
            min_samples: 30,
            ..Default::default()
        });
        let window = build_baseline(&[1.0, 2.0, 3.0], 100);
        let sample = make_sample(100.0);
        assert!(detector.analyze(&sample, &window).is_none());
    }

    // ── IQR tests ───────────────────────────────────────────────────────

    #[test]
    fn iqr_normal_value_scores_zero() {
        let detector = IqrDetector::new(IqrConfig::default());
        let baseline: Vec<f64> = (0..50).map(|i| 50.0 + (i % 20) as f64).collect();
        let window = build_baseline(&baseline, 100);

        let sample = make_sample(55.0); // Well within IQR
        let verdict = detector.analyze(&sample, &window).unwrap();
        assert_eq!(verdict.score, 0.0, "Value within fences should score 0");
    }

    #[test]
    fn iqr_extreme_value_scores_high() {
        let detector = IqrDetector::new(IqrConfig::default());
        let baseline: Vec<f64> = (0..50).map(|i| 50.0 + (i % 20) as f64).collect();
        let window = build_baseline(&baseline, 100);

        let sample = make_sample(500.0); // Way above upper fence
        let verdict = detector.analyze(&sample, &window).unwrap();
        assert!(
            verdict.score > 0.9,
            "Extreme outlier should score near 1, got {}",
            verdict.score
        );
    }

    // ── Rate-of-Change tests ────────────────────────────────────────────

    #[test]
    fn roc_small_change_scores_zero() {
        let detector = RateOfChangeDetector::new(RateOfChangeConfig::default());
        let window = build_baseline(&[100.0, 101.0, 99.0, 100.0, 102.0], 100);

        let sample = make_sample(103.0); // ~1% change from 102
        let verdict = detector.analyze(&sample, &window).unwrap();
        assert_eq!(verdict.score, 0.0);
    }

    #[test]
    fn roc_large_jump_scores_high() {
        let detector = RateOfChangeDetector::new(RateOfChangeConfig::default());
        let window = build_baseline(&[100.0, 101.0, 99.0, 100.0, 102.0], 100);

        let sample = make_sample(500.0); // ~390% change from 102
        let verdict = detector.analyze(&sample, &window).unwrap();
        assert!(
            verdict.score > 0.9,
            "Large jump should score high, got {}",
            verdict.score
        );
    }
}
