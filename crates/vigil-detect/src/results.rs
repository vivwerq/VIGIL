//! # Detection Results
//!
//! Structured output types for anomaly detection verdicts.
//! Every detection result includes a human-readable explanation
//! suitable for NOC operator consumption and LLM context injection.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use vigil_core::types::Severity;

use crate::features::MetricKey;
use crate::stats::WindowStats;

/// The final anomaly assessment for a telemetry event.
///
/// Aggregates verdicts from all active detectors into a single
/// score with actionable explanation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyReport {
    /// Unique ID for this detection result.
    pub id: Uuid,
    /// ID of the telemetry envelope that was analyzed.
    pub envelope_id: Uuid,
    /// When this analysis was performed.
    pub analyzed_at: DateTime<Utc>,
    /// The composite anomaly score (0.0 = normal, 1.0 = extreme anomaly).
    pub score: f64,
    /// The anomaly score computed by the Machine Learning (Isolation Forest) model.
    pub ml_score: f64,
    /// Confidence level of the anomaly classification (0.0 to 1.0).
    pub confidence: f64,
    /// Whether this event crossed the anomaly threshold.
    pub is_anomalous: bool,
    /// Severity classification based on score.
    pub severity: Severity,
    /// Individual detector verdicts that contributed to the score.
    pub verdicts: Vec<DetectorVerdict>,
    /// Human-readable summary of the anomaly (for NOC operators).
    pub explanation: String,
    /// Recommended actions.
    pub recommendations: Vec<String>,
    /// Estimated time in seconds until the anomalous trend leads to service degradation.
    #[serde(default)]
    pub time_to_impact_secs: Option<u64>,
    /// The metric name predicted to breach the critical threshold.
    #[serde(default)]
    pub predicted_breach_metric: Option<String>,
}

impl AnomalyReport {
    /// Classify severity from the anomaly score.
    pub fn classify_severity(score: f64) -> Severity {
        if score >= 0.9 {
            Severity::Critical
        } else if score >= 0.7 {
            Severity::High
        } else if score >= 0.5 {
            Severity::Medium
        } else if score >= 0.3 {
            Severity::Low
        } else {
            Severity::Info
        }
    }
}

/// A single detector's verdict on a specific metric.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectorVerdict {
    /// Which detector produced this verdict.
    pub detector_type: DetectorType,
    /// Which metric was analyzed.
    pub metric_key: MetricKey,
    /// The anomaly score from this detector (0.0–1.0).
    pub score: f64,
    /// The observed value.
    pub observed_value: f64,
    /// The expected value (baseline mean or median).
    pub expected_value: f64,
    /// The threshold that was exceeded (if anomalous).
    pub threshold: f64,
    /// How far the value deviated (Z-score, IQR multiplier, etc.).
    pub deviation: f64,
    /// Window statistics at the time of detection.
    pub baseline_stats: WindowStats,
    /// Human-readable explanation.
    pub explanation: String,
}

/// Types of anomaly detectors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DetectorType {
    /// Modified Z-Score detector (mean + stddev based).
    ZScore,
    /// IQR (Interquartile Range) detector — robust to outliers.
    Iqr,
    /// Rate-of-change detector (detects sudden jumps/drops).
    RateOfChange,
    /// Machine Learning Isolation Forest detector.
    IsolationForest,
}

impl std::fmt::Display for DetectorType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ZScore => write!(f, "Z-Score"),
            Self::Iqr => write!(f, "IQR"),
            Self::RateOfChange => write!(f, "Rate-of-Change"),
            Self::IsolationForest => write!(f, "Isolation Forest (ML)"),
        }
    }
}

/// Generate a human-readable explanation for a Z-Score verdict.
pub fn explain_zscore(
    metric_label: &str,
    observed: f64,
    mean: f64,
    stddev: f64,
    z_score: f64,
    unit: &str,
) -> String {
    let direction = if observed > mean { "above" } else { "below" };
    format!(
        "{} is {:.1}{} — {:.1}σ {} baseline (mean={:.1}{}, σ={:.1}{})",
        metric_label,
        observed,
        unit,
        z_score.abs(),
        direction,
        mean,
        unit,
        stddev,
        unit
    )
}

/// Generate a human-readable explanation for an IQR verdict.
pub fn explain_iqr(
    metric_label: &str,
    observed: f64,
    q1: f64,
    q3: f64,
    iqr: f64,
    unit: &str,
) -> String {
    let lower_fence = q1 - 1.5 * iqr;
    let upper_fence = q3 + 1.5 * iqr;
    if observed > upper_fence {
        format!(
            "{} is {:.1}{} — exceeds upper fence {:.1}{} (Q3={:.1}, IQR={:.1})",
            metric_label, observed, unit, upper_fence, unit, q3, iqr
        )
    } else if observed < lower_fence {
        format!(
            "{} is {:.1}{} — below lower fence {:.1}{} (Q1={:.1}, IQR={:.1})",
            metric_label, observed, unit, lower_fence, unit, q1, iqr
        )
    } else {
        format!(
            "{} is {:.1}{} — within IQR bounds [{:.1}, {:.1}]",
            metric_label, observed, unit, lower_fence, upper_fence
        )
    }
}

/// Generate a human-readable explanation for a rate-of-change verdict.
pub fn explain_rate_of_change(
    metric_label: &str,
    current: f64,
    previous: f64,
    pct_change: f64,
    unit: &str,
) -> String {
    let direction = if current > previous {
        "increase"
    } else {
        "decrease"
    };
    format!(
        "{} changed from {:.1}{} to {:.1}{} — {:.1}% {} in one interval",
        metric_label,
        previous,
        unit,
        current,
        unit,
        pct_change.abs(),
        direction
    )
}
