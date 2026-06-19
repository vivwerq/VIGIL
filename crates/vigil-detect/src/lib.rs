//! # VIGIL Anomaly Detection Engine
//!
//! Statistical anomaly detection using multiple complementary methods:
//!
//! - **Z-Score**: Detects values deviating significantly from the mean.
//!   Assumes approximately normal distribution. Best for: latency, jitter,
//!   bandwidth utilization.
//!
//! - **IQR (Interquartile Range)**: Robust to outliers and skewed distributions.
//!   Uses the 1.5×IQR rule (or configurable multiplier). Best for: error counts,
//!   packet loss, prefix counts.
//!
//! - **Sliding Window Baselines**: All statistics are computed over a bounded
//!   rolling window, so the system adapts to gradual changes in network behavior
//!   while still detecting sudden deviations.
//!
//! ## Architecture
//!
//! ```text
//! TelemetryEnvelope
//!       │
//!       ▼
//! ┌─────────────┐
//! │  Feature     │  Extract numerical features from typed events
//! │  Extraction  │  (e.g., latency_us, utilization_pct, error_rate)
//! └──────┬──────┘
//!        │  Vec<MetricSample>
//!        ▼
//! ┌─────────────┐
//! │  Sliding     │  Maintain per-metric rolling statistics
//! │  Window      │  (mean, variance, quartiles) per source+metric
//! └──────┬──────┘
//!        │  WindowStats
//!        ▼
//! ┌─────────────┐
//! │  Detectors   │  Z-Score + IQR + Rate-of-Change
//! │  (parallel)  │  Each produces an anomaly score [0.0, 1.0]
//! └──────┬──────┘
//!        │  Vec<DetectorVerdict>
//!        ▼
//! ┌─────────────┐
//! │  Scoring     │  Weighted combination → final AnomalyScore
//! │  Engine      │  with human-readable explanation
//! └─────────────┘
//! ```

pub mod detectors;
pub mod engine;
pub mod features;
pub mod ml;
pub mod results;
pub mod stats;
