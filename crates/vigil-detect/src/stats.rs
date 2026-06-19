//! # Online Statistics & Sliding Window
//!
//! Memory-efficient, numerically stable statistical primitives for
//! streaming telemetry data.
//!
//! ## Design Decisions
//!
//! - **Welford's algorithm** for online mean/variance — numerically stable
//!   even with millions of samples (no catastrophic cancellation).
//! - **Ring buffer** for sliding window — O(1) insert, bounded memory.
//! - **Sorted insert** for IQR — maintains a sorted copy for percentile queries.
//!
//! ## Security
//!
//! - All buffers are bounded (max `window_size` elements).
//! - No heap allocations beyond the initial window allocation.
//! - NaN/Inf values are rejected at insertion time.

use serde::{Deserialize, Serialize};

// ─── Welford's Online Statistics ────────────────────────────────────────────

/// Tracks running mean and variance using Welford's online algorithm.
///
/// This is numerically stable even for very large sample counts, unlike
/// the naive "sum of squares minus square of sums" approach which suffers
/// from catastrophic cancellation with floating-point arithmetic.
///
/// Reference: Welford, B. P. (1962). "Note on a method for calculating
/// corrected sums of squares and products."
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WelfordAccumulator {
    /// Number of samples seen.
    count: u64,
    /// Running mean.
    mean: f64,
    /// Running M2 (sum of squared deviations from the mean).
    /// Variance = M2 / (count - 1) for sample variance.
    m2: f64,
    /// Minimum value seen.
    min: f64,
    /// Maximum value seen.
    max: f64,
}

impl WelfordAccumulator {
    /// Create a new empty accumulator.
    pub fn new() -> Self {
        Self {
            count: 0,
            mean: 0.0,
            m2: 0.0,
            min: f64::INFINITY,
            max: f64::NEG_INFINITY,
        }
    }

    /// Add a new sample to the running statistics.
    ///
    /// Returns `false` if the value is NaN/Inf (rejected for safety).
    pub fn update(&mut self, value: f64) -> bool {
        if !value.is_finite() {
            return false;
        }

        self.count += 1;
        let delta = value - self.mean;
        self.mean += delta / self.count as f64;
        let delta2 = value - self.mean;
        self.m2 += delta * delta2;

        if value < self.min {
            self.min = value;
        }
        if value > self.max {
            self.max = value;
        }

        true
    }

    /// Current sample count.
    pub fn count(&self) -> u64 {
        self.count
    }

    /// Current mean. Returns 0.0 if no samples.
    pub fn mean(&self) -> f64 {
        if self.count == 0 { 0.0 } else { self.mean }
    }

    /// Population variance. Returns 0.0 if fewer than 2 samples.
    pub fn variance(&self) -> f64 {
        if self.count < 2 {
            0.0
        } else {
            self.m2 / self.count as f64
        }
    }

    /// Sample variance (Bessel's correction). Returns 0.0 if fewer than 2 samples.
    pub fn sample_variance(&self) -> f64 {
        if self.count < 2 {
            0.0
        } else {
            self.m2 / (self.count - 1) as f64
        }
    }

    /// Standard deviation (population). Returns 0.0 if fewer than 2 samples.
    pub fn stddev(&self) -> f64 {
        self.variance().sqrt()
    }

    /// Sample standard deviation. Returns 0.0 if fewer than 2 samples.
    pub fn sample_stddev(&self) -> f64 {
        self.sample_variance().sqrt()
    }

    /// Minimum value seen. Returns `f64::INFINITY` if no samples.
    pub fn min(&self) -> f64 {
        self.min
    }

    /// Maximum value seen. Returns `f64::NEG_INFINITY` if no samples.
    pub fn max(&self) -> f64 {
        self.max
    }
}

impl Default for WelfordAccumulator {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Sliding Window Ring Buffer ─────────────────────────────────────────────

/// A bounded ring buffer that maintains a sliding window of the most
/// recent `capacity` values. When full, the oldest value is overwritten.
///
/// Also maintains a sorted copy of the window for efficient percentile
/// (IQR) calculations.
///
/// ## Memory Layout
///
/// ```text
/// Ring buffer:  [v4, v5, v6, v7, v8, v1, v2, v3]
///                    ^head                ^oldest
/// Sorted copy: [v1, v2, v3, v4, v5, v6, v7, v8]
///               Q1 ^          median ^       ^ Q3
/// ```
#[derive(Debug, Clone)]
pub struct SlidingWindow {
    /// Ring buffer of raw values in insertion order.
    buffer: Vec<f64>,
    /// Current insertion position (wraps around).
    head: usize,
    /// Number of values currently stored (≤ capacity).
    len: usize,
    /// Maximum number of values to store.
    capacity: usize,
    /// Sorted copy of the window for percentile calculations.
    /// Maintained incrementally on each insert.
    sorted: Vec<f64>,
    /// Running Welford accumulator for the window.
    /// Note: this tracks ALL-TIME stats, not just window stats.
    /// Window-specific stats are computed from the sorted buffer.
    welford: WelfordAccumulator,
}

impl SlidingWindow {
    /// Create a new sliding window with the given capacity.
    ///
    /// # Panics
    ///
    /// Panics if `capacity` is 0. A zero-size window is meaningless.
    pub fn new(capacity: usize) -> Self {
        assert!(capacity > 0, "SlidingWindow capacity must be > 0");
        Self {
            buffer: Vec::with_capacity(capacity),
            head: 0,
            len: 0,
            capacity,
            sorted: Vec::with_capacity(capacity),
            welford: WelfordAccumulator::new(),
        }
    }

    /// Push a new value into the window.
    ///
    /// If the window is full, the oldest value is evicted.
    /// Returns `false` if the value is NaN/Inf (rejected).
    pub fn push(&mut self, value: f64) -> bool {
        if !value.is_finite() {
            return false;
        }

        self.welford.update(value);

        if self.len < self.capacity {
            // Window not yet full — just append.
            self.buffer.push(value);
            // Insert into sorted vec maintaining sort order.
            let insert_pos = self.sorted.partition_point(|&x| x < value);
            self.sorted.insert(insert_pos, value);
            self.len += 1;
        } else {
            // Window full — evict oldest and insert new.
            let evicted = self.buffer[self.head];

            // Remove evicted value from sorted vec.
            if let Ok(pos) = self
                .sorted
                .binary_search_by(|x| x.partial_cmp(&evicted).unwrap_or(std::cmp::Ordering::Equal))
            {
                self.sorted.remove(pos);
            }

            // Insert new value into sorted vec.
            let insert_pos = self.sorted.partition_point(|&x| x < value);
            self.sorted.insert(insert_pos, value);

            // Overwrite oldest in ring buffer.
            self.buffer[self.head] = value;
        }

        // Advance head (ring buffer wrap).
        self.head = (self.head + 1) % self.capacity;

        true
    }

    /// Number of values currently in the window.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether the window is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Whether the window has reached capacity (baseline is "warmed up").
    pub fn is_warmed_up(&self) -> bool {
        self.len == self.capacity
    }

    /// Compute the mean of values currently in the window.
    pub fn mean(&self) -> f64 {
        if self.len == 0 {
            return 0.0;
        }
        self.sorted.iter().sum::<f64>() / self.len as f64
    }

    /// Compute the variance of values in the window.
    pub fn variance(&self) -> f64 {
        if self.len < 2 {
            return 0.0;
        }
        let mean = self.mean();
        let sum_sq: f64 = self.sorted.iter().map(|x| (x - mean).powi(2)).sum();
        sum_sq / (self.len - 1) as f64
    }

    /// Compute the standard deviation of values in the window.
    pub fn stddev(&self) -> f64 {
        self.variance().sqrt()
    }

    /// Get a specific percentile (0.0–1.0) from the sorted window.
    ///
    /// Uses linear interpolation between adjacent values.
    pub fn percentile(&self, p: f64) -> f64 {
        if self.len == 0 {
            return 0.0;
        }
        if self.len == 1 {
            return self.sorted[0];
        }

        let p = p.clamp(0.0, 1.0);
        let index = p * (self.len - 1) as f64;
        let lower = index.floor() as usize;
        let upper = index.ceil() as usize;
        let fraction = index - lower as f64;

        if lower == upper {
            self.sorted[lower]
        } else {
            self.sorted[lower] * (1.0 - fraction) + self.sorted[upper] * fraction
        }
    }

    /// Compute Q1 (25th percentile).
    pub fn q1(&self) -> f64 {
        self.percentile(0.25)
    }

    /// Compute the median (50th percentile).
    pub fn median(&self) -> f64 {
        self.percentile(0.50)
    }

    /// Compute Q3 (75th percentile).
    pub fn q3(&self) -> f64 {
        self.percentile(0.75)
    }

    /// Compute the Interquartile Range (Q3 - Q1).
    pub fn iqr(&self) -> f64 {
        self.q3() - self.q1()
    }

    /// Get the minimum value in the window.
    pub fn min(&self) -> f64 {
        self.sorted.first().copied().unwrap_or(0.0)
    }

    /// Get the maximum value in the window.
    pub fn max(&self) -> f64 {
        self.sorted.last().copied().unwrap_or(0.0)
    }

    /// Compute full window statistics snapshot.
    pub fn stats(&self) -> WindowStats {
        WindowStats {
            count: self.len,
            mean: self.mean(),
            stddev: self.stddev(),
            variance: self.variance(),
            min: self.min(),
            max: self.max(),
            median: self.median(),
            q1: self.q1(),
            q3: self.q3(),
            iqr: self.iqr(),
            warmed_up: self.is_warmed_up(),
        }
    }

    /// Get the most recently inserted value.
    pub fn latest(&self) -> Option<f64> {
        if self.len == 0 {
            return None;
        }
        let idx = if self.head == 0 {
            self.len - 1
        } else {
            self.head - 1
        };
        Some(self.buffer[idx])
    }

    /// Get the all-time Welford accumulator (not window-bounded).
    pub fn all_time_stats(&self) -> &WelfordAccumulator {
        &self.welford
    }

    /// Get a copy of all values currently in the window (in chronological order).
    pub fn values(&self) -> Vec<f64> {
        if self.len == 0 {
            return Vec::new();
        }
        if self.len < self.capacity {
            self.buffer.clone()
        } else {
            let mut ordered = Vec::with_capacity(self.capacity);
            ordered.extend_from_slice(&self.buffer[self.head..]);
            ordered.extend_from_slice(&self.buffer[..self.head]);
            ordered
        }
    }
}

/// Snapshot of statistical properties for a sliding window at a point in time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowStats {
    /// Number of samples in the window.
    pub count: usize,
    /// Arithmetic mean.
    pub mean: f64,
    /// Standard deviation.
    pub stddev: f64,
    /// Variance.
    pub variance: f64,
    /// Minimum value.
    pub min: f64,
    /// Maximum value.
    pub max: f64,
    /// Median (50th percentile).
    pub median: f64,
    /// First quartile (25th percentile).
    pub q1: f64,
    /// Third quartile (75th percentile).
    pub q3: f64,
    /// Interquartile range (Q3 - Q1).
    pub iqr: f64,
    /// Whether the window has reached full capacity.
    pub warmed_up: bool,
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Welford tests ───────────────────────────────────────────────────

    #[test]
    fn welford_single_value() {
        let mut acc = WelfordAccumulator::new();
        acc.update(42.0);
        assert_eq!(acc.count(), 1);
        assert!((acc.mean() - 42.0).abs() < 1e-10);
        assert_eq!(acc.variance(), 0.0);
    }

    #[test]
    fn welford_known_values() {
        // Mean of [2, 4, 4, 4, 5, 5, 7, 9] = 5.0
        // Population variance = 4.0, stddev = 2.0
        let mut acc = WelfordAccumulator::new();
        for v in [2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0] {
            acc.update(v);
        }
        assert_eq!(acc.count(), 8);
        assert!((acc.mean() - 5.0).abs() < 1e-10);
        assert!((acc.variance() - 4.0).abs() < 1e-10);
        assert!((acc.stddev() - 2.0).abs() < 1e-10);
        assert!((acc.min() - 2.0).abs() < 1e-10);
        assert!((acc.max() - 9.0).abs() < 1e-10);
    }

    #[test]
    fn welford_rejects_nan() {
        let mut acc = WelfordAccumulator::new();
        assert!(acc.update(1.0));
        assert!(!acc.update(f64::NAN));
        assert!(!acc.update(f64::INFINITY));
        assert_eq!(acc.count(), 1); // Only the valid value counted
    }

    #[test]
    fn welford_numerical_stability() {
        // Test with large values that would cause catastrophic cancellation
        // in naive implementations.
        let mut acc = WelfordAccumulator::new();
        let base = 1e9;
        for i in 0..1000 {
            acc.update(base + i as f64);
        }
        // Mean should be base + 499.5
        assert!((acc.mean() - (base + 499.5)).abs() < 1e-6);
        // Variance of 0..999 = (1000^2 - 1) / 12 = 83333.25
        assert!((acc.variance() - 83333.25).abs() < 1.0);
    }

    // ── Sliding window tests ────────────────────────────────────────────

    #[test]
    fn window_basic_operations() {
        let mut win = SlidingWindow::new(5);
        assert!(win.is_empty());
        assert!(!win.is_warmed_up());

        for v in [1.0, 2.0, 3.0, 4.0, 5.0] {
            win.push(v);
        }
        assert_eq!(win.len(), 5);
        assert!(win.is_warmed_up());
        assert!((win.mean() - 3.0).abs() < 1e-10);
    }

    #[test]
    fn window_eviction() {
        let mut win = SlidingWindow::new(3);
        win.push(10.0);
        win.push(20.0);
        win.push(30.0);
        assert!((win.mean() - 20.0).abs() < 1e-10);

        // Push a new value — oldest (10.0) should be evicted
        win.push(40.0);
        assert_eq!(win.len(), 3);
        // Window now: [20, 30, 40], mean = 30
        assert!((win.mean() - 30.0).abs() < 1e-10);
    }

    #[test]
    fn window_percentiles() {
        let mut win = SlidingWindow::new(100);
        // Push 1..=100
        for i in 1..=100 {
            win.push(i as f64);
        }

        // Median of 1..100 ≈ 50.5
        assert!((win.median() - 50.5).abs() < 1.0);
        // Q1 ≈ 25.75, Q3 ≈ 75.25
        assert!((win.q1() - 25.75).abs() < 1.0);
        assert!((win.q3() - 75.25).abs() < 1.0);
        // IQR ≈ 49.5
        assert!((win.iqr() - 49.5).abs() < 1.0);
    }

    #[test]
    fn window_rejects_nan() {
        let mut win = SlidingWindow::new(10);
        assert!(win.push(1.0));
        assert!(!win.push(f64::NAN));
        assert_eq!(win.len(), 1);
    }

    #[test]
    fn window_latest_value() {
        let mut win = SlidingWindow::new(5);
        win.push(1.0);
        win.push(2.0);
        win.push(3.0);
        assert_eq!(win.latest(), Some(3.0));
    }

    #[test]
    fn window_stats_snapshot() {
        let mut win = SlidingWindow::new(10);
        for v in [2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0] {
            win.push(v);
        }
        let stats = win.stats();
        assert_eq!(stats.count, 8);
        assert!((stats.mean - 5.0).abs() < 1e-10);
        assert!((stats.min - 2.0).abs() < 1e-10);
        assert!((stats.max - 9.0).abs() < 1e-10);
        assert!(!stats.warmed_up); // Window capacity is 10, only 8 values
    }

    #[test]
    #[should_panic(expected = "capacity must be > 0")]
    fn zero_capacity_panics() {
        SlidingWindow::new(0);
    }
}
