//! # VIGIL Error Hierarchy
//!
//! Unified error types for the entire VIGIL system.
//! Every error is:
//! - Typed (no stringly-typed errors)
//! - Traceable (includes context about what went wrong and where)
//! - Non-panicking (we handle errors, never panic in production)
//!
//! ## Design Decisions
//!
//! We use `thiserror` for library errors (typed, composable) and reserve
//! `anyhow` for the binary entry point only. This ensures that library
//! consumers always get structured errors they can match on.

use thiserror::Error;

/// Convenience type alias used throughout all VIGIL crates.
pub type VigilResult<T> = Result<T, VigilError>;

/// Top-level error enum for the VIGIL system.
///
/// Each variant maps to a specific failure domain. This allows upstream
/// code to match on error categories and take appropriate action
/// (e.g., rate-limit on `InputValidation`, alert on `CryptoVerification`).
#[derive(Debug, Error)]
pub enum VigilError {
    // ── Ingestion Errors ──────────────────────────────────────────────
    /// Telemetry payload failed HMAC-SHA256 verification.
    /// This is a HIGH SEVERITY event — potential data tampering.
    #[error("HMAC verification failed for source '{origin}': {reason}")]
    CryptoVerification { origin: String, reason: String },

    /// Input data failed validation (too large, malformed, etc.).
    #[error("Input validation failed: {field} — {reason}")]
    InputValidation { field: String, reason: String },

    /// Telemetry payload could not be parsed.
    #[error("Parse error for protocol {protocol}: {reason}")]
    ParseError { protocol: String, reason: String },

    /// A telemetry event arrived with a timestamp too far in the past or future.
    #[error("Stale event rejected: age={age_seconds}s, max={max_seconds}s from source '{origin}'")]
    StaleEvent {
        origin: String,
        age_seconds: i64,
        max_seconds: i64,
    },

    /// Rate limit exceeded for a specific source.
    #[error("Rate limit exceeded for source '{origin}': {events_per_second} events/s")]
    RateLimitExceeded {
        origin: String,
        events_per_second: f64,
    },

    // ── Storage Errors ────────────────────────────────────────────────
    /// Database operation failed.
    #[error("Database error: {operation} — {reason}")]
    DatabaseError { operation: String, reason: String },

    // ── Detection Errors ──────────────────────────────────────────────
    /// Anomaly detection model failed.
    #[error("Detection engine error: {reason}")]
    DetectionError { reason: String },

    // ── LLM Errors ────────────────────────────────────────────────────
    /// LLM inference failed.
    #[error("LLM inference error: {reason}")]
    LlmError { reason: String },

    // ── Configuration Errors ──────────────────────────────────────────
    /// Configuration is invalid or missing.
    #[error("Configuration error: {reason}")]
    ConfigError { reason: String },

    // ── Generic/Internal Errors ───────────────────────────────────────
    /// Internal error that should never happen. If it does, it's a bug.
    #[error("Internal error (this is a bug, please report): {reason}")]
    InternalError { reason: String },

    /// Channel send/receive error in the async pipeline.
    #[error("Pipeline channel error: {reason}")]
    ChannelError { reason: String },

    /// I/O error wrapper.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// JSON serialization/deserialization error wrapper.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

impl VigilError {
    /// Returns the severity level of this error for alerting purposes.
    /// Critical errors should trigger immediate operator notification.
    pub fn severity(&self) -> ErrorSeverity {
        match self {
            // Crypto failures are ALWAYS critical — potential tampering
            Self::CryptoVerification { .. } => ErrorSeverity::Critical,
            // Rate limiting and stale events are warnings
            Self::RateLimitExceeded { .. } | Self::StaleEvent { .. } => ErrorSeverity::Warning,
            // Parse errors could be attacks or just malformed data
            Self::ParseError { .. } | Self::InputValidation { .. } => ErrorSeverity::High,
            // Internal errors are critical — they indicate bugs
            Self::InternalError { .. } => ErrorSeverity::Critical,
            // Everything else is medium
            _ => ErrorSeverity::Medium,
        }
    }

    /// Returns true if this error should trigger a security alert.
    pub fn is_security_event(&self) -> bool {
        matches!(
            self,
            Self::CryptoVerification { .. }
                | Self::RateLimitExceeded { .. }
                | Self::InputValidation { .. }
        )
    }
}

/// Severity levels for error classification and alerting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ErrorSeverity {
    Low,
    Medium,
    High,
    Warning,
    Critical,
}

impl std::fmt::Display for ErrorSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Low => write!(f, "LOW"),
            Self::Medium => write!(f, "MEDIUM"),
            Self::High => write!(f, "HIGH"),
            Self::Warning => write!(f, "WARNING"),
            Self::Critical => write!(f, "CRITICAL"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crypto_errors_are_critical() {
        let err = VigilError::CryptoVerification {
            origin: "router-01".into(),
            reason: "HMAC mismatch".into(),
        };
        assert_eq!(err.severity(), ErrorSeverity::Critical);
        assert!(err.is_security_event());
    }

    #[test]
    fn internal_errors_are_critical() {
        let err = VigilError::InternalError {
            reason: "unexpected state".into(),
        };
        assert_eq!(err.severity(), ErrorSeverity::Critical);
    }

    #[test]
    fn error_display_is_informative() {
        let err = VigilError::ParseError {
            protocol: "BGP".into(),
            reason: "invalid AS path length".into(),
        };
        let msg = err.to_string();
        assert!(msg.contains("BGP"));
        assert!(msg.contains("AS path"));
    }
}
