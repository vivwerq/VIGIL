//! # VIGIL Configuration
//!
//! Typed, validated configuration for all VIGIL subsystems.
//! Configuration is loaded from a TOML file at startup and is immutable
//! for the lifetime of the process. No hot-reloading — config changes
//! require a restart (intentional for auditability).

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

use crate::error::{VigilError, VigilResult};

/// Top-level VIGIL configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VigilConfig {
    /// Ingestion pipeline configuration.
    pub ingestion: IngestionConfig,
    /// Storage configuration.
    pub storage: StorageConfig,
    /// Detection engine configuration.
    pub detection: DetectionConfig,
    /// LLM copilot configuration.
    pub llm: LlmConfig,
    /// Per-source HMAC keys (hex-encoded).
    /// Key: source identifier, Value: hex-encoded HMAC key.
    pub hmac_keys: HashMap<String, String>,
}

/// Configuration for the telemetry ingestion pipeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngestionConfig {
    /// Maximum events per second before rate limiting kicks in.
    pub max_events_per_second: u64,
    /// Channel buffer size for the async pipeline.
    pub channel_capacity: usize,
    /// Maximum age of events to accept (seconds).
    pub max_event_age_seconds: i64,
    /// Whether to enforce HMAC verification (should ALWAYS be true in production).
    pub enforce_hmac: bool,
    /// Bind address for telemetry receiver (e.g., "0.0.0.0:9514").
    pub bind_address: String,
}

/// Configuration for the embedded database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    /// Path to the redb database file.
    pub db_path: PathBuf,
    /// Maximum database size in bytes.
    pub max_db_size_bytes: u64,
    /// Compaction interval in seconds.
    pub compaction_interval_secs: u64,
}

/// Configuration for the anomaly detection engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionConfig {
    /// Path to the ONNX model file.
    pub model_path: PathBuf,
    /// Anomaly score threshold (0.0–1.0). Events above this are flagged.
    pub anomaly_threshold: f64,
    /// Window size for feature extraction.
    pub window_size: usize,
}

/// Configuration for the LLM copilot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmConfig {
    /// Path to the GGUF model file.
    pub model_path: PathBuf,
    /// Maximum tokens to generate per response.
    pub max_tokens: usize,
    /// Temperature for generation (0.0 = deterministic).
    pub temperature: f32,
    /// Number of CPU threads for inference.
    pub n_threads: usize,
}

impl Default for LlmConfig {
    fn default() -> Self {
        Self {
            model_path: PathBuf::from("/var/lib/vigil/models/mistral-7b-q4.gguf"),
            max_tokens: 512,
            temperature: 0.1,
            n_threads: 4,
        }
    }
}

impl Default for VigilConfig {
    fn default() -> Self {
        Self {
            ingestion: IngestionConfig {
                max_events_per_second: 1000,
                channel_capacity: 10_000,
                max_event_age_seconds: 300,
                enforce_hmac: true,
                bind_address: "127.0.0.1:9514".to_string(),
            },
            storage: StorageConfig {
                db_path: PathBuf::from("/var/lib/vigil/telemetry.redb"),
                max_db_size_bytes: 10 * 1024 * 1024 * 1024, // 10 GiB
                compaction_interval_secs: 3600,
            },
            detection: DetectionConfig {
                model_path: PathBuf::from("/var/lib/vigil/models/anomaly.onnx"),
                anomaly_threshold: 0.85,
                window_size: 1000,
            },
            llm: LlmConfig {
                model_path: PathBuf::from("/var/lib/vigil/models/mistral-7b-q4.gguf"),
                max_tokens: 512,
                temperature: 0.1,
                n_threads: 4,
            },
            hmac_keys: HashMap::new(),
        }
    }
}

impl VigilConfig {
    /// Validate the configuration for consistency and security.
    ///
    /// # Errors
    ///
    /// Returns `ConfigError` if any validation fails.
    pub fn validate(&self) -> VigilResult<()> {
        // Ingestion validation
        if self.ingestion.max_events_per_second == 0 {
            return Err(VigilError::ConfigError {
                reason: "max_events_per_second must be > 0".to_string(),
            });
        }
        if self.ingestion.channel_capacity == 0 {
            return Err(VigilError::ConfigError {
                reason: "channel_capacity must be > 0".to_string(),
            });
        }

        // Security: HMAC enforcement should only be disabled in test environments
        // NOTE (Vivek): As a security founder, this is my biggest concern. If HMAC is disabled
        // in production, a bad actor with physical access to a ground station switch could flood
        // fake SNMP traps to trick operators. Cryptographic tag validation is mandatory for zero-trust.
        if !self.ingestion.enforce_hmac {
            tracing::warn!(
                "⚠️  HMAC verification is DISABLED — this is only acceptable in test environments"
            );
        }

        // Detection validation
        if !(0.0..=1.0).contains(&self.detection.anomaly_threshold) {
            return Err(VigilError::ConfigError {
                reason: format!(
                    "anomaly_threshold must be in [0.0, 1.0], got {}",
                    self.detection.anomaly_threshold
                ),
            });
        }

        // LLM validation
        if self.llm.temperature < 0.0 || self.llm.temperature > 2.0 {
            return Err(VigilError::ConfigError {
                reason: format!(
                    "temperature must be in [0.0, 2.0], got {}",
                    self.llm.temperature
                ),
            });
        }

        Ok(())
    }

    /// Load configuration from a TOML file.
    pub fn load_from_file<P: AsRef<std::path::Path>>(path: P) -> VigilResult<Self> {
        let content = std::fs::read_to_string(path).map_err(VigilError::Io)?;
        let config: Self = toml::from_str(&content).map_err(|e| VigilError::ConfigError {
            reason: format!("Failed to parse config TOML: {}", e),
        })?;
        config.validate()?;
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_valid() {
        let config = VigilConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn invalid_threshold_rejected() {
        let mut config = VigilConfig::default();
        config.detection.anomaly_threshold = 1.5;
        assert!(config.validate().is_err());
    }

    #[test]
    fn zero_channel_capacity_rejected() {
        let mut config = VigilConfig::default();
        config.ingestion.channel_capacity = 0;
        assert!(config.validate().is_err());
    }
}
