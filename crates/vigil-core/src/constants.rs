//! # System-wide Constants
//!
//! All magic numbers, size limits, and protocol constants live here.
//! Never scatter magic numbers through the codebase — they become
//! invisible attack surfaces.

/// Maximum size of a single telemetry payload in bytes.
/// Anything larger is dropped and logged as a potential DoS attempt.
/// 64 KiB is generous for SNMP/BGP/MPLS telemetry; real payloads are ~1-4 KiB.
pub const MAX_TELEMETRY_PAYLOAD_BYTES: usize = 65_536;

/// Maximum number of events that can be buffered in the ingestion pipeline.
/// Backpressure kicks in beyond this. Sized for ~10 seconds of burst at 1000 events/sec.
pub const INGESTION_CHANNEL_CAPACITY: usize = 10_000;

/// Maximum length of a hostname/device name string.
/// RFC 1123: hostnames are limited to 253 characters.
pub const MAX_HOSTNAME_LENGTH: usize = 253;

/// Maximum number of prefixes in a single BGP update.
/// A single BGP UPDATE with >10,000 prefixes is either a route leak or an attack.
pub const MAX_BGP_PREFIXES_PER_UPDATE: usize = 10_000;

/// Maximum number of labels in an MPLS label stack.
/// RFC 3032 allows arbitrary depth, but >8 labels deep is extremely suspicious.
pub const MAX_MPLS_LABEL_STACK_DEPTH: usize = 8;

/// HMAC key length in bytes (256-bit key).
pub const HMAC_KEY_LENGTH: usize = 32;

/// Maximum age of a telemetry event before it's considered stale (seconds).
/// Events older than 5 minutes are dropped — they're either replays or clock-skewed.
pub const MAX_EVENT_AGE_SECONDS: i64 = 300;

/// Minimum interval between telemetry events from the same source (milliseconds).
/// Events arriving faster than this from a single source trigger rate-limiting.
pub const MIN_EVENT_INTERVAL_MS: u64 = 10;

/// Database compaction interval (seconds).
pub const DB_COMPACTION_INTERVAL_SECS: u64 = 3600;

/// Anomaly detection window size (number of recent events to consider).
pub const ANOMALY_WINDOW_SIZE: usize = 1000;
