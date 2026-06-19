//! # VIGIL Ingestion Engine
//!
//! Async telemetry ingestion pipeline built on Tokio.
//!
//! ## Pipeline Stages
//!
//! ```text
//! Raw Bytes → HMAC Verify → Parse JSON → Validate → Normalize → Channel → Sink
//! ```
//!
//! Each stage is a separate async task connected by bounded channels.
//! Backpressure propagates naturally through channel capacity limits.

pub mod parser;
pub mod pipeline;
pub mod sink;
pub mod validator;
