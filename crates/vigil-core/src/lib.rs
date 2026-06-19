//! # VIGIL Core
//!
//! Foundational types, error hierarchy, configuration, and cryptographic
//! primitives shared across all VIGIL subsystems.
//!
//! ## Security Invariants
//!
//! - All public types implement strict bounds checking on construction.
//! - No unbounded allocations from external/untrusted data.
//! - HMAC-SHA256 verification is mandatory before any data enters the pipeline.
//! - All timestamps use UTC; no local timezone assumptions.

pub mod audit;
pub mod config;
pub mod constants;
pub mod crypto;
pub mod error;
pub mod playbook;
pub mod tpm;
pub mod types;

// Re-export the most commonly used types at crate root for ergonomics.
pub use error::{VigilError, VigilResult};
pub use types::{
    BgpEvent, InterfaceMetrics, LspMetrics, MplsEvent, NetworkEvent, OspfEvent, Severity, SnmpTrap,
    TelemetryEnvelope, TelemetrySource,
};
