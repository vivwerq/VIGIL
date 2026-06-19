//! # Pipeline Sink
//!
//! Output adapters for the ingestion pipeline. Validated telemetry
//! events are forwarded to one or more sinks (database, anomaly engine, etc.).

use vigil_core::types::TelemetryEnvelope;

/// Trait for downstream consumers of validated telemetry events.
///
/// Sinks receive events after HMAC verification, parsing, and validation.
/// They are the first point where data is trusted (but still typed/bounded).
pub trait TelemetrySink: Send + Sync {
    /// Process a validated telemetry envelope.
    /// Implementations should be non-blocking or internally async.
    fn ingest(
        &self,
        envelope: &TelemetryEnvelope,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
}

/// A simple logging sink for development and debugging.
pub struct LogSink;

impl TelemetrySink for LogSink {
    fn ingest(
        &self,
        envelope: &TelemetryEnvelope,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        tracing::info!(
            id = %envelope.id,
            source = %envelope.source.hostname,
            protocol = envelope.event.protocol_name(),
            severity = %envelope.event.severity(),
            "Telemetry event ingested"
        );
        Ok(())
    }
}

/// A sink that collects events in memory (for testing).
#[cfg(test)]
pub struct CollectorSink {
    pub events: std::sync::Mutex<Vec<TelemetryEnvelope>>,
}

#[cfg(test)]
impl CollectorSink {
    pub fn new() -> Self {
        Self {
            events: std::sync::Mutex::new(Vec::new()),
        }
    }

    pub fn count(&self) -> usize {
        self.events.lock().unwrap().len()
    }
}

#[cfg(test)]
impl TelemetrySink for CollectorSink {
    fn ingest(
        &self,
        envelope: &TelemetryEnvelope,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.events.lock().unwrap().push(envelope.clone());
        Ok(())
    }
}
