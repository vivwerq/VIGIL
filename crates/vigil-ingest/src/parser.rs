//! # Telemetry Parser
//!
//! Parses raw JSON bytes into typed `TelemetryEnvelope` structs.
//! HMAC verification happens BEFORE parsing to prevent parser exploitation.

use vigil_core::constants::MAX_TELEMETRY_PAYLOAD_BYTES;
use vigil_core::error::{VigilError, VigilResult};
use vigil_core::types::TelemetryEnvelope;

/// Parse raw bytes into a `TelemetryEnvelope`.
///
/// # Security
///
/// - Payload size is checked FIRST (before any parsing).
/// - HMAC verification should happen BEFORE calling this function.
pub fn parse_telemetry(raw: &[u8]) -> VigilResult<TelemetryEnvelope> {
    if raw.len() > MAX_TELEMETRY_PAYLOAD_BYTES {
        return Err(VigilError::InputValidation {
            field: "payload".into(),
            reason: format!(
                "payload size {} exceeds maximum {} bytes",
                raw.len(),
                MAX_TELEMETRY_PAYLOAD_BYTES
            ),
        });
    }

    let envelope: TelemetryEnvelope =
        serde_json::from_slice(raw).map_err(|e| VigilError::ParseError {
            protocol: "JSON".into(),
            reason: e.to_string(),
        })?;

    Ok(envelope)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oversized_payload_rejected() {
        let huge = vec![b' '; MAX_TELEMETRY_PAYLOAD_BYTES + 1];
        assert!(parse_telemetry(&huge).is_err());
    }

    #[test]
    fn malformed_json_rejected() {
        assert!(parse_telemetry(b"not json").is_err());
    }
}
