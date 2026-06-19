//! # Cryptographically Signed Audit Log Export
//!
//! Provides integrity validation for exported network telemetry and anomaly reports.
//! Using HMAC-SHA256, it ensures that log exports cannot be modified by inside or
//! outside actors after creation.

use crate::error::{VigilError, VigilResult};
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

/// Represents a signed bundle of exported audit logs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedAuditExport {
    /// Serialized JSON array of log records, anomalies, or system alerts.
    pub entries: Vec<serde_json::Value>,
    /// Cryptographic HMAC-SHA256 signature generated over the serialized entries and metadata.
    pub signature: String,
    /// Identifier of the operator who generated the export.
    pub operator_id: String,
    /// Creation timestamp of the export.
    pub created_at: DateTime<Utc>,
}

/// Create a signed audit log export.
///
/// NOTE (Vivek): To comply with security audits in critical NOC networks, the exported files
/// must be tamper-proof. We sign the entries combined with the metadata using the system's
/// private HMAC key.
pub fn create_signed_export(
    entries: Vec<serde_json::Value>,
    secret_key: &[u8],
    operator_id: &str,
) -> VigilResult<SignedAuditExport> {
    let created_at = Utc::now();
    let operator_id = operator_id.to_string();

    // 1. Serialize entries and metadata for signing
    let payload = serde_json::json!({
        "entries": &entries,
        "operator_id": &operator_id,
        "created_at": created_at.to_rfc3339()
    });

    let payload_str = serde_json::to_string(&payload).map_err(VigilError::Json)?;

    // 2. Generate HMAC signature
    let mut mac =
        Hmac::<Sha256>::new_from_slice(secret_key).map_err(|e| VigilError::InternalError {
            reason: format!("Invalid HMAC key length: {}", e),
        })?;
    mac.update(payload_str.as_bytes());
    let sig_bytes = mac.finalize().into_bytes();
    let signature = bytes_to_hex(&sig_bytes);

    Ok(SignedAuditExport {
        entries,
        signature,
        operator_id,
        created_at,
    })
}

/// Verify the integrity of a signed audit log export.
pub fn verify_signed_export(export: &SignedAuditExport, secret_key: &[u8]) -> bool {
    let payload = serde_json::json!({
        "entries": &export.entries,
        "operator_id": &export.operator_id,
        "created_at": export.created_at.to_rfc3339()
    });

    let payload_str = match serde_json::to_string(&payload) {
        Ok(s) => s,
        Err(_) => return false,
    };

    let mut mac = match Hmac::<Sha256>::new_from_slice(secret_key) {
        Ok(m) => m,
        Err(_) => return false,
    };
    mac.update(payload_str.as_bytes());
    let expected_sig_bytes = mac.finalize().into_bytes();
    let expected_sig = bytes_to_hex(&expected_sig_bytes);

    expected_sig == export.signature
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signed_audit_export_flow() {
        let secret_key = b"01234567890123456789012345678912"; // 32 bytes
        let entries = vec![
            serde_json::json!({"event": "bgp_session_down", "node": "router-1"}),
            serde_json::json!({"event": "fiber_cut_detected", "node": "span-4"}),
        ];

        // Create export
        let export = create_signed_export(entries.clone(), secret_key, "admin-operator").unwrap();
        assert_eq!(export.operator_id, "admin-operator");
        assert_eq!(export.entries.len(), 2);

        // Verify signature matches
        assert!(verify_signed_export(&export, secret_key));

        // Verify signature fails with wrong key
        assert!(!verify_signed_export(
            &export,
            b"wrong_secret_key_length_32_bytes"
        ));

        // Verify signature fails if tampered with
        let mut tampered = export;
        tampered.entries[0] = serde_json::json!({"event": "bgp_session_up", "node": "router-1"});
        assert!(!verify_signed_export(&tampered, secret_key));
    }
}
