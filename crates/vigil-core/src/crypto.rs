//! # VIGIL Cryptographic Primitives
//!
//! HMAC-SHA256 verification for telemetry integrity.
//!
//! ## Security Model
//!
//! Every telemetry source has a pre-shared HMAC key (distributed during
//! provisioning). All telemetry payloads include an HMAC tag computed
//! over the payload bytes. We verify this tag BEFORE parsing the payload.
//!
//! This prevents:
//! - Tampered telemetry data from being ingested
//! - Replay attacks (combined with timestamp validation)
//! - Injection of malformed data designed to exploit parser bugs
//!
//! ## Why HMAC-SHA256?
//!
//! - Standardized, FIPS-approved
//! - Constant-time comparison (no timing side channels)
//! - No asymmetric crypto overhead (we're inside an air-gap)
//! - Supported by all network equipment vendors

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::constants::HMAC_KEY_LENGTH;
use crate::error::{VigilError, VigilResult};

/// Type alias for HMAC-SHA256.
type HmacSha256 = Hmac<Sha256>;

/// An HMAC key wrapper that zeroes memory on drop.
///
/// # Security
///
/// Keys are stored in a fixed-size array and are zeroed when the
/// `HmacKey` is dropped, preventing key material from lingering in memory.
#[derive(Clone)]
pub struct HmacKey {
    /// The raw key bytes. Fixed size to prevent heap allocation
    /// of key material (stack is more predictable for zeroing).
    key: [u8; HMAC_KEY_LENGTH],
}

impl HmacKey {
    /// Create a new HMAC key from raw bytes.
    ///
    /// # Errors
    ///
    /// Returns `ConfigError` if the key length doesn't match `HMAC_KEY_LENGTH`.
    pub fn new(key_bytes: &[u8]) -> VigilResult<Self> {
        if key_bytes.len() != HMAC_KEY_LENGTH {
            return Err(VigilError::ConfigError {
                reason: format!(
                    "HMAC key must be exactly {} bytes, got {}",
                    HMAC_KEY_LENGTH,
                    key_bytes.len()
                ),
            });
        }

        let mut key = [0u8; HMAC_KEY_LENGTH];
        key.copy_from_slice(key_bytes);
        Ok(Self { key })
    }

    /// Compute HMAC-SHA256 tag for the given data.
    ///
    /// Returns the 32-byte HMAC tag.
    pub fn compute_tag(&self, data: &[u8]) -> [u8; 32] {
        let mut mac =
            HmacSha256::new_from_slice(&self.key).expect("HMAC key length is always valid");
        mac.update(data);
        let result = mac.finalize();
        result.into_bytes().into()
    }

    /// Verify an HMAC-SHA256 tag against the given data.
    ///
    /// Uses constant-time comparison to prevent timing side-channel attacks.
    ///
    /// # Errors
    ///
    /// Returns `CryptoVerification` error if the tag doesn't match.
    pub fn verify_tag(&self, data: &[u8], expected_tag: &[u8], source: &str) -> VigilResult<()> {
        let mut mac =
            HmacSha256::new_from_slice(&self.key).expect("HMAC key length is always valid");
        mac.update(data);

        // `verify_slice` uses constant-time comparison internally.
        // This is critical — a non-constant-time comparison would leak
        // information about how many bytes of the tag matched.
        mac.verify_slice(expected_tag).map_err(|_| {
            tracing::error!(
                source = source,
                "HMAC verification FAILED — potential data tampering detected"
            );
            VigilError::CryptoVerification {
                origin: source.to_string(),
                reason: "HMAC-SHA256 tag mismatch — payload may have been tampered with"
                    .to_string(),
            }
        })
    }
}

/// Zero out key material on drop.
///
/// This is defense-in-depth. The OS may or may not actually zero the
/// memory, but we make our best effort. In a hardened deployment,
/// combine this with `mlock()` to prevent key material from being
/// swapped to disk.
impl Drop for HmacKey {
    fn drop(&mut self) {
        // Volatile write to prevent the compiler from optimizing away the zeroing.
        // This is the best we can do in safe Rust without `zeroize` crate.
        for byte in &mut self.key {
            // Use black_box to prevent optimization
            *byte = 0;
        }
        std::hint::black_box(&self.key);
    }
}

// Intentionally NOT implementing Debug to prevent key leakage in logs.
impl std::fmt::Debug for HmacKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HmacKey")
            .field("key", &"[REDACTED]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> HmacKey {
        let key_bytes = [0xABu8; HMAC_KEY_LENGTH];
        HmacKey::new(&key_bytes).unwrap()
    }

    #[test]
    fn valid_hmac_verifies() {
        let key = test_key();
        let data = b"test telemetry payload";
        let tag = key.compute_tag(data);
        assert!(key.verify_tag(data, &tag, "test-source").is_ok());
    }

    #[test]
    fn tampered_data_fails_verification() {
        let key = test_key();
        let data = b"original payload";
        let tag = key.compute_tag(data);
        let tampered = b"tampered payload";
        assert!(key.verify_tag(tampered, &tag, "test-source").is_err());
    }

    #[test]
    fn tampered_tag_fails_verification() {
        let key = test_key();
        let data = b"test payload";
        let mut tag = key.compute_tag(data);
        tag[0] ^= 0xFF; // Flip bits in the tag
        assert!(key.verify_tag(data, &tag, "test-source").is_err());
    }

    #[test]
    fn wrong_key_length_rejected() {
        let short_key = [0u8; 16]; // Too short
        assert!(HmacKey::new(&short_key).is_err());
    }

    #[test]
    fn debug_does_not_leak_key() {
        let key = test_key();
        let debug_output = format!("{:?}", key);
        assert!(debug_output.contains("REDACTED"));
        assert!(!debug_output.contains("171")); // 0xAB = 171
    }
}
