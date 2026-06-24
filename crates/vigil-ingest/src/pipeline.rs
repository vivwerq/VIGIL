//! # Async Ingestion Pipeline
//!
//! Multi-stage async pipeline using Tokio tasks and bounded channels.
//! Backpressure propagates naturally through channel capacity limits.

use async_channel::{Receiver, Sender, bounded};
use tokio::task::JoinHandle;
use vigil_core::config::VigilConfig;
use vigil_core::crypto::HmacKey;
use vigil_core::error::{VigilError, VigilResult};
use vigil_core::types::TelemetryEnvelope;

use crate::parser::parse_telemetry;
use crate::validator::validate_envelope;

/// Statistics tracked by the ingestion pipeline.
#[derive(Debug, Default, Clone)]
pub struct PipelineStats {
    pub received: u64,
    pub parsed: u64,
    pub validated: u64,
    pub rejected_hmac: u64,
    pub rejected_validation: u64,
    pub rejected_parse: u64,
}

/// The ingestion pipeline: receives raw bytes, verifies, parses, validates,
/// and forwards typed telemetry events to downstream consumers.
pub struct IngestionPipeline {
    /// Channel for submitting raw telemetry bytes.
    raw_tx: Sender<Vec<u8>>,
    /// Channel for receiving validated telemetry envelopes.
    validated_rx: Receiver<TelemetryEnvelope>,
    /// Background task handles.
    _tasks: Vec<JoinHandle<()>>,
}

impl IngestionPipeline {
    /// Create and start a new ingestion pipeline.
    ///
    /// # Arguments
    /// * `config` - Pipeline configuration.
    /// * `hmac_keys` - HashMap mapping source names to HMAC keys.
    pub fn new(
        config: &VigilConfig,
        hmac_keys: std::collections::HashMap<String, HmacKey>,
    ) -> Self {
        let capacity = config.ingestion.channel_capacity;
        let enforce_hmac = config.ingestion.enforce_hmac;

        // Stage 1 → Stage 2: raw bytes to parsed envelopes
        let (raw_tx, raw_rx) = bounded::<Vec<u8>>(capacity);
        // Stage 2 → Output: validated envelopes
        let (validated_tx, validated_rx) = bounded::<TelemetryEnvelope>(capacity);

        // Spawn the processing task
        let task = tokio::spawn(async move {
            #[derive(serde::Deserialize)]
            struct SourceHeader {
                hostname: String,
            }
            #[derive(serde::Deserialize)]
            struct HmacPayload<'a> {
                source: SourceHeader,
                hmac_tag: String,
                #[serde(borrow)]
                event: &'a serde_json::value::RawValue,
            }

            while let Ok(raw_bytes) = raw_rx.recv().await {
                // HMAC verification (if enforced)
                if enforce_hmac {
                    // Phase 1: Parse generic lightweight representation with RawValue
                    let payload: HmacPayload = match serde_json::from_slice(&raw_bytes) {
                        Ok(p) => p,
                        Err(e) => {
                            tracing::warn!(error = %e, "Generic JSON parse failed, dropping event");
                            continue;
                        }
                    };

                    let hostname = &payload.source.hostname;
                    let hmac_hex = &payload.hmac_tag;

                    let hmac_tag = match hex_to_bytes(hmac_hex) {
                        Some(b) => b,
                        None => {
                            tracing::warn!("Invalid hmac_tag hex format, dropping event");
                            continue;
                        }
                    };

                    if let Some(key) = hmac_keys.get(hostname) {
                        // The raw event bytes are exactly the raw JSON representation of the event field
                        let event_bytes = payload.event.get().as_bytes();
                        if let Err(e) = key.verify_tag(event_bytes, &hmac_tag, hostname) {
                            tracing::error!(error = %e, "HMAC verification FAILED");
                            continue;
                        }
                    } else {
                        tracing::error!(
                            source = hostname,
                            "HMAC verification FAILED: no registered key found for source"
                        );
                        continue;
                    }
                }

                // Phase 2: Deserialization into fully typed TelemetryEnvelope (Safe because signature is verified)
                let envelope = match parse_telemetry(&raw_bytes) {
                    Ok(e) => e,
                    Err(e) => {
                        tracing::warn!(error = %e, "Typed parse failed, dropping event");
                        continue;
                    }
                };

                // Validate
                if let Err(e) = validate_envelope(&envelope) {
                    tracing::warn!(error = %e, "Validation failed, dropping event");
                    continue;
                }

                // Forward to downstream
                if validated_tx.send(envelope).await.is_err() {
                    tracing::error!("Downstream channel closed, stopping pipeline");
                    break;
                }
            }
            tracing::info!("Ingestion pipeline task shutting down");
        });

        Self {
            raw_tx,
            validated_rx,
            _tasks: vec![task],
        }
    }

    /// Submit raw telemetry bytes to the pipeline.
    pub async fn submit(&self, raw: Vec<u8>) -> VigilResult<()> {
        self.raw_tx
            .send(raw)
            .await
            .map_err(|_| VigilError::ChannelError {
                reason: "ingestion pipeline channel closed".into(),
            })
    }

    /// Receive the next validated telemetry envelope.
    pub async fn recv(&self) -> VigilResult<TelemetryEnvelope> {
        self.validated_rx
            .recv()
            .await
            .map_err(|_| VigilError::ChannelError {
                reason: "validated channel closed".into(),
            })
    }

    /// Try to receive without blocking (returns None if no events ready).
    pub fn try_recv(&self) -> Option<TelemetryEnvelope> {
        self.validated_rx.try_recv().ok()
    }

    /// Returns the number of events pending in the raw input queue.
    pub fn pending_raw(&self) -> usize {
        self.raw_tx.len()
    }

    /// Returns the number of validated events pending consumption.
    pub fn pending_validated(&self) -> usize {
        self.validated_rx.len()
    }
}

fn hex_to_bytes(s: &str) -> Option<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut chars = s.chars();
    while let Some(c1) = chars.next() {
        let c2 = chars.next()?;
        let val1 = c1.to_digit(16)?;
        let val2 = c2.to_digit(16)?;
        bytes.push((val1 * 16 + val2) as u8);
    }
    Some(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use std::net::{IpAddr, Ipv4Addr};
    use uuid::Uuid;
    use vigil_core::types::*;

    fn test_config() -> VigilConfig {
        let mut config = VigilConfig::default();
        config.ingestion.enforce_hmac = false; // Disable for tests
        config.ingestion.channel_capacity = 100;
        config
    }

    fn make_test_envelope_json() -> Vec<u8> {
        let envelope = TelemetryEnvelope {
            id: Uuid::now_v7(),
            timestamp: Utc::now(),
            source: TelemetrySource {
                hostname: "test-rtr-01".into(),
                ip_address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                device_type: DeviceType::CoreRouter,
                site_id: "TEST-SITE".into(),
            },
            hmac_tag: vec![0; 32],
            event: NetworkEvent::Bgp(BgpEvent {
                event_type: BgpEventType::SessionUp,
                peer: BgpPeer {
                    address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                    asn: 64512,
                    hostname: None,
                    state: BgpSessionState::Established,
                },
                affected_prefixes: 50,
                as_path_length: 2,
                local_preference: 100,
                med: 0,
                description: "Peer established".into(),
            }),
            sequence_number: 1,
            ground_truth_label: None,
        };
        serde_json::to_vec(&envelope).unwrap()
    }

    #[tokio::test]
    async fn pipeline_processes_valid_event() {
        let config = test_config();
        let pipeline = IngestionPipeline::new(&config, std::collections::HashMap::new());

        let json = make_test_envelope_json();
        pipeline.submit(json).await.unwrap();

        let result = pipeline.recv().await;
        assert!(result.is_ok());

        let envelope = result.unwrap();
        assert_eq!(envelope.source.hostname, "test-rtr-01");
    }

    #[tokio::test]
    async fn pipeline_rejects_malformed_json() {
        let config = test_config();
        let pipeline = IngestionPipeline::new(&config, std::collections::HashMap::new());

        pipeline.submit(b"not json".to_vec()).await.unwrap();

        // Submit a valid event after the bad one to verify pipeline continues
        let json = make_test_envelope_json();
        pipeline.submit(json).await.unwrap();

        let result = pipeline.recv().await;
        assert!(result.is_ok()); // Pipeline recovered and processed the valid event
    }

    #[tokio::test]
    async fn pipeline_verifies_hmac() {
        use std::collections::HashMap;
        use vigil_core::crypto::HmacKey;

        let mut config = test_config();
        config.ingestion.enforce_hmac = true;

        let hostname = "test-rtr-01";
        let key_bytes = vec![0xAB; 32];
        let key = HmacKey::new(&key_bytes).unwrap();
        let mut keys = HashMap::new();
        keys.insert(hostname.to_string(), key.clone());

        let pipeline = IngestionPipeline::new(&config, keys);

        // 1. Valid event
        let mut envelope = TelemetryEnvelope {
            id: Uuid::now_v7(),
            timestamp: Utc::now(),
            source: TelemetrySource {
                hostname: hostname.into(),
                ip_address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                device_type: DeviceType::CoreRouter,
                site_id: "TEST-SITE".into(),
            },
            hmac_tag: vec![],
            event: NetworkEvent::Bgp(BgpEvent {
                event_type: BgpEventType::SessionUp,
                peer: BgpPeer {
                    address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                    asn: 64512,
                    hostname: None,
                    state: BgpSessionState::Established,
                },
                affected_prefixes: 50,
                as_path_length: 2,
                local_preference: 100,
                med: 0,
                description: "Peer established".into(),
            }),
            sequence_number: 1,
            ground_truth_label: None,
        };

        // Compute HMAC signature over the serialized event
        let event_bytes = serde_json::to_vec(&envelope.event).unwrap();
        let tag = key.compute_tag(&event_bytes).to_vec();
        envelope.hmac_tag = tag;

        let json = serde_json::to_vec(&envelope).unwrap();
        pipeline.submit(json).await.unwrap();

        // 2. Invalid tag event
        let mut bad_envelope = envelope.clone();
        bad_envelope.hmac_tag = vec![0x00; 32]; // Tampered tag
        let bad_json = serde_json::to_vec(&bad_envelope).unwrap();
        pipeline.submit(bad_json).await.unwrap();

        // 3. Valid event again to make sure pipeline continues
        let mut env2 = envelope.clone();
        env2.id = Uuid::now_v7();
        let json2 = serde_json::to_vec(&env2).unwrap();
        pipeline.submit(json2).await.unwrap();

        // The first submit should succeed
        let res1 = pipeline.recv().await;
        assert!(res1.is_ok());
        assert_eq!(res1.unwrap().id, envelope.id);

        // The second submit (bad tag) should be silently dropped/ignored.
        // The third submit should succeed.
        let res2 = pipeline.recv().await;
        assert!(res2.is_ok());
        assert_eq!(res2.unwrap().id, env2.id);
    }
}
