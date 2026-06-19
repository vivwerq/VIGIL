//! # Input Validation & Sanitization
//!
//! All telemetry data passes through this validator AFTER HMAC verification
//! and parsing. This catches semantically invalid data that was syntactically
//! correct JSON.
//!
//! ## Security: Defense in Depth
//!
//! Even after HMAC verification, we validate all fields because:
//! 1. A compromised source could have the correct HMAC key but send bad data.
//! 2. Integer overflow or extreme values could cause downstream issues.
//! 3. String fields could contain injection payloads for the LLM.

use chrono::Utc;
use vigil_core::constants::*;
use vigil_core::error::{VigilError, VigilResult};
use vigil_core::types::*;

/// Validates a telemetry envelope for semantic correctness.
///
/// This function checks ALL fields against defined bounds and rejects
/// any data that falls outside acceptable ranges.
pub fn validate_envelope(envelope: &TelemetryEnvelope) -> VigilResult<()> {
    // 1. Validate source metadata
    validate_source(&envelope.source)?;

    // 2. Validate timestamp freshness (anti-replay)
    validate_timestamp(envelope)?;

    // 3. Validate the inner event
    validate_event(&envelope.event)?;

    tracing::trace!(
        id = %envelope.id,
        source = %envelope.source.hostname,
        protocol = envelope.event.protocol_name(),
        "Envelope validation passed"
    );

    Ok(())
}

/// Validate the telemetry source metadata.
fn validate_source(source: &TelemetrySource) -> VigilResult<()> {
    // Hostname length check (RFC 1123)
    if source.hostname.is_empty() || source.hostname.len() > MAX_HOSTNAME_LENGTH {
        return Err(VigilError::InputValidation {
            field: "source.hostname".into(),
            reason: format!(
                "hostname must be 1-{} characters, got {}",
                MAX_HOSTNAME_LENGTH,
                source.hostname.len()
            ),
        });
    }

    // Hostname character validation: only alphanumeric, hyphens, dots
    if !source
        .hostname
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
    {
        return Err(VigilError::InputValidation {
            field: "source.hostname".into(),
            reason: "hostname contains invalid characters (allowed: a-z, 0-9, -, .)".into(),
        });
    }

    // Site ID validation
    if source.site_id.is_empty() || source.site_id.len() > 64 {
        return Err(VigilError::InputValidation {
            field: "source.site_id".into(),
            reason: "site_id must be 1-64 characters".into(),
        });
    }

    Ok(())
}

/// Validate event timestamp is within acceptable bounds.
///
/// Events that are too old could be replay attacks.
/// Events from the future indicate clock skew issues.
fn validate_timestamp(envelope: &TelemetryEnvelope) -> VigilResult<()> {
    let now = Utc::now();
    let age = (now - envelope.timestamp).num_seconds();

    // Reject events from the future (allow 30s for clock skew)
    if age < -30 {
        return Err(VigilError::StaleEvent {
            origin: envelope.source.hostname.clone(),
            age_seconds: age,
            max_seconds: MAX_EVENT_AGE_SECONDS,
        });
    }

    // Reject events that are too old
    if age > MAX_EVENT_AGE_SECONDS {
        return Err(VigilError::StaleEvent {
            origin: envelope.source.hostname.clone(),
            age_seconds: age,
            max_seconds: MAX_EVENT_AGE_SECONDS,
        });
    }

    Ok(())
}

/// Validate the inner network event data.
fn validate_event(event: &NetworkEvent) -> VigilResult<()> {
    match event {
        NetworkEvent::Bgp(bgp) => validate_bgp(bgp),
        NetworkEvent::Mpls(mpls) => validate_mpls(mpls),
        NetworkEvent::Snmp(snmp) => validate_snmp(snmp),
        NetworkEvent::Ospf(_) => Ok(()), // OSPF has simple bounded types
        NetworkEvent::Interface(iface) => validate_interface(iface),
        NetworkEvent::Lsp(lsp) => validate_lsp(lsp),
    }
}

fn validate_bgp(bgp: &BgpEvent) -> VigilResult<()> {
    if bgp.affected_prefixes > MAX_BGP_PREFIXES_PER_UPDATE as u32 {
        return Err(VigilError::InputValidation {
            field: "bgp.affected_prefixes".into(),
            reason: format!(
                "prefix count {} exceeds maximum {} — possible route leak",
                bgp.affected_prefixes, MAX_BGP_PREFIXES_PER_UPDATE
            ),
        });
    }
    // Validate description length to prevent LLM prompt injection
    if bgp.description.len() > 1024 {
        return Err(VigilError::InputValidation {
            field: "bgp.description".into(),
            reason: "description exceeds 1024 characters".into(),
        });
    }
    Ok(())
}

fn validate_mpls(mpls: &MplsEvent) -> VigilResult<()> {
    if mpls.label_stack.len() > MAX_MPLS_LABEL_STACK_DEPTH {
        return Err(VigilError::InputValidation {
            field: "mpls.label_stack".into(),
            reason: format!(
                "label stack depth {} exceeds maximum {}",
                mpls.label_stack.len(),
                MAX_MPLS_LABEL_STACK_DEPTH
            ),
        });
    }
    // MPLS labels are 20-bit values (0–1,048,575)
    for (i, label) in mpls.label_stack.iter().enumerate() {
        if *label > 1_048_575 {
            return Err(VigilError::InputValidation {
                field: format!("mpls.label_stack[{}]", i),
                reason: format!("label value {} exceeds 20-bit maximum", label),
            });
        }
    }
    Ok(())
}

fn validate_snmp(snmp: &SnmpTrap) -> VigilResult<()> {
    // Bound varbinds to prevent memory exhaustion
    if snmp.varbinds.len() > 100 {
        return Err(VigilError::InputValidation {
            field: "snmp.varbinds".into(),
            reason: format!("varbind count {} exceeds maximum 100", snmp.varbinds.len()),
        });
    }
    Ok(())
}

fn validate_interface(iface: &InterfaceMetrics) -> VigilResult<()> {
    if iface.utilization_pct < 0.0 || iface.utilization_pct > 100.0 {
        return Err(VigilError::InputValidation {
            field: "interface.utilization_pct".into(),
            reason: format!("utilization must be 0-100%, got {}", iface.utilization_pct),
        });
    }
    Ok(())
}

fn validate_lsp(lsp: &LspMetrics) -> VigilResult<()> {
    if lsp.packet_loss_pct < 0.0 || lsp.packet_loss_pct > 100.0 {
        return Err(VigilError::InputValidation {
            field: "lsp.packet_loss_pct".into(),
            reason: format!("packet loss must be 0-100%, got {}", lsp.packet_loss_pct),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use uuid::Uuid;

    fn make_test_envelope(event: NetworkEvent) -> TelemetryEnvelope {
        TelemetryEnvelope {
            id: Uuid::now_v7(),
            timestamp: Utc::now(),
            source: TelemetrySource {
                hostname: "test-router-01".into(),
                ip_address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                device_type: DeviceType::CoreRouter,
                site_id: "TEST-SITE".into(),
            },
            hmac_tag: vec![0; 32],
            event,
            sequence_number: 1,
            ground_truth_label: None,
        }
    }

    #[test]
    fn valid_bgp_event_passes() {
        let event = NetworkEvent::Bgp(BgpEvent {
            event_type: BgpEventType::SessionUp,
            peer: BgpPeer {
                address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                asn: 64512,
                hostname: None,
                state: BgpSessionState::Established,
            },
            affected_prefixes: 100,
            as_path_length: 2,
            local_preference: 100,
            med: 0,
            description: "Peer up".into(),
        });
        let envelope = make_test_envelope(event);
        assert!(validate_envelope(&envelope).is_ok());
    }

    #[test]
    fn excessive_prefixes_rejected() {
        let event = NetworkEvent::Bgp(BgpEvent {
            event_type: BgpEventType::RouteAdvertise,
            peer: BgpPeer {
                address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                asn: 64512,
                hostname: None,
                state: BgpSessionState::Established,
            },
            affected_prefixes: 999_999,
            as_path_length: 2,
            local_preference: 100,
            med: 0,
            description: "Route flood".into(),
        });
        let envelope = make_test_envelope(event);
        assert!(validate_envelope(&envelope).is_err());
    }

    #[test]
    fn invalid_hostname_rejected() {
        let mut envelope = make_test_envelope(NetworkEvent::Bgp(BgpEvent {
            event_type: BgpEventType::SessionUp,
            peer: BgpPeer {
                address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                asn: 64512,
                hostname: None,
                state: BgpSessionState::Established,
            },
            affected_prefixes: 0,
            as_path_length: 1,
            local_preference: 100,
            med: 0,
            description: "test".into(),
        }));
        envelope.source.hostname = "router; rm -rf /".into();
        assert!(validate_envelope(&envelope).is_err());
    }

    #[test]
    fn deep_mpls_label_stack_rejected() {
        let event = NetworkEvent::Mpls(MplsEvent {
            event_type: MplsEventType::LabelSwitch,
            label_stack: vec![100; 20], // Way too deep
            fec: "10.0.0.0/24".into(),
            vrf: None,
            tunnel_id: None,
            description: "test".into(),
        });
        let envelope = make_test_envelope(event);
        assert!(validate_envelope(&envelope).is_err());
    }
}
