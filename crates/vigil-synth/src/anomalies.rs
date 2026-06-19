//! # Anomaly Injection Engine
//!
//! Defines anomaly types and injection logic for synthetic telemetry.
//! Each anomaly type models a real-world MPLS network failure mode.

use rand::Rng;
use rand_distr::{Distribution, Normal};
use vigil_core::types::*;

/// Types of anomalies that can be injected into synthetic telemetry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnomalyType {
    /// BGP session flapping: rapid up/down cycles (hardware/config issue).
    BgpFlap,
    /// BGP route leak: unexpected prefixes appearing in the routing table.
    BgpRouteLeak,
    /// Latency spike on an LSP tunnel (congestion or fiber degradation).
    LatencySpike,
    /// Packet loss burst on an LSP (interface errors, buffer overflow).
    PacketLossBurst,
    /// MPLS LSP reroute storm (link failure causing cascading reroutes).
    LspRerouteStorm,
    /// Interface utilization saturation (bandwidth exhaustion).
    InterfaceSaturation,
    /// SNMP authentication failure (potential unauthorized access).
    SnmpAuthFailure,
    /// OSPF neighbor flap (routing instability).
    OspfNeighborFlap,
    /// CRC error burst (physical layer degradation — bad cable/optic).
    CrcErrorBurst,
    /// MPLS label stack corruption (memory corruption or software bug).
    LabelCorruption,
}

impl AnomalyType {
    /// Human-readable description of what this anomaly simulates.
    pub fn description(&self) -> &'static str {
        match self {
            Self::BgpFlap => "BGP session flapping — rapid state oscillation",
            Self::BgpRouteLeak => "BGP route leak — unauthorized prefixes propagating",
            Self::LatencySpike => "LSP latency spike — 10-100x baseline latency",
            Self::PacketLossBurst => "Packet loss burst — >5% loss on LSP",
            Self::LspRerouteStorm => "LSP reroute storm — cascading path changes",
            Self::InterfaceSaturation => "Interface saturation — >95% utilization",
            Self::SnmpAuthFailure => "SNMP authentication failure — potential intrusion",
            Self::OspfNeighborFlap => "OSPF neighbor flap — routing instability",
            Self::CrcErrorBurst => "CRC error burst — physical layer degradation",
            Self::LabelCorruption => "MPLS label corruption — software/hardware fault",
        }
    }
}

/// Configuration for an anomaly injection.
#[derive(Debug, Clone)]
pub struct AnomalyInjection {
    /// Type of anomaly to inject.
    pub anomaly_type: AnomalyType,
    /// Probability of injection per event (0.0-1.0).
    pub probability: f64,
    /// Severity multiplier (how extreme the anomaly is).
    pub intensity: f64,
}

/// Apply a latency spike anomaly to LSP metrics.
pub fn inject_latency_spike(metrics: &mut LspMetrics, rng: &mut impl Rng, intensity: f64) {
    let spike_multiplier = 10.0 + (intensity * 90.0); // 10x to 100x baseline
    let normal = Normal::new(spike_multiplier, spike_multiplier * 0.2).unwrap();
    let multiplier = normal.sample(rng).max(2.0);
    metrics.latency_us = (metrics.latency_us as f64 * multiplier) as u64;
    metrics.jitter_us = (metrics.jitter_us as f64 * multiplier * 1.5) as u64;
}

/// Apply packet loss to LSP metrics.
pub fn inject_packet_loss(metrics: &mut LspMetrics, rng: &mut impl Rng, intensity: f64) {
    let loss_pct = 5.0 + (intensity * 45.0); // 5% to 50%
    let normal = Normal::new(loss_pct, loss_pct * 0.3).unwrap();
    metrics.packet_loss_pct = normal.sample(rng).clamp(1.0, 100.0);
}

/// Apply interface saturation anomaly.
pub fn inject_interface_saturation(
    metrics: &mut InterfaceMetrics,
    rng: &mut impl Rng,
    intensity: f64,
) {
    let target_util = 90.0 + (intensity * 10.0); // 90-100%
    let normal = Normal::new(target_util, 2.0).unwrap();
    metrics.utilization_pct = normal.sample(rng).clamp(85.0, 100.0);
    // Saturation causes errors
    metrics.in_discards = rng.random_range(100..10_000);
    metrics.out_discards = rng.random_range(50..5_000);
}

/// Apply CRC error burst to interface metrics.
pub fn inject_crc_errors(metrics: &mut InterfaceMetrics, rng: &mut impl Rng, intensity: f64) {
    let error_rate = (100.0 * intensity) as u64;
    metrics.crc_errors = rng.random_range(error_rate..error_rate * 10 + 1);
    metrics.in_errors = rng.random_range(error_rate..error_rate * 5 + 1);
}

/// Generate a BGP flap event.
pub fn generate_bgp_flap(peer: &BgpPeer) -> BgpEvent {
    BgpEvent {
        event_type: BgpEventType::SessionFlap,
        peer: peer.clone(),
        affected_prefixes: 0,
        as_path_length: 0,
        local_preference: 100,
        med: 0,
        description: format!(
            "BGP session to {} (AS{}) flapping — {} state changes in 60s",
            peer.address, peer.asn, 5
        ),
    }
}

/// Generate a BGP route leak event.
pub fn generate_route_leak(peer: &BgpPeer, rng: &mut impl Rng) -> BgpEvent {
    let leaked_prefixes = rng.random_range(100..5000);
    BgpEvent {
        event_type: BgpEventType::RouteLeakDetected,
        peer: peer.clone(),
        affected_prefixes: leaked_prefixes,
        as_path_length: rng.random_range(8..15),
        local_preference: 100,
        med: 0,
        description: format!(
            "Route leak detected from AS{}: {} unexpected prefixes with anomalous AS path",
            peer.asn, leaked_prefixes
        ),
    }
}

/// Generate an SNMP authentication failure trap.
pub fn generate_snmp_auth_failure(source_ip: std::net::IpAddr) -> SnmpTrap {
    SnmpTrap {
        oid: "1.3.6.1.6.3.1.1.5.5".into(), // authenticationFailure
        trap_type: SnmpTrapType::AuthenticationFailure,
        severity: Severity::High,
        varbinds: vec![SnmpVarbind {
            oid: "1.3.6.1.2.1.1.3.0".into(), // sysUpTime
            value: "12345678".into(),
        }],
        community: "REDACTED".into(),
        description: format!("SNMP authentication failure from {}", source_ip),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn latency_spike_increases_latency() {
        let mut rng = rand::rng();
        let mut metrics = LspMetrics {
            lsp_name: "test".into(),
            source: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            destination: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            status: LspStatus::Up,
            latency_us: 5000,
            jitter_us: 500,
            packet_loss_pct: 0.0,
            bandwidth_bps: 1_000_000_000,
            reroute_count: 0,
        };
        let original_latency = metrics.latency_us;
        inject_latency_spike(&mut metrics, &mut rng, 0.5);
        assert!(metrics.latency_us > original_latency * 2);
    }

    #[test]
    fn interface_saturation_above_85_pct() {
        let mut rng = rand::rng();
        let mut metrics = InterfaceMetrics {
            interface_name: "TenGigE0/0/0".into(),
            oper_status: InterfaceStatus::Up,
            in_bps: 0,
            out_bps: 0,
            in_pps: 0,
            out_pps: 0,
            in_errors: 0,
            out_errors: 0,
            in_discards: 0,
            out_discards: 0,
            utilization_pct: 30.0,
            crc_errors: 0,
        };
        inject_interface_saturation(&mut metrics, &mut rng, 0.8);
        assert!(metrics.utilization_pct >= 85.0);
    }
}
