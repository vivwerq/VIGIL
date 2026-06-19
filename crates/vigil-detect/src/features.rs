//! # Feature Extraction
//!
//! Transforms typed `NetworkEvent` structs into numerical `MetricSample`
//! vectors suitable for statistical anomaly detection.
//!
//! ## Design Philosophy
//!
//! Each telemetry event produces one or more metric samples, each tagged
//! with a `MetricKey` that uniquely identifies what is being measured.
//! The key includes source, protocol, and metric name — so we maintain
//! separate baselines for each (source, metric) pair.
//!
//! Example: `istrac-core-rtr-01::LSP::latency_us` tracks latency
//! independently from `sdsc-core-rtr-01::LSP::latency_us`.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use vigil_core::types::*;

/// Unique identifier for a metric time series.
///
/// Each unique `MetricKey` gets its own sliding window and baseline.
/// This ensures that anomaly detection is per-source, per-metric —
/// a latency spike on one LSP doesn't affect the baseline of another.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MetricKey {
    /// Source device hostname.
    pub source: String,
    /// Protocol that generated this metric.
    pub protocol: String,
    /// Name of the specific metric (e.g., "latency_us", "utilization_pct").
    pub metric_name: String,
}

impl MetricKey {
    pub fn new(source: &str, protocol: &str, metric: &str) -> Self {
        Self {
            source: source.to_string(),
            protocol: protocol.to_string(),
            metric_name: metric.to_string(),
        }
    }
}

impl std::fmt::Display for MetricKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}::{}::{}",
            self.source, self.protocol, self.metric_name
        )
    }
}

/// A single numerical measurement extracted from a telemetry event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricSample {
    /// Which metric this sample belongs to.
    pub key: MetricKey,
    /// The numerical value.
    pub value: f64,
    /// When this measurement was taken.
    pub timestamp: DateTime<Utc>,
    /// Human-readable label for what this value represents.
    pub label: String,
    /// Unit of measurement (for display/explanation).
    pub unit: String,
}

/// Extract numerical metric samples from a telemetry envelope.
///
/// Each envelope can produce multiple metrics. For example, an `InterfaceMetrics`
/// event produces samples for utilization, error rate, discard rate, etc.
pub fn extract_features(envelope: &TelemetryEnvelope) -> Vec<MetricSample> {
    let source = &envelope.source.hostname;
    let ts = envelope.timestamp;

    match &envelope.event {
        NetworkEvent::Bgp(bgp) => extract_bgp_features(source, ts, bgp),
        NetworkEvent::Mpls(mpls) => extract_mpls_features(source, ts, mpls),
        NetworkEvent::Snmp(_snmp) => extract_snmp_features(source, ts),
        NetworkEvent::Ospf(ospf) => extract_ospf_features(source, ts, ospf),
        NetworkEvent::Interface(iface) => extract_interface_features(source, ts, iface),
        NetworkEvent::Lsp(lsp) => extract_lsp_features(source, ts, lsp),
    }
}

/// BGP features: prefix count, AS path length.
fn extract_bgp_features(source: &str, ts: DateTime<Utc>, bgp: &BgpEvent) -> Vec<MetricSample> {
    vec![
        MetricSample {
            key: MetricKey::new(source, "BGP", "affected_prefixes"),
            value: bgp.affected_prefixes as f64,
            timestamp: ts,
            label: "BGP affected prefix count".into(),
            unit: "prefixes".into(),
        },
        MetricSample {
            key: MetricKey::new(source, "BGP", "as_path_length"),
            value: bgp.as_path_length as f64,
            timestamp: ts,
            label: "BGP AS path length".into(),
            unit: "hops".into(),
        },
    ]
}

/// MPLS features: label stack depth.
fn extract_mpls_features(source: &str, ts: DateTime<Utc>, mpls: &MplsEvent) -> Vec<MetricSample> {
    vec![MetricSample {
        key: MetricKey::new(source, "MPLS", "label_stack_depth"),
        value: mpls.label_stack.len() as f64,
        timestamp: ts,
        label: "MPLS label stack depth".into(),
        unit: "labels".into(),
    }]
}

/// SNMP features: event occurrence (count-based detection).
fn extract_snmp_features(source: &str, ts: DateTime<Utc>) -> Vec<MetricSample> {
    // SNMP traps are event-based, not value-based.
    // We track occurrence rate — each trap is a "1.0" event.
    vec![MetricSample {
        key: MetricKey::new(source, "SNMP", "trap_count"),
        value: 1.0,
        timestamp: ts,
        label: "SNMP trap occurrence".into(),
        unit: "traps".into(),
    }]
}

/// OSPF features: LSA count.
fn extract_ospf_features(source: &str, ts: DateTime<Utc>, ospf: &OspfEvent) -> Vec<MetricSample> {
    vec![MetricSample {
        key: MetricKey::new(source, "OSPF", "lsa_count"),
        value: ospf.lsa_count as f64,
        timestamp: ts,
        label: "OSPF LSA database change count".into(),
        unit: "LSAs".into(),
    }]
}

/// Interface features: utilization, errors, discards, CRC errors.
fn extract_interface_features(
    source: &str,
    ts: DateTime<Utc>,
    iface: &InterfaceMetrics,
) -> Vec<MetricSample> {
    let prefix = format!("{}.{}", source, iface.interface_name);

    vec![
        MetricSample {
            key: MetricKey::new(&prefix, "INTERFACE", "utilization_pct"),
            value: iface.utilization_pct,
            timestamp: ts,
            label: format!("{} utilization", iface.interface_name),
            unit: "%".into(),
        },
        MetricSample {
            key: MetricKey::new(&prefix, "INTERFACE", "in_errors"),
            value: iface.in_errors as f64,
            timestamp: ts,
            label: format!("{} input errors/s", iface.interface_name),
            unit: "errors/s".into(),
        },
        MetricSample {
            key: MetricKey::new(&prefix, "INTERFACE", "out_errors"),
            value: iface.out_errors as f64,
            timestamp: ts,
            label: format!("{} output errors/s", iface.interface_name),
            unit: "errors/s".into(),
        },
        MetricSample {
            key: MetricKey::new(&prefix, "INTERFACE", "crc_errors"),
            value: iface.crc_errors as f64,
            timestamp: ts,
            label: format!("{} CRC errors", iface.interface_name),
            unit: "errors".into(),
        },
        MetricSample {
            key: MetricKey::new(&prefix, "INTERFACE", "total_discards"),
            value: (iface.in_discards + iface.out_discards) as f64,
            timestamp: ts,
            label: format!("{} total discards", iface.interface_name),
            unit: "discards/s".into(),
        },
    ]
}

/// LSP features: latency, jitter, packet loss, reroute count.
fn extract_lsp_features(source: &str, ts: DateTime<Utc>, lsp: &LspMetrics) -> Vec<MetricSample> {
    let prefix = format!("{}.{}", source, lsp.lsp_name);

    vec![
        MetricSample {
            key: MetricKey::new(&prefix, "LSP", "latency_us"),
            value: lsp.latency_us as f64,
            timestamp: ts,
            label: format!("{} round-trip latency", lsp.lsp_name),
            unit: "μs".into(),
        },
        MetricSample {
            key: MetricKey::new(&prefix, "LSP", "jitter_us"),
            value: lsp.jitter_us as f64,
            timestamp: ts,
            label: format!("{} jitter", lsp.lsp_name),
            unit: "μs".into(),
        },
        MetricSample {
            key: MetricKey::new(&prefix, "LSP", "packet_loss_pct"),
            value: lsp.packet_loss_pct,
            timestamp: ts,
            label: format!("{} packet loss", lsp.lsp_name),
            unit: "%".into(),
        },
        MetricSample {
            key: MetricKey::new(&prefix, "LSP", "reroute_count"),
            value: lsp.reroute_count as f64,
            timestamp: ts,
            label: format!("{} reroute count", lsp.lsp_name),
            unit: "reroutes".into(),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use uuid::Uuid;

    fn test_source() -> TelemetrySource {
        TelemetrySource {
            hostname: "test-rtr-01".into(),
            ip_address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            device_type: DeviceType::CoreRouter,
            site_id: "TEST".into(),
        }
    }

    #[test]
    fn lsp_produces_four_metrics() {
        let envelope = TelemetryEnvelope {
            id: Uuid::now_v7(),
            timestamp: Utc::now(),
            source: test_source(),
            hmac_tag: vec![0; 32],
            event: NetworkEvent::Lsp(LspMetrics {
                lsp_name: "LSP-TEST".into(),
                source: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                destination: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                status: LspStatus::Up,
                latency_us: 5000,
                jitter_us: 200,
                packet_loss_pct: 0.0,
                bandwidth_bps: 1_000_000_000,
                reroute_count: 0,
            }),
            sequence_number: 1,
            ground_truth_label: None,
        };

        let samples = extract_features(&envelope);
        assert_eq!(samples.len(), 4);
        assert!(samples.iter().any(|s| s.key.metric_name == "latency_us"));
        assert!(samples.iter().any(|s| s.key.metric_name == "jitter_us"));
        assert!(
            samples
                .iter()
                .any(|s| s.key.metric_name == "packet_loss_pct")
        );
        assert!(samples.iter().any(|s| s.key.metric_name == "reroute_count"));
    }

    #[test]
    fn interface_produces_five_metrics() {
        let envelope = TelemetryEnvelope {
            id: Uuid::now_v7(),
            timestamp: Utc::now(),
            source: test_source(),
            hmac_tag: vec![0; 32],
            event: NetworkEvent::Interface(InterfaceMetrics {
                interface_name: "TenGigE0/0/0".into(),
                oper_status: InterfaceStatus::Up,
                in_bps: 500_000_000,
                out_bps: 300_000_000,
                in_pps: 100_000,
                out_pps: 80_000,
                in_errors: 0,
                out_errors: 0,
                in_discards: 0,
                out_discards: 0,
                utilization_pct: 35.0,
                crc_errors: 0,
            }),
            sequence_number: 1,
            ground_truth_label: None,
        };

        let samples = extract_features(&envelope);
        assert_eq!(samples.len(), 5);
    }

    #[test]
    fn metric_key_display() {
        let key = MetricKey::new("router-01", "LSP", "latency_us");
        assert_eq!(key.to_string(), "router-01::LSP::latency_us");
    }
}
