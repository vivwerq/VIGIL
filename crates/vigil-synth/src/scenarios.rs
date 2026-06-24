//! # Pre-built Failure Scenarios
//!
//! Complete failure scenarios that combine multiple anomaly types to simulate
//! realistic cascading network failures.

use crate::anomalies::{AnomalyInjection, AnomalyType};
use crate::generator::GeneratorConfig;

/// Pre-built scenario: BGP route leak causing cascading failures.
/// Simulates a misconfigured peer leaking thousands of prefixes.
pub fn bgp_route_leak_scenario() -> GeneratorConfig {
    GeneratorConfig {
        anomaly_rate: 0.15,
        enabled_anomalies: vec![AnomalyInjection {
            anomaly_type: AnomalyType::BgpRouteLeak,
            probability: 0.4,
            intensity: 0.9,
        }],
        active_scenario: Some("route-leak".into()),
    }
}

/// Pre-built scenario: Fiber cut causing LSP reroute storm.
/// Simulates physical infrastructure failure at a site.
pub fn fiber_cut_scenario() -> GeneratorConfig {
    GeneratorConfig {
        anomaly_rate: 0.25,
        enabled_anomalies: vec![AnomalyInjection {
            anomaly_type: AnomalyType::LspRerouteStorm,
            probability: 0.3,
            intensity: 1.0,
        }],
        active_scenario: Some("fiber-cut".into()),
    }
}

/// Pre-built scenario: Degraded optics (gradual failure).
/// Simulates slowly degrading fiber optic transceivers.
pub fn degraded_optics_scenario() -> GeneratorConfig {
    GeneratorConfig {
        anomaly_rate: 0.08,
        enabled_anomalies: vec![AnomalyInjection {
            anomaly_type: AnomalyType::CrcErrorBurst,
            probability: 0.5,
            intensity: 0.3,
        }],
        active_scenario: Some("tunnel-degradation".into()),
    }
}

/// Pre-built scenario: Security incident — unauthorized SNMP access.
pub fn security_incident_scenario() -> GeneratorConfig {
    GeneratorConfig {
        anomaly_rate: 0.10,
        enabled_anomalies: vec![AnomalyInjection {
            anomaly_type: AnomalyType::SnmpAuthFailure,
            probability: 0.6,
            intensity: 1.0,
        }],
        active_scenario: Some("security-incident".into()),
    }
}

/// Pre-built scenario: Normal operations (baseline).
pub fn normal_operations_scenario() -> GeneratorConfig {
    GeneratorConfig {
        anomaly_rate: 0.01,
        enabled_anomalies: vec![],
        active_scenario: None,
    }
}

/// Pre-built scenario: Progressive congestion buildup.
pub fn progressive_congestion_scenario() -> GeneratorConfig {
    GeneratorConfig {
        anomaly_rate: 0.12,
        enabled_anomalies: vec![AnomalyInjection {
            anomaly_type: AnomalyType::InterfaceSaturation,
            probability: 0.6,
            intensity: 0.8,
        }],
        active_scenario: Some("congestion-buildup".into()),
    }
}
