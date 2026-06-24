//! # Main Telemetry Generator
//!
//! Produces streams of synthetic telemetry data that mimics real
//! ISRO MPLS network traffic patterns. Supports stateful scenario simulation
//! (e.g. gradual congestion buildup, tunnel degradation) and random anomaly injection.

use chrono::Utc;
use rand::Rng;
use rand_distr::{Distribution, Normal};
use std::net::IpAddr;
use uuid::Uuid;

use vigil_core::types::*;

use crate::anomalies::*;
use crate::profiles::*;

/// Configuration for the telemetry generator.
#[derive(Debug, Clone)]
pub struct GeneratorConfig {
    /// Anomaly injection probability (0.0 = no anomalies, 1.0 = all anomalous).
    pub anomaly_rate: f64,
    /// Which anomaly types to inject.
    pub enabled_anomalies: Vec<AnomalyInjection>,
    /// Active scenario name for stateful progressive simulation.
    pub active_scenario: Option<String>,
}

impl Default for GeneratorConfig {
    fn default() -> Self {
        Self {
            anomaly_rate: 0.05, // 5% of events are anomalous
            enabled_anomalies: vec![
                AnomalyInjection {
                    anomaly_type: AnomalyType::BgpFlap,
                    probability: 0.15,
                    intensity: 0.7,
                },
                AnomalyInjection {
                    anomaly_type: AnomalyType::LatencySpike,
                    probability: 0.20,
                    intensity: 0.5,
                },
                AnomalyInjection {
                    anomaly_type: AnomalyType::PacketLossBurst,
                    probability: 0.15,
                    intensity: 0.6,
                },
                AnomalyInjection {
                    anomaly_type: AnomalyType::InterfaceSaturation,
                    probability: 0.15,
                    intensity: 0.8,
                },
                AnomalyInjection {
                    anomaly_type: AnomalyType::BgpRouteLeak,
                    probability: 0.05,
                    intensity: 0.9,
                },
                AnomalyInjection {
                    anomaly_type: AnomalyType::SnmpAuthFailure,
                    probability: 0.10,
                    intensity: 1.0,
                },
                AnomalyInjection {
                    anomaly_type: AnomalyType::CrcErrorBurst,
                    probability: 0.10,
                    intensity: 0.5,
                },
                AnomalyInjection {
                    anomaly_type: AnomalyType::LabelCorruption,
                    probability: 0.05,
                    intensity: 1.0,
                },
                AnomalyInjection {
                    anomaly_type: AnomalyType::OspfNeighborFlap,
                    probability: 0.05,
                    intensity: 0.7,
                },
            ],
            active_scenario: None,
        }
    }
}

/// The synthetic telemetry generator.
pub struct TelemetryGenerator {
    config: GeneratorConfig,
    profiles: Vec<SiteProfile>,
    rng: rand::rngs::StdRng,
    sequence: u64,
    scenario_tick: u32,
}

impl TelemetryGenerator {
    /// Create a new generator with the ISRO network profile.
    pub fn new(config: GeneratorConfig) -> Self {
        use rand::SeedableRng;
        Self {
            config,
            profiles: isro_network_profile(),
            rng: rand::rngs::StdRng::from_rng(&mut rand::rng()),
            sequence: 0,
            scenario_tick: 0,
        }
    }

    /// Generate a single telemetry event (may or may not contain an anomaly or scenario progression).
    pub fn generate_event(&mut self) -> TelemetryEnvelope {
        self.sequence += 1;
        self.scenario_tick += 1;

        // Pick a random site and device
        let site = &self.profiles[self.rng.random_range(0..self.profiles.len())].clone();
        let device = &site.devices[self.rng.random_range(0..site.devices.len())].clone();

        let mut ground_truth = None;
        let event = if let Some(ref scenario) = self.config.active_scenario {
            match scenario.as_str() {
                "congestion-buildup" => {
                    ground_truth = Some("Progressive Congestion Buildup".to_string());
                    self.generate_congestion_buildup(site)
                }
                "tunnel-degradation" => {
                    ground_truth = Some("Tunnel Degradation (Optics Failure)".to_string());
                    self.generate_tunnel_degradation(site)
                }
                "fiber-cut" => {
                    if self.scenario_tick >= 10 {
                        ground_truth = Some("MPLS LSP Path Cut / Reroute Storm".to_string());
                        self.generate_fiber_cut_failure(site)
                    } else {
                        self.generate_normal_event(site, device)
                    }
                }
                "route-leak" => {
                    ground_truth = Some("BGP Route Leak (Prefix Flood)".to_string());
                    self.generate_route_leak_progression(site)
                }
                "security-incident" => {
                    ground_truth = Some("Unauthorized SNMP Access & Port Probe".to_string());
                    self.generate_security_incident_progression(site, device)
                }
                "satellite-pass-degradation" => {
                    ground_truth = Some("Satellite Pass Link Degradation (Rain Fade)".to_string());
                    self.generate_satellite_pass_degradation(site)
                }
                _ => self.generate_normal_event(site, device),
            }
        } else {
            let is_anomalous = self.rng.random_bool(self.config.anomaly_rate);
            if is_anomalous {
                self.generate_anomalous_event(site, device)
            } else {
                self.generate_normal_event(site, device)
            }
        };

        TelemetryEnvelope {
            id: Uuid::now_v7(),
            timestamp: Utc::now(),
            source: device.clone(),
            hmac_tag: vec![0u8; 32], // Placeholder — real HMAC computed by source
            event,
            sequence_number: self.sequence,
            ground_truth_label: ground_truth,
        }
    }

    /// Generate a batch of events.
    pub fn generate_batch(&mut self, count: usize) -> Vec<TelemetryEnvelope> {
        (0..count).map(|_| self.generate_event()).collect()
    }

    /// Generate congestion buildup progression: gradually ramps utilization, which triggers latency and packet loss.
    fn generate_congestion_buildup(&mut self, site: &SiteProfile) -> NetworkEvent {
        let t = self.scenario_tick;
        // Utilization ramps up gradually from 30% to 98%
        let util = (30.0 + (t as f64 * 2.0).min(68.0) + self.rng.random_range(-1.0..1.0))
            .clamp(0.0, 100.0);

        if t % 2 == 0 {
            let mut iface = self.make_baseline_interface(site);
            iface.interface_name = "TenGigE0/0/0".to_string();
            iface.utilization_pct = util;
            if util > 85.0 {
                iface.in_discards = self.rng.random_range(100..2000);
                iface.out_discards = self.rng.random_range(50..1000);
            }
            NetworkEvent::Interface(iface)
        } else {
            let mut lsp = self.make_baseline_lsp(site);
            if util > 70.0 {
                let excess = util - 70.0;
                lsp.latency_us += (excess * 800.0) as u64; // up to 22.4ms increase
                if util > 80.0 {
                    lsp.packet_loss_pct = (util - 80.0) * 0.35; // up to 6.3% loss
                }
            }
            NetworkEvent::Lsp(lsp)
        }
    }

    /// Generate tunnel degradation progression: gradually increases optical CRC errors and packet loss.
    fn generate_tunnel_degradation(&mut self, site: &SiteProfile) -> NetworkEvent {
        let t = self.scenario_tick;
        if t % 2 == 0 {
            let mut iface = self.make_baseline_interface(site);
            iface.interface_name = "TenGigE0/0/0".to_string();
            iface.crc_errors = (t as f64 * 3.5).min(300.0) as u64;
            iface.in_errors = (t as f64 * 1.5).min(100.0) as u64;
            NetworkEvent::Interface(iface)
        } else {
            let mut lsp = self.make_baseline_lsp(site);
            lsp.packet_loss_pct = (t as f64 * 0.4).min(15.0); // up to 15% packet loss
            lsp.jitter_us += (t as f64 * 80.0).min(3000.0) as u64; // up to 3ms jitter
            NetworkEvent::Lsp(lsp)
        }
    }

    /// Generate fiber cut failure: sudden interface down followed by OSPF flap and LSP reroute storm.
    fn generate_fiber_cut_failure(&mut self, site: &SiteProfile) -> NetworkEvent {
        let t = self.scenario_tick;
        match t % 3 {
            0 => NetworkEvent::Ospf(OspfEvent {
                event_type: OspfEventType::NeighborDown,
                area_id: "0.0.0.0".into(),
                neighbor_id: Some(IpAddr::V4(std::net::Ipv4Addr::new(10, 1, 1, 2))),
                neighbor_state: Some(OspfNeighborState::Down),
                lsa_count: self.rng.random_range(100..400),
                description: "OSPF Neighbor adjacency lost — physical link down".into(),
            }),
            1 => {
                let peer = BgpPeer {
                    address: IpAddr::V4(std::net::Ipv4Addr::new(10, 2, 1, 2)),
                    asn: 64513,
                    hostname: Some("isac-pe-rtr-01".into()),
                    state: BgpSessionState::Active,
                };
                NetworkEvent::Bgp(generate_bgp_flap(&peer))
            }
            _ => {
                let mut lsp = self.make_baseline_lsp(site);
                lsp.status = LspStatus::Rerouted;
                lsp.packet_loss_pct = 100.0;
                lsp.latency_us = 0;
                lsp.reroute_count = self.rng.random_range(15..45);
                NetworkEvent::Lsp(lsp)
            }
        }
    }

    /// Generate BGP route leak: gradually increases prefix announcements.
    fn generate_route_leak_progression(&mut self, site: &SiteProfile) -> NetworkEvent {
        let t = self.scenario_tick;
        let leaked = (t * 220).min(12000);
        let peer_profile = &site.bgp_peers[self.rng.random_range(0..site.bgp_peers.len())];
        NetworkEvent::Bgp(BgpEvent {
            event_type: BgpEventType::RouteLeakDetected,
            peer: BgpPeer {
                address: peer_profile.peer_ip,
                asn: peer_profile.peer_asn,
                hostname: Some(peer_profile.peer_hostname.clone()),
                state: BgpSessionState::Established,
            },
            affected_prefixes: leaked,
            as_path_length: self.rng.random_range(8..15),
            local_preference: 100,
            med: 0,
            description: format!(
                "Route leak detected from AS{}: {} unexpected prefixes with anomalous AS path",
                peer_profile.peer_asn, leaked
            ),
        })
    }

    /// Generate security incident: authentication bursts and label corruptions.
    fn generate_security_incident_progression(
        &mut self,
        _site: &SiteProfile,
        device: &TelemetrySource,
    ) -> NetworkEvent {
        let t = self.scenario_tick;
        if t % 2 == 0 {
            NetworkEvent::Snmp(generate_snmp_auth_failure(device.ip_address))
        } else {
            NetworkEvent::Mpls(MplsEvent {
                event_type: MplsEventType::LabelStackCorruption,
                label_stack: vec![self.rng.random_range(16..1_048_575); 3],
                fec: "10.0.0.0/8".into(),
                vrf: Some("ISRO-MPLS".into()),
                tunnel_id: Some("CORRUPT-LSP".into()),
                description: "Label stack corruption detected during secure authentication burst"
                    .into(),
            })
        }
    }

    /// Generate satellite pass link degradation progression: Eb/No signal drops due to rain fade.
    fn generate_satellite_pass_degradation(&mut self, site: &SiteProfile) -> NetworkEvent {
        let t = self.scenario_tick;
        let error_rate = (t as f64 * 1.5).min(20.0);
        let mut iface = self.make_baseline_interface(site);
        iface.interface_name = "Antenna-Dish-01".to_string();
        if error_rate > 5.0 {
            iface.in_errors = (error_rate * 50.0) as u64;
            iface.in_discards = (error_rate * 250.0) as u64;
            iface.utilization_pct = 95.0;
        }
        NetworkEvent::Interface(iface)
    }

    /// Generate a normal (non-anomalous) event.
    fn generate_normal_event(
        &mut self,
        site: &SiteProfile,
        device: &TelemetrySource,
    ) -> NetworkEvent {
        let event_type = self.rng.random_range(0..5);
        match event_type {
            0 if !site.bgp_peers.is_empty() => self.generate_normal_bgp(site),
            1 if !site.lsp_tunnels.is_empty() => self.generate_normal_lsp(site),
            2 if !site.interfaces.is_empty() => self.generate_normal_interface(site),
            3 => self.generate_normal_mpls(device),
            _ => self.generate_normal_snmp(device),
        }
    }

    /// Generate an anomalous event based on configured injection probabilities.
    fn generate_anomalous_event(
        &mut self,
        site: &SiteProfile,
        device: &TelemetrySource,
    ) -> NetworkEvent {
        let anomalies = self.config.enabled_anomalies.clone();
        if anomalies.is_empty() {
            return self.generate_normal_event(site, device);
        }
        let total_prob: f64 = anomalies.iter().map(|a| a.probability).sum();
        if total_prob <= 0.0 {
            return self.generate_normal_event(site, device);
        }
        let mut roll: f64 = self.rng.random_range(0.0..total_prob);

        for injection in &anomalies {
            roll -= injection.probability;
            if roll <= 0.0 {
                return self.create_anomaly(injection, site, device);
            }
        }

        self.generate_normal_event(site, device)
    }

    fn create_anomaly(
        &mut self,
        injection: &AnomalyInjection,
        site: &SiteProfile,
        device: &TelemetrySource,
    ) -> NetworkEvent {
        match injection.anomaly_type {
            AnomalyType::BgpFlap => {
                if let Some(peer_profile) = site.bgp_peers.first() {
                    let peer = BgpPeer {
                        address: peer_profile.peer_ip,
                        asn: peer_profile.peer_asn,
                        hostname: Some(peer_profile.peer_hostname.clone()),
                        state: BgpSessionState::Active,
                    };
                    NetworkEvent::Bgp(generate_bgp_flap(&peer))
                } else {
                    self.generate_normal_event(site, device)
                }
            }
            AnomalyType::BgpRouteLeak => {
                if let Some(peer_profile) = site.bgp_peers.first() {
                    let peer = BgpPeer {
                        address: peer_profile.peer_ip,
                        asn: peer_profile.peer_asn,
                        hostname: Some(peer_profile.peer_hostname.clone()),
                        state: BgpSessionState::Established,
                    };
                    NetworkEvent::Bgp(generate_route_leak(&peer, &mut self.rng))
                } else {
                    self.generate_normal_event(site, device)
                }
            }
            AnomalyType::LatencySpike => {
                let mut metrics = self.make_baseline_lsp(site);
                inject_latency_spike(&mut metrics, &mut self.rng, injection.intensity);
                NetworkEvent::Lsp(metrics)
            }
            AnomalyType::PacketLossBurst => {
                let mut metrics = self.make_baseline_lsp(site);
                inject_packet_loss(&mut metrics, &mut self.rng, injection.intensity);
                NetworkEvent::Lsp(metrics)
            }
            AnomalyType::InterfaceSaturation => {
                let mut metrics = self.make_baseline_interface(site);
                inject_interface_saturation(&mut metrics, &mut self.rng, injection.intensity);
                NetworkEvent::Interface(metrics)
            }
            AnomalyType::CrcErrorBurst => {
                let mut metrics = self.make_baseline_interface(site);
                inject_crc_errors(&mut metrics, &mut self.rng, injection.intensity);
                NetworkEvent::Interface(metrics)
            }
            AnomalyType::SnmpAuthFailure => {
                NetworkEvent::Snmp(generate_snmp_auth_failure(device.ip_address))
            }
            AnomalyType::LabelCorruption => NetworkEvent::Mpls(MplsEvent {
                event_type: MplsEventType::LabelStackCorruption,
                label_stack: vec![self.rng.random_range(16..1_048_575); 3],
                fec: "10.0.0.0/8".into(),
                vrf: Some("ISRO-MPLS".into()),
                tunnel_id: Some("CORRUPT-LSP".into()),
                description: "Label stack corruption detected — potential memory fault".into(),
            }),
            AnomalyType::OspfNeighborFlap => NetworkEvent::Ospf(OspfEvent {
                event_type: OspfEventType::NeighborDown,
                area_id: "0.0.0.0".into(),
                neighbor_id: Some(IpAddr::V4(std::net::Ipv4Addr::new(
                    10,
                    0,
                    0,
                    self.rng.random_range(1..255),
                ))),
                neighbor_state: Some(OspfNeighborState::Down),
                lsa_count: self.rng.random_range(10..500),
                description: "OSPF neighbor flapping — possible link instability".into(),
            }),
            AnomalyType::LspRerouteStorm => {
                let mut metrics = self.make_baseline_lsp(site);
                metrics.status = LspStatus::Rerouted;
                metrics.reroute_count = self.rng.random_range(5..50);
                inject_latency_spike(&mut metrics, &mut self.rng, 0.3);
                NetworkEvent::Lsp(metrics)
            }
        }
    }

    // ── Normal event generators ─────────────────────────────────────────

    fn generate_normal_bgp(&mut self, site: &SiteProfile) -> NetworkEvent {
        let peer_profile = &site.bgp_peers[self.rng.random_range(0..site.bgp_peers.len())];
        NetworkEvent::Bgp(BgpEvent {
            event_type: BgpEventType::RouteAdvertise,
            peer: BgpPeer {
                address: peer_profile.peer_ip,
                asn: peer_profile.peer_asn,
                hostname: Some(peer_profile.peer_hostname.clone()),
                state: BgpSessionState::Established,
            },
            affected_prefixes: self.rng.random_range(1..50),
            as_path_length: self.rng.random_range(1..5),
            local_preference: 100,
            med: self.rng.random_range(0..100),
            description: "Normal BGP route update".into(),
        })
    }

    fn generate_normal_lsp(&mut self, site: &SiteProfile) -> NetworkEvent {
        NetworkEvent::Lsp(self.make_baseline_lsp(site))
    }

    fn generate_normal_interface(&mut self, site: &SiteProfile) -> NetworkEvent {
        NetworkEvent::Interface(self.make_baseline_interface(site))
    }

    fn generate_normal_mpls(&mut self, _device: &TelemetrySource) -> NetworkEvent {
        let label_count = self.rng.random_range(1..4);
        NetworkEvent::Mpls(MplsEvent {
            event_type: MplsEventType::LabelSwitch,
            label_stack: (0..label_count)
                .map(|_| self.rng.random_range(16..1_048_575))
                .collect(),
            fec: format!(
                "10.{}.{}.0/24",
                self.rng.random_range(0..255u8),
                self.rng.random_range(0..255u8)
            ),
            vrf: Some("ISRO-MPLS".into()),
            tunnel_id: None,
            description: "Normal MPLS label switching".into(),
        })
    }

    fn generate_normal_snmp(&mut self, device: &TelemetrySource) -> NetworkEvent {
        let trap_type = if self.rng.random_bool(0.5) {
            SnmpTrapType::LinkUp
        } else {
            SnmpTrapType::WarmStart
        };
        NetworkEvent::Snmp(SnmpTrap {
            oid: "1.3.6.1.6.3.1.1.5.4".into(),
            trap_type,
            severity: Severity::Info,
            varbinds: vec![SnmpVarbind {
                oid: "1.3.6.1.2.1.1.3.0".into(),
                value: format!("{}", self.rng.random_range(100000..99999999u64)),
            }],
            community: "REDACTED".into(),
            description: format!("Routine SNMP notification from {}", device.hostname),
        })
    }

    // ── Baseline metric generators ──────────────────────────────────────

    fn make_baseline_lsp(&mut self, site: &SiteProfile) -> LspMetrics {
        let tunnel = if site.lsp_tunnels.is_empty() {
            LspProfile {
                name: "LSP-DEFAULT".into(),
                source_ip: IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)),
                dest_ip: IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 2)),
                baseline_latency_us: 5000,
                baseline_bandwidth_bps: 1_000_000_000,
            }
        } else {
            site.lsp_tunnels[self.rng.random_range(0..site.lsp_tunnels.len())].clone()
        };

        let normal_latency = Normal::new(tunnel.baseline_latency_us as f64, 500.0).unwrap();
        let normal_jitter = Normal::new(200.0, 50.0).unwrap();

        LspMetrics {
            lsp_name: tunnel.name,
            source: tunnel.source_ip,
            destination: tunnel.dest_ip,
            status: LspStatus::Up,
            latency_us: {
                let v: f64 = normal_latency.sample(&mut self.rng);
                v.max(100.0) as u64
            },
            jitter_us: {
                let v: f64 = normal_jitter.sample(&mut self.rng);
                v.max(10.0) as u64
            },
            packet_loss_pct: 0.0,
            bandwidth_bps: tunnel.baseline_bandwidth_bps,
            reroute_count: 0,
        }
    }

    fn make_baseline_interface(&mut self, site: &SiteProfile) -> InterfaceMetrics {
        let iface = if site.interfaces.is_empty() {
            InterfaceProfile {
                device_hostname: "default".into(),
                name: "GigE0/0/0".into(),
                baseline_utilization_pct: 30.0,
                capacity_bps: 1_000_000_000,
            }
        } else {
            site.interfaces[self.rng.random_range(0..site.interfaces.len())].clone()
        };

        let normal_util = Normal::new(iface.baseline_utilization_pct, 5.0).unwrap();
        let util = normal_util.sample(&mut self.rng).clamp(0.0, 80.0);

        InterfaceMetrics {
            interface_name: iface.name,
            oper_status: InterfaceStatus::Up,
            in_bps: (iface.capacity_bps as f64 * util / 200.0) as u64,
            out_bps: (iface.capacity_bps as f64 * util / 200.0) as u64,
            in_pps: self.rng.random_range(10_000..500_000),
            out_pps: self.rng.random_range(10_000..500_000),
            in_errors: self.rng.random_range(0..5),
            out_errors: self.rng.random_range(0..3),
            in_discards: 0,
            out_discards: 0,
            utilization_pct: util,
            crc_errors: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_events_without_panic() {
        let mut generator = TelemetryGenerator::new(GeneratorConfig {
            anomaly_rate: 0.05,
            enabled_anomalies: vec![],
            active_scenario: None,
        });
        let batch = generator.generate_batch(100);
        assert_eq!(batch.len(), 100);
    }

    #[test]
    fn zero_anomaly_rate_produces_normal_events() {
        let config = GeneratorConfig {
            anomaly_rate: 0.0,
            enabled_anomalies: vec![],
            active_scenario: None,
        };
        let mut generator = TelemetryGenerator::new(config);
        let batch = generator.generate_batch(50);
        for event in &batch {
            assert_ne!(
                event.event.severity(),
                Severity::Critical,
                "Normal event should not be critical: {:?}",
                event.event.protocol_name()
            );
        }
    }

    #[test]
    fn sequence_numbers_increment() {
        let mut generator = TelemetryGenerator::new(GeneratorConfig {
            anomaly_rate: 0.05,
            enabled_anomalies: vec![],
            active_scenario: None,
        });
        let batch = generator.generate_batch(10);
        for (i, event) in batch.iter().enumerate() {
            assert_eq!(event.sequence_number, (i + 1) as u64);
        }
    }

    #[test]
    fn events_serialize_to_json() {
        let mut generator = TelemetryGenerator::new(GeneratorConfig {
            anomaly_rate: 0.05,
            enabled_anomalies: vec![],
            active_scenario: None,
        });
        let event = generator.generate_event();
        let json = serde_json::to_string(&event);
        assert!(json.is_ok(), "Event should serialize to JSON");
    }
}
