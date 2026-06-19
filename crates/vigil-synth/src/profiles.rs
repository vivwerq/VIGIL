//! # Network Topology Profiles
//!
//! Defines realistic ISRO ground station network topologies for synthetic
//! data generation. Each profile represents a site with its routers,
//! interfaces, and peering relationships.

use std::net::{IpAddr, Ipv4Addr};
use vigil_core::types::{DeviceType, TelemetrySource};

/// A simulated network site with its devices.
#[derive(Debug, Clone)]
pub struct SiteProfile {
    pub site_id: String,
    pub devices: Vec<TelemetrySource>,
    pub bgp_peers: Vec<BgpPeerProfile>,
    pub lsp_tunnels: Vec<LspProfile>,
    pub interfaces: Vec<InterfaceProfile>,
}

/// A simulated BGP peering relationship.
#[derive(Debug, Clone)]
pub struct BgpPeerProfile {
    pub local_device: String,
    pub peer_ip: IpAddr,
    pub peer_asn: u32,
    pub peer_hostname: String,
    pub prefix_count: u32,
}

/// A simulated MPLS LSP tunnel.
#[derive(Debug, Clone)]
pub struct LspProfile {
    pub name: String,
    pub source_ip: IpAddr,
    pub dest_ip: IpAddr,
    pub baseline_latency_us: u64,
    pub baseline_bandwidth_bps: u64,
}

/// A simulated network interface.
#[derive(Debug, Clone)]
pub struct InterfaceProfile {
    pub device_hostname: String,
    pub name: String,
    pub baseline_utilization_pct: f64,
    pub capacity_bps: u64,
}

/// Create a realistic ISRO ground station network topology.
///
/// Simulates a multi-site MPLS network with:
/// - ISTRAC Bangalore (primary NOC)
/// - ISAC Bangalore (satellite center)  
/// - SDSC Sriharikota (launch complex)
/// - MCF Hassan (deep space network)
/// - Port Blair (remote tracking station)
pub fn isro_network_profile() -> Vec<SiteProfile> {
    vec![
        SiteProfile {
            site_id: "Hub (Bangalore)".into(),
            devices: vec![
                TelemetrySource {
                    hostname: "istrac-core-rtr-01".into(),
                    ip_address: IpAddr::V4(Ipv4Addr::new(10, 1, 1, 1)),
                    device_type: DeviceType::CoreRouter,
                    site_id: "Hub (Bangalore)".into(),
                },
                TelemetrySource {
                    hostname: "istrac-pe-rtr-01".into(),
                    ip_address: IpAddr::V4(Ipv4Addr::new(10, 1, 1, 2)),
                    device_type: DeviceType::PeRouter,
                    site_id: "Hub (Bangalore)".into(),
                },
                TelemetrySource {
                    hostname: "istrac-fw-01".into(),
                    ip_address: IpAddr::V4(Ipv4Addr::new(10, 1, 1, 3)),
                    device_type: DeviceType::Firewall,
                    site_id: "Hub (Bangalore)".into(),
                },
            ],
            bgp_peers: vec![
                BgpPeerProfile {
                    local_device: "istrac-pe-rtr-01".into(),
                    peer_ip: IpAddr::V4(Ipv4Addr::new(10, 2, 1, 2)),
                    peer_asn: 64513,
                    peer_hostname: "isac-pe-rtr-01".into(),
                    prefix_count: 250,
                },
                BgpPeerProfile {
                    local_device: "istrac-pe-rtr-01".into(),
                    peer_ip: IpAddr::V4(Ipv4Addr::new(10, 3, 1, 2)),
                    peer_asn: 64514,
                    peer_hostname: "sdsc-pe-rtr-01".into(),
                    prefix_count: 180,
                },
            ],
            lsp_tunnels: vec![
                LspProfile {
                    name: "LSP-ISTRAC-TO-SDSC".into(),
                    source_ip: IpAddr::V4(Ipv4Addr::new(10, 1, 1, 1)),
                    dest_ip: IpAddr::V4(Ipv4Addr::new(10, 3, 1, 1)),
                    baseline_latency_us: 5000,
                    baseline_bandwidth_bps: 10_000_000_000,
                },
                LspProfile {
                    name: "LSP-ISTRAC-TO-MCF".into(),
                    source_ip: IpAddr::V4(Ipv4Addr::new(10, 1, 1, 1)),
                    dest_ip: IpAddr::V4(Ipv4Addr::new(10, 4, 1, 1)),
                    baseline_latency_us: 8000,
                    baseline_bandwidth_bps: 1_000_000_000,
                },
            ],
            interfaces: vec![
                InterfaceProfile {
                    device_hostname: "istrac-core-rtr-01".into(),
                    name: "TenGigE0/0/0".into(),
                    baseline_utilization_pct: 35.0,
                    capacity_bps: 10_000_000_000,
                },
                InterfaceProfile {
                    device_hostname: "istrac-core-rtr-01".into(),
                    name: "TenGigE0/0/1".into(),
                    baseline_utilization_pct: 42.0,
                    capacity_bps: 10_000_000_000,
                },
            ],
        },
        SiteProfile {
            site_id: "Datacenter (Sriharikota)".into(),
            devices: vec![
                TelemetrySource {
                    hostname: "sdsc-core-rtr-01".into(),
                    ip_address: IpAddr::V4(Ipv4Addr::new(10, 3, 1, 1)),
                    device_type: DeviceType::CoreRouter,
                    site_id: "Datacenter (Sriharikota)".into(),
                },
                TelemetrySource {
                    hostname: "sdsc-pe-rtr-01".into(),
                    ip_address: IpAddr::V4(Ipv4Addr::new(10, 3, 1, 2)),
                    device_type: DeviceType::PeRouter,
                    site_id: "Datacenter (Sriharikota)".into(),
                },
            ],
            bgp_peers: vec![BgpPeerProfile {
                local_device: "sdsc-pe-rtr-01".into(),
                peer_ip: IpAddr::V4(Ipv4Addr::new(10, 1, 1, 2)),
                peer_asn: 64512,
                peer_hostname: "istrac-pe-rtr-01".into(),
                prefix_count: 250,
            }],
            lsp_tunnels: vec![LspProfile {
                name: "LSP-SDSC-TO-ISTRAC".into(),
                source_ip: IpAddr::V4(Ipv4Addr::new(10, 3, 1, 1)),
                dest_ip: IpAddr::V4(Ipv4Addr::new(10, 1, 1, 1)),
                baseline_latency_us: 5000,
                baseline_bandwidth_bps: 10_000_000_000,
            }],
            interfaces: vec![InterfaceProfile {
                device_hostname: "sdsc-core-rtr-01".into(),
                name: "TenGigE0/0/0".into(),
                baseline_utilization_pct: 28.0,
                capacity_bps: 10_000_000_000,
            }],
        },
        SiteProfile {
            site_id: "Branch (Mumbai)".into(),
            devices: vec![TelemetrySource {
                hostname: "mcf-core-rtr-01".into(),
                ip_address: IpAddr::V4(Ipv4Addr::new(10, 4, 1, 1)),
                device_type: DeviceType::CoreRouter,
                site_id: "Branch (Mumbai)".into(),
            }],
            bgp_peers: vec![BgpPeerProfile {
                local_device: "mcf-core-rtr-01".into(),
                peer_ip: IpAddr::V4(Ipv4Addr::new(10, 1, 1, 2)),
                peer_asn: 64512,
                peer_hostname: "istrac-pe-rtr-01".into(),
                prefix_count: 120,
            }],
            lsp_tunnels: vec![],
            interfaces: vec![InterfaceProfile {
                device_hostname: "mcf-core-rtr-01".into(),
                name: "GigE0/0/0".into(),
                baseline_utilization_pct: 15.0,
                capacity_bps: 1_000_000_000,
            }],
        },
    ]
}
