//! # Playbook Engine for Incident Remediation
//!
//! Stores and suggests specific Cisco/Juniper/ISRO-centric CLI remediation commands
//! for network anomalies, enabling operators to react in seconds.

use crate::types::NetworkEvent;
use serde::{Deserialize, Serialize};

/// Remediation playbook suggestions for a specific anomaly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationPlaybook {
    /// Friendly name of the playbook.
    pub name: String,
    /// Ordered list of commands suggested for operators.
    pub suggested_commands: Vec<String>,
    /// Rationale for the suggestion.
    pub reasoning: String,
}

/// Query the playbook database for the given network event.
///
/// NOTE (Vivek): I hardcoded some common playbooks for ISRO's routers (Cisco/Juniper style commands).
/// Instead of operators scratching their heads at 3 AM looking at RFC docs, they get copy-pasteable
/// CLI diagnostic commands immediately on the dashboard.
pub fn suggest_playbook(event: &NetworkEvent) -> RemediationPlaybook {
    match event {
        NetworkEvent::Bgp(bgp) => {
            let peer_ip = bgp.peer.address;
            RemediationPlaybook {
                name: "BGP Session Degraded / Down".to_string(),
                suggested_commands: vec![
                    format!("show ip bgp summary | include {}", peer_ip),
                    format!("show ip bgp neighbors {} advertised-routes", peer_ip),
                    format!("ping {} source Loopback0", peer_ip),
                    format!("clear ip bgp {} soft in", peer_ip),
                ],
                reasoning: format!(
                    "BGP peer {} moved to state {:?}. Verify IP connectivity first, check for prefix-limit violations, then perform a soft inbound reset.",
                    peer_ip, bgp.peer.state
                ),
            }
        }
        NetworkEvent::Ospf(ospf) => {
            let neighbor = ospf
                .neighbor_id
                .map(|ip| ip.to_string())
                .unwrap_or_else(|| "unknown".to_string());
            let state = ospf
                .neighbor_state
                .map(|s| format!("{:?}", s))
                .unwrap_or_else(|| "unknown".to_string());
            RemediationPlaybook {
                name: "OSPF Adjacency Flap".to_string(),
                suggested_commands: vec![
                    format!("show ip ospf neighbor {}", neighbor),
                    format!("show ip ospf interface brief"),
                    format!("ping {} size 1500 df-bit", neighbor), // MTU verification
                    format!("clear ip ospf {} process", neighbor),
                ],
                reasoning: format!(
                    "OSPF neighbor {} transitioned to state {}. Check MTU mismatches, verify subnets match, and test ping with DF bit set.",
                    neighbor, state
                ),
            }
        }
        NetworkEvent::Mpls(mpls) => {
            let link = mpls.tunnel_id.as_deref().unwrap_or(&mpls.fec);
            RemediationPlaybook {
                name: "MPLS Label Switched Path (LSP) Alert".to_string(),
                suggested_commands: vec![
                    format!("show mpls ldp neighbor"),
                    format!("show mpls forwarding-table detail | include {}", link),
                    format!("traceroute mpls ipv4 {}", link),
                    format!("show mpls traffic-eng tunnels name {}", link),
                ],
                reasoning: "MPLS signaling or label distribution failure. Check LDP binding tables, verify fast-reroute tunnel states, and run LSP traceroute to identify the breaking node.".to_string(),
            }
        }
        NetworkEvent::Lsp(lsp) => {
            let lsp_name = &lsp.lsp_name;
            RemediationPlaybook {
                name: "LSP Performance Degradation".to_string(),
                suggested_commands: vec![
                    format!("show mpls traffic-eng tunnels name {}", lsp_name),
                    format!("show running-config interface tunnel-te {}", lsp_name),
                    format!("ping mpls ipv4 {} tunnel {}", lsp_name, lsp_name),
                ],
                reasoning: format!(
                    "LSP {} is experiencing packet loss or high latency. Verify TE tunnel path parameters, operational state, and path protection tunnel configs.",
                    lsp_name
                ),
            }
        }
        NetworkEvent::Interface(intf) => {
            let name = &intf.interface_name;
            RemediationPlaybook {
                name: "Physical Link / Port Saturation".to_string(),
                suggested_commands: vec![
                    format!("show interfaces {} status", name),
                    format!("show interfaces {} counters errors", name),
                    format!("show policy-map interface {}", name),
                ],
                reasoning: format!(
                    "Interface {} is reporting anomalous rates, potential optics degradation, or port errors. Check CRC alignment error counters, optical power levels, and QoS queue drops.",
                    name
                ),
            }
        }
        NetworkEvent::Snmp(snmp) => {
            let oid = &snmp.oid;
            RemediationPlaybook {
                name: "Critical SNMP Trap Received".to_string(),
                suggested_commands: vec![
                    "show logging".to_string(),
                    format!("show snmp status"),
                    format!("show snmp mib object {}", oid),
                ],
                reasoning: format!(
                    "System alert received from node via SNMP trap with OID: {}. Check local syslog buffer and query MIB definitions for trap details.",
                    oid
                ),
            }
        }
    }
}
