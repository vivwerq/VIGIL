//! # VIGIL Telemetry Data Models
//!
//! These structs define the canonical representation of all network telemetry
//! events flowing through VIGIL. Every field is bounded, validated, and
//! documented.
//!
//! ## Design Principles
//!
//! 1. **No unbounded types from untrusted input** — all strings have max lengths,
//!    all collections have max sizes.
//! 2. **Timestamps are always UTC** — no timezone ambiguity.
//! 3. **Every event has a unique ID** — UUIDv7 (time-ordered) for efficient indexing.
//! 4. **Enums over strings** — protocol types, severities, etc. are enums, not strings.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use uuid::Uuid;

// ─── Envelope: The outer wrapper for ALL telemetry ───────────────────────────

/// The outermost telemetry container. Every piece of telemetry arriving at
/// VIGIL is wrapped in this envelope, which carries the HMAC tag and metadata
/// needed for verification BEFORE the inner payload is parsed.
///
/// ```text
/// ┌──────────────────────────────────────┐
/// │  TelemetryEnvelope                   │
/// │  ├─ id: UUIDv7                       │
/// │  ├─ timestamp: UTC                   │
/// │  ├─ source: TelemetrySource          │
/// │  ├─ hmac_tag: [u8; 32]              │
/// │  └─ event: NetworkEvent (parsed)     │
/// └──────────────────────────────────────┘
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryEnvelope {
    /// Unique event identifier. UUIDv7 provides time-ordering for efficient
    /// database indexing and natural chronological sorting.
    pub id: Uuid,

    /// When this event was generated at the source (UTC).
    /// We validate this against the local clock to detect replay attacks
    /// and clock skew.
    pub timestamp: DateTime<Utc>,

    /// Where this event came from.
    pub source: TelemetrySource,

    /// HMAC-SHA256 tag computed over the serialized `event` payload.
    /// Verified BEFORE the event is parsed to prevent parser exploitation.
    #[serde(with = "hex_bytes")]
    pub hmac_tag: Vec<u8>,

    /// The actual telemetry event, parsed after HMAC verification.
    pub event: NetworkEvent,

    /// Sequence number from the source for ordering and gap detection.
    pub sequence_number: u64,

    /// Optional ground-truth label for anomaly evaluation and prediction lead time.
    #[serde(default)]
    pub ground_truth_label: Option<String>,
}

/// Identifies the source of telemetry data.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct TelemetrySource {
    /// Hostname or device identifier (bounded to 253 chars per RFC 1123).
    pub hostname: String,
    /// IP address of the source device.
    pub ip_address: IpAddr,
    /// Type of device generating telemetry.
    pub device_type: DeviceType,
    /// Site/location identifier (e.g., "ISTRAC-BLR", "ISAC-BLR").
    pub site_id: String,
}

/// Types of network devices in ISRO's ground station infrastructure.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum DeviceType {
    /// Core MPLS router (e.g., Cisco ASR, Juniper MX).
    CoreRouter,
    /// Provider Edge router at site boundary.
    PeRouter,
    /// Customer Edge router at ground station.
    CeRouter,
    /// Layer 2/3 switch.
    Switch,
    /// Firewall/security appliance.
    Firewall,
    /// Network management station.
    Nms,
    /// Unknown device type — logged for investigation.
    Unknown,
}

// ─── Network Events: The actual telemetry data ──────────────────────────────

/// Top-level enum for all network event types.
/// Each variant carries protocol-specific data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkEvent {
    /// BGP routing protocol event.
    Bgp(BgpEvent),
    /// MPLS label-switched path event.
    Mpls(MplsEvent),
    /// SNMP trap/notification.
    Snmp(SnmpTrap),
    /// OSPF routing protocol event.
    Ospf(OspfEvent),
    /// Interface performance metrics.
    Interface(InterfaceMetrics),
    /// LSP (Label Switched Path) metrics.
    Lsp(LspMetrics),
}

impl NetworkEvent {
    /// Returns the protocol name for logging and classification.
    pub fn protocol_name(&self) -> &'static str {
        match self {
            Self::Bgp(_) => "BGP",
            Self::Mpls(_) => "MPLS",
            Self::Snmp(_) => "SNMP",
            Self::Ospf(_) => "OSPF",
            Self::Interface(_) => "INTERFACE",
            Self::Lsp(_) => "LSP",
        }
    }

    /// Returns the severity of this event for prioritization.
    pub fn severity(&self) -> Severity {
        match self {
            Self::Bgp(e) => e.severity(),
            Self::Mpls(e) => e.severity(),
            Self::Snmp(e) => e.severity,
            Self::Ospf(e) => e.severity(),
            Self::Interface(e) => e.severity(),
            Self::Lsp(e) => e.severity(),
        }
    }
}

// ─── BGP Events ─────────────────────────────────────────────────────────────

/// BGP (Border Gateway Protocol) event types relevant to MPLS network health.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BgpEvent {
    /// Type of BGP event.
    pub event_type: BgpEventType,
    /// The BGP peer involved.
    pub peer: BgpPeer,
    /// Number of prefixes affected (bounded).
    pub affected_prefixes: u32,
    /// AS path length (shorter = more direct routing).
    pub as_path_length: u8,
    /// Local preference value.
    pub local_preference: u32,
    /// Multi-Exit Discriminator.
    pub med: u32,
    /// Human-readable description.
    pub description: String,
}

impl BgpEvent {
    pub fn severity(&self) -> Severity {
        match self.event_type {
            BgpEventType::SessionDown | BgpEventType::SessionFlap => Severity::Critical,
            BgpEventType::RouteWithdraw => Severity::High,
            BgpEventType::RouteAdvertise | BgpEventType::SessionUp => Severity::Info,
            BgpEventType::AttributeChange => Severity::Medium,
            BgpEventType::PrefixLimitWarning => Severity::High,
            BgpEventType::RouteLeakDetected => Severity::Critical,
        }
    }
}

/// Specific BGP event subtypes.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum BgpEventType {
    /// Peer session came up.
    SessionUp,
    /// Peer session went down.
    SessionDown,
    /// Peer session is flapping (rapid up/down cycles).
    SessionFlap,
    /// New routes advertised.
    RouteAdvertise,
    /// Routes withdrawn.
    RouteWithdraw,
    /// Route attributes changed (local-pref, MED, etc.).
    AttributeChange,
    /// Approaching prefix limit on a peer.
    PrefixLimitWarning,
    /// Potential route leak detected (AS path anomaly).
    RouteLeakDetected,
}

/// BGP peer information.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BgpPeer {
    /// Peer IP address.
    pub address: IpAddr,
    /// Peer Autonomous System Number.
    pub asn: u32,
    /// Peer hostname (if known).
    pub hostname: Option<String>,
    /// BGP session state.
    pub state: BgpSessionState,
}

/// BGP session states (RFC 4271 FSM).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum BgpSessionState {
    Idle,
    Connect,
    Active,
    OpenSent,
    OpenConfirm,
    Established,
}

// ─── MPLS Events ────────────────────────────────────────────────────────────

/// MPLS (Multiprotocol Label Switching) event data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MplsEvent {
    /// Type of MPLS event.
    pub event_type: MplsEventType,
    /// Label stack (bounded to MAX_MPLS_LABEL_STACK_DEPTH).
    pub label_stack: Vec<u32>,
    /// Forwarding Equivalence Class identifier.
    pub fec: String,
    /// VRF (Virtual Routing and Forwarding) name.
    pub vrf: Option<String>,
    /// Tunnel/LSP identifier.
    pub tunnel_id: Option<String>,
    /// Description.
    pub description: String,
}

impl MplsEvent {
    pub fn severity(&self) -> Severity {
        match self.event_type {
            MplsEventType::LspDown | MplsEventType::LabelStackCorruption => Severity::Critical,
            MplsEventType::LspReroute | MplsEventType::LspFlap => Severity::High,
            MplsEventType::LspUp | MplsEventType::LabelSwitch => Severity::Info,
            MplsEventType::TrafficEngOverload => Severity::High,
        }
    }
}

/// MPLS event subtypes.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum MplsEventType {
    /// LSP came up.
    LspUp,
    /// LSP went down.
    LspDown,
    /// LSP rerouted to backup path.
    LspReroute,
    /// LSP flapping (rapid state changes).
    LspFlap,
    /// Normal label switching operation.
    LabelSwitch,
    /// Label stack corruption detected.
    LabelStackCorruption,
    /// Traffic engineering threshold exceeded.
    TrafficEngOverload,
}

// ─── SNMP Traps ─────────────────────────────────────────────────────────────

/// SNMP trap/notification event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnmpTrap {
    /// SNMP OID (Object Identifier).
    pub oid: String,
    /// Trap type (generic or enterprise-specific).
    pub trap_type: SnmpTrapType,
    /// Severity as reported by the device.
    pub severity: Severity,
    /// Variable bindings (OID → value pairs). Bounded to prevent DoS.
    pub varbinds: Vec<SnmpVarbind>,
    /// Community string (should be rotated; included for audit trail).
    pub community: String,
    /// Description.
    pub description: String,
}

/// SNMP trap categories.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum SnmpTrapType {
    LinkUp,
    LinkDown,
    ColdStart,
    WarmStart,
    AuthenticationFailure,
    EgpNeighborLoss,
    EnterpriseSpecific,
}

/// A single SNMP variable binding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnmpVarbind {
    /// OID of the variable.
    pub oid: String,
    /// Value as a string (all SNMP types normalized to string for storage).
    pub value: String,
}

// ─── OSPF Events ────────────────────────────────────────────────────────────

/// OSPF routing protocol event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OspfEvent {
    /// Type of OSPF event.
    pub event_type: OspfEventType,
    /// OSPF area ID.
    pub area_id: String,
    /// Neighbor router ID.
    pub neighbor_id: Option<IpAddr>,
    /// Neighbor state.
    pub neighbor_state: Option<OspfNeighborState>,
    /// Number of LSAs in the database change.
    pub lsa_count: u32,
    /// Description.
    pub description: String,
}

impl OspfEvent {
    pub fn severity(&self) -> Severity {
        match self.event_type {
            OspfEventType::NeighborDown | OspfEventType::AreaPartition => Severity::Critical,
            OspfEventType::SpfRecalculation => Severity::High,
            OspfEventType::NeighborUp => Severity::Info,
            OspfEventType::LsaUpdate | OspfEventType::InterfaceStateChange => Severity::Medium,
        }
    }
}

/// OSPF event subtypes.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum OspfEventType {
    NeighborUp,
    NeighborDown,
    SpfRecalculation,
    LsaUpdate,
    InterfaceStateChange,
    AreaPartition,
}

/// OSPF neighbor states (RFC 2328).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum OspfNeighborState {
    Down,
    Attempt,
    Init,
    TwoWay,
    ExStart,
    Exchange,
    Loading,
    Full,
}

// ─── Interface Metrics ──────────────────────────────────────────────────────

/// Network interface performance metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceMetrics {
    /// Interface name (e.g., "GigabitEthernet0/0/0").
    pub interface_name: String,
    /// Interface operational status.
    pub oper_status: InterfaceStatus,
    /// Input bytes per second.
    pub in_bps: u64,
    /// Output bytes per second.
    pub out_bps: u64,
    /// Input packets per second.
    pub in_pps: u64,
    /// Output packets per second.
    pub out_pps: u64,
    /// Input errors per second.
    pub in_errors: u64,
    /// Output errors per second.
    pub out_errors: u64,
    /// Input discards per second.
    pub in_discards: u64,
    /// Output discards per second.
    pub out_discards: u64,
    /// Interface utilization percentage (0.0–100.0).
    pub utilization_pct: f64,
    /// CRC errors (indicates physical layer problems).
    pub crc_errors: u64,
}

impl InterfaceMetrics {
    pub fn severity(&self) -> Severity {
        if self.oper_status == InterfaceStatus::Down {
            return Severity::Critical;
        }
        if self.utilization_pct > 90.0 {
            return Severity::High;
        }
        if self.in_errors > 100 || self.out_errors > 100 || self.crc_errors > 0 {
            return Severity::Medium;
        }
        Severity::Info
    }
}

/// Interface operational status.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum InterfaceStatus {
    Up,
    Down,
    Testing,
    Dormant,
    NotPresent,
    LowerLayerDown,
}

// ─── LSP Metrics ────────────────────────────────────────────────────────────

/// Label Switched Path performance metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LspMetrics {
    /// LSP name/identifier.
    pub lsp_name: String,
    /// Source PE router.
    pub source: IpAddr,
    /// Destination PE router.
    pub destination: IpAddr,
    /// Current operational status.
    pub status: LspStatus,
    /// Round-trip latency in microseconds.
    pub latency_us: u64,
    /// Jitter in microseconds.
    pub jitter_us: u64,
    /// Packet loss percentage (0.0–100.0).
    pub packet_loss_pct: f64,
    /// Bandwidth utilization in bits per second.
    pub bandwidth_bps: u64,
    /// Number of reroutes in the last measurement window.
    pub reroute_count: u32,
}

impl LspMetrics {
    pub fn severity(&self) -> Severity {
        if self.status == LspStatus::Down {
            return Severity::Critical;
        }
        if self.packet_loss_pct > 1.0 || self.latency_us > 100_000 {
            return Severity::High;
        }
        if self.jitter_us > 50_000 || self.reroute_count > 3 {
            return Severity::Medium;
        }
        Severity::Info
    }
}

/// LSP operational status.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum LspStatus {
    Up,
    Down,
    Degraded,
    Rerouted,
}

// ─── Severity ───────────────────────────────────────────────────────────────

/// Event severity levels for prioritization and alerting.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Info => write!(f, "INFO"),
            Self::Low => write!(f, "LOW"),
            Self::Medium => write!(f, "MEDIUM"),
            Self::High => write!(f, "HIGH"),
            Self::Critical => write!(f, "CRITICAL"),
        }
    }
}

// ─── Hex Serialization Helper ───────────────────────────────────────────────

/// Serde helper for serializing/deserializing byte arrays as hex strings.
mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let hex_string: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
        serializer.serialize_str(&hex_string)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(serde::de::Error::custom))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn bgp_session_down_is_critical() {
        let event = BgpEvent {
            event_type: BgpEventType::SessionDown,
            peer: BgpPeer {
                address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                asn: 64512,
                hostname: Some("pe-router-01".into()),
                state: BgpSessionState::Idle,
            },
            affected_prefixes: 150,
            as_path_length: 3,
            local_preference: 100,
            med: 0,
            description: "BGP session down".into(),
        };
        assert_eq!(event.severity(), Severity::Critical);
    }

    #[test]
    fn interface_down_is_critical() {
        let metrics = InterfaceMetrics {
            interface_name: "GigabitEthernet0/0/0".into(),
            oper_status: InterfaceStatus::Down,
            in_bps: 0,
            out_bps: 0,
            in_pps: 0,
            out_pps: 0,
            in_errors: 0,
            out_errors: 0,
            in_discards: 0,
            out_discards: 0,
            utilization_pct: 0.0,
            crc_errors: 0,
        };
        assert_eq!(metrics.severity(), Severity::Critical);
    }

    #[test]
    fn envelope_serializes_to_json() {
        let envelope = TelemetryEnvelope {
            id: Uuid::now_v7(),
            timestamp: Utc::now(),
            source: TelemetrySource {
                hostname: "core-rtr-01".into(),
                ip_address: IpAddr::V4(Ipv4Addr::new(10, 1, 1, 1)),
                device_type: DeviceType::CoreRouter,
                site_id: "ISTRAC-BLR".into(),
            },
            hmac_tag: vec![0xDE, 0xAD, 0xBE, 0xEF],
            event: NetworkEvent::Bgp(BgpEvent {
                event_type: BgpEventType::SessionUp,
                peer: BgpPeer {
                    address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                    asn: 64513,
                    hostname: None,
                    state: BgpSessionState::Established,
                },
                affected_prefixes: 0,
                as_path_length: 1,
                local_preference: 100,
                med: 0,
                description: "Peer up".into(),
            }),
            sequence_number: 1,
            ground_truth_label: None,
        };

        let json = serde_json::to_string_pretty(&envelope).unwrap();
        assert!(json.contains("core-rtr-01"));
        assert!(json.contains("ISTRAC-BLR"));
    }

    #[test]
    fn severity_ordering_is_correct() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
        assert!(Severity::Low > Severity::Info);
    }
}
