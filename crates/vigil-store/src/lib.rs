//! # VIGIL Embedded Storage
//!
//! Robust, memory-safe, ACID-compliant embedded database layer for the VIGIL system.
//! Powered by `redb` (a pure-Rust, single-file copy-on-write B-tree database).
//!
//! ## Tables & Schema
//!
//! 1. **`TELEMETRY_TABLE`**: Key is `[u8; 16]` (UUIDv7 bytes). Value is serialized `TelemetryEnvelope` (bincode).
//! 2. **`ANOMALY_TABLE`**: Key is `[u8; 16]` (AnomalyReport ID bytes). Value is serialized `AnomalyReport` (bincode).
//! 3. **`INDEX_SOURCE_TELEMETRY`**: Key is composite `(source_hostname, UUID)`. Value is `()`.
//! 4. **`INDEX_PROTOCOL_TELEMETRY`**: Key is composite `(protocol_name, UUID)`. Value is `()`.
//! 5. **`INDEX_ENVELOPE_ANOMALY`**: Key is `[u8; 16]` (Telemetry Envelope ID). Value is `[u8; 16]` (AnomalyReport ID).
//!
//! ## Time-Series Queries
//!
//! Since we use UUIDv7 for all primary keys, the keys themselves are naturally
//! sorted by their creation timestamp (the first 48 bits contain Unix timestamp in ms).
//! Lexicographical range queries on the keys map directly to time-range queries.

use std::path::Path;
use std::sync::{Arc, RwLock};

use chrono::{DateTime, Duration, Utc};
use redb::{Database, ReadableTable, TableDefinition};
use uuid::Uuid;
use vigil_core::error::{VigilError, VigilResult};
use vigil_core::types::TelemetryEnvelope;
use vigil_detect::results::AnomalyReport;

// ─── Table Definitions ──────────────────────────────────────────────────────

const TELEMETRY_TABLE: TableDefinition<[u8; 16], &[u8]> = TableDefinition::new("telemetry");
const ANOMALY_TABLE: TableDefinition<[u8; 16], &[u8]> = TableDefinition::new("anomaly_reports");
const DIAGNOSTIC_TABLE: TableDefinition<[u8; 16], &[u8]> =
    TableDefinition::new("diagnostic_reports");

// Indexes
const INDEX_SOURCE_TELEMETRY: TableDefinition<&[u8], ()> =
    TableDefinition::new("idx_source_telemetry");
const INDEX_PROTOCOL_TELEMETRY: TableDefinition<&[u8], ()> =
    TableDefinition::new("idx_protocol_telemetry");
const INDEX_ENVELOPE_ANOMALY: TableDefinition<[u8; 16], [u8; 16]> =
    TableDefinition::new("idx_envelope_anomaly");

// ─── Query Filters ──────────────────────────────────────────────────────────

/// Query filter for retrieving historical telemetry.
#[derive(Debug, Clone, Default)]
pub struct TelemetryQueryFilter {
    /// Start of time window (inclusive).
    pub start_time: Option<DateTime<Utc>>,
    /// End of time window (inclusive).
    pub end_time: Option<DateTime<Utc>>,
    /// Filter by specific telemetry source hostname.
    pub source: Option<String>,
    /// Filter by specific protocol (e.g. "Bgp", "Mpls", "Snmp").
    pub protocol: Option<String>,
    /// Maximum number of records to return.
    pub limit: Option<usize>,
}

/// Query filter for retrieving anomaly reports.
#[derive(Debug, Clone, Default)]
pub struct AnomalyQueryFilter {
    /// Start of time window (inclusive).
    pub start_time: Option<DateTime<Utc>>,
    /// End of time window (inclusive).
    pub end_time: Option<DateTime<Utc>>,
    /// Filter by whether the report was flagged as anomalous.
    pub is_anomalous: Option<bool>,
    /// Minimum anomaly score to retrieve.
    pub min_score: Option<f64>,
    /// Maximum number of records to return.
    pub limit: Option<usize>,
}

/// Results returned by a database pruning operation.
#[derive(Debug, Clone, Copy, Default)]
pub struct PruneResult {
    /// Number of telemetry envelopes deleted.
    pub telemetry_deleted: u64,
    /// Number of anomaly reports deleted.
    pub anomalies_deleted: u64,
}

// ─── Main Store Struct ──────────────────────────────────────────────────────

/// Embedded database manager for VIGIL telemetry and anomaly records.
///
/// Wraps a `redb` database instance protected by a RwLock for administrative compaction.
/// Cheaply cloneable and thread-safe.
// NOTE (Vivek): I chose redb because managing SQLite or PostgreSQL in an air-gapped system
// is a massive headache. This compiles down to a single file and gives us ACID guarantees
// without needing a running database daemon. Saved me hours of config time while studying for exams.
#[derive(Clone)]
pub struct VigilStore {
    db: Arc<RwLock<Database>>,
}

impl VigilStore {
    /// Open or create the VIGIL database at the specified path.
    pub fn open<P: AsRef<Path>>(path: P) -> VigilResult<Self> {
        let db = Database::create(path).map_err(|e| VigilError::DatabaseError {
            operation: "Open/Create Database".into(),
            reason: e.to_string(),
        })?;

        // Initialize tables by performing a dummy write transaction.
        let write_txn = db.begin_write().map_err(|e| VigilError::DatabaseError {
            operation: "Init Transaction".into(),
            reason: e.to_string(),
        })?;
        {
            let _ =
                write_txn
                    .open_table(TELEMETRY_TABLE)
                    .map_err(|e| VigilError::DatabaseError {
                        operation: "Init Table: telemetry".into(),
                        reason: e.to_string(),
                    })?;
            let _ = write_txn
                .open_table(ANOMALY_TABLE)
                .map_err(|e| VigilError::DatabaseError {
                    operation: "Init Table: anomalies".into(),
                    reason: e.to_string(),
                })?;
            let _ =
                write_txn
                    .open_table(DIAGNOSTIC_TABLE)
                    .map_err(|e| VigilError::DatabaseError {
                        operation: "Init Table: diagnostics".into(),
                        reason: e.to_string(),
                    })?;
            let _ = write_txn.open_table(INDEX_SOURCE_TELEMETRY).map_err(|e| {
                VigilError::DatabaseError {
                    operation: "Init Table: idx_source".into(),
                    reason: e.to_string(),
                }
            })?;
            let _ = write_txn
                .open_table(INDEX_PROTOCOL_TELEMETRY)
                .map_err(|e| VigilError::DatabaseError {
                    operation: "Init Table: idx_protocol".into(),
                    reason: e.to_string(),
                })?;
            let _ = write_txn.open_table(INDEX_ENVELOPE_ANOMALY).map_err(|e| {
                VigilError::DatabaseError {
                    operation: "Init Table: idx_envelope_anomaly".into(),
                    reason: e.to_string(),
                }
            })?;
        }
        write_txn.commit().map_err(|e| VigilError::DatabaseError {
            operation: "Commit Init".into(),
            reason: e.to_string(),
        })?;

        Ok(Self {
            db: Arc::new(RwLock::new(db)),
        })
    }

    // ─── Write Operations ───────────────────────────────────────────────────

    /// Insert a telemetry envelope and update all corresponding indexes.
    pub fn insert_telemetry(&self, envelope: &TelemetryEnvelope) -> VigilResult<()> {
        let serialized = bincode::serialize(envelope).map_err(|e| VigilError::DatabaseError {
            operation: "Serialize Telemetry".into(),
            reason: e.to_string(),
        })?;

        let key = envelope.id.into_bytes();
        let protocol_name = get_protocol_name(&envelope.event);

        let db_ref = self.db.read().map_err(|e| VigilError::DatabaseError {
            operation: "Acquire DB Read Lock".into(),
            reason: e.to_string(),
        })?;

        let write_txn = db_ref
            .begin_write()
            .map_err(|e| VigilError::DatabaseError {
                operation: "Begin Write".into(),
                reason: e.to_string(),
            })?;

        {
            // 1. Insert into main telemetry table.
            let mut table =
                write_txn
                    .open_table(TELEMETRY_TABLE)
                    .map_err(|e| VigilError::DatabaseError {
                        operation: "Open Table".into(),
                        reason: e.to_string(),
                    })?;
            table
                .insert(key, serialized.as_slice())
                .map_err(|e| VigilError::DatabaseError {
                    operation: "Insert Telemetry".into(),
                    reason: e.to_string(),
                })?;

            // 2. Insert into source index.
            let mut src_table = write_txn.open_table(INDEX_SOURCE_TELEMETRY).map_err(|e| {
                VigilError::DatabaseError {
                    operation: "Open Source Index".into(),
                    reason: e.to_string(),
                }
            })?;
            let src_key = make_composite_index_key(&envelope.source.hostname, &key);
            src_table
                .insert(src_key.as_slice(), &())
                .map_err(|e| VigilError::DatabaseError {
                    operation: "Insert Source Index".into(),
                    reason: e.to_string(),
                })?;

            // 3. Insert into protocol index.
            let mut proto_table = write_txn
                .open_table(INDEX_PROTOCOL_TELEMETRY)
                .map_err(|e| VigilError::DatabaseError {
                    operation: "Open Protocol Index".into(),
                    reason: e.to_string(),
                })?;
            let proto_key = make_composite_index_key(protocol_name, &key);
            proto_table.insert(proto_key.as_slice(), &()).map_err(|e| {
                VigilError::DatabaseError {
                    operation: "Insert Protocol Index".into(),
                    reason: e.to_string(),
                }
            })?;
        }

        write_txn.commit().map_err(|e| VigilError::DatabaseError {
            operation: "Commit Write Telemetry".into(),
            reason: e.to_string(),
        })?;

        Ok(())
    }

    /// Insert an anomaly report and update the envelope-to-anomaly lookup index.
    pub fn insert_anomaly_report(&self, report: &AnomalyReport) -> VigilResult<()> {
        let serialized = bincode::serialize(report).map_err(|e| VigilError::DatabaseError {
            operation: "Serialize AnomalyReport".into(),
            reason: e.to_string(),
        })?;

        let key = report.id.into_bytes();
        let envelope_key = report.envelope_id.into_bytes();

        let db_ref = self.db.read().map_err(|e| VigilError::DatabaseError {
            operation: "Acquire DB Read Lock".into(),
            reason: e.to_string(),
        })?;

        let write_txn = db_ref
            .begin_write()
            .map_err(|e| VigilError::DatabaseError {
                operation: "Begin Write".into(),
                reason: e.to_string(),
            })?;

        {
            // 1. Insert into main anomaly table.
            let mut table =
                write_txn
                    .open_table(ANOMALY_TABLE)
                    .map_err(|e| VigilError::DatabaseError {
                        operation: "Open Anomaly Table".into(),
                        reason: e.to_string(),
                    })?;
            table
                .insert(key, serialized.as_slice())
                .map_err(|e| VigilError::DatabaseError {
                    operation: "Insert AnomalyReport".into(),
                    reason: e.to_string(),
                })?;

            // 2. Insert into envelope lookup index.
            let mut lookup_table = write_txn.open_table(INDEX_ENVELOPE_ANOMALY).map_err(|e| {
                VigilError::DatabaseError {
                    operation: "Open Envelope Index".into(),
                    reason: e.to_string(),
                }
            })?;
            lookup_table
                .insert(envelope_key, key)
                .map_err(|e| VigilError::DatabaseError {
                    operation: "Insert Envelope Lookup Index".into(),
                    reason: e.to_string(),
                })?;
        }

        write_txn.commit().map_err(|e| VigilError::DatabaseError {
            operation: "Commit Write AnomalyReport".into(),
            reason: e.to_string(),
        })?;

        Ok(())
    }

    /// Insert a diagnostic report associated with an anomaly report ID.
    pub fn insert_diagnostic_report(
        &self,
        anomaly_id: &Uuid,
        report_bytes: &[u8],
    ) -> VigilResult<()> {
        let key = anomaly_id.into_bytes();

        let db_ref = self.db.read().map_err(|e| VigilError::DatabaseError {
            operation: "Acquire DB Read Lock".into(),
            reason: e.to_string(),
        })?;

        let write_txn = db_ref
            .begin_write()
            .map_err(|e| VigilError::DatabaseError {
                operation: "Begin Write".into(),
                reason: e.to_string(),
            })?;

        {
            let mut table =
                write_txn
                    .open_table(DIAGNOSTIC_TABLE)
                    .map_err(|e| VigilError::DatabaseError {
                        operation: "Open Diagnostic Table".into(),
                        reason: e.to_string(),
                    })?;
            table
                .insert(key, report_bytes)
                .map_err(|e| VigilError::DatabaseError {
                    operation: "Insert DiagnosticReport".into(),
                    reason: e.to_string(),
                })?;
        }

        write_txn.commit().map_err(|e| VigilError::DatabaseError {
            operation: "Commit Write DiagnosticReport".into(),
            reason: e.to_string(),
        })?;

        Ok(())
    }

    // ─── Read Operations ────────────────────────────────────────────────────

    /// Retrieve a single telemetry envelope by its ID.
    pub fn get_telemetry(&self, id: Uuid) -> VigilResult<Option<TelemetryEnvelope>> {
        let db_ref = self.db.read().map_err(|e| VigilError::DatabaseError {
            operation: "Acquire DB Read Lock".into(),
            reason: e.to_string(),
        })?;

        let read_txn = db_ref.begin_read().map_err(|e| VigilError::DatabaseError {
            operation: "Begin Read".into(),
            reason: e.to_string(),
        })?;
        let table =
            read_txn
                .open_table(TELEMETRY_TABLE)
                .map_err(|e| VigilError::DatabaseError {
                    operation: "Open Table".into(),
                    reason: e.to_string(),
                })?;

        let val_guard = table
            .get(id.into_bytes())
            .map_err(|e| VigilError::DatabaseError {
                operation: "Get Telemetry".into(),
                reason: e.to_string(),
            })?;

        match val_guard {
            Some(guard) => {
                match bincode::deserialize(guard.value()) {
                    Ok(envelope) => Ok(Some(envelope)),
                    Err(e) => {
                        tracing::warn!("Failed to deserialize Telemetry: {}. Returning None.", e);
                        Ok(None)
                    }
                }
            }
            None => Ok(None),
        }
    }

    /// Retrieve a single anomaly report by its ID.
    pub fn get_anomaly_report(&self, id: Uuid) -> VigilResult<Option<AnomalyReport>> {
        let db_ref = self.db.read().map_err(|e| VigilError::DatabaseError {
            operation: "Acquire DB Read Lock".into(),
            reason: e.to_string(),
        })?;

        let read_txn = db_ref.begin_read().map_err(|e| VigilError::DatabaseError {
            operation: "Begin Read".into(),
            reason: e.to_string(),
        })?;
        let table = read_txn
            .open_table(ANOMALY_TABLE)
            .map_err(|e| VigilError::DatabaseError {
                operation: "Open Table".into(),
                reason: e.to_string(),
            })?;

        let val_guard = table
            .get(id.into_bytes())
            .map_err(|e| VigilError::DatabaseError {
                operation: "Get AnomalyReport".into(),
                reason: e.to_string(),
            })?;

        match val_guard {
            Some(guard) => {
                match bincode::deserialize(guard.value()) {
                    Ok(report) => Ok(Some(report)),
                    Err(e) => {
                        tracing::warn!("Failed to deserialize AnomalyReport: {}. Returning None.", e);
                        Ok(None)
                    }
                }
            }
            None => Ok(None),
        }
    }

    /// Retrieve a diagnostic report associated with an anomaly report ID.
    pub fn get_diagnostic_report(&self, anomaly_id: Uuid) -> VigilResult<Option<Vec<u8>>> {
        let db_ref = self.db.read().map_err(|e| VigilError::DatabaseError {
            operation: "Acquire DB Read Lock".into(),
            reason: e.to_string(),
        })?;

        let read_txn = db_ref.begin_read().map_err(|e| VigilError::DatabaseError {
            operation: "Begin Read".into(),
            reason: e.to_string(),
        })?;
        let table =
            read_txn
                .open_table(DIAGNOSTIC_TABLE)
                .map_err(|e| VigilError::DatabaseError {
                    operation: "Open Table".into(),
                    reason: e.to_string(),
                })?;

        let val_guard =
            table
                .get(anomaly_id.into_bytes())
                .map_err(|e| VigilError::DatabaseError {
                    operation: "Get DiagnosticReport".into(),
                    reason: e.to_string(),
                })?;

        match val_guard {
            Some(guard) => Ok(Some(guard.value().to_vec())),
            None => Ok(None),
        }
    }

    /// Find an anomaly report associated with a specific telemetry envelope ID.
    pub fn get_anomaly_report_by_envelope(
        &self,
        envelope_id: Uuid,
    ) -> VigilResult<Option<AnomalyReport>> {
        let db_ref = self.db.read().map_err(|e| VigilError::DatabaseError {
            operation: "Acquire DB Read Lock".into(),
            reason: e.to_string(),
        })?;

        let read_txn = db_ref.begin_read().map_err(|e| VigilError::DatabaseError {
            operation: "Begin Read".into(),
            reason: e.to_string(),
        })?;
        let lookup_table =
            read_txn
                .open_table(INDEX_ENVELOPE_ANOMALY)
                .map_err(|e| VigilError::DatabaseError {
                    operation: "Open Lookup Index".into(),
                    reason: e.to_string(),
                })?;

        let report_id_guard =
            lookup_table
                .get(envelope_id.into_bytes())
                .map_err(|e| VigilError::DatabaseError {
                    operation: "Get Lookup Index".into(),
                    reason: e.to_string(),
                })?;

        match report_id_guard {
            Some(guard) => {
                let report_id = Uuid::from_bytes(guard.value());
                // Close transactional read, open new lookup
                drop(lookup_table);
                drop(read_txn);
                drop(db_ref);
                self.get_anomaly_report(report_id)
            }
            None => Ok(None),
        }
    }

    // ─── Query Operations ───────────────────────────────────────────────────

    /// Query historical telemetry matching the given filter.
    pub fn query_telemetry(
        &self,
        filter: TelemetryQueryFilter,
    ) -> VigilResult<Vec<TelemetryEnvelope>> {
        let db_ref = self.db.read().map_err(|e| VigilError::DatabaseError {
            operation: "Acquire DB Read Lock".into(),
            reason: e.to_string(),
        })?;

        let read_txn = db_ref.begin_read().map_err(|e| VigilError::DatabaseError {
            operation: "Begin Read".into(),
            reason: e.to_string(),
        })?;

        let start_key = timestamp_to_uuid_bound(filter.start_time, false);
        let end_key = timestamp_to_uuid_bound(filter.end_time, true);

        let mut uuids = Vec::new();

        if let Some(ref source) = filter.source {
            // Query via source index table
            let table = read_txn.open_table(INDEX_SOURCE_TELEMETRY).map_err(|e| {
                VigilError::DatabaseError {
                    operation: "Open Source Index".into(),
                    reason: e.to_string(),
                }
            })?;

            let range_start = make_composite_index_key(source, &start_key.into_bytes());
            let range_end = make_composite_index_key(source, &end_key.into_bytes());

            let range = table
                .range(range_start.as_slice()..=range_end.as_slice())
                .map_err(|e| VigilError::DatabaseError {
                    operation: "Range Source Index".into(),
                    reason: e.to_string(),
                })?;

            for entry in range.rev() {
                let (key_guard, _) = entry.map_err(|e| VigilError::DatabaseError {
                    operation: "Read Source Index Entry".into(),
                    reason: e.to_string(),
                })?;
                let (_, uuid_bytes) = parse_composite_index_key(key_guard.value());
                uuids.push(Uuid::from_bytes(uuid_bytes));
            }
        } else if let Some(ref protocol) = filter.protocol {
            // Query via protocol index table
            let table = read_txn.open_table(INDEX_PROTOCOL_TELEMETRY).map_err(|e| {
                VigilError::DatabaseError {
                    operation: "Open Protocol Index".into(),
                    reason: e.to_string(),
                }
            })?;

            let range_start = make_composite_index_key(protocol, &start_key.into_bytes());
            let range_end = make_composite_index_key(protocol, &end_key.into_bytes());

            let range = table
                .range(range_start.as_slice()..=range_end.as_slice())
                .map_err(|e| VigilError::DatabaseError {
                    operation: "Range Protocol Index".into(),
                    reason: e.to_string(),
                })?;

            for entry in range.rev() {
                let (key_guard, _) = entry.map_err(|e| VigilError::DatabaseError {
                    operation: "Read Protocol Index Entry".into(),
                    reason: e.to_string(),
                })?;
                let (_, uuid_bytes) = parse_composite_index_key(key_guard.value());
                uuids.push(Uuid::from_bytes(uuid_bytes));
            }
        } else {
            // No index matching — scan main table range directly (since UUIDv7 is time-ordered)
            let table =
                read_txn
                    .open_table(TELEMETRY_TABLE)
                    .map_err(|e| VigilError::DatabaseError {
                        operation: "Open Telemetry Table".into(),
                        reason: e.to_string(),
                    })?;

            let range = table
                .range(start_key.into_bytes()..=end_key.into_bytes())
                .map_err(|e| VigilError::DatabaseError {
                    operation: "Range Telemetry".into(),
                    reason: e.to_string(),
                })?;

            for entry in range.rev() {
                let (key_guard, _) = entry.map_err(|e| VigilError::DatabaseError {
                    operation: "Read Telemetry Entry".into(),
                    reason: e.to_string(),
                })?;
                uuids.push(Uuid::from_bytes(key_guard.value()));
            }
        }

        // Apply limit to UUID retrieval before doing deserialization (saves allocations & cycles)
        if let Some(limit) = filter.limit {
            uuids.truncate(limit);
        }

        // Retrieve actual telemetry objects from main table
        let tel_table =
            read_txn
                .open_table(TELEMETRY_TABLE)
                .map_err(|e| VigilError::DatabaseError {
                    operation: "Open Telemetry Table".into(),
                    reason: e.to_string(),
                })?;

        let mut results = Vec::with_capacity(uuids.len());
        for id in uuids {
            if let Some(guard) =
                tel_table
                    .get(id.into_bytes())
                    .map_err(|e| VigilError::DatabaseError {
                        operation: "Get Telemetry".into(),
                        reason: e.to_string(),
                    })?
            {
                let envelope: TelemetryEnvelope = match bincode::deserialize(guard.value()) {
                    Ok(e) => e,
                    Err(err) => {
                        tracing::warn!("Failed to deserialize Telemetry in query: {}. Skipping.", err);
                        continue;
                    }
                };

                // Secondary filters (if queried by source + protocol, we indexed on source, so we filter by protocol here)
                if let Some(ref protocol) = filter.protocol {
                    if get_protocol_name(&envelope.event) != protocol {
                        continue;
                    }
                }
                if let Some(ref source) = filter.source {
                    if envelope.source.hostname != *source {
                        continue;
                    }
                }

                results.push(envelope);
            }
        }

        Ok(results)
    }

    /// Query anomaly reports matching the given filter.
    pub fn query_anomalies(&self, filter: AnomalyQueryFilter) -> VigilResult<Vec<AnomalyReport>> {
        let db_ref = self.db.read().map_err(|e| VigilError::DatabaseError {
            operation: "Acquire DB Read Lock".into(),
            reason: e.to_string(),
        })?;

        let read_txn = db_ref.begin_read().map_err(|e| VigilError::DatabaseError {
            operation: "Begin Read".into(),
            reason: e.to_string(),
        })?;

        let table = read_txn
            .open_table(ANOMALY_TABLE)
            .map_err(|e| VigilError::DatabaseError {
                operation: "Open Anomaly Table".into(),
                reason: e.to_string(),
            })?;

        let start_key = timestamp_to_uuid_bound(filter.start_time, false);
        let end_key = timestamp_to_uuid_bound(filter.end_time, true);

        let range = table
            .range(start_key.into_bytes()..=end_key.into_bytes())
            .map_err(|e| VigilError::DatabaseError {
                operation: "Range Anomalies".into(),
                reason: e.to_string(),
            })?;

        let mut results = Vec::new();
        for entry in range.rev() {
            let (_, val_guard) = entry.map_err(|e| VigilError::DatabaseError {
                operation: "Read Anomaly Entry".into(),
                reason: e.to_string(),
            })?;

            let report: AnomalyReport = match bincode::deserialize(val_guard.value()) {
                Ok(r) => r,
                Err(err) => {
                    tracing::warn!("Failed to deserialize AnomalyReport in query: {}. Skipping.", err);
                    continue;
                }
            };

            // Apply filters
            if let Some(is_anom) = filter.is_anomalous {
                if report.is_anomalous != is_anom {
                    continue;
                }
            }
            if let Some(min_s) = filter.min_score {
                if report.score < min_s {
                    continue;
                }
            }

            results.push(report);

            if let Some(limit) = filter.limit {
                if results.len() >= limit {
                    break;
                }
            }
        }

        Ok(results)
    }

    // ─── Maintenance & Admin ────────────────────────────────────────────────

    /// Prune telemetry and anomalies older than the specified age.
    ///
    /// Cleans up corresponding indexes in the same transaction to maintain database integrity.
    pub fn prune(&self, max_age: Duration) -> VigilResult<PruneResult> {
        let cutoff_time = Utc::now() - max_age;
        let cutoff_key = timestamp_to_uuid_bound(Some(cutoff_time), false);
        let cutoff_bytes = cutoff_key.into_bytes();

        let db_ref = self.db.read().map_err(|e| VigilError::DatabaseError {
            operation: "Acquire DB Read Lock".into(),
            reason: e.to_string(),
        })?;

        let write_txn = db_ref
            .begin_write()
            .map_err(|e| VigilError::DatabaseError {
                operation: "Begin Prune Transaction".into(),
                reason: e.to_string(),
            })?;

        let mut prune_res = PruneResult::default();

        {
            let mut tel_table =
                write_txn
                    .open_table(TELEMETRY_TABLE)
                    .map_err(|e| VigilError::DatabaseError {
                        operation: "Open Telemetry Table".into(),
                        reason: e.to_string(),
                    })?;
            let mut anom_table =
                write_txn
                    .open_table(ANOMALY_TABLE)
                    .map_err(|e| VigilError::DatabaseError {
                        operation: "Open Anomaly Table".into(),
                        reason: e.to_string(),
                    })?;
            let mut src_index = write_txn.open_table(INDEX_SOURCE_TELEMETRY).map_err(|e| {
                VigilError::DatabaseError {
                    operation: "Open Source Index".into(),
                    reason: e.to_string(),
                }
            })?;
            let mut proto_index = write_txn
                .open_table(INDEX_PROTOCOL_TELEMETRY)
                .map_err(|e| VigilError::DatabaseError {
                    operation: "Open Protocol Index".into(),
                    reason: e.to_string(),
                })?;
            let mut envelope_anom_index =
                write_txn.open_table(INDEX_ENVELOPE_ANOMALY).map_err(|e| {
                    VigilError::DatabaseError {
                        operation: "Open Envelope Anomaly Index".into(),
                        reason: e.to_string(),
                    }
                })?;

            // 1. Scan for telemetry records to prune (range is from start of time until cutoff)
            let start_key = [0u8; 16];
            let range = tel_table.range(start_key..cutoff_bytes).map_err(|e| {
                VigilError::DatabaseError {
                    operation: "Scan Telemetry for Pruning".into(),
                    reason: e.to_string(),
                }
            })?;

            let mut targets = Vec::new();
            for entry in range {
                let (key_guard, val_guard) = entry.map_err(|e| VigilError::DatabaseError {
                    operation: "Read Telemetry Prune Entry".into(),
                    reason: e.to_string(),
                })?;
                let key = key_guard.value();
                match bincode::deserialize::<TelemetryEnvelope>(val_guard.value()) {
                    Ok(envelope) => {
                        targets.push((key, Some(envelope)));
                    }
                    Err(e) => {
                        tracing::warn!("Failed to deserialize Telemetry for Prune: {}. Skipping index updates.", e);
                        targets.push((key, None));
                    }
                }
            }

            // 2. Perform deletion and remove from indexes
            for (key, envelope_opt) in targets {
                // Delete from main table
                tel_table
                    .remove(key)
                    .map_err(|e| VigilError::DatabaseError {
                        operation: "Delete Telemetry".into(),
                        reason: e.to_string(),
                    })?;
                prune_res.telemetry_deleted += 1;

                if let Some(envelope) = &envelope_opt {
                    // Delete from source index
                    let src_key = make_composite_index_key(&envelope.source.hostname, &key);
                    let _ = src_index.remove(src_key.as_slice());

                    // Delete from protocol index
                    let protocol_name = get_protocol_name(&envelope.event);
                    let proto_key = make_composite_index_key(protocol_name, &key);
                    let _ = proto_index.remove(proto_key.as_slice());
                }

                // Check for associated anomaly report
                if let Some(anom_id_guard) =
                    envelope_anom_index
                        .remove(key)
                        .map_err(|e| VigilError::DatabaseError {
                            operation: "Remove Envelope-to-Anomaly Index".into(),
                            reason: e.to_string(),
                        })?
                {
                    let anom_id = anom_id_guard.value();
                    // Delete associated anomaly report from table
                    let _ = anom_table.remove(anom_id);
                    prune_res.anomalies_deleted += 1;
                }
            }
        }

        write_txn.commit().map_err(|e| VigilError::DatabaseError {
            operation: "Commit Prune".into(),
            reason: e.to_string(),
        })?;

        Ok(prune_res)
    }

    /// Compact the database file on disk, reclaiming empty pages.
    pub fn compact(&self) -> VigilResult<()> {
        let mut db_ref = self.db.write().map_err(|e| VigilError::DatabaseError {
            operation: "Acquire DB Write Lock for Compaction".into(),
            reason: e.to_string(),
        })?;

        db_ref.compact().map_err(|e| VigilError::DatabaseError {
            operation: "Compact Database".into(),
            reason: e.to_string(),
        })?;
        Ok(())
    }
}

// ─── Helpers ────────────────────────────────────────────────────────────────

/// Determine protocol name string representing the NetworkEvent.
fn get_protocol_name(event: &vigil_core::types::NetworkEvent) -> &'static str {
    match event {
        vigil_core::types::NetworkEvent::Bgp(_) => "Bgp",
        vigil_core::types::NetworkEvent::Mpls(_) => "Mpls",
        vigil_core::types::NetworkEvent::Snmp(_) => "Snmp",
        vigil_core::types::NetworkEvent::Ospf(_) => "Ospf",
        vigil_core::types::NetworkEvent::Interface(_) => "Interface",
        vigil_core::types::NetworkEvent::Lsp(_) => "Lsp",
    }
}

/// Create a lexicographically sortable compound key: `[2-bytes len] + [source bytes] + [16-bytes UUID]`.
fn make_composite_index_key(prefix: &str, uuid_bytes: &[u8; 16]) -> Vec<u8> {
    let prefix_bytes = prefix.as_bytes();
    let mut key = Vec::with_capacity(2 + prefix_bytes.len() + 16);
    key.extend_from_slice(&(prefix_bytes.len() as u16).to_be_bytes());
    key.extend_from_slice(prefix_bytes);
    key.extend_from_slice(uuid_bytes);
    key
}

/// Parse a composite key back into its prefix string and UUID bytes.
fn parse_composite_index_key(key: &[u8]) -> (String, [u8; 16]) {
    let len = u16::from_be_bytes([key[0], key[1]]) as usize;
    let prefix = String::from_utf8_lossy(&key[2..2 + len]).into_owned();
    let mut uuid_bytes = [0u8; 16];
    uuid_bytes.copy_from_slice(&key[2 + len..2 + len + 16]);
    (prefix, uuid_bytes)
}

/// Construct a dummy UUIDv7 for range bounds.
///
/// If timestamp is `None`, returns minimum UUID (`[0; 16]`) or maximum UUID (`[0xFF; 16]`).
fn timestamp_to_uuid_bound(time: Option<DateTime<Utc>>, is_end: bool) -> Uuid {
    let Some(t) = time else {
        if is_end {
            return Uuid::max();
        } else {
            return Uuid::nil();
        }
    };

    let millis = t.timestamp_millis();
    if millis < 0 {
        if is_end {
            return Uuid::max();
        } else {
            return Uuid::nil();
        }
    }

    let mut bytes = [0u8; 16];
    let ts_bytes = (millis as u64).to_be_bytes();
    // Copy 48-bit timestamp (last 6 bytes of u64 to-be-bytes)
    bytes[0..6].copy_from_slice(&ts_bytes[2..8]);

    if is_end {
        bytes[6..16].fill(0xFF);
    } else {
        bytes[6..16].fill(0x00);
    }

    Uuid::from_bytes(bytes)
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use tempfile::NamedTempFile;
    use vigil_core::types::*;

    fn make_test_envelope(id: Uuid, hostname: &str, latency: u64) -> TelemetryEnvelope {
        TelemetryEnvelope {
            id,
            timestamp: Utc::now(),
            source: TelemetrySource {
                hostname: hostname.into(),
                ip_address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                device_type: DeviceType::CoreRouter,
                site_id: "TEST-SITE".into(),
            },
            hmac_tag: vec![0; 32],
            event: NetworkEvent::Lsp(LspMetrics {
                lsp_name: "LSP-TEST".into(),
                source: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                destination: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                status: LspStatus::Up,
                latency_us: latency,
                jitter_us: 100,
                packet_loss_pct: 0.0,
                bandwidth_bps: 100000,
                reroute_count: 0,
            }),
            sequence_number: 0,
            ground_truth_label: None,
        }
    }

    fn make_test_report(id: Uuid, envelope_id: Uuid, score: f64) -> AnomalyReport {
        AnomalyReport {
            id,
            envelope_id,
            analyzed_at: Utc::now(),
            score,
            ml_score: 0.0,
            confidence: 1.0,
            is_anomalous: score >= 0.5,
            severity: Severity::Critical,
            verdicts: Vec::new(),
            explanation: "Latency spike detected".into(),
            recommendations: vec!["Investigate path".into()],
            time_to_impact_secs: None,
            time_to_impact_minutes: None,
            trend_score: 0.0,
            predicted_breach_metric: None,
        }
    }

    #[test]
    fn store_insert_and_retrieve_telemetry() {
        let temp_file = NamedTempFile::new().unwrap();
        let store = VigilStore::open(temp_file.path()).unwrap();

        let id = Uuid::now_v7();
        let envelope = make_test_envelope(id, "rtr-01", 5000);

        store.insert_telemetry(&envelope).unwrap();

        let retrieved = store.get_telemetry(id).unwrap().unwrap();
        assert_eq!(retrieved.id, id);
        assert_eq!(retrieved.source.hostname, "rtr-01");

        // Non-existent ID returns None
        assert!(store.get_telemetry(Uuid::now_v7()).unwrap().is_none());
    }

    #[test]
    fn store_insert_and_retrieve_anomaly() {
        let temp_file = NamedTempFile::new().unwrap();
        let store = VigilStore::open(temp_file.path()).unwrap();

        let env_id = Uuid::now_v7();
        let report_id = Uuid::now_v7();
        let report = make_test_report(report_id, env_id, 0.85);

        store.insert_anomaly_report(&report).unwrap();

        let retrieved = store.get_anomaly_report(report_id).unwrap().unwrap();
        assert_eq!(retrieved.id, report_id);
        assert_eq!(retrieved.envelope_id, env_id);
        assert!(retrieved.is_anomalous);

        // Retrieve by envelope ID
        let retrieved_by_env = store
            .get_anomaly_report_by_envelope(env_id)
            .unwrap()
            .unwrap();
        assert_eq!(retrieved_by_env.id, report_id);
    }

    #[test]
    fn store_query_telemetry_filters() {
        let temp_file = NamedTempFile::new().unwrap();
        let store = VigilStore::open(temp_file.path()).unwrap();

        let id1 = Uuid::now_v7();
        let id2 = Uuid::now_v7();

        let env1 = make_test_envelope(id1, "rtr-01", 5000);
        let env2 = make_test_envelope(id2, "rtr-02", 9000);

        store.insert_telemetry(&env1).unwrap();
        store.insert_telemetry(&env2).unwrap();

        // 1. Query all
        let results = store
            .query_telemetry(TelemetryQueryFilter::default())
            .unwrap();
        assert_eq!(results.len(), 2);

        // 2. Query by source
        let mut filter = TelemetryQueryFilter::default();
        filter.source = Some("rtr-01".into());
        let results = store.query_telemetry(filter).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, id1);

        // 3. Query by limit
        let mut filter = TelemetryQueryFilter::default();
        filter.limit = Some(1);
        let results = store.query_telemetry(filter).unwrap();
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn store_query_anomalies_filters() {
        let temp_file = NamedTempFile::new().unwrap();
        let store = VigilStore::open(temp_file.path()).unwrap();

        let env_id = Uuid::now_v7();
        let r1 = make_test_report(Uuid::now_v7(), env_id, 0.2); // Normal
        let r2 = make_test_report(Uuid::now_v7(), env_id, 0.95); // Critical Anomaly

        store.insert_anomaly_report(&r1).unwrap();
        store.insert_anomaly_report(&r2).unwrap();

        // 1. Query anomalous only
        let mut filter = AnomalyQueryFilter::default();
        filter.is_anomalous = Some(true);
        let results = store.query_anomalies(filter).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].score, 0.95);

        // 2. Query by min score
        let mut filter = AnomalyQueryFilter::default();
        filter.min_score = Some(0.5);
        let results = store.query_anomalies(filter).unwrap();
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn store_prune_reclaims_space() {
        let temp_file = NamedTempFile::new().unwrap();
        let store = VigilStore::open(temp_file.path()).unwrap();

        let id = Uuid::now_v7();
        let env = make_test_envelope(id, "rtr-01", 5000);
        let rep = make_test_report(Uuid::now_v7(), id, 0.9);

        store.insert_telemetry(&env).unwrap();
        store.insert_anomaly_report(&rep).unwrap();

        // Let's prune with 0 duration (retains nothing!)
        let prune_res = store.prune(Duration::zero()).unwrap();
        assert_eq!(prune_res.telemetry_deleted, 1);
        assert_eq!(prune_res.anomalies_deleted, 1);

        // Confirm DB is empty
        assert!(store.get_telemetry(id).unwrap().is_none());
        assert!(store.get_anomaly_report_by_envelope(id).unwrap().is_none());

        // Compaction should run fine
        store.compact().unwrap();
    }

    #[test]
    fn store_insert_and_retrieve_diagnostic() {
        let temp_file = NamedTempFile::new().unwrap();
        let store = VigilStore::open(temp_file.path()).unwrap();

        let anomaly_id = Uuid::now_v7();
        let report_data =
            b"{\"diagnosis\":\"fiber cut simulated\",\"mitigation\":[\"check interface\"]}";

        // Insertion
        store
            .insert_diagnostic_report(&anomaly_id, report_data)
            .unwrap();

        // Retrieval
        let retrieved = store.get_diagnostic_report(anomaly_id).unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap(), report_data);

        // Missing id
        assert!(
            store
                .get_diagnostic_report(Uuid::now_v7())
                .unwrap()
                .is_none()
        );
    }
}
