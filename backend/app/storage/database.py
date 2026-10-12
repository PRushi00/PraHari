"""
PraHari — SQLite Storage Layer

Manages database connections, table creation, and CRUD operations
for normalized events, telemetry sources, import summaries, and
descriptive analysis results.

Uses sqlite3 directly (no ORM) for simplicity and transparency.
"""

from __future__ import annotations

import json
import sqlite3
import logging
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Generator

from app.schemas.events import (
    NormalizedEvent,
    TelemetrySource,
    ImportSummary,
    DescriptiveAnalysis,
    DataCategory,
    EventType,
    LabelProvenance,
    QualityFlag,
)

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────────────────
# Schema DDL
# ──────────────────────────────────────────────────────────────────

TABLES_DDL = """
CREATE TABLE IF NOT EXISTS telemetry_sources (
    source_id       TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    source_type     TEXT NOT NULL,
    description     TEXT,
    enabled         INTEGER NOT NULL DEFAULT 1,
    created_at      TEXT NOT NULL,
    last_event_at   TEXT,
    event_count     INTEGER NOT NULL DEFAULT 0,
    status          TEXT NOT NULL DEFAULT 'active'
);

CREATE TABLE IF NOT EXISTS normalized_events (
    event_id        TEXT PRIMARY KEY,
    schema_version  TEXT NOT NULL,
    source_id       TEXT NOT NULL,
    data_category   TEXT NOT NULL,
    observed_at     TEXT NOT NULL,
    ingested_at     TEXT NOT NULL,
    event_type      TEXT NOT NULL DEFAULT 'network_flow',
    src_ip          TEXT,
    dst_ip          TEXT,
    src_port        INTEGER,
    dst_port        INTEGER,
    protocol        TEXT,
    duration        REAL,
    packets         INTEGER,
    bytes_total     INTEGER,
    label           TEXT,
    label_provenance TEXT NOT NULL DEFAULT 'unlabeled',
    quality_flags   TEXT NOT NULL DEFAULT '[]',
    raw_reference   TEXT,
    app_protocol    TEXT,
    http_method     TEXT,
    http_path       TEXT,
    http_status_code INTEGER,
    http_duration_ms REAL,
    dst_hostname    TEXT,
    FOREIGN KEY (source_id) REFERENCES telemetry_sources(source_id)
);

CREATE INDEX IF NOT EXISTS idx_events_source ON normalized_events(source_id);
CREATE INDEX IF NOT EXISTS idx_events_observed ON normalized_events(observed_at);
CREATE INDEX IF NOT EXISTS idx_events_label ON normalized_events(label);
CREATE INDEX IF NOT EXISTS idx_events_type ON normalized_events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_category ON normalized_events(data_category);
CREATE INDEX IF NOT EXISTS idx_events_dst_ip ON normalized_events(dst_ip);

-- Locally observed DNS resolutions, used to infer a destination hostname for
-- a connection. Kept in a separate table so enrichment never mutates the
-- connection record it describes, and so conflicting or stale observations
-- remain visible as evidence rather than being overwritten.
CREATE TABLE IF NOT EXISTS dns_observations (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address      TEXT NOT NULL,
    hostname        TEXT NOT NULL,
    observed_at     TEXT NOT NULL,
    method          TEXT NOT NULL,
    ttl_seconds     INTEGER,
    source_id       TEXT,
    UNIQUE (ip_address, hostname, observed_at)
);

CREATE INDEX IF NOT EXISTS idx_dns_ip ON dns_observations(ip_address);
CREATE INDEX IF NOT EXISTS idx_dns_observed ON dns_observations(observed_at);

CREATE TABLE IF NOT EXISTS import_summaries (
    import_id           TEXT PRIMARY KEY,
    source_id           TEXT NOT NULL,
    source_file         TEXT,
    data_category       TEXT NOT NULL,
    started_at          TEXT NOT NULL,
    completed_at        TEXT,
    total_records       INTEGER NOT NULL DEFAULT 0,
    accepted_records    INTEGER NOT NULL DEFAULT 0,
    rejected_records    INTEGER NOT NULL DEFAULT 0,
    warnings_count      INTEGER NOT NULL DEFAULT 0,
    rejection_reasons   TEXT NOT NULL DEFAULT '{}',
    schema_version      TEXT NOT NULL,
    FOREIGN KEY (source_id) REFERENCES telemetry_sources(source_id)
);

CREATE TABLE IF NOT EXISTS descriptive_analyses (
    analysis_id         TEXT PRIMARY KEY,
    analysis_type       TEXT NOT NULL DEFAULT 'descriptive_historical',
    source_id           TEXT NOT NULL,
    computed_at         TEXT NOT NULL,
    schema_version      TEXT NOT NULL,
    data_category       TEXT NOT NULL,
    total_events        INTEGER NOT NULL DEFAULT 0,
    events_by_type      TEXT NOT NULL DEFAULT '{}',
    events_by_label     TEXT NOT NULL DEFAULT '{}',
    events_by_protocol  TEXT NOT NULL DEFAULT '{}',
    time_range_start    TEXT,
    time_range_end      TEXT,
    missing_field_counts TEXT NOT NULL DEFAULT '{}',
    unsupported_field_counts TEXT NOT NULL DEFAULT '{}',
    source_limitations  TEXT NOT NULL DEFAULT '[]',
    data_categories     TEXT NOT NULL DEFAULT '{}',
    source_breakdown    TEXT NOT NULL DEFAULT '{}',
    is_mixed_provenance INTEGER NOT NULL DEFAULT 0,
    events_by_connection_state TEXT NOT NULL DEFAULT '{}',
    events_by_process   TEXT NOT NULL DEFAULT '{}',
    top_dst_hostnames   TEXT NOT NULL DEFAULT '[]',
    hostname_attributed_count INTEGER NOT NULL DEFAULT 0,
    events_per_hour     TEXT NOT NULL DEFAULT '{}',
    quality_flag_counts TEXT NOT NULL DEFAULT '{}',
    records_with_warnings INTEGER NOT NULL DEFAULT 0,
    unique_src_ips      INTEGER NOT NULL DEFAULT 0,
    unique_dst_ips      INTEGER NOT NULL DEFAULT 0,
    unique_src_ports    INTEGER NOT NULL DEFAULT 0,
    unique_dst_ports    INTEGER NOT NULL DEFAULT 0,
    top_src_ips         TEXT NOT NULL DEFAULT '[]',
    top_dst_ips         TEXT NOT NULL DEFAULT '[]',
    top_dst_ports       TEXT NOT NULL DEFAULT '[]',
    avg_duration        REAL,
    avg_packets         REAL,
    avg_bytes           REAL,
    total_bytes         INTEGER,
    FOREIGN KEY (source_id) REFERENCES telemetry_sources(source_id)
);

CREATE TABLE IF NOT EXISTS audit_events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       TEXT NOT NULL,
    action          TEXT NOT NULL,
    resource_type   TEXT,
    resource_id     TEXT,
    details         TEXT,
    user_identity   TEXT DEFAULT 'local_operator'
);

CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_events(timestamp);
"""


class Database:
    """
    SQLite database manager for PraHari.

    Manages connection pooling (single connection for SQLite),
    table initialization, and provides typed CRUD operations.
    """

    def __init__(self, db_path: str = "prahari.db"):
        self.db_path = db_path
        self._connection: Optional[sqlite3.Connection] = None

    # Columns added after the initial schema. CREATE TABLE IF NOT EXISTS does
    # not add columns to an existing table, so a database created by an
    # earlier version must be migrated in place — otherwise it silently keeps
    # working while dropping every new field.
    _ADDED_COLUMNS: dict[str, list[tuple[str, str]]] = {
        "normalized_events": [
            ("app_protocol", "TEXT"),
            ("http_method", "TEXT"),
            ("http_path", "TEXT"),
            ("http_status_code", "INTEGER"),
            ("http_duration_ms", "REAL"),
            ("dst_hostname", "TEXT"),
        ],
        "descriptive_analyses": [
            ("unsupported_field_counts", "TEXT NOT NULL DEFAULT '{}'"),
            ("source_limitations", "TEXT NOT NULL DEFAULT '[]'"),
            ("data_categories", "TEXT NOT NULL DEFAULT '{}'"),
            ("source_breakdown", "TEXT NOT NULL DEFAULT '{}'"),
            ("is_mixed_provenance", "INTEGER NOT NULL DEFAULT 0"),
            ("events_by_connection_state", "TEXT NOT NULL DEFAULT '{}'"),
            ("events_by_process", "TEXT NOT NULL DEFAULT '{}'"),
            ("top_dst_hostnames", "TEXT NOT NULL DEFAULT '[]'"),
            ("hostname_attributed_count", "INTEGER NOT NULL DEFAULT 0"),
            ("events_per_hour", "TEXT NOT NULL DEFAULT '{}'"),
        ],
    }

    def initialize(self) -> None:
        """Create tables if absent, then add any columns introduced later."""
        with self.get_connection() as conn:
            conn.executescript(TABLES_DDL)
            self._migrate_columns(conn)
            logger.info("Database initialized at %s", self.db_path)

    def _migrate_columns(self, conn: sqlite3.Connection) -> None:
        """Add missing columns to existing tables, preserving all data."""
        for table, columns in self._ADDED_COLUMNS.items():
            existing = {
                row["name"] for row in conn.execute(f"PRAGMA table_info({table})")
            }
            if not existing:
                continue  # table absent; DDL above will have created it
            for name, ddl in columns:
                if name in existing:
                    continue
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}")
                logger.info("Migrated %s: added column %s", table, name)

    @contextmanager
    def get_connection(self) -> Generator[sqlite3.Connection, None, None]:
        """Get a database connection with proper transaction handling."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def close(self) -> None:
        """Close the persistent connection if open."""
        if self._connection:
            self._connection.close()
            self._connection = None

    # ──────────────── Audit Logging ────────────────

    def log_audit(
        self,
        action: str,
        resource_type: str = "",
        resource_id: str = "",
        details: str = "",
        user_identity: str = "local_operator",
    ) -> None:
        """Record an audit event."""
        with self.get_connection() as conn:
            conn.execute(
                """INSERT INTO audit_events (timestamp, action, resource_type, resource_id, details, user_identity)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    datetime.now(timezone.utc).isoformat(),
                    action,
                    resource_type,
                    resource_id,
                    details,
                    user_identity,
                ),
            )

    # ──────────────── Telemetry Sources ────────────────

    def upsert_source(self, source: TelemetrySource) -> None:
        """Insert or update a telemetry source."""
        with self.get_connection() as conn:
            conn.execute(
                """INSERT INTO telemetry_sources
                   (source_id, name, source_type, description, enabled, created_at, last_event_at, event_count, status)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(source_id) DO UPDATE SET
                     name=excluded.name,
                     source_type=excluded.source_type,
                     description=excluded.description,
                     enabled=excluded.enabled,
                     last_event_at=excluded.last_event_at,
                     event_count=excluded.event_count,
                     status=excluded.status""",
                (
                    source.source_id,
                    source.name,
                    source.source_type,
                    source.description,
                    int(source.enabled),
                    source.created_at.isoformat(),
                    source.last_event_at.isoformat() if source.last_event_at else None,
                    source.event_count,
                    source.status,
                ),
            )

    def refresh_source_activity(
        self,
        source_id: str,
        last_event_at: Optional[datetime] = None,
        status: Optional[str] = None,
    ) -> Optional[TelemetrySource]:
        """
        Recompute a source's activity counters directly from stored events.

        ``event_count`` is derived from ``normalized_events`` rather than
        incremented by batch size. Incrementing is unsafe: it double-counts
        when a batch contains records already present (deduplicated on insert)
        and drifts permanently if an insert is partially rolled back.

        ``last_event_at`` only ever moves forward, so a late-arriving batch of
        older records cannot rewind a source's freshness indicator.
        """
        with self.get_connection() as conn:
            row = conn.execute(
                "SELECT source_id FROM telemetry_sources WHERE source_id = ?",
                (source_id,),
            ).fetchone()
            if row is None:
                return None

            ts = last_event_at.isoformat() if last_event_at else None
            conn.execute(
                """UPDATE telemetry_sources
                   SET event_count = (
                           SELECT COUNT(*) FROM normalized_events
                           WHERE source_id = :sid
                       ),
                       last_event_at = CASE
                           WHEN :ts IS NULL THEN last_event_at
                           WHEN last_event_at IS NULL THEN :ts
                           WHEN :ts > last_event_at THEN :ts
                           ELSE last_event_at
                       END,
                       status = COALESCE(:status, status)
                   WHERE source_id = :sid""",
                {"sid": source_id, "ts": ts, "status": status},
            )
            updated = conn.execute(
                "SELECT * FROM telemetry_sources WHERE source_id = ?",
                (source_id,),
            ).fetchone()
            return self._row_to_source(updated) if updated else None

    def get_source(self, source_id: str) -> Optional[TelemetrySource]:
        """Retrieve a telemetry source by ID."""
        with self.get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM telemetry_sources WHERE source_id = ?",
                (source_id,),
            ).fetchone()
            if row is None:
                return None
            return self._row_to_source(row)

    def list_sources(self) -> list[TelemetrySource]:
        """List all telemetry sources."""
        with self.get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM telemetry_sources ORDER BY created_at DESC"
            ).fetchall()
            return [self._row_to_source(r) for r in rows]

    def _row_to_source(self, row: sqlite3.Row) -> TelemetrySource:
        return TelemetrySource(
            source_id=row["source_id"],
            name=row["name"],
            source_type=row["source_type"],
            description=row["description"],
            enabled=bool(row["enabled"]),
            created_at=datetime.fromisoformat(row["created_at"]),
            last_event_at=datetime.fromisoformat(row["last_event_at"]) if row["last_event_at"] else None,
            event_count=row["event_count"],
            status=row["status"],
        )

    # ──────────────── Normalized Events ────────────────

    def insert_events(self, events: list[NormalizedEvent]) -> int:
        """Insert normalized events. Returns count of inserted records."""
        if not events:
            return 0
        with self.get_connection() as conn:
            count = 0
            for event in events:
                try:
                    cursor = conn.execute(
                        """INSERT OR IGNORE INTO normalized_events
                           (event_id, schema_version, source_id, data_category,
                            observed_at, ingested_at, event_type,
                            src_ip, dst_ip, src_port, dst_port, protocol,
                            duration, packets, bytes_total,
                            label, label_provenance, quality_flags, raw_reference,
                            app_protocol, http_method, http_path,
                            http_status_code, http_duration_ms, dst_hostname)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                                   ?, ?, ?, ?, ?, ?)""",
                        (
                            event.event_id,
                            event.schema_version,
                            event.source_id,
                            event.data_category.value,
                            event.observed_at.isoformat(),
                            event.ingested_at.isoformat(),
                            event.event_type.value,
                            event.src_ip,
                            event.dst_ip,
                            event.src_port,
                            event.dst_port,
                            event.protocol,
                            event.duration,
                            event.packets,
                            event.bytes_total,
                            event.label,
                            event.label_provenance.value,
                            json.dumps([f.value for f in event.quality_flags]),
                            event.raw_reference,
                            event.app_protocol,
                            event.http_method,
                            event.http_path,
                            event.http_status_code,
                            event.http_duration_ms,
                            event.dst_hostname,
                        ),
                    )
                    if cursor.rowcount > 0:
                        count += 1
                except sqlite3.IntegrityError as exc:
                    # INSERT OR IGNORE already absorbs duplicate primary keys
                    # (rowcount 0, no exception). Anything that still raises
                    # here is a different constraint failure — in practice a
                    # foreign-key violation from an unregistered source_id,
                    # which OR IGNORE does NOT suppress. Logging that as a
                    # "duplicate" and continuing would silently discard the
                    # event and report success, so it is raised instead.
                    raise sqlite3.IntegrityError(
                        f"Failed to persist event {event.event_id} for source "
                        f"'{event.source_id}': {exc}. Ensure the telemetry source "
                        f"is registered before inserting its events."
                    ) from exc
            return count

    def get_event(self, event_id: str) -> Optional[NormalizedEvent]:
        """Retrieve a single event by ID."""
        with self.get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM normalized_events WHERE event_id = ?",
                (event_id,),
            ).fetchone()
            if row is None:
                return None
            return self._row_to_event(row)

    def list_events(
        self,
        source_id: Optional[str] = None,
        label: Optional[str] = None,
        event_type: Optional[str] = None,
        data_category: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[NormalizedEvent]:
        """List events with optional filters and pagination."""
        query = "SELECT * FROM normalized_events WHERE 1=1"
        params: list = []

        if source_id:
            query += " AND source_id = ?"
            params.append(source_id)
        if label:
            query += " AND label = ?"
            params.append(label)
        if event_type:
            query += " AND event_type = ?"
            params.append(event_type)
        if data_category:
            query += " AND data_category = ?"
            params.append(data_category)

        query += " ORDER BY observed_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        with self.get_connection() as conn:
            rows = conn.execute(query, params).fetchall()
            return [self._row_to_event(r) for r in rows]

    def count_events(
        self,
        source_id: Optional[str] = None,
        label: Optional[str] = None,
        event_type: Optional[str] = None,
        data_category: Optional[str] = None,
    ) -> int:
        """
        Count events with optional filters.

        Must accept EVERY filter that list_events accepts. It previously
        omitted event_type, so a filtered query reported the unfiltered
        total — e.g. "3,252 total" beside zero rows.
        """
        query = "SELECT COUNT(*) FROM normalized_events WHERE 1=1"
        params: list = []
        if source_id:
            query += " AND source_id = ?"
            params.append(source_id)
        if label:
            query += " AND label = ?"
            params.append(label)
        if event_type:
            query += " AND event_type = ?"
            params.append(event_type)
        if data_category:
            query += " AND data_category = ?"
            params.append(data_category)

        with self.get_connection() as conn:
            row = conn.execute(query, params).fetchone()
            return row[0] if row else 0

    def _row_to_event(self, row: sqlite3.Row) -> NormalizedEvent:
        flags_raw = json.loads(row["quality_flags"]) if row["quality_flags"] else []
        flags = [QualityFlag(f) for f in flags_raw if f in QualityFlag.__members__.values()]

        return NormalizedEvent(
            event_id=row["event_id"],
            schema_version=row["schema_version"],
            source_id=row["source_id"],
            data_category=DataCategory(row["data_category"]),
            observed_at=datetime.fromisoformat(row["observed_at"]),
            ingested_at=datetime.fromisoformat(row["ingested_at"]),
            event_type=EventType(row["event_type"]),
            src_ip=row["src_ip"],
            dst_ip=row["dst_ip"],
            src_port=row["src_port"],
            dst_port=row["dst_port"],
            protocol=row["protocol"],
            duration=row["duration"],
            packets=row["packets"],
            bytes_total=row["bytes_total"],
            label=row["label"],
            label_provenance=LabelProvenance(row["label_provenance"]),
            quality_flags=flags,
            raw_reference=row["raw_reference"],
            app_protocol=self._opt(row, "app_protocol"),
            http_method=self._opt(row, "http_method"),
            http_path=self._opt(row, "http_path"),
            http_status_code=self._opt(row, "http_status_code"),
            http_duration_ms=self._opt(row, "http_duration_ms"),
            dst_hostname=self._opt(row, "dst_hostname"),
        )

    @staticmethod
    def _opt(row: sqlite3.Row, column: str):
        """Read a column that may be absent in an un-migrated database."""
        try:
            return row[column]
        except (IndexError, KeyError):
            return None

    # ──────────────── DNS Observations (enrichment evidence) ────────────────

    def record_dns_observations(self, observations: list[dict]) -> int:
        """
        Persist locally observed DNS resolutions.

        Each observation is evidence that *at some moment* a hostname
        resolved to an address. It is deliberately append-only: a later
        answer does not erase an earlier one, because a shared or CDN
        address legitimately maps to many names and that ambiguity must stay
        visible to anyone judging an attribution.
        """
        if not observations:
            return 0
        inserted = 0
        with self.get_connection() as conn:
            for obs in observations:
                cur = conn.execute(
                    """INSERT OR IGNORE INTO dns_observations
                       (ip_address, hostname, observed_at, method, ttl_seconds, source_id)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (
                        obs["ip_address"],
                        obs["hostname"],
                        obs["observed_at"],
                        obs.get("method", "dns_cache_observation"),
                        obs.get("ttl_seconds"),
                        obs.get("source_id"),
                    ),
                )
                inserted += cur.rowcount if cur.rowcount > 0 else 0
        return inserted

    def get_dns_observations_for_ip(self, ip_address: str, limit: int = 50) -> list[dict]:
        """All recorded hostnames for an address, newest observation first."""
        with self.get_connection() as conn:
            rows = conn.execute(
                """SELECT hostname, observed_at, method, ttl_seconds
                   FROM dns_observations
                   WHERE ip_address = ?
                   ORDER BY observed_at DESC
                   LIMIT ?""",
                (ip_address, limit),
            ).fetchall()
            return [dict(r) for r in rows]

    def get_dns_observations_for_ips(self, ips: list[str]) -> dict[str, list[dict]]:
        """Bulk lookup for many addresses in one query."""
        if not ips:
            return {}
        unique = list({ip for ip in ips if ip})
        out: dict[str, list[dict]] = {ip: [] for ip in unique}
        placeholders = ",".join("?" * len(unique))
        with self.get_connection() as conn:
            rows = conn.execute(
                f"""SELECT ip_address, hostname, observed_at, method, ttl_seconds
                    FROM dns_observations
                    WHERE ip_address IN ({placeholders})
                    ORDER BY observed_at DESC""",
                unique,
            ).fetchall()
        for r in rows:
            out[r["ip_address"]].append(
                {
                    "hostname": r["hostname"],
                    "observed_at": r["observed_at"],
                    "method": r["method"],
                    "ttl_seconds": r["ttl_seconds"],
                }
            )
        return out

    def count_dns_observations(self) -> int:
        with self.get_connection() as conn:
            return conn.execute("SELECT COUNT(*) FROM dns_observations").fetchone()[0]

    def count_dns_distinct_ips(self) -> int:
        with self.get_connection() as conn:
            return conn.execute(
                "SELECT COUNT(DISTINCT ip_address) FROM dns_observations"
            ).fetchone()[0]

    # ──────────────── Import Summaries ────────────────

    def save_import_summary(self, summary: ImportSummary) -> None:
        """Save an import summary."""
        with self.get_connection() as conn:
            conn.execute(
                """INSERT INTO import_summaries
                   (import_id, source_id, source_file, data_category,
                    started_at, completed_at,
                    total_records, accepted_records, rejected_records, warnings_count,
                    rejection_reasons, schema_version)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    summary.import_id,
                    summary.source_id,
                    summary.source_file,
                    summary.data_category.value,
                    summary.started_at.isoformat(),
                    summary.completed_at.isoformat() if summary.completed_at else None,
                    summary.total_records,
                    summary.accepted_records,
                    summary.rejected_records,
                    summary.warnings_count,
                    json.dumps(summary.rejection_reasons),
                    summary.schema_version,
                ),
            )

    def list_import_summaries(self, source_id: Optional[str] = None) -> list[ImportSummary]:
        """List import summaries."""
        query = "SELECT * FROM import_summaries"
        params: list = []
        if source_id:
            query += " WHERE source_id = ?"
            params.append(source_id)
        query += " ORDER BY started_at DESC"

        with self.get_connection() as conn:
            rows = conn.execute(query, params).fetchall()
            result = []
            for r in rows:
                result.append(ImportSummary(
                    import_id=r["import_id"],
                    source_id=r["source_id"],
                    source_file=r["source_file"],
                    data_category=DataCategory(r["data_category"]),
                    started_at=datetime.fromisoformat(r["started_at"]),
                    completed_at=datetime.fromisoformat(r["completed_at"]) if r["completed_at"] else None,
                    total_records=r["total_records"],
                    accepted_records=r["accepted_records"],
                    rejected_records=r["rejected_records"],
                    warnings_count=r["warnings_count"],
                    rejection_reasons=json.loads(r["rejection_reasons"]),
                    schema_version=r["schema_version"],
                ))
            return result

    # ──────────────── Descriptive Analysis ────────────────

    def save_analysis(self, analysis: DescriptiveAnalysis) -> None:
        """Save a descriptive analysis result."""
        with self.get_connection() as conn:
            conn.execute(
                """INSERT OR IGNORE INTO telemetry_sources
                   (source_id, name, source_type, description, created_at)
                   VALUES (?, ?, 'aggregate', 'Auto-created source reference', ?)""",
                (analysis.source_id, analysis.source_id, datetime.now(timezone.utc).isoformat()),
            )
            conn.execute(
                """INSERT OR REPLACE INTO descriptive_analyses
                   (analysis_id, analysis_type, source_id, computed_at, schema_version,
                    data_category, total_events, events_by_type, events_by_label,
                    events_by_protocol, time_range_start, time_range_end,
                    missing_field_counts, quality_flag_counts, records_with_warnings,
                    unique_src_ips, unique_dst_ips, unique_src_ports, unique_dst_ports,
                    top_src_ips, top_dst_ips, top_dst_ports,
                    avg_duration, avg_packets, avg_bytes, total_bytes,
                    unsupported_field_counts, source_limitations,
                    data_categories, source_breakdown, is_mixed_provenance,
                    events_by_connection_state, events_by_process,
                    top_dst_hostnames, hostname_attributed_count, events_per_hour)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                           ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    analysis.analysis_id,
                    analysis.analysis_type,
                    analysis.source_id,
                    analysis.computed_at.isoformat(),
                    analysis.schema_version,
                    analysis.data_category.value,
                    analysis.total_events,
                    json.dumps(analysis.events_by_type),
                    json.dumps(analysis.events_by_label),
                    json.dumps(analysis.events_by_protocol),
                    analysis.time_range_start.isoformat() if analysis.time_range_start else None,
                    analysis.time_range_end.isoformat() if analysis.time_range_end else None,
                    json.dumps(analysis.missing_field_counts),
                    json.dumps(analysis.quality_flag_counts),
                    analysis.records_with_warnings,
                    analysis.unique_src_ips,
                    analysis.unique_dst_ips,
                    analysis.unique_src_ports,
                    analysis.unique_dst_ports,
                    json.dumps(analysis.top_src_ips),
                    json.dumps(analysis.top_dst_ips),
                    json.dumps(analysis.top_dst_ports),
                    analysis.avg_duration,
                    analysis.avg_packets,
                    analysis.avg_bytes,
                    analysis.total_bytes,
                    json.dumps(analysis.unsupported_field_counts),
                    json.dumps(analysis.source_limitations),
                    json.dumps(analysis.data_categories),
                    json.dumps(analysis.source_breakdown),
                    int(analysis.is_mixed_provenance),
                    json.dumps(analysis.events_by_connection_state),
                    json.dumps(analysis.events_by_process),
                    json.dumps(analysis.top_dst_hostnames),
                    analysis.hostname_attributed_count,
                    json.dumps(analysis.events_per_hour),
                ),
            )

    def get_latest_analysis(self, source_id: Optional[str] = None) -> Optional[DescriptiveAnalysis]:
        """Retrieve the most recent descriptive analysis."""
        query = "SELECT * FROM descriptive_analyses"
        params: list = []
        if source_id:
            query += " WHERE source_id = ?"
            params.append(source_id)
        query += " ORDER BY computed_at DESC LIMIT 1"

        with self.get_connection() as conn:
            row = conn.execute(query, params).fetchone()
            if row is None:
                return None
            return self._row_to_analysis(row)

    def list_analyses(self) -> list[DescriptiveAnalysis]:
        """List all descriptive analyses."""
        with self.get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM descriptive_analyses ORDER BY computed_at DESC"
            ).fetchall()
            return [self._row_to_analysis(r) for r in rows]

    def _row_to_analysis(self, row: sqlite3.Row) -> DescriptiveAnalysis:
        return DescriptiveAnalysis(
            analysis_id=row["analysis_id"],
            analysis_type=row["analysis_type"],
            source_id=row["source_id"],
            computed_at=datetime.fromisoformat(row["computed_at"]),
            schema_version=row["schema_version"],
            data_category=DataCategory(row["data_category"]),
            total_events=row["total_events"],
            events_by_type=json.loads(row["events_by_type"]),
            events_by_label=json.loads(row["events_by_label"]),
            events_by_protocol=json.loads(row["events_by_protocol"]),
            time_range_start=datetime.fromisoformat(row["time_range_start"]) if row["time_range_start"] else None,
            time_range_end=datetime.fromisoformat(row["time_range_end"]) if row["time_range_end"] else None,
            missing_field_counts=json.loads(row["missing_field_counts"]),
            quality_flag_counts=json.loads(row["quality_flag_counts"]),
            records_with_warnings=row["records_with_warnings"],
            unique_src_ips=row["unique_src_ips"],
            unique_dst_ips=row["unique_dst_ips"],
            unique_src_ports=row["unique_src_ports"],
            unique_dst_ports=row["unique_dst_ports"],
            top_src_ips=json.loads(row["top_src_ips"]),
            top_dst_ips=json.loads(row["top_dst_ips"]),
            top_dst_ports=json.loads(row["top_dst_ports"]),
            avg_duration=row["avg_duration"],
            avg_packets=row["avg_packets"],
            avg_bytes=row["avg_bytes"],
            total_bytes=row["total_bytes"],
            unsupported_field_counts=self._json_opt(row, "unsupported_field_counts", {}),
            source_limitations=self._json_opt(row, "source_limitations", []),
            data_categories=self._json_opt(row, "data_categories", {}),
            source_breakdown=self._json_opt(row, "source_breakdown", {}),
            is_mixed_provenance=bool(self._opt(row, "is_mixed_provenance") or 0),
            events_by_connection_state=self._json_opt(row, "events_by_connection_state", {}),
            events_by_process=self._json_opt(row, "events_by_process", {}),
            top_dst_hostnames=self._json_opt(row, "top_dst_hostnames", []),
            hostname_attributed_count=self._opt(row, "hostname_attributed_count") or 0,
            events_per_hour=self._json_opt(row, "events_per_hour", {}),
        )

    def _json_opt(self, row: sqlite3.Row, column: str, default):
        """Read and decode a JSON column that may be absent or empty."""
        raw = self._opt(row, column)
        if not raw:
            return default
        try:
            return json.loads(raw)
        except (TypeError, ValueError):
            return default
