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
from typing import Any, Callable, Optional, Generator

from app.storage.guard import assert_safe_to_initialize
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


def _column_present(row, name: str) -> bool:
    """
    Whether a sqlite3.Row actually carries a column.

    A database opened read-only, or one from before the migration, has no
    `received_at` at all — indexing it raises IndexError rather than
    returning None. Reads must stay backward compatible with such a file.
    """
    try:
        return name in row.keys()
    except Exception:  # noqa: BLE001
        return False


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
    -- Nullable by design: NULL means "no measured receipt time", which is
    -- correct for locally collected events, historical imports, and rows
    -- written before this column existed. Never backfilled.
    received_at     TEXT,
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
    user_identity   TEXT DEFAULT 'local_operator',
    -- Correlation id of the request that caused this entry (ADR-063).
    -- NULL for anything with no request behind it: a collector poll, the
    -- CLI, a test. NULL is accurate; a placeholder would not be.
    request_id      TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_events(timestamp);

-- Operator-set overrides of configuration defaults (ADR-059).
--
-- NOT a second policy store: AppConfig remains the source of defaults,
-- and a row here is an explicit, audited override of one of them. The
-- effective value and its origin are reported together so a reader is
-- never left guessing which won.
CREATE TABLE IF NOT EXISTS system_settings (
    key         TEXT PRIMARY KEY,
    value       TEXT NOT NULL,
    updated_at  TEXT NOT NULL,
    updated_by  TEXT
);
"""



def _measured(value) -> "int | None":
    """
    Read a measured-count column.

    -1 is the sentinel for "this row predates the column", and becomes
    None so a reader sees "not recorded" instead of a confident 0. A
    missing column (an even older database) reads the same way.
    """
    if value is None:
        return None
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    return None if number < 0 else number


class EventIdentityConflictError(sqlite3.IntegrityError):
    """
    Raised when an event ID is re-submitted with conflicting canonical content.

    Prevents silent merging or overwrite of distinct telemetry under an already
    persisted event identity.
    """


# ── Canonical identity-conflict policy (ADR-050) ──
#
# The fields that define WHAT AN EVENT CLAIMS HAPPENED. Re-using an event
# identity while changing any of them is a conflict, not a retry: the sender
# is asserting something different under an identity that is already taken,
# and keeping the first version silently would discard telemetry that feature
# extraction, labelling and forecasting all read.
#
# Each entry maps a stored column to the comparable value on a NormalizedEvent.
CONFLICT_FIELDS: dict[str, Callable[[NormalizedEvent], Any]] = {
    # Provenance and time
    "source_id": lambda e: e.source_id,
    "observed_at": lambda e: e.observed_at.isoformat(),
    "data_category": lambda e: e.data_category.value,
    # What was observed
    "event_type": lambda e: e.event_type.value,
    # The connection five-tuple
    "src_ip": lambda e: e.src_ip,
    "dst_ip": lambda e: e.dst_ip,
    "src_port": lambda e: e.src_port,
    "dst_port": lambda e: e.dst_port,
    "protocol": lambda e: e.protocol,
    # The measurements — these feed the forecasting features directly
    "duration": lambda e: e.duration,
    "packets": lambda e: e.packets,
    "bytes_total": lambda e: e.bytes_total,
    # The training target and its provenance
    "label": lambda e: e.label,
    "label_provenance": lambda e: e.label_provenance.value,
    # Application layer
    "app_protocol": lambda e: e.app_protocol,
    "http_method": lambda e: e.http_method,
    "http_path": lambda e: e.http_path,
    "http_status_code": lambda e: e.http_status_code,
    "http_duration_ms": lambda e: e.http_duration_ms,
    "dst_hostname": lambda e: e.dst_hostname,
}

# Deliberately NOT compared. Each exclusion is a decision, not an oversight:
#
#   event_id        the identity being checked, not evidence about it.
#   ingested_at     backend object-construction time. Differs on every
#                   redelivery by definition.
#   received_at     when THIS delivery arrived. A retry necessarily has a
#                   later one, and ADR-048 keeps the original, so comparing
#                   it would make every legitimate retry a conflict.
#   raw_reference   "json:record:N" — the record's POSITION in the submitted
#                   batch. The same event resent at a different position is
#                   still the same event.
#   schema_version  describes the encoding, not the observation. A normalizer
#                   upgrade must not turn retries into conflicts; any real
#                   change it causes surfaces in the compared values above.
#   quality_flags   derived by the normalizer FROM the compared fields rather
#                   than asserted independently by the sender.
CONFLICT_FIELDS_EXCLUDED = (
    "event_id",
    "ingested_at",
    "received_at",
    "raw_reference",
    "schema_version",
    "quality_flags",
)


# ──────────────────────────────────────────────────────────────────
# Row -> model conversion
#
# Module-level, and written against mapping access rather than
# sqlite3.Row, so a second backend (app/storage/postgres.py) reuses these
# verbatim. Restating the mapping per backend is how two stores drift into
# returning subtly different objects from the same row.
# ──────────────────────────────────────────────────────────────────


def _opt(row, column: str):
    """Read a column that may be absent in an un-migrated database."""
    try:
        return row[column]
    except (IndexError, KeyError):
        return None


def _json_opt(row, column: str, default):
    """Read and decode a JSON column that may be absent or empty."""
    raw = _opt(row, column)
    if not raw:
        return default
    try:
        return json.loads(raw)
    except (TypeError, ValueError):
        return default


def row_to_source(row) -> TelemetrySource:
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



def row_to_event(row) -> NormalizedEvent:
    flags_raw = json.loads(row["quality_flags"]) if row["quality_flags"] else []
    flags = [QualityFlag(f) for f in flags_raw if f in QualityFlag.__members__.values()]

    return NormalizedEvent(
        event_id=row["event_id"],
        schema_version=row["schema_version"],
        source_id=row["source_id"],
        data_category=DataCategory(row["data_category"]),
        observed_at=datetime.fromisoformat(row["observed_at"]),
        ingested_at=datetime.fromisoformat(row["ingested_at"]),
        received_at=(
            datetime.fromisoformat(row["received_at"])
            if _column_present(row, "received_at") and row["received_at"]
            else None
        ),
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
        app_protocol=_opt(row, "app_protocol"),
        http_method=_opt(row, "http_method"),
        http_path=_opt(row, "http_path"),
        http_status_code=_opt(row, "http_status_code"),
        http_duration_ms=_opt(row, "http_duration_ms"),
        dst_hostname=_opt(row, "dst_hostname"),
    )



def row_to_analysis(row) -> DescriptiveAnalysis:
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
        unsupported_field_counts=_json_opt(row, "unsupported_field_counts", {}),
        source_limitations=_json_opt(row, "source_limitations", []),
        data_categories=_json_opt(row, "data_categories", {}),
        source_breakdown=_json_opt(row, "source_breakdown", {}),
        is_mixed_provenance=bool(_opt(row, "is_mixed_provenance") or 0),
        events_by_connection_state=_json_opt(row, "events_by_connection_state", {}),
        events_by_process=_json_opt(row, "events_by_process", {}),
        top_dst_hostnames=_json_opt(row, "top_dst_hostnames", []),
        hostname_attributed_count=_opt(row, "hostname_attributed_count") or 0,
        events_per_hour=_json_opt(row, "events_per_hour", {}),
        # A pre-column analysis stores -1. It is surfaced as None —
        # "not recorded" — rather than 0, which would claim a
        # measurement of nothing.
        bytes_measured_count=_measured(_opt(row, "bytes_measured_count")),
        packets_measured_count=_measured(_opt(row, "packets_measured_count")),
        duration_measured_count=_measured(_opt(row, "duration_measured_count")),
        implausible_timestamp_events=_measured(
            _opt(row, "implausible_timestamp_events")
        ),
        # It came out of the database, so it is by definition stored.
        # Whether it is still CURRENT is a question about live counts
        # and is answered by the route, not here.
        persisted=True,
    )



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
            # Phase 2. Nullable with no default, so existing rows keep
            # "unknown" rather than acquiring a fabricated receipt time.
            ("received_at", "TEXT"),
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
            # These four were COMPUTED by analysis.py and then dropped on
            # save: the table had no column for them, so they read back as
            # the Pydantic default 0. That turned "we measured nothing"
            # and "we measured zero" into the same answer, and reported
            # implausible_timestamp_events as 0 while 65 existed.
            #
            # -1 means "this analysis predates the column", which is
            # distinct from a genuine 0. A stored analysis cannot be
            # recomputed retroactively, and backfilling it with 0 would
            # invent a measurement nobody took.
            ("bytes_measured_count", "INTEGER NOT NULL DEFAULT -1"),
            ("packets_measured_count", "INTEGER NOT NULL DEFAULT -1"),
            ("duration_measured_count", "INTEGER NOT NULL DEFAULT -1"),
            ("implausible_timestamp_events", "INTEGER NOT NULL DEFAULT -1"),
        ],
        "audit_events": [
            # Nullable with no default: an entry written before this
            # column existed has no request id, and inventing one would
            # be worse than recording its absence.
            ("request_id", "TEXT"),
        ],
    }

    def initialize(self) -> None:
        """Create tables if absent, then add any columns introduced later."""
        assert_safe_to_initialize(self.db_path)
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
                # A migration against a table that already holds data is
                # a real change to someone's records, even when additive.
                # It was previously an INFO line indistinguishable from
                # ordinary startup noise, which is how one slipped past
                # unnoticed (ADR-054).
                try:
                    rows = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                except sqlite3.Error:
                    rows = -1
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}")
                if rows:
                    logger.warning(
                        "SCHEMA MIGRATION: added column %s to %s, which already "
                        "holds %s row(s), in database %s. Existing rows keep NULL "
                        "for this column.",
                        name, table, rows, self.db_path,
                    )
                else:
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
        user_identity: Optional[str] = None,
        request_id: Optional[str] = None,
    ) -> None:
        """
        Record an audit event.

        `request_id` defaults to the correlation id of the request in
        flight (ADR-063), so every existing call site gains attribution
        without being changed. It is NULL outside a request — a collector
        poll, the CLI, a test — which is the accurate answer.
        """
        if request_id is None:
            try:
                from app.api.request_context import get_request_id

                request_id = get_request_id()
            except Exception:  # pragma: no cover - storage must not depend on the API
                request_id = None

        # The actor (ADR-067): an explicit identity wins; otherwise the
        # authenticated principal of the request in flight; otherwise the
        # local operator, which is accurate only because there is then no
        # authenticated caller - a local deployment, the CLI, a collector.
        if user_identity is None:
            try:
                from app.api.request_context import (
                    LOCAL_OPERATOR_IDENTITY,
                    get_principal_identity,
                )

                user_identity = get_principal_identity() or LOCAL_OPERATOR_IDENTITY
            except Exception:  # pragma: no cover - storage must not depend on the API
                user_identity = "local_operator"

        with self.get_connection() as conn:
            try:
                conn.execute(
                    """INSERT INTO audit_events (timestamp, action, resource_type,
                                                 resource_id, details, user_identity,
                                                 request_id)
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (
                        datetime.now(timezone.utc).isoformat(),
                        action,
                        resource_type,
                        resource_id,
                        details,
                        user_identity,
                        request_id,
                    ),
                )
            except sqlite3.OperationalError:
                # A database that predates the column. An audit entry is
                # more important than its attribution, so the entry is
                # still written.
                conn.execute(
                    """INSERT INTO audit_events (timestamp, action, resource_type,
                                                 resource_id, details, user_identity)
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


    def event_time_range(
        self,
        source_id: Optional[str] = None,
        not_before: Optional[str] = None,
        not_after: Optional[str] = None,
    ) -> Optional[tuple[datetime, datetime]]:
        """
        Earliest and latest observed_at, measured over the whole selection.

        Timestamps are stored as ISO-8601 UTC text, which orders
        lexicographically, so MIN/MAX are the true extremes. This exists so
        a dataset's SPAN is never inferred from a sample of its rows: on a
        dense corpus the most-recent 50,000 events can span under two
        minutes while the dataset spans half an hour (ADR-095).
        """
        query = "SELECT MIN(observed_at) AS lo, MAX(observed_at) AS hi FROM normalized_events WHERE 1=1"
        params: list = []
        if source_id:
            query += " AND source_id = ?"
            params.append(source_id)
        if not_before:
            query += " AND observed_at >= ?"
            params.append(not_before)
        if not_after:
            query += " AND observed_at <= ?"
            params.append(not_after)
        with self.get_connection() as conn:
            row = conn.execute(query, params).fetchone()
        if not row or not row["lo"] or not row["hi"]:
            return None
        try:
            return (datetime.fromisoformat(row["lo"]), datetime.fromisoformat(row["hi"]))
        except ValueError:
            return None

    def label_counts(self, source_id: Optional[str] = None) -> dict[str, int]:
        """
        How many events carry each label, over the whole selection.

        A GROUP BY, not a scan of materialised rows, so asking "does this
        corpus contain any attack at all" costs one query rather than
        reading a sample that may be drawn entirely from one end of the
        capture. NULL and empty labels are reported under "" so the caller
        can distinguish unlabelled from benign without guessing.
        """
        query = (
            "SELECT COALESCE(label, '') AS label, COUNT(*) AS n "
            "FROM normalized_events WHERE 1=1"
        )
        params: list = []
        if source_id:
            query += " AND source_id = ?"
            params.append(source_id)
        query += " GROUP BY COALESCE(label, '')"
        with self.get_connection() as conn:
            rows = conn.execute(query, params).fetchall()
        return {r["label"]: int(r["n"]) for r in rows}

    # ──────────────── audit listing (ADR-093) ────────────────

    def list_audit_events(
        self,
        limit: int = 100,
        offset: int = 0,
        resource_type: Optional[str] = None,
    ) -> list[dict]:
        """
        Audit entries, newest first.

        Returns plain dicts, not API models: storage describes rows, and the
        route decides how to present them. `request_id` is None on an entry
        written before the column existed and on anything with no request
        behind it (ADR-063) - both are accurate, and neither is invented.
        """
        query = "SELECT * FROM audit_events"
        params: list = []
        if resource_type:
            query += " WHERE resource_type = ?"
            params.append(resource_type)
        query += " ORDER BY id DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        with self.get_connection() as conn:
            rows = conn.execute(query, params).fetchall()
        return [
            {
                "id": r["id"],
                "timestamp": r["timestamp"],
                "action": r["action"],
                "resource_type": r["resource_type"] or "",
                "resource_id": r["resource_id"] or "",
                "details": r["details"] or "",
                "user_identity": r["user_identity"] or "system",
                "request_id": _opt(r, "request_id"),
            }
            for r in rows
        ]

    # ──────────────── retention queries (ADR-093) ────────────────

    def _retention_where(
        self, comparison: str, cutoff_iso: str,
        categories: list[str], source_id: Optional[str],
    ) -> tuple[str, list]:
        if not categories:
            raise ValueError(
                "A retention query must name at least one category; an empty "
                "list is ambiguous between 'nothing' and 'everything'."
            )
        placeholders = ",".join("?" * len(categories))
        where = f"observed_at {comparison} ? AND data_category IN ({placeholders})"
        params: list = [cutoff_iso, *categories]
        if source_id:
            where += " AND source_id = ?"
            params.append(source_id)
        return where, params

    def count_events_before(
        self, cutoff_iso: str, categories: list[str],
        source_id: Optional[str] = None,
    ) -> int:
        where, params = self._retention_where("<", cutoff_iso, categories, source_id)
        with self.get_connection() as conn:
            return conn.execute(
                f"SELECT COUNT(*) FROM normalized_events WHERE {where}", params
            ).fetchone()[0]

    def count_events_at_or_after(
        self, cutoff_iso: str, categories: list[str],
        source_id: Optional[str] = None,
    ) -> int:
        where, params = self._retention_where(">=", cutoff_iso, categories, source_id)
        with self.get_connection() as conn:
            return conn.execute(
                f"SELECT COUNT(*) FROM normalized_events WHERE {where}", params
            ).fetchone()[0]

    def oldest_event_ids_before(
        self, cutoff_iso: str, categories: list[str],
        source_id: Optional[str] = None, limit: int = 1000,
    ) -> list[str]:
        """The oldest eligible ids, so deletion proceeds oldest-first."""
        where, params = self._retention_where("<", cutoff_iso, categories, source_id)
        with self.get_connection() as conn:
            rows = conn.execute(
                f"SELECT event_id FROM normalized_events WHERE {where} "
                f"ORDER BY observed_at ASC LIMIT ?",
                [*params, limit],
            ).fetchall()
        return [r["event_id"] for r in rows]

    def delete_events_by_id(self, event_ids: list[str]) -> int:
        """
        Delete exactly these events; return how many rows were ACTUALLY removed.

        Not `len(event_ids)`. The caller selects ids and deletes them in two
        statements, so a row another writer removed in between is already
        gone - counting it here would report a deletion this run did not
        perform. The difference matters because that count is what the
        retention result tells an operator was destroyed.
        """
        if not event_ids:
            return 0
        with self.get_connection() as conn:
            cur = conn.executemany(
                "DELETE FROM normalized_events WHERE event_id = ?",
                [(i,) for i in event_ids],
            )
            return cur.rowcount if cur.rowcount is not None and cur.rowcount >= 0 else 0

    # ──────────────── diagnostics (ADR-093) ────────────────

    def storage_diagnostics(self) -> dict:
        """
        What SQLite can say about itself.

        `healthy` rests on PRAGMA integrity_check, a real structural check,
        and `health_basis` records that - so a reader comparing two backends
        can see what the word is standing on in each.
        """
        with self.get_connection() as conn:
            integrity = conn.execute("PRAGMA integrity_check").fetchone()[0]
            journal = conn.execute("PRAGMA journal_mode").fetchone()[0]
            page_count = conn.execute("PRAGMA page_count").fetchone()[0]
            page_size = conn.execute("PRAGMA page_size").fetchone()[0]
            columns = [
                r["name"] for r in conn.execute("PRAGMA table_info(normalized_events)")
            ]
        return {
            "backend": "sqlite",
            "integrity_check": integrity,
            "healthy": integrity == "ok",
            "health_basis": "PRAGMA integrity_check",
            "journal_mode": journal,
            "size_bytes": page_count * page_size,
            "event_count": self.count_events(),
            "source_count": len(self.list_sources()),
            "received_at_column_present": "received_at" in columns,
            "normalized_events_columns": len(columns),
        }

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

    def latest_received_at_by_source(self) -> dict[str, datetime]:
        """
        Most recent server-measured receipt per source.

        Only rows with a non-NULL ``received_at`` contribute, so a source
        that has never submitted over the API is simply absent — it is not
        given a fabricated receipt.
        """
        results: dict[str, datetime] = {}
        with self.get_connection() as conn:
            try:
                rows = conn.execute(
                    """SELECT source_id, MAX(received_at) AS latest
                       FROM normalized_events
                       WHERE received_at IS NOT NULL
                       GROUP BY source_id"""
                ).fetchall()
            except sqlite3.OperationalError:
                # Database predates the column; no receipt evidence exists.
                return {}
        for row in rows:
            if row["latest"]:
                try:
                    results[row["source_id"]] = datetime.fromisoformat(row["latest"])
                except ValueError:
                    logger.warning(
                        "Unparseable received_at for source %s", row["source_id"]
                    )
        return results

    def list_sources(self) -> list[TelemetrySource]:
        """List all telemetry sources."""
        with self.get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM telemetry_sources ORDER BY created_at DESC"
            ).fetchall()
            return [self._row_to_source(r) for r in rows]

    def _row_to_source(self, row) -> TelemetrySource:
        return row_to_source(row)

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
                            observed_at, ingested_at, received_at, event_type,
                            src_ip, dst_ip, src_port, dst_port, protocol,
                            duration, packets, bytes_total,
                            label, label_provenance, quality_flags, raw_reference,
                            app_protocol, http_method, http_path,
                            http_status_code, http_duration_ms, dst_hostname)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                                   ?, ?, ?, ?, ?, ?, ?)""",
                        (
                            event.event_id,
                            event.schema_version,
                            event.source_id,
                            event.data_category.value,
                            event.observed_at.isoformat(),
                            event.ingested_at.isoformat(),
                            # NULL when no receipt was measured. INSERT OR
                            # IGNORE means a re-delivered event keeps its
                            # ORIGINAL receipt time rather than acquiring the
                            # retry's — see ADR-048.
                            event.received_at.isoformat() if event.received_at else None,
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
                    else:
                        # Existing event with same ID exists. Verify that this is
                        # a legitimate retry/duplicate of the same logical event
                        # rather than conflicting reuse of the event ID.
                        existing = conn.execute(
                            "SELECT " + ", ".join(CONFLICT_FIELDS) + " "
                            "FROM normalized_events WHERE event_id = ?",
                            (event.event_id,),
                        ).fetchone()
                        if existing is not None:
                            # Every canonical field, not just the five-tuple.
                            # A changed byte count or label under a reused
                            # identity is a different claim about the world,
                            # and dropping it silently would corrupt the
                            # features and the training target alike.
                            differing = [
                                column
                                for column, extract in CONFLICT_FIELDS.items()
                                if existing[column] != extract(event)
                            ]
                            if differing:
                                raise EventIdentityConflictError(
                                    f"Event '{event.event_id}' already exists for source "
                                    f"'{existing['source_id']}' with different content. "
                                    f"Conflicting field(s): {', '.join(differing)}. "
                                    "The stored event was NOT modified."
                                )
                except EventIdentityConflictError:
                    raise
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

    def existing_event_ids(self, event_ids: list[str]) -> set[str]:
        """Which of these event ids are already stored. Parameterized, chunked."""
        found: set[str] = set()
        ids = list(dict.fromkeys(event_ids))
        with self.get_connection() as conn:
            for start in range(0, len(ids), 500):
                chunk = ids[start:start + 500]
                placeholders = ",".join("?" * len(chunk))
                rows = conn.execute(
                    f"SELECT event_id FROM normalized_events WHERE event_id IN ({placeholders})",
                    chunk,
                ).fetchall()
                found.update(row[0] for row in rows)
        return found

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

    def _row_to_event(self, row) -> NormalizedEvent:
        return row_to_event(row)

    @staticmethod
    def _opt(row, column):
        return _opt(row, column)

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

    # ──────────────── operator setting overrides (ADR-059) ────────────────

    def get_setting(self, key: str) -> Optional[str]:
        """The stored override for `key`, or None when none is set."""
        try:
            with self.get_connection() as conn:
                row = conn.execute(
                    "SELECT value FROM system_settings WHERE key = ?", (key,)
                ).fetchone()
        except sqlite3.OperationalError:
            # A database that predates the table. No override exists.
            return None
        return row["value"] if row else None

    def set_setting(self, key: str, value: str, updated_by: str = "operator") -> None:
        """Store an override. One statement, so it applies entirely or not at all."""
        with self.get_connection() as conn:
            conn.execute(
                """INSERT INTO system_settings (key, value, updated_at, updated_by)
                   VALUES (?, ?, ?, ?)
                   ON CONFLICT(key) DO UPDATE SET
                       value = excluded.value,
                       updated_at = excluded.updated_at,
                       updated_by = excluded.updated_by""",
                (key, value, datetime.now(timezone.utc).isoformat(), updated_by),
            )

    def clear_setting(self, key: str) -> bool:
        """Remove an override so the configured default applies again."""
        with self.get_connection() as conn:
            cur = conn.execute("DELETE FROM system_settings WHERE key = ?", (key,))
            return cur.rowcount > 0

    def set_source_enabled(self, source_id: str, enabled: bool) -> bool:
        """
        Enable or disable one source. Returns False when it does not exist.

        Only the `enabled` column is touched: an administrative toggle
        must not silently rewrite a source's counters or last-event time.
        """
        with self.get_connection() as conn:
            cur = conn.execute(
                "UPDATE telemetry_sources SET enabled = ? WHERE source_id = ?",
                (1 if enabled else 0, source_id),
            )
            return cur.rowcount > 0

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
                    top_dst_hostnames, hostname_attributed_count, events_per_hour,
                    bytes_measured_count, packets_measured_count,
                    duration_measured_count, implausible_timestamp_events)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                           ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
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
                    analysis.bytes_measured_count,
                    analysis.packets_measured_count,
                    analysis.duration_measured_count,
                    analysis.implausible_timestamp_events,
                ),
            )

    def count_analyses(self, source_id: Optional[str] = None) -> int:
        """How many descriptive analyses are stored."""
        query = "SELECT COUNT(*) FROM descriptive_analyses"
        params: list = []
        if source_id:
            query += " WHERE source_id = ?"
            params.append(source_id)
        with self.get_connection() as conn:
            return conn.execute(query, params).fetchone()[0]

    def analyses_exceeding_limit(
        self, keep: int, source_id: Optional[str] = None
    ) -> list[str]:
        """
        The analysis_ids that would be removed to leave the newest `keep`.

        Read-only: it names the candidates so an operator can see exactly
        what a prune would delete before authorising it. Ordering is by
        `computed_at` descending, with `analysis_id` as a tiebreak so the
        selection is deterministic when two analyses share a timestamp.
        """
        if keep < 0:
            raise ValueError("keep must not be negative")
        query = "SELECT analysis_id FROM descriptive_analyses"
        params: list = []
        if source_id:
            query += " WHERE source_id = ?"
            params.append(source_id)
        query += " ORDER BY computed_at DESC, analysis_id DESC"
        with self.get_connection() as conn:
            ids = [r["analysis_id"] for r in conn.execute(query, params)]
        return ids[keep:]

    def prune_analyses(self, keep: int, source_id: Optional[str] = None) -> int:
        """
        Delete all but the newest `keep` analyses. Returns the count removed.

        **Destructive, and deliberately never called automatically.** The
        only caller is an explicitly confirmed administrative endpoint
        (ADR-064). Analyses are historical records of what was computed,
        not a cache, so nothing in PraHari expires them on a timer, at
        startup, or as a side effect of a read.
        """
        doomed = self.analyses_exceeding_limit(keep, source_id=source_id)
        if not doomed:
            return 0
        with self.get_connection() as conn:
            conn.executemany(
                "DELETE FROM descriptive_analyses WHERE analysis_id = ?",
                [(a,) for a in doomed],
            )
        return len(doomed)

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

    def _row_to_analysis(self, row) -> DescriptiveAnalysis:
        return row_to_analysis(row)

    def _json_opt(self, row, column, default):
        return _json_opt(row, column, default)
