"""
PraHari — PostgreSQL Telemetry Store (ADR-092)

The blueprint proposes "SQLite local; PostgreSQL central" (§4.3, §9).
`app/storage/contract.py` wrote down what the application actually asks of
storage and said plainly what did not exist:

    "It does not make PostgreSQL work. No PostgreSQL backend exists, no
     driver is installed, and no server was available to test against."

This module is that backend. It is complete only on the terms the contract
set: it satisfies the `TelemetryStore` Protocol AND passes
`tests/integration/test_storage_contract.py` against a **real server** —
not a mock, because the properties under test (atomic batches, idempotent
identity, concurrent writers) are exactly what a mock cannot exhibit.

What is deliberate here
-----------------------
**Timestamps are stored as ISO-8601 TEXT, as SQLite stores them.** Native
`timestamptz` would be the more idiomatic column type, but it would also
make this backend return subtly different objects from the same logical
row: a different resolution, a normalised offset, and a dependence on the
server's timezone setting. Identical semantics across backends is worth
more here than idiomatic DDL, and ISO-8601 UTC text orders correctly, so
`ORDER BY observed_at` and `MAX(received_at)` behave as they do on SQLite.
The cost is that server-side date arithmetic is unavailable; nothing in
the contract needs it.

**Booleans are INTEGER 0/1**, again to match what the shared row
converters in `database.py` expect.

**A batch inserts in event_id order.** PostgreSQL blocks a second
transaction that touches a row an uncommitted transaction has inserted,
so two concurrent batches overlapping on two ids in opposite orders would
deadlock. SQLite cannot deadlock this way because it serialises writers.
Sorting gives every transaction one global acquisition order, which is
what makes the contract's eight-writer test pass rather than hang.

What this does NOT establish
----------------------------
The application still runs on SQLite. The three abstraction leaks named in
`contract.KNOWN_ABSTRACTION_LEAKS` issue SQLite-dialect SQL directly and
are NOT fixed here, so this backend cannot simply be substituted under the
running application yet. It is a conforming store, proven against a real
server; it is not a deployed central database, and no production
deployment, TLS arrangement, backup or migration story is claimed.
"""

from __future__ import annotations

import json
import logging
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Generator, Optional

from app.schemas.events import (
    DataCategory,
    DescriptiveAnalysis,
    ImportSummary,
    NormalizedEvent,
    TelemetrySource,
)
from app.storage.database import (
    CONFLICT_FIELDS,
    EventIdentityConflictError,
    row_to_analysis,
    row_to_event,
    row_to_source,
)

logger = logging.getLogger(__name__)

try:  # pragma: no cover - import guard, exercised by its absence
    import psycopg
    from psycopg.rows import dict_row

    PSYCOPG_AVAILABLE = True
except ImportError:  # pragma: no cover
    psycopg = None  # type: ignore[assignment]
    dict_row = None  # type: ignore[assignment]
    PSYCOPG_AVAILABLE = False


class PostgresDriverMissing(RuntimeError):
    """Raised on construction when psycopg is not installed."""


# ──────────────────────────────────────────────────────────────────
# Schema
#
# The SQLite DDL translated construct for construct, per the table in
# contract.SQLITE_DIALECT_CONSTRUCTS. Column names, nullability and
# defaults are identical, because the shared row converters read them.
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
    -- NULL means "no measured receipt time", exactly as on SQLite. Never
    -- backfilled: a re-delivered event keeps its ORIGINAL receipt.
    received_at     TEXT,
    event_type      TEXT NOT NULL DEFAULT 'network_flow',
    src_ip          TEXT,
    dst_ip          TEXT,
    src_port        INTEGER,
    dst_port        INTEGER,
    protocol        TEXT,
    duration        DOUBLE PRECISION,
    packets         BIGINT,
    bytes_total     BIGINT,
    label           TEXT,
    label_provenance TEXT NOT NULL DEFAULT 'unlabeled',
    quality_flags   TEXT NOT NULL DEFAULT '[]',
    raw_reference   TEXT,
    app_protocol    TEXT,
    http_method     TEXT,
    http_path       TEXT,
    http_status_code INTEGER,
    http_duration_ms DOUBLE PRECISION,
    dst_hostname    TEXT,
    FOREIGN KEY (source_id) REFERENCES telemetry_sources(source_id)
);

CREATE INDEX IF NOT EXISTS idx_events_source ON normalized_events(source_id);
CREATE INDEX IF NOT EXISTS idx_events_observed ON normalized_events(observed_at);
CREATE INDEX IF NOT EXISTS idx_events_label ON normalized_events(label);
CREATE INDEX IF NOT EXISTS idx_events_type ON normalized_events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_category ON normalized_events(data_category);
CREATE INDEX IF NOT EXISTS idx_events_dst_ip ON normalized_events(dst_ip);

CREATE TABLE IF NOT EXISTS dns_observations (
    id              BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
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
    avg_duration        DOUBLE PRECISION,
    avg_packets         DOUBLE PRECISION,
    avg_bytes           DOUBLE PRECISION,
    total_bytes         BIGINT,
    -- -1 means "this analysis predates the column", which is distinct from
    -- a genuine 0; see database.py's _measured().
    bytes_measured_count INTEGER NOT NULL DEFAULT -1,
    packets_measured_count INTEGER NOT NULL DEFAULT -1,
    duration_measured_count INTEGER NOT NULL DEFAULT -1,
    implausible_timestamp_events INTEGER NOT NULL DEFAULT -1,
    FOREIGN KEY (source_id) REFERENCES telemetry_sources(source_id)
);

CREATE TABLE IF NOT EXISTS audit_events (
    id              BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
    timestamp       TEXT NOT NULL,
    action          TEXT NOT NULL,
    resource_type   TEXT,
    resource_id     TEXT,
    details         TEXT,
    user_identity   TEXT DEFAULT 'local_operator',
    request_id      TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_events(timestamp);

CREATE TABLE IF NOT EXISTS system_settings (
    key         TEXT PRIMARY KEY,
    value       TEXT NOT NULL,
    updated_at  TEXT NOT NULL,
    updated_by  TEXT
);
"""


class PostgresStore:
    """
    A `TelemetryStore` over PostgreSQL.

    `schema` scopes every table to one namespace, so a test run, a tenant
    or a trial migration can share a server without colliding. It is set on
    the connection's `search_path` rather than interpolated into each
    statement.
    """

    def __init__(self, dsn: str, schema: str = "public") -> None:
        if not PSYCOPG_AVAILABLE:
            raise PostgresDriverMissing(
                "psycopg is not installed, so the PostgreSQL backend cannot be "
                "used. Install `psycopg[binary]`. PraHari does not fall back to "
                "SQLite here: silently storing central telemetry somewhere other "
                "than the configured database would be worse than refusing."
            )
        if not schema.isidentifier():
            raise ValueError(f"schema {schema!r} is not a plain identifier")
        self.dsn = dsn
        self.schema = schema

    # ──────────────── lifecycle ────────────────

    @contextmanager
    def get_connection(self) -> Generator[Any, None, None]:
        """
        A connection scoped to this store's schema.

        Mirrors the SQLite manager's contract: commit on success, roll back
        on any exception, always close. A batch therefore applies entirely
        or not at all.
        """
        conn = psycopg.connect(self.dsn, row_factory=dict_row)
        try:
            conn.execute(f'SET search_path TO "{self.schema}"')
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def initialize(self) -> None:
        """Create the schema and its tables if absent."""
        conn = psycopg.connect(self.dsn, row_factory=dict_row)
        try:
            conn.execute(f'CREATE SCHEMA IF NOT EXISTS "{self.schema}"')
            conn.execute(f'SET search_path TO "{self.schema}"')
            conn.execute(TABLES_DDL)
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
        logger.info("PostgreSQL store initialized in schema %s", self.schema)

    def close(self) -> None:
        """No persistent connection is held, so there is nothing to close."""
        return None

    def drop_schema(self) -> None:
        """
        Remove this store's schema and everything in it.

        Destructive, and provided for test teardown and an explicitly
        confirmed administrative teardown only — never called by the
        application.
        """
        conn = psycopg.connect(self.dsn)
        try:
            conn.execute(f'DROP SCHEMA IF EXISTS "{self.schema}" CASCADE')
            conn.commit()
        finally:
            conn.close()

    # ──────────────── audit ────────────────

    def log_audit(
        self,
        action: str,
        resource_type: str = "",
        resource_id: str = "",
        details: str = "",
        user_identity: Optional[str] = None,
        request_id: Optional[str] = None,
    ) -> None:
        """Record an audit event, attributing it as the SQLite store does."""
        if request_id is None:
            try:
                from app.api.request_context import get_request_id

                request_id = get_request_id()
            except Exception:  # pragma: no cover - storage must not depend on the API
                request_id = None

        if user_identity is None:
            try:
                from app.api.request_context import (
                    LOCAL_OPERATOR_IDENTITY,
                    get_principal_identity,
                )

                user_identity = get_principal_identity() or LOCAL_OPERATOR_IDENTITY
            except Exception:  # pragma: no cover
                user_identity = "local_operator"

        with self.get_connection() as conn:
            conn.execute(
                """INSERT INTO audit_events (timestamp, action, resource_type,
                                             resource_id, details, user_identity,
                                             request_id)
                   VALUES (%s, %s, %s, %s, %s, %s, %s)""",
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


    # ──────────────── audit listing (ADR-093) ────────────────

    def list_audit_events(
        self,
        limit: int = 100,
        offset: int = 0,
        resource_type: Optional[str] = None,
    ) -> list[dict]:
        """Audit entries, newest first, with the same keys as SQLite returns."""
        query = "SELECT * FROM audit_events"
        params: list = []
        if resource_type:
            query += " WHERE resource_type = %s"
            params.append(resource_type)
        query += " ORDER BY id DESC LIMIT %s OFFSET %s"
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
                "request_id": r["request_id"],
            }
            for r in rows
        ]

    # ──────────────── retention queries (ADR-093) ────────────────

    @staticmethod
    def _retention_where(
        comparison: str, cutoff_iso: str,
        categories: list[str], source_id: Optional[str],
    ) -> tuple[str, list]:
        if not categories:
            raise ValueError(
                "A retention query must name at least one category; an empty "
                "list is ambiguous between 'nothing' and 'everything'."
            )
        where = f"observed_at {comparison} %s AND data_category = ANY(%s)"
        params: list = [cutoff_iso, list(categories)]
        if source_id:
            where += " AND source_id = %s"
            params.append(source_id)
        return where, params

    def count_events_before(
        self, cutoff_iso: str, categories: list[str],
        source_id: Optional[str] = None,
    ) -> int:
        where, params = self._retention_where("<", cutoff_iso, categories, source_id)
        with self.get_connection() as conn:
            return int(
                conn.execute(
                    f"SELECT COUNT(*) AS n FROM normalized_events WHERE {where}",
                    params,
                ).fetchone()["n"]
            )

    def count_events_at_or_after(
        self, cutoff_iso: str, categories: list[str],
        source_id: Optional[str] = None,
    ) -> int:
        where, params = self._retention_where(">=", cutoff_iso, categories, source_id)
        with self.get_connection() as conn:
            return int(
                conn.execute(
                    f"SELECT COUNT(*) AS n FROM normalized_events WHERE {where}",
                    params,
                ).fetchone()["n"]
            )

    def oldest_event_ids_before(
        self, cutoff_iso: str, categories: list[str],
        source_id: Optional[str] = None, limit: int = 1000,
    ) -> list[str]:
        where, params = self._retention_where("<", cutoff_iso, categories, source_id)
        with self.get_connection() as conn:
            rows = conn.execute(
                f"SELECT event_id FROM normalized_events WHERE {where} "
                f"ORDER BY observed_at ASC LIMIT %s",
                [*params, limit],
            ).fetchall()
        return [r["event_id"] for r in rows]

    def delete_events_by_id(self, event_ids: list[str]) -> int:
        """
        Delete exactly these events; return how many rows were ACTUALLY
        removed - not `len(event_ids)`. See the SQLite backend's note: the
        count is what an operator is told was destroyed.
        """
        if not event_ids:
            return 0
        with self.get_connection() as conn:
            cur = conn.execute(
                "DELETE FROM normalized_events WHERE event_id = ANY(%s)",
                (list(event_ids),),
            )
            return cur.rowcount if cur.rowcount and cur.rowcount > 0 else 0

    # ──────────────── diagnostics (ADR-093) ────────────────

    def storage_diagnostics(self) -> dict:
        """
        What PostgreSQL can say about itself.

        `integrity_check` and `journal_mode` are SQLite's; PostgreSQL has no
        single-statement equivalent of the first, and its WAL is not a mode
        that can be switched the way SQLite's journal can. Both keys are
        therefore present and **None**, each with a note, rather than filled
        with a plausible-looking value: reporting "ok" for a check that was
        never run would be a fabricated measurement, which is exactly what
        §11's honesty rules forbid.

        `healthy` here means the store answered a query, and `health_basis`
        says so, so the word is not read as the structural check SQLite
        actually performs.
        """
        with self.get_connection() as conn:
            version = conn.execute("SHOW server_version").fetchone()["server_version"]
            size = conn.execute(
                "SELECT pg_database_size(current_database()) AS n"
            ).fetchone()["n"]
            columns = [
                r["column_name"]
                for r in conn.execute(
                    """SELECT column_name FROM information_schema.columns
                       WHERE table_schema = %s AND table_name = 'normalized_events'""",
                    (self.schema,),
                ).fetchall()
            ]
        return {
            "backend": "postgresql",
            "server_version": version,
            "schema": self.schema,
            "integrity_check": None,
            "integrity_check_note": (
                "PostgreSQL has no single-statement equivalent of SQLite's "
                "PRAGMA integrity_check. Reported as not measured rather than "
                "as 'ok'."
            ),
            "healthy": True,
            "health_basis": "the store answered a query; no structural check was run",
            "journal_mode": None,
            "journal_mode_note": (
                "PostgreSQL always uses WAL and it is not a per-database mode "
                "to report, so this SQLite field is not measured here."
            ),
            "size_bytes": int(size),
            "event_count": self.count_events(),
            "source_count": len(self.list_sources()),
            "received_at_column_present": "received_at" in columns,
            "normalized_events_columns": len(columns),
        }

    # ──────────────── sources ────────────────

    def upsert_source(self, source: TelemetrySource) -> None:
        with self.get_connection() as conn:
            conn.execute(
                """INSERT INTO telemetry_sources
                   (source_id, name, source_type, description, enabled,
                    created_at, last_event_at, event_count, status)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                   ON CONFLICT (source_id) DO UPDATE SET
                     name=EXCLUDED.name,
                     source_type=EXCLUDED.source_type,
                     description=EXCLUDED.description,
                     enabled=EXCLUDED.enabled,
                     last_event_at=EXCLUDED.last_event_at,
                     event_count=EXCLUDED.event_count,
                     status=EXCLUDED.status""",
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
        Recompute a source's counters from stored events.

        `event_count` is derived, never incremented, and `last_event_at`
        only moves forward — the same rules as the SQLite store, for the
        same reasons.
        """
        with self.get_connection() as conn:
            row = conn.execute(
                "SELECT source_id FROM telemetry_sources WHERE source_id = %s",
                (source_id,),
            ).fetchone()
            if row is None:
                return None

            ts = last_event_at.isoformat() if last_event_at else None
            conn.execute(
                """UPDATE telemetry_sources
                   SET event_count = (
                           SELECT COUNT(*) FROM normalized_events
                           WHERE source_id = %(sid)s
                       ),
                       -- Cast explicitly: PostgreSQL cannot infer the type
                       -- of a bare parameter in a CASE predicate, and
                       -- raises AmbiguousParameter rather than guessing.
                       last_event_at = CASE
                           WHEN %(ts)s::text IS NULL THEN last_event_at
                           WHEN last_event_at IS NULL THEN %(ts)s::text
                           WHEN %(ts)s::text > last_event_at THEN %(ts)s::text
                           ELSE last_event_at
                       END,
                       status = COALESCE(%(status)s::text, status)
                   WHERE source_id = %(sid)s""",
                {"sid": source_id, "ts": ts, "status": status},
            )
            updated = conn.execute(
                "SELECT * FROM telemetry_sources WHERE source_id = %s",
                (source_id,),
            ).fetchone()
            return row_to_source(updated) if updated else None

    def get_source(self, source_id: str) -> Optional[TelemetrySource]:
        with self.get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM telemetry_sources WHERE source_id = %s",
                (source_id,),
            ).fetchone()
            return row_to_source(row) if row else None

    def list_sources(self) -> list[TelemetrySource]:
        with self.get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM telemetry_sources ORDER BY created_at DESC"
            ).fetchall()
            return [row_to_source(r) for r in rows]

    def set_source_enabled(self, source_id: str, enabled: bool) -> bool:
        """Only the `enabled` column is touched; counters are left alone."""
        with self.get_connection() as conn:
            cur = conn.execute(
                "UPDATE telemetry_sources SET enabled = %s WHERE source_id = %s",
                (1 if enabled else 0, source_id),
            )
            return cur.rowcount > 0

    def latest_received_at_by_source(self) -> dict[str, datetime]:
        """
        Most recent server-measured receipt per source.

        Rows with a NULL `received_at` contribute nothing, so a source that
        never submitted over the API is absent rather than given a
        fabricated receipt.
        """
        results: dict[str, datetime] = {}
        with self.get_connection() as conn:
            rows = conn.execute(
                """SELECT source_id, MAX(received_at) AS latest
                   FROM normalized_events
                   WHERE received_at IS NOT NULL
                   GROUP BY source_id"""
            ).fetchall()
        for row in rows:
            if row["latest"]:
                try:
                    results[row["source_id"]] = datetime.fromisoformat(row["latest"])
                except ValueError:
                    logger.warning(
                        "Unparseable received_at for source %s", row["source_id"]
                    )
        return results

    # ──────────────── events ────────────────

    _EVENT_COLUMNS = (
        "event_id, schema_version, source_id, data_category, observed_at, "
        "ingested_at, received_at, event_type, src_ip, dst_ip, src_port, "
        "dst_port, protocol, duration, packets, bytes_total, label, "
        "label_provenance, quality_flags, raw_reference, app_protocol, "
        "http_method, http_path, http_status_code, http_duration_ms, dst_hostname"
    )

    @staticmethod
    def _event_values(event: NormalizedEvent) -> tuple:
        return (
            event.event_id,
            event.schema_version,
            event.source_id,
            event.data_category.value,
            event.observed_at.isoformat(),
            event.ingested_at.isoformat(),
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
        )

    def insert_events(self, events: list[NormalizedEvent]) -> int:
        """
        Insert events idempotently; return how many were newly stored.

        A re-delivered event is ignored, keeping its ORIGINAL receipt time.
        A reused event_id carrying DIFFERENT content is a conflict: it
        raises, and the surrounding transaction rolls the whole batch back,
        so a partial batch is never committed.

        Insertion is ordered by event_id. PostgreSQL makes a transaction
        wait on a row another uncommitted transaction inserted, so two
        overlapping batches acquiring ids in opposite orders deadlock, and
        one of them is aborted by the server. Sorting gives every writer the
        same acquisition order, which removes the cycle.

        This ordering - not a lock - is what makes concurrent delivery safe.
        An in-process lock would serialise this process's threads while
        doing nothing for a second process against the same database, which
        is precisely the central-mode case the blueprint describes.
        """
        if not events:
            return 0

        ordered = sorted(events, key=lambda e: e.event_id)
        count = 0
        with self.get_connection() as conn:
            for event in ordered:
                try:
                    cur = conn.execute(
                        f"""INSERT INTO normalized_events ({self._EVENT_COLUMNS})
                            VALUES ({", ".join(["%s"] * 26)})
                            ON CONFLICT (event_id) DO NOTHING""",
                        self._event_values(event),
                    )
                except psycopg.errors.ForeignKeyViolation as exc:
                    # ON CONFLICT DO NOTHING absorbs a duplicate key, not a
                    # foreign-key violation. Logging this as a duplicate and
                    # continuing would discard the event and report success.
                    raise psycopg.IntegrityError(
                        f"Failed to persist event {event.event_id} for source "
                        f"'{event.source_id}': {exc}. Ensure the telemetry source "
                        f"is registered before inserting its events."
                    ) from exc

                if cur.rowcount > 0:
                    count += 1
                    continue

                existing = conn.execute(
                    "SELECT " + ", ".join(CONFLICT_FIELDS) + " "
                    "FROM normalized_events WHERE event_id = %s",
                    (event.event_id,),
                ).fetchone()
                if existing is None:
                    continue
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
        return count

    def existing_event_ids(self, event_ids: list[str]) -> set[str]:
        """Which of these ids are already stored. Parameterized, chunked."""
        found: set[str] = set()
        ids = list(dict.fromkeys(event_ids))
        if not ids:
            return found
        with self.get_connection() as conn:
            for start in range(0, len(ids), 500):
                chunk = ids[start:start + 500]
                rows = conn.execute(
                    "SELECT event_id FROM normalized_events WHERE event_id = ANY(%s)",
                    (chunk,),
                ).fetchall()
                found.update(r["event_id"] for r in rows)
        return found

    def get_event(self, event_id: str) -> Optional[NormalizedEvent]:
        with self.get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM normalized_events WHERE event_id = %s",
                (event_id,),
            ).fetchone()
            return row_to_event(row) if row else None

    def _event_filters(
        self,
        source_id: Optional[str],
        label: Optional[str],
        event_type: Optional[str],
        data_category: Optional[str],
    ) -> tuple[str, list]:
        clause = ""
        params: list = []
        if source_id:
            clause += " AND source_id = %s"
            params.append(source_id)
        if label:
            clause += " AND label = %s"
            params.append(label)
        if event_type:
            clause += " AND event_type = %s"
            params.append(event_type)
        if data_category:
            clause += " AND data_category = %s"
            params.append(data_category)
        return clause, params

    def list_events(
        self,
        source_id: Optional[str] = None,
        label: Optional[str] = None,
        event_type: Optional[str] = None,
        data_category: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[NormalizedEvent]:
        clause, params = self._event_filters(source_id, label, event_type, data_category)
        query = (
            "SELECT * FROM normalized_events WHERE 1=1" + clause
            + " ORDER BY observed_at DESC LIMIT %s OFFSET %s"
        )
        params.extend([limit, offset])
        with self.get_connection() as conn:
            rows = conn.execute(query, params).fetchall()
            return [row_to_event(r) for r in rows]

    def count_events(
        self,
        source_id: Optional[str] = None,
        label: Optional[str] = None,
        event_type: Optional[str] = None,
        data_category: Optional[str] = None,
    ) -> int:
        """Accepts every filter `list_events` accepts, so a filtered query
        can never report the unfiltered total."""
        clause, params = self._event_filters(source_id, label, event_type, data_category)
        with self.get_connection() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS n FROM normalized_events WHERE 1=1" + clause,
                params,
            ).fetchone()
            return int(row["n"]) if row else 0

    # ──────────────── DNS observations ────────────────

    def record_dns_observations(self, observations: list[dict]) -> int:
        """Append-only: a later answer never erases an earlier one."""
        if not observations:
            return 0
        inserted = 0
        with self.get_connection() as conn:
            for obs in observations:
                cur = conn.execute(
                    """INSERT INTO dns_observations
                       (ip_address, hostname, observed_at, method, ttl_seconds, source_id)
                       VALUES (%s, %s, %s, %s, %s, %s)
                       ON CONFLICT (ip_address, hostname, observed_at) DO NOTHING""",
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
        with self.get_connection() as conn:
            rows = conn.execute(
                """SELECT hostname, observed_at, method, ttl_seconds
                   FROM dns_observations
                   WHERE ip_address = %s
                   ORDER BY observed_at DESC
                   LIMIT %s""",
                (ip_address, limit),
            ).fetchall()
            return [dict(r) for r in rows]

    def get_dns_observations_for_ips(self, ips: list[str]) -> dict[str, list[dict]]:
        if not ips:
            return {}
        unique = list({ip for ip in ips if ip})
        out: dict[str, list[dict]] = {ip: [] for ip in unique}
        if not unique:
            return out
        with self.get_connection() as conn:
            rows = conn.execute(
                """SELECT ip_address, hostname, observed_at, method, ttl_seconds
                   FROM dns_observations
                   WHERE ip_address = ANY(%s)
                   ORDER BY observed_at DESC""",
                (unique,),
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
            return int(
                conn.execute("SELECT COUNT(*) AS n FROM dns_observations").fetchone()["n"]
            )

    def count_dns_distinct_ips(self) -> int:
        with self.get_connection() as conn:
            return int(
                conn.execute(
                    "SELECT COUNT(DISTINCT ip_address) AS n FROM dns_observations"
                ).fetchone()["n"]
            )

    # ──────────────── settings ────────────────

    def get_setting(self, key: str) -> Optional[str]:
        with self.get_connection() as conn:
            row = conn.execute(
                "SELECT value FROM system_settings WHERE key = %s", (key,)
            ).fetchone()
        return row["value"] if row else None

    def set_setting(self, key: str, value: str, updated_by: str = "operator") -> None:
        with self.get_connection() as conn:
            conn.execute(
                """INSERT INTO system_settings (key, value, updated_at, updated_by)
                   VALUES (%s, %s, %s, %s)
                   ON CONFLICT (key) DO UPDATE SET
                       value = EXCLUDED.value,
                       updated_at = EXCLUDED.updated_at,
                       updated_by = EXCLUDED.updated_by""",
                (key, value, datetime.now(timezone.utc).isoformat(), updated_by),
            )

    def clear_setting(self, key: str) -> bool:
        with self.get_connection() as conn:
            cur = conn.execute("DELETE FROM system_settings WHERE key = %s", (key,))
            return cur.rowcount > 0

    # ──────────────── import summaries ────────────────

    def save_import_summary(self, summary: ImportSummary) -> None:
        with self.get_connection() as conn:
            conn.execute(
                """INSERT INTO import_summaries
                   (import_id, source_id, source_file, data_category,
                    started_at, completed_at, total_records, accepted_records,
                    rejected_records, warnings_count, rejection_reasons,
                    schema_version)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
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
        query = "SELECT * FROM import_summaries"
        params: list = []
        if source_id:
            query += " WHERE source_id = %s"
            params.append(source_id)
        query += " ORDER BY started_at DESC"

        with self.get_connection() as conn:
            rows = conn.execute(query, params).fetchall()
        return [
            ImportSummary(
                import_id=r["import_id"],
                source_id=r["source_id"],
                source_file=r["source_file"],
                data_category=DataCategory(r["data_category"]),
                started_at=datetime.fromisoformat(r["started_at"]),
                completed_at=(
                    datetime.fromisoformat(r["completed_at"]) if r["completed_at"] else None
                ),
                total_records=r["total_records"],
                accepted_records=r["accepted_records"],
                rejected_records=r["rejected_records"],
                warnings_count=r["warnings_count"],
                rejection_reasons=json.loads(r["rejection_reasons"]),
                schema_version=r["schema_version"],
            )
            for r in rows
        ]

    # ──────────────── analyses ────────────────

    _ANALYSIS_COLUMNS = (
        "analysis_id, analysis_type, source_id, computed_at, schema_version, "
        "data_category, total_events, events_by_type, events_by_label, "
        "events_by_protocol, time_range_start, time_range_end, "
        "missing_field_counts, quality_flag_counts, records_with_warnings, "
        "unique_src_ips, unique_dst_ips, unique_src_ports, unique_dst_ports, "
        "top_src_ips, top_dst_ips, top_dst_ports, avg_duration, avg_packets, "
        "avg_bytes, total_bytes, unsupported_field_counts, source_limitations, "
        "data_categories, source_breakdown, is_mixed_provenance, "
        "events_by_connection_state, events_by_process, top_dst_hostnames, "
        "hostname_attributed_count, events_per_hour, bytes_measured_count, "
        "packets_measured_count, duration_measured_count, "
        "implausible_timestamp_events"
    )

    def save_analysis(self, analysis: DescriptiveAnalysis) -> None:
        columns = [c.strip() for c in self._ANALYSIS_COLUMNS.split(",")]
        updates = ", ".join(
            f"{c}=EXCLUDED.{c}" for c in columns if c != "analysis_id"
        )
        with self.get_connection() as conn:
            conn.execute(
                """INSERT INTO telemetry_sources
                   (source_id, name, source_type, description, created_at)
                   VALUES (%s, %s, 'aggregate', 'Auto-created source reference', %s)
                   ON CONFLICT (source_id) DO NOTHING""",
                (
                    analysis.source_id,
                    analysis.source_id,
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
            conn.execute(
                f"""INSERT INTO descriptive_analyses ({self._ANALYSIS_COLUMNS})
                    VALUES ({", ".join(["%s"] * len(columns))})
                    ON CONFLICT (analysis_id) DO UPDATE SET {updates}""",
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
        query = "SELECT COUNT(*) AS n FROM descriptive_analyses"
        params: list = []
        if source_id:
            query += " WHERE source_id = %s"
            params.append(source_id)
        with self.get_connection() as conn:
            return int(conn.execute(query, params).fetchone()["n"])

    def analyses_exceeding_limit(
        self, keep: int, source_id: Optional[str] = None
    ) -> list[str]:
        """
        Read-only preview of what a prune would delete.

        Ordered by `computed_at` descending with `analysis_id` as tiebreak,
        so the selection is deterministic when timestamps collide.
        """
        if keep < 0:
            raise ValueError("keep must not be negative")
        query = "SELECT analysis_id FROM descriptive_analyses"
        params: list = []
        if source_id:
            query += " WHERE source_id = %s"
            params.append(source_id)
        query += " ORDER BY computed_at DESC, analysis_id DESC"
        with self.get_connection() as conn:
            ids = [r["analysis_id"] for r in conn.execute(query, params).fetchall()]
        return ids[keep:]

    def prune_analyses(self, keep: int, source_id: Optional[str] = None) -> int:
        """
        Destructive, and never called automatically — analyses are
        historical records, not a cache.
        """
        doomed = self.analyses_exceeding_limit(keep, source_id=source_id)
        if not doomed:
            return 0
        with self.get_connection() as conn:
            conn.execute(
                "DELETE FROM descriptive_analyses WHERE analysis_id = ANY(%s)",
                (doomed,),
            )
        return len(doomed)

    def get_latest_analysis(
        self, source_id: Optional[str] = None
    ) -> Optional[DescriptiveAnalysis]:
        query = "SELECT * FROM descriptive_analyses"
        params: list = []
        if source_id:
            query += " WHERE source_id = %s"
            params.append(source_id)
        query += " ORDER BY computed_at DESC LIMIT 1"
        with self.get_connection() as conn:
            row = conn.execute(query, params).fetchone()
            return row_to_analysis(row) if row else None

    def list_analyses(self) -> list[DescriptiveAnalysis]:
        with self.get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM descriptive_analyses ORDER BY computed_at DESC"
            ).fetchall()
            return [row_to_analysis(r) for r in rows]
