"""
PraHari — The Storage Contract (ADR-071)

The blueprint proposes SQLite locally and PostgreSQL for a central
multi-user store "where justified". Earlier status reports said PostgreSQL
was blocked only by the absence of a service and that "repository
abstractions already exist". The second half was wrong: there was no
abstraction at all, only the concrete SQLite `Database` class.

This module is that abstraction, stated as what the application actually
calls - derived from every `db.<method>(` call site in `app/`, not from a
wish list. `tests/integration/test_storage_contract.py` is the executable
half: behaviour every backend must exhibit, run against SQLite and against
PostgreSQL. A PostgreSQL backend is done when it satisfies this Protocol
AND passes that suite against a real server - not before, and not against
a mock.

That backend now exists: `app/storage/postgres.py` (ADR-092). It satisfies
this Protocol and passes the conformance suite against PostgreSQL 16.15,
alongside a PostgreSQL-specific suite and cross-backend equivalence tests
asserting both stores return equal objects from the same rows.

What this does NOT do
---------------------
It does not make PostgreSQL the store the application runs on. The three
leaks below still issue SQLite-dialect SQL directly, so the backend cannot
yet be substituted under the running application, and nothing about a
production deployment - TLS, backups, migrations, a tuned server - is
claimed by a conformance run.

Known abstraction leaks
-----------------------
Three modules outside `storage/` open a raw connection and issue
SQLite-dialect SQL themselves. A second backend cannot be substituted
until each moves behind a method of this contract - this is what still
stands between a conforming PostgreSQL store and a PostgreSQL deployment.
They are listed so the leak is visible, and a test fails if a FOURTH
appears.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional, Protocol, runtime_checkable

from app.schemas.events import NormalizedEvent, TelemetrySource

# Empty, and kept as a ratchet (ADR-093): the three modules that used to
# open a raw connection - audit listing, storage diagnostics and retention
# - now go through the methods below. A test fails if a new one appears.
KNOWN_ABSTRACTION_LEAKS: frozenset[str] = frozenset()

# SQLite-specific constructs a port must translate. Recorded from
# database.py so the size of the job is known rather than estimated.
SQLITE_DIALECT_CONSTRUCTS = {
    "INSERT OR IGNORE": "ON CONFLICT DO NOTHING",
    "INSERT OR REPLACE": "ON CONFLICT (...) DO UPDATE",
    "PRAGMA": "no equivalent; journal and foreign-key settings are server-side",
    "AUTOINCREMENT": "GENERATED ... AS IDENTITY",
    "? placeholders": "%s (psycopg) or $n (asyncpg)",
    "sqlite3.IntegrityError": "the driver's UniqueViolation / IntegrityError",
}


@runtime_checkable
class TelemetryStore(Protocol):
    """Everything the application asks of storage."""

    # lifecycle
    def initialize(self) -> None: ...
    def close(self) -> None: ...

    # sources
    def upsert_source(self, source: TelemetrySource) -> None: ...
    def get_source(self, source_id: str) -> Optional[TelemetrySource]: ...
    def list_sources(self) -> list[TelemetrySource]: ...
    def set_source_enabled(self, source_id: str, enabled: bool) -> bool: ...
    def refresh_source_activity(
        self, source_id: str, last_event_at: Optional[datetime] = None,
        status: Optional[str] = None,
    ) -> Any: ...

    # events - insert is idempotent on event identity, and a batch is
    # atomic: an identity conflict rolls the whole batch back.
    def insert_events(self, events: list[NormalizedEvent]) -> int: ...
    def get_event(self, event_id: str) -> Optional[NormalizedEvent]: ...
    def list_events(self, source_id: Optional[str] = None, *args: Any, **kwargs: Any) -> list[NormalizedEvent]: ...
    def count_events(self, source_id: Optional[str] = None, *args: Any, **kwargs: Any) -> int: ...
    def latest_received_at_by_source(self) -> dict[str, datetime]: ...
    # Dataset-level span, measured by the store rather than inferred from a
    # sample of rows (ADR-095). `not_before`/`not_after` are ISO bounds the
    # caller supplies so the plausibility rule stays in one place.
    def event_time_range(
        self, source_id: Optional[str] = None,
        not_before: Optional[str] = None, not_after: Optional[str] = None,
    ) -> Optional[tuple[datetime, datetime]]: ...
    # Label histogram over the whole selection. Whether a dataset contains
    # any positive at all is a property of the dataset; a sample drawn
    # from one end of it cannot answer that (ADR-095).
    def label_counts(self, source_id: Optional[str] = None) -> dict[str, int]: ...

    # imports
    def save_import_summary(self, summary: Any) -> None: ...
    def list_import_summaries(self, source_id: Optional[str] = None) -> list[Any]: ...

    # DNS observations
    def record_dns_observations(self, observations: list[dict]) -> int: ...
    def get_dns_observations_for_ip(self, ip_address: str, limit: int = 50) -> list[dict]: ...
    def get_dns_observations_for_ips(self, ips: list[str]) -> dict[str, list[dict]]: ...
    def count_dns_observations(self) -> int: ...
    def count_dns_distinct_ips(self) -> int: ...

    # analyses - historical records; nothing prunes them implicitly
    def save_analysis(self, analysis: Any) -> None: ...
    def get_latest_analysis(self, source_id: Optional[str] = None) -> Optional[Any]: ...
    def list_analyses(self) -> list[Any]: ...
    def count_analyses(self, source_id: Optional[str] = None) -> int: ...
    def analyses_exceeding_limit(self, keep: int, source_id: Optional[str] = None) -> list[str]: ...
    def prune_analyses(self, keep: int, source_id: Optional[str] = None) -> int: ...

    # audit - request id and actor default from the request context
    def log_audit(
        self, action: str, resource_type: str = "", resource_id: str = "",
        details: str = "", user_identity: Optional[str] = None,
        request_id: Optional[str] = None,
    ) -> None: ...

    def list_audit_events(
        self, limit: int = 100, offset: int = 0,
        resource_type: Optional[str] = None,
    ) -> list[dict]: ...

    # settings
    def get_setting(self, key: str) -> Optional[str]: ...
    def set_setting(self, key: str, value: str, updated_by: str = "operator") -> None: ...
    def clear_setting(self, key: str) -> bool: ...

    # retention - the POLICY (budget, batching, confirmation) stays in
    # services/retention.py; only the queries live here.
    def count_events_before(
        self, cutoff_iso: str, categories: list[str],
        source_id: Optional[str] = None,
    ) -> int: ...
    def count_events_at_or_after(
        self, cutoff_iso: str, categories: list[str],
        source_id: Optional[str] = None,
    ) -> int: ...
    def oldest_event_ids_before(
        self, cutoff_iso: str, categories: list[str],
        source_id: Optional[str] = None, limit: int = 1000,
    ) -> list[str]: ...
    def delete_events_by_id(self, event_ids: list[str]) -> int: ...

    # diagnostics - each backend describes ITSELF. A store must never
    # report a check it did not run: where a backend has no equivalent of
    # another's check, the key is present and None, with a note saying so.
    def storage_diagnostics(self) -> dict: ...
