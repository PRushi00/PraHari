"""
PraHari — Storage Contract Conformance Suite (ADR-071).

Behaviour every storage backend must exhibit, written against the
`TelemetryStore` contract rather than SQLite internals. It runs today
against SQLite, the only backend that exists.

A PostgreSQL backend is complete when it is added to BACKENDS below and
this suite passes against a REAL server. Passing against a mock would not
count: the properties tested here - atomic batches, idempotent identity,
concurrent writers - are exactly what a mock cannot exhibit.

PostgreSQL (ADR-092) is in BACKENDS, and runs when
``PRAHARI_TEST_POSTGRES_DSN`` points at a real server. Without one it is
SKIPPED, never silently passed: a machine with no server has no evidence
about PostgreSQL, and a green run there must not be read as if it had.

Temporary databases and throwaway schemas only.
"""

from __future__ import annotations

import os
import re
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from app.schemas.events import (
    DataCategory,
    EventType,
    LabelProvenance,
    NormalizedEvent,
    TelemetrySource,
)
from app.services.analysis import compute_descriptive_analysis
from app.storage.contract import (
    KNOWN_ABSTRACTION_LEAKS,
    SQLITE_DIALECT_CONSTRUCTS,
    TelemetryStore,
)
from app.storage.database import Database, EventIdentityConflictError

APP = Path(__file__).resolve().parents[2] / "app"
T0 = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)


POSTGRES_DSN = os.environ.get("PRAHARI_TEST_POSTGRES_DSN", "").strip()


def _sqlite(tmp_path):
    db = Database(db_path=str(tmp_path / "contract.db"))
    db.initialize()
    return db


def _sqlite_reopen(store, tmp_path):
    """A second handle on the same SQLite file."""
    db = Database(db_path=str(tmp_path / "contract.db"))
    db.initialize()
    return db


def _postgres(tmp_path):
    if not POSTGRES_DSN:
        pytest.skip(
            "PRAHARI_TEST_POSTGRES_DSN is unset. The PostgreSQL backend is "
            "only evidenced against a REAL server; it is skipped here rather "
            "than passed against a mock."
        )
    from app.storage.postgres import PostgresStore

    # One throwaway schema per test, so tests cannot see each other's rows
    # and nothing outside the schema is touched.
    schema = "prahari_contract_" + uuid.uuid4().hex[:12]
    store = PostgresStore(POSTGRES_DSN, schema=schema)
    store.initialize()
    return store


def _postgres_reopen(store, tmp_path):
    """A second handle on the same PostgreSQL schema."""
    from app.storage.postgres import PostgresStore

    reopened = PostgresStore(store.dsn, schema=store.schema)
    reopened.initialize()
    return reopened


# Each entry: (name, factory(tmp_path), reopen(store, tmp_path)).
BACKENDS = [
    ("sqlite", _sqlite, _sqlite_reopen),
    ("postgres", _postgres, _postgres_reopen),
]


@pytest.fixture(params=BACKENDS, ids=[name for name, _, _ in BACKENDS])
def store(request, tmp_path):
    _, factory, reopen = request.param
    backend = factory(tmp_path)
    backend._contract_reopen = lambda: reopen(backend, tmp_path)
    for sid in ("src-a", "src-b"):
        backend.upsert_source(TelemetrySource(source_id=sid, name=sid, source_type="json_stream"))
    yield backend
    if hasattr(backend, "drop_schema"):
        backend.drop_schema()
    backend.close()


def _ev(source, i, *, dst_port=443, received=None, bytes_total=100):
    return NormalizedEvent(
        event_id=f"{source}-{i}", source_id=source,
        data_category=DataCategory.LIVE_TELEMETRY,
        observed_at=T0 + timedelta(seconds=i), received_at=received,
        event_type=EventType.NETWORK_FLOW, src_ip="192.0.2.1", dst_ip="198.51.100.2",
        src_port=40000 + i, dst_port=dst_port, protocol="TCP", bytes_total=bytes_total,
        label_provenance=LabelProvenance.UNLABELED,
    )


# ──────────────────────────────────────────────────────────────────
# The contract itself
# ──────────────────────────────────────────────────────────────────


def test_the_backend_satisfies_the_contract(store):
    assert isinstance(store, TelemetryStore)


def test_the_contract_covers_every_storage_call_the_application_makes():
    """Derived from the code, so a new call site cannot silently bypass it."""
    called = set()
    for path in APP.rglob("*.py"):
        if "storage" in path.parts:
            continue
        called |= set(re.findall(r"\bdb\.([a-z_]+)\(", path.read_text(encoding="utf-8")))
    called -= {"get_connection", "ravel"}  # the leak itself; a numpy false match
    missing = {m for m in called if not hasattr(TelemetryStore, m)}
    assert not missing, f"storage calls outside the contract: {sorted(missing)}"


def test_raw_sql_outside_storage_does_not_spread():
    """
    A ratchet: the three known leaks are recorded, and a fourth fails.
    Fixing one means removing it from KNOWN_ABSTRACTION_LEAKS.
    """
    leaking = {
        path.relative_to(APP.parent).as_posix()
        for path in APP.rglob("*.py")
        if "storage" not in path.parts and "get_connection()" in path.read_text(encoding="utf-8")
    }
    assert leaking == set(KNOWN_ABSTRACTION_LEAKS)


def test_every_listed_sqlite_construct_is_really_in_the_storage_code():
    source = (APP / "storage" / "database.py").read_text(encoding="utf-8")
    for construct in SQLITE_DIALECT_CONSTRUCTS:
        if construct == "? placeholders":
            assert "= ?" in source
        else:
            assert construct in source, f"{construct!r} is listed but not used"


# ──────────────────────────────────────────────────────────────────
# Events: identity, atomicity, isolation
# ──────────────────────────────────────────────────────────────────


def test_insert_is_idempotent_on_event_identity(store):
    batch = [_ev("src-a", i) for i in range(5)]
    assert store.insert_events(batch) == 5
    assert store.insert_events(batch) == 0, "a retry must store nothing"
    assert store.count_events(source_id="src-a") == 5


def test_a_conflicting_identity_rolls_the_whole_batch_back(store):
    store.insert_events([_ev("src-a", 1)])
    fresh = _ev("src-a", 2)
    conflicting = _ev("src-a", 1, dst_port=22)  # same id, different content

    with pytest.raises(EventIdentityConflictError):
        store.insert_events([fresh, conflicting])

    assert store.get_event(fresh.event_id) is None, "a partial batch was committed"
    assert store.count_events(source_id="src-a") == 1


def test_sources_are_isolated_on_read(store):
    store.insert_events([_ev("src-a", i) for i in range(3)])
    store.insert_events([_ev("src-b", i) for i in range(2)])

    assert {e.source_id for e in store.list_events(source_id="src-a")} == {"src-a"}
    assert store.count_events(source_id="src-b") == 2


def test_receipt_time_and_absence_survive_a_round_trip(store):
    rx = T0 + timedelta(seconds=30)
    store.insert_events([_ev("src-a", 1, received=rx), _ev("src-a", 2, received=None)])

    assert store.get_event("src-a-1").received_at == rx
    assert store.get_event("src-a-2").received_at is None, "absent must not become a value"
    assert store.latest_received_at_by_source()["src-a"] == rx


def test_concurrent_writers_never_duplicate(store):
    """Eight threads deliver overlapping batches at once - the at-least-once
    retry storm a fleet of sensors produces."""
    batches = [[_ev("src-a", i) for i in range(k, k + 20)] for k in range(0, 80, 10)]
    errors: list[BaseException] = []

    def deliver(batch):
        try:
            store.insert_events(batch)
        except BaseException as exc:  # noqa: BLE001 - recorded, asserted below
            errors.append(exc)

    threads = [threading.Thread(target=deliver, args=(b,)) for b in batches]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)

    assert not errors, errors
    assert store.count_events(source_id="src-a") == 90  # ids 0..89, once each


# ──────────────────────────────────────────────────────────────────
# Analyses, audit, settings
# ──────────────────────────────────────────────────────────────────


def test_analyses_persist_and_prune_only_on_request(store):
    events = [_ev("src-a", i) for i in range(10)]
    store.insert_events(events)
    for _ in range(3):
        store.save_analysis(compute_descriptive_analysis(events, source_id="src-a"))

    assert store.count_analyses() == 3
    assert store.get_latest_analysis() is not None
    assert len(store.analyses_exceeding_limit(keep=1)) == 2
    assert store.count_analyses() == 3, "previewing a prune must not prune"
    assert store.prune_analyses(keep=1) == 2
    assert store.count_analyses() == 1
    assert store.count_events(source_id="src-a") == 10, "telemetry is never touched"


def test_audit_entries_keep_their_actor_and_request_id(store):
    store.log_audit(action="contract_check", resource_type="t",
                    user_identity="credential:abc source:src-a role:ingest",
                    request_id="req-123")
    with store.get_connection() as conn:  # inspection only; not part of the contract
        row = conn.execute(
            "SELECT user_identity, request_id FROM audit_events WHERE action='contract_check'"
        ).fetchone()
    # By column name: a sqlite3.Row and a psycopg dict row both support it,
    # whereas tuple() over the latter would yield its KEYS.
    assert row["user_identity"] == "credential:abc source:src-a role:ingest"
    assert row["request_id"] == "req-123"


def test_settings_round_trip_and_clear(store):
    assert store.get_setting("k") is None
    store.set_setting("k", "v")
    assert store.get_setting("k") == "v"
    assert store.clear_setting("k") is True
    assert store.get_setting("k") is None


def test_data_survives_close_and_reopen(store, tmp_path):
    """Reopens the SAME backend; it previously reopened SQLite regardless."""
    store.insert_events([_ev("src-a", i) for i in range(4)])
    store.close()

    reopened = store._contract_reopen()
    try:
        assert reopened.count_events(source_id="src-a") == 4
    finally:
        reopened.close()


# ──────────────────────────────────────────────────────────────────
# Audit listing, retention queries and diagnostics (ADR-093)
#
# These moved out of three modules that had been issuing SQLite SQL
# directly. Both backends must now exhibit them identically, which is
# what makes the second backend substitutable rather than merely
# conforming on paper.
# ──────────────────────────────────────────────────────────────────


def test_audit_entries_come_back_newest_first(store):
    for i in range(5):
        store.log_audit(action=f"act-{i}", resource_type="alpha")

    entries = store.list_audit_events(limit=10)
    assert [e["action"] for e in entries] == [f"act-{i}" for i in reversed(range(5))]
    assert all(e["user_identity"] for e in entries), "actor must never be blank"


def test_audit_listing_honours_limit_offset_and_resource_type(store):
    for i in range(4):
        store.log_audit(action=f"alpha-{i}", resource_type="alpha")
    for i in range(3):
        store.log_audit(action=f"beta-{i}", resource_type="beta")

    assert len(store.list_audit_events(limit=2)) == 2

    page1 = store.list_audit_events(limit=3, offset=0)
    page2 = store.list_audit_events(limit=3, offset=3)
    assert {e["id"] for e in page1}.isdisjoint({e["id"] for e in page2})

    betas = store.list_audit_events(limit=50, resource_type="beta")
    assert len(betas) == 3
    assert {e["resource_type"] for e in betas} == {"beta"}


def test_an_entry_with_no_request_behind_it_reports_none_not_a_placeholder(store):
    store.log_audit(action="no-request")
    entry = store.list_audit_events(limit=1)[0]
    assert entry["request_id"] is None


def test_retention_counts_split_at_the_cutoff(store):
    store.insert_events([_ev("src-a", i) for i in range(10)])
    cutoff = (T0 + timedelta(seconds=4)).isoformat()
    categories = [DataCategory.LIVE_TELEMETRY.value]

    before = store.count_events_before(cutoff, categories)
    at_or_after = store.count_events_at_or_after(cutoff, categories)

    assert before == 4          # seconds 0..3
    assert at_or_after == 6     # seconds 4..9
    assert before + at_or_after == 10, "the cutoff must partition, not overlap"


def test_retention_queries_respect_category_and_source(store):
    store.insert_events([_ev("src-a", i) for i in range(5)])
    store.insert_events([_ev("src-b", i) for i in range(3)])
    cutoff = (T0 + timedelta(seconds=100)).isoformat()

    assert store.count_events_before(
        cutoff, [DataCategory.LIVE_TELEMETRY.value], "src-a"
    ) == 5
    # A category nothing was stored under protects every row.
    assert store.count_events_before(
        cutoff, [DataCategory.SYNTHETIC_DEMO.value]
    ) == 0


def test_an_empty_category_list_is_refused_not_read_as_everything(store):
    """'Nothing' and 'everything' must never be the same argument."""
    cutoff = (T0 + timedelta(seconds=100)).isoformat()
    with pytest.raises(ValueError, match="at least one category"):
        store.count_events_before(cutoff, [])
    with pytest.raises(ValueError, match="at least one category"):
        store.oldest_event_ids_before(cutoff, [], limit=10)


def test_deletion_takes_the_oldest_first_and_only_what_was_named(store):
    store.insert_events([_ev("src-a", i) for i in range(10)])
    store.insert_events([_ev("src-b", i) for i in range(4)])
    cutoff = (T0 + timedelta(seconds=100)).isoformat()
    categories = [DataCategory.LIVE_TELEMETRY.value]

    doomed = store.oldest_event_ids_before(cutoff, categories, "src-a", limit=3)
    assert doomed == ["src-a-0", "src-a-1", "src-a-2"]

    assert store.delete_events_by_id(doomed) == 3
    assert store.count_events(source_id="src-a") == 7
    assert store.count_events(source_id="src-b") == 4, "another source was touched"
    assert store.get_event("src-a-0") is None
    assert store.get_event("src-a-3") is not None

    assert store.delete_events_by_id([]) == 0


def test_diagnostics_describe_the_backend_without_inventing_a_check(store):
    """
    A store may not report a check it did not run.

    Where a backend has no equivalent of another's check, the key is
    present and None - never filled with a plausible-looking value.
    """
    diagnostics = store.storage_diagnostics()

    for required in (
        "backend", "healthy", "health_basis", "size_bytes", "event_count",
        "source_count", "received_at_column_present",
        "normalized_events_columns", "integrity_check", "journal_mode",
    ):
        assert required in diagnostics, f"missing {required}"

    assert diagnostics["healthy"] is True
    assert diagnostics["health_basis"], "healthy must say what it rests on"
    assert diagnostics["size_bytes"] > 0
    assert diagnostics["received_at_column_present"] is True
    assert diagnostics["normalized_events_columns"] >= 26

    # Anything reported as not measured must say why, in the same payload.
    for field in ("integrity_check", "journal_mode"):
        if diagnostics[field] is None:
            assert diagnostics.get(f"{field}_note"), (
                f"{field} is None but carries no note explaining why"
            )


def test_diagnostics_event_count_tracks_what_is_stored(store):
    before = store.storage_diagnostics()["event_count"]
    store.insert_events([_ev("src-a", i) for i in range(6)])
    assert store.storage_diagnostics()["event_count"] == before + 6
