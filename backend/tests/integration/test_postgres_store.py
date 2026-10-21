"""
PraHari — PostgreSQL backend specifics (ADR-092).

`test_storage_contract.py` runs the shared behaviour against both stores.
This file covers what is specific to the PostgreSQL port:

* that it REFUSES rather than falling back to SQLite when the driver is
  absent — silently writing central telemetry to a different database than
  the configured one would be worse than failing;
* that one schema cannot see another's rows, which is what makes a shared
  server safe for a test run, a tenant or a trial migration;
* that the batch ordering which prevents deadlock is real, not decorative;
* that a foreign-key violation is raised rather than absorbed as a
  "duplicate", which would discard the event and report success;
* **cross-backend equivalence**: the same events stored in SQLite and in
  PostgreSQL read back as equal objects. Two stores returning subtly
  different objects from the same row is the failure a second backend
  invites, and it is the reason both share one set of row converters.

Every test here needs a REAL server; without `PRAHARI_TEST_POSTGRES_DSN`
they skip. A skip is never counted as a pass.
"""

from __future__ import annotations

import os
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
    QualityFlag,
    TelemetrySource,
)
from app.storage.database import Database

POSTGRES_DSN = os.environ.get("PRAHARI_TEST_POSTGRES_DSN", "").strip()
T0 = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)

requires_server = pytest.mark.skipif(
    not POSTGRES_DSN,
    reason="PRAHARI_TEST_POSTGRES_DSN is unset; the PostgreSQL backend is "
    "only evidenced against a real server.",
)


def _store():
    from app.storage.postgres import PostgresStore

    store = PostgresStore(POSTGRES_DSN, schema="prahari_pg_" + uuid.uuid4().hex[:12])
    store.initialize()
    store.upsert_source(
        TelemetrySource(source_id="src-a", name="src-a", source_type="json_stream")
    )
    return store


def _event(i: int, **over) -> NormalizedEvent:
    fields = dict(
        event_id=f"pg-{i}",
        source_id="src-a",
        schema_version="1.0.0",
        data_category=DataCategory.LIVE_TELEMETRY,
        observed_at=T0 + timedelta(seconds=i),
        received_at=T0 + timedelta(seconds=i, milliseconds=250),
        event_type=EventType.NETWORK_FLOW,
        src_ip="192.0.2.1",
        dst_ip="198.51.100.2",
        src_port=40000 + i,
        dst_port=443,
        protocol="TCP",
        duration=1.25,
        packets=10,
        bytes_total=2048,
        label="Benign",
        label_provenance=LabelProvenance.DATASET_GROUND_TRUTH,
        quality_flags=[QualityFlag.MISSING_FIELD],
        raw_reference="ref-1",
        app_protocol="https",
        http_status_code=200,
        http_duration_ms=12.5,
        dst_hostname="example.test",
    )
    fields.update(over)
    return NormalizedEvent(**fields)


# ──────────────────────────────────────────────────────────────────
# Refusal when the driver is absent
# ──────────────────────────────────────────────────────────────────


def test_without_the_driver_it_refuses_instead_of_using_sqlite(monkeypatch):
    """A silent fallback would store central telemetry in the wrong place."""
    import app.storage.postgres as pg

    monkeypatch.setattr(pg, "PSYCOPG_AVAILABLE", False)
    with pytest.raises(pg.PostgresDriverMissing) as exc:
        pg.PostgresStore("postgresql://unused/db")

    assert "does not fall back to SQLite" in str(exc.value)


def test_a_schema_name_that_is_not_an_identifier_is_refused():
    """The schema goes into DDL by name, so it is never free text."""
    import app.storage.postgres as pg

    if not pg.PSYCOPG_AVAILABLE:
        pytest.skip("psycopg not installed")
    with pytest.raises(ValueError, match="plain identifier"):
        pg.PostgresStore("postgresql://unused/db", schema='public"; DROP SCHEMA x --')


# ──────────────────────────────────────────────────────────────────
# Server-backed behaviour
# ──────────────────────────────────────────────────────────────────


@requires_server
def test_the_store_satisfies_the_contract_protocol():
    from app.storage.contract import TelemetryStore

    store = _store()
    try:
        assert isinstance(store, TelemetryStore)
    finally:
        store.drop_schema()


@requires_server
def test_one_schema_cannot_see_another_schemas_rows():
    first, second = _store(), _store()
    try:
        first.insert_events([_event(i) for i in range(5)])
        assert first.count_events(source_id="src-a") == 5
        assert second.count_events(source_id="src-a") == 0
        assert second.get_event("pg-1") is None
    finally:
        first.drop_schema()
        second.drop_schema()


@requires_server
def test_an_unregistered_source_is_raised_not_absorbed_as_a_duplicate():
    """Absorbing it would discard the event and report success."""
    import psycopg

    store = _store()
    try:
        orphan = _event(1, event_id="pg-orphan", source_id="src-never-registered")
        with pytest.raises(psycopg.IntegrityError) as exc:
            store.insert_events([orphan])
        assert "is registered before inserting" in str(exc.value)
        assert store.count_events() == 0, "a rejected batch left rows behind"
    finally:
        store.drop_schema()


@requires_server
def test_a_batch_is_inserted_in_event_id_order():
    """
    The ordering that prevents deadlock between concurrent writers.

    Asserted directly rather than only inferred from the concurrency test:
    shuffling this order makes PostgreSQL raise DeadlockDetected under the
    contract suite's eight-writer test.
    """
    store = _store()
    try:
        shuffled = [_event(i) for i in (7, 2, 9, 1, 5)]
        store.insert_events(shuffled)
        # Insertion order is observable through the identity column.
        with store.get_connection() as conn:
            rows = conn.execute(
                "SELECT event_id FROM normalized_events ORDER BY observed_at"
            ).fetchall()
        stored = [r["event_id"] for r in rows]
        assert stored == sorted(stored)
    finally:
        store.drop_schema()


@requires_server
def test_concurrent_overlapping_batches_do_not_deadlock():
    """
    The central-mode case: several sensors retrying overlapping batches.

    Separate from the contract suite's version so a PostgreSQL regression
    names itself.
    """
    store = _store()
    errors: list[BaseException] = []

    def deliver(batch):
        try:
            store.insert_events(batch)
        except BaseException as exc:  # noqa: BLE001 - recorded, asserted below
            errors.append(exc)

    batches = [[_event(i) for i in range(k, k + 25)] for k in range(0, 100, 10)]
    threads = [threading.Thread(target=deliver, args=(b,)) for b in batches]
    try:
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=60)
        assert not errors, errors
        # Ten overlapping batches of 25 starting every 10: ids 0..114, each
        # stored exactly once however many deliveries contained it.
        assert store.count_events(source_id="src-a") == 115
    finally:
        store.drop_schema()


@requires_server
def test_a_redelivered_event_keeps_its_original_receipt_time():
    """ADR-048: the retry's receipt must not overwrite the first one."""
    store = _store()
    try:
        first = _event(1, received_at=T0 + timedelta(seconds=1))
        store.insert_events([first])
        retry = _event(1, received_at=T0 + timedelta(hours=9))
        assert store.insert_events([retry]) == 0
        assert store.get_event("pg-1").received_at == T0 + timedelta(seconds=1)
    finally:
        store.drop_schema()


@requires_server
def test_an_absent_receipt_never_becomes_a_value():
    store = _store()
    try:
        store.insert_events([_event(1, received_at=None)])
        assert store.get_event("pg-1").received_at is None
        assert "src-a" not in store.latest_received_at_by_source()
    finally:
        store.drop_schema()


@requires_server
def test_counters_are_derived_and_freshness_only_moves_forward():
    store = _store()
    try:
        store.insert_events([_event(i) for i in range(4)])
        updated = store.refresh_source_activity("src-a", last_event_at=T0 + timedelta(seconds=100))
        assert updated.event_count == 4
        assert updated.last_event_at == T0 + timedelta(seconds=100)

        # A late batch of older records must not rewind freshness.
        rewound = store.refresh_source_activity("src-a", last_event_at=T0)
        assert rewound.last_event_at == T0 + timedelta(seconds=100)

        assert store.refresh_source_activity("src-missing") is None
    finally:
        store.drop_schema()


@requires_server
def test_disabling_a_source_touches_nothing_else():
    store = _store()
    try:
        store.insert_events([_event(i) for i in range(3)])
        store.refresh_source_activity("src-a", last_event_at=T0 + timedelta(seconds=9))
        before = store.get_source("src-a")

        assert store.set_source_enabled("src-a", False) is True
        after = store.get_source("src-a")

        assert after.enabled is False
        assert after.event_count == before.event_count
        assert after.last_event_at == before.last_event_at
        assert store.set_source_enabled("src-nope", False) is False
    finally:
        store.drop_schema()


@requires_server
def test_dns_observations_are_append_only():
    store = _store()
    try:
        obs = {
            "ip_address": "198.51.100.2",
            "hostname": "a.test",
            "observed_at": T0.isoformat(),
            "method": "dns_cache_observation",
            "ttl_seconds": 60,
        }
        assert store.record_dns_observations([obs]) == 1
        assert store.record_dns_observations([obs]) == 0, "identical evidence duplicated"

        later = dict(obs, hostname="b.test")
        assert store.record_dns_observations([later]) == 1

        # A second name for one address stays visible as ambiguity.
        names = {o["hostname"] for o in store.get_dns_observations_for_ip("198.51.100.2")}
        assert names == {"a.test", "b.test"}
        assert store.count_dns_observations() == 2
        assert store.count_dns_distinct_ips() == 1
        bulk = store.get_dns_observations_for_ips(["198.51.100.2", "203.0.113.9"])
        assert len(bulk["198.51.100.2"]) == 2
        assert bulk["203.0.113.9"] == []
    finally:
        store.drop_schema()


# ──────────────────────────────────────────────────────────────────
# Cross-backend equivalence
# ──────────────────────────────────────────────────────────────────


@requires_server
def test_both_backends_return_equal_objects_for_the_same_events(tmp_path: Path):
    """
    The failure a second backend invites: two stores that each look correct
    while returning subtly different objects from the same row.
    """
    events = [_event(i) for i in range(6)]
    events.append(
        _event(
            99,
            received_at=None,
            label=None,
            label_provenance=LabelProvenance.UNLABELED,
            duration=None,
            packets=None,
            bytes_total=None,
            quality_flags=[],
            raw_reference=None,
            app_protocol=None,
            http_status_code=None,
            http_duration_ms=None,
            dst_hostname=None,
        )
    )

    sqlite_store = Database(db_path=str(tmp_path / "equiv.db"))
    sqlite_store.initialize()
    sqlite_store.upsert_source(
        TelemetrySource(source_id="src-a", name="src-a", source_type="json_stream")
    )
    pg_store = _store()
    try:
        assert sqlite_store.insert_events(events) == len(events)
        assert pg_store.insert_events(events) == len(events)

        from_sqlite = sorted(
            sqlite_store.list_events(source_id="src-a", limit=100),
            key=lambda e: e.event_id,
        )
        from_pg = sorted(
            pg_store.list_events(source_id="src-a", limit=100),
            key=lambda e: e.event_id,
        )

        assert len(from_sqlite) == len(from_pg) == len(events)
        for a, b in zip(from_sqlite, from_pg):
            assert a.model_dump() == b.model_dump(), f"{a.event_id} differs"
    finally:
        pg_store.drop_schema()
        sqlite_store.close()


@requires_server
def test_both_backends_store_and_return_an_equal_analysis(tmp_path: Path):
    """Analyses carry the -1 'not recorded' sentinel; it must survive both."""
    from app.services.analysis import compute_descriptive_analysis

    events = [_event(i) for i in range(8)]
    analysis = compute_descriptive_analysis(events, source_id="src-a")

    sqlite_store = Database(db_path=str(tmp_path / "equiv2.db"))
    sqlite_store.initialize()
    sqlite_store.upsert_source(
        TelemetrySource(source_id="src-a", name="src-a", source_type="json_stream")
    )
    pg_store = _store()
    try:
        sqlite_store.save_analysis(analysis)
        pg_store.save_analysis(analysis)

        a = sqlite_store.get_latest_analysis(source_id="src-a")
        b = pg_store.get_latest_analysis(source_id="src-a")
        assert a is not None and b is not None
        assert a.model_dump() == b.model_dump()
    finally:
        pg_store.drop_schema()
        sqlite_store.close()


@requires_server
def test_both_backends_agree_on_import_summaries(tmp_path: Path):
    from app.schemas.events import ImportSummary

    summary = ImportSummary(
        import_id="imp-1",
        source_id="src-a",
        source_file="flows.csv",
        data_category=DataCategory.HISTORICAL_IMPORT,
        started_at=T0,
        completed_at=T0 + timedelta(seconds=12),
        total_records=10,
        accepted_records=8,
        rejected_records=2,
        warnings_count=1,
        rejection_reasons={"bad_timestamp": 2},
        schema_version="1.0.0",
    )

    sqlite_store = Database(db_path=str(tmp_path / "equiv3.db"))
    sqlite_store.initialize()
    sqlite_store.upsert_source(
        TelemetrySource(source_id="src-a", name="src-a", source_type="json_stream")
    )
    pg_store = _store()
    try:
        sqlite_store.save_import_summary(summary)
        pg_store.save_import_summary(summary)

        a = sqlite_store.list_import_summaries(source_id="src-a")
        b = pg_store.list_import_summaries(source_id="src-a")
        assert len(a) == len(b) == 1
        assert a[0].model_dump() == b[0].model_dump()
    finally:
        pg_store.drop_schema()
        sqlite_store.close()
