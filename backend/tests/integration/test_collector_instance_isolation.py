"""
PraHari — A New Collector Does Not Inherit Another Collector's State (ADR-083).

Found on Windows by running the real collector twice in one process. The
process-wide adapter registry returned the ALREADY-REGISTERED adapter for a
source id, so every new collector for the same source silently reused the
previous instance's adapter, including:

* its deduplication cache: a new collector on a different database
  suppressed as "repeats" connections that database had never stored, and
  persisted none of them. The live run showed records_observed=100,
  duplicates_suppressed=75, events_persisted=0 on a fresh database;
* its configuration: the new collector's include_loopback was ignored in
  favour of the old adapter's.

Platform-neutral: the OS query is injected, so this runs everywhere.
"""

from __future__ import annotations

import asyncio

import pytest

from app.adapters.base import get_adapter_registry
from app.services.collector import WindowsTelemetryCollectorService
from app.storage.database import Database

SOURCE = "isolation_host"


def _connections(remote: str = "93.184.216.10", local: str = "192.0.2.10", n: int = 4):
    def query(*_a, **_k):
        return [
            {
                "protocol": "TCP", "local_address": local, "local_port": 51000 + i,
                "remote_address": remote, "remote_port": 443, "state": "Established",
                "owning_pid": 4100 + i, "creation_time": "2026-10-11T16:36:26.0000000Z",
            }
            for i in range(n)
        ]
    return query


@pytest.fixture
def make_db(tmp_path):
    made = []

    def _make(name: str) -> Database:
        db = Database(db_path=str(tmp_path / f"{name}.db"))
        db.initialize()
        made.append(db)
        return db

    yield _make
    for db in made:
        db.close()


def test_a_new_collector_on_another_database_stores_what_it_observes(make_db):
    first_db, second_db = make_db("first"), make_db("second")

    async def run():
        first = WindowsTelemetryCollectorService(db=first_db, source_id=SOURCE,
                                                 query_fn=_connections())
        r1 = await first.poll_once()
        second = WindowsTelemetryCollectorService(db=second_db, source_id=SOURCE,
                                                  query_fn=_connections())
        r2 = await second.poll_once()
        return r1, r2

    r1, r2 = asyncio.run(run())

    assert r1.events_persisted == 4
    assert r2.duplicates_suppressed == 0, "repeats were judged against another collector's memory"
    assert r2.events_persisted == 4
    assert second_db.count_events(source_id=SOURCE) == 4


def test_a_new_collector_uses_its_own_configuration(make_db):
    """Loopback connections: excluded by the first collector, wanted by the second."""
    db = make_db("config")

    async def run():
        excluding = WindowsTelemetryCollectorService(
            db=db, source_id=SOURCE, include_loopback=False,
            query_fn=_connections(remote="127.0.0.1", local="127.0.0.1"))
        r1 = await excluding.poll_once()
        including = WindowsTelemetryCollectorService(
            db=db, source_id=SOURCE, include_loopback=True,
            query_fn=_connections(remote="127.0.0.1", local="127.0.0.1"))
        r2 = await including.poll_once()
        return r1, r2

    r1, r2 = asyncio.run(run())

    assert r1.events_persisted == 0 and r1.records_filtered_by_policy == 4
    assert r2.records_filtered_by_policy == 0, "include_loopback=True was ignored"
    assert r2.events_persisted == 4


def test_the_registry_reports_the_current_collectors_adapter(make_db):
    db = make_db("registry")
    first = WindowsTelemetryCollectorService(db=db, source_id=SOURCE, query_fn=_connections())
    second = WindowsTelemetryCollectorService(db=db, source_id=SOURCE, query_fn=_connections())

    assert second.adapter is not first.adapter
    assert get_adapter_registry().get(SOURCE) is second.adapter, (
        "/stream/adapters must report the collector that is actually running"
    )


def test_a_new_collector_starts_with_zeroed_counters_and_an_empty_cache(make_db):
    """
    Counters as well as fingerprints: the adapter's processed/rejected
    totals feed /stream/adapters, so an inherited adapter also reported the
    previous collector's work as this one's.
    """
    db = make_db("counters")

    async def run():
        first = WindowsTelemetryCollectorService(db=db, source_id=SOURCE, query_fn=_connections())
        await first.poll_once()
        return first, WindowsTelemetryCollectorService(db=db, source_id=SOURCE,
                                                       query_fn=_connections())

    first, second = asyncio.run(run())

    assert first.adapter.records_processed > 0, "the first collector must have done work"
    assert first.adapter._seen_fingerprints, "and remembered what it saw"
    assert second.adapter.records_processed == 0
    assert second.adapter.records_rejected == 0
    assert second.adapter._seen_fingerprints == set()
    status = second.status()
    assert status.polls_attempted == 0 and status.records_observed_total == 0
