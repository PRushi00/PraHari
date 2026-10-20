"""
PraHari — The Real Collector Lifecycle on Windows, Into a Temporary Database.

The collector lifecycle (start, background polling, stop) had only been
exercised with injected query functions. Running it for real was blocked
because the application's collector writes to the operational database.

This test runs the SAME collector class the application uses, with the
real `Get-NetTCPConnection` query and the real DNS-cache refresh, but
constructed against a temporary database. It is a real collector run: it
reads this host's live connection table and stores what it sees, into a
file deleted afterwards. The application's own collector instance is not
touched and the operational database is never opened (the test-database
guard would refuse it).

It also checks, on Windows, the Linux revision's restart fix (ADR-077): a
second collector process on the same database must not turn connections
that are still open into identity conflicts.
"""

from __future__ import annotations

import asyncio
import sys
import time

import pytest

from app.services.collector import CAPABILITY_NOTES, WindowsTelemetryCollectorService
from app.storage.database import Database

pytestmark = [
    pytest.mark.live_windows,
    pytest.mark.skipif(sys.platform != "win32", reason="real Windows connection-table collection"),
]

SOURCE = "live_lifecycle_host"
INTERVAL = 2.0  # the collector's minimum


@pytest.fixture
def db(tmp_path):
    database = Database(db_path=str(tmp_path / "lifecycle.db"))
    database.initialize()
    yield database
    database.close()


def _audit_actions(db: Database) -> list[str]:
    with db.get_connection() as conn:
        return [r[0] for r in conn.execute("SELECT action FROM audit_events ORDER BY id")]


async def _wait_for_polls(collector, n: int, timeout: float = 30.0) -> None:
    deadline = time.monotonic() + timeout
    while collector.status().polls_succeeded < n:
        if time.monotonic() > deadline:
            raise AssertionError(f"only {collector.status().polls_succeeded} polls in {timeout}s: "
                                 f"{collector.status().last_error}")
        await asyncio.sleep(0.2)


def test_start_poll_stop_with_the_real_query(db):
    async def scenario():
        collector = WindowsTelemetryCollectorService(db=db, source_id=SOURCE, interval_seconds=INTERVAL)

        assert collector.refresh_dns is True, "on Windows the DNS refresh must stay on"
        before = collector.status()
        assert before.state == "stopped" and before.polls_attempted == 0

        started = await collector.start()
        assert started.state == "running" and collector.is_running
        assert db.get_source(SOURCE) is not None, "starting registers the source"

        await _wait_for_polls(collector, 2)
        running = collector.status()

        stopped = await collector.stop()
        assert stopped.state == "stopped"
        assert not collector.is_running and collector._task is None

        # Stopped means stopped: no poll happens after stop() returns.
        frozen = collector.status().polls_attempted
        await asyncio.sleep(INTERVAL * 1.5)
        assert collector.status().polls_attempted == frozen

        return running, stopped

    running, stopped = asyncio.run(scenario())

    assert running.polls_failed == 0, running.last_error
    assert stopped.records_observed_total > 0, "the live table always holds connections"
    assert stopped.events_persisted_total > 0
    assert any("Get-NetTCPConnection" in n for n in stopped.capability_notes)
    assert stopped.capability_notes == list(CAPABILITY_NOTES)

    stored = db.count_events(source_id=SOURCE)
    assert stored == stopped.events_persisted_total, "every persisted event is in storage, once"
    with db.get_connection() as conn:
        ids = [r[0] for r in conn.execute(
            "SELECT event_id FROM normalized_events WHERE source_id = ?", (SOURCE,))]
    assert len(ids) == len(set(ids))

    actions = _audit_actions(db)
    assert actions.count("start_live_collector") == 1
    assert actions.count("stop_live_collector") == 1
    assert db.get_source(SOURCE).status == "disconnected"


def test_a_restarted_collector_does_not_conflict_on_connections_still_open(db):
    """A new process forgets its in-memory cache; storage does not (ADR-077)."""
    async def two_processes():
        first = WindowsTelemetryCollectorService(db=db, source_id=SOURCE, interval_seconds=INTERVAL)
        r1 = await first.poll_once()

        second = WindowsTelemetryCollectorService(db=db, source_id=SOURCE, interval_seconds=INTERVAL)
        r2 = await second.poll_once()
        return r1, r2

    r1, r2 = asyncio.run(two_processes())

    assert r1.succeeded and r1.events_persisted > 0
    assert r2.succeeded, f"the restarted collector's first poll failed: {r2.error}"
    assert r2.events_persisted < r2.records_observed, (
        "connections still open were stored again instead of being recognised"
    )
    assert db.count_events(source_id=SOURCE) == r1.events_persisted + r2.events_persisted
