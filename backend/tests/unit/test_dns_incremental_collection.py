"""
Continuous DNS collection: the bookmark and the loop (ADR-127).

Collection used to read "the newest 500" on a button press, which both
re-read what it already held and missed anything that scrolled out of
the circular channel between presses. These tests cover the parts that
replaced it — incremental reads, a durable bookmark, rollover, restart
and the loop's own safety — on every platform.

**None of this proves Windows integration.** `read_dns_events` shells
out to PowerShell against a channel that exists only on Windows; it is
stubbed here. What is tested is everything around it: which record the
bookmark lands on, when it refuses to move, and what the loop does with
a failure. The real event-log read is covered by the Windows-only
integration tests and must be verified on the host.
"""

from __future__ import annotations

import asyncio

import pytest

from app.adapters.windows_dns_events import EventLogRead
from app.services.dns_collector import (
    MAX_CONSECUTIVE_FAILURES,
    DnsEventCollectorService,
)
from app.services.enrichment import get_enrichment_service
from app.storage.database import Database


@pytest.fixture()
def db(tmp_path):
    store = Database(db_path=str(tmp_path / "dns.db"))
    store.initialize()
    yield store
    store.close()


def _record(record_id: int, name: str, addr: str, when: str) -> dict:
    """One interpretable 3008 record, as the adapter yields them."""
    return {
        "Id": 3008,
        "RecordId": record_id,
        "TimeCreated": when,
        "QueryName": name,
        "QueryResults": f"::ffff:{addr};",
        "QueryStatus": "0",
    }


# ---------------------------------------------------------------------
# EventLogRead — the bookmark arithmetic
# ---------------------------------------------------------------------


def test_the_batch_reports_its_highest_record():
    read = EventLogRead(
        records=[{"RecordId": 11}, {"RecordId": 9}, {"RecordId": 14}],
        newest_record_id=14,
        requested_after=8,
        batch_limit=100,
    )
    assert read.max_record_id == 14


def test_an_empty_batch_has_no_record_to_advance_to():
    read = EventLogRead(records=[], newest_record_id=40, requested_after=40, batch_limit=100)
    assert read.max_record_id == 0
    assert not read.batch_was_full


def test_a_full_batch_says_more_is_waiting():
    """Otherwise a burst would drain one interval at a time."""
    read = EventLogRead(
        records=[{"RecordId": i} for i in range(5)],
        newest_record_id=99,
        requested_after=0,
        batch_limit=5,
    )
    assert read.batch_was_full


def test_a_cleared_log_is_detected():
    """
    Windows restarts RecordId at 1 after a clear. A bookmark above the
    newest record would filter out everything, for ever, while DNS
    activity carried on.
    """
    assert EventLogRead(
        records=[], newest_record_id=3, requested_after=9000, batch_limit=50
    ).log_was_reset


def test_a_normal_read_is_not_mistaken_for_a_clear():
    assert not EventLogRead(
        records=[{"RecordId": 9001}], newest_record_id=9001, requested_after=9000, batch_limit=50
    ).log_was_reset
    # A cold start has no bookmark to be stale.
    assert not EventLogRead(
        records=[], newest_record_id=0, requested_after=0, batch_limit=50
    ).log_was_reset


# ---------------------------------------------------------------------
# The bookmark, through the real service and real storage
# ---------------------------------------------------------------------


def _stub_reads(monkeypatch, batches: list[EventLogRead]):
    """Serve pre-built reads in order; assert the bookmark asked for."""
    seen: list[int] = []

    def fake_read(max_events=500, after_record_id=0, **kwargs):
        seen.append(after_record_id)
        return batches.pop(0) if batches else EventLogRead(
            records=[], newest_record_id=0, requested_after=after_record_id,
            batch_limit=max_events,
        )

    monkeypatch.setattr(
        "app.adapters.windows_dns_events.read_dns_events", fake_read
    )
    return seen


def test_collection_advances_the_bookmark_over_what_it_stored(db, monkeypatch):
    service = get_enrichment_service(db)
    assert service.read_bookmark() == 0

    _stub_reads(monkeypatch, [
        EventLogRead(
            records=[
                _record(101, "example.com", "93.184.216.34", "2026-10-22T12:00:00Z"),
                _record(103, "github.com", "140.82.121.4", "2026-10-22T12:00:05Z"),
            ],
            newest_record_id=103, requested_after=0, batch_limit=500,
        ),
    ])

    result = service.collect_from_dns_event_log(incremental=True)

    assert result["succeeded"]
    assert result["bookmark_before"] == 0
    assert result["bookmark_after"] == 103
    assert service.read_bookmark() == 103


def test_the_next_poll_asks_only_for_what_is_newer(db, monkeypatch):
    """The whole point: no re-scan of the same fixed window."""
    service = get_enrichment_service(db)
    seen = _stub_reads(monkeypatch, [
        EventLogRead(
            records=[_record(10, "a.test", "10.0.0.1", "2026-10-22T12:00:00Z")],
            newest_record_id=10, requested_after=0, batch_limit=500,
        ),
        EventLogRead(
            records=[_record(11, "b.test", "10.0.0.2", "2026-10-22T12:00:10Z")],
            newest_record_id=11, requested_after=10, batch_limit=500,
        ),
    ])

    service.collect_from_dns_event_log(incremental=True)
    service.collect_from_dns_event_log(incremental=True)

    assert seen == [0, 10], "the second read must start after the first bookmark"
    assert service.read_bookmark() == 11


def test_an_empty_poll_leaves_the_bookmark_alone(db, monkeypatch):
    service = get_enrichment_service(db)
    db.set_setting(service.BOOKMARK_KEY, "500")

    _stub_reads(monkeypatch, [
        EventLogRead(records=[], newest_record_id=500, requested_after=500, batch_limit=500),
    ])
    result = service.collect_from_dns_event_log(incremental=True)

    assert result["succeeded"]
    assert service.read_bookmark() == 500, "nothing was read, so nothing was passed"


def test_the_bookmark_never_moves_backwards(db, monkeypatch):
    """A stale or out-of-order batch must not rewind progress."""
    service = get_enrichment_service(db)
    db.set_setting(service.BOOKMARK_KEY, "900")

    _stub_reads(monkeypatch, [
        EventLogRead(
            records=[_record(850, "old.test", "10.0.0.9", "2026-10-22T11:00:00Z")],
            newest_record_id=950, requested_after=900, batch_limit=500,
        ),
    ])
    service.collect_from_dns_event_log(incremental=True)

    assert service.read_bookmark() == 900


def test_a_cleared_log_restarts_collection_instead_of_stalling(db, monkeypatch):
    service = get_enrichment_service(db)
    db.set_setting(service.BOOKMARK_KEY, "9000")

    seen = _stub_reads(monkeypatch, [
        # Bookmark is above the newest record: the log was cleared.
        EventLogRead(records=[], newest_record_id=4, requested_after=9000, batch_limit=500),
        # The retry, from a cold start.
        EventLogRead(
            records=[_record(4, "fresh.test", "10.0.0.4", "2026-10-22T13:00:00Z")],
            newest_record_id=4, requested_after=0, batch_limit=500,
        ),
    ])

    result = service.collect_from_dns_event_log(incremental=True)

    assert result["log_was_reset"] is True
    assert seen == [9000, 0], "it must re-read from the start of the new log"
    assert service.read_bookmark() == 4
    assert result["observations_recorded"] == 1


def test_a_corrupt_bookmark_cold_starts_rather_than_wedging(db):
    service = get_enrichment_service(db)
    db.set_setting(service.BOOKMARK_KEY, "not-a-number")
    assert service.read_bookmark() == 0


def test_a_full_batch_reports_more_available(db, monkeypatch):
    service = get_enrichment_service(db)
    _stub_reads(monkeypatch, [
        EventLogRead(
            records=[
                _record(i, f"h{i}.test", f"10.0.1.{i}", "2026-10-22T12:00:00Z")
                for i in range(1, 4)
            ],
            newest_record_id=3, requested_after=0, batch_limit=3,
        ),
    ])
    result = service.collect_from_dns_event_log(max_events=3, incremental=True)
    assert result["more_available"] is True


def test_a_manual_collection_does_not_touch_the_bookmark(db, monkeypatch):
    """
    The one-shot button is still a snapshot of the newest window. If it
    moved the bookmark, pressing it would make continuous collection
    skip everything older than that snapshot.
    """
    service = get_enrichment_service(db)
    db.set_setting(service.BOOKMARK_KEY, "77")
    seen = _stub_reads(monkeypatch, [
        EventLogRead(
            records=[_record(500, "x.test", "10.0.0.5", "2026-10-22T12:00:00Z")],
            newest_record_id=500, requested_after=0, batch_limit=500,
        ),
    ])

    service.collect_from_dns_event_log(incremental=False)

    assert seen == [0], "a manual snapshot reads the newest window"
    assert service.read_bookmark() == 77, "and leaves the bookmark where it was"


def test_restart_recovery_resumes_from_storage(db, monkeypatch):
    """
    The bookmark lives in `system_settings`, not in the process. A fresh
    service object on the same database must resume, not cold start.
    """
    first = get_enrichment_service(db)
    _stub_reads(monkeypatch, [
        EventLogRead(
            records=[_record(640, "a.test", "10.0.0.1", "2026-10-22T12:00:00Z")],
            newest_record_id=640, requested_after=0, batch_limit=500,
        ),
    ])
    first.collect_from_dns_event_log(incremental=True)
    assert first.read_bookmark() == 640

    # Simulate a restart: a new service over the same storage.
    import app.services.enrichment as enrichment_module

    enrichment_module._service = None  # type: ignore[attr-defined]
    revived = get_enrichment_service(db)

    seen = _stub_reads(monkeypatch, [
        EventLogRead(records=[], newest_record_id=640, requested_after=640, batch_limit=500),
    ])
    revived.collect_from_dns_event_log(incremental=True)

    assert seen == [640], "collection resumed from the stored bookmark"


def test_duplicate_records_do_not_duplicate_rows(db, monkeypatch):
    """
    Re-reading an overlapping window is safe: storage's UNIQUE
    constraint absorbs it. That is what makes store-then-advance a safe
    order after a crash.
    """
    service = get_enrichment_service(db)
    same = _record(50, "dup.test", "10.0.0.50", "2026-10-22T12:00:00Z")

    _stub_reads(monkeypatch, [
        EventLogRead(records=[same], newest_record_id=50, requested_after=0, batch_limit=500),
        EventLogRead(records=[same], newest_record_id=50, requested_after=0, batch_limit=500),
    ])
    first = service.collect_from_dns_event_log(incremental=False)
    second = service.collect_from_dns_event_log(incremental=False)

    assert first["observations_recorded"] == 1
    assert second["observations_recorded"] == 0, "the repeat stored nothing new"
    rows = db.recent_dns_observations(limit=50)
    assert len([r for r in rows if r["hostname"] == "dup.test"]) == 1


# ---------------------------------------------------------------------
# The loop
# ---------------------------------------------------------------------


def test_the_loop_will_not_start_off_windows(db):
    """
    A Linux backend cannot read a Windows host's event log. Saying
    otherwise, or starting a loop that can only fail, would be the
    fabrication this project exists to avoid.
    """
    service = DnsEventCollectorService(db=db)
    if service.platform_supported:
        pytest.skip("this assertion is about non-Windows hosts")

    status = asyncio.run(service.start())

    assert status.state == "unsupported"
    assert not service.is_running
    assert "Windows" in (status.last_error or "")


def test_concurrent_polls_do_not_overlap(db, monkeypatch):
    """
    Two readers racing on one bookmark would both advance it. A poll
    that is already running must cause the next to be skipped, not
    queued behind it.
    """
    service = DnsEventCollectorService(db=db)
    started = asyncio.Event()
    release = asyncio.Event()
    calls = {"n": 0}

    async def run():
        async def slow_collect():
            calls["n"] += 1
            started.set()
            await release.wait()
            return {"succeeded": True, "records_read": 0, "observations_recorded": 0,
                    "skipped_failed_query": 0, "more_available": False}

        # Replace the thread hop with a controllable coroutine.
        async def fake_to_thread(fn, *a, **k):
            return await slow_collect()

        monkeypatch.setattr("app.services.dns_collector.asyncio.to_thread", fake_to_thread)

        first = asyncio.create_task(service.poll_once())
        await started.wait()
        second = await service.poll_once()  # must return immediately
        release.set()
        await first
        return second

    skipped = asyncio.run(run())

    assert calls["n"] == 1, "the second poll ran a collection while one was in flight"
    assert skipped is False


def test_a_failing_poll_is_recorded_not_raised(db, monkeypatch):
    service = DnsEventCollectorService(db=db)

    async def run():
        async def fake_to_thread(fn, *a, **k):
            raise RuntimeError("powershell exploded")

        monkeypatch.setattr("app.services.dns_collector.asyncio.to_thread", fake_to_thread)
        return await service.poll_once()

    assert asyncio.run(run()) is False
    assert service.polls_failed == 1
    assert service.consecutive_failures == 1
    assert "powershell exploded" in (service.last_error or "")


def test_an_unsuccessful_result_counts_as_a_failure(db, monkeypatch):
    """A disabled channel is reported, not retried as if it had worked."""
    service = DnsEventCollectorService(db=db)

    async def run():
        async def fake_to_thread(fn, *a, **k):
            return {"succeeded": False, "error": "channel is disabled"}

        monkeypatch.setattr("app.services.dns_collector.asyncio.to_thread", fake_to_thread)
        return await service.poll_once()

    assert asyncio.run(run()) is False
    assert service.last_error == "channel is disabled"


def test_stop_is_safe_when_nothing_is_running(db):
    service = DnsEventCollectorService(db=db)
    status = asyncio.run(service.stop())
    assert status.state in {"stopped", "unsupported"}
    # And twice.
    asyncio.run(service.stop())


def test_the_interval_is_clamped(db):
    """Each poll spawns a PowerShell process; sub-second polling thrashes."""
    assert DnsEventCollectorService(db=db, interval_seconds=0.01).interval_seconds >= 2.0
    assert DnsEventCollectorService(db=db, interval_seconds=10_000).interval_seconds <= 3600.0


def test_the_failure_limit_is_finite(db):
    """
    A disabled channel does not start reporting because it was asked
    nine hundred times; the log noise buries anything real.
    """
    assert 1 <= MAX_CONSECUTIVE_FAILURES <= 100
