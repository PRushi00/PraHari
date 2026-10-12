"""
Integration tests for the live Windows telemetry collector.

Two distinct layers are tested, and they are NOT interchangeable:

  * Collector mechanics (lifecycle, persistence, accounting, failure
    handling) are tested with an injected query function. These prove the
    pipeline wiring, not that the OS query works.

  * Genuine OS collection is tested separately and marked `live_windows`.
    Those tests query the real Windows connection table and are skipped on
    other platforms. Only they demonstrate that real telemetry is observed.
"""

from __future__ import annotations

import asyncio
import functools
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.adapters.base import get_adapter_registry
from app.adapters.windows_telemetry import (
    WindowsTelemetryUnavailable,
    query_windows_connections,
)
from app.api.deps import get_db
from app.main import app
from app.schemas.events import DataCategory, EventType
from app.services.collector import (
    WindowsTelemetryCollectorService,
    reset_collector,
)
from app.storage.database import Database

def run_async(fn):
    """
    Run an async test body on a fresh event loop.

    Avoids adding a pytest-asyncio dependency: `pip install -r
    requirements.txt` stays sufficient to run the whole suite.
    """

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        return asyncio.run(fn(*args, **kwargs))

    return wrapper


requires_windows = pytest.mark.skipif(
    sys.platform != "win32",
    reason="Live Windows connection-table collection requires Windows",
)


@pytest.fixture
def temp_db():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        db_path = tmp.name
    db = Database(db_path=db_path)
    db.initialize()
    yield db
    db.close()
    try:
        Path(db_path).unlink(missing_ok=True)
    except Exception:
        pass


def _fake_connections(n: int = 3, base_port: int = 50000, created: str | None = None):
    created = created or "2026-10-11T16:36:26.0000000Z"

    def _query(*_args, **_kwargs):
        return [
            {
                "protocol": "TCP",
                "local_address": "192.0.2.10",
                "local_port": base_port + i,
                "remote_address": f"93.184.216.{10 + i}",
                "remote_port": 443,
                "state": "Established",
                "owning_pid": 4000 + i,
                "creation_time": created,
            }
            for i in range(n)
        ]

    return _query


# ──────────────────────────────────────────────────────────────────
# Collector mechanics (injected query — proves wiring only)
# ──────────────────────────────────────────────────────────────────


@run_async
async def test_poll_persists_events_and_registers_source(temp_db):
    collector = WindowsTelemetryCollectorService(
        db=temp_db, source_id="win_test", query_fn=_fake_connections(3)
    )
    collector._ensure_source_registered()

    result = await collector.poll_once()

    assert result.succeeded
    assert result.records_observed == 3
    assert result.events_accepted == 3
    assert result.events_persisted == 3

    # Events reached storage with live provenance intact.
    events = temp_db.list_events(source_id="win_test", limit=100)
    assert len(events) == 3
    assert all(e.data_category == DataCategory.LIVE_TELEMETRY for e in events)
    assert all(e.event_type == EventType.CONNECTION for e in events)
    assert all(e.source_id == "win_test" for e in events)

    # Source health reflects stored reality.
    source = temp_db.get_source("win_test")
    assert source is not None
    assert source.event_count == 3
    assert source.last_event_at is not None
    assert source.status == "active"


@run_async
async def test_repeated_polls_do_not_duplicate_or_inflate_counts(temp_db):
    """
    Polling the same still-open connections repeatedly must leave both the
    stored row count and the source's event_count unchanged.
    """
    collector = WindowsTelemetryCollectorService(
        db=temp_db, source_id="win_dedup", query_fn=_fake_connections(4)
    )
    collector._ensure_source_registered()

    first = await collector.poll_once()
    assert first.events_persisted == 4

    second = await collector.poll_once()
    assert second.records_observed == 4
    assert second.events_accepted == 0
    assert second.events_persisted == 0
    assert second.duplicates_suppressed == 4

    assert temp_db.count_events(source_id="win_dedup") == 4
    source = temp_db.get_source("win_dedup")
    assert source is not None
    assert source.event_count == 4

    status = collector.status()
    assert status.events_persisted_total == 4
    assert status.duplicates_suppressed_total == 4
    assert status.polls_succeeded == 2


@run_async
async def test_new_connections_are_added_on_later_polls(temp_db):
    collector = WindowsTelemetryCollectorService(
        db=temp_db, source_id="win_growth", query_fn=_fake_connections(2)
    )
    collector._ensure_source_registered()
    await collector.poll_once()
    assert temp_db.count_events(source_id="win_growth") == 2

    # A later poll sees the original two plus two new connections.
    collector._query_fn = _fake_connections(4)
    result = await collector.poll_once()

    assert result.events_persisted == 2
    assert result.duplicates_suppressed == 2
    assert temp_db.count_events(source_id="win_growth") == 4


@run_async
async def test_events_persist_across_database_reconnection(temp_db):
    collector = WindowsTelemetryCollectorService(
        db=temp_db, source_id="win_persist", query_fn=_fake_connections(3)
    )
    collector._ensure_source_registered()
    await collector.poll_once()

    reopened = Database(db_path=temp_db.db_path)
    assert reopened.count_events(source_id="win_persist") == 3
    reopened.close()


@run_async
async def test_collection_failure_is_surfaced_not_swallowed(temp_db):
    def _failing(*_args, **_kwargs):
        raise WindowsTelemetryUnavailable("simulated query failure")

    collector = WindowsTelemetryCollectorService(
        db=temp_db, source_id="win_fail", query_fn=_failing
    )
    collector._ensure_source_registered()

    result = await collector.poll_once()

    assert result.succeeded is False
    assert "simulated query failure" in result.error

    status = collector.status()
    assert status.polls_failed == 1
    assert status.consecutive_failures == 1
    assert "simulated query failure" in status.last_error

    # Source health records the error rather than claiming to be active.
    source = temp_db.get_source("win_fail")
    assert source is not None
    assert source.status == "error"


@run_async
async def test_no_traffic_observed_is_a_clean_success(temp_db):
    """An empty connection table is a valid observation, not a failure."""
    collector = WindowsTelemetryCollectorService(
        db=temp_db, source_id="win_quiet", query_fn=lambda *a, **k: []
    )
    collector._ensure_source_registered()

    result = await collector.poll_once()

    assert result.succeeded is True
    assert result.records_observed == 0
    assert result.events_persisted == 0
    assert collector.status().polls_succeeded == 1
    assert collector.status().last_error is None


@run_async
async def test_collection_gap_is_recorded(temp_db):
    collector = WindowsTelemetryCollectorService(
        db=temp_db,
        source_id="win_gap",
        interval_seconds=2.0,
        query_fn=_fake_connections(1),
    )
    collector._ensure_source_registered()
    await collector.poll_once()

    # Simulate a long outage since the last successful collection.
    collector._last_success_at = datetime.now(timezone.utc) - timedelta(minutes=5)
    await collector.poll_once()

    gaps = collector.status().collection_gaps
    assert len(gaps) == 1
    assert gaps[0].gap_seconds > 2.0 * 2.5


@run_async
async def test_start_and_stop_are_clean_and_idempotent(temp_db):
    collector = WindowsTelemetryCollectorService(
        db=temp_db,
        source_id="win_lifecycle",
        interval_seconds=2.0,
        query_fn=_fake_connections(2),
    )

    status = await collector.start()
    assert status.state == "running"
    assert collector.is_running

    # Starting twice must not spawn a second polling task.
    again = await collector.start()
    assert again.state == "running"

    stopped = await collector.stop()
    assert stopped.state == "stopped"
    assert collector.is_running is False

    # Stopping twice is harmless.
    assert (await collector.stop()).state == "stopped"

    source = temp_db.get_source("win_lifecycle")
    assert source is not None
    assert source.status == "disconnected"


@run_async
async def test_restart_preserves_previously_stored_events(temp_db):
    collector = WindowsTelemetryCollectorService(
        db=temp_db, source_id="win_restart", query_fn=_fake_connections(3)
    )
    collector._ensure_source_registered()
    await collector.poll_once()
    assert temp_db.count_events(source_id="win_restart") == 3

    # Simulate an application restart: a new process starts with an empty
    # adapter registry, so in-memory dedup state is gone and the same
    # connections are normalized afresh. Deterministic event ids must still
    # prevent duplicate rows.
    get_adapter_registry().clear()
    fresh = WindowsTelemetryCollectorService(
        db=temp_db, source_id="win_restart", query_fn=_fake_connections(3)
    )
    fresh._ensure_source_registered()
    result = await fresh.poll_once()

    assert result.events_accepted == 3   # re-normalized by the new instance
    assert result.events_persisted == 0  # but storage recognised them
    assert temp_db.count_events(source_id="win_restart") == 3


@run_async
async def test_policy_filtered_records_are_not_counted_as_rejections(temp_db):
    """
    A collector excluding loopback traffic must not report those records as
    rejections — otherwise a healthy collector looks like it is failing
    validation on most of its input.
    """
    def _loopback_heavy(*_args, **_kwargs):
        return [
            {
                "protocol": "TCP", "local_address": "127.0.0.1", "local_port": 7000 + i,
                "remote_address": "127.0.0.1", "remote_port": 8000 + i,
                "state": "Established", "owning_pid": 900 + i,
                "creation_time": "2026-10-11T16:36:26.0000000Z",
            }
            for i in range(4)
        ] + [
            {
                "protocol": "TCP", "local_address": "192.0.2.10", "local_port": 60001,
                "remote_address": "140.82.113.21", "remote_port": 443,
                "state": "Established", "owning_pid": 1234,
                "creation_time": "2026-10-11T16:36:26.0000000Z",
            }
        ]

    collector = WindowsTelemetryCollectorService(
        db=temp_db, source_id="win_filter", query_fn=_loopback_heavy
    )
    collector._ensure_source_registered()
    result = await collector.poll_once()

    assert result.succeeded
    assert result.records_observed == 5
    assert result.events_accepted == 1
    assert result.records_filtered_by_policy == 4
    assert result.records_rejected == 0

    status = collector.status()
    assert status.records_filtered_by_policy_total == 4
    assert status.records_rejected_total == 0


def test_status_reports_capability_limits(temp_db):
    collector = WindowsTelemetryCollectorService(db=temp_db, source_id="win_caps")
    status = collector.status()

    notes = " ".join(status.capability_notes).lower()
    assert "connection metadata only" in notes
    assert "not available" in notes          # byte/packet counts
    assert "snapshot polling" in notes
    assert status.data_category == DataCategory.LIVE_TELEMETRY


# ──────────────────────────────────────────────────────────────────
# API surface
# ──────────────────────────────────────────────────────────────────


@pytest.fixture
def api_client(temp_db):
    reset_collector(db=temp_db, source_id="api_win", query_fn=_fake_connections(3))
    app.dependency_overrides[get_db] = lambda: temp_db
    with TestClient(app) as client:
        yield client, temp_db
    app.dependency_overrides.clear()
    reset_collector(None)


def test_collector_status_endpoint_before_any_collection(api_client):
    client, _ = api_client
    res = client.get("/api/v1/collector/status")
    assert res.status_code == 200
    body = res.json()

    # Before starting, the dashboard must be able to show "not collecting".
    assert body["state"] in ("stopped", "unsupported")
    assert body["events_persisted_total"] == 0
    assert body["last_success_at"] is None
    assert body["data_category"] == "live_telemetry"
    assert len(body["capability_notes"]) >= 5


def test_collector_poll_endpoint_ingests_and_reports(api_client):
    client, db = api_client
    res = client.post("/api/v1/collector/poll")

    if sys.platform != "win32":
        # Off Windows the endpoint must refuse clearly rather than pretend.
        assert res.status_code == 501
        return

    assert res.status_code == 200
    body = res.json()
    assert body["succeeded"] is True
    assert body["events_persisted"] == 3
    assert db.count_events(source_id="api_win") == 3

    # The collected events are visible through the normal events API.
    events = client.get("/api/v1/events?source_id=api_win&limit=10").json()
    assert events["total"] == 3
    assert all(e["data_category"] == "live_telemetry" for e in events["events"])
    assert all(e["event_type"] == "connection" for e in events["events"])


def test_collector_start_stop_endpoints(api_client):
    client, _ = api_client
    start = client.post("/api/v1/collector/start", json={"interval_seconds": 5})

    if sys.platform != "win32":
        assert start.status_code == 501
        return

    assert start.status_code == 200
    assert start.json()["state"] == "running"
    assert start.json()["interval_seconds"] == 5

    stop = client.post("/api/v1/collector/stop")
    assert stop.status_code == 200
    assert stop.json()["state"] == "stopped"


def test_collector_rejects_out_of_range_interval(api_client):
    client, _ = api_client
    res = client.post("/api/v1/collector/start", json={"interval_seconds": 0.1})
    assert res.status_code == 422


# ──────────────────────────────────────────────────────────────────
# GENUINE live collection (real OS query — Windows only)
# ──────────────────────────────────────────────────────────────────


@requires_windows
@pytest.mark.live_windows
def test_live_query_returns_real_connections():
    """
    Query the real Windows connection table and assert the returned records
    are structurally genuine. This is the only test that demonstrates actual
    host visibility; the mocked tests above do not.
    """
    records = query_windows_connections()

    assert isinstance(records, list)
    assert len(records) > 0, (
        "No TCP connections observed on this host. Open a network connection "
        "and retry — this test requires genuine local network activity."
    )

    sample = records[0]
    for field in (
        "protocol",
        "local_address",
        "local_port",
        "remote_address",
        "remote_port",
        "state",
        "creation_time",
    ):
        assert field in sample, f"OS record missing '{field}': {sample}"

    # At least one connection should have a real (non-wildcard) remote peer.
    real_peers = [
        r for r in records
        if r.get("remote_address") not in ("0.0.0.0", "::", "", None)
        and int(r.get("remote_port") or 0) > 0
    ]
    assert real_peers, "No connections with a real remote peer were observed"


@requires_windows
@pytest.mark.live_windows
@run_async
async def test_live_collection_end_to_end_persists_real_telemetry(temp_db):
    """
    Full genuine path: real OS query -> normalization -> persistence ->
    retrieval, with provenance and honest field absence verified on the
    stored records.
    """
    collector = WindowsTelemetryCollectorService(
        db=temp_db, source_id="live_windows_host"
    )
    collector._ensure_source_registered()

    result = await collector.poll_once()
    assert result.succeeded, f"Live collection failed: {result.error}"
    assert result.records_observed > 0, "No live connections observed"
    assert result.events_persisted > 0, "No live events were persisted"

    stored = temp_db.list_events(source_id="live_windows_host", limit=500)
    assert len(stored) == result.events_persisted

    for ev in stored:
        # Provenance
        assert ev.data_category == DataCategory.LIVE_TELEMETRY
        assert ev.event_type == EventType.CONNECTION
        assert ev.source_id == "live_windows_host"
        # Real endpoints
        assert ev.src_ip and ev.dst_ip
        assert ev.dst_port is not None and 0 <= ev.dst_port <= 65535
        assert ev.protocol == "TCP"
        # Timestamps are timezone-aware and not in the future
        assert ev.observed_at.tzinfo is not None
        assert ev.observed_at <= datetime.now(timezone.utc) + timedelta(minutes=1)
        # Fields this source cannot provide remain absent
        assert ev.bytes_total is None
        assert ev.packets is None
        # No fabricated labels
        assert ev.label is None

    # A second live poll must not duplicate still-open connections.
    before = temp_db.count_events(source_id="live_windows_host")
    second = await collector.poll_once()
    assert second.succeeded
    after = temp_db.count_events(source_id="live_windows_host")
    assert after >= before
    assert second.duplicates_suppressed > 0, (
        "Expected at least one still-open connection to be suppressed on the "
        "second poll"
    )


@run_async
async def test_counter_invariant_holds_across_many_polls(temp_db):
    """
    observed == accepted + duplicates + filtered + rejected, always.

    The dashboard shows these side by side, so a drift between them reads
    as lost telemetry.
    """
    def _varying(call=[0]):
        def _q(*_a, **_k):
            call[0] += 1
            n = call[0]
            rows = [
                {
                    "protocol": "TCP", "local_address": "192.0.2.10",
                    "local_port": 50000 + i, "remote_address": f"93.184.216.{i}",
                    "remote_port": 443, "state": "Established",
                    "owning_pid": 100 + i, "process_name": "test",
                    "creation_time": "2026-10-11T16:36:26.0000000Z",
                }
                for i in range(5)
            ]
            # A new connection each poll, plus loopback noise to be filtered,
            # plus one unusable record.
            rows.append({
                "protocol": "TCP", "local_address": "192.0.2.10",
                "local_port": 60000 + n, "remote_address": "140.82.113.21",
                "remote_port": 443, "state": "Established", "owning_pid": 7,
                "process_name": "test", "creation_time": f"2026-10-11T17:0{n}:00.0000000Z",
            })
            rows.append({
                "protocol": "TCP", "local_address": "127.0.0.1", "local_port": 1,
                "remote_address": "127.0.0.1", "remote_port": 2,
                "state": "Established", "owning_pid": 8,
                "creation_time": "2026-10-11T16:36:26.0000000Z",
            })
            rows.append({
                "protocol": "TCP", "local_address": "192.0.2.10",
                "local_port": 3, "remote_address": "0.0.0.0", "remote_port": 0,
                "state": "Established", "owning_pid": 9,
                "creation_time": "2026-10-11T16:36:26.0000000Z",
            })
            return rows
        return _q

    collector = WindowsTelemetryCollectorService(
        db=temp_db, source_id="win_invariant", query_fn=_varying()
    )
    collector._ensure_source_registered()

    for _ in range(4):
        result = await collector.poll_once()
        assert result.succeeded
        assert result.records_observed == (
            result.events_accepted
            + result.duplicates_suppressed
            + result.records_filtered_by_policy
            + result.records_rejected
        ), "per-poll accounting must balance"

    status = collector.status()
    assert status.records_observed_total == (
        status.events_accepted_total
        + status.duplicates_suppressed_total
        + status.records_filtered_by_policy_total
        + status.records_rejected_total
    ), "cumulative accounting must balance"

    # Repeat sightings were suppressed, new connections were not.
    assert status.duplicates_suppressed_total > 0
    assert status.records_filtered_by_policy_total > 0
    assert status.records_rejected_total > 0

    # Stored rows never exceed what was accepted, and the source counter is
    # derived from storage rather than from the in-memory counters.
    stored = temp_db.count_events(source_id="win_invariant")
    assert stored <= status.events_accepted_total
    source = temp_db.get_source("win_invariant")
    assert source is not None
    assert source.event_count == stored


@run_async
async def test_new_connections_are_not_suppressed_as_duplicates(temp_db):
    """A genuinely new connection must never be counted as a repeat."""
    state = {"n": 0}

    def _q(*_a, **_k):
        state["n"] += 1
        return [{
            "protocol": "TCP", "local_address": "192.0.2.10",
            "local_port": 40000 + state["n"], "remote_address": "140.82.113.21",
            "remote_port": 443, "state": "Established", "owning_pid": 1,
            "process_name": "test",
            "creation_time": f"2026-10-11T18:0{state['n']}:00.0000000Z",
        }]

    collector = WindowsTelemetryCollectorService(
        db=temp_db, source_id="win_new", query_fn=_q
    )
    collector._ensure_source_registered()

    for expected in range(1, 4):
        result = await collector.poll_once()
        assert result.events_accepted == 1, "each distinct connection is new"
        assert result.duplicates_suppressed == 0
        assert temp_db.count_events(source_id="win_new") == expected


@run_async
async def test_injected_query_does_not_touch_the_real_operating_system(temp_db, monkeypatch):
    """
    A test that mocks the connection table must not shell out to PowerShell.

    Enrichment previously refreshed the real DNS cache on every poll even
    when the connection query was injected, spawning a PowerShell process
    per poll. That is both inconsistent (fake connections, real DNS) and
    slow enough to dominate the suite's runtime.
    """
    import subprocess as _sp

    spawned: list = []
    real_run = _sp.run

    def _tracking_run(*args, **kwargs):
        spawned.append(args[0] if args else kwargs.get("args"))
        return real_run(*args, **kwargs)

    monkeypatch.setattr(_sp, "run", _tracking_run)

    collector = WindowsTelemetryCollectorService(
        db=temp_db, source_id="win_isolated", query_fn=_fake_connections(3)
    )
    collector._ensure_source_registered()

    assert collector.refresh_dns is False, "injected query must default to no DNS refresh"

    result = await collector.poll_once()
    assert result.succeeded
    assert result.events_persisted == 3
    assert spawned == [], f"no subprocess should be spawned, got: {spawned}"


@run_async
async def test_real_collection_still_refreshes_dns_evidence(temp_db):
    """The production path keeps enrichment enabled."""
    collector = WindowsTelemetryCollectorService(db=temp_db, source_id="win_real_default")
    assert collector.refresh_dns is True

    # An explicit value always wins, in either direction.
    off = WindowsTelemetryCollectorService(db=temp_db, source_id="x", refresh_dns=False)
    assert off.refresh_dns is False
    on = WindowsTelemetryCollectorService(
        db=temp_db, source_id="y", query_fn=_fake_connections(1), refresh_dns=True
    )
    assert on.refresh_dns is True
