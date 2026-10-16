"""
PraHari — Timestamp Integrity, Adapter to Database to API (ADR-060).

The live operational database holds 65 events whose `observed_at` is
`1601-01-01T00:00:00Z` — the Windows FILETIME epoch, which the OS returns
for a socket with no recorded start (PID 0, TimeWait). An early version of
the Windows adapter stored that as a real observation time.

The adapter was fixed: `_is_plausible` now discards it and falls back to
the poll time with `INVALID_VALUE` + `TIMESTAMP_UNCERTAINTY`. Evidence
from the operational database that the fix holds — read-only:

* the 65 bad rows were all ingested in one 26-minute window on
  2026-10-11, and carry only `["missing_field"]`;
* 1,612 later rows carry `invalid_value` + `timestamp_uncertainty`, which
  is the new guard doing its job;
* of 3,263 Windows events ingested after that window, **zero** have 1601.

What was missing was a test covering the whole path. `test_windows_telemetry`
stops at `validate_and_normalize`, and `test_research_gate` injects 1601
straight onto an event object, bypassing the adapter. Neither proves a
sentinel cannot survive persistence and serialization.

These tests close that, and pin the feasibility gate's behaviour when such
records DO exist — which is the live situation, and must stay a failure.

Temporary databases only. The operational database is never opened.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.adapters.windows_telemetry import WindowsConnectionAdapter
from app.api.deps import get_db
from app.api.v1.router import api_v1_router
from app.core.config import AppConfig, get_config
from app.research.feasibility import audit_dataset_feasibility
from app.schemas.events import (
    DataCategory,
    EventType,
    LabelProvenance,
    NormalizedEvent,
    QualityFlag,
    TelemetrySource,
    is_plausible_timestamp,
)
from app.storage.database import Database

SOURCE = "windows_local_host"
FILETIME_EPOCH = "1601-01-01T00:00:00.0000000Z"
POLL_TIME = datetime(2026, 10, 16, 12, 0, 0, tzinfo=timezone.utc)


def _conn(**over) -> dict:
    record = {
        "local_address": "192.168.1.10",
        "local_port": 51000,
        "remote_address": "203.0.113.5",
        "remote_port": 443,
        "protocol": "TCP",
        "state": "Established",
        "owning_pid": 4242,
        "process_name": "app.exe",
        "creation_time": "2026-10-16T11:59:00.000000Z",
        "observed_at": POLL_TIME.isoformat(),
    }
    record.update(over)
    return record


@pytest.fixture
def db(tmp_path):
    database = Database(db_path=str(tmp_path / "timestamps.db"))
    database.initialize()
    database.upsert_source(
        TelemetrySource(
            source_id=SOURCE, name=SOURCE,
            source_type="windows_connection_table",
        )
    )
    yield database
    database.close()


@pytest.fixture
def client(db):
    app = FastAPI()
    app.include_router(api_v1_router, prefix="/api/v1")
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[get_config] = lambda: AppConfig()
    with TestClient(app) as c:
        yield c, db


# ──────────────────────────────────────────────────────────────────
# The full path: adapter -> database -> API
# ──────────────────────────────────────────────────────────────────


def test_a_filetime_sentinel_never_reaches_the_database(client):
    """
    The regression that produced the 65 live rows. A sentinel must not
    survive persistence under any circumstance.
    """
    c, database = client
    adapter = WindowsConnectionAdapter(adapter_id=SOURCE)
    record = _conn(creation_time=FILETIME_EPOCH, state="TimeWait", owning_pid=0)

    result = adapter.validate_and_normalize(record, 0)
    assert result.is_valid and result.event is not None
    database.insert_events([result.event])

    stored = database.list_events(source_id=SOURCE, limit=10)
    assert len(stored) == 1
    assert stored[0].observed_at.year != 1601
    assert stored[0].observed_at == POLL_TIME


def test_the_sentinel_does_not_survive_api_serialization(client):
    c, database = client
    adapter = WindowsConnectionAdapter(adapter_id=SOURCE)
    event = adapter.validate_and_normalize(
        _conn(creation_time=FILETIME_EPOCH, state="TimeWait", owning_pid=0), 0
    ).event
    database.insert_events([event])

    body = c.get("/api/v1/events", params={"source_id": SOURCE}).json()
    events = body["events"] if isinstance(body, dict) else body

    assert events
    assert "1601" not in str(events), "the sentinel reached the API response"


def test_the_substituted_time_is_marked_as_poll_time_not_connection_start(client):
    """
    The fallback is honest only if it is flagged. An unflagged poll time
    would read as a genuine connection start.
    """
    c, database = client
    adapter = WindowsConnectionAdapter(adapter_id=SOURCE)
    event = adapter.validate_and_normalize(
        _conn(creation_time=FILETIME_EPOCH, state="TimeWait", owning_pid=0), 0
    ).event
    database.insert_events([event])

    stored = database.list_events(source_id=SOURCE, limit=5)[0]

    assert QualityFlag.INVALID_VALUE in stored.quality_flags
    assert QualityFlag.TIMESTAMP_UNCERTAINTY in stored.quality_flags


def test_a_genuine_creation_time_round_trips_unchanged(client):
    """The guard must not damage a good timestamp."""
    c, database = client
    adapter = WindowsConnectionAdapter(adapter_id=SOURCE)
    genuine = datetime(2026, 10, 16, 11, 59, 0, tzinfo=timezone.utc)

    event = adapter.validate_and_normalize(_conn(), 0).event
    database.insert_events([event])
    stored = database.list_events(source_id=SOURCE, limit=5)[0]

    assert stored.observed_at == genuine
    assert QualityFlag.INVALID_VALUE not in stored.quality_flags


@pytest.mark.parametrize(
    "creation_time, expect_substituted",
    [
        ("1601-01-01T00:00:00.0000000Z", True),    # FILETIME epoch
        ("1899-12-30T00:00:00Z", True),            # OLE automation epoch
        ("1970-01-01T00:00:00Z", True),            # Unix epoch sentinel
        ("not-a-timestamp", True),                 # unparseable
        ("", True),                                # empty
        (None, True),                              # absent
        ("2026-10-16T11:59:00.000000Z", False),    # genuine
    ],
)
def test_every_sentinel_shape_is_substituted(client, creation_time, expect_substituted):
    c, database = client
    adapter = WindowsConnectionAdapter(adapter_id=SOURCE)

    event = adapter.validate_and_normalize(
        _conn(creation_time=creation_time), 0
    ).event

    assert event is not None
    if expect_substituted:
        assert event.observed_at == POLL_TIME
        assert QualityFlag.TIMESTAMP_UNCERTAINTY in event.quality_flags
    else:
        assert event.observed_at.year == 2026
        assert event.observed_at != POLL_TIME


def test_a_future_creation_time_is_substituted_not_stored(client):
    """
    A connection cannot have started after it was observed. Storing that
    would let a future-dated row leak into an earlier forecast window.
    """
    c, database = client
    adapter = WindowsConnectionAdapter(adapter_id=SOURCE)
    far_future = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()

    event = adapter.validate_and_normalize(
        _conn(creation_time=far_future, observed_at=datetime.now(timezone.utc).isoformat()),
        0,
    ).event
    database.insert_events([event])

    stored = database.list_events(source_id=SOURCE, limit=5)[0]
    assert is_plausible_timestamp(stored.observed_at)


def test_the_substitution_does_not_fabricate_the_current_time(client):
    """
    The poll time is evidence — PraHari saw the connection then. Using
    `now()` instead would date the record to import time, which is a
    different and unobserved claim.
    """
    c, database = client
    adapter = WindowsConnectionAdapter(adapter_id=SOURCE)
    old_poll = datetime(2026, 10, 1, 8, 0, 0, tzinfo=timezone.utc)

    event = adapter.validate_and_normalize(
        _conn(creation_time=FILETIME_EPOCH, observed_at=old_poll.isoformat()), 0
    ).event

    assert event.observed_at == old_poll, "the recorded poll time was discarded"
    assert (datetime.now(timezone.utc) - event.observed_at).days >= 1


# ──────────────────────────────────────────────────────────────────
# The feasibility gate must keep failing while such records exist
# ──────────────────────────────────────────────────────────────────


def _event(idx: int, observed: datetime) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=f"ts-{idx}",
        source_id=SOURCE,
        data_category=DataCategory.LIVE_TELEMETRY,
        observed_at=observed,
        event_type=EventType.CONNECTION,
        src_ip="192.0.2.10",
        dst_ip="198.51.100.20",
        src_port=40000 + idx,
        dst_port=443,
        protocol="TCP",
        label_provenance=LabelProvenance.UNLABELED,
    )


def _audit(events):
    report = audit_dataset_feasibility(events, dataset_id="timestamp_integrity")
    temporal = next(
        c for c in report.checks if "temporal" in c.check_name.lower()
    )
    return report, temporal


def test_a_single_implausible_record_fails_the_temporal_check():
    """
    The live situation: 65 bad rows among thousands of good ones. The
    gate must refuse, not round the problem away.
    """
    base = datetime(2026, 10, 1, tzinfo=timezone.utc)
    events = [_event(i, base + timedelta(minutes=i)) for i in range(200)]
    events.append(_event(999, datetime(1601, 1, 1, tzinfo=timezone.utc)))

    _, temporal = _audit(events)

    assert temporal.passed is False
    assert "implausible" in temporal.details.lower()


def test_the_reported_score_moves_with_the_verdict():
    """
    A score of 100% printed beside a failed check reads as a display bug
    and invites a reader to dismiss the failure.
    """
    base = datetime(2026, 10, 1, tzinfo=timezone.utc)
    clean = [_event(i, base + timedelta(minutes=i)) for i in range(100)]
    dirty = clean + [_event(999, datetime(1601, 1, 1, tzinfo=timezone.utc))]

    _, clean_check = _audit(clean)
    _, dirty_check = _audit(dirty)

    assert clean_check.passed is True
    assert dirty_check.passed is False
    assert dirty_check.score < clean_check.score, (
        "the score ignored the implausible records"
    )


def test_clean_data_passes_the_temporal_check():
    """The gate must not fail everything indiscriminately."""
    base = datetime(2026, 10, 1, tzinfo=timezone.utc)

    _, temporal = _audit([_event(i, base + timedelta(minutes=i)) for i in range(50)])

    assert temporal.passed is True


def test_the_detail_explains_why_rather_than_only_that_it_failed():
    base = datetime(2026, 10, 1, tzinfo=timezone.utc)
    events = [_event(i, base + timedelta(minutes=i)) for i in range(50)]
    events.append(_event(999, datetime(1601, 1, 1, tzinfo=timezone.utc)))

    _, temporal = _audit(events)

    detail = temporal.details.lower()
    assert "1 record" in detail
    assert "excluded from the span" in detail
    assert "does not pass" in detail


def test_implausible_records_are_excluded_from_the_span_not_included():
    """
    Including 1601 would report a span of four centuries and make every
    rate feature meaningless.
    """
    # At least `min_event_count` (25), or the auditor returns before the
    # temporal check ever runs.
    base = datetime(2026, 10, 1, tzinfo=timezone.utc)
    events = [_event(i, base + timedelta(minutes=i)) for i in range(30)]
    events.append(_event(999, datetime(1601, 1, 1, tzinfo=timezone.utc)))

    _, temporal = _audit(events)

    # 29 minutes between the first and last plausible event, not four
    # centuries — which is what including 1601 would report.
    assert "1740.0s" in temporal.details, temporal.details
