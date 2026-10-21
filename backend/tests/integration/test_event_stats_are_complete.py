"""
PraHari — `GET /events/stats/summary` counts every event (ADR-100).

The handler reported `total_events` from a full `COUNT(*)` but built the
label, event-type and data-category breakdowns from
`list_events(limit=1000)`. Past a thousand events the two halves of one
response described different populations, and nothing in the response
said so.

This is ADR-095's defect in a second place. There, readiness reported
"0 positive" for a corpus holding 52,498 attack-labelled events, because
its 50,000-row sample was the day's tail. The fix added `label_counts()`
— a GROUP BY — but only readiness was changed; this endpoint kept
sampling.

It is reachable in ordinary use: a Windows collector observed here
reached 699 events in 22 minutes of polling, so an afternoon's
collection crosses the limit.

These pin:

* the breakdowns sum to `total_events` past the old sample cap;
* a label present only in the OLDEST events is still counted, which the
  sample could not see and is the form the defect took in ADR-095;
* unlabelled events keep the `"unlabeled"` key the API already returned.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.deps import get_db
from app.api.v1.router import api_v1_router
from app.schemas.events import (
    DataCategory,
    EventType,
    LabelProvenance,
    NormalizedEvent,
    TelemetrySource,
)
from app.storage.database import Database

SOURCE = "windows_local_host"
# One more than the sample cap the handler used, so the shortfall is
# produced by the cap and not by the size of the fixture.
TOTAL = 1200
OLD_ATTACKS = 150

BASE = datetime(2026, 10, 21, 0, 0, tzinfo=timezone.utc)


@pytest.fixture()
def client(tmp_path):
    db = Database(str(tmp_path / "stats.db"))
    db.initialize()
    db.upsert_source(
        TelemetrySource(
            source_id=SOURCE, name="Host", source_type="windows_connection_table"
        )
    )
    # The attacks are the OLDEST events. A newest-first sample of 1000 out
    # of 1200 cannot see any of them — the shape of the ADR-095 failure.
    db.insert_events(
        [
            NormalizedEvent(
                event_id=f"evt-{i:06d}",
                source_id=SOURCE,
                observed_at=BASE + timedelta(seconds=i),
                event_type=EventType.CONNECTION,
                data_category=DataCategory.LIVE_TELEMETRY,
                schema_version="1.0.0",
                label=("attack" if i < OLD_ATTACKS else None),
                label_provenance=LabelProvenance.UNLABELED,
            )
            for i in range(TOTAL)
        ]
    )

    app = FastAPI()
    app.include_router(api_v1_router, prefix="/api/v1")
    app.dependency_overrides[get_db] = lambda: db
    with TestClient(app) as c:
        yield c
    db.close()


def test_the_breakdowns_account_for_every_event(client):
    body = client.get("/api/v1/events/stats/summary").json()

    assert body["total_events"] == TOTAL
    for key in ("labels", "event_types", "data_categories"):
        assert sum(body[key].values()) == TOTAL, (
            f"{key} sums to {sum(body[key].values())}, not {TOTAL}: the "
            "breakdown and the total describe different populations"
        )


def test_a_label_only_in_the_oldest_events_is_still_counted(client):
    """
    The ADR-095 failure exactly: the sample was drawn from one end of the
    capture, so a label living at the other end read as absent.
    """
    body = client.get("/api/v1/events/stats/summary").json()

    assert body["labels"].get("attack") == OLD_ATTACKS
    assert body["labels"].get("unlabeled") == TOTAL - OLD_ATTACKS


def test_unlabelled_events_keep_the_key_the_api_already_returned(client):
    """Storage reports '' for unlabelled; the API contract says 'unlabeled'."""
    body = client.get("/api/v1/events/stats/summary").json()

    assert "unlabeled" in body["labels"]
    assert "" not in body["labels"]


def test_the_storage_breakdown_matches_a_filtered_count(tmp_path):
    """
    The breakdown must agree with the count the same store gives for one
    filter, or one of the two is wrong.
    """
    db = Database(str(tmp_path / "agree.db"))
    db.initialize()
    db.upsert_source(
        TelemetrySource(
            source_id=SOURCE, name="Host", source_type="windows_connection_table"
        )
    )
    db.insert_events(
        [
            NormalizedEvent(
                event_id=f"x-{i:05d}",
                source_id=SOURCE,
                observed_at=BASE + timedelta(seconds=i),
                event_type=EventType.CONNECTION,
                data_category=DataCategory.LIVE_TELEMETRY,
                schema_version="1.0.0",
                label=("attack" if i % 3 == 0 else None),
                label_provenance=LabelProvenance.UNLABELED,
            )
            for i in range(1100)
        ]
    )
    try:
        breakdown = db.event_breakdown()
        assert breakdown["labels"]["attack"] == db.count_events(label="attack")
        assert sum(breakdown["labels"].values()) == db.count_events()
        assert breakdown["labels"] == db.label_counts()
    finally:
        db.close()
