"""
PraHari — GET /analysis/latest Must Not Write (ADR-062).

Confirmed defect: the GET route called `db.save_analysis()` whenever the
stored analysis was stale. Because `_build_analysis` mints a fresh
`uuid4`, `INSERT OR REPLACE` never replaced anything — every stale GET
appended a row. The live database accumulated 30 analyses, 30 distinct
ids, six of them inside one ten-minute window while the collector ran.

Any client that assumes GET is safe — a browser page load, a prefetch, a
monitoring probe, a `curl` during read-only inspection — silently wrote
to the operational database. It defeated an explicitly read-only
investigation, which is how it was found.

These tests assert at the **storage layer**, by counting rows and by
intercepting writes, not by reading HTTP status codes. A route can return
200 while writing; only a write count proves it did not.

Temporary databases only.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.deps import get_db
from app.api.v1.router import api_v1_router
from app.core.config import AppConfig, get_config
from app.schemas.events import (
    DataCategory,
    EventType,
    LabelProvenance,
    NormalizedEvent,
    TelemetrySource,
)
from app.storage.database import Database

SOURCE = "ro-sensor"
NOW = datetime(2026, 10, 16, 12, 0, 0, tzinfo=timezone.utc)


def _event(idx: int) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=f"ro-{idx}",
        source_id=SOURCE,
        data_category=DataCategory.LIVE_TELEMETRY,
        observed_at=NOW + timedelta(seconds=idx),
        event_type=EventType.NETWORK_FLOW,
        src_ip="192.0.2.10",
        dst_ip="198.51.100.20",
        src_port=40000 + idx,
        dst_port=443,
        protocol="TCP",
        bytes_total=100 + idx,
        label_provenance=LabelProvenance.UNLABELED,
    )


class CountingDatabase(Database):
    """
    Records every call that can persist an analysis.

    Subclassed rather than mocked so the route runs against the real
    storage layer and a write would genuinely happen if the code made
    one.
    """

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.save_analysis_calls = 0

    def save_analysis(self, analysis):  # type: ignore[override]
        self.save_analysis_calls += 1
        return super().save_analysis(analysis)


def _rows(db: Database) -> int:
    with db.get_connection() as conn:
        return conn.execute("SELECT COUNT(*) FROM descriptive_analyses").fetchone()[0]


def _audit_actions(db: Database) -> list[str]:
    with db.get_connection() as conn:
        return [r["action"] for r in conn.execute("SELECT action FROM audit_events")]


@pytest.fixture
def client(tmp_path):
    db = CountingDatabase(db_path=str(tmp_path / "readonly.db"))
    db.initialize()
    db.upsert_source(
        TelemetrySource(source_id=SOURCE, name=SOURCE, source_type="json_stream")
    )
    db.insert_events([_event(i) for i in range(10)])

    app = FastAPI()
    app.include_router(api_v1_router, prefix="/api/v1")
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[get_config] = lambda: AppConfig()
    with TestClient(app) as c:
        yield c, db
    db.close()


# ──────────────────────────────────────────────────────────────────
# The defect: GET must never write
# ──────────────────────────────────────────────────────────────────


def test_get_with_no_stored_analysis_writes_nothing(client):
    c, db = client
    before = _rows(db)

    response = c.get("/api/v1/analysis/latest")

    assert response.status_code == 200
    assert _rows(db) == before == 0, "a GET created an analysis row"
    assert db.save_analysis_calls == 0, "save_analysis was called from a GET"


def test_get_with_a_current_stored_analysis_writes_nothing(client):
    c, db = client
    c.post("/api/v1/analysis/run", json={})          # persist one, legitimately
    before, saves = _rows(db), db.save_analysis_calls

    c.get("/api/v1/analysis/latest")

    assert _rows(db) == before
    assert db.save_analysis_calls == saves


def test_get_with_a_STALE_stored_analysis_writes_nothing(client):
    """The exact branch that caused the live row growth."""
    c, db = client
    c.post("/api/v1/analysis/run", json={})
    before, saves = _rows(db), db.save_analysis_calls

    db.insert_events([_event(i) for i in range(100, 120)])   # now stale

    response = c.get("/api/v1/analysis/latest")

    assert response.status_code == 200
    assert _rows(db) == before, "a stale GET appended an analysis row"
    assert db.save_analysis_calls == saves, "a stale GET called save_analysis"


def test_repeated_gets_do_not_grow_the_table(client):
    """
    Reproduces the live symptom: six rows in ten minutes from routine
    page loads while the collector was running.
    """
    c, db = client
    c.post("/api/v1/analysis/run", json={})
    before = _rows(db)

    for i in range(10):
        db.insert_events([_event(1000 + i)])   # stale again each time
        c.get("/api/v1/analysis/latest")

    assert _rows(db) == before, (
        f"10 GETs grew the table from {before} to {_rows(db)}"
    )


def test_get_writes_nothing_even_with_recompute_disabled(client):
    c, db = client
    c.post("/api/v1/analysis/run", json={})
    db.insert_events([_event(i) for i in range(200, 210)])
    before, saves = _rows(db), db.save_analysis_calls

    c.get("/api/v1/analysis/latest?recompute_if_stale=false")

    assert _rows(db) == before
    assert db.save_analysis_calls == saves


def test_no_get_on_the_whole_analysis_router_writes(client):
    c, db = client
    c.post("/api/v1/analysis/run", json={})
    before, saves = _rows(db), db.save_analysis_calls

    for path in ("/api/v1/analysis/latest", "/api/v1/analysis",
                 f"/api/v1/analysis/latest?source_id={SOURCE}"):
        c.get(path)

    assert _rows(db) == before
    assert db.save_analysis_calls == saves


# ──────────────────────────────────────────────────────────────────
# The response says which it is
# ──────────────────────────────────────────────────────────────────


def test_a_computed_result_is_not_labelled_persisted(client):
    c, db = client

    body = c.get("/api/v1/analysis/latest").json()

    assert body["persisted"] is False, "an unsaved result claimed to be stored"
    assert body["is_current"] is True
    assert _rows(db) == 0


def test_a_stored_current_result_is_labelled_persisted(client):
    c, _ = client
    c.post("/api/v1/analysis/run", json={})

    body = c.get("/api/v1/analysis/latest").json()

    assert body["persisted"] is True
    assert body["is_current"] is True


def test_a_stale_recomputed_result_is_current_but_not_persisted(client):
    c, db = client
    c.post("/api/v1/analysis/run", json={})
    db.insert_events([_event(i) for i in range(300, 305)])

    body = c.get("/api/v1/analysis/latest").json()

    assert body["persisted"] is False
    assert body["is_current"] is True
    assert body["total_events"] == 15, "the fresh result must reflect live counts"


def test_a_stale_snapshot_requested_explicitly_is_flagged_not_current(client):
    c, db = client
    c.post("/api/v1/analysis/run", json={})
    db.insert_events([_event(i) for i in range(400, 405)])

    body = c.get("/api/v1/analysis/latest?recompute_if_stale=false").json()

    assert body["persisted"] is True
    assert body["is_current"] is False, "a stale snapshot was served as current"
    assert body["total_events"] == 10, "the stored snapshot's own total"


def test_an_empty_database_returns_null_without_writing(tmp_path):
    db = CountingDatabase(db_path=str(tmp_path / "empty.db"))
    db.initialize()
    app = FastAPI()
    app.include_router(api_v1_router, prefix="/api/v1")
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[get_config] = lambda: AppConfig()

    with TestClient(app) as c:
        response = c.get("/api/v1/analysis/latest")

    assert response.json() is None
    assert db.save_analysis_calls == 0
    db.close()


# ──────────────────────────────────────────────────────────────────
# POST keeps its job
# ──────────────────────────────────────────────────────────────────


def test_post_persists_exactly_one_record(client):
    c, db = client
    before = _rows(db)

    body = c.post("/api/v1/analysis/run", json={}).json()

    assert _rows(db) == before + 1
    assert db.save_analysis_calls == 1
    assert body["persisted"] is True
    assert body["is_current"] is True


def test_post_still_writes_its_audit_record(client):
    c, db = client

    c.post("/api/v1/analysis/run", json={})

    assert "run_descriptive_analysis" in _audit_actions(db)


def test_a_get_leaves_no_audit_record(client):
    """A read is not an administrative action."""
    c, db = client

    c.get("/api/v1/analysis/latest")

    assert "run_descriptive_analysis" not in _audit_actions(db)


def test_post_remains_the_only_way_to_grow_the_table(client):
    c, db = client

    for _ in range(3):
        c.get("/api/v1/analysis/latest")
    assert _rows(db) == 0

    c.post("/api/v1/analysis/run", json={})
    assert _rows(db) == 1


# ──────────────────────────────────────────────────────────────────
# Earlier guarantees must survive
# ──────────────────────────────────────────────────────────────────


def test_measured_counts_still_distinguish_zero_from_unknown(client):
    """ADR-061 must not be undone by this change."""
    c, db = client

    persisted = c.post("/api/v1/analysis/run", json={}).json()

    assert persisted["bytes_measured_count"] == 10, "all ten carry bytes_total"
    assert persisted["avg_bytes"] is not None

    reloaded = db.get_latest_analysis()
    assert reloaded.bytes_measured_count == 10
    assert reloaded.persisted is True


def test_a_computed_response_still_carries_real_measured_counts(client):
    c, _ = client

    body = c.get("/api/v1/analysis/latest").json()

    assert body["bytes_measured_count"] == 10
    assert body["total_events"] == 10


def test_provenance_is_unchanged_by_the_freshness_fields(client):
    c, _ = client

    body = c.get("/api/v1/analysis/latest").json()

    assert body["data_categories"] == {"live_telemetry": 10}
    assert body["source_id"] == "all_sources"


def test_the_freshness_fields_are_not_persisted_as_columns(client):
    """
    They describe a response, not an analysis. Storing them would store a
    fact about a past request.
    """
    c, db = client
    c.post("/api/v1/analysis/run", json={})

    with db.get_connection() as conn:
        cols = {r["name"] for r in conn.execute("PRAGMA table_info(descriptive_analyses)")}

    assert "persisted" not in cols
    assert "is_current" not in cols
