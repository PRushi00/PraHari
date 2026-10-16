"""
Tests for retention enforcement (blueprint §12, DoD item 11).

Every test uses an isolated temporary database. The operator's telemetry
store is never opened — see the final test in this module.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app.api.deps import get_db
from app.core.config import AppConfig, get_config
from app.main import app
from app.schemas.events import (
    DataCategory,
    EventType,
    LabelProvenance,
    NormalizedEvent,
    TelemetrySource,
)
from app.services.retention import (
    DEFAULT_ELIGIBLE_CATEGORIES,
    RetentionPolicy,
    RetentionService,
)
from app.storage.database import Database

NOW = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)


def _event(age_days: float, category=DataCategory.LIVE_TELEMETRY, source="win", idx=0):
    return NormalizedEvent(
        event_id=f"{category.value}-{age_days}-{idx}",
        source_id=source,
        data_category=category,
        observed_at=NOW - timedelta(days=age_days),
        event_type=EventType.CONNECTION,
        src_ip="192.0.2.10",
        dst_ip="198.51.100.9",
        src_port=40000 + idx,
        dst_port=443,
        protocol="TCP",
        label_provenance=LabelProvenance.UNLABELED,
    )


@pytest.fixture
def db(tmp_path):
    database = Database(db_path=str(tmp_path / "retention.db"))
    database.initialize()
    for sid, stype in (
        ("win", "windows_connection_table"),
        ("csv", "csv_import"),
        ("synth", "synthetic_replay"),
    ):
        database.upsert_source(
            TelemetrySource(source_id=sid, name=sid, source_type=stype)
        )
    yield database
    database.close()


# ──────────────────────────────────────────────────────────────────
# Age boundaries
# ──────────────────────────────────────────────────────────────────


def test_only_events_older_than_the_cutoff_are_eligible(db):
    db.insert_events([
        _event(40, idx=1),   # older than 30 days -> eligible
        _event(31, idx=2),   # eligible
        _event(29, idx=3),   # retained
        _event(0.5, idx=4),  # retained
    ])
    svc = RetentionService(db)
    result = svc.preview(RetentionPolicy(retention_days=30), now=NOW)

    assert result.candidates == 2
    assert result.retained_newer_than_cutoff == 2
    assert result.dry_run is True
    assert db.count_events() == 4, "preview must not delete"


def test_event_exactly_at_the_boundary_is_retained(db):
    """Strictly older than the cutoff. Equality is retained."""
    db.insert_events([_event(30, idx=1)])
    result = RetentionService(db).preview(RetentionPolicy(retention_days=30), now=NOW)
    assert result.candidates == 0


def test_cutoff_is_computed_in_utc_regardless_of_input_timezone(db):
    """A local-time reference must not shift the boundary."""
    policy = RetentionPolicy(retention_days=30)
    utc_cutoff = policy.cutoff(NOW)

    from datetime import timezone as tz
    ist = tz(timedelta(hours=5, minutes=30))
    same_moment_local = NOW.astimezone(ist)

    assert policy.cutoff(same_moment_local) == utc_cutoff
    assert utc_cutoff.tzinfo == timezone.utc


def test_age_uses_observed_at_not_ingestion_time(db):
    """
    Old telemetry imported recently must still be eligible; using
    ingested_at would protect it forever.
    """
    old = _event(100, idx=1)
    old.ingested_at = NOW  # ingested just now
    db.insert_events([old])

    result = RetentionService(db).preview(RetentionPolicy(retention_days=30), now=NOW)
    assert result.candidates == 1


# ──────────────────────────────────────────────────────────────────
# Scope
# ──────────────────────────────────────────────────────────────────


def test_categories_outside_the_policy_are_never_touched(db):
    db.insert_events([
        _event(60, DataCategory.LIVE_TELEMETRY, "win", 1),
        _event(60, DataCategory.HISTORICAL_IMPORT, "csv", 2),
        _event(60, DataCategory.TEST_FIXTURE, "csv", 3),
    ])
    svc = RetentionService(db)
    result = svc.enforce(RetentionPolicy(retention_days=30), now=NOW)

    assert result.deleted == 1  # live only
    assert db.count_events(data_category="historical_import") == 1
    assert db.count_events(data_category="test_fixture") == 1
    assert "historical_import" in result.protected_categories
    assert "test_fixture" in result.protected_categories


def test_pruning_can_be_scoped_to_one_source(db):
    db.insert_events([
        _event(60, DataCategory.LIVE_TELEMETRY, "win", 1),
        _event(60, DataCategory.SYNTHETIC_DEMO, "synth", 2),
    ])
    result = RetentionService(db).enforce(
        RetentionPolicy(retention_days=30, source_id="win"), now=NOW
    )
    assert result.deleted == 1
    assert db.count_events(source_id="synth") == 1


def test_empty_category_list_is_rejected_as_ambiguous(db):
    with pytest.raises(ValueError) as exc:
        RetentionService(db).preview(
            RetentionPolicy(retention_days=30, eligible_categories=[]), now=NOW
        )
    assert "at least one eligible category" in str(exc.value)


def test_sources_summaries_and_audit_records_are_never_pruned(db):
    db.insert_events([_event(60, idx=i) for i in range(5)])
    db.log_audit(action="something_old", resource_type="x", resource_id="y")

    before_sources = len(db.list_sources())
    with db.get_connection() as conn:
        before_audit = conn.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0]

    RetentionService(db).enforce(RetentionPolicy(retention_days=30), now=NOW)

    assert len(db.list_sources()) == before_sources
    with db.get_connection() as conn:
        after_audit = conn.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0]
    # Audit grows (the run is logged); it never shrinks.
    assert after_audit > before_audit


# ──────────────────────────────────────────────────────────────────
# Batching, limits, interruption
# ──────────────────────────────────────────────────────────────────


def test_deletion_is_batched(db):
    db.insert_events([_event(60, idx=i) for i in range(25)])
    result = RetentionService(db).enforce(
        RetentionPolicy(retention_days=30, batch_size=10), now=NOW
    )
    assert result.deleted == 25
    assert result.batches == 3  # 10 + 10 + 5
    assert db.count_events() == 0


def test_max_deletions_caps_a_single_run(db):
    db.insert_events([_event(60, idx=i) for i in range(50)])
    result = RetentionService(db).enforce(
        RetentionPolicy(retention_days=30, batch_size=10, max_deletions=25), now=NOW
    )
    assert result.deleted == 25
    assert result.reached_max_deletions is True
    assert db.count_events() == 25
    assert any("ceiling" in n for n in result.notes)


def test_interrupted_run_leaves_a_consistent_database(db, monkeypatch):
    """
    Each batch commits independently, so a failure mid-run loses no
    integrity: completed batches are durable, the rest remain.
    """
    db.insert_events([_event(60, idx=i) for i in range(30)])
    svc = RetentionService(db)

    real_conn = db.get_connection
    state = {"batches": 0}

    def _failing_conn():
        # Fail on the third acquisition used for deleting.
        state["batches"] += 1
        if state["batches"] == 5:
            raise RuntimeError("simulated interruption")
        return real_conn()

    monkeypatch.setattr(db, "get_connection", _failing_conn)
    with pytest.raises(RuntimeError):
        svc.enforce(RetentionPolicy(retention_days=30, batch_size=10), now=NOW)

    monkeypatch.setattr(db, "get_connection", real_conn)
    remaining = db.count_events()
    # Some batches committed, the database is readable, nothing is corrupt.
    assert 0 <= remaining <= 30
    assert remaining % 10 == 0, "partial batches must not be left half-deleted"


def test_resuming_after_an_interruption_completes_the_work(db):
    db.insert_events([_event(60, idx=i) for i in range(30)])
    svc = RetentionService(db)
    svc.enforce(RetentionPolicy(retention_days=30, batch_size=10, max_deletions=10), now=NOW)
    assert db.count_events() == 20
    svc.enforce(RetentionPolicy(retention_days=30, batch_size=10), now=NOW)
    assert db.count_events() == 0


def test_source_counters_are_refreshed_after_pruning(db):
    db.insert_events([_event(60, idx=i) for i in range(10)])
    db.refresh_source_activity("win")
    assert db.get_source("win").event_count == 10

    RetentionService(db).enforce(RetentionPolicy(retention_days=30), now=NOW)
    assert db.get_source("win").event_count == 0, (
        "counters must not report rows that no longer exist"
    )


# ──────────────────────────────────────────────────────────────────
# Auditability
# ──────────────────────────────────────────────────────────────────


def test_enforcement_is_audited_and_preview_is_not(db):
    db.insert_events([_event(60, idx=i) for i in range(3)])
    svc = RetentionService(db)

    svc.preview(RetentionPolicy(retention_days=30), now=NOW)
    with db.get_connection() as conn:
        actions = [r["action"] for r in conn.execute("SELECT action FROM audit_events")]
    assert "enforce_retention" not in actions, "a dry run must not log a deletion"

    svc.enforce(RetentionPolicy(retention_days=30), now=NOW)
    with db.get_connection() as conn:
        rows = [dict(r) for r in conn.execute("SELECT * FROM audit_events")]
    entry = next(r for r in rows if r["action"] == "enforce_retention")
    assert "Deleted 3 event(s)" in entry["details"]
    assert "retention_days=30" in entry["details"]


# ──────────────────────────────────────────────────────────────────
# API surface
# ──────────────────────────────────────────────────────────────────


@pytest.fixture
def client(db, tmp_path):
    cfg = AppConfig(
        retention_days=30, database_url=f"sqlite:///{tmp_path / 'retention.db'}"
    )
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[get_config] = lambda: cfg
    with TestClient(app) as c:
        yield c, db
    app.dependency_overrides.clear()


def test_policy_endpoint_states_that_pruning_is_manual(client):
    c, _ = client
    body = c.get("/api/v1/retention/policy").json()
    assert body["automatic_pruning"] is False
    assert body["enforcement"] == "manual"
    assert body["confirmation_required"] is True
    assert any("observed_at" in n for n in body["notes"])


def test_preview_endpoint_deletes_nothing(client):
    c, db = client
    db.insert_events([_event(60, idx=i) for i in range(4)])
    body = c.post("/api/v1/retention/preview", json={}).json()
    assert body["dry_run"] is True
    assert body["candidates"] == 4
    assert db.count_events() == 4


def test_enforce_without_the_confirmation_token_is_refused(client):
    c, db = client
    db.insert_events([_event(60, idx=i) for i in range(4)])

    for bad in ({}, {"confirm": "yes"}, {"confirm": "true"}, {"confirm": ""}):
        res = c.post("/api/v1/retention/enforce", json=bad)
        assert res.status_code in (400, 422), f"{bad} was accepted"
    assert db.count_events() == 4, "nothing may be deleted without confirmation"


def test_enforce_with_the_confirmation_token_prunes(client):
    c, db = client
    # The API path uses the real clock, so "recent" must be recent NOW —
    # not relative to this module's fixed reference instant.
    recent = _event(0, idx=99)
    recent.observed_at = datetime.now(timezone.utc)
    recent.event_id = "recent-survivor"
    db.insert_events([_event(60, idx=i) for i in range(4)] + [recent])

    res = c.post(
        "/api/v1/retention/enforce",
        json={"confirm": "DELETE-EXPIRED-TELEMETRY"},
    )
    assert res.status_code == 200, res.json()
    body = res.json()
    assert body["dry_run"] is False
    assert body["deleted"] == 4
    assert db.count_events() == 1  # the recent event survives


def test_nothing_prunes_automatically_on_startup(db, tmp_path):
    """
    Starting the application must never delete telemetry. A retention bug
    that fires at startup would be catastrophic and silent.
    """
    db.insert_events([_event(9999, idx=i) for i in range(5)])
    cfg = AppConfig(retention_days=1, database_url=f"sqlite:///{tmp_path / 'r.db'}")
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[get_config] = lambda: cfg
    try:
        with TestClient(app) as c:
            c.get("/api/v1/health")
        assert db.count_events() == 5, "startup must not prune"
    finally:
        app.dependency_overrides.clear()


def test_retention_tests_never_touch_the_operational_database():
    """
    The suite must never open the operator's live telemetry store.

    Checks the property that matters — the resolved path is not the
    repository's prahari.db — rather than looking for "tmp" in the string.
    The substring form failed on Linux purely because the throwaway
    database sat under $HOME, which is isolation by any reasonable reading.
    """
    import os
    from pathlib import Path

    from app.core.config import get_config

    url = os.environ.get("PRAHARI_DATABASE_URL", "")
    assert url, "tests must pin an isolated database URL"

    resolved = Path(str(get_config().get_database_path())).resolve()
    operational = (Path(__file__).resolve().parents[3] / "prahari.db").resolve()
    legacy = (Path(__file__).resolve().parents[2] / "prahari.db").resolve()

    assert resolved != operational, (
        f"tests resolved to the OPERATIONAL database at {resolved}"
    )
    assert resolved != legacy, (
        f"tests resolved to the legacy backend database at {resolved}"
    )
    assert resolved.name != "prahari.db", (
        f"tests resolved to a file named prahari.db ({resolved}); name the "
        "throwaway database distinctly so this guard cannot be fooled"
    )

