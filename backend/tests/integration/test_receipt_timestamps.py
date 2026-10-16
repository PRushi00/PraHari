"""
Server-receipt timestamps: capture, isolation, migration, compatibility.

`received_at` is stamped by the backend at the API boundary when a remote
source submits. Every test here guards one of four properties:

* it is captured only where a genuine submission occurred;
* it is never supplied or influenced by the client;
* absence means "not measured" and is never backfilled or inferred;
* a retry does not overwrite the original receipt.

All databases are temporary. Documentation addresses only (RFC 5737).
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app.api.deps import get_db
from app.main import app
from app.schemas.events import (
    DataCategory,
    EventType,
    LabelProvenance,
    NormalizedEvent,
    TelemetrySource,
)
from app.services.source_health import HealthState, evaluate_source_health
from app.storage.database import Database

NOW = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)


@pytest.fixture
def db(tmp_path):
    database = Database(db_path=str(tmp_path / "receipt.db"))
    database.initialize()
    yield database
    database.close()


@pytest.fixture
def client(db):
    app.dependency_overrides[get_db] = lambda: db
    with TestClient(app) as c:
        yield c, db
    app.dependency_overrides.clear()


def _ndjson(count=3, base_offset=0):
    rows = []
    for i in range(count):
        rows.append(json.dumps({
            "ts": 1700000000.0 + base_offset + i,
            "id.orig_h": "192.0.2.10", "id.resp_h": "198.51.100.20",
            "id.orig_p": 40000 + i, "id.resp_p": 443, "proto": "tcp",
            "orig_bytes": 100, "resp_bytes": 200, "duration": 0.5,
        }))
    return "\n".join(rows) + "\n"


# ──────────────────────────────────────────────────────────────────
# Capture at genuine submission boundaries
# ──────────────────────────────────────────────────────────────────


def test_a_remote_submission_records_a_server_receipt(client):
    c, database = client
    before = datetime.now(timezone.utc)

    res = c.post("/api/v1/stream/ingest/ndjson", json={
        "source_id": "sensor-01", "ndjson_content": _ndjson(5),
        "data_category": "historical_import",
    })
    after = datetime.now(timezone.utc)
    assert res.status_code == 200, res.text

    stored = database.list_events(source_id="sensor-01", limit=10)
    assert len(stored) == 5
    for event in stored:
        assert event.received_at is not None, "a submission must record a receipt"
        assert before <= event.received_at <= after
        # The source's own event time is untouched and far older.
        assert event.observed_at < before


def test_every_event_in_one_batch_shares_the_boundary_receipt(client):
    """One arrival, one receipt — not a per-row clock read during parsing."""
    c, database = client
    c.post("/api/v1/stream/ingest/ndjson", json={
        "source_id": "sensor-01", "ndjson_content": _ndjson(20),
    })
    receipts = {e.received_at for e in database.list_events(source_id="sensor-01", limit=50)}
    assert len(receipts) == 1


def test_the_client_cannot_supply_or_influence_the_receipt(client):
    """
    An attacker-controlled receipt would let a source backdate its own
    arrival. The request model has no such field, and an attempt to inject
    one must be ignored rather than honoured.
    """
    c, database = client
    forged = (NOW - timedelta(days=365)).isoformat()

    res = c.post("/api/v1/stream/ingest/ndjson", json={
        "source_id": "sensor-01", "ndjson_content": _ndjson(3),
        "received_at": forged,
        "server_received_at": forged,
    })
    assert res.status_code == 200, res.text

    for event in database.list_events(source_id="sensor-01", limit=10):
        assert event.received_at is not None
        assert event.received_at.year >= 2026, "a client-supplied receipt was honoured"


def test_a_retry_never_rewrites_an_existing_receipt(client):
    """
    An already-stored event keeps its ORIGINAL receipt. `INSERT OR IGNORE`
    means a re-delivered row is not updated, so the first arrival remains
    the recorded one.

    Note what this does NOT assert. The NDJSON adapter assigns
    `uuid.uuid4()` per row (`adapters/json_stream.py`), so a retried
    submission is stored as NEW events rather than being recognised as a
    repeat — see `test_the_stream_path_is_not_idempotent_on_retry` below.
    This test covers the receipts that already existed.
    """
    c, database = client
    payload = {"source_id": "sensor-01", "ndjson_content": _ndjson(4)}

    c.post("/api/v1/stream/ingest/ndjson", json=payload)
    first = {
        e.event_id: e.received_at
        for e in database.list_events(source_id="sensor-01", limit=50)
    }
    assert len(first) == 4

    c.post("/api/v1/stream/ingest/ndjson", json=payload)
    after = {
        e.event_id: e.received_at
        for e in database.list_events(source_id="sensor-01", limit=50)
    }

    for event_id, receipt in first.items():
        assert after[event_id] == receipt, "an existing receipt was rewritten"


def test_the_stream_path_is_not_idempotent_on_retry(client):
    """
    Legacy behaviour, preserved deliberately. This payload carries no
    identity metadata — no `uid`, `event_id`, `uuid` or `record_id`, and
    no batch idempotency key — so the adapter still assigns a fresh
    `uuid.uuid4()` per row and a retry double-counts.

    Phase 3 (ADR-050) did NOT change that. It added a protocol a sender
    can opt into; it could not retrofit identity onto a sender that
    supplies none, because the only remaining basis would be content
    equality, which would collapse genuinely distinct events that happen
    to look alike. A legacy sensor retrying after a timeout therefore
    still double-counts its own telemetry, and that is the standing
    reason to move senders onto the identity protocol.
    """
    c, database = client
    payload = {"source_id": "sensor-01", "ndjson_content": _ndjson(4)}

    c.post("/api/v1/stream/ingest/ndjson", json=payload)
    c.post("/api/v1/stream/ingest/ndjson", json=payload)

    stored = database.list_events(source_id="sensor-01", limit=50)
    assert len(stored) == 8, (
        "expected duplication; if this now fails the path became idempotent "
        "and the finding should be closed"
    )
    # Each delivery carries its own receipt, which is correct: they are
    # genuinely two separate arrivals as far as this backend can tell.
    assert len({e.received_at for e in stored}) == 2


# ──────────────────────────────────────────────────────────────────
# Paths that must NOT record a receipt
# ──────────────────────────────────────────────────────────────────


def test_a_historical_csv_import_records_no_receipt(client):
    """
    The file arrived now; the events did not. Stamping them would assert an
    arrival time that was never observed.
    """
    c, database = client
    csv_text = (
        "Timestamp,Src IP,Dst IP,Src Port,Dst Port,Protocol,Flow Duration,"
        "Tot Fwd Pkts,TotLen Fwd Pkts,Label\n"
        "2018-02-14 10:32:00,192.0.2.10,198.51.100.20,40000,443,6,2500000,10,1000,Benign\n"
    )
    res = c.post("/api/v1/import/csv/raw", json={
        "source_id": "corpus", "csv_content": csv_text,
        "data_category": "test_fixture",
    })
    assert res.status_code == 200, res.text

    stored = database.list_events(source_id="corpus", limit=10)
    assert stored
    assert all(e.received_at is None for e in stored)


def test_synthetic_replay_records_no_receipt(client):
    c, database = client
    res = c.post("/api/v1/stream/replay/synthetic", json={
        "source_id": "synthetic", "count": 20, "attack_ratio": 0.2,
    })
    assert res.status_code == 200, res.text
    stored = database.list_events(source_id="synthetic", limit=50)
    assert stored
    assert all(e.received_at is None for e in stored), (
        "generated events were never received from anywhere"
    )


# ──────────────────────────────────────────────────────────────────
# Absence, migration and backward compatibility
# ──────────────────────────────────────────────────────────────────


def test_absence_is_preserved_and_never_backfilled(db):
    event = NormalizedEvent(
        event_id="legacy-1", source_id="old", data_category=DataCategory.LIVE_TELEMETRY,
        observed_at=NOW, event_type=EventType.CONNECTION,
        src_ip="192.0.2.1", dst_ip="198.51.100.1", src_port=40000, dst_port=443,
        protocol="TCP", label_provenance=LabelProvenance.UNLABELED,
    )
    assert event.received_at is None

    db.upsert_source(TelemetrySource(source_id="old", name="old", source_type="csv_import"))
    db.insert_events([event])

    stored = db.list_events(source_id="old", limit=5)[0]
    assert stored.received_at is None, "absence must survive a round trip"


def test_a_pre_migration_database_gains_a_nullable_column(tmp_path):
    """
    An existing file is migrated additively. Rows written before the column
    existed keep NULL — "not measured" — rather than a fabricated value.
    """
    path = tmp_path / "legacy.db"

    # Build a database from the REAL schema with only the new column
    # removed, so the indexes and constraints match a genuine older file.
    from app.storage.database import TABLES_DDL

    legacy_ddl = chr(10).join(
        line for line in TABLES_DDL.splitlines()
        if "received_at" not in line and not line.strip().startswith("-- Nullable")
        and "written before this column" not in line
        and "correct for locally collected" not in line
    )
    raw = sqlite3.connect(str(path))
    raw.executescript(legacy_ddl)
    raw.execute(
        """INSERT INTO normalized_events
           (event_id, schema_version, source_id, data_category,
            observed_at, ingested_at, event_type)
           VALUES (?,?,?,?,?,?,?)""",
        ("old-1", "1.0.0", "old", "live_telemetry",
         NOW.isoformat(), NOW.isoformat(), "connection"),
    )
    raw.commit()
    columns_before = {r[1] for r in raw.execute("PRAGMA table_info(normalized_events)")}
    raw.close()
    assert "received_at" not in columns_before

    database = Database(db_path=str(path))
    database.initialize()
    try:
        with database.get_connection() as conn:
            columns_after = {
                r["name"] for r in conn.execute("PRAGMA table_info(normalized_events)")
            }
            value = conn.execute(
                "SELECT received_at FROM normalized_events WHERE event_id='old-1'"
            ).fetchone()["received_at"]

        assert "received_at" in columns_after, "the migration did not run"
        assert value is None, "an existing row was given a fabricated receipt"
    finally:
        database.close()


def test_the_event_api_response_still_carries_its_existing_fields(client):
    """Additive change: existing clients must not break."""
    c, database = client
    c.post("/api/v1/stream/ingest/ndjson", json={
        "source_id": "sensor-01", "ndjson_content": _ndjson(2),
    })

    body = c.get("/api/v1/events?source_id=sensor-01&limit=5").json()
    assert body["total"] == 2
    event = body["events"][0]
    for field in ("event_id", "source_id", "observed_at", "ingested_at",
                  "event_type", "data_category", "label_provenance"):
        assert field in event, f"existing field {field} disappeared"
    assert "received_at" in event


# ──────────────────────────────────────────────────────────────────
# Diagnostics driven by the new evidence
# ──────────────────────────────────────────────────────────────────


def test_clock_integrity_uses_the_measured_receipt_end_to_end(client):
    c, _ = client
    c.post("/api/v1/stream/ingest/ndjson", json={
        "source_id": "sensor-01", "ndjson_content": _ndjson(40),
    })

    reports = c.get("/api/v1/sources/clock-integrity?source_id=sensor-01").json()
    assert reports
    report = reports[0]
    assert report["lag_reference"] == "received_at"
    assert report["samples_with_received_at"] == 40
    assert report["samples_without_received_at"] == 0
    # The corpus timestamps are from 2023, received now: a huge positive lag
    # that supports no skew claim.
    assert report["lag_median_seconds"] > 0
    assert report["clock_ahead_lower_bound_seconds"] is None


def test_health_prefers_a_measured_receipt_over_a_skewed_event_time():
    """
    The failure receipt evidence exists to prevent: a source whose clock
    runs fast looks fresh on event time while the backend has not heard
    from it in days.
    """
    source = TelemetrySource(
        source_id="fast-clock", name="fast", source_type="windows_connection_table",
        last_event_at=NOW - timedelta(seconds=5),   # claims to be fresh
        event_count=100,
    )

    on_event_time = evaluate_source_health(source, now=NOW)
    assert on_event_time.state is HealthState.REPORTING
    assert on_event_time.clock_dependent is True

    on_receipt = evaluate_source_health(
        source, now=NOW, last_received_at=NOW - timedelta(days=3)
    )
    assert on_receipt.state is HealthState.SILENT, (
        "a measured receipt must override a source's own optimistic clock"
    )
    assert on_receipt.clock_dependent is False
    assert on_receipt.receipt_evidence_available is True
    assert on_receipt.seconds_since_last_event == 5.0  # still reported
    assert any("currently connected" in lim for lim in on_receipt.limitations)


def test_health_endpoint_reports_receipt_evidence(client):
    c, database = client
    c.post("/api/v1/stream/ingest/ndjson", json={
        "source_id": "sensor-01", "ndjson_content": _ndjson(5),
    })

    body = c.get("/api/v1/sources/health").json()
    entry = [s for s in body["sources"] if s["source_id"] == "sensor-01"][0]

    assert entry["receipt_evidence_available"] is True
    assert entry["clock_dependent"] is False
    assert "measured by this backend" in entry["freshness_basis"]
    assert entry["state"] == "reporting"


def test_a_source_without_receipts_falls_back_and_says_so(client):
    c, database = client
    database.upsert_source(TelemetrySource(
        source_id="local", name="local", source_type="windows_connection_table",
        last_event_at=datetime.now(timezone.utc) - timedelta(seconds=30),
    ))

    body = c.get("/api/v1/sources/health").json()
    entry = [s for s in body["sources"] if s["source_id"] == "local"][0]

    assert entry["receipt_evidence_available"] is False
    assert entry["clock_dependent"] is True
    assert any("No measured receipt" in lim for lim in entry["limitations"])
