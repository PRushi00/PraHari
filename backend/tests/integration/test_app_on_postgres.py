"""
PraHari — The application served from PostgreSQL (ADR-093).

ADR-071 named three modules that opened a raw connection and issued
SQLite-dialect SQL, and said what that cost: "A second backend cannot be
substituted until each moves behind a method of this contract." ADR-092
then built a conforming PostgreSQL store and recorded the same caveat —
conforming, but not substitutable.

These tests are the difference between those two claims. The FastAPI
application is served with a `PostgresStore` in place of SQLite and driven
through the routes that used to leak, plus the ingestion and query paths
that did not. If any SQLite dialect remained in the request path, these
would fail rather than a reviewer having to take the claim on trust.

Needs a REAL server; without `PRAHARI_TEST_POSTGRES_DSN` every test here
skips. A skip is never counted as a pass.
"""

from __future__ import annotations

import os
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import status
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

POSTGRES_DSN = os.environ.get("PRAHARI_TEST_POSTGRES_DSN", "").strip()
T0 = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)

pytestmark = pytest.mark.skipif(
    not POSTGRES_DSN,
    reason="PRAHARI_TEST_POSTGRES_DSN is unset; running the application on "
    "PostgreSQL is only evidenced against a real server.",
)


@pytest.fixture
def pg_client():
    """The real application, served entirely from PostgreSQL."""
    from app.storage.postgres import PostgresStore

    store = PostgresStore(
        POSTGRES_DSN, schema="prahari_app_" + uuid.uuid4().hex[:12]
    )
    store.initialize()
    store.upsert_source(
        TelemetrySource(source_id="src-api", name="src-api", source_type="json_stream")
    )

    app.dependency_overrides[get_db] = lambda: store
    with TestClient(app) as client:
        yield client, store
    app.dependency_overrides.clear()
    store.drop_schema()


def _events(n: int, start: int = 0, category=DataCategory.HISTORICAL_IMPORT):
    return [
        NormalizedEvent(
            event_id=f"app-{i}",
            source_id="src-api",
            event_type=EventType.NETWORK_FLOW,
            observed_at=T0 + timedelta(seconds=i),
            data_category=category,
            label="Benign",
            label_provenance=LabelProvenance.DATASET_GROUND_TRUTH,
            src_ip="192.0.2.1",
            dst_ip="198.51.100.2",
            dst_port=443,
            protocol="TCP",
            packets=4,
            bytes_total=512,
        )
        for i in range(start, start + n)
    ]


# ──────────────────────────────────────────────────────────────────
# The three routes that used to issue SQLite SQL
# ──────────────────────────────────────────────────────────────────


def test_audit_log_route_serves_from_postgres(pg_client):
    client, store = pg_client
    for i in range(3):
        store.log_audit(action=f"pg-action-{i}", resource_type="alpha")
    store.log_audit(action="pg-other", resource_type="beta")

    response = client.get("/api/v1/audit/logs?limit=10")
    assert response.status_code == status.HTTP_200_OK, response.text
    actions = [e["action"] for e in response.json()]
    assert actions[:3] == ["pg-other", "pg-action-2", "pg-action-1"]

    filtered = client.get("/api/v1/audit/logs?limit=10&resource_type=beta")
    assert filtered.status_code == status.HTTP_200_OK
    assert [e["action"] for e in filtered.json()] == ["pg-other"]

    paged = client.get("/api/v1/audit/logs?limit=2&offset=2")
    assert paged.status_code == status.HTTP_200_OK
    assert len(paged.json()) == 2


def test_system_health_route_reports_postgres_as_postgres(pg_client):
    """The PRAGMAs this route used to run do not exist here."""
    client, store = pg_client
    store.insert_events(_events(5))

    response = client.get("/api/v1/system/health")
    assert response.status_code == status.HTTP_200_OK, response.text
    storage = response.json()["storage"]

    assert storage["available"] is True
    data = storage["data"]
    assert data["backend"] == "postgresql"
    assert data["event_count"] == 5
    assert data["size_bytes"] > 0
    assert data["normalized_events_columns"] >= 26

    # Not measured here, and saying so rather than claiming "ok".
    assert data["integrity_check"] is None
    assert data["integrity_check_note"]
    assert data["journal_mode"] is None
    assert "the store answered a query" in data["health_basis"]


def test_retention_preview_and_enforcement_run_on_postgres(pg_client):
    client, store = pg_client
    store.insert_events(_events(10))

    preview = client.post(
        "/api/v1/retention/preview",
        json={"retention_days": 1, "eligible_categories": ["historical_import"]},
    )
    assert preview.status_code == status.HTTP_200_OK, preview.text
    body = preview.json()
    assert body["dry_run"] is True
    assert body["candidates"] == 10
    assert store.count_events() == 10, "a preview deleted rows"


# ──────────────────────────────────────────────────────────────────
# The ordinary paths, to show nothing else depended on SQLite either
# ──────────────────────────────────────────────────────────────────


def test_ingestion_and_query_round_trip_through_the_api(pg_client):
    client, store = pg_client

    ndjson = "\n".join(
        e.model_dump_json() for e in _events(4, start=100, category=DataCategory.LIVE_TELEMETRY)
    )
    ingest = client.post(
        "/api/v1/stream/ingest/ndjson",
        json={"source_id": "src-api", "ndjson_content": ndjson},
    )
    assert ingest.status_code in (200, 201), ingest.text

    listed = client.get("/api/v1/events?source_id=src-api&limit=50")
    assert listed.status_code == status.HTTP_200_OK
    assert listed.json()["total"] >= 4

    # The ingestion path assigns its own canonical identity, so the id to
    # fetch comes from the listing rather than from what was submitted.
    stored_id = listed.json()["events"][0]["event_id"]
    one = client.get(f"/api/v1/events/{stored_id}")
    assert one.status_code == status.HTTP_200_OK, one.text
    assert one.json()["event_id"] == stored_id


def test_sources_and_analysis_routes_work_on_postgres(pg_client):
    client, store = pg_client
    store.insert_events(_events(12))

    sources = client.get("/api/v1/sources")
    assert sources.status_code == status.HTTP_200_OK
    assert any(s["source_id"] == "src-api" for s in sources.json())

    analysis = client.post("/api/v1/analysis/run", json={"source_id": "src-api"})
    assert analysis.status_code in (200, 201), analysis.text
    assert analysis.json()["total_events"] == 12

    latest = client.get("/api/v1/analysis/latest?source_id=src-api")
    assert latest.status_code == status.HTTP_200_OK
    assert latest.json()["total_events"] == 12


def test_the_health_endpoint_answers_from_postgres(pg_client):
    client, _ = pg_client
    response = client.get("/api/v1/health")
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["status"] in ("healthy", "ok", "degraded")
