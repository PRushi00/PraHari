"""
PraHari — External Ingestion Cannot Write Into a Local Producer's Source (ADR-090).

Found by the independent review of `windows-closure` and confirmed: once
the live collector existed, `POST /stream/ingest/ndjson` with
`source_id="windows_local_host"` returned **HTTP 500**. The stream path's
`get_or_register` handed back the collector's connection-table adapter,
which has no NDJSON importer.

The 500 was the visible half. Synthetic replay and CSV import accepted the
same source id and wrote into the host collector's live source, mixing
synthetic or imported records into the local host's provenance. Because
the collector is created lazily - on the dashboard's first status poll -
whether this happened depended on whether anyone had opened the dashboard
since the last restart.

Platform-neutral. Temporary databases only; the collector is constructed
with an injected query and never polls the operating system.
"""

from __future__ import annotations

import json

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.adapters.base import get_adapter_registry
from app.adapters.windows_telemetry import WindowsConnectionAdapter
from app.api.auth import CentralAuthMiddleware
from app.api.deps import get_db
from app.api.v1.hostobs import UDP_SOURCE_ID
from app.api.v1.router import api_v1_router
from app.core.config import AppConfig, DeploymentMode, get_config
from app.core.security import Credential, CredentialStore, Role
from app.services.collector import DEFAULT_SOURCE_ID, WindowsTelemetryCollectorService
from app.storage.database import Database

LINE = json.dumps({"event_id": "ext-1", "timestamp": "2026-06-01T12:00:00Z",
                   "src_ip": "192.0.2.10", "dst_ip": "198.51.100.20",
                   "src_port": 40001, "dst_port": 443, "proto": "tcp"}) + "\n"
CSV = ("Timestamp,Src IP,Dst IP,Src Port,Dst Port,Protocol,Label\n"
       "2026-06-01T12:00:00Z,192.0.2.10,198.51.100.20,40001,443,6,Benign\n")


def _no_os(*_a, **_k):
    return []


@pytest.fixture
def db(tmp_path):
    database = Database(db_path=str(tmp_path / "reserved.db"))
    database.initialize()
    yield database
    database.close()


@pytest.fixture
def client(db):
    app = FastAPI()
    app.include_router(api_v1_router, prefix="/api/v1")
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[get_config] = lambda: AppConfig()
    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture
def no_collector_registered():
    """The state after a restart, before the dashboard creates the collector."""
    registry = get_adapter_registry()
    saved = {k: registry._adapters.pop(k) for k in (DEFAULT_SOURCE_ID, UDP_SOURCE_ID)
             if k in registry._adapters}
    yield
    registry._adapters.update(saved)


def _stream(client, source_id):
    return client.post("/api/v1/stream/ingest/ndjson", json={
        "source_id": source_id, "ndjson_content": LINE, "data_category": "live_telemetry"})


def _refused(response, source_id):
    assert response.status_code == 403, response.text
    detail = response.json()["detail"]
    assert detail["error"] == "source_reserved_for_local_producer"
    assert detail["source_id"] == source_id


# ──────────────────────────────────────────────────────────────────
# The reported defect
# ──────────────────────────────────────────────────────────────────


def test_the_reported_500_is_gone(client, db):
    WindowsTelemetryCollectorService(db=db, query_fn=_no_os)  # registers its adapter

    r = _stream(client, DEFAULT_SOURCE_ID)

    assert r.status_code != 500
    _refused(r, DEFAULT_SOURCE_ID)
    assert db.count_events() == 0


def test_the_collectors_adapter_is_left_in_place(client, db):
    collector = WindowsTelemetryCollectorService(db=db, query_fn=_no_os)

    _stream(client, DEFAULT_SOURCE_ID)

    assert get_adapter_registry().get(DEFAULT_SOURCE_ID) is collector.adapter
    assert isinstance(collector.adapter, WindowsConnectionAdapter)


# ──────────────────────────────────────────────────────────────────
# Independent of what has run since the last restart
# ──────────────────────────────────────────────────────────────────


def test_the_host_source_is_refused_before_the_collector_exists(client, db, no_collector_registered):
    r = _stream(client, DEFAULT_SOURCE_ID)

    _refused(r, DEFAULT_SOURCE_ID)
    assert db.count_events() == 0
    assert db.get_source(DEFAULT_SOURCE_ID) is None, "no source may be auto-registered for it"
    assert get_adapter_registry().get(DEFAULT_SOURCE_ID) is None, (
        "a stream adapter registered here would later be replaced by the collector's"
    )


def test_the_udp_observer_source_is_refused(client, db, no_collector_registered):
    _refused(_stream(client, UDP_SOURCE_ID), UDP_SOURCE_ID)
    assert db.count_events() == 0


def test_a_collector_under_a_custom_id_owns_that_id_while_it_exists(client, db):
    custom = "lab-host-collector"
    WindowsTelemetryCollectorService(db=db, source_id=custom, query_fn=_no_os)

    _refused(_stream(client, custom), custom)


# ──────────────────────────────────────────────────────────────────
# Every external write path, not only the stream
# ──────────────────────────────────────────────────────────────────


def test_synthetic_replay_cannot_fill_the_live_host_source(client, db, no_collector_registered):
    r = client.post("/api/v1/stream/replay/synthetic",
                    json={"source_id": DEFAULT_SOURCE_ID, "count": 20})

    _refused(r, DEFAULT_SOURCE_ID)
    assert db.count_events() == 0, "synthetic records would have entered live host provenance"


def test_csv_import_cannot_fill_the_live_host_source(client, db, no_collector_registered):
    r = client.post("/api/v1/import/csv/raw",
                    json={"source_id": DEFAULT_SOURCE_ID, "csv_content": CSV})

    _refused(r, DEFAULT_SOURCE_ID)
    assert db.count_events() == 0


# ──────────────────────────────────────────────────────────────────
# Nothing legitimate is refused
# ──────────────────────────────────────────────────────────────────


def test_an_ordinary_source_still_ingests(client, db):
    WindowsTelemetryCollectorService(db=db, query_fn=_no_os)

    r = _stream(client, "sensor-a")

    assert r.status_code == 200, r.text
    assert r.json()["stored_records"] == 1


def test_a_source_merely_named_like_a_type_is_not_reserved(client, db):
    """Only the producers' own ids are reserved, not every id that looks similar."""
    for source_id in ("windows_local_host_2", "remote-windows-host"):
        assert _stream(client, source_id).status_code == 200


# ──────────────────────────────────────────────────────────────────
# Central mode: identity first, then ownership
# ──────────────────────────────────────────────────────────────────


def test_an_admin_cannot_ingest_on_behalf_of_the_host_collector(db, no_collector_registered):
    admin, token = Credential.create("ops", Role.ADMIN, "operator")
    cfg = AppConfig(deployment_mode=DeploymentMode.CENTRAL)
    app = FastAPI()
    app.include_router(api_v1_router, prefix="/api/v1")
    app.add_middleware(CentralAuthMiddleware, store=CredentialStore([admin]),
                       public_paths=cfg.central_public_paths)
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[get_config] = lambda: cfg
    c = TestClient(app, raise_server_exceptions=False)

    r = c.post("/api/v1/stream/ingest/ndjson",
               json={"source_id": DEFAULT_SOURCE_ID, "ndjson_content": LINE,
                     "data_category": "live_telemetry"},
               headers={"Authorization": f"Bearer {token}"})

    _refused(r, DEFAULT_SOURCE_ID)
    assert db.count_events() == 0


def test_csv_file_upload_cannot_fill_the_live_host_source(client, db, no_collector_registered):
    r = client.post(
        "/api/v1/import/csv/file",
        files={"file": ("flows.csv", CSV.encode("utf-8"), "text/csv")},
        data={"source_id": DEFAULT_SOURCE_ID},
    )

    _refused(r, DEFAULT_SOURCE_ID)
    assert db.count_events() == 0


def test_application_layer_ingest_cannot_fill_a_local_producers_source(db, no_collector_registered):
    """
    Two layers. The endpoint's own validator (pre-dating ADR-090) already
    rejects the collector's default id with 422, but knows only that one
    id. The trust-boundary guard covers the ids it does not: the UDP
    observer's and a collector running under a custom id.

    Enabled explicitly: disabled, the endpoint refuses for another reason.
    """
    app = FastAPI()
    app.include_router(api_v1_router, prefix="/api/v1")
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[get_config] = lambda: AppConfig(enable_application_layer_ingest=True)
    c = TestClient(app, raise_server_exceptions=False)
    record = {"observed_at": "2026-06-01T12:00:00Z", "method": "GET",
              "url": "https://example.test/", "dst_ip": "198.51.100.20", "dst_port": 443}

    def ingest(source_id):
        return c.post("/api/v1/applayer/ingest", json={
            "source_id": source_id, "producer": "test-probe", "records": [record]})

    by_validator = ingest(DEFAULT_SOURCE_ID)
    assert by_validator.status_code == 422, by_validator.text

    _refused(ingest(UDP_SOURCE_ID), UDP_SOURCE_ID)
    custom = "lab-host-collector-2"
    WindowsTelemetryCollectorService(db=db, source_id=custom, query_fn=_no_os)
    _refused(ingest(custom), custom)
    assert db.count_events() == 0

    ok = ingest("browser-probe")
    assert ok.status_code == 200, ok.text


# ──────────────────────────────────────────────────────────────────
# What a sensor agent does with the refusal
# ──────────────────────────────────────────────────────────────────


def test_the_sensor_agent_treats_the_refusal_as_permanent_not_as_a_conflict(client, db):
    """
    403, not 409: the agent counts every 409 as an event-identity conflict.
    Driven through the real endpoint, so the status and body are the
    server's own.
    """
    from app.agents.sensor_agent import AgentConfig, SensorAgent

    WindowsTelemetryCollectorService(db=db, query_fn=_no_os)

    class ThroughTheApp:
        attempts = 0

        def post(self, url, body, headers, timeout):
            ThroughTheApp.attempts += 1
            r = client.post("/api/v1/stream/ingest/ndjson", content=body,
                            headers={"Content-Type": "application/json"})
            return r.status_code, dict(r.headers), r.content

    agent = SensorAgent(
        AgentConfig(endpoint="https://central.invalid/api/v1/stream/ingest/ndjson",
                    source_id=DEFAULT_SOURCE_ID, token="t", batch_size=10, max_attempts=5),
        transport=ThroughTheApp(), sleep_fn=lambda s: None)
    agent.offer_many([json.loads(LINE)])

    result = agent.flush_once()
    health = agent.health()

    assert result.status == 403 and not result.retryable
    assert ThroughTheApp.attempts == 1, "a permanent refusal must not be retried"
    assert health["conflicts"] == 0, "must not be counted as an event-identity conflict"
    assert health["batches_failed_permanent"] == 1
    assert health["last_error_kind"] == "source_reserved_for_local_producer"
    assert db.count_events() == 0
