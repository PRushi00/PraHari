"""
PraHari — Bounded Admission Control and the System Health View
(ADR-056; blueprint §4.2, §6, §11).

§6 requires bounded ingestion resources and visible backpressure; §11
requires one view carrying ingestion latency, queue depth, parser errors,
rejected records, storage status and inference latency.

The hard rule these tests enforce is the honesty one: a field that was
not measured is **null**, never 0, and `queue_depth` is null because
there is no queue — reporting 0 would assert an empty one.
"""

from __future__ import annotations

import json
import threading
import time

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.deps import get_db
from app.api.v1.router import api_v1_router
from app.core.config import AppConfig, get_config
from app.schemas.events import TelemetrySource
from app.services.admission import (
    AdmissionController,
    IngestionOverloaded,
    reset_admission_controller,
)
from app.storage.database import Database

SOURCE = "health-sensor"


def _record(i: int) -> dict:
    return {
        "event_id": f"evt-health-{i}",
        "timestamp": "2026-06-01T12:00:00Z",
        "src_ip": "192.0.2.10", "dst_ip": "198.51.100.20",
        "src_port": 40000 + i, "dst_port": 443, "proto": "tcp",
    }


@pytest.fixture(autouse=True)
def fresh_controller():
    reset_admission_controller()
    yield
    reset_admission_controller()


@pytest.fixture
def client(tmp_path):
    db = Database(db_path=str(tmp_path / "health.db"))
    db.initialize()
    db.upsert_source(
        TelemetrySource(source_id=SOURCE, name=SOURCE, source_type="json_stream")
    )
    cfg = AppConfig()
    app = FastAPI()
    app.include_router(api_v1_router, prefix="/api/v1")
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[get_config] = lambda: cfg
    with TestClient(app) as c:
        yield c, db
    db.close()


# ──────────────────────────────────────────────────────────────────
# The admission controller itself
# ──────────────────────────────────────────────────────────────────


def test_admission_is_bounded_by_capacity():
    controller = AdmissionController(max_concurrent=2)

    a = controller.admit()
    b = controller.admit()
    assert controller.in_flight == 2

    with pytest.raises(IngestionOverloaded):
        controller.admit()

    a.__exit__(None, None, None)
    b.__exit__(None, None, None)
    assert controller.in_flight == 0


def test_a_slot_is_released_even_when_the_handler_raises():
    """A conflict or database error must not leak capacity."""
    controller = AdmissionController(max_concurrent=1)

    with pytest.raises(ValueError):
        with controller.admit():
            raise ValueError("boom")

    assert controller.in_flight == 0
    with controller.admit():
        pass  # capacity recovered


def test_refusals_are_counted_separately_from_admissions():
    controller = AdmissionController(max_concurrent=1)

    with controller.admit():
        with pytest.raises(IngestionOverloaded):
            controller.admit()

    snap = controller.snapshot()
    assert snap["requests_admitted"] == 1
    assert snap["requests_rejected_overloaded"] == 1


def test_peak_in_flight_is_retained():
    controller = AdmissionController(max_concurrent=4)

    slots = [controller.admit() for _ in range(3)]
    for s in slots:
        s.__exit__(None, None, None)

    assert controller.in_flight == 0
    assert controller.peak_in_flight == 3


def test_concurrent_admission_never_exceeds_capacity():
    controller = AdmissionController(max_concurrent=3)
    observed: list[int] = []
    barrier = threading.Barrier(8, timeout=10)

    def worker():
        barrier.wait()
        try:
            with controller.admit():
                observed.append(controller.in_flight)
                time.sleep(0.01)
        except IngestionOverloaded:
            pass

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)

    assert observed, "no thread was admitted"
    assert max(observed) <= 3, f"capacity exceeded: {max(observed)}"
    assert controller.in_flight == 0


def test_a_rejected_configuration_is_refused():
    with pytest.raises(ValueError):
        AdmissionController(max_concurrent=0)


def test_latency_samples_are_bounded():
    """A long-running process must not grow this without limit."""
    controller = AdmissionController(max_concurrent=1)
    for i in range(1000):
        controller.metrics.record_latency(float(i))

    assert len(controller.metrics._latencies_ms) <= controller.metrics._max_samples


def test_latency_is_null_before_anything_is_measured():
    """Null means not measured. Zero would claim instantaneous work."""
    summary = AdmissionController(max_concurrent=1).metrics.latency_summary()

    assert summary["samples"] == 0
    assert summary["p50_ms"] is None
    assert summary["max_ms"] is None


# ──────────────────────────────────────────────────────────────────
# Admission control is wired into real ingestion
# ──────────────────────────────────────────────────────────────────


def test_ingestion_records_measured_counters(client):
    c, _ = client
    payload = {
        "source_id": SOURCE,
        "ndjson_content": "\n".join(json.dumps(_record(i)) for i in range(3)) + "\n",
    }

    assert c.post("/api/v1/stream/ingest/ndjson", json=payload).status_code == 200

    data = c.get("/api/v1/system/health").json()["ingestion"]["data"]
    assert data["batches_completed"] == 1
    assert data["events_stored"] == 3
    assert data["requests_admitted"] >= 1
    assert data["last_success_at"] is not None
    assert data["processing_latency"]["samples"] == 1


def test_a_retry_is_counted_as_duplicates_not_stores(client):
    c, _ = client
    payload = {
        "source_id": SOURCE,
        "ndjson_content": json.dumps(_record(0)) + "\n",
    }
    c.post("/api/v1/stream/ingest/ndjson", json=payload)
    c.post("/api/v1/stream/ingest/ndjson", json=payload)

    data = c.get("/api/v1/system/health").json()["ingestion"]["data"]
    assert data["events_stored"] == 1
    assert data["events_duplicate"] == 1


def test_a_conflict_is_counted_as_a_failure(client):
    c, _ = client
    base = _record(0)
    c.post("/api/v1/stream/ingest/ndjson",
           json={"source_id": SOURCE, "ndjson_content": json.dumps(base) + "\n"})

    conflicting = {**base, "bytes": 999999}
    assert c.post(
        "/api/v1/stream/ingest/ndjson",
        json={"source_id": SOURCE, "ndjson_content": json.dumps(conflicting) + "\n"},
    ).status_code == 409

    data = c.get("/api/v1/system/health").json()["ingestion"]["data"]
    assert data["conflicts"] == 1
    assert data["batches_failed"] == 1
    assert data["last_error_kind"] == "conflict"


def test_a_conflict_does_not_leak_ingestion_capacity(client):
    c, _ = client
    base = _record(0)
    c.post("/api/v1/stream/ingest/ndjson",
           json={"source_id": SOURCE, "ndjson_content": json.dumps(base) + "\n"})
    c.post("/api/v1/stream/ingest/ndjson",
           json={"source_id": SOURCE,
                 "ndjson_content": json.dumps({**base, "bytes": 1}) + "\n"})

    data = c.get("/api/v1/system/health").json()["ingestion"]["data"]
    assert data["in_flight"] == 0, "a 409 leaked an admission slot"


def test_saturation_is_refused_with_503_and_stores_nothing(client):
    """
    Drive the controller to capacity and confirm ingestion is refused
    rather than buffered — nothing is queued, nothing is stored.
    """
    c, db = client
    controller = reset_admission_controller(max_concurrent=1)

    held = controller.admit()
    try:
        response = c.post(
            "/api/v1/stream/ingest/ndjson",
            json={"source_id": SOURCE,
                  "ndjson_content": json.dumps(_record(9)) + "\n"},
        )
    finally:
        held.__exit__(None, None, None)

    assert response.status_code == 503
    detail = response.json()["detail"]
    assert detail["error"] == "ingestion_overloaded"
    assert detail["stored_records"] == 0
    assert response.headers.get("Retry-After")
    assert db.count_events() == 0, "a refused request stored telemetry"


def test_capacity_recovers_after_saturation(client):
    c, db = client
    controller = reset_admission_controller(max_concurrent=1)

    held = controller.admit()
    c.post("/api/v1/stream/ingest/ndjson",
           json={"source_id": SOURCE, "ndjson_content": json.dumps(_record(1)) + "\n"})
    held.__exit__(None, None, None)

    after = c.post(
        "/api/v1/stream/ingest/ndjson",
        json={"source_id": SOURCE, "ndjson_content": json.dumps(_record(1)) + "\n"},
    )

    assert after.status_code == 200
    assert db.count_events() == 1


# ──────────────────────────────────────────────────────────────────
# The System Health report, and its honesty rules
# ──────────────────────────────────────────────────────────────────


def test_the_report_carries_every_section_the_blueprint_names(client):
    c, _ = client

    body = c.get("/api/v1/system/health").json()

    for block in ("ingestion", "sources", "storage", "models", "adapters", "limits"):
        assert block in body, f"missing §11 block: {block}"
        assert "available" in body[block]


def test_queue_depth_is_null_because_there_is_no_queue(client):
    """
    Reporting 0 would assert an empty queue. There is no queue at all,
    and the response has to say which of those is true.
    """
    c, _ = client

    data = c.get("/api/v1/system/health").json()["ingestion"]["data"]

    assert data["queue_depth"] is None
    assert data["admission_model"] == "bounded_concurrency_no_queue"
    assert "no queue" in data["queue_depth_note"].lower()


def test_unmeasured_inference_latency_is_null_not_zero(client):
    c, _ = client

    models = c.get("/api/v1/system/health").json()["models"]

    if models["available"]:
        assert models["data"]["inference_latency"] is None


def test_model_availability_matches_the_registry_exactly(client):
    """
    §9 forbids substituting a demo score when a model is missing, so
    `inference_available` must track the registry rather than being
    asserted independently.

    The registry is a process-wide singleton, so whether any model is
    trained depends on what else ran first. The invariant that must hold
    either way is the consistency between the two fields — asserting an
    empty registry would only test the suite's ordering.
    """
    c, _ = client

    models = c.get("/api/v1/system/health").json()["models"]

    if not models["available"]:
        assert models["reason"], "unavailable must say why"
        return

    data = models["data"]
    assert data["model_count"] == len(data["trained_models"])
    assert data["inference_available"] == (data["model_count"] > 0)


def test_storage_reports_real_integrity_and_migration_state(client):
    c, _ = client

    storage = c.get("/api/v1/system/health").json()["storage"]

    assert storage["available"] is True
    assert storage["data"]["integrity_check"] == "ok"
    assert storage["data"]["healthy"] is True
    assert storage["data"]["received_at_column_present"] is True
    assert storage["data"]["size_bytes"] > 0


def test_limits_report_enforcement_not_just_configured_numbers(client):
    """
    A configured number without its enforcement state is how
    max_request_size_mb came to be published as a boundary nothing read.
    """
    c, _ = client

    limits = c.get("/api/v1/system/health").json()["limits"]["data"]

    for key in (
        "request_size_limit_enforced",
        "import_record_limit_enforced",
        "admission_control_enforced",
    ):
        assert limits[key] is True
    assert "rate_limit_enforced" in limits


def test_source_health_is_surfaced_with_its_basis(client):
    c, _ = client

    sources = c.get("/api/v1/system/health").json()["sources"]["data"]

    assert sources["total"] == 1
    record = sources["sources"][0]
    assert record["source_id"] == SOURCE
    assert "freshness_basis" in record
    assert "clock_dependent" in record


def test_no_sources_reads_as_zero_not_as_unavailable(tmp_path):
    """Nothing registered is a measurement. It is not a failure to measure."""
    db = Database(db_path=str(tmp_path / "empty.db"))
    db.initialize()
    app = FastAPI()
    app.include_router(api_v1_router, prefix="/api/v1")
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[get_config] = lambda: AppConfig()

    with TestClient(app) as c:
        sources = c.get("/api/v1/system/health").json()["sources"]
    db.close()

    assert sources["available"] is True
    assert sources["data"]["total"] == 0


def test_the_report_changes_nothing(client):
    """Read-only: it starts nothing and collects nothing."""
    c, db = client
    before = db.count_events()

    for _ in range(3):
        assert c.get("/api/v1/system/health").status_code == 200

    assert db.count_events() == before


def test_runtime_info_exposes_no_secrets(client):
    c, _ = client

    body = c.get("/api/v1/system/runtime").text.lower()

    for leak in ("token", "password", "secret", "credential", "salt"):
        assert leak not in body
