"""
Integration tests for Research, Forecasting, Streaming, and Audit Endpoints.
"""

from pathlib import Path
import tempfile
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.api.deps import get_db
from app.storage.database import Database
from app.schemas.events import TelemetrySource
from app.adapters.synthetic_replay import SyntheticFlowGenerator


@pytest.fixture
def client_with_db():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        db_path = tmp.name
    test_db = Database(db_path=db_path)
    test_db.initialize()

    # Pre-seed source and 50 synthetic events into test DB
    test_db.upsert_source(TelemetrySource(
        source_id="test_sensor",
        name="Test Sensor",
        source_type="synthetic_replay",
    ))
    # 800 synthetic events spanning ~2400s: enough to satisfy the research
    # gate's data prerequisites, so the forecasting happy path can be tested.
    gen = SyntheticFlowGenerator(seed=99, source_id="test_sensor")
    seed_events = gen.generate_scenario_batch(count=800, attack_ratio=0.25)
    test_db.insert_events(seed_events)

    app.dependency_overrides[get_db] = lambda: test_db
    with TestClient(app) as client:
        yield client, test_db

    app.dependency_overrides.clear()
    test_db.close()
    try:
        Path(db_path).unlink(missing_ok=True)
    except Exception:
        pass


def test_research_audit_endpoint(client_with_db):
    client, _ = client_with_db
    res = client.post("/api/v1/research/audit")
    assert res.status_code == 200
    report = res.json()
    assert "gate_passed" in report
    assert "overall_score" in report
    assert len(report["checks"]) > 0


def test_synthetic_replay_endpoint(client_with_db):
    client, _ = client_with_db
    res = client.post("/api/v1/stream/replay/synthetic", json={
        "source_id": "api_test_synth",
        "source_name": "API Replay Test",
        "count": 25,
        "attack_ratio": 0.2,
    })
    assert res.status_code == 200
    data = res.json()
    assert data["accepted_records"] == 25
    assert data["rejected_records"] == 0


def test_forecast_readiness_endpoint_reports_state_and_target(client_with_db):
    client, _ = client_with_db
    res = client.get("/api/v1/forecast/readiness")
    assert res.status_code == 200
    report = res.json()

    # The gate states what it is forecasting and over what horizon.
    assert "attack" in report["prediction_target"].lower()
    assert report["prediction_horizon_seconds"] > 0
    assert report["observation_window_seconds"] > 0

    # Every prerequisite is reported with observed vs required values.
    assert len(report["requirements"]) >= 5
    for req in report["requirements"]:
        assert {"name", "satisfied", "required", "observed"} <= set(req)

    assert report["can_train"] is True
    assert report["unmet_requirements"] == []


def test_forecast_train_and_predict_endpoint(client_with_db):
    client, _ = client_with_db

    # 1. Train forecasting models
    res = client.post("/api/v1/forecast/train", json={"max_events": 1000})
    assert res.status_code == 200
    models = res.json()
    assert "random_forest_forecaster" in models
    assert "baseline_threshold" in models

    # 2. Get comparative models
    res = client.get("/api/v1/forecast/models")
    assert res.status_code == 200

    # 3. Predict incident propensity
    res = client.post("/api/v1/forecast/predict", json={
        "model_id": "random_forest_forecaster",
        "threshold": 0.5,
    })
    assert res.status_code == 200
    pred = res.json()
    assert "propensity_score" in pred
    assert "predicted_incident" in pred
    assert len(pred["top_contributing_features"]) > 0


def test_audit_logs_and_config_endpoint(client_with_db):
    client, _ = client_with_db

    # Check audit logs
    res = client.get("/api/v1/audit/logs?limit=50")
    assert res.status_code == 200
    logs = res.json()
    assert isinstance(logs, list)

    # Check system security config
    # Arrive on the configured listener (127.0.0.1:8000). The test client's
    # default "testserver:80" matches no configuration, and since ADR-089 the
    # report no longer claims loopback without that evidence.
    res = client.get("http://127.0.0.1:8000/api/v1/audit/config")
    assert res.status_code == 200
    cfg = res.json()
    assert cfg["loopback_enforced"] is True

    # Security boundaries must be derived from live state, not asserted as
    # fixed constants. Each value below reflects something the running system
    # can actually be checked against.
    boundaries = cfg["security_boundaries"]
    assert boundaries["packet_capture_in_use"] is False
    assert boundaries["external_telemetry_transmission"] is False
    assert boundaries["service_exposure"] == "loopback_only"
    assert boundaries["authentication_required"] == cfg["authentication_required"]
    assert boundaries["raw_payload_storage_enabled"] is False
    # The collector reports a real state rather than a hardcoded "disabled".
    assert boundaries["live_collector_state"] in (
        "stopped", "running", "error", "unsupported", "unknown",
    )
    # The research gate is described honestly as advisory, not claimed as a
    # hard block the system does not actually implement.
    assert "advisory" in boundaries["research_gate_enforcement"]
