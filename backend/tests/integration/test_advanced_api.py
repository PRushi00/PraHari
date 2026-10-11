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
    gen = SyntheticFlowGenerator(seed=99, source_id="test_sensor")
    seed_events = gen.generate_scenario_batch(count=150, attack_ratio=0.25)
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
    res = client.get("/api/v1/audit/config")
    assert res.status_code == 200
    cfg = res.json()
    assert cfg["loopback_enforced"] is True
    assert cfg["security_boundaries"]["live_sniffing_disabled"] is True
