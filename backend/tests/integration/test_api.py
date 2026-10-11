"""
Integration tests for FastAPI endpoints.
"""

from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.api.deps import get_db
from app.storage.database import Database
import tempfile


@pytest.fixture
def client_with_db():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        db_path = tmp.name
    test_db = Database(db_path=db_path)
    test_db.initialize()

    app.dependency_overrides[get_db] = lambda: test_db
    with TestClient(app) as client:
        yield client, test_db

    app.dependency_overrides.clear()
    test_db.close()
    try:
        Path(db_path).unlink(missing_ok=True)
    except Exception:
        pass


def test_health_endpoint(client_with_db):
    client, _ = client_with_db
    res = client.get("/api/v1/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "healthy"
    assert "schema_version" in data
    assert data["database"]["connected"] is True


def test_sources_and_events_workflow(client_with_db):
    client, _ = client_with_db

    # 1. Create a source
    res = client.post("/api/v1/sources", json={
        "source_id": "ids_sensor_01",
        "name": "Perimeter IDS",
        "source_type": "csv_import",
        "description": "Perimeter network sensor",
    })
    assert res.status_code == 201
    source_data = res.json()
    assert source_data["source_id"] == "ids_sensor_01"

    # 2. Import raw CSV data
    raw_csv = """Src IP,Dst IP,Src Port,Dst Port,Protocol,Timestamp,Flow Duration,Tot Fwd Pkts,TotLen Fwd Pkts,Label
192.168.1.10,10.0.0.1,54000,443,6,2026-02-15 10:00:00,100000,5,1500,Benign
192.168.1.20,10.0.0.1,54001,22,6,2026-02-15 10:00:01,200000,6,1200,SSH-BruteForce
"""
    res = client.post("/api/v1/import/csv/raw", json={
        "source_id": "ids_sensor_01",
        "csv_content": raw_csv,
    })
    assert res.status_code == 200
    summary = res.json()
    assert summary["accepted_records"] == 2
    assert summary["rejected_records"] == 0

    # 3. Query events
    res = client.get("/api/v1/events?source_id=ids_sensor_01")
    assert res.status_code == 200
    ev_data = res.json()
    assert ev_data["total"] == 2
    assert len(ev_data["events"]) == 2

    # 4. Run descriptive analysis
    res = client.post("/api/v1/analysis/run", json={"source_id": "ids_sensor_01"})
    assert res.status_code == 200
    analysis = res.json()
    assert analysis["total_events"] == 2
    assert analysis["events_by_label"]["Benign"] == 1
    assert analysis["events_by_label"]["SSH-BruteForce"] == 1
    assert analysis["unique_src_ips"] == 2
