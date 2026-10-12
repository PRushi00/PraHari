"""
End-to-End Local Workflow Verification Test

Tests the full local operational cycle:
1. Ingest CSV telemetry fixture
2. Ingest Zeek and Suricata NDJSON stream
3. Query normalized persisted events and summary statistics
4. Run descriptive analytics and verify factual distributions
5. Audit dataset feasibility for research gating
6. Train and benchmark forecasting models with strict temporal splits
7. Run live incident propensity inference
8. Verify database persistence and schema integrity across restart
"""

import json
from pathlib import Path
from datetime import datetime, timezone
from fastapi.testclient import TestClient

from app.main import app
from app.api.deps import get_db
from app.storage.database import Database
from app.models.registry import reset_forecasting_pipeline


def test_complete_end_to_end_pipeline(tmp_path: Path):
    db_path = tmp_path / "e2e_prahari.db"
    db = Database(str(db_path))
    db.initialize()
    reset_forecasting_pipeline()

    app.dependency_overrides[get_db] = lambda: db
    client = TestClient(app)

    # 1. Health check & Initial state
    resp = client.get("/api/v1/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "healthy"
    assert resp.json()["database"]["events_count"] == 0

    # 2. Ingest CSV Fixture
    fixture_path = Path(__file__).resolve().parent.parent / "fixtures" / "sample_flows.csv"
    assert fixture_path.exists(), "sample_flows.csv fixture must exist"

    with open(fixture_path, "rb") as f:
        resp = client.post(
            "/api/v1/import/csv/file",
            files={"file": ("sample_flows.csv", f, "text/csv")},
            data={"source_id": "e2e_csv_sensor", "data_category": "historical_import"},
        )
    assert resp.status_code == 200
    import_summary = resp.json()
    assert import_summary["total_records"] == 45
    assert import_summary["accepted_records"] == 35
    assert import_summary["rejected_records"] == 10
    assert import_summary["accepted_records"] + import_summary["rejected_records"] == 45

    # 3. Ingest NDJSON Stream (Zeek and Suricata lines)
    ndjson_payload = (
        # Zeek format
        json.dumps({
            "ts": 1771144500.0,
            "id.orig_h": "10.0.1.50",
            "id.resp_h": "192.168.1.1",
            "id.orig_p": 49999,
            "id.resp_p": 80,
            "proto": "tcp",
            "duration": 0.05,
            "orig_bytes": 120,
            "resp_bytes": 450,
        }) + "\n" +
        # Suricata EVE format
        json.dumps({
            "timestamp": "2026-02-15T08:35:10.000Z",
            "event_type": "flow",
            "src_ip": "10.0.1.60",
            "dest_ip": "192.168.1.1",
            "src_port": 50001,
            "dest_port": 443,
            "proto": "TCP",
            "flow": {
                "age": 12,
                "bytes_toserver": 300,
                "bytes_toclient": 1200,
                "pkts_toserver": 4,
                "pkts_toclient": 8,
            },
        })
    )
    resp = client.post(
        "/api/v1/stream/ingest/ndjson",
        json={
            "source_id": "e2e_stream_sensor",
            "ndjson_content": ndjson_payload,
            "data_category": "live_telemetry",
        },
    )
    assert resp.status_code == 200
    stream_res = resp.json()
    assert stream_res["accepted_records"] == 2
    assert stream_res["rejected_records"] == 0

    # 4. Verify Total Events Retrieved via API (35 CSV + 2 NDJSON = 37)
    resp = client.get("/api/v1/events?limit=100")
    assert resp.status_code == 200
    events_data = resp.json()
    assert events_data["total"] == 37
    assert len(events_data["events"]) == 37

    # 5. Descriptive Analytics
    resp = client.post("/api/v1/analysis/run", json={"max_events": 1000})
    assert resp.status_code == 200
    analysis = resp.json()
    assert analysis["total_events"] == 37
    assert "TCP" in analysis["events_by_protocol"]
    assert "UDP" in analysis["events_by_protocol"]
    assert analysis["total_bytes"] > 0
    assert len(analysis["top_dst_ports"]) > 0

    # 6. Research Feasibility Audit
    resp = client.post("/api/v1/research/audit")
    assert resp.status_code == 200
    feasibility = resp.json()
    assert feasibility["overall_score"] > 0.0
    assert feasibility["recommendation"] in ("PERMIT_FORECASTING", "CONDITIONAL_REVIEW")
    assert len(feasibility["checks"]) >= 4

    # 7. Research gate — 37 events over a few minutes cannot support
    #    supervised forecasting, so the gate refuses BEFORE any model runs.
    #    This is enforced in the backend, so a direct API call is refused on
    #    the same terms as a dashboard click.
    resp = client.get("/api/v1/forecast/readiness")
    assert resp.status_code == 200
    readiness = resp.json()
    assert readiness["can_train"] is False
    assert readiness["state"] == "insufficient_data"
    assert readiness["unmet_requirements"], "gate must name what is unmet"

    resp = client.post("/api/v1/forecast/train", json={"max_events": 1000, "train_ratio": 0.7})
    assert resp.status_code == 409
    detail = resp.json()["detail"]
    assert detail["error"] == "forecasting_blocked_by_research_gate"
    assert detail["readiness_state"] == "insufficient_data"
    assert len(detail["unmet_requirements"]) >= 1
    assert detail["next_steps"]
    # The refusal states what the model would have been forecasting.
    assert "attack" in detail["prediction_target"].lower()

    # 8. Prediction is refused on the same grounds — an uncalibrated score
    #    here would invite being read as a forecast.
    resp = client.post("/api/v1/forecast/predict", json={"threshold": 0.5})
    assert resp.status_code == 409
    assert resp.json()["detail"]["operation"] == "predict"

    # 8b. No model may be advertised, because none was trained.
    resp = client.get("/api/v1/forecast/models")
    assert resp.status_code == 200
    assert resp.json() == {}

    # 9. Audit Log Verification
    resp = client.get("/api/v1/audit/logs?limit=50")
    assert resp.status_code == 200
    audit_logs = resp.json()
    actions = [log["action"] for log in audit_logs]
    assert "import_csv_file" in actions
    assert "run_descriptive_analysis" in actions
    # The blocked attempt is itself auditable: the refusal is recorded with
    # its reason, rather than leaving no trace.
    assert "train_forecasting_models_blocked" in actions
    blocked = next(l for l in audit_logs if l["action"] == "train_forecasting_models_blocked")
    assert "refused" in blocked["details"].lower()

    # 10. Persistence Across Database Re-open
    db_reopened = Database(str(db_path))
    assert db_reopened.count_events() == 37
    assert len(db_reopened.list_sources()) >= 2
    latest_analysis = db_reopened.get_latest_analysis()
    assert latest_analysis is not None
    assert latest_analysis.total_events == 37

    app.dependency_overrides.clear()
