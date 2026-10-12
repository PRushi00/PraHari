"""
Unit tests for JSON Stream Adapter and Synthetic Flow Generator.
"""

import json
from datetime import datetime, timezone
import pytest

from app.adapters.json_stream import JsonStreamAdapter
from app.adapters.synthetic_replay import SyntheticFlowGenerator
from app.schemas.events import DataCategory, QualityFlag


def test_json_stream_zeek_format():
    adapter = JsonStreamAdapter(adapter_id="zeek_test")
    raw_zeek = {
        "ts": 1771152000.0,
        "id.orig_h": "192.168.1.15",
        "id.resp_h": "10.0.0.1",
        "id.orig_p": 49152,
        "id.resp_p": 443,
        "proto": "tcp",
        "duration": 1.25,
        "orig_bytes": 1024,
        "label": "Benign",
    }
    res = adapter.validate_and_normalize(raw_zeek, record_index=1)
    assert res.is_valid is True
    assert res.event is not None
    assert res.event.src_ip == "192.168.1.15"
    assert res.event.dst_ip == "10.0.0.1"
    assert res.event.src_port == 49152
    assert res.event.dst_port == 443
    assert res.event.protocol == "TCP"
    assert res.event.label == "Benign"


def test_json_stream_rejection_of_corrupted():
    adapter = JsonStreamAdapter(adapter_id="zeek_test")
    corrupt_record = {
        "ts": 1771152000.0,
        "src_ip": "bad_ip_address",
        "dst_ip": "10.0.0.1",
        "src_port": 80,
        "dst_port": 80,
    }
    res = adapter.validate_and_normalize(corrupt_record, record_index=2)
    assert res.is_valid is False
    assert any("invalid src_ip" in err for err in res.errors)


def test_synthetic_flow_generator():
    generator = SyntheticFlowGenerator(seed=123, source_id="synth_unit_test")
    events = generator.generate_scenario_batch(count=30, attack_ratio=0.3)

    assert len(events) == 30
    assert all(e.data_category == DataCategory.SYNTHETIC for e in events)
    assert all(QualityFlag.SYNTHETIC_SAMPLE in e.quality_flags for e in events)
    attack_events = [e for e in events if e.label != "Benign"]
    assert len(attack_events) > 0
    # Chronological check
    for i in range(len(events) - 1):
        assert events[i].observed_at <= events[i + 1].observed_at


def test_synthetic_replay_summary_records_both_timestamps():
    """
    Regression: the replay summary never set completed_at, so elapsed
    duration was unavailable to every consumer. The dashboard had papered
    over this by reading a `duration_seconds` field the API does not
    return, which crashed the page.
    """
    import tempfile
    from pathlib import Path

    from fastapi.testclient import TestClient

    from app.api.deps import get_db
    from app.main import app
    from app.storage.database import Database

    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        db_path = tmp.name
    db = Database(db_path=db_path)
    db.initialize()
    app.dependency_overrides[get_db] = lambda: db
    try:
        with TestClient(app) as client:
            res = client.post(
                "/api/v1/stream/replay/synthetic",
                json={"source_id": "synthetic_replay_engine", "count": 20},
            )
        assert res.status_code == 200
        body = res.json()

        assert body["started_at"] is not None
        assert body["completed_at"] is not None
        assert body["completed_at"] >= body["started_at"]

        # The fields the dashboard actually renders.
        assert body["total_records"] == 20
        assert body["data_category"] == "synthetic_demo"

        # And the ones it must NOT expect.
        for phantom in ("duration_seconds", "simulated_attack_ratio", "generated_records"):
            assert phantom not in body
    finally:
        app.dependency_overrides.clear()
        db.close()
        Path(db_path).unlink(missing_ok=True)
