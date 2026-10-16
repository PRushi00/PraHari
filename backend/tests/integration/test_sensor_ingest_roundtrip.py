"""
End-to-end ingest of Zeek and Suricata output through the live API.

The unit tests pin the adapter's behaviour; these confirm the same
guarantees survive the HTTP boundary and persistence, which is where the
claims in docs/PLATFORM_SUPPORT.md are actually made.

Documentation addresses only (RFC 5737). No real telemetry.
"""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from app.api.deps import get_db
from app.main import app
from app.schemas.events import LabelProvenance, TelemetrySource
from app.storage.database import Database

SOURCE = "sensor-roundtrip"


@pytest.fixture
def client(tmp_path):
    db = Database(db_path=str(tmp_path / "sensor.db"))
    db.initialize()
    db.upsert_source(
        TelemetrySource(source_id=SOURCE, name="Sensor", source_type="json_stream")
    )
    app.dependency_overrides[get_db] = lambda: db
    with TestClient(app) as c:
        yield c, db
    app.dependency_overrides.clear()
    db.close()


def _ingest(client, records, category="historical_import"):
    payload = "\n".join(json.dumps(r) for r in records)
    res = client.post(
        "/api/v1/stream/ingest/ndjson",
        json={
            "source_id": SOURCE,
            "ndjson_content": payload,
            "data_category": category,
        },
    )
    assert res.status_code == 200, res.text
    return res.json()


def _zeek(i: int) -> dict:
    return {
        "ts": 1700000000.0 + i,
        "id.orig_h": "192.0.2.70", "id.orig_p": 40000 + i,
        "id.resp_h": "198.51.100.70", "id.resp_p": 443,
        "proto": "tcp", "orig_bytes": 100, "resp_bytes": 200,
        "duration": 0.0,
    }


def _suricata_alert(i: int) -> dict:
    return {
        "timestamp": f"2026-03-15T14:{i % 60:02d}:00.000000Z",
        "event_type": "alert",
        "src_ip": "192.0.2.71", "dest_ip": "198.51.100.71",
        "src_port": 41000 + i, "dest_port": 445, "proto": "TCP",
        "alert": {"signature": "ET EXPLOIT Example", "severity": 1},
    }


def test_zeek_batch_ingests_and_reconciles(client):
    c, db = client
    summary = _ingest(c, [_zeek(i) for i in range(10)])

    assert summary["total_records"] == 10
    assert summary["accepted_records"] + summary["rejected_records"] == 10
    assert summary["accepted_records"] == 10

    stored = db.list_events(source_id=SOURCE, limit=100)
    assert len(stored) == 10
    # The zero duration survives storage as a measured value.
    assert all(e.duration == 0.0 for e in stored)
    assert all(e.bytes_total == 300 for e in stored)


def test_detector_labels_persist_as_detector_output_not_ground_truth(client):
    """
    The provenance distinction has to survive the round trip, because it is
    what the readiness report and the experiment manifest are read from.
    """
    c, db = client
    _ingest(c, [_suricata_alert(i) for i in range(12)])

    stored = db.list_events(source_id=SOURCE, limit=100)
    assert len(stored) == 12
    assert {e.label_provenance for e in stored} == {LabelProvenance.DETECTOR_OUTPUT}
    assert all(e.label == "ET EXPLOIT Example" for e in stored)
    assert not any(
        e.label_provenance is LabelProvenance.DATASET_GROUND_TRUTH for e in stored
    )


def test_readiness_endpoint_flags_detector_labels(client):
    c, _ = client
    _ingest(c, [_suricata_alert(i) for i in range(40)])

    res = c.get(f"/api/v1/forecast/readiness?source_id={SOURCE}")
    assert res.status_code == 200
    body = res.json()

    assert body["non_ground_truth_labelled_events"] == 40
    assert body["label_caveats"], "the dashboard would show no caveat at all"
    assert any("detector" in cav.lower() for cav in body["label_caveats"])
    assert "detector_output" in body["label_provenances"]
    assert "dataset_ground_truth" not in body["label_provenances"]


def test_a_malformed_record_does_not_discard_the_batch(client):
    c, db = client
    records = [_zeek(0), {"ts": 1700000001.0, "id.orig_h": "not-an-ip"}, _zeek(2)]
    summary = _ingest(c, records)

    assert summary["total_records"] == 3
    assert summary["accepted_records"] == 2
    assert summary["rejected_records"] == 1
    assert summary["rejection_reasons"]
    assert len(db.list_events(source_id=SOURCE, limit=100)) == 2


def test_mixed_sensor_output_keeps_event_types_distinct(client):
    """A labelled flow is still a flow; only an alert is an alert."""
    c, db = client
    _ingest(c, [
        _zeek(0),
        _suricata_alert(1),
        {
            "timestamp": "2026-03-15T14:05:00.000000Z",
            "event_type": "dns",
            "src_ip": "192.0.2.72", "dest_ip": "198.51.100.53",
            "src_port": 42000, "dest_port": 53, "proto": "UDP",
        },
        {
            "timestamp": "2026-03-15T14:06:00.000000Z",
            "event_type": "flow",
            "src_ip": "192.0.2.73", "dest_ip": "198.51.100.73",
            "src_port": 42001, "dest_port": 443, "proto": "TCP",
            "label": "DDoS",
        },
    ])

    stored = {e.src_ip: e for e in db.list_events(source_id=SOURCE, limit=100)}
    assert stored["192.0.2.70"].event_type.value == "network_flow"
    assert stored["192.0.2.71"].event_type.value == "alert"
    assert stored["192.0.2.72"].event_type.value == "dns_query"

    labelled_flow = stored["192.0.2.73"]
    assert labelled_flow.event_type.value == "network_flow"
    assert labelled_flow.label == "DDoS"
    assert labelled_flow.label_provenance is LabelProvenance.DATASET_GROUND_TRUTH
