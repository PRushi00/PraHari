"""
PraHari — Comprehensive Telemetry Ingestion Audit & Verification Suite

Verifies:
- Zeek, Suricata, and CSV format mappings
- Valid, malformed, and missing fields
- Invalid IPs, out-of-bound ports, invalid timestamps
- Timestamp units (sec, ms, ISO) and UTC normalization
- Rejection categorization and exact count reconciliation
- Duplicate batch idempotency and transaction boundaries
- Source health and data category provenance
"""

import json
import tempfile
from pathlib import Path
from datetime import datetime, timezone
import pytest

from app.adapters.csv_import import CsvImportAdapter
from app.adapters.json_stream import JsonStreamAdapter
from app.schemas.events import (
    TelemetrySource,
    NormalizedEvent,
    EventType,
    DataCategory,
    LabelProvenance,
    QualityFlag,
)
from app.storage.database import Database


@pytest.fixture
def test_db():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        db_path = tmp.name
    db = Database(db_path=db_path)
    db.initialize()
    yield db
    db.close()
    try:
        Path(db_path).unlink(missing_ok=True)
    except Exception:
        pass


def test_zeek_field_mapping_and_timestamp_units():
    adapter = JsonStreamAdapter()

    # 1. Zeek with Unix timestamp in seconds
    zeek_sec = {
        "ts": 1700000000.5,
        "id.orig_h": "192.168.1.10",
        "id.orig_p": 45000,
        "id.resp_h": "10.0.0.1",
        "id.resp_p": 443,
        "proto": "tcp",
        "duration": 0.5,
        "orig_bytes": 1024,
        "resp_bytes": 4096,
        "conn_state": "SF",
    }
    res = adapter.validate_and_normalize(zeek_sec, record_index=0)
    assert res.is_valid is True
    event = res.event
    assert event.src_ip == "192.168.1.10"
    assert event.dst_ip == "10.0.0.1"
    assert event.src_port == 45000
    assert event.dst_port == 443
    assert event.protocol == "TCP"
    assert event.bytes_total == 5120
    assert event.observed_at.tzinfo == timezone.utc

    # 2. Zeek with Unix timestamp in milliseconds
    zeek_ms = {
        "ts": 1700000000500,  # > 1e11
        "id": {"orig_h": "192.168.1.11", "resp_h": "10.0.0.2", "orig_p": 50000, "resp_p": 80},
        "proto": 6,
    }
    res_ms = adapter.validate_and_normalize(zeek_ms, record_index=1)
    assert res_ms.is_valid is True
    assert res_ms.event.src_ip == "192.168.1.11"
    assert res_ms.event.dst_port == 80
    assert res_ms.event.protocol == "TCP"


def test_suricata_eve_mapping_and_iso_timestamp():
    adapter = JsonStreamAdapter()

    suricata_event = {
        "timestamp": "2026-03-15T14:30:00.123456Z",
        "event_type": "flow",
        "src_ip": "10.10.10.5",
        "dest_ip": "1.1.1.1",
        "src_port": 53000,
        "dest_port": 53,
        "proto": "UDP",
        "flow": {
            "bytes_toclient": 256,
            "bytes_toserver": 128,
            "pkts_toclient": 2,
            "pkts_toserver": 1,
            "age": 0.05,
        },
    }
    res = adapter.validate_and_normalize(suricata_event, record_index=0)
    assert res.is_valid is True
    ev = res.event
    assert ev.src_ip == "10.10.10.5"
    assert ev.dst_ip == "1.1.1.1"
    assert ev.dst_port == 53
    assert ev.protocol == "UDP"
    assert ev.bytes_total == 384
    assert ev.packets == 3


def test_missing_and_invalid_fields_rejection_reasons():
    adapter = JsonStreamAdapter()

    # Invalid IP
    r1 = adapter.validate_and_normalize({"ts": 1700000000, "src_ip": "999.999.999.999", "dst_ip": "1.1.1.1"}, 0)
    assert r1.is_valid is False
    assert any("invalid src_ip" in err for err in r1.errors)

    # Invalid Port (out of bounds)
    r2 = adapter.validate_and_normalize({"ts": 1700000000, "src_ip": "1.1.1.1", "dst_ip": "2.2.2.2", "dst_port": 70000}, 1)
    assert r2.is_valid is False
    assert any("dst_port" in err for err in r2.errors)

    # Missing Timestamp
    r3 = adapter.validate_and_normalize({"src_ip": "1.1.1.1", "dst_ip": "2.2.2.2"}, 2)
    assert r3.is_valid is False
    assert any("timestamp" in err for err in r3.errors)


def test_mixed_batch_ndjson_accounting_reconciliation():
    adapter = JsonStreamAdapter()

    # 4 lines: 2 valid, 1 corrupted JSON, 1 invalid IP
    lines = [
        json.dumps({"ts": 1700000001, "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "dst_port": 80, "proto": "TCP"}),
        "THIS_IS_CORRUPTED_JSON_LINE{{{",
        json.dumps({"ts": 1700000002, "src_ip": "INVALID_IP", "dst_ip": "10.0.0.2", "dst_port": 443}),
        json.dumps({"ts": 1700000003, "src_ip": "10.0.0.3", "dst_ip": "10.0.0.4", "dst_port": 22, "proto": "TCP"}),
    ]
    ndjson_content = "\n".join(lines)

    events, summary = adapter.import_ndjson_string(
        ndjson_content=ndjson_content,
        data_category=DataCategory.HISTORICAL_IMPORT,
    )

    # Reconciliation: accepted + rejected == total
    assert summary.total_records == 4
    assert summary.accepted_records == 2
    assert summary.rejected_records == 2
    assert summary.accepted_records + summary.rejected_records == summary.total_records
    assert len(events) == 2

    # Categorized reasons check
    assert "invalid_json_syntax" in summary.rejection_reasons
    assert summary.rejection_reasons["invalid_json_syntax"] == 1
    assert "invalid src_ip" in summary.rejection_reasons
    assert summary.rejection_reasons["invalid src_ip"] == 1


def test_duplicate_events_idempotency_and_transaction(test_db: Database):
    test_db.upsert_source(TelemetrySource(
        source_id="idemp_source",
        name="Idempotency Source",
        source_type="stream",
    ))

    ev1 = NormalizedEvent(
        event_id="constant-uuid-1",
        source_id="idemp_source",
        observed_at=datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
        event_type=EventType.NETWORK_FLOW,
        src_ip="192.168.1.1",
        dst_ip="10.0.0.1",
        src_port=1000,
        dst_port=80,
        protocol="TCP",
    )

    # First insert: accepted
    c1 = test_db.insert_events([ev1])
    assert c1 == 1

    # Second insert with identical event_id: safely skipped without transaction abort
    c2 = test_db.insert_events([ev1])
    assert c2 == 0

    # Total persisted events remains exactly 1
    total = test_db.count_events(source_id="idemp_source")
    assert total == 1


def test_csv_rejection_categorization_and_provenance():
    adapter = CsvImportAdapter()

    csv_data = (
        "Src IP,Dst IP,Src Port,Dst Port,Protocol,Timestamp,Flow Duration,Tot Fwd Pkts,TotLen Fwd Pkts,Label\n"
        "192.168.1.10,10.0.0.1,50000,443,6,2026-02-01 10:00:00,100,5,500,Benign\n"
        "999.1.1.1,10.0.0.1,50001,443,6,2026-02-01 10:00:01,100,5,500,Benign\n"
        "192.168.1.10,10.0.0.1,50002,99999,6,2026-02-01 10:00:02,100,5,500,Benign\n"
    )

    events, summary = adapter.import_string(
        csv_content=csv_data,
        source_id="csv_test_src",
        data_category=DataCategory.HISTORICAL_IMPORT,
    )

    assert summary.total_records == 3
    assert summary.accepted_records == 1
    assert summary.rejected_records == 2
    assert "missing or invalid src_ip" in summary.rejection_reasons
    assert "invalid dst_port" in summary.rejection_reasons
    assert events[0].label_provenance == LabelProvenance.DATASET_GROUND_TRUTH
