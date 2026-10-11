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
