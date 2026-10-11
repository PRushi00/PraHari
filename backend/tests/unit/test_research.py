"""
Unit tests for Research Feasibility Assessment & Dataset Audit Engine.
"""

from datetime import datetime, timezone, timedelta
import pytest

from app.schemas.events import NormalizedEvent, EventType, DataCategory, LabelProvenance, QualityFlag
from app.research.feasibility import audit_dataset_feasibility


def test_feasibility_insufficient_samples():
    events = [
        NormalizedEvent(
            source_id="test_small",
            observed_at=datetime.now(timezone.utc),
            event_type=EventType.NETWORK_FLOW,
            src_ip="192.168.1.1",
            dst_ip="10.0.0.1",
            protocol="TCP",
        )
        for _ in range(5)
    ]
    report = audit_dataset_feasibility(events, min_event_count=20)
    assert report.gate_passed is False
    assert report.recommendation == "REJECT_FORECASTING"
    assert any(c.check_name == "Sample Size Adequacy" and not c.passed for c in report.checks)


def test_feasibility_valid_balanced_dataset():
    base_time = datetime(2026, 2, 15, 10, 0, 0, tzinfo=timezone.utc)
    events: list[NormalizedEvent] = []

    for i in range(40):
        t = base_time + timedelta(seconds=i * 2)
        is_attack = i >= 30
        events.append(
            NormalizedEvent(
                source_id="sensor_bench",
                observed_at=t,
                event_type=EventType.NETWORK_FLOW,
                src_ip="192.168.1.10" if not is_attack else "172.16.0.5",
                dst_ip="10.0.0.1",
                protocol="TCP",
                label="Benign" if not is_attack else "SSH-BruteForce",
                label_provenance=LabelProvenance.DATASET_GROUND_TRUTH,
            )
        )

    report = audit_dataset_feasibility(events, min_event_count=25)
    assert report.gate_passed is True
    assert report.recommendation == "PERMIT_FORECASTING"
    assert report.overall_score >= 0.75
    assert all(c.passed for c in report.checks)
