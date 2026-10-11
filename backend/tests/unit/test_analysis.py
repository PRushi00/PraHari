"""
Unit tests for Descriptive Analysis computation.
"""

from datetime import datetime, timezone
import pytest

from app.schemas.events import NormalizedEvent, EventType, DataCategory, QualityFlag
from app.services.analysis import compute_descriptive_analysis


def test_compute_descriptive_analysis():
    events = [
        NormalizedEvent(
            source_id="sensor_a",
            data_category=DataCategory.HISTORICAL_IMPORT,
            observed_at=datetime(2026, 2, 15, 10, i, 0, tzinfo=timezone.utc),
            event_type=EventType.NETWORK_FLOW,
            src_ip="192.168.1.10",
            dst_ip="10.0.0.1",
            src_port=40000 + i,
            dst_port=443 if i < 3 else 80,
            protocol="TCP",
            duration=100.0 * (i + 1),
            packets=10 * (i + 1),
            bytes_total=500 * (i + 1),
            label="Benign" if i < 4 else "DDoS-HOIC",
            quality_flags=[QualityFlag.TIMESTAMP_UNCERTAINTY] if i == 0 else [],
        )
        for i in range(5)
    ]

    analysis = compute_descriptive_analysis(events, source_id="sensor_a")

    assert analysis.total_events == 5
    assert analysis.events_by_type["network_flow"] == 5
    assert analysis.events_by_label["Benign"] == 4
    assert analysis.events_by_label["DDoS-HOIC"] == 1
    assert analysis.unique_src_ips == 1
    assert analysis.unique_dst_ips == 1
    assert analysis.unique_dst_ports == 2
    assert analysis.records_with_warnings == 1
    assert analysis.quality_flag_counts["timestamp_uncertainty"] == 1
    assert analysis.avg_duration == 300.0  # (100+200+300+400+500)/5
    assert analysis.total_bytes == 7500
