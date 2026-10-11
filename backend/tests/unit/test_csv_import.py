"""
Unit tests for CSV Import Adapter and validation logic.
"""

from pathlib import Path
import pytest

from app.adapters.csv_import import (
    CsvImportAdapter,
    import_csv_file,
    import_csv_string,
    validate_and_normalize_row,
)
from app.schemas.events import DataCategory, EventType


def test_validate_and_normalize_valid_row():
    row = {
        "Src IP": "192.168.1.10",
        "Dst IP": "10.0.0.1",
        "Src Port": "45000",
        "Dst Port": "443",
        "Protocol": "6",
        "Timestamp": "2026-02-15 10:00:00",
        "Flow Duration": "150000",
        "Tot Fwd Pkts": "10",
        "TotLen Fwd Pkts": "2400",
        "Label": "Benign",
    }
    result = validate_and_normalize_row(
        row=row,
        row_index=1,
        source_id="test_source",
        data_category=DataCategory.HISTORICAL_IMPORT,
    )
    assert result.is_valid is True
    assert result.event is not None
    assert result.event.src_ip == "192.168.1.10"
    assert result.event.dst_ip == "10.0.0.1"
    assert result.event.src_port == 45000
    assert result.event.dst_port == 443
    assert result.event.protocol == "TCP"
    assert result.event.duration == 150000.0
    assert result.event.packets == 10
    assert result.event.bytes_total == 2400
    assert result.event.label == "Benign"


def test_reject_invalid_ip():
    row = {
        "Src IP": "999.999.999.999",
        "Dst IP": "10.0.0.1",
        "Src Port": "45000",
        "Dst Port": "443",
        "Protocol": "6",
        "Timestamp": "2026-02-15 10:00:00",
    }
    result = validate_and_normalize_row(
        row=row,
        row_index=2,
        source_id="test_source",
    )
    assert result.is_valid is False
    assert any("src_ip" in err.lower() for err in result.errors)


def test_reject_invalid_port():
    row = {
        "Src IP": "192.168.1.10",
        "Dst IP": "10.0.0.1",
        "Src Port": "70000",
        "Dst Port": "443",
        "Protocol": "6",
        "Timestamp": "2026-02-15 10:00:00",
    }
    result = validate_and_normalize_row(
        row=row,
        row_index=3,
        source_id="test_source",
    )
    assert result.is_valid is False
    assert any("port" in err.lower() for err in result.errors)


def test_import_csv_file_fixture():
    fixture_path = Path(__file__).parent.parent / "fixtures" / "sample_flows.csv"
    assert fixture_path.exists(), f"Fixture not found at {fixture_path}"

    adapter = CsvImportAdapter()
    events, summary = adapter.import_file(
        file_path=fixture_path,
        source_id="fixture_source",
    )

    assert summary.total_records == 45
    assert summary.accepted_records == 35
    assert summary.rejected_records == 10
    assert len(events) == 35
    assert "file_not_found" not in summary.rejection_reasons
    # Verify rejection keys are meaningful categories, NOT row prefixes like 'Row 36'
    assert not any(key.startswith("Row ") for key in summary.rejection_reasons.keys())
    assert "missing or invalid src_ip" in summary.rejection_reasons or "invalid src_ip" in summary.rejection_reasons


def test_rejection_reasons_grouping_regression():
    csv_data = """Src IP,Dst IP,Src Port,Dst Port,Protocol,Timestamp,Flow Duration,Tot Fwd Pkts,TotLen Fwd Pkts,Label
999.1.1.1,10.0.0.1,5000,443,6,2026-02-15 10:00:00,100,1,64,Benign
192.168.1.1,10.0.0.1,70000,443,6,2026-02-15 10:00:00,100,1,64,Benign
192.168.1.2,10.0.0.1,5000,443,6,invalid_time,100,1,64,Benign
"""
    adapter = CsvImportAdapter()
    _, summary = adapter.import_string(csv_data, source_id="test_rejection_src")
    assert summary.total_records == 3
    assert summary.accepted_records == 0
    assert summary.rejected_records == 3
    # Ensure no row indices in keys
    for key in summary.rejection_reasons.keys():
        assert not key.startswith("Row ")
    assert "missing or invalid src_ip" in summary.rejection_reasons or "invalid src_ip" in summary.rejection_reasons
    assert "invalid src_port" in summary.rejection_reasons
    assert "invalid or missing timestamp" in summary.rejection_reasons

