"""
Unit tests for Database SQLite CRUD and Transactions.
"""

import tempfile
from pathlib import Path
from datetime import datetime, timezone
import pytest

from app.storage.database import Database
from app.schemas.events import (
    TelemetrySource,
    NormalizedEvent,
    EventType,
    DataCategory,
    LabelProvenance,
)


@pytest.fixture
def temp_db():
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


def test_source_lifecycle(temp_db: Database):
    src = TelemetrySource(
        source_id="src_1",
        name="Firewall Flow Ingest",
        source_type="csv_import",
        description="Test source",
    )
    temp_db.upsert_source(src)

    fetched = temp_db.get_source("src_1")
    assert fetched is not None
    assert fetched.name == "Firewall Flow Ingest"
    assert fetched.enabled is True

    sources = temp_db.list_sources()
    assert len(sources) == 1


def test_insert_and_query_events(temp_db: Database):
    src = TelemetrySource(source_id="src_1", name="Source 1", source_type="csv_import")
    temp_db.upsert_source(src)

    events = [
        NormalizedEvent(
            source_id="src_1",
            data_category=DataCategory.HISTORICAL_IMPORT,
            observed_at=datetime(2026, 2, 15, 12, 0, 0, tzinfo=timezone.utc),
            event_type=EventType.NETWORK_FLOW,
            src_ip="192.168.1.1",
            dst_ip="10.0.0.1",
            src_port=1000 + i,
            dst_port=80,
            protocol="TCP",
            label="Benign" if i % 2 == 0 else "PortScan",
        )
        for i in range(10)
    ]

    inserted = temp_db.insert_events(events)
    assert inserted == 10

    total_count = temp_db.count_events()
    assert total_count == 10

    portscan_events = temp_db.list_events(label="PortScan")
    assert len(portscan_events) == 5

    single = temp_db.get_event(events[0].event_id)
    assert single is not None
    assert single.event_id == events[0].event_id
