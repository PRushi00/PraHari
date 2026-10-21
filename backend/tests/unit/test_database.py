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


# ──────────────────────────────────────────────────────────────────
# Configuration fails closed on a store it cannot serve (ADR-094)
# ──────────────────────────────────────────────────────────────────


def test_a_non_sqlite_database_url_is_refused_not_silently_sqlite():
    """
    The trap this closes: `database_url` carries a scheme, so setting a
    PostgreSQL URL looks like configuring PostgreSQL. It used to fall back
    to `prahari.db` — the operator's live telemetry — and run on SQLite
    while appearing configured for something else.
    """
    from app.core.config import AppConfig, UnsupportedDatabaseURL

    for url in (
        "postgresql://user@host/prahari",
        "postgres://user@host/prahari",
        "mysql://user@host/prahari",
    ):
        config = AppConfig(database_url=url)
        with pytest.raises(UnsupportedDatabaseURL) as exc:
            config.get_database_path()
        # The refusal has to say why, and what does exist.
        assert "sqlite:///" in str(exc.value)
        assert "postgres" in str(exc.value).lower()


def test_a_sqlite_url_still_resolves_against_the_project_root():
    from app.core.config import AppConfig

    config = AppConfig(database_url="sqlite:///./prahari.db")
    resolved = config.get_database_path()
    assert resolved.is_absolute()
    assert resolved.name == "prahari.db"
    assert resolved.parent == config.project_root
