"""
Tests for optional application-layer telemetry and the connection-intelligence API.

Key properties under test:

  * HTTP fields appear ONLY when an authorized application-layer source
    supplies them — never inferred from a port number by the TCP collector.
  * Disabling application-layer telemetry leaves ordinary TCP collection
    completely unaffected.
  * Bodies, cookies and credentials cannot be ingested even if sent.
  * Missing DNS evidence never prevents a connection from being stored.
"""

from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile

import pytest
from fastapi.testclient import TestClient

from app.api.deps import get_db
from app.core.config import AppConfig, get_config
from app.main import app
from app.schemas.events import (
    DataCategory,
    EventType,
    LabelProvenance,
    NormalizedEvent,
    QualityFlag,
    TelemetrySource,
)
from app.services.enrichment import reset_enrichment_service
from app.storage.database import Database

NOW = datetime(2026, 10, 11, 12, 0, 0, tzinfo=timezone.utc)


def _connection(i: int = 0, **kw) -> NormalizedEvent:
    defaults = dict(
        source_id="windows_local_host",
        data_category=DataCategory.LIVE_TELEMETRY,
        observed_at=NOW + timedelta(seconds=i * 5),
        event_type=EventType.CONNECTION,
        src_ip="192.0.2.10",
        dst_ip=f"93.184.216.{10 + i}",
        src_port=50000 + i,
        dst_port=443,
        protocol="TCP",
        quality_flags=[QualityFlag.SOURCE_LIMITED],
        raw_reference=f"windows:tcp;state=Established;pid={900 + i};process=msedge",
    )
    defaults.update(kw)
    return NormalizedEvent(**defaults)


@pytest.fixture
def client_db(tmp_path):
    db = Database(db_path=str(tmp_path / "api.db"))
    db.initialize()
    db.upsert_source(
        TelemetrySource(
            source_id="windows_local_host",
            name="Windows Local Host",
            source_type="windows_connection_table",
        )
    )
    reset_enrichment_service(db=db, query_fn=lambda: [])
    app.dependency_overrides[get_db] = lambda: db
    with TestClient(app) as client:
        yield client, db
    app.dependency_overrides.clear()
    reset_enrichment_service(None)
    db.close()


@pytest.fixture
def applayer_enabled(client_db):
    """Enable application-layer ingestion for one test."""
    client, db = client_db
    base = get_config()
    enabled = AppConfig(
        enable_application_layer_ingest=True,
        applayer_retain_query_strings=False,
        database_url=base.database_url,
    )
    app.dependency_overrides[get_config] = lambda: enabled
    yield client, db
    app.dependency_overrides.pop(get_config, None)


# ──────────────────────────────────────────────────────────────────
# Application-layer telemetry is opt-in
# ──────────────────────────────────────────────────────────────────


def test_applayer_disabled_by_default(client_db):
    client, _ = client_db
    status_res = client.get("/api/v1/applayer/status")
    assert status_res.status_code == 200
    assert status_res.json()["enabled"] is False

    res = client.post(
        "/api/v1/applayer/ingest",
        json={
            "producer": "browser-extension",
            "records": [
                {"observed_at": NOW.isoformat(), "method": "GET", "url": "https://example.com/a"}
            ],
        },
    )
    assert res.status_code == 403
    detail = res.json()["detail"]
    assert detail["error"] == "application_layer_ingest_disabled"
    assert "how_to_enable" in detail


def test_disabling_applayer_leaves_tcp_collection_working(client_db):
    """
    The optional feature must be genuinely optional: with it off, ordinary
    connection telemetry still ingests, persists and reports normally.
    """
    client, db = client_db
    db.insert_events([_connection(i) for i in range(5)])

    assert client.get("/api/v1/applayer/status").json()["enabled"] is False

    page = client.get("/api/v1/events?source_id=windows_local_host").json()
    assert page["total"] == 5

    conns = client.get("/api/v1/events/connections").json()
    assert conns["returned"] == 5
    assert all(c["event"]["http_method"] is None for c in conns["connections"])

    analysis = client.post("/api/v1/analysis/run", json={}).json()
    assert analysis["total_events"] == 5
    assert analysis["data_category"] == "live_telemetry"


def test_applayer_ingest_populates_http_fields_with_correct_provenance(applayer_enabled):
    client, db = applayer_enabled
    res = client.post(
        "/api/v1/applayer/ingest",
        json={
            "source_id": "browser_probe",
            "producer": "browser-extension",
            "records": [
                {
                    "observed_at": NOW.isoformat(),
                    "method": "get",
                    "url": "https://docs.example.com/guide/page",
                    "status_code": 200,
                    "duration_ms": 123.4,
                    "dst_ip": "93.184.216.34",
                    "dst_port": 443,
                }
            ],
        },
    )
    assert res.status_code == 200, res.json()
    assert res.json()["accepted_records"] == 1

    events = db.list_events(source_id="browser_probe", limit=10)
    assert len(events) == 1
    ev = events[0]
    assert ev.event_type == EventType.HTTP_REQUEST
    assert ev.http_method == "GET"
    assert ev.http_path == "/guide/page"
    assert ev.http_status_code == 200
    assert ev.http_duration_ms == 123.4
    assert ev.app_protocol == "HTTPS"
    # Hostname here is REPORTED by the producer, not inferred from DNS.
    assert ev.dst_hostname == "docs.example.com"
    assert ev.data_category == DataCategory.LIVE_TELEMETRY


def test_query_strings_are_stripped_by_default(applayer_enabled):
    """Query strings carry search terms and tokens, so they are removed."""
    client, db = applayer_enabled
    client.post(
        "/api/v1/applayer/ingest",
        json={
            "source_id": "browser_probe",
            "producer": "browser-extension",
            "records": [
                {
                    "observed_at": NOW.isoformat(),
                    "method": "GET",
                    "url": "https://search.example.com/results?q=private+search+terms&token=secret",
                }
            ],
        },
    )
    ev = db.list_events(source_id="browser_probe", limit=1)[0]
    assert ev.http_path == "/results"
    assert "q=" not in (ev.http_path or "")
    assert "secret" not in (ev.http_path or "")


def test_bodies_and_credentials_cannot_be_ingested(applayer_enabled):
    """
    The payload schema has no field for them, and unknown fields are
    rejected — so a misconfigured producer fails loudly rather than having
    secrets silently discarded.
    """
    client, _ = applayer_enabled
    for forbidden in ("body", "cookies", "authorization", "headers", "password"):
        res = client.post(
            "/api/v1/applayer/ingest",
            json={
                "producer": "browser-extension",
                "records": [
                    {
                        "observed_at": NOW.isoformat(),
                        "method": "POST",
                        "url": "https://example.com/login",
                        forbidden: "sensitive-value",
                    }
                ],
            },
        )
        assert res.status_code == 422, f"{forbidden} should be rejected"


def test_applayer_cannot_impersonate_the_connection_collector(applayer_enabled):
    client, _ = applayer_enabled
    res = client.post(
        "/api/v1/applayer/ingest",
        json={
            "source_id": "windows_local_host",
            "producer": "browser-extension",
            "records": [
                {"observed_at": NOW.isoformat(), "method": "GET", "url": "https://example.com/"}
            ],
        },
    )
    assert res.status_code == 422


def test_applayer_ingest_is_idempotent(applayer_enabled):
    client, db = applayer_enabled
    payload = {
        "source_id": "browser_probe",
        "producer": "browser-extension",
        "records": [
            {
                "observed_at": NOW.isoformat(),
                "method": "GET",
                "url": "https://example.com/x",
                "status_code": 200,
            }
        ],
    }
    client.post("/api/v1/applayer/ingest", json=payload)
    client.post("/api/v1/applayer/ingest", json=payload)
    assert db.count_events(source_id="browser_probe") == 1


# ──────────────────────────────────────────────────────────────────
# HTTP status codes are never invented from ports
# ──────────────────────────────────────────────────────────────────


def test_tcp_connections_never_carry_http_status_codes(client_db):
    """
    Port 443 is conventionally HTTPS, but a TCP observation says nothing
    about HTTP. No status code, method or path may appear.
    """
    client, db = client_db
    db.insert_events([_connection(i, dst_port=443) for i in range(3)])

    conns = client.get("/api/v1/events/connections").json()["connections"]
    assert len(conns) == 3
    for c in conns:
        ev = c["event"]
        assert ev["dst_port"] == 443
        assert ev["http_status_code"] is None
        assert ev["http_method"] is None
        assert ev["http_path"] is None
        assert ev["app_protocol"] is None
        # And the capability profile says why.
        assert "http_status_code" in c["unsupported_fields"]


def test_capabilities_endpoint_reports_what_each_source_can_provide(client_db):
    client, _ = client_db
    caps = client.get("/api/v1/events/capabilities").json()
    win = next(c for c in caps if c["source_type"] == "windows_connection_table")

    assert win["fields"]["dst_ip"] == "populated"
    assert win["fields"]["bytes_total"] == "unsupported_by_source"
    assert win["fields"]["http_status_code"] == "unsupported_by_source"
    assert any("byte counts" in l.lower() for l in win["limitations"])


# ──────────────────────────────────────────────────────────────────
# Connection intelligence
# ──────────────────────────────────────────────────────────────────


def test_connections_endpoint_decodes_process_and_state(client_db):
    client, db = client_db
    db.insert_events([
        _connection(0, raw_reference="windows:tcp;state=Established;pid=777;process=opera"),
        _connection(1, raw_reference="windows:tcp;state=CloseWait;pid=888;process=msedge"),
    ])
    conns = client.get("/api/v1/events/connections").json()["connections"]
    by_proc = {c["process_name"]: c for c in conns}

    assert by_proc["opera"]["connection_state"] == "Established"
    assert by_proc["opera"]["process_id"] == 777
    assert by_proc["msedge"]["connection_state"] == "CloseWait"


def test_missing_dns_evidence_does_not_block_connection_storage(client_db):
    """
    Enrichment is supplementary. With no DNS evidence at all, connections
    must still be stored and served — with the hostname honestly unknown.
    """
    client, db = client_db
    db.insert_events([_connection(i) for i in range(4)])

    conns = client.get("/api/v1/events/connections").json()
    assert conns["returned"] == 4
    for c in conns["connections"]:
        assert c["event"]["dst_ip"] is not None          # record intact
        attribution = c["domain_attribution"]
        assert attribution["hostname"] is None            # honestly unknown
        assert attribution["confidence"] == "none"
        assert attribution["limitations"]


def test_connection_filters_apply(client_db):
    client, db = client_db
    db.insert_events([
        _connection(0, dst_port=443, raw_reference="windows:tcp;state=Established;pid=1;process=opera"),
        _connection(1, dst_port=80, raw_reference="windows:tcp;state=Established;pid=2;process=msedge"),
        _connection(2, dst_port=443, raw_reference="windows:tcp;state=CloseWait;pid=3;process=opera"),
    ])

    assert client.get("/api/v1/events/connections?dst_port=443").json()["returned"] == 2
    assert client.get("/api/v1/events/connections?process=opera").json()["returned"] == 2
    assert client.get("/api/v1/events/connections?connection_state=CloseWait").json()["returned"] == 1
    assert client.get("/api/v1/events/connections?protocol=TCP").json()["returned"] == 3
    assert client.get("/api/v1/events/connections?protocol=UDP").json()["returned"] == 0


def test_connections_report_applied_filters(client_db):
    client, db = client_db
    db.insert_events([_connection(0)])
    body = client.get("/api/v1/events/connections?dst_port=443&protocol=TCP").json()
    assert body["filters_applied"] == {"dst_port": 443, "protocol": "TCP"}


def test_events_can_be_filtered_by_data_category(client_db):
    client, db = client_db
    db.upsert_source(
        TelemetrySource(source_id="csv_src", name="CSV", source_type="csv_import")
    )
    db.insert_events([_connection(i) for i in range(3)])
    db.insert_events([
        NormalizedEvent(
            source_id="csv_src",
            data_category=DataCategory.HISTORICAL_IMPORT,
            observed_at=NOW,
            event_type=EventType.NETWORK_FLOW,
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=1234,
            dst_port=80,
            protocol="TCP",
        )
    ])

    live = client.get("/api/v1/events?data_category=live_telemetry").json()
    hist = client.get("/api/v1/events?data_category=historical_import").json()
    assert live["total"] == 3
    assert hist["total"] == 1

    stats = client.get("/api/v1/events/stats/summary").json()
    assert stats["data_categories"] == {"live_telemetry": 3, "historical_import": 1}


def test_mixed_sources_analysis_is_reported_as_mixed_via_api(client_db):
    client, db = client_db
    db.upsert_source(
        TelemetrySource(source_id="csv_src", name="CSV", source_type="csv_import")
    )
    db.insert_events([_connection(i) for i in range(2)])
    db.insert_events([
        NormalizedEvent(
            source_id="csv_src",
            data_category=DataCategory.HISTORICAL_IMPORT,
            observed_at=NOW,
            event_type=EventType.NETWORK_FLOW,
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=1,
            dst_port=80,
            protocol="TCP",
            bytes_total=100,
            packets=2,
            duration=0.5,
        )
    ])

    analysis = client.post("/api/v1/analysis/run", json={}).json()
    assert analysis["is_mixed_provenance"] is True
    assert analysis["data_category"] == "mixed"
    assert analysis["data_categories"] == {"live_telemetry": 2, "historical_import": 1}


def test_stale_analysis_is_recomputed_rather_than_served_as_current(client_db):
    """A saved snapshot must not be presented as describing current data."""
    client, db = client_db
    db.insert_events([_connection(i) for i in range(3)])
    first = client.post("/api/v1/analysis/run", json={}).json()
    assert first["total_events"] == 3

    db.insert_events([_connection(i) for i in range(10, 15)])
    latest = client.get("/api/v1/analysis/latest").json()
    assert latest["total_events"] == 8


def test_enrichment_status_endpoint_reports_limits(client_db):
    client, _ = client_db
    body = client.get("/api/v1/enrichment/status").json()
    joined = " ".join(body["limitations"]).lower()
    assert "reverse dns" in joined
    assert "inferred" in joined
    assert body["method"] == "dns_cache_observation"


def test_submitted_dns_evidence_produces_attribution(client_db):
    client, _ = client_db
    res = client.post(
        "/api/v1/enrichment/dns/observations",
        json=[
            {
                "ip_address": "93.184.216.10",
                "hostname": "example.com",
                "observed_at": datetime.now(timezone.utc).isoformat(),
                "ttl_seconds": 300,
            }
        ],
    )
    assert res.status_code == 201
    assert res.json()["recorded"] == 1

    body = client.get("/api/v1/enrichment/ip/93.184.216.10").json()
    assert body["attribution"]["hostname"] == "example.com"
    assert body["attribution"]["identifies_requested_host"] is True
    assert len(body["observations"]) == 1


# ──────────────────────────────────────────────────────────────────
# Paginated totals must agree with the rows they accompany
# ──────────────────────────────────────────────────────────────────


def test_total_honours_the_event_type_filter(client_db):
    """
    Regression: count_events ignored event_type, so a filtered query
    reported the UNFILTERED total — the dashboard showed "3,252 total"
    beside zero rows.
    """
    client, db = client_db
    db.insert_events([_connection(i) for i in range(6)])

    # No HTTP events exist, so a filtered query must report zero.
    body = client.get("/api/v1/events?event_type=http_request").json()
    assert body["total"] == 0
    assert body["events"] == []

    # The connection type matches everything stored.
    body = client.get("/api/v1/events?event_type=connection").json()
    assert body["total"] == 6
    assert len(body["events"]) == 6


def test_total_matches_rows_for_every_filter_combination(client_db):
    client, db = client_db
    db.upsert_source(
        TelemetrySource(source_id="csv_src", name="CSV", source_type="csv_import")
    )
    db.insert_events([_connection(i) for i in range(4)])
    db.insert_events([
        NormalizedEvent(
            source_id="csv_src",
            data_category=DataCategory.HISTORICAL_IMPORT,
            observed_at=NOW,
            event_type=EventType.NETWORK_FLOW,
            src_ip="10.0.0.1", dst_ip="10.0.0.2",
            src_port=1 + i, dst_port=80, protocol="TCP",
            label="Benign",
        )
        for i in range(3)
    ])

    for query in (
        "?",
        "?event_type=connection",
        "?event_type=network_flow",
        "?data_category=live_telemetry",
        "?data_category=historical_import",
        "?source_id=csv_src",
        "?source_id=csv_src&event_type=network_flow",
        "?event_type=connection&data_category=live_telemetry",
        "?label=Benign",
        "?event_type=connection&data_category=historical_import",  # empty set
    ):
        url = f"/api/v1/events{query}&limit=500".replace("?&", "?")
        body = client.get(url).json()
        assert body["total"] == len(body["events"]), (
            f"total disagrees with rows for {query!r}: "
            f"{body['total']} vs {len(body['events'])}"
        )


def test_pagination_total_is_the_full_filtered_count_not_the_page_size(client_db):
    """With paging, total is the whole filtered set — rows are just a page."""
    client, db = client_db
    db.insert_events([_connection(i) for i in range(10)])

    page = client.get("/api/v1/events?event_type=connection&limit=3").json()
    assert page["total"] == 10
    assert len(page["events"]) == 3
