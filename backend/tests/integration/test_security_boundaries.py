"""
Security and operational-safety tests (blueprint section 12, DoD item 12).

These assert the boundaries the project commits to: loopback-only service
exposure, payload limits, input validation, no disruptive response, and no
leakage of sensitive local telemetry through unintended routes.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.api.deps import get_db
from app.core.config import AppConfig, get_config
from app.main import app
from app.storage.database import Database


@pytest.fixture
def client(tmp_path):
    db = Database(db_path=str(tmp_path / "sec.db"))
    db.initialize()
    app.dependency_overrides[get_db] = lambda: db
    with TestClient(app) as c:
        yield c, db
    app.dependency_overrides.clear()
    db.close()


# ──────────────────────────────────────────────────────────────────
# Service exposure
# ──────────────────────────────────────────────────────────────────


def test_default_binding_is_loopback():
    cfg = AppConfig()
    assert cfg.host in ("127.0.0.1", "localhost", "::1")


def test_security_config_reports_loopback_and_no_capture(client):
    c, _ = client
    cfg = c.get("/api/v1/audit/config").json()
    assert cfg["loopback_enforced"] is True
    assert cfg["security_boundaries"]["packet_capture_in_use"] is False
    assert cfg["security_boundaries"]["external_telemetry_transmission"] is False
    assert cfg["security_boundaries"]["service_exposure"] == "loopback_only"


def test_no_blocking_or_response_endpoints_exist(client):
    """
    PraHari must not offer automatic blocking, isolation or remediation.
    A route appearing here would be a disruptive-response capability.
    """
    c, _ = client
    paths = c.get("/openapi.json").json()["paths"].keys()
    forbidden = (
        "block", "quarantine", "isolate", "remediate", "firewall",
        "kill", "shutdown-host", "disable-adapter", "drop",
    )
    offenders = [p for p in paths for word in forbidden if word in p.lower()]
    assert not offenders, f"disruptive-response routes present: {offenders}"


def test_application_layer_ingest_is_opt_in(client):
    c, _ = client
    assert c.get("/api/v1/applayer/status").json()["enabled"] is False


# ──────────────────────────────────────────────────────────────────
# Input validation and payload limits
# ──────────────────────────────────────────────────────────────────


def test_oversized_dns_observation_batch_is_rejected(client):
    c, _ = client
    payload = [
        {
            "ip_address": "198.51.100.1",
            "hostname": f"host{i}.example.com",
            "observed_at": "2026-04-01T09:00:00Z",
        }
        for i in range(5001)
    ]
    res = c.post("/api/v1/enrichment/dns/observations", json=payload)
    assert res.status_code == 413


def test_pagination_limits_are_bounded(client):
    """An unbounded limit would allow a single request to dump the store."""
    c, _ = client
    assert c.get("/api/v1/events?limit=100000").status_code == 422
    assert c.get("/api/v1/events?limit=0").status_code == 422
    assert c.get("/api/v1/events?offset=-1").status_code == 422


def test_malformed_input_is_rejected_with_a_clear_error(client):
    c, _ = client
    bad_cases = [
        ("/api/v1/sources", {"source_id": "", "name": "x", "source_type": "y"}),
        ("/api/v1/sources", {"name": "missing id", "source_type": "y"}),
        ("/api/v1/import/csv/raw", {"source_id": "s"}),  # no csv_content
    ]
    for path, body in bad_cases:
        res = c.post(path, json=body)
        assert res.status_code == 422, f"{path} accepted invalid input"
        assert "detail" in res.json()


def test_invalid_port_and_ip_values_are_rejected_at_ingest(client):
    c, db = client
    csv = (
        "Src IP,Dst IP,Src Port,Dst Port,Protocol,Timestamp,Label\n"
        "999.999.999.999,10.0.0.1,80,443,6,2026-04-01 09:00:00,Benign\n"
        "10.0.0.1,10.0.0.2,70000,443,6,2026-04-01 09:00:01,Benign\n"
    )
    res = c.post(
        "/api/v1/import/csv/raw",
        json={"source_id": "sec_csv", "csv_content": csv},
    )
    assert res.status_code == 200
    summary = res.json()
    # Both rows are invalid and must be rejected, not coerced.
    assert summary["accepted_records"] == 0
    assert summary["rejected_records"] == 2
    assert summary["rejection_reasons"]


def test_unknown_api_route_returns_json_404_not_the_spa(client):
    c, _ = client
    res = c.get("/api/v1/definitely/not/a/route")
    assert res.status_code == 404
    assert res.headers["content-type"].startswith("application/json")


# ──────────────────────────────────────────────────────────────────
# Sensitive-data handling
# ──────────────────────────────────────────────────────────────────


def test_config_endpoint_does_not_leak_secrets(client):
    c, _ = client
    body = c.get("/api/v1/audit/config").json()
    flat = str(body).lower()
    for secret_marker in ("api_key", "password", "secret", "token"):
        assert secret_marker not in flat, f"config response exposes {secret_marker}"


def test_health_endpoint_does_not_expose_telemetry_contents(client):
    """Health may report counts; it must not return event records."""
    c, _ = client
    body = c.get("/api/v1/health").json()
    flat = str(body)
    assert "src_ip" not in flat and "dst_ip" not in flat
    assert set(body["database"].keys()) <= {
        "connected", "path", "sources_count", "events_count",
    }


def test_app_layer_payload_cannot_carry_credentials(client, tmp_path):
    """Credential-bearing fields have no schema slot and are rejected."""
    enabled = AppConfig(
        enable_application_layer_ingest=True,
        database_url=f"sqlite:///{tmp_path / 'sec.db'}",
    )
    app.dependency_overrides[get_config] = lambda: enabled
    try:
        c, _ = client
        for field in ("cookies", "authorization", "password", "request_body"):
            res = c.post("/api/v1/applayer/ingest", json={
                "producer": "test",
                "records": [{
                    "observed_at": "2026-04-01T09:00:00Z",
                    "method": "POST",
                    "url": "https://example.com/login",
                    field: "sensitive",
                }],
            })
            assert res.status_code == 422, f"{field} must be rejected"
    finally:
        app.dependency_overrides.pop(get_config, None)


def test_retention_setting_is_reported(client):
    """Retention behaviour must be visible even though pruning is not implemented."""
    c, _ = client
    cfg = c.get("/api/v1/audit/config").json()
    assert isinstance(cfg["retention_days"], int)
    assert cfg["security_boundaries"]["raw_payload_storage_enabled"] is False


# ──────────────────────────────────────────────────────────────────
# Database safety
# ──────────────────────────────────────────────────────────────────


def test_tests_never_target_the_operational_database():
    """
    The suite must not open the operator's live telemetry store. conftest
    pins PRAHARI_DATABASE_URL to a throwaway path.
    """
    import os

    url = os.environ.get("PRAHARI_DATABASE_URL", "")
    assert url, "tests must pin an isolated database URL"
    resolved = str(get_config().get_database_path()).lower()
    assert "prahari_test_session" in resolved or "tmp" in resolved or "temp" in resolved, (
        f"tests resolved to {resolved}, which may be the operational database"
    )


def test_foreign_key_enforcement_is_on(tmp_path):
    """Events must not be insertable for an unregistered source."""
    import sqlite3

    db = Database(db_path=str(tmp_path / "fk.db"))
    db.initialize()
    try:
        with db.get_connection() as conn:
            on = conn.execute("PRAGMA foreign_keys").fetchone()[0]
        assert on == 1
    finally:
        db.close()
