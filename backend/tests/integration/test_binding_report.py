"""
PraHari — The Dashboard's Network-Isolation Claim Is Measured (ADR-078).

Found in a real browser during Windows validation: a server listening on
127.0.0.1:18765 displayed "LOOPBACK ENFORCED - Binding: 127.0.0.1:8000".

Two defects:
* `/audit/config` reported the CONFIGURED host and port. uvicorn's --host
  and --port do not update configuration, so another port, or a 0.0.0.0
  bind, was reported as 127.0.0.1:8000 and as loopback-only.
* The dashboard printed LOOPBACK ENFORCED unconditionally; it never read
  `loopback_enforced` at all.

The application cannot observe its own bind address, but each request
records the local address it arrived on. These tests drive requests that
arrive on chosen addresses and check what the report may then claim.
Temporary database only.
"""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.deps import get_db
from app.api.v1.router import api_v1_router
from app.core.config import AppConfig, get_config
from app.storage.database import Database


@pytest.fixture
def make_client(tmp_path):
    db = Database(db_path=str(tmp_path / "binding.db"))
    db.initialize()

    def _client(base_url: str, **config) -> TestClient:
        app = FastAPI()
        app.include_router(api_v1_router, prefix="/api/v1")
        app.dependency_overrides[get_db] = lambda: db
        app.dependency_overrides[get_config] = lambda: AppConfig(**config)
        return TestClient(app, base_url=base_url)

    yield _client
    db.close()


def _report(client: TestClient) -> dict:
    r = client.get("/api/v1/audit/config")
    assert r.status_code == 200, r.text
    return r.json()


def test_the_serving_port_is_measured_not_configured(make_client):
    body = _report(make_client("http://127.0.0.1:18765"))

    assert body["port"] == 8000, "configuration, still reported as such"
    assert body["serving_port"] == 18765, "the port the request really arrived on"
    assert body["serving_host"] == "127.0.0.1"


def test_a_port_mismatch_is_reported_as_unverified(make_client):
    body = _report(make_client("http://127.0.0.1:18765"))

    assert body["listener_matches_configuration"] is False
    assert body["binding_evidence"].startswith("UNVERIFIED")
    # The review's scenario: `uvicorn --host 0.0.0.0 --port 18765` without the
    # launcher, browsed over loopback. Loopback must not be claimed (ADR-089).
    assert body["loopback_enforced"] is None
    assert body["security_boundaries"]["service_exposure"] == "loopback_configured_unverified"


def test_matching_configuration_is_reported_as_configured_not_proven(make_client):
    body = _report(make_client("http://127.0.0.1:8000"))

    assert body["listener_matches_configuration"] is True
    assert body["loopback_enforced"] is True
    assert body["binding_evidence"].startswith("CONFIGURED")
    assert "not observable" in body["binding_evidence"], (
        "arrival on loopback does not prove a loopback-only bind"
    )


def test_arrival_on_a_non_loopback_address_proves_exposure(make_client):
    """
    A 0.0.0.0 bind with the default configuration: the old report said
    loopback-only. A request arriving on a LAN address disproves that.
    """
    body = _report(make_client("http://192.0.2.50:8000"))

    assert body["loopback_enforced"] is False
    assert body["binding_evidence"].startswith("EXPOSED")
    assert body["security_boundaries"]["service_exposure"] == "reachable_on_192.0.2.50"


def test_ipv6_loopback_arrival_is_not_exposure(make_client):
    body = _report(make_client("http://[::1]:8000"))

    assert body["loopback_enforced"] is True
    assert not body["binding_evidence"].startswith("EXPOSED")


def test_a_non_address_host_is_no_evidence_either_way(make_client):
    """A test client's 'testserver' must neither prove nor disprove exposure."""
    body = _report(make_client("http://testserver"))

    assert body["loopback_enforced"] is None, "no evidence either way is None, not True"
    assert not body["binding_evidence"].startswith("EXPOSED")


def test_an_ipv4_mapped_loopback_arrival_is_loopback(make_client):
    """A dual-stack bind reports a local IPv4 client as ::ffff:127.0.0.1."""
    body = _report(make_client("http://[::ffff:127.0.0.1]:8000"))

    assert body["loopback_enforced"] is True
    assert not body["binding_evidence"].startswith("EXPOSED")


def test_a_configured_non_loopback_host_is_never_called_loopback(make_client):
    body = _report(make_client("http://127.0.0.1:8000", host="0.0.0.0"))

    assert body["loopback_enforced"] is False
    assert body["security_boundaries"]["service_exposure"] == "bound_to_0.0.0.0"


def test_configuration_from_the_environment_matches_a_launcher_start(monkeypatch, make_client):
    """What start_prahari.ps1 now does: pass --host/--port into configuration."""
    monkeypatch.setenv("PRAHARI_HOST", "127.0.0.1")
    monkeypatch.setenv("PRAHARI_PORT", "18765")
    cfg = AppConfig()
    assert (cfg.host, cfg.port) == ("127.0.0.1", 18765)

    body = _report(make_client("http://127.0.0.1:18765", host=cfg.host, port=cfg.port))
    assert body["listener_matches_configuration"] is True
