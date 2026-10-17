"""
PraHari — Live Windows Host-Observation and DNS Endpoints.

The Linux revision (4360ca3) added a platform gate to the DNS endpoints
and the collector's DNS refresh. These tests prove, on a real Windows
host, that the gate did not switch Windows off: each endpoint is called
through the API and answered from the genuine OS facility -
Get-NetUDPEndpoint, Get-NetAdapterStatistics and the DNS client cache.

What they read is local and read-only. Nothing is sent to the network and
no setting is changed. Everything that persists goes into a temporary
database that is deleted afterwards; the operational databases are never
opened, and the application's collector is not involved.

Marked `live_windows`: they need a real Windows host and skip elsewhere.
"""

from __future__ import annotations

import sys

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.deps import get_db
from app.api.v1.router import api_v1_router
from app.core.config import AppConfig, get_config
from app.services.enrichment import reset_enrichment_service
from app.storage.database import Database

pytestmark = [
    pytest.mark.live_windows,
    pytest.mark.skipif(sys.platform != "win32", reason="requires a real Windows host"),
]

UDP_SOURCE = "windows_udp_endpoints"


@pytest.fixture
def live(tmp_path):
    db = Database(db_path=str(tmp_path / "live-hostobs.db"))
    db.initialize()
    app = FastAPI()
    app.include_router(api_v1_router, prefix="/api/v1")
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[get_config] = lambda: AppConfig()
    yield TestClient(app), db
    reset_enrichment_service()  # drop the singleton's reference to this db
    db.close()


def test_capabilities_report_windows_sources_as_available(live):
    client, _ = live
    r = client.get("/api/v1/hostobs/capabilities")

    assert r.status_code == 200
    caps = r.json()
    assert caps, "no capability reported"
    text = str(caps).lower()
    assert "udp" in text and "interface" in text


def test_a_udp_poll_without_persist_reads_real_sockets_and_stores_nothing(live):
    client, db = live
    r = client.post("/api/v1/hostobs/udp/poll", params={"persist": "false"})

    assert r.status_code == 200, r.text
    body = r.json()
    assert body["endpoints_observed"] > 0, "a Windows host always has bound UDP sockets"
    assert body["events_normalized"] > 0
    assert body["events_persisted"] == 0
    assert db.count_events() == 0


def test_a_persisted_udp_poll_is_idempotent_on_repeat(live):
    client, db = live
    first = client.post("/api/v1/hostobs/udp/poll").json()
    stored = db.count_events()

    assert first["events_persisted"] > 0
    assert stored == first["events_persisted"]
    for ev in db.list_events(limit=50):
        assert ev.dst_ip is None, "a UDP endpoint has no remote peer to report"

    second = client.post("/api/v1/hostobs/udp/poll").json()

    # Exact accounting: every stored row is accounted for by a persist count,
    # so a socket still bound on the second poll was NOT stored again.
    # Sockets opened between the polls are legitimately new.
    assert db.count_events() == first["events_persisted"] + second["events_persisted"]
    with db.get_connection() as conn:
        ids = [r[0] for r in conn.execute("SELECT event_id FROM normalized_events")]
    assert len(ids) == len(set(ids)), "an endpoint was stored twice"
    assert second["events_persisted"] < second["endpoints_observed"], (
        "most sockets survive between two polls a moment apart; if none was "
        "recognised as already stored, deduplication is not working"
    )


def test_interface_counters_are_real_and_declare_their_scope(live):
    client, _ = live
    r = client.get("/api/v1/hostobs/interfaces")

    assert r.status_code == 200, r.text
    snap = r.json()
    assert snap["measurement_scope"] == "interface_cumulative"
    assert snap["attributable_to_flow"] is False
    assert snap["attributable_to_process"] is False
    assert snap["interfaces"], "no network adapter reported"
    for iface in snap["interfaces"]:
        assert iface["name"]
        assert iface["received_bytes"] >= 0 and iface["sent_bytes"] >= 0


def test_dns_diagnosis_runs_the_windows_path_not_the_gate(live):
    client, _ = live
    body = client.get("/api/v1/enrichment/dns/diagnose").json()

    for key in ("checked_at", "cache_entries", "likely_causes", "conclusion"):
        assert key in body
    assert "unavailable on platform" not in (body.get("error") or "")
    assert "unavailable on platform" not in body["conclusion"]


def test_dns_refresh_reads_the_cache_and_records_into_temporary_storage(live):
    client, db = live
    r = client.post("/api/v1/enrichment/dns/refresh")

    assert r.status_code == 200, r.text
    body = r.json()
    assert "unavailable on platform" not in (body.get("error") or "")
    if body["succeeded"]:
        assert body["observations_recorded"] == db.count_dns_observations()
        assert body["address_records"] <= body["entries_read"]
    else:
        # A Windows host can legitimately have an empty or unreadable cache;
        # then the failure must say why, not fail silently.
        assert body["error"] or body["diagnosis"]
