"""
DNS-Client event log, end to end (ADR-120).

The unit tests cover the parser. These cover the thing the parser exists
for: that a real record read from the channel reaches the observation
store, is deduplicated by storage rather than by hope, is told apart
from cache evidence by `method`, and surfaces as a hostname attribution
labelled `dns_query_log`.

The collection half is stubbed at `subprocess.run`, because it needs
Windows and an enabled channel. Everything from the raw record onward —
parse, store, dedupe, attribute — is the real code path.
"""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.api.deps import get_db
from app.storage.database import Database


#: The record captured on the operator's real machine (ADR-119), plus an
#: external lookup in the same shape. Nothing here is invented beyond
#: substituting a public name and address into the observed field layout.
REAL_3008 = {
    "Id": 3008,
    "TimeCreated": "2026-10-22T12:09:56.4674908Z",
    "ProcessId": "13268",
    "QueryName": "localhost",
    "QueryType": "1",
    "QueryOptions": "720575941721587776",
    "QueryStatus": "0",
    "QueryResults": "127.0.0.1;",
}

EXTERNAL_3008 = {
    **REAL_3008,
    "TimeCreated": "2026-10-22T12:10:30.1234567Z",
    "QueryName": "example.com",
    "QueryResults": "93.184.216.34;",
}


@pytest.fixture()
def client(tmp_path):
    db = Database(str(tmp_path / "dns_events.db"))
    db.initialize()
    app.dependency_overrides[get_db] = lambda: db
    with TestClient(app) as c:
        yield c, db
    app.dependency_overrides.clear()


def _stub_powershell(monkeypatch, records: list[dict]):
    import subprocess as sp

    class _Proc:
        returncode = 0
        stdout = json.dumps({"records": records})
        stderr = ""

    monkeypatch.setattr(sp, "run", lambda *a, **k: _Proc())


def test_a_real_record_reaches_the_observation_store(client, monkeypatch):
    c, db = client
    _stub_powershell(monkeypatch, [REAL_3008, EXTERNAL_3008])

    res = c.post("/api/v1/enrichment/dns/events/collect")
    assert res.status_code == 200, res.text
    body = res.json()

    assert body["succeeded"] is True
    assert body["records_read"] == 2
    assert body["successful_records"] == 2
    assert body["observations_recorded"] == 2
    assert db.count_dns_observations() == 2

    stored = db.get_dns_observations_for_ip("93.184.216.34")
    assert stored, "the external resolution was not stored"
    assert stored[0]["hostname"] == "example.com"
    assert stored[0]["method"] == "dns_query_log"


def test_re_reading_an_overlapping_window_stores_nothing_twice(client, monkeypatch):
    """
    The circular log is re-read on every collection, so overlap is the
    normal case, not an edge one. Storage deduplicates on
    UNIQUE(ip_address, hostname, observed_at).
    """
    c, db = client
    _stub_powershell(monkeypatch, [REAL_3008, EXTERNAL_3008])

    first = c.post("/api/v1/enrichment/dns/events/collect").json()
    second = c.post("/api/v1/enrichment/dns/events/collect").json()

    assert first["observations_recorded"] == 2
    assert second["records_read"] == 2, "the second read saw the same records"
    assert second["observations_recorded"] == 0, "a duplicate was stored"
    assert db.count_dns_observations() == 2


def test_event_log_evidence_does_not_disturb_cache_evidence(client, monkeypatch):
    """
    Both sources write the same table. Enabling this one must leave the
    cache path's rows exactly as they were — they are told apart by
    `method`, not kept in separate stores.
    """
    c, db = client
    db.record_dns_observations(
        [
            {
                "ip_address": "93.184.216.34",
                "hostname": "cached.example.com",
                "observed_at": "2026-10-22T11:00:00+00:00",
                "method": "dns_cache_observation",
                "ttl_seconds": 300,
                "source_id": "windows_dns_cache",
            }
        ]
    )
    _stub_powershell(monkeypatch, [EXTERNAL_3008])
    c.post("/api/v1/enrichment/dns/events/collect")

    rows = db.get_dns_observations_for_ip("93.184.216.34")
    methods = {r["method"] for r in rows}
    assert methods == {"dns_cache_observation", "dns_query_log"}, (
        "one evidence source overwrote the other"
    )
    cached = [r for r in rows if r["method"] == "dns_cache_observation"][0]
    assert cached["hostname"] == "cached.example.com"
    assert cached["ttl_seconds"] == 300


def test_an_attribution_reports_the_event_log_as_its_method(client, monkeypatch):
    """
    The point of collecting at all: a stored observation becomes a
    hostname on a connection, carrying the evidence that produced it.
    """
    c, _ = client
    _stub_powershell(monkeypatch, [EXTERNAL_3008])
    c.post("/api/v1/enrichment/dns/events/collect")

    res = c.get("/api/v1/enrichment/ip/93.184.216.34")
    assert res.status_code == 200, res.text
    attribution = res.json()["attribution"]
    assert attribution["hostname"] == "example.com"
    assert attribution["method"] == "dns_query_log", (
        "event-log evidence was mislabelled as another method"
    )


def test_uninterpreted_event_ids_are_reported_not_hidden(client, monkeypatch):
    c, db = client
    _stub_powershell(
        monkeypatch,
        [REAL_3008, {**REAL_3008, "Id": 3006}, {**REAL_3008, "Id": 1001}],
    )

    body = c.post("/api/v1/enrichment/dns/events/collect").json()

    assert body["records_read"] == 3
    assert body["uninterpreted_by_event_id"] == {"3006": 1, "1001": 1}
    assert any("would be a guess" in n for n in body["notes"])
    # Only the one interpretable record produced a row.
    assert db.count_dns_observations() == 1


@pytest.mark.parametrize(
    ("error_payload", "expected"),
    [
        ("channel_absent", "does not exist on this host"),
        ("channel_disabled", "disabled, which is the Windows"),
    ],
)
def test_an_unavailable_channel_reports_its_specific_reason(
    client, monkeypatch, error_payload, expected
):
    """
    Absent and disabled are different operator actions. The endpoint
    returns 200 with `succeeded: false` and the reason — this is a
    statement about the host, not a server error.
    """
    c, db = client
    import subprocess as sp

    class _Proc:
        returncode = 0
        stdout = json.dumps({"error": error_payload})
        stderr = ""

    monkeypatch.setattr(sp, "run", lambda *a, **k: _Proc())

    res = c.post("/api/v1/enrichment/dns/events/collect")
    assert res.status_code == 200
    body = res.json()
    assert body["succeeded"] is False
    assert expected in body["error"]
    assert db.count_dns_observations() == 0


def test_the_endpoint_bounds_how_much_of_the_log_it_will_read(client):
    c, _ = client
    assert c.post("/api/v1/enrichment/dns/events/collect?max_events=0").status_code == 422
    assert c.post("/api/v1/enrichment/dns/events/collect?max_events=99999").status_code == 422


def test_the_cache_refresh_endpoint_still_behaves_as_before(client):
    """
    Requirement: do not break the existing DNS-cache enrichment. Off
    Windows it reports `succeeded: false` with a reason and spawns
    nothing — unchanged by this work.
    """
    c, _ = client
    res = c.post("/api/v1/enrichment/dns/refresh")
    assert res.status_code == 200
    assert res.json()["succeeded"] is False
