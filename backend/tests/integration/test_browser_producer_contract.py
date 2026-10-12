"""
Contract tests for the browser telemetry producer (extension/).

These verify that the payload the extension ACTUALLY builds is accepted by
the backend, and that the privacy rules hold at the API boundary.

Scope note: these prove the **integration contract**. They do not prove
that a real browser produced the data — installing the extension requires
an explicit user action, so genuine browser-sourced end-to-end verification
remains outstanding and is recorded as such in IMPLEMENTATION_STATUS.md.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.api.deps import get_db
from app.core.config import AppConfig, get_config
from app.main import app
from app.schemas.events import EventType, TelemetrySource
from app.storage.database import Database

EXTENSION_DIR = Path(__file__).resolve().parents[3] / "extension"
NOW = datetime(2026, 10, 12, 9, 0, 0, tzinfo=timezone.utc)


@pytest.fixture
def client_db(tmp_path):
    db = Database(db_path=str(tmp_path / "applayer.db"))
    db.initialize()
    app.dependency_overrides[get_db] = lambda: db
    enabled = AppConfig(
        enable_application_layer_ingest=True,
        applayer_retain_query_strings=False,
        database_url=f"sqlite:///{tmp_path / 'applayer.db'}",
    )
    app.dependency_overrides[get_config] = lambda: enabled
    with TestClient(app) as client:
        yield client, db
    app.dependency_overrides.clear()
    db.close()


def _extension_payload(records):
    """The exact envelope extension/background.js posts."""
    return {
        "source_id": "browser_probe",
        "source_name": "Browser Telemetry Probe (this profile)",
        "producer": "browser-extension",
        "records": records,
    }


# ──────────────────────────────────────────────────────────────────
# The extension source itself
# ──────────────────────────────────────────────────────────────────


def test_extension_files_exist():
    for name in ("manifest.json", "background.js", "popup.html", "popup.js"):
        assert (EXTENSION_DIR / name).exists(), f"missing extension/{name}"


def test_manifest_requests_only_the_permissions_it_needs():
    manifest = json.loads((EXTENSION_DIR / "manifest.json").read_text(encoding="utf-8"))

    assert manifest["manifest_version"] == 3
    # webRequest observes metadata. webRequestBlocking / declarativeNetRequest
    # would allow modifying traffic, which this probe must never do.
    assert set(manifest["permissions"]) <= {"webRequest", "storage", "alarms"}
    assert "webRequestBlocking" not in manifest["permissions"]
    assert "cookies" not in manifest["permissions"]
    assert "<all_urls>" not in manifest.get("host_permissions", [])

    # Only the local endpoint is granted by default; observing sites is an
    # OPTIONAL permission the user grants and can revoke.
    assert manifest["host_permissions"] == ["http://127.0.0.1:8000/*"]
    assert "optional_host_permissions" in manifest


def test_background_script_never_collects_sensitive_fields():
    src = (EXTENSION_DIR / "background.js").read_text(encoding="utf-8")

    # The payload builder must not reference any of these.
    posted = re.search(r"records:\s*batch\.map\(\(r\)\s*=>\s*\(\{(.*?)\}\)\)", src, re.S)
    assert posted, "could not locate the payload mapping"
    body = posted.group(1)

    for forbidden in (
        "requestHeaders", "responseHeaders", "requestBody", "cookie",
        "Cookie", "authorization", "search", "hash",
    ):
        assert forbidden not in body, f"payload must not include {forbidden}"

    # Query strings are discarded in the browser, before transmission.
    assert "u.pathname" in src
    assert "search" not in src.split("function minimalUrl")[1].split("}")[0]


def test_background_script_posts_only_to_the_configured_local_endpoint():
    src = (EXTENSION_DIR / "background.js").read_text(encoding="utf-8")
    urls = re.findall(r"https?://[^\s\"'`]+", src)
    external = [
        u for u in urls
        if "127.0.0.1" not in u and "localhost" not in u
    ]
    assert not external, f"extension must not contact external hosts: {external}"


def test_collection_is_off_by_default():
    src = (EXTENSION_DIR / "background.js").read_text(encoding="utf-8")
    assert re.search(r"enabled:\s*false", src), "collection must default to OFF"


# ──────────────────────────────────────────────────────────────────
# The backend accepts what the extension emits
# ──────────────────────────────────────────────────────────────────


def test_backend_accepts_the_exact_extension_payload(client_db):
    client, db = client_db
    payload = _extension_payload([
        {
            "observed_at": NOW.isoformat(),
            "method": "GET",
            "url": "https://docs.example.com/guide/intro",
            "status_code": 200,
            "duration_ms": 142,
            "dst_ip": "93.184.216.34",
            "dst_port": 443,
        }
    ])

    res = client.post("/api/v1/applayer/ingest", json=payload)
    assert res.status_code == 200, res.json()
    assert res.json()["accepted_records"] == 1

    ev = db.list_events(source_id="browser_probe", limit=5)[0]
    assert ev.event_type == EventType.HTTP_REQUEST
    assert ev.http_method == "GET"
    assert ev.http_status_code == 200
    assert ev.http_path == "/guide/intro"
    assert ev.dst_hostname == "docs.example.com"
    assert ev.app_protocol == "HTTPS"


def test_failed_request_reports_no_status_rather_than_a_fabricated_one(client_db):
    """
    chrome.webRequest.onErrorOccurred carries no HTTP status. Substituting
    one (say 0, or 500) would invent an observation.
    """
    client, db = client_db
    res = client.post("/api/v1/applayer/ingest", json=_extension_payload([
        {
            "observed_at": NOW.isoformat(),
            "method": "GET",
            "url": "https://unreachable.example.com/x",
            "status_code": None,
            "duration_ms": None,
            "dst_ip": None,
            "dst_port": 443,
        }
    ]))
    assert res.status_code == 200

    ev = db.list_events(source_id="browser_probe", limit=5)[0]
    assert ev.http_status_code is None
    assert ev.http_method == "GET"
    assert ev.dst_hostname == "unreachable.example.com"


def test_backend_rejects_a_producer_that_adds_sensitive_fields(client_db):
    """A misconfigured producer must fail loudly, not be silently trimmed."""
    client, _ = client_db
    for extra in ("cookies", "authorization", "request_body", "headers"):
        res = client.post("/api/v1/applayer/ingest", json=_extension_payload([
            {
                "observed_at": NOW.isoformat(),
                "method": "POST",
                "url": "https://example.com/login",
                extra: "sensitive",
            }
        ]))
        assert res.status_code == 422, f"{extra} must be rejected"


def test_query_strings_are_stripped_even_if_a_producer_sends_them(client_db):
    """
    The extension strips them in the browser; the backend strips them again.
    Defence in depth, because a different producer might not.
    """
    client, db = client_db
    client.post("/api/v1/applayer/ingest", json=_extension_payload([
        {
            "observed_at": NOW.isoformat(),
            "method": "GET",
            "url": "https://search.example.com/results?q=sensitive+terms&session=abc123",
            "status_code": 200,
        }
    ]))
    ev = db.list_events(source_id="browser_probe", limit=5)[0]
    assert ev.http_path == "/results"
    assert "sensitive" not in (ev.http_path or "")
    assert "abc123" not in (ev.http_path or "")


def test_batch_ingest_is_idempotent(client_db):
    """A retried batch must not duplicate rows."""
    client, db = client_db
    records = [
        {
            "observed_at": (NOW + timedelta(seconds=i)).isoformat(),
            "method": "GET",
            "url": f"https://example.com/page{i}",
            "status_code": 200,
        }
        for i in range(10)
    ]
    client.post("/api/v1/applayer/ingest", json=_extension_payload(records))
    client.post("/api/v1/applayer/ingest", json=_extension_payload(records))
    assert db.count_events(source_id="browser_probe") == 10


def test_app_layer_events_are_distinguishable_from_connection_telemetry(client_db):
    """
    HTTP metadata and TCP connection metadata must remain separate records
    with separate provenance, so neither is mistaken for the other.
    """
    client, db = client_db
    db.upsert_source(TelemetrySource(
        source_id="windows_local_host", name="Win",
        source_type="windows_connection_table",
    ))
    client.post("/api/v1/applayer/ingest", json=_extension_payload([
        {
            "observed_at": NOW.isoformat(), "method": "GET",
            "url": "https://example.com/a", "status_code": 200,
        }
    ]))

    http_events = db.list_events(source_id="browser_probe", limit=10)
    assert all(e.event_type == EventType.HTTP_REQUEST for e in http_events)

    caps = client.get("/api/v1/events/capabilities").json()
    by_type = {c["source_type"]: c for c in caps}
    assert by_type["application_layer"]["fields"]["http_status_code"] == "populated"
    assert (
        by_type["windows_connection_table"]["fields"]["http_status_code"]
        == "unsupported_by_source"
    )


def test_ingest_disabled_returns_an_actionable_refusal(tmp_path):
    """With the feature off, the endpoint must explain how to enable it."""
    db = Database(db_path=str(tmp_path / "off.db"))
    db.initialize()
    app.dependency_overrides[get_db] = lambda: db
    try:
        with TestClient(app) as client:
            res = client.post("/api/v1/applayer/ingest", json=_extension_payload([
                {"observed_at": NOW.isoformat(), "method": "GET", "url": "https://x.example/"}
            ]))
        assert res.status_code == 403
        detail = res.json()["detail"]
        assert detail["error"] == "application_layer_ingest_disabled"
        assert "PRAHARI_ENABLE_APPLICATION_LAYER_INGEST" in detail["how_to_enable"]
    finally:
        app.dependency_overrides.clear()
        db.close()
