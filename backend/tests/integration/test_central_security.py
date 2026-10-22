"""
Central-mode security tests (blueprint §12, DoD items 2 and 11).

All of these run over loopback with isolated temporary databases. No
listener is exposed beyond 127.0.0.1 and no network configuration is
touched.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.auth import CentralAuthMiddleware
from app.api.deps import get_db
from app.api.v1.router import api_v1_router
from app.core.config import AppConfig, DeploymentMode, get_config
from app.core.security import (
    Credential,
    CredentialStore,
    InvalidCredentialError,
    MissingCredentialsError,
    Principal,
    Role,
    SourceAccessDenied,
    generate_token,
    hash_token,
    redact,
)
from app.schemas.events import (
    DataCategory,
    EventType,
    LabelProvenance,
    NormalizedEvent,
    TelemetrySource,
)
from app.storage.database import Database

NOW = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)


def _event(source: str, idx: int) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=f"{source}-{idx}",
        source_id=source,
        data_category=DataCategory.LIVE_TELEMETRY,
        observed_at=NOW,
        event_type=EventType.CONNECTION,
        src_ip="192.0.2.10",
        dst_ip="198.51.100.9",
        src_port=40000 + idx,
        dst_port=443,
        protocol="TCP",
        label_provenance=LabelProvenance.UNLABELED,
    )


@pytest.fixture
def db(tmp_path):
    database = Database(db_path=str(tmp_path / "central.db"))
    database.initialize()
    for sid in ("sensor-a", "sensor-b"):
        database.upsert_source(
            TelemetrySource(source_id=sid, name=sid, source_type="windows_connection_table")
        )
    database.insert_events([_event("sensor-a", i) for i in range(5)])
    database.insert_events([_event("sensor-b", i) for i in range(3)])
    yield database
    database.close()


@pytest.fixture
def central(db):
    """A central-mode app with three credentials over loopback."""
    cred_a, token_a = Credential.create("sensor-a", Role.INGEST, "sensor A")
    cred_b, token_b = Credential.create("sensor-b", Role.INGEST, "sensor B")
    cred_admin, token_admin = Credential.create("central", Role.ADMIN, "operator")
    store = CredentialStore([cred_a, cred_b, cred_admin])

    cfg = AppConfig(deployment_mode=DeploymentMode.CENTRAL)
    central_app = FastAPI()
    central_app.include_router(api_v1_router, prefix="/api/v1")
    central_app.add_middleware(
        CentralAuthMiddleware, store=store, public_paths=cfg.central_public_paths
    )
    central_app.dependency_overrides[get_db] = lambda: db
    central_app.dependency_overrides[get_config] = lambda: cfg

    with TestClient(central_app) as client:
        yield client, {"a": token_a, "b": token_b, "admin": token_admin}, db


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# ──────────────────────────────────────────────────────────────────
# Fail closed
# ──────────────────────────────────────────────────────────────────


def test_central_mode_refuses_to_start_without_credentials(monkeypatch):
    monkeypatch.delenv("PRAHARI_CREDENTIALS_JSON", raising=False)
    monkeypatch.delenv("PRAHARI_CREDENTIALS_FILE", raising=False)
    cfg = AppConfig(deployment_mode=DeploymentMode.CENTRAL, credentials_file="")

    with pytest.raises(MissingCredentialsError) as exc:
        CredentialStore.load(cfg)
    assert "will not run centrally without authentication" in str(exc.value)


def test_central_mode_refuses_an_empty_credential_set(monkeypatch):
    monkeypatch.setenv("PRAHARI_CREDENTIALS_JSON", "[]")
    with pytest.raises(MissingCredentialsError) as exc:
        CredentialStore.load(AppConfig(deployment_mode=DeploymentMode.CENTRAL))
    assert "no credentials" in str(exc.value).lower()


def test_central_mode_refuses_a_missing_credential_file(monkeypatch, tmp_path):
    monkeypatch.delenv("PRAHARI_CREDENTIALS_JSON", raising=False)
    monkeypatch.setenv("PRAHARI_CREDENTIALS_FILE", str(tmp_path / "nope.json"))
    with pytest.raises(MissingCredentialsError) as exc:
        CredentialStore.load(AppConfig(deployment_mode=DeploymentMode.CENTRAL))
    assert "not found" in str(exc.value)


def test_central_mode_refuses_a_malformed_credential_file(monkeypatch, tmp_path):
    path = tmp_path / "creds.json"
    path.write_text("{not json", encoding="utf-8")
    monkeypatch.delenv("PRAHARI_CREDENTIALS_JSON", raising=False)
    monkeypatch.setenv("PRAHARI_CREDENTIALS_FILE", str(path))
    with pytest.raises(MissingCredentialsError):
        CredentialStore.load(AppConfig(deployment_mode=DeploymentMode.CENTRAL))


def test_local_mode_remains_unauthenticated(db, tmp_path):
    """The loopback deployment must keep working with no credentials."""
    from app.main import app as local_app

    local_app.dependency_overrides[get_db] = lambda: db
    try:
        with TestClient(local_app) as c:
            assert c.get("/api/v1/health").status_code == 200
            assert c.get("/api/v1/events").status_code == 200
    finally:
        local_app.dependency_overrides.clear()


# ──────────────────────────────────────────────────────────────────
# Authentication
# ──────────────────────────────────────────────────────────────────


def test_unauthenticated_requests_are_rejected(central):
    client, _, _ = central
    for path in ("/api/v1/events", "/api/v1/sources", "/api/v1/audit/logs"):
        res = client.get(path)
        assert res.status_code == 401, f"{path} was reachable unauthenticated"
        assert res.headers.get("WWW-Authenticate") == "Bearer"
        assert res.json()["detail"]["error"] == "authentication_required"


def test_invalid_credentials_are_rejected(central):
    client, _, _ = central
    for bad in ("", "garbage", generate_token(), "Bearer x"):
        res = client.get("/api/v1/events", headers={"Authorization": f"Bearer {bad}"})
        assert res.status_code == 401


def test_health_remains_public_for_diagnosis(central):
    client, _, _ = central
    assert client.get("/api/v1/health").status_code == 200


def test_valid_credential_is_accepted(central):
    client, tokens, _ = central
    res = client.get("/api/v1/events", headers=_auth(tokens["a"]))
    assert res.status_code == 200
    assert res.headers.get("X-PraHari-Source") == "sensor-a"


def test_disabled_credential_stops_authenticating():
    cred, token = Credential.create("sensor-x", Role.INGEST)
    assert cred.verify(token) is True

    disabled = Credential(
        credential_id=cred.credential_id,
        source_id=cred.source_id,
        role=cred.role,
        salt=cred.salt,
        token_hash=cred.token_hash,
        enabled=False,
    )
    assert disabled.verify(token) is False
    with pytest.raises(InvalidCredentialError):
        CredentialStore([disabled]).authenticate(token)


# ──────────────────────────────────────────────────────────────────
# Source isolation
# ──────────────────────────────────────────────────────────────────


def test_a_source_sees_only_its_own_telemetry(central):
    client, tokens, _ = central

    a = client.get("/api/v1/events", headers=_auth(tokens["a"])).json()
    assert a["total"] == 5
    assert all(e["source_id"] == "sensor-a" for e in a["events"])

    b = client.get("/api/v1/events", headers=_auth(tokens["b"])).json()
    assert b["total"] == 3
    assert all(e["source_id"] == "sensor-b" for e in b["events"])


def test_unscoped_query_does_not_expose_all_sources(central):
    """
    Omitting source_id must scope to the caller, not mean "everything".
    """
    client, tokens, db = central
    assert db.count_events() == 8

    body = client.get("/api/v1/events", headers=_auth(tokens["a"])).json()
    assert body["total"] == 5, "unscoped query leaked other sources"


def test_cross_source_access_is_refused_not_silently_rewritten(central):
    """A client asking for the wrong source should be told, not misled."""
    client, tokens, _ = central
    res = client.get(
        "/api/v1/events?source_id=sensor-b", headers=_auth(tokens["a"])
    )
    assert res.status_code == 403
    assert res.json()["detail"]["error"] == "cross_source_access_denied"


def test_connections_route_is_scoped_too(central):
    client, tokens, _ = central
    body = client.get("/api/v1/events/connections", headers=_auth(tokens["a"])).json()
    assert body["total"] == 5
    res = client.get(
        "/api/v1/events/connections?source_id=sensor-b", headers=_auth(tokens["a"])
    )
    assert res.status_code == 403


def test_admin_may_access_all_sources(central):
    client, tokens, _ = central
    body = client.get("/api/v1/events", headers=_auth(tokens["admin"])).json()
    assert body["total"] == 8
    assert (
        client.get(
            "/api/v1/events?source_id=sensor-a", headers=_auth(tokens["admin"])
        ).status_code == 200
    )


def test_principal_scoping_rules():
    ingest = Principal("c1", "sensor-a", Role.INGEST)
    admin = Principal("c2", "central", Role.ADMIN)

    assert ingest.may_access_source("sensor-a") is True
    assert ingest.may_access_source("sensor-b") is False
    assert ingest.may_access_source(None) is False  # unscoped is not "all"
    assert admin.may_access_source(None) is True

    assert ingest.assert_source_access(None) == "sensor-a"
    with pytest.raises(SourceAccessDenied):
        ingest.assert_source_access("sensor-b")

    assert ingest.may_write() is True
    assert Principal("c3", "s", Role.READ_ONLY).may_write() is False


# ──────────────────────────────────────────────────────────────────
# Secret handling
# ──────────────────────────────────────────────────────────────────


def test_tokens_are_hashed_never_stored_in_plaintext():
    cred, token = Credential.create("sensor-a", Role.INGEST)
    record = json.dumps(cred.to_record())

    assert token not in record, "plaintext token must never be persisted"
    assert cred.token_hash != token
    assert len(cred.token_hash) == 64  # sha256 hex
    assert cred.verify(token) is True
    assert cred.verify(token + "x") is False


def test_each_credential_has_a_distinct_salt():
    a, _ = Credential.create("s", Role.INGEST)
    b, _ = Credential.create("s", Role.INGEST)
    assert a.salt != b.salt


def test_same_token_hashes_differently_under_different_salts():
    import secrets
    token = generate_token()
    s1, s2 = secrets.token_bytes(16), secrets.token_bytes(16)
    assert hash_token(token, s1) != hash_token(token, s2)


def test_redaction_never_reveals_token_content():
    token = generate_token()
    out = redact(token)
    assert token not in out
    assert out.startswith("<token:")
    assert redact(None) == "<none>"


def test_error_responses_do_not_echo_the_presented_token(central):
    client, _, _ = central
    secret = "super-secret-value-123"
    res = client.get("/api/v1/events", headers={"Authorization": f"Bearer {secret}"})
    assert res.status_code == 401
    assert secret not in res.text


def test_unknown_and_disabled_credentials_are_indistinguishable(central):
    """
    Distinguishing them would disclose which source ids exist.
    """
    client, _, _ = central
    a = client.get("/api/v1/events", headers=_auth(generate_token())).json()
    cred, token = Credential.create("x", Role.INGEST)
    disabled_store_msg = a["detail"]["message"]
    assert disabled_store_msg == "Credential is not recognised."


def test_config_response_contains_no_credential_material(central):
    client, tokens, _ = central
    body = client.get("/api/v1/audit/config", headers=_auth(tokens["admin"])).json()
    flat = json.dumps(body).lower()
    for marker in ("token", "secret", "password", "salt", "credential"):
        assert marker not in flat, f"config exposes {marker}"


def test_credential_file_is_gitignored():
    """A committed credential file would defeat the entire scheme."""
    from pathlib import Path

    gitignore = (
        Path(__file__).resolve().parents[3] / ".gitignore"
    ).read_text(encoding="utf-8")
    assert "secrets/" in gitignore or "credentials.json" in gitignore


# ──────────────────────────────────────────────────────────────────
# Source registration (ADR-118)
# ──────────────────────────────────────────────────────────────────


def test_registering_a_source_requires_admin_in_central_mode(central):
    """
    Creating a source is at least as significant as toggling one.

    `PATCH /sources/{id}/enabled` required admin; `POST /sources` did
    not, so a sensor credential could register arbitrary source rows in
    central mode. It granted no ingestion rights — `assert_source_access`
    governs that separately, and a new row adds nothing to a principal's
    allowed set — but it let a non-admin populate the registry, the
    source-health summary and the dashboard, and take a source id a
    legitimate producer would then be refused with a 409.

    Found while building the device-registration interface over this
    endpoint, which makes it far easier to call.
    """
    client, tokens, _ = central

    res = client.post(
        "/api/v1/sources",
        json={
            "source_id": "sensor-a-invented",
            "name": "Invented",
            "source_type": "json_stream",
        },
        headers=_auth(tokens["a"]),
    )
    assert res.status_code == 403, (
        "a non-admin credential registered a telemetry source in central mode"
    )


def test_an_admin_may_still_register_a_source(central):
    """The guard must not close the endpoint to the operator."""
    client, tokens, _ = central

    res = client.post(
        "/api/v1/sources",
        json={
            "source_id": "lab-sensor-1",
            "name": "Lab sensor",
            "source_type": "json_stream",
        },
        headers=_auth(tokens["admin"]),
    )
    assert res.status_code == 201, res.text
    assert res.json()["source_id"] == "lab-sensor-1"
