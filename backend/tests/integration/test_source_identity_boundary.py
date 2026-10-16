"""
PraHari — The Ingestion Source-Identity Trust Boundary (ADR-051).

Central mode already authenticated every request and already scoped
*reads* to the caller's own source. Ingestion did neither: every write
path took `source_id` from the request body verbatim, so a sensor holding
a valid credential for one source could file telemetry — and occupy the
idempotency namespace — of any other.

These tests drive the real API over loopback with isolated temporary
databases. Credentials are minted per test and exist only in memory; no
credential value is printed, persisted or reused.
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
from app.core.security import Credential, CredentialStore, Role
from app.schemas.events import TelemetrySource
from app.storage.database import Database

SENSOR_A = "sensor-a"
SENSOR_B = "sensor-b"

NDJSON_RECORD = {
    "event_id": "evt-boundary-1",
    "timestamp": "2026-06-01T12:00:00Z",
    "src_ip": "192.0.2.10",
    "dst_ip": "198.51.100.20",
    "src_port": 40000,
    "dst_port": 443,
    "proto": "tcp",
    "bytes": 512,
}


def _ndjson(*records) -> str:
    return "\n".join(json.dumps(r) for r in (records or (NDJSON_RECORD,))) + "\n"


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def db(tmp_path):
    database = Database(db_path=str(tmp_path / "identity_boundary.db"))
    database.initialize()
    for sid in (SENSOR_A, SENSOR_B):
        database.upsert_source(
            TelemetrySource(source_id=sid, name=sid, source_type="json_stream")
        )
    yield database
    database.close()


@pytest.fixture
def central(db):
    """
    A central-mode app with four credentials: two sensors, one read-only
    and one admin. Tokens are returned to the test and nowhere else.
    """
    cred_a, token_a = Credential.create(SENSOR_A, Role.INGEST, "sensor A")
    cred_b, token_b = Credential.create(SENSOR_B, Role.INGEST, "sensor B")
    cred_ro, token_ro = Credential.create(SENSOR_A, Role.READ_ONLY, "viewer")
    cred_admin, token_admin = Credential.create("central", Role.ADMIN, "operator")
    cred_off, token_off = Credential.create("sensor-retired", Role.INGEST, "revoked")
    store = CredentialStore([cred_a, cred_b, cred_ro, cred_admin])
    # Enrolled once, then switched off. Kept out of the store entirely is a
    # different case (unknown); this one is known-but-disabled.
    store.add(
        Credential(
            credential_id=cred_off.credential_id,
            source_id=cred_off.source_id,
            role=cred_off.role,
            salt=cred_off.salt,
            token_hash=cred_off.token_hash,
            enabled=False,
        )
    )

    cfg = AppConfig(deployment_mode=DeploymentMode.CENTRAL)
    app = FastAPI()
    app.include_router(api_v1_router, prefix="/api/v1")
    app.add_middleware(
        CentralAuthMiddleware, store=store, public_paths=cfg.central_public_paths
    )
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[get_config] = lambda: cfg

    with TestClient(app) as client:
        yield client, {
            "a": token_a,
            "b": token_b,
            "read_only": token_ro,
            "admin": token_admin,
            "disabled": token_off,
        }, db



def _applayer_central(db):
    """A central app with application-layer ingest switched on."""
    cred_a, token_a = Credential.create(SENSOR_A, Role.INGEST, "sensor A")
    store = CredentialStore([cred_a])
    cfg = AppConfig(
        deployment_mode=DeploymentMode.CENTRAL,
        enable_application_layer_ingest=True,
    )
    app = FastAPI()
    app.include_router(api_v1_router, prefix="/api/v1")
    app.add_middleware(
        CentralAuthMiddleware, store=store, public_paths=cfg.central_public_paths
    )
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[get_config] = lambda: cfg
    return TestClient(app), {"a": token_a}


def _ingest(client, token, source_id, content=None, **extra):
    body = {
        "source_id": source_id,
        "ndjson_content": content or _ndjson(),
        **extra,
    }
    return client.post(
        "/api/v1/stream/ingest/ndjson", json=body, headers=_auth(token)
    )


# ──────────────────────────────────────────────────────────────────
# Impersonation — the defect this phase exists to close
# ──────────────────────────────────────────────────────────────────


def test_a_sensor_cannot_file_telemetry_under_another_source(central):
    client, tokens, db = central

    response = _ingest(client, tokens["a"], SENSOR_B)

    assert response.status_code == 403
    assert response.json()["detail"]["error"] == "source_identity_mismatch"
    assert db.count_events(source_id=SENSOR_B) == 0, (
        "a credential for one sensor wrote telemetry attributed to another"
    )


def test_a_rejected_impersonation_persists_nothing_at_all(central):
    client, tokens, db = central

    assert _ingest(client, tokens["a"], SENSOR_B).status_code == 403

    assert db.count_events() == 0, "a refused request still created rows"


def test_the_mismatch_error_does_not_reveal_whether_the_other_source_exists(central):
    """
    The same wording for an enrolled source and an invented one, so the
    response cannot be used to enumerate the fleet.
    """
    client, tokens, _ = central

    enrolled = _ingest(client, tokens["a"], SENSOR_B).json()["detail"]["message"]
    invented = _ingest(client, tokens["a"], "no-such-sensor").json()["detail"]["message"]

    assert enrolled == invented
    assert SENSOR_B not in enrolled and "no-such-sensor" not in invented


def test_stored_events_carry_the_authenticated_identity(central):
    client, tokens, db = central

    assert _ingest(client, tokens["a"], SENSOR_A).status_code == 200

    stored = db.list_events(limit=10)
    assert stored and all(e.source_id == SENSOR_A for e in stored)


def test_one_source_cannot_occupy_another_sources_idempotency_namespace(central):
    """
    Event identity is UUIDv5 over the source (ADR-050). If a client could
    choose the source it could mint collisions in another's namespace —
    either 409-ing that source's legitimate events or silently merging
    with them.
    """
    client, tokens, db = central

    assert _ingest(client, tokens["b"], SENSOR_B).status_code == 200
    before = db.count_events(source_id=SENSOR_B)

    # Sensor A submits the SAME sender event_id while claiming to be B.
    assert _ingest(client, tokens["a"], SENSOR_B).status_code == 403

    # And submitting it as itself is a separate event, not a collision.
    assert _ingest(client, tokens["a"], SENSOR_A).status_code == 200
    assert db.count_events(source_id=SENSOR_B) == before
    assert db.count_events(source_id=SENSOR_A) == 1


def test_a_batch_cannot_smuggle_a_per_record_source(central):
    """
    Source is resolved once, before parsing. A `source_id` inside an
    NDJSON record is not an identity assertion and must not become one.
    """
    client, tokens, db = central
    smuggled = {**NDJSON_RECORD, "source_id": SENSOR_B, "event_id": "evt-smuggle"}

    assert _ingest(client, tokens["a"], SENSOR_A, content=_ndjson(smuggled)).status_code == 200

    assert db.count_events(source_id=SENSOR_B) == 0
    assert db.count_events(source_id=SENSOR_A) == 1


# ──────────────────────────────────────────────────────────────────
# Authentication failures — no fallback to the request body
# ──────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "headers, label",
    [
        ({}, "no header"),
        ({"Authorization": "Bearer "}, "empty bearer"),
        ({"Authorization": "not-a-bearer-token"}, "malformed scheme"),
        ({"Authorization": "Basic dXNlcjpwYXNz"}, "wrong scheme"),
        ({"Authorization": "Bearer deadbeef-not-a-real-token"}, "unknown token"),
    ],
)
def test_ingestion_without_a_usable_credential_is_refused(central, headers, label):
    client, _, db = central

    response = client.post(
        "/api/v1/stream/ingest/ndjson",
        json={"source_id": SENSOR_A, "ndjson_content": _ndjson()},
        headers=headers,
    )

    assert response.status_code == 401, f"{label} was accepted"
    assert db.count_events() == 0, f"{label} persisted telemetry"


def test_a_disabled_credential_is_refused(central):
    client, tokens, db = central

    response = client.post(
        "/api/v1/stream/ingest/ndjson",
        json={"source_id": "sensor-retired", "ndjson_content": _ndjson()},
        headers=_auth(tokens["disabled"]),
    )

    assert response.status_code == 401
    # Same wording as an unknown token: whether a source was ever enrolled
    # is not disclosed.
    assert response.json()["detail"]["message"] == "Credential is not recognised."
    assert db.count_events() == 0


def test_authentication_failure_does_not_fall_back_to_the_body(central):
    """The body still names a real, enrolled source. It must not help."""
    client, _, db = central

    response = client.post(
        "/api/v1/stream/ingest/ndjson",
        json={"source_id": SENSOR_A, "ndjson_content": _ndjson()},
        headers=_auth("entirely-invented-token"),
    )

    assert response.status_code == 401
    assert db.count_events(source_id=SENSOR_A) == 0


# ──────────────────────────────────────────────────────────────────
# Roles
# ──────────────────────────────────────────────────────────────────


def test_a_read_only_credential_cannot_submit_telemetry(central):
    client, tokens, db = central

    response = _ingest(client, tokens["read_only"], SENSOR_A)

    assert response.status_code == 403
    assert response.json()["detail"]["error"] == "write_not_permitted"
    assert db.count_events() == 0


def test_an_admin_must_name_the_source_it_submits_for(central):
    """An admin credential is not itself a sensor."""
    client, tokens, db = central

    response = _ingest(client, tokens["admin"], "")

    assert response.status_code == 400
    assert response.json()["detail"]["error"] == "source_id_required"
    assert db.count_events() == 0


def test_an_admin_may_submit_on_behalf_of_an_enrolled_source(central):
    client, tokens, db = central

    assert _ingest(client, tokens["admin"], SENSOR_B).status_code == 200

    assert db.count_events(source_id=SENSOR_B) == 1


def test_a_sensor_credential_cannot_read_the_audit_log(central):
    """
    `/audit/logs` exists and is admin-only. An earlier draft of this test
    asked for `/audit/events`, which does not exist, and passed on the 404
    without ever reaching the authorization check.
    """
    client, tokens, _ = central

    allowed = client.get("/api/v1/audit/logs", headers=_auth(tokens["admin"]))
    assert allowed.status_code == 200, "the route under test must exist"

    denied = client.get("/api/v1/audit/logs", headers=_auth(tokens["a"]))
    assert denied.status_code == 403
    assert denied.json()["detail"]["error"] == "insufficient_privilege"


# ──────────────────────────────────────────────────────────────────
# The boundary applies to every write path, not just the stream
# ──────────────────────────────────────────────────────────────────


def test_the_application_layer_endpoint_enforces_the_same_boundary(db):
    """
    Built with the endpoint explicitly enabled, so the request reaches the
    identity boundary rather than being turned away by the opt-in gate or
    by payload validation.
    """
    client, tokens = _applayer_central(db)

    response = client.post(
        "/api/v1/applayer/ingest",
        json={
            "source_id": SENSOR_B,
            "producer": "test-probe",
            "records": [
                {
                    "observed_at": "2026-06-01T12:00:00Z",
                    "method": "GET",
                    "url": "https://example.test/a",
                    "status_code": 200,
                }
            ],
        },
        headers=_auth(tokens["a"]),
    )

    assert response.status_code == 403, response.text
    assert response.json()["detail"]["error"] == "source_identity_mismatch"
    assert db.count_events(source_id=SENSOR_B) == 0


def test_the_application_layer_endpoint_accepts_its_own_source(db):
    """The counterpart: the boundary refuses impersonation, not ingestion."""
    client, tokens = _applayer_central(db)

    response = client.post(
        "/api/v1/applayer/ingest",
        json={
            "source_id": SENSOR_A,
            "producer": "test-probe",
            "records": [
                {
                    "observed_at": "2026-06-01T12:00:00Z",
                    "method": "GET",
                    "url": "https://example.test/a",
                    "status_code": 200,
                }
            ],
        },
        headers=_auth(tokens["a"]),
    )

    assert response.status_code == 200, response.text
    assert db.count_events(source_id=SENSOR_A) == 1


def test_the_csv_import_endpoint_enforces_the_same_boundary(central):
    client, tokens, db = central

    response = client.post(
        "/api/v1/import/csv/raw",
        json={
            "source_id": SENSOR_B,
            "csv_content": "timestamp,src_ip,dst_ip,src_port,dst_port,protocol\n",
        },
        headers=_auth(tokens["a"]),
    )

    assert response.status_code == 403
    assert response.json()["detail"]["error"] == "source_identity_mismatch"
    assert db.count_events(source_id=SENSOR_B) == 0


def test_the_synthetic_replay_endpoint_enforces_the_same_boundary(central):
    client, tokens, db = central

    response = client.post(
        "/api/v1/stream/replay/synthetic",
        json={"source_id": SENSOR_B, "count": 10},
        headers=_auth(tokens["a"]),
    )

    assert response.status_code == 403
    assert db.count_events(source_id=SENSOR_B) == 0


# ──────────────────────────────────────────────────────────────────
# Established behaviour must survive the new boundary
# ──────────────────────────────────────────────────────────────────


def test_retry_idempotency_still_holds_under_an_authenticated_identity(central):
    client, tokens, db = central

    first = _ingest(client, tokens["a"], SENSOR_A, idempotency_key="k-auth")
    second = _ingest(client, tokens["a"], SENSOR_A, idempotency_key="k-auth")

    assert first.json()["stored_records"] == 1
    assert second.json()["stored_records"] == 0
    assert db.count_events(source_id=SENSOR_A) == 1


def test_two_sources_using_the_same_sender_id_stay_separate(central):
    """Scoping by authenticated source, so identical sender ids coexist."""
    client, tokens, db = central

    assert _ingest(client, tokens["a"], SENSOR_A).status_code == 200
    assert _ingest(client, tokens["b"], SENSOR_B).status_code == 200

    assert db.count_events(source_id=SENSOR_A) == 1
    assert db.count_events(source_id=SENSOR_B) == 1


def test_received_at_is_still_server_generated_and_unforgeable(central):
    client, tokens, db = central
    forged = {**NDJSON_RECORD, "received_at": "1999-01-01T00:00:00Z"}

    assert _ingest(client, tokens["a"], SENSOR_A, content=_ndjson(forged)).status_code == 200

    stored = db.list_events(source_id=SENSOR_A, limit=5)[0]
    assert stored.received_at is not None
    assert stored.received_at.year >= 2026


def test_a_conflicting_batch_still_rolls_back_under_authentication(central):
    client, tokens, db = central
    assert _ingest(client, tokens["a"], SENSOR_A).status_code == 200

    conflicting = {**NDJSON_RECORD, "bytes": 999999}
    fresh = {**NDJSON_RECORD, "event_id": "evt-fresh", "src_port": 40001}

    response = _ingest(
        client, tokens["a"], SENSOR_A, content=_ndjson(fresh, conflicting)
    )

    assert response.status_code == 409
    assert db.count_events(source_id=SENSOR_A) == 1, "partial batch survived"


def test_source_health_still_reports_without_inventing_evidence(central):
    client, tokens, _ = central

    response = client.get("/api/v1/sources/health", headers=_auth(tokens["admin"]))

    assert response.status_code == 200
    payload = response.json()
    assert payload["sources"], "health reported no sources at all"
    for record in payload["sources"]:
        assert "freshness_basis" in record
        assert "clock_dependent" in record


# ──────────────────────────────────────────────────────────────────
# Credential hygiene
# ──────────────────────────────────────────────────────────────────


def test_a_minted_credential_never_stores_the_token(central):
    credential, token = Credential.create("sensor-hygiene", Role.INGEST)
    record = json.dumps(credential.to_record())

    assert token not in record
    assert "token_hash" in record
    assert credential.verify(token)
    assert not credential.verify(token + "x")


def test_source_listings_never_expose_credential_material(central):
    client, tokens, _ = central

    response = client.get("/api/v1/sources/", headers=_auth(tokens["admin"]))

    assert response.status_code == 200
    body = response.text.lower()
    for leak in ("token", "token_hash", "salt", "credential_id", "secret"):
        assert leak not in body, f"source listing exposed {leak!r}"


# ──────────────────────────────────────────────────────────────────
# Local mode is unchanged — the pre-existing contract
# ──────────────────────────────────────────────────────────────────


def test_local_mode_ingestion_is_unchanged(db):
    """
    Loopback deployment is unauthenticated by design. The boundary adds no
    principal there, so the claimed source passes through exactly as before.
    """
    from app.main import app as local_app

    local_app.dependency_overrides[get_db] = lambda: db
    try:
        with TestClient(local_app) as client:
            response = client.post(
                "/api/v1/stream/ingest/ndjson",
                json={"source_id": SENSOR_A, "ndjson_content": _ndjson()},
            )
        assert response.status_code == 200
        assert db.count_events(source_id=SENSOR_A) == 1
    finally:
        local_app.dependency_overrides.clear()
