"""
PraHari — Credential Expiry, Rotation and Revocation (ADR-055).

Before this, a credential had exactly one lifecycle control: `enabled`,
editable only by hand in the credential file, and honoured by a running
process only after a restart. That is not revocation; it is a note to
self.

Everything here uses credentials minted inside the test, in temporary
files. No token value is printed, and no real credential store is read.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

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
    Role,
)
from app.schemas.events import TelemetrySource
from app.storage.database import Database

SOURCE = "sensor-lifecycle"
NOW = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)


def _iso(delta: timedelta) -> str:
    return (NOW + delta).isoformat()


def _ndjson() -> str:
    return json.dumps({
        "event_id": "evt-lifecycle-1",
        "timestamp": "2026-06-01T12:00:00Z",
        "src_ip": "192.0.2.10", "dst_ip": "198.51.100.20",
        "src_port": 40000, "dst_port": 443, "proto": "tcp",
    }) + "\n"


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def db(tmp_path):
    database = Database(db_path=str(tmp_path / "lifecycle.db"))
    database.initialize()
    database.upsert_source(
        TelemetrySource(source_id=SOURCE, name=SOURCE, source_type="json_stream")
    )
    yield database
    database.close()


def _central(db, store):
    cfg = AppConfig(deployment_mode=DeploymentMode.CENTRAL)
    app = FastAPI()
    app.include_router(api_v1_router, prefix="/api/v1")
    app.add_middleware(
        CentralAuthMiddleware, store=store, public_paths=cfg.central_public_paths
    )
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[get_config] = lambda: cfg
    return TestClient(app)


# ──────────────────────────────────────────────────────────────────
# Expiry
# ──────────────────────────────────────────────────────────────────


def test_a_credential_without_an_expiry_never_expires():
    """
    Adding the field must not retroactively invalidate a store an
    operator is already running.
    """
    cred, token = Credential.create(SOURCE, Role.INGEST)

    assert cred.not_after is None
    assert not cred.is_expired(now=NOW + timedelta(days=36500))
    assert cred.verify(token, now=NOW + timedelta(days=36500))


def test_a_credential_past_its_deadline_is_expired():
    cred, token = Credential.create(
        SOURCE, Role.INGEST, not_after=_iso(timedelta(hours=1))
    )

    assert cred.verify(token, now=NOW)
    assert not cred.verify(token, now=NOW + timedelta(hours=2))


def test_expiry_is_inclusive_at_the_boundary():
    """`not_after` means valid up to, not through, the instant."""
    deadline = _iso(timedelta(hours=1))
    cred, token = Credential.create(SOURCE, Role.INGEST, not_after=deadline)

    assert cred.verify(token, now=NOW + timedelta(minutes=59, seconds=59))
    assert not cred.verify(token, now=NOW + timedelta(hours=1))


def test_an_unreadable_expiry_counts_as_expired():
    """
    Treating a value we cannot parse as "no expiry" would turn a
    corrupted store into an indefinitely valid credential.
    """
    cred, token = Credential.create(SOURCE, Role.INGEST)
    broken = Credential(**{**cred.to_record(), "role": cred.role, "not_after": "soon-ish"})

    assert broken.is_expired(now=NOW)
    assert not broken.verify(token, now=NOW)


def test_a_naive_deadline_is_read_as_utc_not_local_time():
    """Otherwise the same store behaves differently on different hosts."""
    cred, token = Credential.create(
        SOURCE, Role.INGEST, not_after="2026-06-01T13:00:00"
    )

    assert cred.verify(token, now=NOW)
    assert not cred.verify(token, now=NOW + timedelta(hours=2))


def test_an_expired_credential_cannot_authenticate_at_all():
    cred, token = Credential.create(
        SOURCE, Role.INGEST, not_after="2020-01-01T00:00:00+00:00"
    )
    store = CredentialStore([cred])

    with pytest.raises(InvalidCredentialError):
        store.authenticate(token)


def test_an_expired_credential_is_refused_at_the_ingestion_boundary(db):
    cred, token = Credential.create(
        SOURCE, Role.INGEST, not_after="2020-01-01T00:00:00+00:00"
    )
    client = _central(db, CredentialStore([cred]))

    response = client.post(
        "/api/v1/stream/ingest/ndjson",
        json={"source_id": SOURCE, "ndjson_content": _ndjson()},
        headers=_auth(token),
    )

    assert response.status_code == 401
    assert db.count_events() == 0


def test_expiry_does_not_fall_back_to_the_request_body(db):
    """The body still names a real source. It must not help."""
    cred, token = Credential.create(
        SOURCE, Role.INGEST, not_after="2020-01-01T00:00:00+00:00"
    )
    client = _central(db, CredentialStore([cred]))

    client.post(
        "/api/v1/stream/ingest/ndjson",
        json={"source_id": SOURCE, "ndjson_content": _ndjson()},
        headers=_auth(token),
    )

    assert db.count_events(source_id=SOURCE) == 0


# ──────────────────────────────────────────────────────────────────
# Revocation
# ──────────────────────────────────────────────────────────────────


def test_a_revoked_credential_is_refused():
    cred, token = Credential.create(SOURCE, Role.INGEST)
    revoked = Credential(
        **{**cred.to_record(), "role": cred.role,
           "revoked_at": NOW.isoformat(), "revoked_reason": "laptop lost"}
    )

    assert revoked.is_revoked
    assert not revoked.verify(token, now=NOW)


def test_revocation_outranks_enabled():
    """A revoked credential stays refused even if `enabled` is true."""
    cred, token = Credential.create(SOURCE, Role.INGEST)
    revoked = Credential(
        **{**cred.to_record(), "role": cred.role,
           "enabled": True, "revoked_at": NOW.isoformat()}
    )

    assert not revoked.verify(token, now=NOW)


def test_revocation_takes_effect_without_restarting_the_service(tmp_path, db):
    """
    The point of the whole change. Before this, an edit to the credential
    file was honoured only after a restart.
    """
    cred, token = Credential.create(SOURCE, Role.INGEST)
    cred_file = tmp_path / "creds.json"
    cred_file.write_text(json.dumps([cred.to_record()]), encoding="utf-8")

    store = CredentialStore([cred], source_path=cred_file)
    client = _central(db, store)

    assert client.post(
        "/api/v1/stream/ingest/ndjson",
        json={"source_id": SOURCE, "ndjson_content": _ndjson()},
        headers=_auth(token),
    ).status_code == 200

    # The operator revokes it. Same process, no restart.
    record = cred.to_record()
    record["revoked_at"] = datetime.now(timezone.utc).isoformat()
    record["enabled"] = False
    _rewrite(cred_file, [record])

    after = client.post(
        "/api/v1/stream/ingest/ndjson",
        json={"source_id": SOURCE, "ndjson_content": _ndjson()},
        headers=_auth(token),
    )

    assert after.status_code == 401
    assert db.count_events() == 1, "only the pre-revocation event was stored"


def test_repeated_requests_after_revocation_stay_refused(tmp_path, db):
    cred, token = Credential.create(SOURCE, Role.INGEST)
    cred_file = tmp_path / "creds.json"
    record = cred.to_record()
    record["revoked_at"] = NOW.isoformat()
    cred_file.write_text(json.dumps([record]), encoding="utf-8")
    store = CredentialStore.from_records(json.loads(cred_file.read_text()))
    store._source_path = cred_file
    client = _central(db, store)

    for _ in range(5):
        assert client.post(
            "/api/v1/stream/ingest/ndjson",
            json={"source_id": SOURCE, "ndjson_content": _ndjson()},
            headers=_auth(token),
        ).status_code == 401
    assert db.count_events() == 0


def test_a_corrupt_credential_file_does_not_unauthenticate_the_fleet(tmp_path, db):
    """
    An operator who breaks the file must not thereby lock everyone out,
    nor have a half-parsed store silently swapped in.
    """
    cred, token = Credential.create(SOURCE, Role.INGEST)
    cred_file = tmp_path / "creds.json"
    cred_file.write_text(json.dumps([cred.to_record()]), encoding="utf-8")
    store = CredentialStore([cred], source_path=cred_file)

    _rewrite(cred_file, None, raw="{ this is not json")

    assert store.authenticate(token).source_id == SOURCE


def test_an_emptied_credential_file_is_refused_rather_than_applied(tmp_path):
    """Emptying the store would disable authentication for everyone."""
    cred, token = Credential.create(SOURCE, Role.INGEST)
    cred_file = tmp_path / "creds.json"
    cred_file.write_text(json.dumps([cred.to_record()]), encoding="utf-8")
    store = CredentialStore([cred], source_path=cred_file)

    _rewrite(cred_file, [])

    assert store.authenticate(token).source_id == SOURCE


def test_a_fixed_file_is_picked_up_without_a_restart(tmp_path):
    """A failed reload must not latch; the next change is still read."""
    cred, token = Credential.create(SOURCE, Role.INGEST)
    cred_file = tmp_path / "creds.json"
    cred_file.write_text(json.dumps([cred.to_record()]), encoding="utf-8")
    store = CredentialStore([cred], source_path=cred_file)

    _rewrite(cred_file, None, raw="{ broken")
    assert store.authenticate(token).source_id == SOURCE  # survived

    record = cred.to_record()
    record["revoked_at"] = datetime.now(timezone.utc).isoformat()
    _rewrite(cred_file, [record])

    with pytest.raises(InvalidCredentialError):
        store.authenticate(token)


# ──────────────────────────────────────────────────────────────────
# Rotation
# ──────────────────────────────────────────────────────────────────


def test_rotation_keeps_the_source_identity_and_namespace(db):
    """
    source_id scopes ingestion and the idempotency namespace (ADR-050,
    ADR-051). Rotating a secret must not move a sensor's data.
    """
    old, old_token = Credential.create(SOURCE, Role.INGEST)
    new, new_token = Credential.create(
        SOURCE, Role.INGEST, replaces_credential_id=old.credential_id
    )

    assert new.source_id == old.source_id
    assert new.credential_id != old.credential_id
    assert new.token_hash != old.token_hash
    assert new.salt != old.salt

    client = _central(db, CredentialStore([old, new]))
    first = client.post(
        "/api/v1/stream/ingest/ndjson",
        json={"source_id": SOURCE, "ndjson_content": _ndjson()},
        headers=_auth(old_token),
    )
    second = client.post(
        "/api/v1/stream/ingest/ndjson",
        json={"source_id": SOURCE, "ndjson_content": _ndjson()},
        headers=_auth(new_token),
    )

    assert first.json()["stored_records"] == 1
    assert second.json()["stored_records"] == 0, (
        "the rotated credential must land in the SAME idempotency namespace"
    )
    assert db.count_events(source_id=SOURCE) == 1


def test_both_credentials_work_during_the_overlap(db):
    # Deliberately anchored to the REAL clock, not the fixture's NOW:
    # `authenticate` uses the wall clock, so an overlap expressed against
    # a fixed past instant would already have elapsed.
    overlap_end = (datetime.now(timezone.utc) + timedelta(days=7)).isoformat()
    old, old_token = Credential.create(SOURCE, Role.INGEST, not_after=overlap_end)
    new, new_token = Credential.create(SOURCE, Role.INGEST)
    store = CredentialStore([old, new])

    assert store.authenticate(old_token).source_id == SOURCE
    assert store.authenticate(new_token).source_id == SOURCE


def test_the_old_credential_stops_at_the_end_of_the_overlap():
    old, old_token = Credential.create(
        SOURCE, Role.INGEST, not_after="2020-01-01T00:00:00+00:00"
    )
    new, new_token = Credential.create(SOURCE, Role.INGEST)
    store = CredentialStore([old, new])

    with pytest.raises(InvalidCredentialError):
        store.authenticate(old_token)
    assert store.authenticate(new_token).source_id == SOURCE


def test_rotation_records_what_it_replaced():
    old, _ = Credential.create(SOURCE, Role.INGEST)
    new, _ = Credential.create(
        SOURCE, Role.INGEST, replaces_credential_id=old.credential_id
    )

    assert new.to_record()["replaces_credential_id"] == old.credential_id


# ──────────────────────────────────────────────────────────────────
# Credential hygiene and authorization
# ──────────────────────────────────────────────────────────────────


def test_no_lifecycle_field_leaks_the_token():
    cred, token = Credential.create(
        SOURCE, Role.INGEST, not_after=_iso(timedelta(days=1))
    )

    serialized = json.dumps(cred.to_record())

    assert token not in serialized
    assert "token_hash" in serialized


def test_an_error_response_never_echoes_the_presented_token(db):
    cred, _ = Credential.create(SOURCE, Role.INGEST)
    client = _central(db, CredentialStore([cred]))
    canary = "CANARY-TOKEN-VALUE-0123456789"

    response = client.post(
        "/api/v1/stream/ingest/ndjson",
        json={"source_id": SOURCE, "ndjson_content": _ndjson()},
        headers=_auth(canary),
    )

    assert response.status_code == 401
    assert canary not in response.text


def test_expired_disabled_revoked_and_unknown_are_indistinguishable(db):
    """
    Four different reasons, one message. Distinguishing them would
    confirm which source ids exist and which credentials once worked.
    """
    base, _ = Credential.create(SOURCE, Role.INGEST)
    variants = {
        "expired": Credential(**{**base.to_record(), "role": base.role,
                                 "not_after": "2020-01-01T00:00:00+00:00"}),
        "disabled": Credential(**{**base.to_record(), "role": base.role,
                                  "enabled": False}),
        "revoked": Credential(**{**base.to_record(), "role": base.role,
                                 "revoked_at": NOW.isoformat()}),
    }
    messages = set()
    for cred in variants.values():
        store = CredentialStore([cred])
        with pytest.raises(InvalidCredentialError) as exc:
            store.authenticate("whatever-token")
        messages.add(str(exc.value))
    # And an entirely unknown token.
    with pytest.raises(InvalidCredentialError) as exc:
        CredentialStore([base]).authenticate("unknown-token")
    messages.add(str(exc.value))

    assert len(messages) == 1, f"wording differs per reason: {messages}"


def test_a_sensor_credential_still_cannot_reach_admin_routes(db):
    cred, token = Credential.create(SOURCE, Role.INGEST)
    client = _central(db, CredentialStore([cred]))

    response = client.get("/api/v1/audit/logs", headers=_auth(token))

    assert response.status_code == 403


def test_local_mode_is_unaffected_by_the_lifecycle_fields(db):
    """Loopback deployment stays unauthenticated by design."""
    from app.main import app as local_app

    local_app.dependency_overrides[get_db] = lambda: db
    try:
        with TestClient(local_app) as client:
            response = client.post(
                "/api/v1/stream/ingest/ndjson",
                json={"source_id": SOURCE, "ndjson_content": _ndjson()},
            )
        assert response.status_code == 200
    finally:
        local_app.dependency_overrides.clear()


# ──────────────────────────────────────────────────────────────────


def _rewrite(path: Path, records, raw: str | None = None) -> None:
    """
    Rewrite the credential file so the change is detectable.

    The store compares (mtime, size); a test can rewrite a file within
    the same filesystem timestamp tick, so the mtime is pushed forward
    explicitly rather than relying on clock resolution.
    """
    import os
    import time

    path.write_text(
        raw if raw is not None else json.dumps(records), encoding="utf-8"
    )
    future = time.time() + 10
    os.utime(path, (future, future))
