"""
PraHari — Source and Retention Administration (ADR-059, blueprint §11).

Two administrative operations the API did not have: enabling/disabling a
source, and changing the retention period. Both are admin-gated in
central mode, audited, and validated server side.

The rule these tests exist to hold: **a policy change deletes nothing.**
Shortening retention sets a number; pruning still requires the separate
confirmed enforcement call.
"""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.auth import CentralAuthMiddleware
from app.api.deps import get_db
from app.api.v1.router import api_v1_router
from app.core.config import AppConfig, DeploymentMode, get_config
from app.core.security import Credential, CredentialStore, Role
from app.schemas.events import (
    DataCategory,
    EventType,
    LabelProvenance,
    NormalizedEvent,
    TelemetrySource,
)
from app.storage.database import Database
from datetime import datetime, timezone

SENSOR = "admin-sensor-a"
OTHER = "admin-sensor-b"


def _event(source: str, i: int) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=f"{source}-{i}",
        source_id=source,
        data_category=DataCategory.LIVE_TELEMETRY,
        observed_at=datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc),
        event_type=EventType.NETWORK_FLOW,
        src_ip="192.0.2.10",
        dst_ip="198.51.100.20",
        src_port=40000 + i,
        dst_port=443,
        protocol="TCP",
        label_provenance=LabelProvenance.UNLABELED,
    )


@pytest.fixture
def db(tmp_path):
    database = Database(db_path=str(tmp_path / "admin.db"))
    database.initialize()
    for sid in (SENSOR, OTHER):
        database.upsert_source(
            TelemetrySource(source_id=sid, name=sid, source_type="json_stream")
        )
    database.insert_events([_event(SENSOR, i) for i in range(3)])
    yield database
    database.close()


@pytest.fixture
def local(db):
    """Loopback deployment: unauthenticated by design."""
    app = FastAPI()
    app.include_router(api_v1_router, prefix="/api/v1")
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[get_config] = lambda: AppConfig(retention_days=365)
    with TestClient(app) as c:
        yield c, db


@pytest.fixture
def central(db):
    """Central deployment with an admin and a sensor credential."""
    admin_cred, admin_token = Credential.create("central", Role.ADMIN, "operator")
    sensor_cred, sensor_token = Credential.create(SENSOR, Role.INGEST, "sensor")
    cfg = AppConfig(deployment_mode=DeploymentMode.CENTRAL, retention_days=365)
    app = FastAPI()
    app.include_router(api_v1_router, prefix="/api/v1")
    app.add_middleware(
        CentralAuthMiddleware,
        store=CredentialStore([admin_cred, sensor_cred]),
        public_paths=cfg.central_public_paths,
    )
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[get_config] = lambda: cfg
    with TestClient(app) as c:
        yield c, db, {"admin": admin_token, "sensor": sensor_token}


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _audit_actions(db):
    with db.get_connection() as conn:
        return [r["action"] for r in conn.execute("SELECT action FROM audit_events")]


# ──────────────────────────────────────────────────────────────────
# Source enable / disable
# ──────────────────────────────────────────────────────────────────


def test_disabling_a_source_persists(local):
    c, db = local

    response = c.patch(
        f"/api/v1/sources/{SENSOR}/enabled",
        json={"enabled": False, "reason": "decommissioned"},
    )

    assert response.status_code == 200
    assert response.json()["enabled"] is False
    assert db.get_source(SENSOR).enabled is False


def test_enabling_a_source_again_persists(local):
    c, db = local
    c.patch(f"/api/v1/sources/{SENSOR}/enabled", json={"enabled": False})

    c.patch(f"/api/v1/sources/{SENSOR}/enabled", json={"enabled": True})

    assert db.get_source(SENSOR).enabled is True


def test_disabling_deletes_no_telemetry(local):
    """An administrative toggle must not destroy evidence."""
    c, db = local
    before = db.count_events(source_id=SENSOR)

    c.patch(f"/api/v1/sources/{SENSOR}/enabled", json={"enabled": False})

    assert db.count_events(source_id=SENSOR) == before == 3


def test_disabling_preserves_counters_and_last_event(local):
    c, db = local
    before = db.get_source(SENSOR)

    c.patch(f"/api/v1/sources/{SENSOR}/enabled", json={"enabled": False})
    after = db.get_source(SENSOR)

    assert after.event_count == before.event_count
    assert after.last_event_at == before.last_event_at
    assert after.source_type == before.source_type


def test_disabling_is_reflected_in_source_health(local):
    c, db = local
    c.patch(f"/api/v1/sources/{SENSOR}/enabled", json={"enabled": False})

    health = c.get("/api/v1/sources/health").json()
    record = next(s for s in health["sources"] if s["source_id"] == SENSOR)

    assert record["state"] == "disabled"


def test_an_unknown_source_is_a_404_not_a_silent_success(local):
    c, _ = local

    response = c.patch("/api/v1/sources/no-such-source/enabled",
                       json={"enabled": False})

    assert response.status_code == 404
    assert response.json()["detail"]["error"] == "source_not_found"


def test_the_change_is_audited(local):
    c, db = local

    c.patch(f"/api/v1/sources/{SENSOR}/enabled",
            json={"enabled": False, "reason": "maintenance"})

    assert "set_source_enabled" in _audit_actions(db)


def test_only_the_named_source_is_affected(local):
    c, db = local

    c.patch(f"/api/v1/sources/{SENSOR}/enabled", json={"enabled": False})

    assert db.get_source(OTHER).enabled is True


def test_a_missing_enabled_field_is_rejected(local):
    c, _ = local

    assert c.patch(f"/api/v1/sources/{SENSOR}/enabled", json={}).status_code == 422


# ──────────────────────────────────────────────────────────────────
# Authorization
# ──────────────────────────────────────────────────────────────────


def test_an_admin_may_disable_a_source(central):
    c, db, tokens = central

    response = c.patch(
        f"/api/v1/sources/{SENSOR}/enabled",
        json={"enabled": False},
        headers=_auth(tokens["admin"]),
    )

    assert response.status_code == 200
    assert db.get_source(SENSOR).enabled is False


def test_a_sensor_credential_cannot_disable_a_source(central):
    c, db, tokens = central

    response = c.patch(
        f"/api/v1/sources/{SENSOR}/enabled",
        json={"enabled": False},
        headers=_auth(tokens["sensor"]),
    )

    assert response.status_code == 403
    assert db.get_source(SENSOR).enabled is True, "an unauthorized call took effect"


def test_a_sensor_credential_cannot_disable_another_source(central):
    c, db, tokens = central

    response = c.patch(
        f"/api/v1/sources/{OTHER}/enabled",
        json={"enabled": False},
        headers=_auth(tokens["sensor"]),
    )

    assert response.status_code == 403
    assert db.get_source(OTHER).enabled is True


def test_an_unauthenticated_call_is_refused_in_central_mode(central):
    c, db, _ = central

    response = c.patch(f"/api/v1/sources/{SENSOR}/enabled", json={"enabled": False})

    assert response.status_code == 401
    assert db.get_source(SENSOR).enabled is True


def test_a_sensor_credential_cannot_change_retention(central):
    c, db, tokens = central

    response = c.put(
        "/api/v1/retention/policy",
        json={"retention_days": 1},
        headers=_auth(tokens["sensor"]),
    )

    assert response.status_code == 403
    assert c.get(
        "/api/v1/retention/policy", headers=_auth(tokens["admin"])
    ).json()["retention_days"] == 365


# ──────────────────────────────────────────────────────────────────
# Retention policy
# ──────────────────────────────────────────────────────────────────


def test_the_configured_default_applies_when_no_override_is_set(local):
    c, _ = local

    body = c.get("/api/v1/retention/policy").json()

    assert body["retention_days"] == 365
    assert body["origin"] == "configured_default"


def test_an_override_takes_effect_and_names_its_origin(local):
    c, _ = local

    update = c.put("/api/v1/retention/policy",
                   json={"retention_days": 30, "reason": "storage pressure"})

    assert update.status_code == 200
    assert update.json()["retention_days"] == 30
    assert update.json()["origin"] == "operator_override"

    assert c.get("/api/v1/retention/policy").json()["retention_days"] == 30


def test_the_override_survives_a_new_database_handle(local, tmp_path):
    """Persisted, not held in process memory."""
    c, db = local
    c.put("/api/v1/retention/policy", json={"retention_days": 45})

    reopened = Database(db_path=db.db_path)
    try:
        assert reopened.get_setting("retention_days") == "45"
    finally:
        reopened.close()


def test_the_configured_default_is_still_reported_alongside_the_override(local):
    c, _ = local
    c.put("/api/v1/retention/policy", json={"retention_days": 30})

    body = c.get("/api/v1/retention/policy").json()

    assert body["retention_days"] == 30
    assert body["configured_default"] == 365, (
        "an operator must be able to see what the override replaced"
    )


def test_clearing_the_override_restores_the_default(local):
    c, _ = local
    c.put("/api/v1/retention/policy", json={"retention_days": 30})

    cleared = c.put("/api/v1/retention/policy", json={"retention_days": None})

    assert cleared.json()["override_cleared"] is True
    assert cleared.json()["retention_days"] == 365
    assert c.get("/api/v1/retention/policy").json()["origin"] == "configured_default"


@pytest.mark.parametrize("value", [0, -1, -365, 36_501])
def test_an_out_of_range_retention_value_is_refused(local, value):
    c, _ = local

    response = c.put("/api/v1/retention/policy", json={"retention_days": value})

    assert response.status_code == 422
    assert c.get("/api/v1/retention/policy").json()["retention_days"] == 365


def test_a_non_integer_retention_value_is_refused(local):
    c, _ = local

    assert c.put("/api/v1/retention/policy",
                 json={"retention_days": "thirty"}).status_code == 422


def test_a_rejected_update_leaves_no_partial_state(local, db):
    c, _ = local

    c.put("/api/v1/retention/policy", json={"retention_days": 0})

    assert db.get_setting("retention_days") is None


def test_changing_the_policy_deletes_nothing(local):
    """
    The rule this whole feature rests on: shortening retention sets a
    number. Pruning is a separate, confirmed operation.
    """
    c, db = local
    before = db.count_events()

    c.put("/api/v1/retention/policy", json={"retention_days": 1})

    assert db.count_events() == before == 3


def test_merely_reading_the_policy_deletes_nothing(local):
    c, db = local
    before = db.count_events()

    for _ in range(3):
        c.get("/api/v1/retention/policy")

    assert db.count_events() == before


def test_the_policy_change_is_audited(local):
    c, db = local

    c.put("/api/v1/retention/policy",
          json={"retention_days": 30, "reason": "quarterly review"})

    actions = _audit_actions(db)
    assert "update_retention_policy" in actions


def test_the_response_describes_what_was_persisted_not_what_was_asked(local):
    c, _ = local
    c.put("/api/v1/retention/policy", json={"retention_days": 30})

    second = c.put("/api/v1/retention/policy", json={"retention_days": 60}).json()

    assert second["previous_retention_days"] == 30
    assert second["retention_days"] == 60


def test_a_corrupt_override_falls_back_to_the_default_not_to_zero(local, db):
    """
    Guessing at an unreadable value could shorten retention — the
    direction that destroys data.
    """
    c, _ = local
    db.set_setting("retention_days", "not-a-number")

    body = c.get("/api/v1/retention/policy").json()

    assert body["retention_days"] == 365
    assert body["origin"] == "configured_default_override_unreadable"


def test_an_out_of_range_stored_override_is_ignored(local, db):
    c, _ = local
    db.set_setting("retention_days", "-5")

    body = c.get("/api/v1/retention/policy").json()

    assert body["retention_days"] == 365
    assert body["origin"] == "configured_default_override_out_of_range"


def test_the_policy_response_exposes_no_secrets(local):
    c, _ = local

    body = c.get("/api/v1/retention/policy").json()

    # The prose legitimately mentions the enforcement confirmation token,
    # so the check is for secret-bearing FIELDS, not for the word.
    for leak in ("token_hash", "salt", "password", "credential_id", "secret"):
        assert leak not in body, f"policy response carries {leak!r}"


def test_a_pre_migration_database_reports_the_default(tmp_path):
    """A database without the settings table must still answer."""
    import sqlite3

    db_file = tmp_path / "legacy.db"
    # A database that simply predates the settings table. Built minimally
    # rather than by slicing the real DDL, which is not safely splittable
    # on semicolons.
    con = sqlite3.connect(db_file)
    con.execute("CREATE TABLE telemetry_sources (source_id TEXT PRIMARY KEY)")
    con.commit()
    con.close()

    database = Database(db_path=str(db_file))
    try:
        assert database.get_setting("retention_days") is None
    finally:
        database.close()
