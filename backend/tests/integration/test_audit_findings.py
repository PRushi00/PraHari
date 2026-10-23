"""
Regressions for three defects found by an independent audit (ADR-126).

All three were found by exercising the running application, not by
reading it, and none was caught by the existing 1572-test suite.

* **AUDIT-01 (P1)** — `POST /retention/enforce` deletes telemetry
  irreversibly and carried no admin guard. `PUT /retention/policy` did.
  So the reversible settings change was protected while the destructive
  operation it configures was reachable by any authenticated credential,
  including an ingest sensor — and retention runs across every source,
  not just the caller's own.

* **AUDIT-02 (P2)** — `POST /collector/{start,stop,poll}` carried no
  admin guard. An ingest credential stopped the host collector and the
  status endpoint then reported `state=stopped`. For a security
  monitoring product that is an authenticated client blinding the
  operator's own collection.

* **AUDIT-03 (P2)** — `offset` was bounded below and not above, so a
  value past SQLite's 64-bit INTEGER range raised an unhandled
  `OverflowError`: HTTP 500 and a traceback, from an input every other
  numeric parameter rejected with a clean 422.

The first two share a root cause the codebase has already met once:
`require_admin_in_central` exists precisely because "a sensor's
credential cannot read the audit log" was a property of the design and
not of the code. These routes were the same omission elsewhere.
"""

from __future__ import annotations

import json

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.auth import CentralAuthMiddleware
from app.api.deps import get_db
from app.api.request_context import RequestIdMiddleware
from app.api.v1.router import api_v1_router
from app.core.config import AppConfig, DeploymentMode, get_config
from app.core.security import Credential, CredentialStore, Role
from app.storage.database import Database

CONFIRMATION_TOKEN = "DELETE-EXPIRED-TELEMETRY"

#: Every mutating route that acts on the whole deployment rather than on
#: one source, and so must not be reachable by a non-admin credential.
FLEET_WIDE_WRITES = [
    ("post", "/api/v1/retention/enforce", {"confirm": CONFIRMATION_TOKEN}),
    ("post", "/api/v1/collector/start", {"interval_seconds": 60}),
    ("post", "/api/v1/collector/stop", {}),
    ("post", "/api/v1/collector/poll", {}),
]


def _build(db: Database, store: CredentialStore | None) -> FastAPI:
    """The same wiring the existing central-mode tests use."""
    app = FastAPI()
    app.include_router(api_v1_router, prefix="/api/v1")
    if store is not None:
        cfg = AppConfig(deployment_mode=DeploymentMode.CENTRAL)
        app.add_middleware(
            CentralAuthMiddleware, store=store, public_paths=cfg.central_public_paths
        )
    else:
        cfg = AppConfig()
    app.add_middleware(RequestIdMiddleware)
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[get_config] = lambda: cfg
    return app


@pytest.fixture()
def central(tmp_path):
    """Central mode with one ingest credential and one admin credential."""
    db = Database(db_path=str(tmp_path / "central.db"))
    db.initialize()
    creds, tokens = {}, {}
    for name, source, role in (
        ("ingest", "sensor-01", Role.INGEST),
        ("admin", "ops", Role.ADMIN),
    ):
        creds[name], tokens[name] = Credential.create(source, role, name)
    app = _build(db, CredentialStore(list(creds.values())))
    with TestClient(app) as client:
        yield client, tokens["ingest"], tokens["admin"]
    db.close()


@pytest.fixture()
def local(tmp_path):
    db = Database(db_path=str(tmp_path / "local.db"))
    db.initialize()
    app = _build(db, None)
    with TestClient(app) as client:
        yield client
    db.close()


def _call(client, method, path, body, token=None):
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    return getattr(client, method)(path, json=body, headers=headers)


# ---------------------------------------------------------------------
# AUDIT-01 and AUDIT-02 — fleet-wide writes reachable by a sensor
# ---------------------------------------------------------------------


@pytest.mark.parametrize("method,path,body", FLEET_WIDE_WRITES)
def test_fleet_wide_write_refuses_an_ingest_credential(central, method, path, body):
    """
    A sensor credential must not delete the fleet's telemetry or stop the
    operator's collector. Before the fix these returned 200 and took
    effect.
    """
    client, ingest, _admin = central

    response = _call(client, method, path, body, ingest)

    assert response.status_code == 403, (
        f"{method.upper()} {path} accepted a non-admin credential "
        f"({response.status_code}). This operation affects every source, "
        f"not only the caller's."
    )


@pytest.mark.parametrize("method,path,body", FLEET_WIDE_WRITES)
def test_fleet_wide_write_refuses_an_anonymous_caller(central, method, path, body):
    client, _ingest, _admin = central
    assert _call(client, method, path, body).status_code == 401


def test_the_collector_is_not_stopped_by_a_refused_request(central):
    """
    The refusal must happen before the side effect.

    A 403 returned after the collector had already been stopped would
    close the status code and leave the defect.
    """
    client, ingest, admin = central
    auth = {"Authorization": f"Bearer {admin}"}

    _call(client, "post", "/api/v1/collector/start", {"interval_seconds": 60}, admin)
    before = client.get("/api/v1/collector/status", headers=auth).json()

    refused = _call(client, "post", "/api/v1/collector/stop", {}, ingest)
    assert refused.status_code == 403

    after = client.get("/api/v1/collector/status", headers=auth).json()
    assert after["state"] == before["state"], (
        "a refused request still changed the collector's state"
    )


def test_an_admin_may_still_do_all_of_it(central):
    """The guard must not lock the operator out of their own deployment."""
    client, _ingest, admin = central

    for method, path, body in FLEET_WIDE_WRITES:
        response = _call(client, method, path, body, admin)
        assert response.status_code < 400, (
            f"{method.upper()} {path} refused an ADMIN credential "
            f"({response.status_code}): {response.text[:200]}"
        )


def test_local_mode_is_unaffected(local):
    """
    On a loopback deployment the operator is the only caller and there is
    no principal to check. The guard must stay a no-op there, or this fix
    would break every single-machine install.
    """
    for method, path, body in FLEET_WIDE_WRITES:
        response = _call(local, method, path, body)
        assert response.status_code < 400, (
            f"{method.upper()} {path} broke in LOCAL mode "
            f"({response.status_code}): {response.text[:200]}"
        )


# ---------------------------------------------------------------------
# AUDIT-03 — the unbounded offset
# ---------------------------------------------------------------------

PAGINATED = [
    "/api/v1/events",
    "/api/v1/events/connections",
    "/api/v1/audit/logs",
]

#: 2**63 is the first value SQLite's INTEGER cannot hold. 2**63 - 1 was
#: observed returning 200, so the boundary is exact.
BEYOND_SQLITE_INTEGER = 2**63


@pytest.mark.parametrize("path", PAGINATED)
def test_an_enormous_offset_is_refused_not_a_server_error(local, path):
    """
    422, like every other out-of-range numeric parameter — not 500.

    `limit=999999999` was already a clean 422. The same shape of input on
    `offset` reached the database driver and raised.
    """
    response = local.get(path, params={"offset": BEYOND_SQLITE_INTEGER})

    assert response.status_code == 422, (
        f"{path} returned {response.status_code} for an out-of-range "
        f"offset; expected a validation refusal"
    )


@pytest.mark.parametrize("path", PAGINATED)
def test_a_usable_offset_still_works(local, path):
    """The bound must not break ordinary paging."""
    assert local.get(path, params={"offset": 0, "limit": 5}).status_code == 200
    assert local.get(path, params={"offset": 1000}).status_code == 200


def test_the_refusal_names_the_parameter(local):
    """A 422 a caller cannot act on is only a tidier 500."""
    body = local.get(
        "/api/v1/events", params={"offset": BEYOND_SQLITE_INTEGER}
    ).json()
    assert "offset" in json.dumps(body)
