"""
PraHari — Audit Actor Attribution (ADR-067) and Rejection Visibility (ADR-068).

ADR-067. No audit call site passed `user_identity`, so in central mode
every entry was attributed to "local_operator" — a person at the console
who did none of it. The audit trail named the wrong actor for every
sensor ingest, credential change and prune.

ADR-068. On the stream path, a batch in which EVERY record was rejected
skipped the block that records measurements. The response reported
`stored_records: None` ("not reported") for a count that was measured —
zero — and the rejections never reached /system/health. A sensor whose
every record fails validation showed `events_rejected: 0`.

Both are tested at the storage and metrics layers, not by status codes.
Also covered: request ids and identities stay with their own request
under real concurrency. Temporary databases only.
"""

from __future__ import annotations

import asyncio
import json

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.auth import CentralAuthMiddleware
from app.api.deps import get_db
from app.api.request_context import (
    LOCAL_OPERATOR_IDENTITY,
    RequestIdMiddleware,
    describe_principal,
    get_principal_identity,
    get_request_id,
)
from app.api.v1.router import api_v1_router
from app.core.config import AppConfig, DeploymentMode, get_config
from app.core.security import Credential, CredentialStore, Principal, Role
from app.schemas.events import TelemetrySource
from app.services.admission import get_admission_controller, reset_admission_controller
from app.storage.database import Database

INGEST = "/api/v1/stream/ingest/ndjson"


def _record(i: int, prefix: str = "evt") -> str:
    return json.dumps({
        "event_id": f"{prefix}-{i}",
        "timestamp": "2026-06-01T12:00:00Z",
        "src_ip": "192.0.2.10",
        "dst_ip": "198.51.100.20",
        "src_port": 40000 + i,
        "dst_port": 443,
        "proto": "tcp",
    })


def _body(source: str, lines: list[str]) -> dict:
    return {"source_id": source, "ndjson_content": "\n".join(lines) + "\n",
            "data_category": "live_telemetry"}


@pytest.fixture
def db(tmp_path):
    database = Database(db_path=str(tmp_path / "audit.db"))
    database.initialize()
    for sid in ("sensor-a", "sensor-b"):
        database.upsert_source(TelemetrySource(source_id=sid, name=sid, source_type="json_stream"))
    yield database
    database.close()


def _app(db: Database, store: CredentialStore | None = None) -> FastAPI:
    app = FastAPI()
    app.include_router(api_v1_router, prefix="/api/v1")
    if store is not None:
        cfg = AppConfig(deployment_mode=DeploymentMode.CENTRAL)
        app.add_middleware(CentralAuthMiddleware, store=store,
                           public_paths=cfg.central_public_paths)
    else:
        cfg = AppConfig()
    app.add_middleware(RequestIdMiddleware)  # outermost, as in main.py
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[get_config] = lambda: cfg
    return app


@pytest.fixture
def central(db):
    creds, tokens = {}, {}
    for name, source, role in (("a", "sensor-a", Role.INGEST),
                               ("b", "sensor-b", Role.INGEST),
                               ("admin", "ops", Role.ADMIN)):
        creds[name], tokens[name] = Credential.create(source, role, name)
    app = _app(db, CredentialStore(list(creds.values())))
    with TestClient(app) as client:
        yield client, tokens, creds, db


def _audit(db: Database, action: str | None = None) -> list[dict]:
    q = "SELECT action, user_identity, request_id FROM audit_events"
    params: tuple = ()
    if action:
        q += " WHERE action = ?"
        params = (action,)
    with db.get_connection() as conn:
        return [dict(r) for r in conn.execute(q + " ORDER BY id", params)]


# ──────────────────────────────────────────────────────────────────
# ADR-067: the actor is the authenticated credential
# ──────────────────────────────────────────────────────────────────


def test_a_central_ingest_is_attributed_to_its_credential_not_a_local_operator(central):
    client, tokens, creds, db = central

    r = client.post(INGEST, json=_body("sensor-a", [_record(1)]),
                    headers={"Authorization": f"Bearer {tokens['a']}"})

    assert r.status_code == 200
    (entry,) = _audit(db, "ingest_ndjson_stream")
    assert entry["user_identity"] == describe_principal(
        Principal(creds["a"].credential_id, "sensor-a", Role.INGEST)
    )
    assert entry["user_identity"] != LOCAL_OPERATOR_IDENTITY


def test_two_sensors_are_told_apart_in_the_audit_trail(central):
    client, tokens, creds, db = central

    client.post(INGEST, json=_body("sensor-a", [_record(1, "a")]),
                headers={"Authorization": f"Bearer {tokens['a']}"})
    client.post(INGEST, json=_body("sensor-b", [_record(1, "b")]),
                headers={"Authorization": f"Bearer {tokens['b']}"})

    identities = [e["user_identity"] for e in _audit(db, "ingest_ndjson_stream")]
    assert identities[0].startswith(f"credential:{creds['a'].credential_id} ")
    assert identities[1].startswith(f"credential:{creds['b'].credential_id} ")


def test_an_admin_action_is_attributed_to_the_admin_credential(central):
    client, tokens, creds, db = central
    client.post("/api/v1/analysis/run", json={},
                headers={"Authorization": f"Bearer {tokens['admin']}"})

    (entry,) = _audit(db, "run_descriptive_analysis")
    assert f"credential:{creds['admin'].credential_id}" in entry["user_identity"]
    assert "role:admin" in entry["user_identity"]


def test_the_identity_never_contains_the_token(central):
    client, tokens, _, db = central
    client.post(INGEST, json=_body("sensor-a", [_record(1)]),
                headers={"Authorization": f"Bearer {tokens['a']}"})

    for entry in _audit(db):
        for token in tokens.values():
            assert token not in (entry["user_identity"] or "")


def test_a_local_deployment_is_still_the_local_operator(db):
    with TestClient(_app(db)) as client:
        client.post(INGEST, json=_body("sensor-a", [_record(1)]))

    (entry,) = _audit(db, "ingest_ndjson_stream")
    assert entry["user_identity"] == LOCAL_OPERATOR_IDENTITY


def test_outside_any_request_there_is_no_request_id_and_no_principal(db):
    """The CLI, the collector and tests: the accurate answer is none."""
    assert get_request_id() is None
    assert get_principal_identity() is None

    db.log_audit(action="collector_poll", resource_type="collector")

    (entry,) = _audit(db, "collector_poll")
    assert entry["request_id"] is None
    assert entry["user_identity"] == LOCAL_OPERATOR_IDENTITY


def test_an_explicit_identity_still_wins(db):
    db.log_audit(action="cli_change", resource_type="x", user_identity="cli:operator")
    (entry,) = _audit(db, "cli_change")
    assert entry["user_identity"] == "cli:operator"


def test_the_identity_does_not_outlive_its_request(central):
    client, tokens, _, _ = central
    client.post(INGEST, json=_body("sensor-a", [_record(1)]),
                headers={"Authorization": f"Bearer {tokens['a']}"})

    assert get_principal_identity() is None


# ──────────────────────────────────────────────────────────────────
# Context isolation under real concurrency
# ──────────────────────────────────────────────────────────────────


def test_concurrent_requests_keep_their_own_request_id_and_identity(central):
    """
    Twenty requests in flight at once, alternating between two
    credentials. Every audit row must carry the request id its own
    request sent and the identity of its own credential — a contextvar
    that leaked across tasks or worker threads would mismatch them.
    """
    _, tokens, creds, db = central
    app = _app(db, CredentialStore(list(creds.values())))

    async def one(client, i):
        who = "a" if i % 2 == 0 else "b"
        source = f"sensor-{who}"
        r = await client.post(
            INGEST, json=_body(source, [_record(i, f"conc-{who}")]),
            headers={"Authorization": f"Bearer {tokens[who]}",
                     "X-Request-ID": f"conc-{i:02d}"},
        )
        return i, who, r.status_code, r.headers.get("x-request-id")

    async def run():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            return await asyncio.gather(*(one(client, i) for i in range(20)))

    # Admission control would correctly refuse some of twenty simultaneous
    # ingests with 503 (its own tests cover that). Capacity is raised here
    # so every request is admitted and this test measures one thing:
    # whether context crosses between concurrently running handlers.
    reset_admission_controller(max_concurrent=64)
    try:
        results = asyncio.run(run())
    finally:
        reset_admission_controller()

    for i, _, status, echoed in results:
        assert status == 200
        assert echoed == f"conc-{i:02d}", "a response carried another request's id"

    rows = {e["request_id"]: e["user_identity"] for e in _audit(db, "ingest_ndjson_stream")}
    assert len(rows) == 20, "every request must be audited exactly once under its own id"
    for i in range(20):
        who = "a" if i % 2 == 0 else "b"
        identity = rows[f"conc-{i:02d}"]
        assert identity.startswith(f"credential:{creds[who].credential_id} "), (
            f"request {i} was attributed to the wrong credential: {identity}"
        )


# ──────────────────────────────────────────────────────────────────
# ADR-068: a fully rejected batch is measured, and visible in health
# ──────────────────────────────────────────────────────────────────


@pytest.fixture
def local(db):
    reset_admission_controller()
    with TestClient(_app(db)) as client:
        yield client, db
    reset_admission_controller()


def test_a_fully_rejected_batch_reports_zero_stored_not_unknown(local):
    client, _ = local

    r = client.post(INGEST, json=_body("sensor-a", ["{not json}", json.dumps({"no": "fields"})]))

    assert r.status_code == 200
    summary = r.json()
    assert summary["rejected_records"] == 2
    assert summary["stored_records"] == 0, "measured zero was reported as 'not reported'"
    assert summary["duplicate_records"] == 0


def test_a_fully_rejected_batch_reaches_system_health(local):
    client, _ = local
    before = get_admission_controller().snapshot()["events_rejected"]

    client.post(INGEST, json=_body("sensor-a", ["{bad", "{worse", "[]"]))

    after = get_admission_controller().snapshot()["events_rejected"]
    assert after - before == 3, (
        "a sensor whose every record is rejected must not look healthy"
    )


def test_a_fully_rejected_batch_stores_nothing(local):
    client, db = local
    client.post(INGEST, json=_body("sensor-a", ["{bad"]))

    with db.get_connection() as conn:
        assert conn.execute("SELECT COUNT(*) FROM normalized_events").fetchone()[0] == 0


def test_a_mixed_batch_still_counts_both_sides(local):
    client, _ = local
    before = get_admission_controller().snapshot()

    r = client.post(INGEST, json=_body("sensor-a", [_record(1, "mix"), "{bad"]))

    summary = r.json()
    after = get_admission_controller().snapshot()
    assert summary["stored_records"] == 1 and summary["rejected_records"] == 1
    assert after["events_stored"] - before["events_stored"] == 1
    assert after["events_rejected"] - before["events_rejected"] == 1


@pytest.mark.parametrize("line", ["[]", "42", '"a string"', "null", "[1, 2]", "true"])
def test_a_non_object_json_line_costs_only_itself(local, line):
    """
    Valid JSON that is not an object used to raise AttributeError inside
    the adapter, turning the whole batch into a 500 and losing the good
    record beside it.
    """
    client, db = local

    r = client.post(INGEST, json=_body("sensor-a", [_record(1, f"beside-{line}"), line]))

    assert r.status_code == 200, r.text
    summary = r.json()
    assert summary["stored_records"] == 1, "the good record must survive its neighbour"
    assert summary["rejected_records"] == 1
    assert summary["rejection_reasons"].get("record_not_an_object") == 1
