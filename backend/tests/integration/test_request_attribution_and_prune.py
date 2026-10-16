"""
PraHari — Request Attribution and Analysis-History Retention
(ADR-063, ADR-064).

Two gaps left open by ADR-062 and recorded there as recommended-not-done.

**Attribution.** An unexplained `descriptive_analyses` row took a code
trace to attribute, because `audit_events` stored only
`user_identity="local_operator"` — no request id, method or path. A
correlation id now reaches every audit write through a ContextVar, so
existing call sites gain it without being touched, and it is NULL for
anything with no request behind it.

**Retention.** `POST /analysis/run` could still grow the table without
bound. Analyses are historical records of what was computed, not cache
entries, so nothing expires them automatically. Trimming is an explicit,
confirmed, audited administrative act — dry-run by default, mirroring the
telemetry retention service.

Temporary databases only. The protected databases are never opened.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.auth import CentralAuthMiddleware
from app.api.deps import get_db
from app.api.request_context import (
    MAX_REQUEST_ID_LENGTH,
    REQUEST_ID_HEADER,
    RequestIdMiddleware,
    get_request_id,
    sanitise_request_id,
)
from app.api.v1.analysis import ANALYSIS_PRUNE_CONFIRMATION
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

SOURCE = "attr-sensor"
NOW = datetime(2026, 10, 17, 12, 0, 0, tzinfo=timezone.utc)


def _event(idx: int) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=f"attr-{idx}",
        source_id=SOURCE,
        data_category=DataCategory.LIVE_TELEMETRY,
        observed_at=NOW + timedelta(seconds=idx),
        event_type=EventType.NETWORK_FLOW,
        src_ip="192.0.2.10",
        dst_ip="198.51.100.20",
        src_port=40000 + idx,
        dst_port=443,
        protocol="TCP",
        bytes_total=100,
        label_provenance=LabelProvenance.UNLABELED,
    )


@pytest.fixture
def db(tmp_path):
    database = Database(db_path=str(tmp_path / "attribution.db"))
    database.initialize()
    database.upsert_source(
        TelemetrySource(source_id=SOURCE, name=SOURCE, source_type="json_stream")
    )
    database.insert_events([_event(i) for i in range(5)])
    yield database
    database.close()


def _app(db, *, central=False):
    cfg = AppConfig(
        deployment_mode=DeploymentMode.CENTRAL if central else DeploymentMode.LOCAL
    )
    app = FastAPI()
    app.include_router(api_v1_router, prefix="/api/v1")
    tokens = {}
    if central:
        admin, admin_token = Credential.create("central", Role.ADMIN, "operator")
        sensor, sensor_token = Credential.create(SOURCE, Role.INGEST, "sensor")
        app.add_middleware(
            CentralAuthMiddleware,
            store=CredentialStore([admin, sensor]),
            public_paths=cfg.central_public_paths,
        )
        tokens = {"admin": admin_token, "sensor": sensor_token}
    app.add_middleware(RequestIdMiddleware)
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[get_config] = lambda: cfg
    return TestClient(app), tokens


def _audit(db, action: str) -> list[sqlite3.Row]:
    with db.get_connection() as conn:
        return conn.execute(
            "SELECT * FROM audit_events WHERE action = ? ORDER BY id DESC", (action,)
        ).fetchall()


def _analyses(db) -> int:
    with db.get_connection() as conn:
        return conn.execute("SELECT COUNT(*) FROM descriptive_analyses").fetchone()[0]


# ──────────────────────────────────────────────────────────────────
# Correlation ids
# ──────────────────────────────────────────────────────────────────


def test_a_response_carries_a_request_id(db):
    client, _ = _app(db)

    response = client.get("/api/v1/health")

    assert response.headers.get(REQUEST_ID_HEADER)


def test_each_request_gets_a_distinct_id(db):
    client, _ = _app(db)

    ids = {client.get("/api/v1/health").headers[REQUEST_ID_HEADER] for _ in range(5)}

    assert len(ids) == 5


def test_an_audit_entry_records_the_request_that_caused_it(db):
    """The gap that made the ADR-062 write untraceable."""
    client, _ = _app(db)

    response = client.post("/api/v1/analysis/run", json={})
    request_id = response.headers[REQUEST_ID_HEADER]

    rows = _audit(db, "run_descriptive_analysis")
    assert rows, "the POST wrote no audit entry"
    assert rows[0]["request_id"] == request_id


def test_existing_call_sites_gained_attribution_without_being_changed(db):
    """
    The point of the ContextVar: a route that already called log_audit
    now records the id with no edit to that route.
    """
    client, _ = _app(db)

    response = client.patch(
        f"/api/v1/sources/{SOURCE}/enabled", json={"enabled": False}
    )
    request_id = response.headers[REQUEST_ID_HEADER]

    rows = _audit(db, "set_source_enabled")
    assert rows and rows[0]["request_id"] == request_id


def test_a_client_supplied_id_is_honoured(db):
    client, _ = _app(db)
    supplied = "trace-abc-123"

    response = client.post(
        "/api/v1/analysis/run", json={}, headers={REQUEST_ID_HEADER: supplied}
    )

    assert response.headers[REQUEST_ID_HEADER] == supplied
    assert _audit(db, "run_descriptive_analysis")[0]["request_id"] == supplied


@pytest.mark.parametrize(
    "hostile",
    [
        "x" * (MAX_REQUEST_ID_LENGTH + 1),       # unbounded
        "id with spaces",
        "id\nwith-newline",                       # log injection
        "id\x00null",
        "'; DROP TABLE audit_events; --",
        "",
    ],
)
def test_a_hostile_client_id_is_replaced_not_stored(db, hostile):
    """
    This value is persisted and shown in reports, so an unbounded or
    control-character id would be a log-injection vector.
    """
    client, _ = _app(db)

    response = client.post(
        "/api/v1/analysis/run", json={}, headers={REQUEST_ID_HEADER: hostile}
    )

    recorded = response.headers[REQUEST_ID_HEADER]
    assert recorded != hostile
    assert len(recorded) <= MAX_REQUEST_ID_LENGTH
    assert _audit(db, "run_descriptive_analysis")[0]["request_id"] == recorded


def test_sanitisation_rejects_rather_than_truncates():
    """
    A truncated 10 KB header would look legitimate while no longer
    matching what the client holds.
    """
    assert sanitise_request_id("ok-123") == "ok-123"
    assert sanitise_request_id("x" * 200) is None
    assert sanitise_request_id("bad value") is None
    assert sanitise_request_id(None) is None


def test_outside_a_request_the_id_is_none(db):
    """A collector poll, the CLI and a test have no request behind them."""
    assert get_request_id() is None

    db.log_audit(action="background_task", resource_type="test")

    rows = _audit(db, "background_task")
    assert rows and rows[0]["request_id"] is None, (
        "a placeholder id was invented for a non-request write"
    )


def test_an_audit_entry_is_still_written_on_a_pre_migration_database(tmp_path):
    """
    An audit entry matters more than its attribution, so a database
    without the column must still record the event.
    """
    db_file = tmp_path / "legacy.db"
    # The pre-ADR-063 audit_events shape, written out explicitly. Filtering
    # the real DDL by line leaves a dangling comma, and slicing it on
    # semicolons is not safe either.
    con = sqlite3.connect(db_file)
    con.executescript(
        """
        CREATE TABLE audit_events (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp       TEXT NOT NULL,
            action          TEXT NOT NULL,
            resource_type   TEXT,
            resource_id     TEXT,
            details         TEXT,
            user_identity   TEXT DEFAULT 'local_operator'
        );
        """
    )
    con.commit()
    cols = {r[1] for r in con.execute("PRAGMA table_info(audit_events)")}
    con.close()
    assert "request_id" not in cols, "precondition: the column is absent"

    # Opened WITHOUT initialize(), so the migration does not run.
    database = Database(db_path=str(db_file))
    try:
        database.log_audit(action="legacy_write", resource_type="test")
        with database.get_connection() as conn:
            n = conn.execute(
                "SELECT COUNT(*) FROM audit_events WHERE action='legacy_write'"
            ).fetchone()[0]
    finally:
        database.close()

    assert n == 1, "the audit entry was lost because the column was missing"


def test_the_audit_api_exposes_the_request_id(db):
    client, _ = _app(db)
    response = client.post("/api/v1/analysis/run", json={})
    request_id = response.headers[REQUEST_ID_HEADER]

    logs = client.get("/api/v1/audit/logs").json()

    match = [e for e in logs if e["action"] == "run_descriptive_analysis"]
    assert match and match[0]["request_id"] == request_id


def test_the_recorded_id_carries_no_client_metadata(db):
    """
    Only the correlation id is stored. An address or user agent would put
    identifying data in a long-lived table.
    """
    client, _ = _app(db)
    client.post("/api/v1/analysis/run", json={},
                headers={"User-Agent": "secret-agent/9.9"})

    row = _audit(db, "run_descriptive_analysis")[0]
    blob = " ".join(str(row[k]) for k in row.keys())

    assert "secret-agent" not in blob
    assert "testclient" not in blob.lower()


# ──────────────────────────────────────────────────────────────────
# Analysis history: dry run by default
# ──────────────────────────────────────────────────────────────────


def _make_analyses(client, n: int) -> None:
    for _ in range(n):
        assert client.post("/api/v1/analysis/run", json={}).status_code == 200


def test_prune_is_a_dry_run_without_the_confirmation(db):
    client, _ = _app(db)
    _make_analyses(client, 5)
    before = _analyses(db)

    body = client.post("/api/v1/analysis/prune", json={"keep": 2}).json()

    assert body["dry_run"] is True
    assert body["deleted"] == 0
    assert body["would_delete"] == 3
    assert _analyses(db) == before, "a dry run deleted records"


def test_the_dry_run_names_what_it_would_delete(db):
    client, _ = _app(db)
    _make_analyses(client, 4)

    body = client.post("/api/v1/analysis/prune", json={"keep": 1}).json()

    assert len(body["would_delete_ids"]) == 3
    assert body["confirmation_required"] == ANALYSIS_PRUNE_CONFIRMATION


def test_a_wrong_confirmation_token_deletes_nothing(db):
    client, _ = _app(db)
    _make_analyses(client, 4)
    before = _analyses(db)

    body = client.post(
        "/api/v1/analysis/prune", json={"keep": 1, "confirm": "yes please"}
    ).json()

    assert body["dry_run"] is True
    assert _analyses(db) == before


def test_a_confirmed_prune_keeps_exactly_the_newest_n(db):
    client, _ = _app(db)
    _make_analyses(client, 6)

    with db.get_connection() as conn:
        newest = [
            r["analysis_id"] for r in conn.execute(
                "SELECT analysis_id FROM descriptive_analyses "
                "ORDER BY computed_at DESC, analysis_id DESC LIMIT 2"
            )
        ]

    body = client.post(
        "/api/v1/analysis/prune",
        json={"keep": 2, "confirm": ANALYSIS_PRUNE_CONFIRMATION, "reason": "tidy"},
    ).json()

    assert body["dry_run"] is False
    assert body["deleted"] == 4
    assert _analyses(db) == 2
    with db.get_connection() as conn:
        remaining = {
            r["analysis_id"] for r in conn.execute(
                "SELECT analysis_id FROM descriptive_analyses"
            )
        }
    assert remaining == set(newest), "the wrong analyses survived"


def test_pruning_is_audited(db):
    client, _ = _app(db)
    _make_analyses(client, 3)

    response = client.post(
        "/api/v1/analysis/prune",
        json={"keep": 1, "confirm": ANALYSIS_PRUNE_CONFIRMATION},
    )

    rows = _audit(db, "prune_analysis_history")
    assert rows
    assert rows[0]["request_id"] == response.headers[REQUEST_ID_HEADER]


def test_keep_must_be_at_least_one(db):
    """This trims history; it does not empty it."""
    client, _ = _app(db)
    _make_analyses(client, 3)

    for bad in (0, -1):
        assert client.post(
            "/api/v1/analysis/prune",
            json={"keep": bad, "confirm": ANALYSIS_PRUNE_CONFIRMATION},
        ).status_code == 422
    assert _analyses(db) == 3


def test_pruning_below_the_count_is_a_no_op(db):
    client, _ = _app(db)
    _make_analyses(client, 2)

    body = client.post(
        "/api/v1/analysis/prune",
        json={"keep": 10, "confirm": ANALYSIS_PRUNE_CONFIRMATION},
    ).json()

    assert body["deleted"] == 0
    assert _analyses(db) == 2


def test_pruning_never_touches_telemetry(db):
    client, _ = _app(db)
    _make_analyses(client, 4)
    events_before = db.count_events()

    client.post(
        "/api/v1/analysis/prune",
        json={"keep": 1, "confirm": ANALYSIS_PRUNE_CONFIRMATION},
    )

    assert db.count_events() == events_before == 5


def test_nothing_prunes_automatically(db):
    """
    The central guarantee. No read, no write, no startup and no analysis
    run may expire history as a side effect.
    """
    client, _ = _app(db)
    _make_analyses(client, 6)
    assert _analyses(db) == 6

    for _ in range(5):
        client.get("/api/v1/analysis/latest")
        client.get("/api/v1/health")
        client.get("/api/v1/audit/logs")
    client.post("/api/v1/analysis/run", json={})

    assert _analyses(db) == 7, "something pruned history without being asked"


def test_the_configured_limit_is_a_suggestion_not_an_enforcer(db):
    """
    `analysis_history_limit` must not cause deletion on its own: the
    default is 0 (keep everything) and even a positive value only informs
    the explicit endpoint.
    """
    cfg = AppConfig(analysis_history_limit=1)
    app = FastAPI()
    app.include_router(api_v1_router, prefix="/api/v1")
    app.add_middleware(RequestIdMiddleware)
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[get_config] = lambda: cfg

    with TestClient(app) as client:
        _make_analyses(client, 4)
        assert _analyses(db) == 4, "the configured limit pruned on its own"
        body = client.post("/api/v1/analysis/prune", json={"keep": 2}).json()

    assert body["dry_run"] is True
    assert _analyses(db) == 4


def test_the_default_configuration_keeps_everything():
    assert AppConfig().analysis_history_limit == 0


# ──────────────────────────────────────────────────────────────────
# Authorization
# ──────────────────────────────────────────────────────────────────


def test_a_sensor_credential_cannot_prune_history(db):
    client, tokens = _app(db, central=True)
    client.post(
        "/api/v1/analysis/run", json={},
        headers={"Authorization": f"Bearer {tokens['admin']}"},
    )
    before = _analyses(db)

    response = client.post(
        "/api/v1/analysis/prune",
        json={"keep": 1, "confirm": ANALYSIS_PRUNE_CONFIRMATION},
        headers={"Authorization": f"Bearer {tokens['sensor']}"},
    )

    assert response.status_code == 403
    assert _analyses(db) == before, "an unauthorized prune took effect"


def test_an_unauthenticated_prune_is_refused_in_central_mode(db):
    client, tokens = _app(db, central=True)
    client.post(
        "/api/v1/analysis/run", json={},
        headers={"Authorization": f"Bearer {tokens['admin']}"},
    )
    before = _analyses(db)

    response = client.post(
        "/api/v1/analysis/prune",
        json={"keep": 1, "confirm": ANALYSIS_PRUNE_CONFIRMATION},
    )

    assert response.status_code == 401
    assert _analyses(db) == before


def test_an_admin_may_prune_in_central_mode(db):
    client, tokens = _app(db, central=True)
    auth = {"Authorization": f"Bearer {tokens['admin']}"}
    for _ in range(3):
        client.post("/api/v1/analysis/run", json={}, headers=auth)

    body = client.post(
        "/api/v1/analysis/prune",
        json={"keep": 1, "confirm": ANALYSIS_PRUNE_CONFIRMATION},
        headers=auth,
    ).json()

    assert body["deleted"] == 2
    assert _analyses(db) == 1
