"""
PraHari — Request Size and Rate Limits (ADR-052, blueprint §4.2, §6, §12).

`max_request_size_mb` was a configuration value from the first schema, was
published by `/audit/config` as a security boundary, and was read by
nothing. Rate limiting did not exist at all, though §4.2 lists "rate"
among the things central ingestion must validate.

All tests build their own app with small limits and isolated temporary
databases, so none depends on the shipped defaults.
"""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from app.api.deps import get_db
from app.api.limits import (
    BYTES_PER_MB,
    FixedWindowRateLimiter,
    RateLimitMiddleware,
    RequestSizeLimitMiddleware,
)
from app.api.v1.router import api_v1_router
from app.core.config import AppConfig, get_config
from app.schemas.events import TelemetrySource
from app.storage.database import Database

SOURCE = "limits-sensor"


def _record(i: int = 0) -> dict:
    return {
        "event_id": f"evt-limit-{i}",
        "timestamp": "2026-06-01T12:00:00Z",
        "src_ip": "192.0.2.10",
        "dst_ip": "198.51.100.20",
        "src_port": 40000 + i,
        "dst_port": 443,
        "proto": "tcp",
    }


@pytest.fixture
def db(tmp_path):
    database = Database(db_path=str(tmp_path / "limits.db"))
    database.initialize()
    database.upsert_source(
        TelemetrySource(source_id=SOURCE, name=SOURCE, source_type="json_stream")
    )
    yield database
    database.close()


def _app(db, *, max_bytes=None, rate=None, window=60.0):
    from fastapi import FastAPI

    cfg = AppConfig()
    app = FastAPI()
    app.include_router(api_v1_router, prefix="/api/v1")
    if rate is not None:
        app.add_middleware(
            RateLimitMiddleware,
            limiter=FixedWindowRateLimiter(max_requests=rate, window_seconds=window),
            exempt_paths=("/api/v1/health",),
        )
    if max_bytes is not None:
        app.add_middleware(RequestSizeLimitMiddleware, max_bytes=max_bytes)
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[get_config] = lambda: cfg
    return TestClient(app)


# ──────────────────────────────────────────────────────────────────
# Payload size
# ──────────────────────────────────────────────────────────────────


def test_an_oversized_body_is_refused_with_413(db):
    client = _app(db, max_bytes=2048)

    oversized = "x" * 8192
    response = client.post(
        "/api/v1/stream/ingest/ndjson",
        json={"source_id": SOURCE, "ndjson_content": oversized},
    )

    assert response.status_code == 413
    detail = response.json()["detail"]
    assert detail["error"] == "payload_too_large"
    assert detail["max_bytes"] == 2048


def test_an_oversized_body_persists_nothing(db):
    client = _app(db, max_bytes=2048)
    big = "\n".join(json.dumps(_record(i)) for i in range(200))

    assert client.post(
        "/api/v1/stream/ingest/ndjson",
        json={"source_id": SOURCE, "ndjson_content": big},
    ).status_code == 413

    assert db.count_events() == 0


def test_a_body_within_the_limit_is_unaffected(db):
    client = _app(db, max_bytes=1 * BYTES_PER_MB)

    response = client.post(
        "/api/v1/stream/ingest/ndjson",
        json={"source_id": SOURCE, "ndjson_content": json.dumps(_record()) + "\n"},
    )

    assert response.status_code == 200
    assert db.count_events() == 1


def test_a_malformed_content_length_is_refused_rather_than_guessed(db):
    client = _app(db, max_bytes=2048)

    response = client.post(
        "/api/v1/stream/ingest/ndjson",
        content=b'{"source_id": "x", "ndjson_content": ""}',
        headers={"Content-Length": "not-a-number", "Content-Type": "application/json"},
    )

    assert response.status_code in (400, 422)
    if response.status_code == 400:
        assert response.json()["detail"]["error"] == "malformed_content_length"


def test_the_limit_does_not_apply_to_reads(db):
    """A GET carries no body; the check must not interfere with it."""
    client = _app(db, max_bytes=16)

    assert client.get("/api/v1/health").status_code == 200


def test_the_error_reveals_nothing_about_the_body(db):
    client = _app(db, max_bytes=512)
    secret = "SUPERSECRET-CANARY-VALUE"

    response = client.post(
        "/api/v1/stream/ingest/ndjson",
        json={"source_id": SOURCE, "ndjson_content": secret + "y" * 4096},
    )

    assert response.status_code == 413
    assert secret not in response.text


# ──────────────────────────────────────────────────────────────────
# Rate limiting — the counter itself
# ──────────────────────────────────────────────────────────────────


def test_the_limiter_allows_up_to_the_limit_then_refuses():
    limiter = FixedWindowRateLimiter(max_requests=3, window_seconds=60.0)

    results = [limiter.check("k", now=100.0 + i)[0] for i in range(5)]

    assert results == [True, True, True, False, False]


def test_the_window_resets():
    limiter = FixedWindowRateLimiter(max_requests=2, window_seconds=10.0)

    assert limiter.check("k", now=0.0)[0] is True
    assert limiter.check("k", now=1.0)[0] is True
    assert limiter.check("k", now=2.0)[0] is False
    # Past the window.
    assert limiter.check("k", now=11.0)[0] is True


def test_a_refused_request_does_not_extend_the_penalty():
    """
    A client in a retry loop must be able to recover. Counting refusals
    would hold the window open indefinitely.
    """
    limiter = FixedWindowRateLimiter(max_requests=1, window_seconds=10.0)

    assert limiter.check("k", now=0.0)[0] is True
    for t in (1.0, 2.0, 3.0, 4.0):
        assert limiter.check("k", now=t)[0] is False

    assert limiter.check("k", now=10.5)[0] is True


def test_keys_are_counted_independently():
    limiter = FixedWindowRateLimiter(max_requests=1, window_seconds=60.0)

    assert limiter.check("a", now=0.0)[0] is True
    assert limiter.check("b", now=0.0)[0] is True
    assert limiter.check("a", now=0.0)[0] is False


def test_the_limiter_rejects_a_nonsensical_configuration():
    with pytest.raises(ValueError):
        FixedWindowRateLimiter(max_requests=0, window_seconds=60.0)
    with pytest.raises(ValueError):
        FixedWindowRateLimiter(max_requests=5, window_seconds=0)


def test_expired_windows_are_pruned_so_the_table_stays_bounded():
    limiter = FixedWindowRateLimiter(max_requests=5, window_seconds=1.0)

    for i in range(2000):
        limiter.check(f"key-{i}", now=0.0)
    before = len(limiter._windows)
    # One request well past the window triggers the prune.
    limiter.check("later", now=100.0)

    assert before >= 2000
    assert len(limiter._windows) < before


# ──────────────────────────────────────────────────────────────────
# Rate limiting — over the API
# ──────────────────────────────────────────────────────────────────


def test_exceeding_the_rate_limit_returns_429_with_retry_after(db):
    client = _app(db, rate=3, window=60.0)
    payload = {"source_id": SOURCE, "ndjson_content": json.dumps(_record()) + "\n"}

    codes = [
        client.post("/api/v1/stream/ingest/ndjson", json=payload).status_code
        for _ in range(5)
    ]

    assert codes[:3] == [200, 200, 200]
    assert codes[3:] == [429, 429]

    refused = client.post("/api/v1/stream/ingest/ndjson", json=payload)
    assert refused.headers.get("Retry-After")
    assert refused.json()["detail"]["error"] == "rate_limit_exceeded"


def test_a_rate_limited_request_persists_nothing(db):
    client = _app(db, rate=2, window=60.0)

    for i in range(6):
        client.post(
            "/api/v1/stream/ingest/ndjson",
            json={
                "source_id": SOURCE,
                "ndjson_content": json.dumps(_record(i)) + "\n",
            },
        )

    assert db.count_events() == 2, "a refused request still wrote telemetry"


def test_allowed_responses_advertise_the_remaining_allowance(db):
    client = _app(db, rate=5, window=60.0)

    first = client.get("/api/v1/sources")
    assert first.headers["X-RateLimit-Limit"] == "5"
    assert first.headers["X-RateLimit-Remaining"] == "4"

    second = client.get("/api/v1/sources")
    assert second.headers["X-RateLimit-Remaining"] == "3"


def test_health_stays_reachable_when_the_limit_is_reached(db):
    """
    An operator diagnosing a rate-limited deployment must still be able to
    ask whether the service is alive.
    """
    client = _app(db, rate=1, window=60.0)

    client.get("/api/v1/sources")
    assert client.get("/api/v1/sources").status_code == 429
    assert client.get("/api/v1/health").status_code == 200


# ──────────────────────────────────────────────────────────────────
# What /audit/config now reports
# ──────────────────────────────────────────────────────────────────


def test_the_config_report_states_enforcement_not_just_the_number(db):
    client = _app(db, max_bytes=1 * BYTES_PER_MB, rate=10)

    report = client.get("/api/v1/audit/config").json()

    assert report["request_size_limit_enforced"] is True
    assert report["rate_limit_enforced"] is True
    assert report["rate_limit_requests"] > 0


def test_a_disabled_rate_limit_is_reported_as_disabled(db):
    """Reporting a control as active when it is switched off is the
    defect this field exists to prevent."""
    from fastapi import FastAPI

    cfg = AppConfig(rate_limit_requests=0)
    app = FastAPI()
    app.include_router(api_v1_router, prefix="/api/v1")
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[get_config] = lambda: cfg

    with TestClient(app) as client:
        report = client.get("/api/v1/audit/config").json()

    assert report["rate_limit_enforced"] is False


def test_lowering_the_configured_import_ceiling_actually_bites(db):
    """
    `max_import_records` was a config value the import handler never read:
    the request model carried its own hard-coded ceiling, so an operator
    lowering the policy saw no effect. The effective limit is now the
    lower of the two.
    """
    from fastapi import FastAPI

    cfg = AppConfig(max_import_records=2)
    app = FastAPI()
    app.include_router(api_v1_router, prefix="/api/v1")
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[get_config] = lambda: cfg

    header = "timestamp,src_ip,dst_ip,src_port,dst_port,protocol\n"
    rows = "".join(
        f"2026-06-01T12:00:0{i}Z,192.0.2.1,198.51.100.1,{5000 + i},443,TCP\n"
        for i in range(5)
    )

    with TestClient(app) as client:
        body = client.post(
            "/api/v1/import/csv/raw",
            json={"source_id": SOURCE, "csv_content": header + rows},
        ).json()

    assert body["total_records"] <= 2, (
        f"the configured ceiling of 2 was ignored: {body['total_records']}"
    )
