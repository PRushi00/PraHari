"""
PraHari — Sensor Forwarding Agent (ADR-058, blueprint §4.2, §5, §13).

Two layers of testing:

1. A scripted transport, so every failure mode — timeout, 401, 409, 429,
   503, malformed body — is exercised deterministically.
2. A real end-to-end run against an **in-process** PraHari built with a
   temporary database, proving the agent speaks the actual ingestion
   contract rather than a test double's idea of it.

No socket is opened to anything outside this process, and no test reads
either protected database.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.agents.sensor_agent import (
    AgentConfig,
    ConfigError,
    OverflowPolicy,
    SensorAgent,
    validate_event,
)
from app.api.auth import CentralAuthMiddleware
from app.api.deps import get_db
from app.api.v1.router import api_v1_router
from app.core.config import AppConfig, DeploymentMode, get_config
from app.core.security import Credential, CredentialStore, Role
from app.schemas.events import TelemetrySource
from app.storage.database import Database

SOURCE = "agent-sensor-a"
ENDPOINT = "https://central.invalid/api/v1/stream/ingest/ndjson"
TOKEN = "test-token-not-a-real-credential"


def _event(i: int) -> dict:
    return {
        "event_id": f"agent-evt-{i}",
        "timestamp": "2026-06-01T12:00:00Z",
        "src_ip": "192.0.2.10",
        "dst_ip": "198.51.100.20",
        "src_port": 40000 + i,
        "dst_port": 443,
        "proto": "tcp",
    }


def _config(**kw) -> AgentConfig:
    base = dict(endpoint=ENDPOINT, source_id=SOURCE, token=TOKEN, batch_size=10)
    base.update(kw)
    return AgentConfig(**base)


class ScriptedTransport:
    """Returns queued responses; records every request it was given."""

    def __init__(self, responses):
        self._responses = list(responses)
        self.requests: list[dict] = []

    def post(self, url, body, headers, timeout):
        self.requests.append(
            {"url": url, "body": json.loads(body.decode()), "headers": headers,
             "timeout": timeout}
        )
        if not self._responses:
            return 200, {}, json.dumps({"stored_records": 0}).encode()
        item = self._responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def _ok(stored=1, duplicates=0):
    return (
        200, {},
        json.dumps({"stored_records": stored, "duplicate_records": duplicates}).encode(),
    )


def _err(status, error="x", message="y", headers=None):
    return (
        status, headers or {},
        json.dumps({"detail": {"error": error, "message": message}}).encode(),
    )


@pytest.fixture
def no_sleep():
    """Backoff must not actually delay the suite."""
    slept: list[float] = []
    yield slept, lambda s: slept.append(s)


# ──────────────────────────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "kw, fragment",
    [
        ({"endpoint": ""}, "absolute http"),
        ({"endpoint": "ftp://x/y"}, "absolute http"),
        ({"source_id": "  "}, "source_id is required"),
        ({"token": ""}, "token is required"),
        ({"batch_size": 0}, "batch_size"),
        ({"buffer_capacity": 1, "batch_size": 10}, "buffer_capacity"),
        ({"timeout_seconds": 0}, "timeout_seconds"),
        ({"max_attempts": 0}, "max_attempts"),
        ({"overflow_policy": "nonsense"}, "overflow_policy"),
    ],
)
def test_malformed_configuration_is_refused(kw, fragment):
    with pytest.raises(ConfigError) as exc:
        _config(**kw)
    assert fragment in str(exc.value)


def test_plaintext_http_to_a_remote_host_is_refused():
    """A bearer credential over plaintext is compromised on first use."""
    with pytest.raises(ConfigError) as exc:
        _config(endpoint="http://central.example/api/v1/stream/ingest/ndjson")
    assert "plaintext" in str(exc.value).lower()


def test_loopback_plaintext_is_allowed_for_local_testing():
    cfg = _config(endpoint="http://127.0.0.1:8000/api/v1/stream/ingest/ndjson")
    assert cfg.endpoint.startswith("http://127.0.0.1")


def test_the_configuration_never_prints_the_token():
    cfg = _config()
    assert TOKEN not in repr(cfg)
    assert TOKEN not in str(cfg)
    assert "redacted" in repr(cfg)


# ──────────────────────────────────────────────────────────────────
# Validation and buffering
# ──────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "record",
    [
        {},
        {"timestamp": "2026-06-01T12:00:00Z", "src_ip": "1.1.1.1", "dst_ip": "2.2.2.2"},
        {"event_id": "  ", "timestamp": "t", "src_ip": "1.1.1.1", "dst_ip": "2.2.2.2"},
        "not-a-dict",
    ],
)
def test_an_invalid_event_is_rejected_before_it_reaches_the_wire(record):
    agent = SensorAgent(_config(), transport=ScriptedTransport([]))

    assert agent.offer(record) is False
    assert agent.buffered == 0
    assert agent.stats.events_invalid == 1


def test_event_id_is_required_because_retries_depend_on_it():
    """Without it a retry is not deduplicated server-side (ADR-050)."""
    problems = validate_event(
        {"timestamp": "t", "src_ip": "1.1.1.1", "dst_ip": "2.2.2.2"}
    )
    assert "missing_event_id" in problems


def test_the_buffer_is_bounded_and_drops_the_oldest_by_default():
    agent = SensorAgent(_config(buffer_capacity=10, batch_size=5),
                        transport=ScriptedTransport([]))

    for i in range(15):
        agent.offer(_event(i))

    assert agent.buffered == 10
    assert agent.stats.events_dropped_overflow == 5
    # The freshest telemetry was kept.
    batch = agent._take_batch()
    assert batch[0]["event_id"] == "agent-evt-5"


def test_drop_newest_refuses_the_offer_instead():
    agent = SensorAgent(
        _config(buffer_capacity=10, batch_size=5,
                overflow_policy=OverflowPolicy.DROP_NEWEST),
        transport=ScriptedTransport([]),
    )
    for i in range(10):
        agent.offer(_event(i))

    assert agent.offer(_event(99)) is False
    assert agent.buffered == 10
    assert agent.stats.events_dropped_overflow == 1


def test_nothing_is_dropped_silently():
    agent = SensorAgent(_config(buffer_capacity=2, batch_size=2),
                        transport=ScriptedTransport([]))
    for i in range(5):
        agent.offer(_event(i))

    assert agent.stats.events_dropped_overflow == 3
    assert agent.health()["events_dropped_overflow"] == 3


# ──────────────────────────────────────────────────────────────────
# Delivery outcomes
# ──────────────────────────────────────────────────────────────────


def test_a_successful_forward_is_authenticated_and_acknowledged():
    transport = ScriptedTransport([_ok(stored=3)])
    agent = SensorAgent(_config(), transport=transport)
    for i in range(3):
        agent.offer(_event(i))

    result = agent.flush_once()

    assert result.ok and result.stored == 3
    assert agent.buffered == 0
    sent = transport.requests[0]
    assert sent["headers"]["Authorization"] == f"Bearer {TOKEN}"
    assert sent["body"]["source_id"] == SOURCE
    assert sent["headers"]["Idempotency-Key"]


def test_a_timeout_is_retried_then_succeeds(no_sleep):
    slept, sleep_fn = no_sleep
    transport = ScriptedTransport([TimeoutError("timed out"), _ok(stored=1)])
    agent = SensorAgent(_config(), transport=transport, sleep_fn=sleep_fn)
    agent.offer(_event(0))

    result = agent.flush_once()

    assert result.ok
    assert agent.stats.retries == 1
    assert len(slept) == 1 and slept[0] > 0
    assert agent.buffered == 0


def test_a_connection_error_is_treated_as_transient(no_sleep):
    slept, sleep_fn = no_sleep
    transport = ScriptedTransport([OSError("connection refused"), _ok()])
    agent = SensorAgent(_config(), transport=transport, sleep_fn=sleep_fn)
    agent.offer(_event(0))

    assert agent.flush_once().ok


def test_a_temporary_server_failure_is_retried(no_sleep):
    slept, sleep_fn = no_sleep
    transport = ScriptedTransport([_err(503, "ingestion_overloaded"), _ok()])
    agent = SensorAgent(_config(), transport=transport, sleep_fn=sleep_fn)
    agent.offer(_event(0))

    assert agent.flush_once().ok
    assert agent.stats.retries == 1


@pytest.mark.parametrize(
    "status, error",
    [(400, "bad_request"), (401, "invalid_credential"),
     (403, "source_identity_mismatch"), (413, "payload_too_large")],
)
def test_a_permanent_refusal_is_not_retried(status, error, no_sleep):
    """Resending the same bytes cannot help; retrying would loop."""
    slept, sleep_fn = no_sleep
    transport = ScriptedTransport([_err(status, error)])
    agent = SensorAgent(_config(), transport=transport, sleep_fn=sleep_fn)
    agent.offer(_event(0))

    result = agent.flush_once()

    assert not result.ok and not result.retryable
    assert len(transport.requests) == 1, "a permanent failure was retried"
    assert slept == []
    assert agent.stats.batches_failed_permanent == 1
    assert agent.buffered == 0, "a permanently refused batch must not be requeued"


def test_an_unauthorized_response_stops_immediately(no_sleep):
    slept, sleep_fn = no_sleep
    transport = ScriptedTransport([_err(401, "invalid_credential")] * 5)
    agent = SensorAgent(_config(), transport=transport, sleep_fn=sleep_fn)
    agent.offer(_event(0))

    agent.flush_once()

    assert len(transport.requests) == 1


def test_rate_limiting_honours_retry_after(no_sleep):
    slept, sleep_fn = no_sleep
    transport = ScriptedTransport([
        _err(429, "rate_limit_exceeded", headers={"retry-after": "7"}),
        _ok(),
    ])
    agent = SensorAgent(_config(), transport=transport, sleep_fn=sleep_fn)
    agent.offer(_event(0))

    assert agent.flush_once().ok
    assert slept == [7.0], "the server's Retry-After must win over local backoff"
    assert agent.stats.rate_limited == 1


def test_retry_after_is_capped_by_max_backoff(no_sleep):
    slept, sleep_fn = no_sleep
    transport = ScriptedTransport([
        _err(429, "rate_limit_exceeded", headers={"retry-after": "99999"}),
        _ok(),
    ])
    agent = SensorAgent(_config(max_backoff_seconds=30.0),
                        transport=transport, sleep_fn=sleep_fn)
    agent.offer(_event(0))
    agent.flush_once()

    assert slept == [30.0]


def test_backoff_grows_and_is_bounded(no_sleep):
    slept, sleep_fn = no_sleep
    transport = ScriptedTransport([_err(503)] * 4 + [_ok()])
    agent = SensorAgent(
        _config(max_attempts=5, base_backoff_seconds=1.0, max_backoff_seconds=4.0),
        transport=transport, sleep_fn=sleep_fn,
    )
    agent.offer(_event(0))
    agent.flush_once()

    assert len(slept) == 4
    assert all(0 < s <= 4.0 for s in slept), f"backoff left its bound: {slept}"
    assert slept[-1] >= slept[0], "backoff did not grow"


def test_exhausted_retries_return_the_batch_to_the_buffer(no_sleep):
    slept, sleep_fn = no_sleep
    transport = ScriptedTransport([_err(503)] * 3)
    agent = SensorAgent(_config(max_attempts=3), transport=transport,
                        sleep_fn=sleep_fn)
    for i in range(3):
        agent.offer(_event(i))

    result = agent.flush_once()

    assert not result.ok
    assert agent.buffered == 3, "events were lost after exhausted retries"
    assert agent.stats.batches_exhausted_retries == 1


def test_a_returned_batch_keeps_its_order(no_sleep):
    slept, sleep_fn = no_sleep
    agent = SensorAgent(_config(max_attempts=1, batch_size=3),
                        transport=ScriptedTransport([_err(503)]),
                        sleep_fn=sleep_fn)
    for i in range(3):
        agent.offer(_event(i))

    agent.flush_once()

    assert [r["event_id"] for r in agent._take_batch()] == [
        "agent-evt-0", "agent-evt-1", "agent-evt-2"
    ]


def test_a_conflict_is_counted_and_not_retried(no_sleep):
    slept, sleep_fn = no_sleep
    transport = ScriptedTransport([_err(409, "event_identity_conflict")])
    agent = SensorAgent(_config(), transport=transport, sleep_fn=sleep_fn)
    agent.offer(_event(0))

    agent.flush_once()

    assert agent.stats.conflicts == 1
    assert len(transport.requests) == 1


def test_a_duplicate_acknowledgement_is_recorded_as_such():
    transport = ScriptedTransport([_ok(stored=0, duplicates=3)])
    agent = SensorAgent(_config(), transport=transport)
    for i in range(3):
        agent.offer(_event(i))

    result = agent.flush_once()

    assert result.ok
    assert result.stored == 0 and result.duplicates == 3
    assert agent.stats.events_duplicate_reported == 3


def test_a_response_with_an_unexpected_shape_is_still_an_acknowledgement():
    """The status decides success; a missing field is not an error."""
    transport = ScriptedTransport([(200, {}, b'{"unexpected": true}')])
    agent = SensorAgent(_config(), transport=transport)
    agent.offer(_event(0))

    result = agent.flush_once()

    assert result.ok
    assert result.stored is None, "an absent count must not be read as 0"


def test_an_unparseable_body_does_not_turn_a_failure_into_a_success():
    transport = ScriptedTransport([(500, {}, b"<html>gateway error</html>"), _ok()])
    agent = SensorAgent(_config(), transport=transport, sleep_fn=lambda s: None)
    agent.offer(_event(0))

    assert agent.flush_once().ok
    assert agent.stats.retries == 1


# ──────────────────────────────────────────────────────────────────
# Idempotency
# ──────────────────────────────────────────────────────────────────


def test_a_retry_presents_the_same_idempotency_key(no_sleep):
    slept, sleep_fn = no_sleep
    transport = ScriptedTransport([_err(503), _ok()])
    agent = SensorAgent(_config(), transport=transport, sleep_fn=sleep_fn)
    agent.offer(_event(0))

    agent.flush_once()

    keys = {r["headers"]["Idempotency-Key"] for r in transport.requests}
    assert len(keys) == 1, "a resend used a new identity namespace"


def test_event_ids_are_unchanged_across_a_retry(no_sleep):
    slept, sleep_fn = no_sleep
    transport = ScriptedTransport([_err(503), _ok()])
    agent = SensorAgent(_config(), transport=transport, sleep_fn=sleep_fn)
    agent.offer(_event(7))

    agent.flush_once()

    bodies = [r["body"]["ndjson_content"] for r in transport.requests]
    assert bodies[0] == bodies[1]
    assert "agent-evt-7" in bodies[0]


def test_the_key_is_scoped_to_the_source():
    a = SensorAgent(_config(source_id="sensor-a"), transport=ScriptedTransport([]))
    b = SensorAgent(_config(source_id="sensor-b"), transport=ScriptedTransport([]))
    batch = [_event(0)]

    assert a._idempotency_key(batch) != b._idempotency_key(batch)


# ──────────────────────────────────────────────────────────────────
# Lifecycle and secrets
# ──────────────────────────────────────────────────────────────────


def test_shutdown_drains_what_it_can():
    transport = ScriptedTransport([_ok(stored=2), _ok(stored=1)])
    agent = SensorAgent(_config(batch_size=2), transport=transport)
    for i in range(3):
        agent.offer(_event(i))

    stats = agent.shutdown(drain=True)

    assert agent.buffered == 0
    assert stats["batches_acknowledged"] == 2


def test_shutdown_reports_what_it_could_not_deliver(no_sleep):
    slept, sleep_fn = no_sleep
    agent = SensorAgent(_config(max_attempts=1), transport=ScriptedTransport([_err(503)]),
                        sleep_fn=sleep_fn)
    for i in range(3):
        agent.offer(_event(i))

    stats = agent.shutdown(drain=True)

    assert stats["buffered_events"] == 3, "undelivered events reported as delivered"
    assert "lost if the process is killed" in stats["buffer_durability"]


def test_a_stop_request_interrupts_the_retry_loop(no_sleep):
    slept, sleep_fn = no_sleep
    transport = ScriptedTransport([_err(503)] * 10)
    agent = SensorAgent(_config(max_attempts=10), transport=transport,
                        sleep_fn=sleep_fn)
    agent.offer(_event(0))
    agent.request_stop()

    agent.flush_once()

    assert len(transport.requests) == 1, "shutdown did not interrupt the retries"
    assert agent.buffered == 1, "the event was dropped on interruption"


def test_health_never_contains_the_token():
    agent = SensorAgent(_config(), transport=ScriptedTransport([_ok()]))
    agent.offer(_event(0))
    agent.flush_once()

    serialized = json.dumps(agent.health())

    assert TOKEN not in serialized
    for leak in ("authorization", "bearer", "token", "secret"):
        assert leak not in serialized.lower()


def test_health_states_the_delivery_semantics_honestly():
    health = SensorAgent(_config(), transport=ScriptedTransport([])).health()

    assert "at-least-once" in health["delivery_semantics"]
    assert "NOT exactly-once" in health["delivery_semantics"]


def test_no_transport_is_used_until_a_flush():
    """Offering events must not touch the network."""
    transport = ScriptedTransport([])
    agent = SensorAgent(_config(), transport=transport)
    for i in range(5):
        agent.offer(_event(i))

    assert transport.requests == []


# ──────────────────────────────────────────────────────────────────
# End to end, against a real in-process PraHari
# ──────────────────────────────────────────────────────────────────


@pytest.fixture
def receiver(tmp_path):
    """A genuine central-mode PraHari on a temporary database."""
    db = Database(db_path=str(tmp_path / "agent_e2e.db"))
    db.initialize()
    db.upsert_source(
        TelemetrySource(source_id=SOURCE, name=SOURCE, source_type="json_stream")
    )
    cred, token = Credential.create(SOURCE, Role.INGEST, "agent")
    cfg = AppConfig(deployment_mode=DeploymentMode.CENTRAL)
    app = FastAPI()
    app.include_router(api_v1_router, prefix="/api/v1")
    app.add_middleware(
        CentralAuthMiddleware, store=CredentialStore([cred]),
        public_paths=cfg.central_public_paths,
    )
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[get_config] = lambda: cfg
    with TestClient(app) as client:
        yield client, db, token
    db.close()


class LoopbackTransport:
    """Routes the agent's request into the in-process app. No socket."""

    def __init__(self, client):
        self._client = client
        self.calls = 0

    def post(self, url, body, headers, timeout):
        self.calls += 1
        response = self._client.post(
            "/api/v1/stream/ingest/ndjson",
            content=body,
            headers=headers,
        )
        return (
            response.status_code,
            {k.lower(): v for k, v in response.headers.items()},
            response.content,
        )


def test_end_to_end_forwarding_stores_events(receiver):
    client, db, token = receiver
    agent = SensorAgent(
        _config(endpoint="https://central.invalid/x", token=token),
        transport=LoopbackTransport(client),
    )
    for i in range(5):
        agent.offer(_event(i))

    result = agent.flush_once()

    assert result.ok, result.detail
    assert result.stored == 5
    assert db.count_events(source_id=SOURCE) == 5


def test_end_to_end_a_resend_stores_no_second_copy(receiver):
    """The whole reason the agent sets an idempotency key."""
    client, db, token = receiver
    transport = LoopbackTransport(client)
    agent = SensorAgent(
        _config(endpoint="https://central.invalid/x", token=token),
        transport=transport,
    )
    for i in range(4):
        agent.offer(_event(i))
    agent.flush_once()

    # The sensor never saw the response and resends the same events.
    for i in range(4):
        agent.offer(_event(i))
    second = agent.flush_once()

    assert second.ok
    assert second.stored == 0 and second.duplicates == 4
    assert db.count_events(source_id=SOURCE) == 4
    assert transport.calls == 2


def test_end_to_end_a_bad_credential_is_refused_and_not_retried(receiver, no_sleep):
    client, db, _ = receiver
    slept, sleep_fn = no_sleep
    transport = LoopbackTransport(client)
    agent = SensorAgent(
        _config(endpoint="https://central.invalid/x", token="wrong-token"),
        transport=transport, sleep_fn=sleep_fn,
    )
    agent.offer(_event(0))

    result = agent.flush_once()

    assert result.status == 401
    assert not result.retryable
    assert transport.calls == 1
    assert db.count_events() == 0


def test_end_to_end_the_agent_cannot_forge_another_sources_identity(receiver):
    """ADR-051 holds for the agent like any other client."""
    client, db, token = receiver
    agent = SensorAgent(
        _config(endpoint="https://central.invalid/x", token=token,
                source_id="some-other-sensor"),
        transport=LoopbackTransport(client),
    )
    agent.offer(_event(0))

    result = agent.flush_once()

    assert result.status == 403
    assert db.count_events(source_id="some-other-sensor") == 0


def test_end_to_end_events_carry_a_server_measured_receipt(receiver):
    client, db, token = receiver
    agent = SensorAgent(
        _config(endpoint="https://central.invalid/x", token=token),
        transport=LoopbackTransport(client),
    )
    agent.offer(_event(0))
    agent.flush_once()

    stored = db.list_events(source_id=SOURCE, limit=5)[0]
    assert stored.received_at is not None
    assert stored.source_id == SOURCE
