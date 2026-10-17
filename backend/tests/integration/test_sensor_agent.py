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

import http.client
import json
import urllib.error
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


class SizeLimitedServer:
    """
    Models a central server with a request-body limit, either refusing
    cleanly with 413 or, as a real server often does mid-upload, dropping
    the connection. Records every body size it was sent.
    """

    def __init__(self, limit: int, shape: str = "413"):
        self.limit = limit
        self.shape = shape
        self.sizes: list[int] = []
        self.bodies: list[bytes] = []
        self.stored: list[str] = []

    def post(self, url, body, headers, timeout):
        self.sizes.append(len(body))
        self.bodies.append(body)
        if len(body) > self.limit:
            if self.shape == "reset":
                raise ConnectionResetError("connection reset by peer")
            return 413, {}, json.dumps({"detail": {
                "error": "payload_too_large",
                "message": "Split the submission into smaller batches.",
            }}).encode()
        records = json.loads(body.decode())["ndjson_content"].strip().splitlines()
        self.stored.extend(json.loads(r)["event_id"] for r in records)
        return 200, {}, json.dumps({"stored_records": len(records)}).encode()


def _sized_event(i: int, pad: int) -> dict:
    return {**_event(i), "note": "x" * pad}


def test_a_bound_under_the_server_limit_never_sends_an_oversized_body(no_sleep):
    _, sleep_fn = no_sleep
    server = SizeLimitedServer(limit=20_000)
    agent = SensorAgent(
        _config(batch_size=10, max_request_bytes=15_000), transport=server, sleep_fn=sleep_fn
    )
    agent.offer_many(_sized_event(i, 3_000) for i in range(10))

    agent.flush_all()

    assert max(server.sizes) <= 15_000
    assert server.stored == [f"agent-evt-{i}" for i in range(10)], "all delivered, in order"
    assert agent.stats.batches_split >= 1
    assert agent.stats.events_oversized == 0


def test_a_clean_413_splits_the_batch_instead_of_dropping_valid_events(no_sleep):
    """
    Bound misconfigured above the server's limit, server answers 413: the
    events are kept and delivered in smaller batches - not dropped as a
    permanent failure, and the identical body is never resent.
    """
    slept, sleep_fn = no_sleep
    server = SizeLimitedServer(limit=10_000, shape="413")
    agent = SensorAgent(
        _config(batch_size=10, max_request_bytes=1_000_000), transport=server, sleep_fn=sleep_fn
    )
    agent.offer_many(_sized_event(i, 3_000) for i in range(10))

    first = agent.flush_once()
    assert first.status == 413 and not first.retryable and not first.ok
    assert agent.buffered == 10, "a size refusal must keep the events"

    agent.flush_all()

    assert server.stored == [f"agent-evt-{i}" for i in range(10)], "all delivered, in order"
    assert agent.stats.batches_failed_permanent == 0
    assert agent.stats.events_oversized == 0
    assert agent.stats.retries == 0 and slept == []
    refused = [b for b, n in zip(server.bodies, server.sizes) if n > server.limit]
    assert len(refused) == len(set(refused)), "a refused body was resent unchanged"
    assert len(server.sizes) <= 10, "splitting must converge, not loop"


def test_a_413_for_one_event_alone_drops_it_and_the_rest_still_flow(no_sleep):
    _, sleep_fn = no_sleep
    server = SizeLimitedServer(limit=10_000, shape="413")
    agent = SensorAgent(
        _config(batch_size=10, max_request_bytes=1_000_000), transport=server, sleep_fn=sleep_fn
    )
    agent.offer(_sized_event(0, 20_000))  # the server will never take this one
    agent.offer_many(_event(i) for i in range(1, 6))

    agent.flush_all()

    assert agent.buffered == 0
    assert agent.stats.events_oversized == 1
    assert agent.stats.batches_failed_permanent == 1
    assert server.stored == [f"agent-evt-{i}" for i in range(1, 6)]
    assert len(server.sizes) <= 10, "must converge, not loop"


# ──────────────────────────────────────────────────────────────────
# Ambiguous failures and the retry bound (ADR-073)
# ──────────────────────────────────────────────────────────────────


class ChannelModel:
    """
    A server reachable or not, with an optional body limit it enforces by
    dropping the connection instead of answering 413. `down` models an
    outage: "refuse" (never connects) or "drop" (every request dropped).
    """

    def __init__(self, limit: int | None = None, down: str | None = None):
        self.limit = limit
        self.down = down
        self.sent: list[list[str]] = []
        self.stored: list[str] = []

    def post(self, url, body, headers, timeout):
        ids = [
            json.loads(r)["event_id"]
            for r in json.loads(body.decode())["ndjson_content"].strip().splitlines()
        ]
        self.sent.append(ids)
        if self.down == "refuse":
            raise ConnectionRefusedError("connection refused")
        if self.down == "drop" or (self.limit is not None and len(body) > self.limit):
            raise ConnectionResetError("connection reset by peer")
        new = [i for i in ids if i not in self.stored]
        self.stored.extend(new)
        return 200, {}, json.dumps(
            {"stored_records": len(new), "duplicate_records": len(ids) - len(new)}
        ).encode()


def _drain(agent: SensorAgent, rounds: int = 50) -> int:
    """Flush the way a caller loop would, until empty or out of rounds."""
    for n in range(1, rounds + 1):
        agent.flush_all()
        if agent.buffered == 0:
            return n
    return rounds


def test_a_drop_mid_request_is_classified_apart_from_a_refused_connection(no_sleep):
    _, sleep_fn = no_sleep
    for exc, kind in [
        (ConnectionResetError("reset"), "connection_dropped"),
        (BrokenPipeError("pipe"), "connection_dropped"),
        (http.client.IncompleteRead(b"", 10), "connection_dropped"),
        (http.client.RemoteDisconnected("gone"), "connection_dropped"),
        (urllib.error.URLError(ConnectionResetError("reset")), "connection_dropped"),
        (ConnectionRefusedError("refused"), "connection_error"),
        (urllib.error.URLError(ConnectionRefusedError("refused")), "connection_error"),
        (OSError("network unreachable"), "connection_error"),
    ]:
        agent = SensorAgent(
            _config(max_attempts=1), transport=ScriptedTransport([exc]), sleep_fn=sleep_fn
        )
        agent.offer(_event(0))
        result = agent.flush_once()
        assert result.retryable and result.error_kind == kind, (exc, result)
        assert agent.buffered == 1, f"{exc!r} lost the event"


def test_a_truncated_413_body_is_still_a_confirmed_413():
    """The status line arrived; a body cut off after it must not hide it."""
    from app.agents.sensor_agent import UrllibTransport

    class _Truncated:
        def read(self, *a):
            raise http.client.IncompleteRead(b"{", 40)

        def close(self):
            pass

    class _Opener:
        def open(self, request, timeout):
            raise urllib.error.HTTPError(
                request.full_url, 413, "Content Too Large", {}, _Truncated()
            )

    transport = UrllibTransport()
    transport._opener = _Opener()
    status, _, body = transport.post(ENDPOINT, b"{}", {}, 5)
    assert (status, body) == (413, b"")


def test_an_unexpected_transport_error_does_not_lose_the_batch():
    agent = SensorAgent(_config(), transport=ScriptedTransport([ValueError("bug")]))
    agent.offer_many(_event(i) for i in range(3))

    with pytest.raises(ValueError):
        agent.flush_once()

    assert agent.buffered == 3
    assert [r["event_id"] for r in agent._buffer] == [f"agent-evt-{i}" for i in range(3)]


def test_repeated_drops_on_an_oversized_batch_split_until_everything_delivers(no_sleep):
    """
    Bound above the server's limit, server drops instead of answering 413
    (the ADR-066 wedge). The batch is split - unconfirmed - until it fits;
    every event is delivered in order and nothing is dropped.
    """
    _, sleep_fn = no_sleep
    server = ChannelModel(limit=10_000)
    agent = SensorAgent(
        _config(batch_size=10, max_request_bytes=1_000_000, max_attempts=2),
        transport=server, sleep_fn=sleep_fn,
    )
    agent.offer_many(_sized_event(i, 3_000) for i in range(10))

    first = agent.flush_once()
    assert first.retryable and first.error_kind == "connection_dropped"
    assert agent.buffered == 10, "a drop must keep the events"

    rounds = _drain(agent)

    assert server.stored == [f"agent-evt-{i}" for i in range(10)]
    assert agent.stats.batches_split_unconfirmed >= 1
    assert agent.stats.batches_failed_permanent == 0
    assert agent.stats.events_oversized == agent.stats.events_dead_lettered == 0
    assert rounds < 50
    # The same set of events is never sent more than one round's worth.
    sends = [tuple(ids) for ids in server.sent]
    assert max(sends.count(b) for b in set(sends)) <= agent.config.max_attempts


def test_a_refusing_outage_is_retried_never_split_never_set_aside(no_sleep):
    _, sleep_fn = no_sleep
    server = ChannelModel(down="refuse")
    agent = SensorAgent(_config(batch_size=5, max_attempts=2), transport=server, sleep_fn=sleep_fn)
    agent.offer_many(_event(i) for i in range(5))

    for _ in range(10):
        result = agent.flush_once()
        assert result.retryable and result.error_kind == "connection_error"

    assert agent.buffered == 5
    assert agent.stats.batches_split_unconfirmed == 0
    assert agent.stats.channel_probes == 0
    assert agent.stats.events_dead_lettered == 0
    assert all(ids == server.sent[0] for ids in server.sent), "the outage must not reshape batches"

    server.down = None
    assert agent.flush_once().ok
    assert server.stored == [f"agent-evt-{i}" for i in range(5)]


def test_an_outage_that_drops_everything_loses_nothing_and_the_cap_recovers(no_sleep):
    """
    Drops from an outage look like drops from an oversized body. Splitting
    down to one event is harmless, the probe then fails, so nothing is set
    aside; once the channel returns, the cap grows back.
    """
    _, sleep_fn = no_sleep
    server = ChannelModel(down="drop")
    agent = SensorAgent(_config(batch_size=8, max_attempts=2), transport=server, sleep_fn=sleep_fn)
    agent.offer_many(_event(i) for i in range(40))

    for _ in range(10):
        agent.flush_all()

    assert agent.buffered == 40
    assert [r["event_id"] for r in agent._buffer] == [f"agent-evt-{i}" for i in range(40)]
    assert agent.stats.events_dead_lettered == 0
    assert agent.stats.channel_probes >= 1, "the single-event stage was reached and probed"
    assert agent.health()["batch_size_cap"] == 1
    assert agent.health()["learned_max_request_bytes"] is None, "drops never confirm a limit"

    server.down = None
    _drain(agent)

    assert server.stored == [f"agent-evt-{i}" for i in range(40)]
    assert agent.health()["batch_size_cap"] == 8, "an unconfirmed cap recovers"


def test_mixed_ambiguous_failures_stay_retryable_and_do_not_split(no_sleep):
    """Only a round made ENTIRELY of mid-request drops is evidence."""
    _, sleep_fn = no_sleep
    transport = ScriptedTransport(
        [ConnectionResetError("reset"), ConnectionRefusedError("refused")] * 3
        + [TimeoutError("slow"), ConnectionResetError("reset")] * 3
    )
    agent = SensorAgent(_config(batch_size=4, max_attempts=2), transport=transport, sleep_fn=sleep_fn)
    agent.offer_many(_event(i) for i in range(4))

    for _ in range(6):
        assert agent.flush_once().retryable

    assert agent.buffered == 4
    assert agent.stats.batches_split_unconfirmed == 0
    assert agent.health()["batch_size_cap"] == 4
    assert agent.stats.connection_drops == 6
    assert agent.stats.batches_exhausted_retries == 6


def test_one_event_that_always_drops_is_set_aside_and_the_rest_flow(no_sleep):
    """
    The single-event stage: the event behind it is delivered, the suspect
    drops again back to back, so it is dead-lettered - kept, counted and
    requeueable - and the queue moves.
    """
    _, sleep_fn = no_sleep
    server = ChannelModel(limit=10_000)
    agent = SensorAgent(
        _config(batch_size=10, max_request_bytes=1_000_000, max_attempts=2),
        transport=server, sleep_fn=sleep_fn,
    )
    agent.offer_many(_event(i) for i in range(3))
    agent.offer(_sized_event(3, 20_000))  # the server never takes this one
    agent.offer_many(_event(i) for i in range(4, 8))

    _drain(agent)

    assert server.stored == [f"agent-evt-{i}" for i in range(8) if i != 3]
    assert agent.buffered == 0
    assert agent.stats.events_dead_lettered == 1
    assert [r["event_id"] for r in agent.dead_letters()] == ["agent-evt-3"]
    health = agent.health()
    assert health["dead_letter_events"] == 1
    assert health["events_oversized"] == 0, "unconfirmed: not counted as a known size refusal"
    assert health["batches_failed_permanent"] == 0

    # An operator who fixes the server can requeue it.
    server.limit = None
    assert agent.requeue_dead_letters() == 1
    assert agent.flush_once().ok
    assert "agent-evt-3" in server.stored and agent.dead_letters() == []


def test_the_single_event_stage_with_nothing_behind_it_keeps_the_event(no_sleep):
    """No event to probe with means no evidence: keep it, retryable."""
    _, sleep_fn = no_sleep
    server = ChannelModel(limit=10_000)
    agent = SensorAgent(
        _config(max_request_bytes=1_000_000, max_attempts=2), transport=server, sleep_fn=sleep_fn
    )
    agent.offer(_sized_event(0, 20_000))

    for _ in range(5):
        assert agent.flush_once().retryable

    assert agent.buffered == 1
    assert agent.stats.events_dead_lettered == 0


def test_a_probe_failing_restores_the_original_order(no_sleep):
    _, sleep_fn = no_sleep
    server = ChannelModel(down="drop")
    agent = SensorAgent(_config(batch_size=1, max_attempts=2), transport=server, sleep_fn=sleep_fn)
    agent.offer_many(_event(i) for i in range(3))

    agent.flush_once()

    assert server.sent[-1] == ["agent-evt-1"], "the event behind was used as the probe"
    assert [r["event_id"] for r in agent._buffer] == [f"agent-evt-{i}" for i in range(3)]
    assert agent.stats.channel_probes == 1


def test_a_suspect_that_succeeds_on_the_confirming_attempt_is_delivered(no_sleep):
    """A blip that ends exactly at the probe must not dead-letter anything."""
    _, sleep_fn = no_sleep
    transport = ScriptedTransport(
        [ConnectionResetError("reset"), ConnectionResetError("reset"), _ok(), _ok()]
    )
    agent = SensorAgent(_config(batch_size=1, max_attempts=2), transport=transport, sleep_fn=sleep_fn)
    agent.offer_many(_event(i) for i in range(2))

    result = agent.flush_once()

    assert result.ok
    assert agent.buffered == 0
    assert agent.stats.events_dead_lettered == 0
    assert agent.stats.batches_acknowledged == 2


def test_the_dead_letter_store_is_bounded_and_counts_overflow(no_sleep):
    _, sleep_fn = no_sleep
    server = ChannelModel(limit=10_000)
    agent = SensorAgent(
        _config(batch_size=1, buffer_capacity=1, max_attempts=1, max_request_bytes=1_000_000),
        transport=server, sleep_fn=sleep_fn,
    )
    agent._dead_letter.append(_event(0))  # the store is already full
    agent.offer(_sized_event(9, 20_000))
    agent._buffer.append(_event(10))  # behind it, bypassing capacity for the test

    agent.flush_once()

    assert agent.stats.events_dead_lettered == 1
    assert agent.stats.events_dead_letter_overflow == 1
    assert [r["event_id"] for r in agent.dead_letters()] == ["agent-evt-9"]


# ──────────────────────────────────────────────────────────────────
# Event accounting at the buffer boundary (Linux closure audit)
# ──────────────────────────────────────────────────────────────────


def test_events_lost_returning_to_a_full_buffer_are_all_counted(no_sleep):
    """
    The collector keeps offering while a batch is in flight. If the buffer
    filled meanwhile, every event that cannot go back is a counted drop -
    not one count for the whole batch.
    """
    _, sleep_fn = no_sleep

    class _CollectorRacesTheFlush:
        def post(self, url, body, headers, timeout):
            agent.offer_many(_event(100 + i) for i in range(5))  # fills the buffer
            raise ConnectionRefusedError("down")

    agent = SensorAgent(
        _config(batch_size=5, buffer_capacity=10, max_attempts=1),
        transport=_CollectorRacesTheFlush(), sleep_fn=sleep_fn,
    )
    agent.offer_many(_event(i) for i in range(10))

    agent.flush_once()

    stats = agent.stats
    assert agent.buffered == 10
    assert stats.events_offered == 15
    assert agent.buffered + stats.events_dropped_overflow == stats.events_offered, (
        "every offered event is buffered or counted as dropped"
    )


def test_requeueing_dead_letters_into_a_full_buffer_loses_none(no_sleep):
    _, sleep_fn = no_sleep
    agent = SensorAgent(
        _config(batch_size=2, buffer_capacity=4), transport=ScriptedTransport([]),
        sleep_fn=sleep_fn,
    )
    for i in range(3):
        agent._dead_letter.append(_event(i))
    agent.offer_many(_event(10 + i) for i in range(4))  # buffer full

    assert agent.requeue_dead_letters() == 0
    assert len(agent.dead_letters()) == 3, "nothing requeued, nothing lost"
    assert agent.stats.events_dropped_overflow == 0

    agent._take_batch(limit=2)  # make room for two
    assert agent.requeue_dead_letters() == 2
    assert [r["event_id"] for r in agent._buffer][:2] == ["agent-evt-0", "agent-evt-1"]
    assert [r["event_id"] for r in agent.dead_letters()] == ["agent-evt-2"]
    assert agent.stats.events_dropped_overflow == 0


def test_a_probe_refused_outright_does_not_livelock_the_queue(no_sleep):
    """
    The suspect drops; the event behind it is refused with a definite 409.
    A definite answer proves the channel carries requests, and the 409
    applies to that event however it was sent - so it is dropped under
    the normal rule and the suspect is judged, instead of both being put
    back to repeat the same round forever.
    """
    _, sleep_fn = no_sleep

    class _Server:
        def __init__(self):
            self.sent = []

        def post(self, url, body, headers, timeout):
            ids = [json.loads(r)["event_id"] for r in
                   json.loads(body.decode())["ndjson_content"].strip().splitlines()]
            self.sent.append(ids)
            if ids == ["agent-evt-0"]:
                raise ConnectionResetError("reset")
            if ids == ["agent-evt-1"]:
                return _err(409, "event_identity_conflict")
            return _ok(stored=len(ids))

    server = _Server()
    agent = SensorAgent(_config(batch_size=1, max_attempts=2), transport=server, sleep_fn=sleep_fn)
    agent.offer_many(_event(i) for i in range(4))

    for _ in range(6):
        agent.flush_all()
        if agent.buffered == 0:
            break

    assert agent.buffered == 0, f"queue wedged: {server.sent}"
    assert agent.stats.conflicts == 1
    assert agent.stats.batches_failed_permanent == 1
    assert [r["event_id"] for r in agent.dead_letters()] == ["agent-evt-0"]
    assert ["agent-evt-2"] in server.sent and ["agent-evt-3"] in server.sent


def test_one_413_does_not_cap_later_small_batches_at_one_event(no_sleep):
    """
    A 413 proves a body of that SIZE is too large - not that a batch of
    that many events is. Two large events refused must not reduce a
    stream of small events to one per request for the agent's lifetime.
    """
    _, sleep_fn = no_sleep
    server = SizeLimitedServer(limit=10_000, shape="413")
    agent = SensorAgent(
        _config(batch_size=50, buffer_capacity=100, max_request_bytes=1_000_000),
        transport=server, sleep_fn=sleep_fn,
    )
    agent.offer_many(_sized_event(i, 6_000) for i in range(2))
    agent.flush_all()
    assert server.stored == ["agent-evt-0", "agent-evt-1"]

    before = len(server.sizes)
    agent.offer_many(_event(100 + i) for i in range(40))
    agent.flush_all()

    assert agent.buffered == 0
    assert len(server.stored) == 42
    assert len(server.sizes) - before <= 2, (
        f"{len(server.sizes) - before} requests for 40 small events"
    )
    assert max(server.sizes[before:]) <= server.limit


def test_a_learned_ceiling_never_drops_a_single_event_locally(no_sleep):
    """
    The ceiling learned from a 413 splits multi-event batches only. One
    event above it - but under max_request_bytes - is still sent: whether
    it is too large is the server's call.
    """
    _, sleep_fn = no_sleep
    server = SizeLimitedServer(limit=10_000, shape="413")
    agent = SensorAgent(
        _config(batch_size=10, max_request_bytes=1_000_000), transport=server, sleep_fn=sleep_fn
    )
    agent.offer_many(_sized_event(i, 6_000) for i in range(2))
    agent.flush_all()
    ceiling = agent.health()["learned_max_request_bytes"]
    assert ceiling is not None and ceiling < 13_000

    server.limit = 100_000  # the server's limit was raised
    agent.offer(_sized_event(9, 20_000))
    agent.flush_all()

    assert "agent-evt-9" in server.stored
    assert agent.stats.events_oversized == 0


def test_an_event_that_cannot_be_serialised_is_refused_at_the_door(no_sleep):
    """
    A collector handing over a datetime (or any non-JSON value) used to be
    accepted, then made encoding raise inside flush_once with the whole
    batch already out of the buffer - the valid events in it were lost,
    uncounted. It is now refused and counted on offer.
    """
    from datetime import datetime, timezone

    transport = ScriptedTransport([_ok(stored=2)])
    agent = SensorAgent(_config(), transport=transport)
    agent.offer(_event(0))
    assert agent.offer({**_event(1), "timestamp": datetime.now(timezone.utc)}) is False
    agent.offer(_event(2))

    assert agent.stats.events_invalid == 1
    assert agent.buffered == 2
    assert agent.flush_once().ok
    assert agent.buffered == 0


def test_an_encoding_failure_in_flight_keeps_the_batch():
    """Defence in depth: a record mutated after offer() cannot take the batch with it."""
    from datetime import datetime, timezone

    agent = SensorAgent(_config(), transport=ScriptedTransport([]))
    agent.offer_many(_event(i) for i in range(3))
    agent._buffer[1]["timestamp"] = datetime.now(timezone.utc)  # mutated after offer

    with pytest.raises(TypeError):
        agent.flush_once()

    assert [r["event_id"] for r in agent._buffer] == [f"agent-evt-{i}" for i in range(3)]


def test_an_encoding_failure_in_the_probe_keeps_both_events(no_sleep):
    from datetime import datetime, timezone

    _, sleep_fn = no_sleep
    transport = ScriptedTransport([ConnectionResetError("reset")] * 2)
    agent = SensorAgent(_config(batch_size=1, max_attempts=2), transport=transport, sleep_fn=sleep_fn)
    agent.offer_many(_event(i) for i in range(2))
    agent._buffer[1]["timestamp"] = datetime.now(timezone.utc)  # the probe, mutated after offer

    with pytest.raises(TypeError):
        agent.flush_once()

    assert [r["event_id"] for r in agent._buffer] == ["agent-evt-0", "agent-evt-1"]


def test_records_the_server_rejects_inside_a_2xx_are_counted(receiver):
    """
    The server validates each record and reports rejections in an
    otherwise successful response. Those events are gone; the agent must
    count them rather than call the batch fully delivered.
    """
    client, db, token = receiver
    agent = SensorAgent(
        _config(endpoint="https://central.invalid/x", token=token),
        transport=LoopbackTransport(client),
    )
    agent.offer_many([
        _event(10),
        {**_event(11), "src_ip": "not-an-ip"},
        {**_event(12), "timestamp": "yesterday-ish"},
    ])

    result = agent.flush_once()

    assert result.ok and result.stored == 1 and result.rejected == 2
    health = agent.health()
    assert health["events_stored_reported"] == 1
    assert health["events_rejected_reported"] == 2
    assert db.count_events(source_id=SOURCE) == 1


@pytest.mark.parametrize("status", [404, 405])
def test_a_wrong_endpoint_halts_and_keeps_the_events(status, no_sleep):
    """
    The ingest route never answers 404/405 about the data, only about the
    URL or method. A typo in the endpoint used to drop every batch as a
    permanent refusal; it is a channel fault, like a redirect.
    """
    slept, sleep_fn = no_sleep
    transport = ScriptedTransport([_err(status, "not_found")] * 3)
    agent = SensorAgent(_config(), transport=transport, sleep_fn=sleep_fn)
    agent.offer_many(_event(i) for i in range(5))

    result = agent.flush_once()
    agent.flush_all()

    assert result.halt and not result.retryable
    assert result.error_kind == "endpoint_refused"
    assert agent.buffered == 5, "the events are not at fault"
    assert agent.stats.batches_failed_permanent == 0
    assert agent.stats.channel_refusals == 2
    assert len(transport.requests) == 2, "never retried within a flush"
    assert slept == []


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


def test_end_to_end_a_lost_response_then_a_split_stores_each_event_once(receiver, no_sleep):
    """
    The duplicate hazard of splitting after an ambiguous failure, against
    the real ingest path: the server STORES every multi-event batch and the
    response is lost (connection dropped). The agent splits and resends in
    different batch boundaries - a different Idempotency-Key - and the
    server still stores each event once, because identity is the sender's
    event_id (ADR-050 tier 1), not the batch. At-least-once on the wire,
    at-most-once in storage; not exactly-once.
    """
    client, db, token = receiver
    _, sleep_fn = no_sleep
    inner = LoopbackTransport(client)

    class _ResponseLostForBigBatches:
        def post(self, url, body, headers, timeout):
            status, h, b = inner.post(url, body, headers, timeout)
            n = len(json.loads(body.decode())["ndjson_content"].strip().splitlines())
            if n > 2:
                raise ConnectionResetError("response lost after the server stored it")
            return status, h, b

    agent = SensorAgent(
        _config(endpoint="https://central.invalid/x", token=token, batch_size=8, max_attempts=2),
        transport=_ResponseLostForBigBatches(), sleep_fn=sleep_fn,
    )
    agent.offer_many(_event(i) for i in range(8))

    for _ in range(10):
        agent.flush_all()
        if agent.buffered == 0:
            break

    assert agent.buffered == 0
    assert db.count_events(source_id=SOURCE) == 8, "each event stored exactly once"
    assert agent.stats.conflicts == 0
    assert agent.stats.events_stored_reported == 0, "the first, lost response stored them all"
    assert agent.stats.events_duplicate_reported == 8
    assert agent.stats.batches_split_unconfirmed >= 1


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
