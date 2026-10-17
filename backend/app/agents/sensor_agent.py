"""
PraHari — Sensor Forwarding Agent (blueprint §4.2, §5, §13 `agents/sensor/`)

An optional process that runs beside a sensor, collects from an existing
local adapter, and forwards canonical events to a central PraHari over
the **existing** authenticated ingestion contract. It introduces no second
event schema, no second identity mechanism and no new dependency: the
transport is `urllib` from the standard library, because an agent is the
one component most likely to run somewhere with nothing installed.

What it reuses, deliberately
----------------------------
* `POST /api/v1/stream/ingest/ndjson` — the same endpoint a sensor would
  call by hand.
* `Authorization: Bearer <token>` — the credential model of ADR-051/055.
* Sender-supplied `event_id` per record plus a batch `Idempotency-Key`,
  so a retry is deduplicated server side exactly as ADR-050 specifies.
* The server's own response vocabulary: 409 conflict, 413 too large, 429
  rate limited, 503 overloaded.

Delivery semantics, stated precisely
------------------------------------
**At-least-once delivery, with server-side deduplication.** The agent
retries until the server acknowledges, and the server stores at most one
copy because event identity is deterministic. That is NOT exactly-once
network delivery: a response lost in transit causes a resend, and the
duplicate is absorbed at the database, not prevented on the wire.

The buffer is **bounded and in memory**. Unacknowledged events are lost
if the process is killed. A persistent spool was considered and not
built: it would need its own storage, atomic rename semantics and
recovery validation, and the honest default for a research agent is to
say what is lost rather than imply durability it does not have.
"""

from __future__ import annotations

import http.client
import json
import logging
import os
import random
import ssl
import threading
import time
import urllib.error
import urllib.request
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Iterable, Optional, Protocol

logger = logging.getLogger(__name__)

DEFAULT_BATCH_SIZE = 100
DEFAULT_BUFFER_CAPACITY = 10_000
DEFAULT_TIMEOUT_SECONDS = 15.0
DEFAULT_MAX_ATTEMPTS = 5
DEFAULT_BASE_BACKOFF = 1.0
DEFAULT_MAX_BACKOFF = 60.0
# Well under the server's default (max_request_size_mb = 50). Set it to
# the central server's configured limit, or lower.
DEFAULT_MAX_REQUEST_BYTES = 4 * 1024 * 1024

# Server responses that mean "try again later". Anything else is the
# server telling us the request itself is wrong, and resending it
# unchanged would be a loop.
RETRYABLE_STATUSES = frozenset({408, 425, 429, 500, 502, 503, 504})

# The ingest route never answers these about the DATA - only about the URL
# or method - so they mean the endpoint is misconfigured: a channel fault
# that halts and keeps the events, like a redirect (ADR-077).
ENDPOINT_REFUSED_STATUSES = frozenset({404, 405})

# A connection that was established and then lost mid-request (ADR-073).
# Ambiguous by nature: an outage, a server refusing an oversized body
# before reading it, or a response lost after the server stored the batch.
DROPPED = "connection_dropped"
_DROP_ERRORS = (
    ConnectionResetError,     # includes http.client.RemoteDisconnected
    BrokenPipeError,
    ConnectionAbortedError,
    ssl.SSLEOFError,
    ssl.SSLZeroReturnError,
)

# Successful deliveries at a batch cap lowered by UNCONFIRMED evidence
# before it is doubled back toward batch_size (ADR-073).
CAP_RECOVERY_SUCCESSES = 4


class OverflowPolicy:
    """What to do when the buffer is full."""

    DROP_OLDEST = "drop_oldest"   # keep the freshest telemetry
    DROP_NEWEST = "drop_newest"   # keep the earliest, refuse new
    BLOCK = "block"               # refuse the offer, let the caller decide


class ConfigError(ValueError):
    """The agent cannot start with this configuration."""


@dataclass
class AgentConfig:
    """
    Validated agent configuration. Safe defaults, no secret defaults.

    The token is never defaulted and never logged; `__repr__` is
    overridden so an accidental print cannot leak it.
    """

    endpoint: str
    source_id: str
    token: str
    batch_size: int = DEFAULT_BATCH_SIZE
    buffer_capacity: int = DEFAULT_BUFFER_CAPACITY
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS
    max_attempts: int = DEFAULT_MAX_ATTEMPTS
    base_backoff_seconds: float = DEFAULT_BASE_BACKOFF
    max_backoff_seconds: float = DEFAULT_MAX_BACKOFF
    overflow_policy: str = OverflowPolicy.DROP_OLDEST
    # Kept for configuration compatibility, but it is NOT a switch: False
    # is refused below. Before ADR-066 this field existed and nothing read
    # it, so setting it changed nothing while appearing to disable
    # verification.
    verify_tls: bool = True
    # A PEM bundle of the CA(s) that issued the central server's
    # certificate, for an internal CA. None uses the system trust store.
    # This is how a private deployment is trusted - by naming its issuer,
    # never by switching verification off.
    ca_file: Optional[str] = None
    # Largest request body the agent will send (ADR-066). A server refusing
    # an oversized body closes the connection before reading it, so the
    # client may never see the 413 - only a dropped connection, which is
    # retryable. Without this bound one oversized batch was resent forever
    # and wedged everything behind it. Whether the 413 arrives intact is a
    # matter of timing and platform (it usually does on Linux loopback);
    # when it does, the agent splits rather than drops (see flush_once).
    max_request_bytes: int = DEFAULT_MAX_REQUEST_BYTES

    def __post_init__(self) -> None:
        if not self.endpoint or not self.endpoint.startswith(("http://", "https://")):
            raise ConfigError(
                "endpoint must be an absolute http(s) URL, e.g. "
                "https://prahari.example/api/v1/stream/ingest/ndjson"
            )
        if self.endpoint.startswith("http://") and not _is_loopback(self.endpoint):
            # Bearer credentials over plaintext are compromised on first
            # use. Refused rather than warned about.
            raise ConfigError(
                "Refusing to send a bearer credential over plaintext HTTP to a "
                "non-loopback host. Use https://, or a loopback endpoint for "
                "local testing."
            )
        if not self.verify_tls:
            raise ConfigError(
                "Certificate verification cannot be disabled: the agent sends a "
                "bearer credential, and an unverified TLS peer can capture it. "
                "For an internal CA, set ca_file to its PEM bundle instead."
            )
        if self.ca_file is not None and not os.path.isfile(self.ca_file):
            raise ConfigError(f"ca_file does not exist or is not a file: {self.ca_file}")
        if not self.source_id.strip():
            raise ConfigError("source_id is required")
        if not self.token.strip():
            raise ConfigError("token is required; the agent will not run unauthenticated")
        if self.batch_size < 1:
            raise ConfigError("batch_size must be at least 1")
        if self.max_request_bytes < 1024:
            raise ConfigError("max_request_bytes must be at least 1024")
        if self.buffer_capacity < self.batch_size:
            raise ConfigError(
                "buffer_capacity must be at least batch_size, otherwise a full "
                "batch can never be assembled"
            )
        if self.timeout_seconds <= 0:
            raise ConfigError("timeout_seconds must be positive; an unbounded wait hangs the agent")
        if self.max_attempts < 1:
            raise ConfigError("max_attempts must be at least 1")
        if self.base_backoff_seconds <= 0 or self.max_backoff_seconds <= 0:
            raise ConfigError("backoff values must be positive")
        if self.overflow_policy not in vars(OverflowPolicy).values():
            raise ConfigError(f"unknown overflow_policy {self.overflow_policy!r}")

    def __repr__(self) -> str:  # pragma: no cover - trivial
        return (
            f"AgentConfig(endpoint={self.endpoint!r}, source_id={self.source_id!r}, "
            f"token=<redacted {len(self.token)} chars>, batch_size={self.batch_size}, "
            f"buffer_capacity={self.buffer_capacity})"
        )

    __str__ = __repr__


def _is_loopback(url: str) -> bool:
    from urllib.parse import urlparse

    host = (urlparse(url).hostname or "").lower()
    return host in {"localhost", "127.0.0.1", "::1"} or host.endswith(".localhost")


@dataclass
class ForwardResult:
    """One delivery attempt's outcome, as the agent understood it."""

    status: int
    ok: bool
    retryable: bool
    stored: Optional[int] = None
    duplicates: Optional[int] = None
    # Records the server parsed and refused inside a 2xx (ADR-077).
    rejected: Optional[int] = None
    retry_after: Optional[float] = None
    error_kind: Optional[str] = None
    detail: str = ""
    # The CHANNEL is unusable, not the request: a certificate that fails
    # verification, or a redirect. Resending cannot help, but the events
    # are valid, so the batch is kept rather than dropped (ADR-066).
    halt: bool = False


class Transport(Protocol):
    """Injected so tests never touch a socket."""

    def post(
        self, url: str, body: bytes, headers: dict[str, str], timeout: float
    ) -> tuple[int, dict[str, str], bytes]:
        ...


class _RefuseRedirects(urllib.request.HTTPRedirectHandler):
    """
    Never follow a redirect.

    CPython's redirect handling copies every request header except the
    content headers onto the new request - including `Authorization`. An
    HTTPS endpoint answering `302 Location: http://...` would therefore
    make the agent resend its bearer token in plaintext, to a host chosen
    by whoever controls the response. An ingest endpoint has no reason to
    redirect, so the 3xx is surfaced as an error instead.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class UrllibTransport:
    """Standard-library HTTP. No new dependency on a sensor host."""

    def __init__(self, ca_file: Optional[str] = None):
        # Hostname checking and CERT_REQUIRED are the defaults of
        # create_default_context; they are asserted here, not assumed.
        context = ssl.create_default_context(cafile=ca_file)
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        self.ssl_context = context
        self._opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=context),
            _RefuseRedirects(),
        )

    def post(
        self, url: str, body: bytes, headers: dict[str, str], timeout: float
    ) -> tuple[int, dict[str, str], bytes]:
        request = urllib.request.Request(url, data=body, headers=headers, method="POST")
        try:
            with self._opener.open(request, timeout=timeout) as response:
                return (
                    response.status,
                    {k.lower(): v for k, v in response.headers.items()},
                    response.read(),
                )
        except urllib.error.HTTPError as exc:
            # An HTTP error is still a server answer, and its status is
            # what decides retryability. The status line arrived intact
            # even when the body did not - a server refusing an oversized
            # upload often closes before its 413 body is read - so a
            # failed body read must not turn a definite 413 into an
            # ambiguous drop (ADR-073).
            try:
                body = exc.read() if hasattr(exc, "read") else b""
            except (OSError, http.client.HTTPException):
                body = b""
            return (
                exc.code,
                {k.lower(): v for k, v in (exc.headers or {}).items()},
                body,
            )


@dataclass
class AgentStats:
    """Forwarding statistics. Contains no credential material."""

    events_offered: int = 0
    events_dropped_overflow: int = 0
    events_invalid: int = 0
    batches_sent: int = 0
    batches_acknowledged: int = 0
    batches_failed_permanent: int = 0
    batches_exhausted_retries: int = 0
    events_stored_reported: int = 0
    events_duplicate_reported: int = 0
    events_rejected_reported: int = 0
    retries: int = 0
    rate_limited: int = 0
    conflicts: int = 0
    channel_refusals: int = 0
    events_oversized: int = 0
    batches_split: int = 0
    # ADR-073: ambiguous mid-request drops, and what they led to.
    connection_drops: int = 0
    batches_split_unconfirmed: int = 0
    channel_probes: int = 0
    events_dead_lettered: int = 0
    events_dead_letter_overflow: int = 0
    last_success_at: Optional[datetime] = None
    last_failure_at: Optional[datetime] = None
    last_error_kind: Optional[str] = None

    def snapshot(self, buffered: int, capacity: int, running: bool) -> dict[str, Any]:
        return {
            "running": running,
            "buffered_events": buffered,
            "buffer_capacity": capacity,
            "buffer_utilisation": round(buffered / capacity, 4) if capacity else None,
            "events_offered": self.events_offered,
            "events_dropped_overflow": self.events_dropped_overflow,
            "events_invalid": self.events_invalid,
            "batches_sent": self.batches_sent,
            "batches_acknowledged": self.batches_acknowledged,
            "batches_failed_permanent": self.batches_failed_permanent,
            "batches_exhausted_retries": self.batches_exhausted_retries,
            "events_stored_reported": self.events_stored_reported,
            "events_duplicate_reported": self.events_duplicate_reported,
            "events_rejected_reported": self.events_rejected_reported,
            "retries": self.retries,
            "rate_limited": self.rate_limited,
            "conflicts": self.conflicts,
            "channel_refusals": self.channel_refusals,
            "events_oversized": self.events_oversized,
            "batches_split": self.batches_split,
            "connection_drops": self.connection_drops,
            "batches_split_unconfirmed": self.batches_split_unconfirmed,
            "channel_probes": self.channel_probes,
            "events_dead_lettered": self.events_dead_lettered,
            "events_dead_letter_overflow": self.events_dead_letter_overflow,
            "last_success_at": (
                self.last_success_at.isoformat() if self.last_success_at else None
            ),
            "last_failure_at": (
                self.last_failure_at.isoformat() if self.last_failure_at else None
            ),
            "last_error_kind": self.last_error_kind,
            "delivery_semantics": (
                "at-least-once with server-side deduplication; NOT exactly-once"
            ),
            "buffer_durability": (
                "in-memory and bounded: unacknowledged events are lost if the "
                "process is killed"
            ),
        }


REQUIRED_EVENT_FIELDS = ("event_id", "timestamp", "src_ip", "dst_ip")


def validate_event(record: dict[str, Any]) -> list[str]:
    """
    Reject locally what the server would reject anyway.

    Forwarding a record the server cannot accept wastes a round trip and,
    worse, a permanently invalid record would occupy buffer space behind
    valid telemetry.

    `event_id` is required by the agent even though the API tolerates its
    absence: without it a retry is NOT deduplicated (ADR-050), so an
    agent that retries must supply one.
    """
    problems = []
    if not isinstance(record, dict):
        return ["record_is_not_an_object"]
    for key in REQUIRED_EVENT_FIELDS:
        value = record.get(key)
        if value is None or (isinstance(value, str) and not value.strip()):
            problems.append(f"missing_{key}")
    try:
        # Checked here, not at send time: a value json cannot encode (a
        # datetime is the usual one) used to raise inside flush_once with
        # the whole batch already out of the buffer (ADR-077).
        json.dumps(record)
    except (TypeError, ValueError):
        problems.append("not_json_serialisable")
    return problems


class SensorAgent:
    """
    Buffers locally collected events and forwards them to a central
    PraHari, retrying transient failures with bounded backoff.

    Thread-safe. `offer()` may be called from a collector thread while
    `flush_once()` runs on another.
    """

    def __init__(
        self,
        config: AgentConfig,
        transport: Optional[Transport] = None,
        sleep_fn: Callable[[float], None] = time.sleep,
        clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ):
        self.config = config
        self._transport = transport or UrllibTransport(ca_file=config.ca_file)
        self._sleep = sleep_fn
        self._clock = clock
        self._buffer: deque[dict[str, Any]] = deque()
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._running = False
        self.stats = AgentStats()
        # What the server has CONFIRMED about its limit (ADR-073): a clean
        # 413 proves a body of that size is too large, so multi-event
        # bodies are kept below it from then on. A byte ceiling, not an
        # event count - a 413 on two large events says nothing about a
        # batch of small ones. Only a 413 lowers it; it never rises.
        self._learned_max_bytes: Optional[int] = None
        # Batch size by event count, lowered only by UNCONFIRMED evidence
        # (rounds of mid-request drops) and recovering toward batch_size
        # after successful deliveries, so a flaky network does not shrink
        # batches for good.
        self._batch_cap = config.batch_size
        self._cap_successes = 0
        # Events set aside on evidence that they alone cannot be delivered
        # (ADR-073). Kept in memory, bounded, reported - never silently
        # discarded - and requeueable by an operator.
        self._dead_letter: deque[dict[str, Any]] = deque()

    # ──────────────── intake ────────────────

    def offer(self, record: dict[str, Any]) -> bool:
        """
        Add one event to the buffer.

        Returns False when the event was not accepted — invalid, or the
        buffer is full under a policy that refuses. Nothing is ever
        discarded silently: every drop increments a counter and logs.
        """
        problems = validate_event(record)
        if problems:
            with self._lock:
                self.stats.events_invalid += 1
            logger.warning(
                "Rejected an event before forwarding: %s", ", ".join(problems)
            )
            return False

        with self._lock:
            self.stats.events_offered += 1
            if len(self._buffer) >= self.config.buffer_capacity:
                if self.config.overflow_policy == OverflowPolicy.DROP_OLDEST:
                    self._buffer.popleft()
                    self.stats.events_dropped_overflow += 1
                    logger.warning(
                        "Buffer full (%d); dropped the oldest event to make room.",
                        self.config.buffer_capacity,
                    )
                else:
                    self.stats.events_dropped_overflow += 1
                    logger.warning(
                        "Buffer full (%d); refusing the new event.",
                        self.config.buffer_capacity,
                    )
                    return False
            self._buffer.append(record)
            return True

    def offer_many(self, records: Iterable[dict[str, Any]]) -> int:
        return sum(1 for r in records if self.offer(r))

    @property
    def buffered(self) -> int:
        with self._lock:
            return len(self._buffer)

    # ──────────────── delivery ────────────────

    def _take_batch(self, limit: Optional[int] = None) -> list[dict[str, Any]]:
        with self._lock:
            n = min(limit or self._batch_cap, len(self._buffer))
            return [self._buffer.popleft() for _ in range(n)]

    def _return_batch(self, batch: list[dict[str, Any]]) -> None:
        """
        Put an undelivered batch back at the FRONT, preserving order.

        Appending would reorder telemetry and, worse, let a failing batch
        starve behind newer events indefinitely.
        """
        with self._lock:
            kept = 0
            for record in reversed(batch):
                if len(self._buffer) >= self.config.buffer_capacity:
                    break
                self._buffer.appendleft(record)
                kept += 1
            # The collector may have filled the buffer while this batch was
            # in flight. What cannot go back is the oldest telemetry -
            # dropped, as DROP_OLDEST would - and EVERY such event is
            # counted, not one per batch.
            lost = len(batch) - kept
            self.stats.events_dropped_overflow += lost
        if lost:
            logger.warning(
                "Buffer full while returning an undelivered batch; dropped the "
                "%d oldest event(s).", lost,
            )

    def _idempotency_key(self, batch: list[dict[str, Any]]) -> str:
        """
        Stable for a given batch so a retry reuses it.

        Derived from the event ids, not from a counter or the clock: a
        resend after a lost response must present the same key, or the
        server allocates a new identity namespace for it (ADR-050).
        """
        import hashlib

        joined = "|".join(str(r.get("event_id", "")) for r in batch)
        digest = hashlib.sha256(
            f"{self.config.source_id}|{joined}".encode("utf-8")
        ).hexdigest()
        return f"agent-{digest[:32]}"

    def _interpret(self, status: int, headers: dict[str, str], body: bytes) -> ForwardResult:
        if 300 <= status < 400:
            return ForwardResult(
                status=status, ok=False, retryable=False, halt=True,
                error_kind="redirect_refused",
                detail="the ingest endpoint redirected; redirects are never "
                       "followed because they would carry the credential",
            )
        if status in ENDPOINT_REFUSED_STATUSES:
            return ForwardResult(
                status=status, ok=False, retryable=False, halt=True,
                error_kind="endpoint_refused",
                detail=f"HTTP {status} from the ingest endpoint: the URL or method "
                       "is wrong. The events are kept; correct the endpoint.",
            )
        retry_after: Optional[float] = None
        raw = headers.get("retry-after")
        if raw:
            try:
                retry_after = float(raw)
            except ValueError:
                retry_after = None

        payload: dict[str, Any] = {}
        if body:
            try:
                parsed = json.loads(body.decode("utf-8", errors="replace"))
                if isinstance(parsed, dict):
                    payload = parsed
            except (json.JSONDecodeError, UnicodeDecodeError):
                # A response we cannot parse is not a reason to assume
                # success; the status alone decides.
                payload = {}

        if 200 <= status < 300:
            stored = payload.get("stored_records")
            duplicates = payload.get("duplicate_records")
            rejected = payload.get("rejected_records")
            if not isinstance(stored, int):
                stored = None
            if not isinstance(duplicates, int):
                duplicates = None
            if not isinstance(rejected, int):
                rejected = None
            reasons = payload.get("rejection_reasons")
            return ForwardResult(
                status=status, ok=True, retryable=False,
                stored=stored, duplicates=duplicates, rejected=rejected,
                detail=json.dumps(reasons)[:300] if rejected and reasons else "",
            )

        detail = payload.get("detail")
        kind = None
        message = ""
        if isinstance(detail, dict):
            kind = detail.get("error")
            message = str(detail.get("message", ""))
        elif isinstance(detail, str):
            message = detail

        return ForwardResult(
            status=status,
            ok=False,
            retryable=status in RETRYABLE_STATUSES,
            retry_after=retry_after,
            error_kind=kind or f"http_{status}",
            detail=message[:300],
        )

    def _encode(self, batch: list[dict[str, Any]]) -> tuple[str, bytes]:
        ndjson = "\n".join(json.dumps(r) for r in batch) + "\n"
        key = self._idempotency_key(batch)
        body = json.dumps({
            "source_id": self.config.source_id,
            "ndjson_content": ndjson,
            "data_category": "live_telemetry",
            "idempotency_key": key,
        }).encode("utf-8")
        return key, body

    def _fit_batch(self, batch: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """
        Shrink a batch until its request fits `max_request_bytes`.

        The tail is returned to the FRONT of the buffer, so order is kept
        and it is sent next. A single event that cannot fit on its own is
        dropped and counted: it could never be delivered, and keeping it
        would block every event behind it.
        """
        limit = self.config.max_request_bytes
        # Below a body the server refused with 413, if one has been seen.
        # Applied to multi-event batches only: whether one event is too
        # large is the server's call (a 413 for it alone drops it), never
        # inferred from a ceiling learned on other events.
        soft = min(limit, self._learned_max_bytes or limit)
        while batch:
            _, body = self._encode(batch)
            if len(body) <= soft:
                return batch
            if len(batch) == 1:
                if len(body) <= limit:
                    return batch
                with self._lock:
                    self.stats.events_oversized += 1
                logger.error(
                    "Dropping one event whose request alone is %d bytes, over "
                    "max_request_bytes=%d; it could never be accepted.",
                    len(body), limit,
                )
                return []
            half = len(batch) // 2
            self._return_batch(batch[half:])
            batch = batch[:half]
            with self._lock:
                self.stats.batches_split += 1
        return batch

    def _post(self, batch: list[dict[str, Any]]) -> ForwardResult:
        key, body = self._encode(batch)

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.config.token}",
            "Idempotency-Key": key,
            "User-Agent": "prahari-sensor-agent",
        }
        try:
            status, resp_headers, resp_body = self._transport.post(
                self.config.endpoint, body, headers, self.config.timeout_seconds
            )
        except TimeoutError as exc:
            return ForwardResult(
                status=0, ok=False, retryable=True,
                error_kind="timeout", detail=str(exc)[:300],
            )
        except OSError as exc:
            # Checked BEFORE the generic branch: urllib wraps a certificate
            # failure in URLError, which is an OSError, so it used to be
            # reported as "connection_error" and retried. A certificate
            # that fails verification is a misconfiguration or an
            # interception, never a transient fault.
            reason = getattr(exc, "reason", exc)
            if isinstance(reason, ssl.SSLCertVerificationError):
                return ForwardResult(
                    status=0, ok=False, retryable=False, halt=True,
                    error_kind="tls_verification_failed",
                    detail=str(getattr(reason, "verify_message", "") or reason)[:300],
                )
            # Other SSLError subclasses (SSLEOFError above all) are the peer
            # closing the connection, not a trust failure: a server that
            # refuses an oversized body closes the socket mid-upload, and
            # the client sees an EOF. Only a failed verification halts.
            #
            # A connection lost mid-request is kept apart from one never
            # made (refused, DNS, unreachable): both are retryable, but only
            # repeated drops are evidence the request itself may be the
            # problem (ADR-073).
            if isinstance(reason, _DROP_ERRORS) or isinstance(exc, _DROP_ERRORS):
                return ForwardResult(
                    status=0, ok=False, retryable=True,
                    error_kind=DROPPED, detail=str(exc)[:300],
                )
            return ForwardResult(
                status=0, ok=False, retryable=True,
                error_kind="connection_error", detail=str(exc)[:300],
            )
        except http.client.HTTPException as exc:
            # IncompleteRead, BadStatusLine: the connection was made and the
            # exchange broke off. Not an OSError, so it used to escape
            # flush_once with the batch already out of the buffer.
            return ForwardResult(
                status=0, ok=False, retryable=True,
                error_kind=DROPPED, detail=f"{type(exc).__name__}: {exc}"[:300],
            )
        return self._interpret(status, resp_headers, resp_body)

    def _send(self, batch: list[dict[str, Any]], *held: list[dict[str, Any]]) -> ForwardResult:
        """
        `_post`, counted - and never losing events to an unexpected error.

        A transport may raise something `_post` does not classify. The
        batch is already out of the buffer at that point, so it (and any
        other events held aside, front-most first) goes back before the
        exception propagates.
        """
        with self._lock:
            self.stats.batches_sent += 1
        try:
            return self._post(batch)
        except Exception:
            for group in reversed((*held, batch)):
                self._return_batch(group)
            raise

    def _note_failure(self, result: ForwardResult) -> bool:
        """Failure bookkeeping for any send. True for a mid-request drop."""
        with self._lock:
            self.stats.last_failure_at = self._clock()
            self.stats.last_error_kind = result.error_kind
            if result.status == 429:
                self.stats.rate_limited += 1
            if result.status == 409:
                self.stats.conflicts += 1
            if result.error_kind == DROPPED:
                self.stats.connection_drops += 1
                return True
        return False

    def _drop_refused(self, batch: list[dict[str, Any]], result: ForwardResult) -> None:
        """
        400/401/403/409, or 413 for one event alone: resending the same
        bytes cannot help. The batch is dropped rather than retried forever,
        and the drop is counted and logged with its reason.
        """
        with self._lock:
            self.stats.batches_failed_permanent += 1
            if result.status == 413:
                # One event the server will never accept: the same outcome
                # as one over max_request_bytes locally.
                self.stats.events_oversized += len(batch)
        logger.error(
            "Dropping %d event(s): server refused permanently (%s: %s). "
            "Retrying would loop.",
            len(batch), result.error_kind, result.detail,
        )

    def _record_ack(self, result: ForwardResult) -> None:
        if result.rejected:
            # Acknowledged, but these events are gone: the server refused
            # them individually and will not take them on a resend either.
            logger.warning(
                "Server accepted the batch but rejected %d record(s): %s",
                result.rejected, result.detail or "no reasons given",
            )
        with self._lock:
            self.stats.batches_acknowledged += 1
            self.stats.last_success_at = self._clock()
            if result.stored:
                self.stats.events_stored_reported += result.stored
            if result.duplicates:
                self.stats.events_duplicate_reported += result.duplicates
            if result.rejected:
                self.stats.events_rejected_reported += result.rejected
            if self._batch_cap < self.config.batch_size:
                self._cap_successes += 1
                if self._cap_successes >= CAP_RECOVERY_SUCCESSES:
                    self._batch_cap = min(self.config.batch_size, self._batch_cap * 2)
                    self._cap_successes = 0

    def _backoff(self, attempt: int, retry_after: Optional[float]) -> float:
        """
        Bounded exponential backoff with jitter.

        A server-supplied `Retry-After` wins: the server knows when it
        will be ready and the agent should not second-guess it. Jitter
        exists so a fleet reconnecting after an outage does not
        synchronise into a thundering herd.
        """
        if retry_after is not None and retry_after >= 0:
            return min(retry_after, self.config.max_backoff_seconds)
        delay = min(
            self.config.base_backoff_seconds * (2 ** max(0, attempt - 1)),
            self.config.max_backoff_seconds,
        )
        return delay * (0.5 + random.random() * 0.5)

    def flush_once(self) -> Optional[ForwardResult]:
        """
        Send one batch, retrying transient failures up to `max_attempts`.

        Returns None when there is nothing buffered. A batch that cannot
        be delivered is returned to the buffer unless the server said the
        request itself is wrong.
        """
        batch = self._take_batch()
        if not batch:
            return None
        try:
            batch = self._fit_batch(batch)
        except Exception:
            # Encoding failed (a record changed after offer()). Whatever
            # _fit_batch had not already returned goes back in front.
            self._return_batch(batch)
            raise
        if not batch:
            return ForwardResult(
                status=0, ok=False, retryable=False,
                error_kind="event_too_large",
                detail="an event exceeded max_request_bytes on its own and was dropped",
            )

        last: Optional[ForwardResult] = None
        drops = 0
        for attempt in range(1, self.config.max_attempts + 1):
            if self._stop.is_set() and attempt > 1:
                # Interrupted mid-retry: keep the events rather than
                # burning the remaining attempts during shutdown.
                self._return_batch(batch)
                return last

            result = self._send(batch)
            last = result

            if result.ok:
                self._record_ack(result)
                return result

            if self._note_failure(result):
                drops += 1

            if result.halt:
                # The channel is unusable. Keep the events and stop sending
                # until an operator fixes the endpoint or its trust.
                with self._lock:
                    self.stats.channel_refusals += 1
                self._return_batch(batch)
                logger.error(
                    "Keeping %d event(s) and halting delivery: %s (%s). "
                    "Fix the endpoint or ca_file; verification will not be relaxed.",
                    len(batch), result.error_kind, result.detail,
                )
                return result

            if not result.retryable and result.status == 413 and len(batch) > 1:
                # The server's body limit is below max_request_bytes and it
                # said so cleanly. The events are not at fault - the server
                # asks for smaller batches - so they are kept, in order,
                # and every later multi-event body is kept below this one.
                # The same bytes are never resent, and each such refusal
                # strictly lowers the ceiling, so this ends: in delivery,
                # or at a single event the server refuses alone (dropped
                # below).
                _, body = self._encode(batch)
                with self._lock:
                    self._learned_max_bytes = min(
                        self._learned_max_bytes or len(body), len(body) - 1
                    )
                    self.stats.batches_split += 1
                self._return_batch(batch)
                logger.warning(
                    "Server refused a %d-event, %d-byte batch as too large (%s); "
                    "keeping the events and sending smaller batches. Set "
                    "max_request_bytes to the server's limit or lower.",
                    len(batch), len(body), result.detail,
                )
                return result

            if not result.retryable:
                self._drop_refused(batch, result)
                return result

            if attempt < self.config.max_attempts:
                with self._lock:
                    self.stats.retries += 1
                self._sleep(self._backoff(attempt, result.retry_after))

        with self._lock:
            self.stats.batches_exhausted_retries += 1
        if drops == self.config.max_attempts:
            # Every attempt was a mid-request drop: the one pattern that
            # may mean the request itself cannot get through. Resending the
            # same bytes on the next flush is the ADR-066 wedge.
            return self._after_repeated_drops(batch, last)
        logger.warning(
            "Returning %d event(s) to the buffer after %d failed attempts.",
            len(batch), self.config.max_attempts,
        )
        self._return_batch(batch)
        return last

    def _after_repeated_drops(
        self, batch: list[dict[str, Any]], last: Optional[ForwardResult]
    ) -> Optional[ForwardResult]:
        """
        Bounded handling of a batch whose every attempt dropped mid-request.

        A multi-event batch is split (cap halved) - UNCONFIRMED, because an
        outage looks identical; splitting loses nothing either way and the
        cap recovers after successes. Each such round at least halves the
        batch, so this reaches a single event in bounded rounds.
        """
        if len(batch) > 1:
            with self._lock:
                self._batch_cap = max(1, len(batch) // 2)
                self._cap_successes = 0
                self.stats.batches_split_unconfirmed += 1
            self._return_batch(batch)
            logger.warning(
                "Every attempt to send %d event(s) dropped mid-request; keeping "
                "them and capping batches at %d (unconfirmed: an outage looks "
                "the same). If the server's body limit is below max_request_bytes, "
                "lower max_request_bytes.",
                len(batch), self._batch_cap,
            )
            return last
        return self._probe_past(batch[0], last)

    def _probe_past(
        self, suspect: dict[str, Any], last: Optional[ForwardResult]
    ) -> ForwardResult:
        """
        Decide whether ONE event, not the channel, is what keeps dropping.

        The next buffered event is sent alone. If the channel cannot carry
        it either, this is an outage: both go back in their original order,
        still retryable. If it is acknowledged, the suspect gets one more
        immediate attempt; dropping again, back to back with a success, is
        evidence enough to set it aside in the dead-letter store - kept,
        counted and requeueable, never silently discarded - so the events
        behind it can flow. Only the dead-letter case changes the order
        of delivery, and only for the event set aside.
        """
        taken = self._take_batch(limit=1)
        try:
            probe = self._fit_batch(taken)
        except Exception:
            self._return_batch(taken)
            self._return_batch([suspect])
            raise
        if not probe:
            self._return_batch([suspect])
            return last
        with self._lock:
            self.stats.channel_probes += 1
        probe_result = self._send(probe, [suspect])
        if probe_result.ok:
            self._record_ack(probe_result)
        else:
            self._note_failure(probe_result)
            if probe_result.halt or probe_result.retryable:
                # No evidence about the suspect: an outage, an overloaded
                # server, or a channel fault. Restore the order.
                self._return_batch(probe)
                self._return_batch([suspect])
                return last
            # A definite refusal of the probe event itself (400/401/403/409,
            # or 413 for it alone). It applies to that event however it was
            # sent, so the normal rule drops it - and an answer at all is
            # proof the channel carries requests. Putting both back would
            # repeat this exact round on every flush.
            self._drop_refused(probe, probe_result)

        again = self._send([suspect])
        if again.ok:
            self._record_ack(again)
            return again
        if not self._note_failure(again):
            # A definite answer now; the next flush applies the normal rule.
            self._return_batch([suspect])
            return again

        with self._lock:
            if len(self._dead_letter) >= self.config.buffer_capacity:
                self._dead_letter.popleft()
                self.stats.events_dead_letter_overflow += 1
            self._dead_letter.append(suspect)
            self.stats.events_dead_lettered += 1
        logger.error(
            "Event %s dropped the connection on every attempt while the event "
            "behind it was delivered; set aside in the dead-letter store (see "
            "dead_letters / requeue_dead_letters).",
            suspect.get("event_id"),
        )
        return ForwardResult(
            status=0, ok=False, retryable=False,
            error_kind="event_undeliverable",
            detail="one event repeatedly dropped the connection while the "
                   "channel delivered others; set aside, not discarded",
        )

    def dead_letters(self) -> list[dict[str, Any]]:
        """Events set aside as undeliverable, oldest first (copies)."""
        with self._lock:
            return [dict(r) for r in self._dead_letter]

    def requeue_dead_letters(self) -> int:
        """
        Put set-aside events back at the FRONT of the buffer, in order -
        for an operator who has corrected max_request_bytes or the server.

        Only as many as the buffer has room for, oldest first; the rest
        stay in the dead-letter store rather than being dropped. Returns
        the number actually requeued.
        """
        with self._lock:
            room = max(0, self.config.buffer_capacity - len(self._buffer))
            moved = [self._dead_letter.popleft() for _ in range(min(room, len(self._dead_letter)))]
            for record in reversed(moved):
                self._buffer.appendleft(record)
        return len(moved)

    def flush_all(self, max_batches: int = 1000) -> int:
        """Drain the buffer. Bounded so a failing server cannot spin forever."""
        delivered = 0
        for _ in range(max_batches):
            if self._stop.is_set():
                break
            result = self.flush_once()
            if result is None:
                break
            if result.ok:
                delivered += 1
            elif result.halt:
                break  # the same batch would fail the same way; never spin
            elif not result.retryable:
                continue
            else:
                break  # transient and exhausted; stop and keep the buffer
        return delivered

    # ──────────────── lifecycle ────────────────

    def request_stop(self) -> None:
        self._stop.set()

    def shutdown(self, drain: bool = True, max_batches: int = 50) -> dict[str, Any]:
        """
        Stop accepting work and optionally drain what is buffered.

        Returns the final statistics, including how many events were
        still buffered — never reported as delivered.
        """
        self._running = False
        if drain:
            # Drained BEFORE the stop flag so the final flush is allowed
            # to complete; request_stop would abort it mid-retry.
            for _ in range(max_batches):
                result = self.flush_once()
                if result is None or not result.ok:
                    break
        self._stop.set()
        remaining = self.buffered
        if remaining:
            logger.warning(
                "Shutting down with %d unacknowledged event(s) still buffered; "
                "they are in memory only and will be lost.", remaining,
            )
        return self.health()

    def health(self) -> dict[str, Any]:
        """Forwarding statistics. Never contains the token."""
        snapshot = self.stats.snapshot(
            buffered=self.buffered,
            capacity=self.config.buffer_capacity,
            running=self._running,
        )
        with self._lock:
            snapshot["batch_size_cap"] = self._batch_cap
            snapshot["learned_max_request_bytes"] = self._learned_max_bytes
            snapshot["dead_letter_events"] = len(self._dead_letter)
        return snapshot
