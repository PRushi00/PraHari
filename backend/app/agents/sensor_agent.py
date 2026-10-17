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
    # client never sees the 413 - only a dropped connection, which is
    # retryable. Without this bound one oversized batch was resent forever
    # and wedged everything behind it.
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
            # what decides retryability.
            return (
                exc.code,
                {k.lower(): v for k, v in (exc.headers or {}).items()},
                exc.read() if hasattr(exc, "read") else b"",
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
    retries: int = 0
    rate_limited: int = 0
    conflicts: int = 0
    channel_refusals: int = 0
    events_oversized: int = 0
    batches_split: int = 0
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
            "retries": self.retries,
            "rate_limited": self.rate_limited,
            "conflicts": self.conflicts,
            "channel_refusals": self.channel_refusals,
            "events_oversized": self.events_oversized,
            "batches_split": self.batches_split,
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

    def _take_batch(self) -> list[dict[str, Any]]:
        with self._lock:
            n = min(self.config.batch_size, len(self._buffer))
            return [self._buffer.popleft() for _ in range(n)]

    def _return_batch(self, batch: list[dict[str, Any]]) -> None:
        """
        Put an undelivered batch back at the FRONT, preserving order.

        Appending would reorder telemetry and, worse, let a failing batch
        starve behind newer events indefinitely.
        """
        with self._lock:
            for record in reversed(batch):
                if len(self._buffer) >= self.config.buffer_capacity:
                    self.stats.events_dropped_overflow += 1
                    logger.warning("Buffer full while returning an undelivered batch.")
                    break
                self._buffer.appendleft(record)

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
            if not isinstance(stored, int):
                stored = None
            if not isinstance(duplicates, int):
                duplicates = None
            return ForwardResult(
                status=status, ok=True, retryable=False,
                stored=stored, duplicates=duplicates,
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
        while batch:
            _, body = self._encode(batch)
            if len(body) <= limit:
                return batch
            if len(batch) == 1:
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
            # the client sees an EOF. Those fall through as connection
            # errors; only a failed verification halts.
            # Connection refused, DNS failure, reset — all transient from
            # the agent's point of view.
            return ForwardResult(
                status=0, ok=False, retryable=True,
                error_kind="connection_error", detail=str(exc)[:300],
            )
        return self._interpret(status, resp_headers, resp_body)

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
        batch = self._fit_batch(batch)
        if not batch:
            return ForwardResult(
                status=0, ok=False, retryable=False,
                error_kind="event_too_large",
                detail="an event exceeded max_request_bytes on its own and was dropped",
            )

        last: Optional[ForwardResult] = None
        for attempt in range(1, self.config.max_attempts + 1):
            if self._stop.is_set() and attempt > 1:
                # Interrupted mid-retry: keep the events rather than
                # burning the remaining attempts during shutdown.
                self._return_batch(batch)
                return last

            with self._lock:
                self.stats.batches_sent += 1
            result = self._post(batch)
            last = result

            if result.ok:
                with self._lock:
                    self.stats.batches_acknowledged += 1
                    self.stats.last_success_at = self._clock()
                    if result.stored:
                        self.stats.events_stored_reported += result.stored
                    if result.duplicates:
                        self.stats.events_duplicate_reported += result.duplicates
                return result

            with self._lock:
                self.stats.last_failure_at = self._clock()
                self.stats.last_error_kind = result.error_kind
                if result.status == 429:
                    self.stats.rate_limited += 1
                if result.status == 409:
                    self.stats.conflicts += 1

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

            if not result.retryable:
                # 400/401/403/409/413: resending the same bytes cannot
                # help. The batch is dropped rather than retried forever,
                # and the drop is counted and logged with its reason.
                with self._lock:
                    self.stats.batches_failed_permanent += 1
                logger.error(
                    "Dropping %d event(s): server refused permanently (%s: %s). "
                    "Retrying would loop.",
                    len(batch), result.error_kind, result.detail,
                )
                return result

            if attempt < self.config.max_attempts:
                with self._lock:
                    self.stats.retries += 1
                self._sleep(self._backoff(attempt, result.retry_after))

        with self._lock:
            self.stats.batches_exhausted_retries += 1
        logger.warning(
            "Returning %d event(s) to the buffer after %d failed attempts.",
            len(batch), self.config.max_attempts,
        )
        self._return_batch(batch)
        return last

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
        return self.stats.snapshot(
            buffered=self.buffered,
            capacity=self.config.buffer_capacity,
            running=self._running,
        )
