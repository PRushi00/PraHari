"""
PraHari — Bounded Ingestion Admission Control and Metrics (blueprint §4.2, §6)

§6 requires bounded resources and observable ingestion: "Use bounded queues
and expose backpressure rather than consuming unlimited memory", and §4.2
requires central deployment to expose "health, lag, queue depth, rejected
records, and last-successful-ingestion time".

Why this is admission control and not a queue
---------------------------------------------
PraHari's ingestion is synchronous end to end: a request is parsed,
normalized and committed inside the handler, and the caller's HTTP
response reports what was stored (ADR-050's `stored_records`). Inserting a
queue would mean answering the request before the data is durable, which
would break that contract, the 409 conflict response and the atomic batch
rollback — three things that were deliberately built.

So the bound is applied at **admission** instead: concurrent in-flight
ingestion work is capped, and a request that cannot be admitted is
rejected immediately with 503 rather than being buffered. That satisfies
the actual safety requirement — bounded memory, visible backpressure, no
unbounded growth — without inventing a durability gap.

**`queue_depth` is therefore reported as null, not zero.** A zero would
claim an empty queue; null says there is no queue. The field
`in_flight` carries the real number, and `admission_model` names the
mechanism so a reader is not left to assume.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

DEFAULT_MAX_CONCURRENT = 8
DEFAULT_MAX_WAIT_SECONDS = 0.0  # reject immediately rather than queueing


class IngestionOverloaded(RuntimeError):
    """Admission refused: too much ingestion already in flight."""

    def __init__(self, in_flight: int, capacity: int):
        self.in_flight = in_flight
        self.capacity = capacity
        super().__init__(
            f"Ingestion is at capacity ({in_flight}/{capacity} in flight)."
        )


@dataclass
class IngestionMetrics:
    """
    Counters for what ingestion actually did.

    Every field is something measured. Nothing here is derived from a
    configuration value or estimated, because §11 requires each displayed
    metric to be traceable to a real measurement.
    """

    requests_admitted: int = 0
    requests_rejected_overloaded: int = 0
    batches_completed: int = 0
    batches_failed: int = 0
    events_stored: int = 0
    events_duplicate: int = 0
    events_rejected: int = 0
    conflicts: int = 0

    last_success_at: Optional[datetime] = None
    last_failure_at: Optional[datetime] = None
    last_error_kind: Optional[str] = None

    # Processing latency of completed batches, in milliseconds. Bounded:
    # only the most recent samples are kept, so a long-running process
    # cannot grow this without limit.
    _latencies_ms: list[float] = field(default_factory=list)
    _max_samples: int = 256

    def record_latency(self, ms: float) -> None:
        self._latencies_ms.append(ms)
        if len(self._latencies_ms) > self._max_samples:
            del self._latencies_ms[: len(self._latencies_ms) - self._max_samples]

    def latency_summary(self) -> dict[str, Optional[float]]:
        """
        Percentiles over the retained samples, or nulls when there are
        none. Null means "not measured yet" — never 0, which would claim
        instantaneous processing.
        """
        samples = sorted(self._latencies_ms)
        if not samples:
            return {
                "samples": 0, "p50_ms": None, "p95_ms": None, "max_ms": None,
            }

        def pct(p: float) -> float:
            idx = min(len(samples) - 1, int(round((len(samples) - 1) * p)))
            return round(samples[idx], 3)

        return {
            "samples": len(samples),
            "p50_ms": pct(0.50),
            "p95_ms": pct(0.95),
            "max_ms": round(samples[-1], 3),
        }


class AdmissionController:
    """
    Caps concurrent in-flight ingestion and records what happened.

    Thread-safe: FastAPI runs synchronous handlers in a worker thread
    pool, so several can genuinely be in flight at once.
    """

    def __init__(
        self,
        max_concurrent: int = DEFAULT_MAX_CONCURRENT,
        max_wait_seconds: float = DEFAULT_MAX_WAIT_SECONDS,
    ):
        if max_concurrent < 1:
            raise ValueError("max_concurrent must be at least 1")
        self.max_concurrent = max_concurrent
        self.max_wait_seconds = max_wait_seconds
        self._semaphore = threading.BoundedSemaphore(max_concurrent)
        self._lock = threading.Lock()
        self._in_flight = 0
        self._peak_in_flight = 0
        self.metrics = IngestionMetrics()

    @property
    def in_flight(self) -> int:
        with self._lock:
            return self._in_flight

    @property
    def peak_in_flight(self) -> int:
        with self._lock:
            return self._peak_in_flight

    def admit(self) -> "_Admission":
        """
        Reserve a slot, or raise IngestionOverloaded.

        Returns a context manager so the slot is released even when the
        handler raises — a conflict or a database error must not leak
        capacity.
        """
        acquired = self._semaphore.acquire(
            blocking=self.max_wait_seconds > 0,
            timeout=self.max_wait_seconds if self.max_wait_seconds > 0 else None,
        )
        if not acquired:
            with self._lock:
                self.metrics.requests_rejected_overloaded += 1
                current = self._in_flight
            logger.warning(
                "Ingestion admission refused: %d/%d in flight",
                current, self.max_concurrent,
            )
            raise IngestionOverloaded(current, self.max_concurrent)

        with self._lock:
            self._in_flight += 1
            self._peak_in_flight = max(self._peak_in_flight, self._in_flight)
            self.metrics.requests_admitted += 1
        return _Admission(self)

    def _release(self) -> None:
        with self._lock:
            self._in_flight = max(0, self._in_flight - 1)
        self._semaphore.release()

    # ──────────────── outcome recording ────────────────

    def record_batch(
        self,
        stored: int,
        duplicates: int,
        rejected: int,
        elapsed_ms: float,
    ) -> None:
        with self._lock:
            self.metrics.batches_completed += 1
            self.metrics.events_stored += stored
            self.metrics.events_duplicate += duplicates
            self.metrics.events_rejected += rejected
            self.metrics.last_success_at = datetime.now(timezone.utc)
            self.metrics.record_latency(elapsed_ms)

    def record_failure(self, kind: str) -> None:
        with self._lock:
            self.metrics.batches_failed += 1
            if kind == "conflict":
                self.metrics.conflicts += 1
            self.metrics.last_failure_at = datetime.now(timezone.utc)
            self.metrics.last_error_kind = kind

    def snapshot(self) -> dict:
        """
        Everything measured, shaped for the health API.

        `queue_depth` is **null by design**: there is no queue. Reporting
        0 would assert an empty one.
        """
        with self._lock:
            m = self.metrics
            return {
                "admission_model": "bounded_concurrency_no_queue",
                "queue_depth": None,
                "queue_depth_note": (
                    "Ingestion is synchronous: a request is parsed, stored and "
                    "answered in the handler, so no queue exists. Bounding is "
                    "applied by capping concurrent in-flight work instead. "
                    "null means 'no queue', not 'an empty queue'."
                ),
                "in_flight": self._in_flight,
                "peak_in_flight": self._peak_in_flight,
                "capacity": self.max_concurrent,
                "saturated": self._in_flight >= self.max_concurrent,
                "requests_admitted": m.requests_admitted,
                "requests_rejected_overloaded": m.requests_rejected_overloaded,
                "batches_completed": m.batches_completed,
                "batches_failed": m.batches_failed,
                "conflicts": m.conflicts,
                "events_stored": m.events_stored,
                "events_duplicate": m.events_duplicate,
                "events_rejected": m.events_rejected,
                "last_success_at": (
                    m.last_success_at.isoformat() if m.last_success_at else None
                ),
                "last_failure_at": (
                    m.last_failure_at.isoformat() if m.last_failure_at else None
                ),
                "last_error_kind": m.last_error_kind,
                "processing_latency": m.latency_summary(),
            }

    def reset(self) -> None:
        """Test helper. Never called by the application."""
        with self._lock:
            self._in_flight = 0
            self._peak_in_flight = 0
            self.metrics = IngestionMetrics()
        self._semaphore = threading.BoundedSemaphore(self.max_concurrent)


class _Admission:
    """Releases the slot on exit, however the handler ends."""

    def __init__(self, controller: AdmissionController):
        self._controller = controller
        self.started_at = time.perf_counter()

    def elapsed_ms(self) -> float:
        return (time.perf_counter() - self.started_at) * 1000.0

    def __enter__(self) -> "_Admission":
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        self._controller._release()
        return False


_controller: Optional[AdmissionController] = None
_controller_lock = threading.Lock()


def get_admission_controller(
    max_concurrent: Optional[int] = None,
) -> AdmissionController:
    """Process-wide controller. Bounding is per process, as is the limit."""
    global _controller
    with _controller_lock:
        if _controller is None:
            _controller = AdmissionController(
                max_concurrent=max_concurrent or DEFAULT_MAX_CONCURRENT
            )
        return _controller


def reset_admission_controller(max_concurrent: Optional[int] = None) -> AdmissionController:
    """Test helper: replace the process-wide controller."""
    global _controller
    with _controller_lock:
        _controller = AdmissionController(
            max_concurrent=max_concurrent or DEFAULT_MAX_CONCURRENT
        )
        return _controller
