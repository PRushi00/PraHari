"""
PraHari — Live Windows Telemetry Collector Service

Runs the Windows connection-table adapter on a background polling loop,
persists genuinely new observations through the existing storage layer, and
exposes truthful operational health: poll counts, acceptance/rejection
accounting, suppressed repeat observations, collection gaps, and errors.

Design constraints honoured here:
  * Collection never blocks the API event loop (OS query and SQLite writes
    both run in worker threads).
  * The collector is explicitly started by an operator — it does not
    auto-start and it does not seed the database on application startup.
  * Repeat observations of a still-open connection are suppressed rather than
    re-inserted, so unique event counts are not inflated.
  * Failures are surfaced, never swallowed.
"""

from __future__ import annotations

import asyncio
import logging
import platform
import sys
from datetime import datetime, timezone
from typing import Any, Callable, Optional

from pydantic import BaseModel, Field

from app.adapters.base import get_adapter_registry
from app.adapters.linux_telemetry import (
    platform_is_linux,
    query_linux_connections,
)
from app.adapters.windows_telemetry import (
    DEFAULT_TCP_STATES,
    WINDOWS_SOURCE_TYPE,
    WindowsConnectionAdapter,
    WindowsTelemetryUnavailable,
    query_windows_connections,
)
from app.schemas.events import DataCategory, ImportSummary, TelemetrySource
from app.storage.database import Database

logger = logging.getLogger(__name__)

DEFAULT_SOURCE_ID = "windows_local_host"
MIN_INTERVAL_SECONDS = 2.0
MAX_CONSECUTIVE_FAILURES = 5



def default_host_query_fn():
    """
    The host connection-table query for THIS platform.

    Selected at construction rather than at import, so a test that
    monkeypatches the platform sees the choice it expects. On an
    unsupported platform the Windows function is returned and
    `platform_supported` is False, so the collector refuses to start
    rather than calling it.
    """
    if platform_is_linux():
        return query_linux_connections
    return query_windows_connections


class CollectionGap(BaseModel):
    """A period during which no successful collection occurred."""
    gap_start: datetime
    gap_end: datetime
    gap_seconds: float
    reason: str


class PollResult(BaseModel):
    """Outcome of a single collection poll."""
    polled_at: datetime
    succeeded: bool
    records_observed: int = 0
    events_accepted: int = 0
    events_persisted: int = 0
    duplicates_suppressed: int = 0
    records_filtered_by_policy: int = 0
    records_rejected: int = 0
    rejection_reasons: dict[str, int] = Field(default_factory=dict)
    latest_event_observed_at: Optional[datetime] = None
    error: Optional[str] = None


class CollectorStatus(BaseModel):
    """Operational state of the live Windows telemetry collector."""
    state: str  # stopped | running | error | unsupported
    platform_supported: bool
    platform_name: str
    source_id: str
    source_type: str = WINDOWS_SOURCE_TYPE
    data_category: DataCategory = DataCategory.LIVE_TELEMETRY

    interval_seconds: float
    include_loopback: bool
    collected_tcp_states: list[str]

    started_at: Optional[datetime] = None
    stopped_at: Optional[datetime] = None
    last_poll_at: Optional[datetime] = None
    last_success_at: Optional[datetime] = None
    latest_event_observed_at: Optional[datetime] = None

    polls_attempted: int = 0
    polls_succeeded: int = 0
    polls_failed: int = 0
    consecutive_failures: int = 0

    records_observed_total: int = 0
    events_accepted_total: int = 0
    events_persisted_total: int = 0
    duplicates_suppressed_total: int = 0
    records_filtered_by_policy_total: int = 0
    records_rejected_total: int = 0
    rejection_reasons: dict[str, int] = Field(default_factory=dict)

    last_error: Optional[str] = None
    collection_gaps: list[CollectionGap] = Field(default_factory=list)

    # Honest statement of what this source can and cannot see.
    capability_notes: list[str] = Field(default_factory=list)


CAPABILITY_NOTES = [
    "Source is the Windows TCP connection table (Get-NetTCPConnection): connection metadata only.",
    "Owning process NAME is resolved where visible without elevation; the command line is never collected.",
    "Destination hostnames are NOT reported by this source. Any hostname shown is inferred separately from local DNS evidence and carries its own confidence.",
    "HTTP method, path, status and timing are NOT observable here; they appear only if an authorized application-layer source reports them.",
    "Byte counts, packet counts and completed-flow duration are NOT available from this source and are stored as null.",
    "Collection is snapshot polling: connections opening and closing entirely between polls are never observed.",
    "observed_at is the OS-reported connection creation time where available, otherwise the poll time (flagged timestamp_uncertainty).",
    "UDP is not collected: Windows exposes only local UDP endpoint binds with no remote peer.",
    "Records carry no attack labels; no ground truth exists for locally observed traffic.",
]

# The Linux source reads /proc/net/tcp[6]; describing it with the Windows
# notes would claim Get-NetTCPConnection, OS creation times and a Windows
# UDP rationale that do not apply on this host (ADR-053).
LINUX_CAPABILITY_NOTES = [
    "Source is the Linux kernel TCP connection table (/proc/net/tcp and /proc/net/tcp6): connection metadata only.",
    "Owning process NAME (comm) is resolved only for processes this user may inspect; the command line is never collected.",
    "Destination hostnames are NOT reported by this source. DNS cache enrichment is Windows-only and is not performed on this host.",
    "HTTP method, path, status and timing are NOT observable here; they appear only if an authorized application-layer source reports them.",
    "Byte counts, packet counts and completed-flow duration are NOT available from this source and are stored as null.",
    "Collection is snapshot polling: connections opening and closing entirely between polls are never observed.",
    "/proc exposes no socket creation time: observed_at is always the poll time, flagged timestamp_uncertainty.",
    "UDP is not collected by this source.",
    "Records carry no attack labels; no ground truth exists for locally observed traffic.",
]


class WindowsTelemetryCollectorService:
    """Background poller for live Windows connection telemetry."""

    def __init__(
        self,
        db: Database,
        source_id: str = DEFAULT_SOURCE_ID,
        interval_seconds: float = 15.0,
        include_loopback: bool = False,
        query_fn: Optional[Callable[..., list[dict[str, Any]]]] = None,
        refresh_dns: Optional[bool] = None,
    ):
        self.db = db
        self.source_id = source_id
        self.interval_seconds = max(MIN_INTERVAL_SECONDS, float(interval_seconds))
        self.include_loopback = include_loopback
        # Injectable for tests and for any alternative producer; defaults to
        # the real OS query.
        self._query_fn = query_fn or default_host_query_fn()
        self._uses_injected_source = query_fn is not None
        # Which genuine host source the default query reads, so status and
        # source registration describe what is actually collected.
        self._reads_linux_proc = query_fn is None and platform_is_linux()

        # Snapshot the local DNS cache alongside each poll so hostname
        # evidence is captured close in time to the connections it explains.
        #
        # When a caller injects its own query_fn it is deliberately NOT
        # reading the real connection table, so touching the real DNS cache
        # would be inconsistent — and it costs a PowerShell process per
        # poll, which made the test suite spawn hundreds of subprocesses.
        # Enrichment therefore defaults OFF for an injected query, and ON
        # for genuine collection. An explicit value always wins.
        #
        # The DNS cache is read through PowerShell from the Windows DNS
        # client, so genuine collection on any other host (Linux reads
        # /proc) must not default to spawning it either.
        if refresh_dns is None:
            refresh_dns = query_fn is None and sys.platform == "win32"
        self.refresh_dns = refresh_dns
        self.dns_refresh_failures = 0

        # Registered so /stream/adapters reports this adapter's genuine
        # counters alongside the file/stream adapters.
        self.adapter = get_adapter_registry().register(
            WindowsConnectionAdapter(
                adapter_id=source_id,
                include_loopback=include_loopback,
            )
        )

        self._task: Optional[asyncio.Task] = None
        self._stop_event: Optional[asyncio.Event] = None
        self._lock = asyncio.Lock()

        self._state = "stopped"
        self._started_at: Optional[datetime] = None
        self._stopped_at: Optional[datetime] = None
        self._last_poll_at: Optional[datetime] = None
        self._last_success_at: Optional[datetime] = None
        self._latest_event_observed_at: Optional[datetime] = None

        self._polls_attempted = 0
        self._polls_succeeded = 0
        self._polls_failed = 0
        self._consecutive_failures = 0

        self._records_observed = 0
        self._events_accepted = 0
        self._events_persisted = 0
        self._records_rejected = 0
        self._rejection_reasons: dict[str, int] = {}

        self._last_error: Optional[str] = None
        self._gaps: list[CollectionGap] = []

    # ──────────────── platform ────────────────

    @property
    def platform_supported(self) -> bool:
        """
        Whether this collector can actually poll.

        The gate exists to stop the **PowerShell connection-table probe**
        running on a host that has no such table — not to stop collection
        as such. When a caller injects its own query function, no Windows
        facility is touched, so refusing would be refusing on a ground that
        does not apply.

        Found by running the suite on Linux: twelve collector tests that
        inject a fake query were failing with "unavailable on platform
        'linux'", and a genuine alternative producer would have been
        refused for the same wrong reason.
        """
        if self._uses_injected_source:
            return True
        # Windows reads the PowerShell connection table; Linux reads
        # /proc/net/tcp. Both produce the same raw record shape, so the
        # rest of this service is identical on either (blueprint §4.4).
        return sys.platform == "win32" or platform_is_linux()

    # ──────────────── lifecycle ────────────────

    @property
    def is_running(self) -> bool:
        return self._task is not None and not self._task.done()

    async def start(self, interval_seconds: Optional[float] = None) -> CollectorStatus:
        """Start the background collection loop (idempotent)."""
        async with self._lock:
            if interval_seconds is not None:
                self.interval_seconds = max(MIN_INTERVAL_SECONDS, float(interval_seconds))

            if self.is_running:
                return self.status()

            self._ensure_source_registered()

            self._stop_event = asyncio.Event()
            self._state = "running"
            self._started_at = datetime.now(timezone.utc)
            self._stopped_at = None
            self._last_error = None
            self._consecutive_failures = 0

            self._task = asyncio.create_task(
                self._run_loop(), name=f"prahari-collector-{self.source_id}"
            )
            logger.info(
                "Windows telemetry collector started (source=%s, interval=%ss)",
                self.source_id,
                self.interval_seconds,
            )
            self.db.log_audit(
                action="start_live_collector",
                resource_type="telemetry_source",
                resource_id=self.source_id,
                details=(
                    f"Started Windows connection-table collector "
                    f"(interval={self.interval_seconds}s, include_loopback={self.include_loopback})"
                ),
            )
            return self.status()

    async def stop(self, timeout: float = 30.0) -> CollectorStatus:
        """Stop the background loop and wait for it to finish cleanly."""
        async with self._lock:
            if not self.is_running:
                self._state = "stopped" if self._state != "error" else self._state
                return self.status()

            assert self._stop_event is not None
            self._stop_event.set()
            task = self._task
            try:
                await asyncio.wait_for(asyncio.shield(task), timeout=timeout)
            except asyncio.TimeoutError:
                logger.warning("Collector did not stop within %ss; cancelling", timeout)
                task.cancel()
                try:
                    await task
                except (asyncio.CancelledError, Exception):  # noqa: BLE001
                    pass
            except asyncio.CancelledError:
                pass
            except Exception as exc:  # noqa: BLE001
                logger.warning("Collector loop ended with error: %s", exc)

            self._task = None
            self._stopped_at = datetime.now(timezone.utc)
            self._state = "stopped"
            self._mark_source_status("disconnected")
            logger.info("Windows telemetry collector stopped (source=%s)", self.source_id)
            self.db.log_audit(
                action="stop_live_collector",
                resource_type="telemetry_source",
                resource_id=self.source_id,
                details=(
                    f"Stopped collector after {self._polls_succeeded} successful polls, "
                    f"{self._events_persisted} events persisted"
                ),
            )
            return self.status()

    async def _run_loop(self) -> None:
        assert self._stop_event is not None
        try:
            while not self._stop_event.is_set():
                await self.poll_once()
                if self._consecutive_failures >= MAX_CONSECUTIVE_FAILURES:
                    self._state = "error"
                    logger.error(
                        "Collector halting after %d consecutive failures: %s",
                        self._consecutive_failures,
                        self._last_error,
                    )
                    self._mark_source_status("error")
                    return
                try:
                    await asyncio.wait_for(
                        self._stop_event.wait(), timeout=self.interval_seconds
                    )
                except asyncio.TimeoutError:
                    continue
        except asyncio.CancelledError:
            logger.info("Collector loop cancelled")
            raise

    # ──────────────── collection ────────────────

    async def poll_once(self) -> PollResult:
        """
        Execute a single collection poll: query the OS, normalize, persist.

        Both the OS query and the SQLite write run in worker threads so the
        API event loop is never blocked.
        """
        polled_at = datetime.now(timezone.utc)
        self._polls_attempted += 1
        self._detect_gap(polled_at)
        self._last_poll_at = polled_at

        if not self.platform_supported:
            msg = (
                f"Windows connection-table collection is unavailable on "
                f"platform '{sys.platform}'. This host has no Windows "
                "connection table; supply an alternative query function or "
                "ingest from a network sensor instead."
            )
            return self._record_failed_poll(polled_at, msg, state="unsupported")

        try:
            records = await asyncio.to_thread(
                self._query_fn,
                DEFAULT_TCP_STATES,
            )
        except WindowsTelemetryUnavailable as exc:
            return self._record_failed_poll(polled_at, str(exc))
        except Exception as exc:  # noqa: BLE001
            return self._record_failed_poll(
                polled_at, f"{type(exc).__name__}: {exc}"
            )

        events, summary = self.adapter.normalize_batch(
            records,
            data_category=DataCategory.LIVE_TELEMETRY,
            poll_time=polled_at,
        )

        duplicates = summary.rejection_reasons.pop("_duplicates_suppressed", 0)
        filtered = summary.rejection_reasons.pop("_filtered_by_policy", 0)

        persisted = 0
        latest_observed: Optional[datetime] = None
        if events:
            try:
                # The in-memory cache forgets on every restart, but storage
                # does not. A connection still open across a restart is a
                # repeat observation - the first one stays canonical - and
                # must not be re-inserted: without an OS creation time
                # (Linux /proc) its observed_at is the poll time, so the
                # re-insert differs and was an identity conflict that failed
                # the whole poll (ADR-077). It still counts as accepted
                # (parsed and valid) but not persisted, as before.
                known = await asyncio.to_thread(
                    self.db.existing_event_ids, [e.event_id for e in events]
                )
                events = [e for e in events if e.event_id not in known]
                if events:
                    persisted = await asyncio.to_thread(self._persist, events, summary)
            except Exception as exc:  # noqa: BLE001
                # Nothing from this batch was stored, so none of it may be
                # suppressed as a repeat on the next poll.
                self.adapter.forget_last_batch()
                return self._record_failed_poll(
                    polled_at, f"persistence_failed: {type(exc).__name__}: {exc}"
                )
        if events:
            latest_observed = max(e.observed_at for e in events)
            if (
                self._latest_event_observed_at is None
                or latest_observed > self._latest_event_observed_at
            ):
                self._latest_event_observed_at = latest_observed

        self.adapter.prune_fingerprint_cache()

        # Capture DNS evidence for this moment. Enrichment is strictly
        # supplementary: a failure here must never fail the poll or discard
        # connection telemetry that was collected successfully.
        if self.refresh_dns:
            try:
                await asyncio.to_thread(self._refresh_dns_evidence)
            except Exception as exc:  # noqa: BLE001
                self.dns_refresh_failures += 1
                logger.warning("DNS evidence refresh failed (collection unaffected): %s", exc)

        # Successful poll bookkeeping
        self._polls_succeeded += 1
        self._consecutive_failures = 0
        self._last_success_at = polled_at
        self._last_error = None
        if self._state != "stopped":
            self._state = "running"

        self._records_observed += summary.total_records
        self._events_accepted += summary.accepted_records
        self._events_persisted += persisted
        self._records_rejected += summary.rejected_records
        for reason, count in summary.rejection_reasons.items():
            self._rejection_reasons[reason] = self._rejection_reasons.get(reason, 0) + count

        logger.info(
            "Collector poll: observed=%d accepted=%d persisted=%d duplicates=%d "
            "filtered=%d rejected=%d",
            summary.total_records,
            summary.accepted_records,
            persisted,
            duplicates,
            filtered,
            summary.rejected_records,
        )

        return PollResult(
            polled_at=polled_at,
            succeeded=True,
            records_observed=summary.total_records,
            events_accepted=summary.accepted_records,
            events_persisted=persisted,
            duplicates_suppressed=duplicates,
            records_filtered_by_policy=filtered,
            records_rejected=summary.rejected_records,
            rejection_reasons=dict(summary.rejection_reasons),
            latest_event_observed_at=latest_observed,
        )

    def _refresh_dns_evidence(self) -> None:
        """Snapshot local DNS observations. Runs in a worker thread."""
        from app.services.enrichment import get_enrichment_service

        get_enrichment_service(self.db).refresh_from_dns_cache()

    def _persist(self, events: list, summary: ImportSummary) -> int:
        """Persist events and update source health. Runs in a worker thread."""
        # The source row must exist before inserting: normalized_events has a
        # foreign key to telemetry_sources, and a single poll issued without a
        # prior start() would otherwise fail the constraint.
        self._ensure_source_registered()
        inserted = self.db.insert_events(events)
        latest = max(e.observed_at for e in events)
        # Derive the authoritative count from storage rather than incrementing
        # by batch length, so the figure cannot drift or double-count.
        self.db.refresh_source_activity(
            self.source_id,
            last_event_at=latest,
            status="active",
        )
        self.db.save_import_summary(summary)
        return inserted

    # ──────────────── bookkeeping helpers ────────────────

    def _record_failed_poll(
        self,
        polled_at: datetime,
        error: str,
        state: str = "error",
    ) -> PollResult:
        self._polls_failed += 1
        self._consecutive_failures += 1
        self._last_error = error
        if state == "unsupported":
            self._state = "unsupported"
        logger.error("Collector poll failed: %s", error)
        try:
            self._mark_source_status("error")
        except Exception:  # noqa: BLE001
            logger.debug("Could not update source status after failure", exc_info=True)
        return PollResult(polled_at=polled_at, succeeded=False, error=error)

    def _detect_gap(self, now: datetime) -> None:
        """Record a collection gap when polls stop landing on schedule."""
        if self._last_success_at is None:
            return
        elapsed = (now - self._last_success_at).total_seconds()
        if elapsed > self.interval_seconds * 2.5:
            self._gaps.append(
                CollectionGap(
                    gap_start=self._last_success_at,
                    gap_end=now,
                    gap_seconds=round(elapsed, 2),
                    reason=self._last_error or "no successful collection within expected interval",
                )
            )
            # Keep only the most recent gaps.
            self._gaps = self._gaps[-50:]

    def _ensure_source_registered(self) -> None:
        """Register the live source, preserving existing counters."""
        existing = self.db.get_source(self.source_id)
        if existing is None:
            host = platform.node() or "this machine"
            if self._reads_linux_proc:
                name = f"Linux Local Host ({host})"
                description = (
                    "Live TCP connection metadata read from the local Linux "
                    "connection table (/proc/net/tcp, /proc/net/tcp6). Connection "
                    "metadata only — no packet or byte accounting."
                )
            else:
                name = f"Windows Local Host ({host})"
                description = (
                    "Live TCP connection metadata polled from the local Windows "
                    "connection table (Get-NetTCPConnection). Connection metadata "
                    "only — no packet or byte accounting."
                )
            self.db.upsert_source(
                TelemetrySource(
                    source_id=self.source_id,
                    name=name,
                    source_type=WINDOWS_SOURCE_TYPE,
                    description=description,
                    status="active",
                )
            )
        else:
            self.db.refresh_source_activity(self.source_id, status="active")

    def _mark_source_status(self, status: str) -> None:
        self.db.refresh_source_activity(self.source_id, status=status)

    # ──────────────── status ────────────────

    def status(self) -> CollectorStatus:
        state = self._state
        if state == "running" and not self.is_running:
            # Loop exited without an explicit stop.
            state = "error" if self._last_error else "stopped"
        if not self.platform_supported and state == "stopped":
            state = "unsupported"

        return CollectorStatus(
            state=state,
            platform_supported=self.platform_supported,
            platform_name=f"{platform.system()} {platform.release()}".strip(),
            source_id=self.source_id,
            interval_seconds=self.interval_seconds,
            include_loopback=self.include_loopback,
            collected_tcp_states=list(DEFAULT_TCP_STATES),
            started_at=self._started_at,
            stopped_at=self._stopped_at,
            last_poll_at=self._last_poll_at,
            last_success_at=self._last_success_at,
            latest_event_observed_at=self._latest_event_observed_at,
            polls_attempted=self._polls_attempted,
            polls_succeeded=self._polls_succeeded,
            polls_failed=self._polls_failed,
            consecutive_failures=self._consecutive_failures,
            records_observed_total=self._records_observed,
            events_accepted_total=self._events_accepted,
            events_persisted_total=self._events_persisted,
            duplicates_suppressed_total=self.adapter.duplicates_suppressed,
            records_filtered_by_policy_total=self.adapter.filtered_by_policy,
            records_rejected_total=self._records_rejected,
            rejection_reasons=dict(self._rejection_reasons),
            last_error=self._last_error,
            collection_gaps=list(self._gaps),
            capability_notes=list(
                LINUX_CAPABILITY_NOTES if self._reads_linux_proc else CAPABILITY_NOTES
            ),
        )


# ──────────────── singleton accessor ────────────────

_collector: Optional[WindowsTelemetryCollectorService] = None


def get_collector(db: Database) -> WindowsTelemetryCollectorService:
    """Get (or lazily create) the process-wide collector service."""
    global _collector
    if _collector is None:
        _collector = WindowsTelemetryCollectorService(db=db)
    return _collector


def reset_collector(
    db: Optional[Database] = None,
    **kwargs: Any,
) -> Optional[WindowsTelemetryCollectorService]:
    """Replace the collector singleton (used by tests and shutdown)."""
    global _collector
    _collector = (
        WindowsTelemetryCollectorService(db=db, **kwargs) if db is not None else None
    )
    return _collector
