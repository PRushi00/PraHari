"""
Continuous DNS event-log collection (ADR-127).

The Windows DNS-Client Operational channel records a resolution as it
happens, but PraHari only read it when an operator pressed a button. DNS
evidence is only useful while it is fresh — the channel is circular, so
what is not read in time is overwritten — and a manual snapshot of "the
newest 500" both re-reads what it already has and misses anything that
scrolled past between presses.

This service polls the channel on an interval and advances a durable
bookmark, so each record is read once and none is skipped.

**Where this runs matters.** The channel is readable only by a process on
that Windows host, through PowerShell. This service therefore collects
only where PraHari itself runs on the Windows machine being observed. On
any other platform it reports `unsupported` and starts nothing; it does
not pretend a remote backend can read another machine's event log. A
central deployment collecting from several Windows hosts needs an agent
on each — the sensor path that already exists — not this loop.

What it will not do:

* **Never enable, disable or reconfigure the channel.** Turning it on
  requires Administrator and is the operator's decision (ADR-121). If it
  is off, this service says so and stops.
* **Never advance the bookmark past unprocessed records.** Rows are
  stored first; the bookmark moves only over what storage accepted.
* **Never run two collections at once.** A poll that overruns its
  interval is skipped, not queued.
"""

from __future__ import annotations

import asyncio
import logging
import platform
from datetime import datetime, timezone
from typing import Any, Optional

from pydantic import BaseModel, Field

from app.services.enrichment import get_enrichment_service
from app.storage.contract import TelemetryStore

logger = logging.getLogger(__name__)

#: Bounds on the poll interval. The floor exists because each poll spawns
#: a PowerShell process: below a second or two the host spends more time
#: starting interpreters than reading events.
MIN_INTERVAL_SECONDS = 2.0
MAX_INTERVAL_SECONDS = 3600.0
DEFAULT_INTERVAL_SECONDS = 8.0

#: Records read per poll. The channel is circular and bursty, so this is
#: a batch size rather than a budget: when a batch fills, the loop polls
#: again immediately instead of waiting out the interval.
DEFAULT_BATCH = 500

#: Consecutive failures after which the loop stops rather than retrying
#: for ever. A disabled channel does not start reporting because it was
#: asked 900 times, and the log noise buries anything real.
MAX_CONSECUTIVE_FAILURES = 10


class DnsCollectorStatus(BaseModel):
    """What the service is doing, and on what evidence."""

    state: str = Field(
        description="running | stopped | unsupported | error",
    )
    platform_supported: bool
    platform_name: str
    interval_seconds: float
    batch_size: int

    started_at: Optional[str] = None
    stopped_at: Optional[str] = None
    last_poll_at: Optional[str] = None
    last_success_at: Optional[str] = None

    polls_attempted: int = 0
    polls_succeeded: int = 0
    polls_failed: int = 0
    consecutive_failures: int = 0

    records_read_total: int = 0
    observations_recorded_total: int = 0
    skipped_failed_query_total: int = 0

    #: The RecordId last safely processed. Survives restarts.
    bookmark: int = 0
    log_resets_seen: int = 0

    last_error: Optional[str] = None
    notes: list[str] = Field(default_factory=list)


class DnsEventCollectorService:
    """
    A managed background loop over the Windows DNS-Client channel.

    Lifecycle mirrors the connection collector: `start`, `stop`, and a
    `status` that reports measurements rather than intentions.
    """

    def __init__(
        self,
        db: TelemetryStore,
        source_id: str = "windows_dns_events",
        interval_seconds: float = DEFAULT_INTERVAL_SECONDS,
        batch_size: int = DEFAULT_BATCH,
    ) -> None:
        self.db = db
        self.source_id = source_id
        self.interval_seconds = self._clamp(interval_seconds)
        self.batch_size = max(1, min(int(batch_size), 5000))

        self._task: Optional[asyncio.Task] = None
        # One collection at a time. A poll that overruns its interval is
        # skipped rather than queued: two PowerShell readers racing on
        # the same bookmark would both advance it.
        self._lock = asyncio.Lock()
        self._stopping = False

        self.started_at: Optional[datetime] = None
        self.stopped_at: Optional[datetime] = None
        self.last_poll_at: Optional[datetime] = None
        self.last_success_at: Optional[datetime] = None

        self.polls_attempted = 0
        self.polls_succeeded = 0
        self.polls_failed = 0
        self.consecutive_failures = 0
        self.records_read_total = 0
        self.observations_recorded_total = 0
        self.skipped_failed_query_total = 0
        self.log_resets_seen = 0
        self.last_error: Optional[str] = None

    # ---------------- platform ----------------

    @staticmethod
    def _clamp(seconds: float) -> float:
        return max(MIN_INTERVAL_SECONDS, min(float(seconds), MAX_INTERVAL_SECONDS))

    @property
    def platform_supported(self) -> bool:
        """
        Only Windows has this channel.

        This is a statement about where the process runs, not about the
        operator's network: a Linux PraHari cannot read a Windows host's
        event log, and saying otherwise would be the fabrication this
        project exists to avoid.
        """
        return platform.system() == "Windows"

    @property
    def is_running(self) -> bool:
        return self._task is not None and not self._task.done()

    # ---------------- lifecycle ----------------

    async def start(
        self,
        interval_seconds: Optional[float] = None,
        batch_size: Optional[int] = None,
    ) -> DnsCollectorStatus:
        """Begin polling. Idempotent: starting a running loop is a no-op."""
        if interval_seconds is not None:
            self.interval_seconds = self._clamp(interval_seconds)
        if batch_size is not None:
            self.batch_size = max(1, min(int(batch_size), 5000))

        if not self.platform_supported:
            self.last_error = (
                f"The DNS-Client event channel is a Windows facility and this "
                f"backend runs on {platform.system()}. Nothing was started."
            )
            return self.status()

        if self.is_running:
            return self.status()

        self._stopping = False
        self.consecutive_failures = 0
        self.last_error = None
        self.started_at = datetime.now(timezone.utc)
        self.stopped_at = None
        self._task = asyncio.create_task(
            self._run_loop(), name="prahari-dns-event-collector"
        )
        logger.info(
            "DNS event collector started (every %.1fs, batches of %d)",
            self.interval_seconds,
            self.batch_size,
        )
        return self.status()

    async def stop(self, timeout: float = 30.0) -> DnsCollectorStatus:
        """
        Stop cleanly, cancelling the loop and waiting for it to unwind.

        Safe to call when not running, and safe to call twice.
        """
        self._stopping = True
        task = self._task
        self._task = None

        if task is not None and not task.done():
            task.cancel()
            try:
                await asyncio.wait_for(asyncio.shield(task), timeout=timeout)
            except (asyncio.CancelledError, asyncio.TimeoutError):
                pass
            except Exception as exc:  # noqa: BLE001
                logger.warning("DNS collector stopped with an error: %s", exc)

        self.stopped_at = datetime.now(timezone.utc)
        logger.info("DNS event collector stopped")
        return self.status()

    async def _run_loop(self) -> None:
        try:
            while not self._stopping:
                drained = await self.poll_once()

                if self.consecutive_failures >= MAX_CONSECUTIVE_FAILURES:
                    self.last_error = (
                        f"Stopped after {self.consecutive_failures} consecutive "
                        f"failures. Last reason: {self.last_error}"
                    )
                    logger.error("DNS event collector giving up: %s", self.last_error)
                    self._stopping = True
                    break

                # A full batch means unread events remain. Poll again at
                # once rather than draining a burst one interval at a
                # time — but yield first, so this cannot spin a core.
                if drained:
                    await asyncio.sleep(0)
                    continue

                await asyncio.sleep(self.interval_seconds)
        except asyncio.CancelledError:
            # Expected on stop(); unwind quietly.
            raise
        except Exception as exc:  # noqa: BLE001
            self.last_error = f"{type(exc).__name__}: {exc}"
            logger.exception("DNS event collector loop failed")

    # ---------------- one poll ----------------

    async def poll_once(self) -> bool:
        """
        Collect one batch. Returns True when more events are waiting.

        Never raises: a poll that fails records the reason and lets the
        loop decide, because one unreadable read is not a reason to tear
        down collection.
        """
        if self._lock.locked():
            # The previous poll is still running. Skipping is correct:
            # queueing would stack PowerShell processes behind a slow
            # read and race two writers onto one bookmark.
            logger.debug("DNS poll skipped: previous poll still running")
            return False

        async with self._lock:
            self.polls_attempted += 1
            self.last_poll_at = datetime.now(timezone.utc)
            try:
                result = await asyncio.to_thread(self._collect)
            except Exception as exc:  # noqa: BLE001
                self.polls_failed += 1
                self.consecutive_failures += 1
                self.last_error = f"{type(exc).__name__}: {exc}"
                logger.warning("DNS poll raised: %s", self.last_error)
                return False

            if not result.get("succeeded"):
                self.polls_failed += 1
                self.consecutive_failures += 1
                self.last_error = result.get("error") or "collection did not succeed"
                return False

            self.polls_succeeded += 1
            self.consecutive_failures = 0
            self.last_error = None
            self.last_success_at = datetime.now(timezone.utc)
            self.records_read_total += int(result.get("records_read") or 0)
            self.observations_recorded_total += int(
                result.get("observations_recorded") or 0
            )
            self.skipped_failed_query_total += int(
                result.get("skipped_failed_query") or 0
            )
            if result.get("log_was_reset"):
                self.log_resets_seen += 1
            return bool(result.get("more_available"))

    def _collect(self) -> dict[str, Any]:
        """Runs in a worker thread: PowerShell and SQLite both block."""
        return get_enrichment_service(self.db).collect_from_dns_event_log(
            max_events=self.batch_size,
            source_id=self.source_id,
            incremental=True,
        )

    # ---------------- reporting ----------------

    def status(self) -> DnsCollectorStatus:
        if not self.platform_supported:
            state = "unsupported"
        elif self.is_running:
            state = "running"
        elif self.last_error and self.consecutive_failures >= MAX_CONSECUTIVE_FAILURES:
            state = "error"
        else:
            state = "stopped"

        notes = [
            "Reads the Windows DNS-Client Operational channel. It enables no "
            "channel, clears no log and sends no DNS query.",
            "A resolution is evidence that a name was looked up. It is not "
            "evidence that a connection followed.",
        ]
        if not self.platform_supported:
            notes.append(
                f"This backend runs on {platform.system()}. The channel is a "
                "Windows facility and cannot be read from here; a Windows host "
                "needs PraHari (or a sensor agent) running on it."
            )

        try:
            bookmark = get_enrichment_service(self.db).read_bookmark()
        except Exception:  # noqa: BLE001
            bookmark = 0

        return DnsCollectorStatus(
            state=state,
            platform_supported=self.platform_supported,
            platform_name=f"{platform.system()} {platform.release()}".strip(),
            interval_seconds=self.interval_seconds,
            batch_size=self.batch_size,
            started_at=self.started_at.isoformat() if self.started_at else None,
            stopped_at=self.stopped_at.isoformat() if self.stopped_at else None,
            last_poll_at=self.last_poll_at.isoformat() if self.last_poll_at else None,
            last_success_at=(
                self.last_success_at.isoformat() if self.last_success_at else None
            ),
            polls_attempted=self.polls_attempted,
            polls_succeeded=self.polls_succeeded,
            polls_failed=self.polls_failed,
            consecutive_failures=self.consecutive_failures,
            records_read_total=self.records_read_total,
            observations_recorded_total=self.observations_recorded_total,
            skipped_failed_query_total=self.skipped_failed_query_total,
            bookmark=bookmark,
            log_resets_seen=self.log_resets_seen,
            last_error=self.last_error,
            notes=notes,
        )


_service: Optional[DnsEventCollectorService] = None


def get_dns_collector(db: TelemetryStore) -> DnsEventCollectorService:
    """The process-wide DNS collector, created on first use."""
    global _service
    if _service is None:
        _service = DnsEventCollectorService(db=db)
    return _service


def reset_dns_collector() -> None:
    """Drop the singleton. For tests, which must not share a loop."""
    global _service
    _service = None
