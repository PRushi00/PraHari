"""
PraHari — Per-Source Health and Staleness

What the stored evidence supports about whether a source is still
reporting — and, just as importantly, what it does not.

The central limitation, verified in `database.refresh_source_activity`:
``TelemetrySource.last_event_at`` is the maximum **observed_at** of the
source's events. That is **event time, stated by the source**, not the time
PraHari last heard from it. Two consequences follow and are reported
rather than glossed:

* A source whose clock runs fast looks **fresher** than it is. It can
  appear healthy while silent.
* A source whose clock runs slow looks **staler** than it is, and can be
  reported silent while reporting normally.

So freshness and clock integrity are the same question here, and this
module links to the clock diagnostic rather than pretending otherwise.

**Silence is not disconnection.** PraHari has no heartbeat: a source with
nothing to report is indistinguishable from one that has died. The states
below say "we have not heard from it", never "it is down".
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Iterable, Optional

from pydantic import BaseModel, Field

from app.schemas.events import TelemetrySource, is_plausible_timestamp

logger = logging.getLogger(__name__)

# Defaults, overridable per call. Deliberately generous: calling a source
# silent is an operational claim, and a wrong one wastes an operator's time.
DEFAULT_FRESH_SECONDS = 300.0      # 5 minutes
DEFAULT_STALE_SECONDS = 3600.0     # 1 hour


class HealthState(str, Enum):
    """
    Every state is a statement about PraHari's evidence, not about the
    remote machine. None of them asserts that a host is up or down.
    """

    REPORTING = "reporting"          # an event within the fresh window
    STALE = "stale"                  # nothing recent, but within the stale window
    SILENT = "silent"                # nothing beyond the stale window
    NEVER_SEEN = "never_seen"        # registered, no event ever recorded
    DISABLED = "disabled"            # explicitly turned off by an operator
    ERROR = "error"                  # the source recorded a failure state
    UNKNOWN = "unknown"              # evidence insufficient or untrustworthy


# Statuses that `refresh_source_activity` and the collector may write.
_ERROR_STATUSES = {"error", "degraded", "failed"}
_DISCONNECTED_STATUSES = {"disconnected", "stopped"}


class SourceHealth(BaseModel):
    """One source's health, with the basis for the verdict attached."""

    source_id: str
    name: str
    source_type: str
    state: HealthState
    enabled: bool = True
    recorded_status: Optional[str] = None

    event_count: int = 0
    last_event_at: Optional[datetime] = None
    seconds_since_last_event: Optional[float] = None

    fresh_threshold_seconds: float = DEFAULT_FRESH_SECONDS
    stale_threshold_seconds: float = DEFAULT_STALE_SECONDS
    evaluated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    # ── Server-measured receipt (Phase 2) ──
    # When a remote source submitted over the API, the backend stamped the
    # arrival itself. That is independent of the source's clock, so it
    # supports a freshness claim that event time cannot.
    #
    # It establishes "this backend received data at time T" — and nothing
    # more. It does NOT establish that the endpoint is currently connected,
    # running, or healthy; only that it was heard from then.
    last_received_at: Optional[datetime] = None
    seconds_since_last_receipt: Optional[float] = None
    receipt_evidence_available: bool = False

    # The basis, stated so a reader is not left to assume it.
    freshness_basis: str = (
        "max(observed_at) reported by the source — event time, not receipt time"
    )
    clock_dependent: bool = True
    reasons: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)

    @property
    def is_reporting(self) -> bool:
        return self.state is HealthState.REPORTING


class SourceHealthSummary(BaseModel):
    """Fleet view. Counts are of PraHari's evidence, not of live hosts."""

    evaluated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    sources: list[SourceHealth] = Field(default_factory=list)
    counts_by_state: dict[str, int] = Field(default_factory=dict)
    fresh_threshold_seconds: float = DEFAULT_FRESH_SECONDS
    stale_threshold_seconds: float = DEFAULT_STALE_SECONDS
    notes: list[str] = Field(
        default_factory=lambda: [
            "Freshness is derived from event time reported by each source. A source with a fast clock appears fresher than it is; one with a slow clock appears staler.",
            "PraHari has no heartbeat. Silence means 'no events recorded', never 'the host is down'.",
            "A source that legitimately has nothing to report is indistinguishable from one that has stopped.",
        ]
    )


def evaluate_source_health(
    source: TelemetrySource,
    now: Optional[datetime] = None,
    fresh_seconds: float = DEFAULT_FRESH_SECONDS,
    stale_seconds: float = DEFAULT_STALE_SECONDS,
    last_received_at: Optional[datetime] = None,
) -> SourceHealth:
    """
    Classify one source. Pure: reads the record, changes nothing.

    Order of precedence is deliberate. An operator disabling a source is a
    stronger statement than any timing evidence, and a recorded error is
    stronger than apparent freshness — a source can be failing while its
    last successful event is still recent.
    """
    now = now or datetime.now(timezone.utc)
    if fresh_seconds > stale_seconds:
        raise ValueError(
            f"fresh_seconds ({fresh_seconds}) must not exceed "
            f"stale_seconds ({stale_seconds})"
        )

    health = SourceHealth(
        source_id=source.source_id,
        name=source.name,
        source_type=source.source_type,
        state=HealthState.UNKNOWN,
        enabled=source.enabled,
        recorded_status=source.status,
        event_count=source.event_count,
        last_event_at=source.last_event_at,
        fresh_threshold_seconds=fresh_seconds,
        stale_threshold_seconds=stale_seconds,
        evaluated_at=now,
    )
    health.limitations = [
        "No heartbeat exists: a silent source may be healthy with nothing to report.",
    ]

    # Receipt evidence, when the backend measured an arrival itself.
    if last_received_at is not None and is_plausible_timestamp(last_received_at, now):
        health.last_received_at = last_received_at
        health.receipt_evidence_available = True
        health.seconds_since_last_receipt = round(
            (now - last_received_at).total_seconds(), 3
        )
        health.freshness_basis = (
            "max(received_at) measured by this backend at the API boundary — "
            "independent of the source's clock"
        )
        health.clock_dependent = False
        health.limitations.append(
            "A measured receipt establishes that this backend received data at "
            "that time. It does NOT establish that the endpoint is currently "
            "connected, running or healthy."
        )
    else:
        health.limitations.append(
            "No measured receipt for this source, so freshness falls back to "
            "event time reported by the source and is only as trustworthy as "
            "that source's clock. See GET /sources/clock-integrity."
        )

    if not source.enabled:
        health.state = HealthState.DISABLED
        health.reasons.append("The source is disabled; no telemetry is expected.")
        return health

    status = (source.status or "").strip().lower()
    if status in _ERROR_STATUSES:
        health.state = HealthState.ERROR
        health.reasons.append(
            f"The source recorded status {source.status!r}. A recent event does "
            "not clear this: a source can fail after its last success."
        )
        return health

    if source.last_event_at is None:
        health.state = HealthState.NEVER_SEEN
        health.reasons.append(
            "Registered, but no event has ever been recorded. This is not the "
            "same as silent — nothing has been heard at any point."
        )
        if source.event_count:
            health.reasons.append(
                f"event_count is {source.event_count} while last_event_at is "
                "unset, which is inconsistent; the counters may be stale."
            )
            health.state = HealthState.UNKNOWN
        return health

    if not is_plausible_timestamp(source.last_event_at, now):
        health.state = HealthState.UNKNOWN
        health.reasons.append(
            f"last_event_at ({source.last_event_at.isoformat()}) cannot describe "
            "a real observation, so freshness cannot be derived from it."
        )
        return health

    health.seconds_since_last_event = round(
        (now - source.last_event_at).total_seconds(), 3
    )

    # Decide on the measured receipt where one exists: it is independent of
    # the source's clock, so a skewed clock can no longer make a silent
    # source look fresh.
    age = (
        health.seconds_since_last_receipt
        if health.receipt_evidence_available
        else health.seconds_since_last_event
    )

    if age < 0:
        # The source's newest event is in this host's future. Delay cannot be
        # negative, so this is clock evidence, not freshness evidence.
        health.state = HealthState.UNKNOWN
        health.reasons.append(
            f"The newest event is {abs(round(age, 1))}s in the future relative to "
            "this host. The source's clock leads ours by at least that much, so "
            "no freshness judgement is made."
        )
        return health

    if status in _DISCONNECTED_STATUSES:
        health.state = HealthState.SILENT
        health.reasons.append(
            f"The source recorded status {source.status!r} and its last event "
            f"was {round(age)}s ago."
        )
        return health

    if age <= fresh_seconds:
        health.state = HealthState.REPORTING
        health.reasons.append(
            f"An event {round(age)}s ago, within the {round(fresh_seconds)}s "
            "freshness window."
        )
    elif age <= stale_seconds:
        health.state = HealthState.STALE
        health.reasons.append(
            f"No event for {round(age)}s, beyond the {round(fresh_seconds)}s "
            f"freshness window but within {round(stale_seconds)}s."
        )
    else:
        health.state = HealthState.SILENT
        health.reasons.append(
            f"No event for {round(age)}s, beyond the {round(stale_seconds)}s "
            "staleness window. PraHari has not heard from it; whether it is "
            "running is unknown."
        )

    return health


def summarize_source_health(
    sources: Iterable[TelemetrySource],
    now: Optional[datetime] = None,
    fresh_seconds: float = DEFAULT_FRESH_SECONDS,
    stale_seconds: float = DEFAULT_STALE_SECONDS,
    last_received_by_source: Optional[dict[str, datetime]] = None,
) -> SourceHealthSummary:
    """
    Evaluate every source and count the states.

    ``last_received_by_source`` supplies the server-measured arrival per
    source where one exists. Sources without one are evaluated on event
    time, and say so.
    """
    now = now or datetime.now(timezone.utc)
    receipts = last_received_by_source or {}
    evaluated = [
        evaluate_source_health(
            s, now=now, fresh_seconds=fresh_seconds, stale_seconds=stale_seconds,
            last_received_at=receipts.get(s.source_id),
        )
        for s in sources
    ]
    counts: dict[str, int] = {}
    for health in evaluated:
        counts[health.state.value] = counts.get(health.state.value, 0) + 1

    return SourceHealthSummary(
        evaluated_at=now,
        sources=sorted(evaluated, key=lambda h: h.source_id),
        counts_by_state=counts,
        fresh_threshold_seconds=fresh_seconds,
        stale_threshold_seconds=stale_seconds,
    )
