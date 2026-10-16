"""
PraHari — Clock Integrity Diagnostic

**PraHari cannot measure clock skew, and this module does not claim to.**

Measuring skew requires comparing a source's clock against a trusted
reference at a known instant. PraHari has no such reference. What it has,
verified against the schema rather than assumed:

* ``NormalizedEvent.observed_at`` — event time, as stated by the source.
* ``NormalizedEvent.ingested_at`` — set by a ``default_factory`` at object
  construction, i.e. when the backend normalized the record. It is close to
  receipt time but is **not** a transport timestamp.
* No monotonic clock, no sequence numbers, no round-trip measurement.
  (``grep`` for ``monotonic``/``perf_counter``/``seq`` over ``app/`` returns
  nothing.)

So the only quantity available is

    ingest_lag = ingested_at - observed_at

which is the sum of **clock offset + collection latency + transport +
queueing + processing**, with no way to separate the terms. Reporting it as
"skew" would be inventing an attribution the data cannot support.

The one rigorous inference
--------------------------
Latency cannot be negative. An event cannot be normalized before it
happened. So if the lag is negative by δ, the source's clock must be ahead
of this host's by **at least** δ:

    clock_ahead_by >= -min(ingest_lag)        when min(ingest_lag) < 0

That is a *lower bound*, not an estimate, and it is the only skew claim
this module makes. A positive lag tells us nothing about skew at all,
because an arbitrarily large part of it may be latency.

Nothing here mutates a timestamp. Diagnosing a clock is not a licence to
rewrite what a source reported.
"""

from __future__ import annotations

import logging
import statistics
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Iterable, Optional

from pydantic import BaseModel, Field

from app.schemas.events import NormalizedEvent, QualityFlag, is_plausible_timestamp

logger = logging.getLogger(__name__)

# Below this many usable samples the percentiles describe the sample, not
# the source, and no verdict is offered.
MIN_SAMPLES_FOR_VERDICT = 30

# A negative lag beyond this is treated as evidence rather than noise.
# Chosen to sit above plausible sub-second scheduling and rounding effects
# without masking a real clock difference, and reported alongside every
# result so a reader can apply their own threshold.
NEGATIVE_LAG_EVIDENCE_SECONDS = 2.0


class ClockVerdict(str, Enum):
    """What the available evidence supports — and nothing beyond it."""

    INSUFFICIENT_EVIDENCE = "insufficient_evidence"
    NO_ANOMALY_DETECTED = "no_anomaly_detected"
    SOURCE_CLOCK_AHEAD = "source_clock_ahead"
    ORDERING_ANOMALY = "ordering_anomaly"
    UNUSABLE_TIMESTAMPS = "unusable_timestamps"


class LagReference(str, Enum):
    """Which server-side timestamp the lag was measured against."""

    # Captured at the API boundary when a remote source submitted the event.
    # The only reference that genuinely bounds "time of arrival".
    RECEIVED_AT = "received_at"
    # Set when the backend constructed the object. For a bulk import that is
    # normalization time, which can be long after the data arrived and bears
    # no relation to the original arrival at all.
    INGESTED_AT = "ingested_at"
    MIXED = "mixed"
    NONE = "none"


class ClockIntegrityReport(BaseModel):
    """
    Ingest-lag statistics for one source, with their limits attached.

    Every field is a measurement or a count. The only inferred value is
    ``clock_ahead_lower_bound_seconds``, which is a bound rather than an
    estimate, and is populated only when a negative lag was observed.
    """

    source_id: str
    verdict: ClockVerdict

    # Evidence
    events_examined: int = 0
    usable_samples: int = 0
    events_with_implausible_timestamps: int = 0
    events_with_timestamp_uncertainty_flag: int = 0
    interval_start: Optional[datetime] = None
    interval_end: Optional[datetime] = None
    interval_seconds: Optional[float] = None

    # Ingest lag = ingested_at - observed_at, in seconds.
    # NOT clock skew: it also contains collection, transport and queueing
    # delay, which this system does not measure separately.
    # Which reference the lag was measured against, and how many samples
    # had a measured receipt. A conclusion drawn against ingested_at is
    # weaker than one drawn against received_at, and the difference must be
    # visible rather than buried.
    lag_reference: LagReference = LagReference.NONE
    samples_with_received_at: int = 0
    samples_without_received_at: int = 0

    lag_min_seconds: Optional[float] = None
    lag_p05_seconds: Optional[float] = None
    lag_median_seconds: Optional[float] = None
    lag_p95_seconds: Optional[float] = None
    lag_max_seconds: Optional[float] = None

    negative_lag_count: int = 0
    negative_lag_beyond_threshold: int = 0
    negative_lag_threshold_seconds: float = NEGATIVE_LAG_EVIDENCE_SECONDS

    # The one sound inference: latency >= 0, so a negative lag of δ means
    # the source clock leads this host's by at least δ.
    clock_ahead_lower_bound_seconds: Optional[float] = None

    # Ordering
    out_of_order_events: int = 0
    largest_backward_step_seconds: Optional[float] = None

    limitations: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)

    @property
    def has_clock_evidence(self) -> bool:
        return self.clock_ahead_lower_bound_seconds is not None


def _percentile(values: list[float], fraction: float) -> float:
    """Nearest-rank percentile. No interpolation, no numpy dependency."""
    if not values:
        raise ValueError("no values")
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, int(round(fraction * (len(ordered) - 1)))))
    return ordered[index]


def analyze_clock_integrity(
    events: Iterable[NormalizedEvent],
    source_id: str = "<unspecified>",
    now: Optional[datetime] = None,
) -> ClockIntegrityReport:
    """
    Examine one source's timestamps and report what they support.

    Pure: reads events, mutates nothing, touches no database. Events whose
    ``observed_at`` cannot describe a real observation are excluded from the
    statistics and counted, because one FILETIME-epoch record would
    otherwise dominate every percentile.
    """
    events = list(events)
    report = ClockIntegrityReport(
        source_id=source_id, verdict=ClockVerdict.INSUFFICIENT_EVIDENCE
    )
    report.events_examined = len(events)

    report.limitations = [
        "ingest_lag = ingested_at - observed_at. It contains clock offset AND "
        "collection, transport, queueing and processing delay. PraHari does not "
        "measure those separately, so a positive lag supports NO skew claim.",
        "ingested_at is set when the backend constructs the event, not when a "
        "submission was received over the network.",
        "No monotonic clock, sequence number or round-trip measurement exists, "
        "so there is no trusted reference against which to measure skew.",
        "For a source collected in this process, both timestamps come from the "
        "same clock, so the lag is latency only and reveals nothing about skew.",
    ]

    if not events:
        report.notes.append("No events supplied.")
        return report

    now = now or datetime.now(timezone.utc)

    usable: list[NormalizedEvent] = []
    for event in events:
        if QualityFlag.TIMESTAMP_UNCERTAINTY in event.quality_flags:
            report.events_with_timestamp_uncertainty_flag += 1
        if not is_plausible_timestamp(event.observed_at, now):
            report.events_with_implausible_timestamps += 1
            continue
        usable.append(event)

    if report.events_with_timestamp_uncertainty_flag:
        report.limitations.append(
            f"{report.events_with_timestamp_uncertainty_flag} event(s) carry a "
            "timestamp-uncertainty flag: their timezone was assumed rather than "
            "stated by the source. Lag computed from them is correspondingly "
            "uncertain, potentially by whole hours."
        )

    if not usable:
        report.verdict = ClockVerdict.UNUSABLE_TIMESTAMPS
        report.notes.append(
            "Every event carries an implausible timestamp; no lag can be computed."
        )
        return report

    ordered = sorted(usable, key=lambda e: e.observed_at)
    report.usable_samples = len(usable)
    report.interval_start = ordered[0].observed_at
    report.interval_end = ordered[-1].observed_at
    report.interval_seconds = round(
        (report.interval_end - report.interval_start).total_seconds(), 3
    )

    # Prefer the measured receipt. `ingested_at` is construction time: for a
    # bulk import it is when the row was normalized, which says nothing about
    # when the data arrived, so a lower bound derived from it would rest on
    # an assumption that does not hold. Where both exist per source, the
    # mix is reported rather than silently averaged.
    lags: list[float] = []
    for event in usable:
        reference = getattr(event, "received_at", None)
        if reference is not None:
            report.samples_with_received_at += 1
            lags.append((reference - event.observed_at).total_seconds())
        elif event.ingested_at is not None:
            report.samples_without_received_at += 1
            lags.append((event.ingested_at - event.observed_at).total_seconds())

    if report.samples_with_received_at and report.samples_without_received_at:
        report.lag_reference = LagReference.MIXED
    elif report.samples_with_received_at:
        report.lag_reference = LagReference.RECEIVED_AT
    elif report.samples_without_received_at:
        report.lag_reference = LagReference.INGESTED_AT

    if report.lag_reference in (LagReference.INGESTED_AT, LagReference.MIXED):
        report.limitations.append(
            f"{report.samples_without_received_at} sample(s) have no measured "
            "receipt time, so their lag is computed against ingested_at — "
            "object construction, not arrival. For an imported corpus that is "
            "normalization time and bears no relation to the original arrival. "
            "A lower bound from those samples is NOT asserted."
        )

    # Ordering is assessed in ARRIVAL order — approximated by ingested_at,
    # the only arrival evidence stored. It must NOT be assessed in the order
    # the caller happened to supply: `Database.list_events` returns
    # `ORDER BY observed_at DESC`, so iterating the input directly reported
    # every well-behaved source as a continuous backward march. (Caught by
    # driving the endpoint against a temporary database, not by a unit test.)
    #
    # Only strictly increasing ingest times are compared. A bulk insert
    # shares an ingested_at, and within such a tie there is no arrival
    # order to violate.
    by_arrival = sorted(usable, key=lambda e: (e.ingested_at, e.observed_at))
    largest_backward = 0.0
    previous_arrival: Optional[datetime] = None
    previous_observed: Optional[datetime] = None
    for event in by_arrival:
        if (
            previous_arrival is not None
            and event.ingested_at > previous_arrival
            and event.observed_at < previous_observed
        ):
            report.out_of_order_events += 1
            step = (previous_observed - event.observed_at).total_seconds()
            largest_backward = max(largest_backward, step)
        if previous_arrival is None or event.ingested_at > previous_arrival:
            previous_arrival = event.ingested_at
            previous_observed = event.observed_at
    if report.out_of_order_events:
        report.largest_backward_step_seconds = round(largest_backward, 3)

    if lags:
        report.lag_min_seconds = round(min(lags), 3)
        report.lag_max_seconds = round(max(lags), 3)
        report.lag_median_seconds = round(statistics.median(lags), 3)
        report.lag_p05_seconds = round(_percentile(lags, 0.05), 3)
        report.lag_p95_seconds = round(_percentile(lags, 0.95), 3)
        report.negative_lag_count = sum(1 for v in lags if v < 0)
        report.negative_lag_beyond_threshold = sum(
            1 for v in lags if v < -NEGATIVE_LAG_EVIDENCE_SECONDS
        )

        if (
            report.lag_min_seconds < 0
            and report.lag_reference is LagReference.RECEIVED_AT
        ):
            # The bound rests on one assumption: an event cannot be RECEIVED
            # before it happened, so transit time >= 0. That holds for a
            # measured receipt at the API boundary. It does NOT hold for
            # ingested_at, where a historical import is routinely constructed
            # long after — or, for a backdated corpus, "before" — the events
            # it describes. The bound is therefore asserted only against a
            # measured receipt.
            report.clock_ahead_lower_bound_seconds = round(-report.lag_min_seconds, 3)
        elif report.lag_min_seconds is not None and report.lag_min_seconds < 0:
            report.notes.append(
                "A negative lag was observed, but against ingested_at rather "
                "than a measured receipt. No clock bound is claimed: "
                "construction time can legitimately precede an imported "
                "event's stated time."
            )

    # ── Verdict ──
    if len(usable) < MIN_SAMPLES_FOR_VERDICT:
        report.verdict = ClockVerdict.INSUFFICIENT_EVIDENCE
        report.notes.append(
            f"{len(usable)} usable sample(s); at least {MIN_SAMPLES_FOR_VERDICT} "
            "are needed before the statistics describe the source rather than "
            "the sample."
        )
        return report

    if (
        report.negative_lag_beyond_threshold > 0
        and report.lag_reference is LagReference.RECEIVED_AT
    ):
        report.verdict = ClockVerdict.SOURCE_CLOCK_AHEAD
        report.notes.append(
            f"{report.negative_lag_beyond_threshold} event(s) were ingested "
            f"before their stated observation time by more than "
            f"{NEGATIVE_LAG_EVIDENCE_SECONDS}s. Delay cannot be negative, so "
            f"this source's clock leads this host's by at least "
            f"{report.clock_ahead_lower_bound_seconds}s. The true offset may be "
            "larger; it cannot be smaller."
        )
    elif report.out_of_order_events > 0:
        report.verdict = ClockVerdict.ORDERING_ANOMALY
        report.notes.append(
            f"{report.out_of_order_events} event(s) arrived with an observation "
            f"time earlier than their predecessor (largest backward step "
            f"{report.largest_backward_step_seconds}s). Possible causes include "
            "a clock adjustment at the source, out-of-order delivery, or a "
            "batch of older records. This diagnostic cannot distinguish them."
        )
    else:
        report.verdict = ClockVerdict.NO_ANOMALY_DETECTED
        report.notes.append(
            "No negative lag and no backward ordering step. This does NOT "
            "establish that the source's clock is correct — a consistently "
            "offset clock produces a consistently offset lag, which is "
            "indistinguishable from latency here."
        )

    return report


def analyze_per_source(
    events: Iterable[NormalizedEvent], now: Optional[datetime] = None
) -> dict[str, ClockIntegrityReport]:
    """Group by ``source_id`` and analyze each independently."""
    grouped: dict[str, list[NormalizedEvent]] = {}
    for event in events:
        grouped.setdefault(event.source_id, []).append(event)
    return {
        source_id: analyze_clock_integrity(group, source_id=source_id, now=now)
        for source_id, group in sorted(grouped.items())
    }
