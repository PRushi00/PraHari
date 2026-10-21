"""
PraHari — Causal Feature Engineering Engine

Extracts retrospective window-based telemetry features without forward leakage.
Observation Window: [t - W, t]
Prediction Horizon: [t + lead_time, t + lead_time + H]
"""

from __future__ import annotations

import math
from bisect import bisect_left
from datetime import datetime, timedelta, timezone
from typing import Any, Optional
import numpy as np
from pydantic import BaseModel, Field

from app.schemas.events import DataCategory, NormalizedEvent


def _empty_dataset() -> tuple[np.ndarray, np.ndarray, list[datetime]]:
    """
    The canonical "no instances" return.

    Every no-data path must produce the SAME shape and dtype. Returning a
    one-dimensional ``(0,)`` from one path and ``(0, n_features)`` from
    another is not a cosmetic difference: a caller that reads
    ``X.shape[1]`` — as ``stack_lagged_windows`` does — raises IndexError
    on the first form and works on the second. That crash is currently
    unreachable only because the pipeline refuses fewer than four
    instances first, which is a guard, not a contract.
    """
    return (
        np.empty((0, len(FEATURE_NAMES)), dtype=np.float32),
        np.empty((0,), dtype=np.int32),
        [],
    )


class WindowCoverageIncomplete(RuntimeError):
    """
    The window cap prevented examining every eligible window.

    Raised only when a caller asked for complete coverage. The partial
    report travels with the exception so the caller can see how far the run
    got rather than only that it stopped.
    """

    def __init__(self, message: str, report: "WindowingReport"):
        self.report = report
        super().__init__(message)


class WindowingReport(BaseModel):
    """
    Factual record of how windowing actually ran.

    The nominal configuration (W=60s, L=30s, H=60s, S=15s) cannot always be
    applied to a short dataset. When it is adjusted, that adjustment is
    reported here rather than left implicit, so no downstream claim can cite
    the nominal parameters for an evaluation that did not use them.
    """
    # Which feature schema the events supported, and the names it emits.
    # Carried here so a result is never compared across feature sets
    # without that being visible (ADR-096).
    feature_schema: str = "prahari.window_features.full.v1"
    feature_names: list[str] = Field(default_factory=lambda: list(FEATURE_NAMES))

    nominal_window_seconds: float
    nominal_lead_seconds: float
    nominal_horizon_seconds: float
    nominal_stride_seconds: float

    effective_window_seconds: float
    effective_lead_seconds: float
    effective_horizon_seconds: float
    effective_stride_seconds: float

    # Negative-label validity accounting (blueprint section 7).
    windows_excluded_empty_horizon: int = 0
    windows_excluded_unlabelled_horizon: int = 0
    require_labelled_horizon: bool = True

    # ── Ongoing-attack accounting ──
    # A window whose OBSERVATION period already contains attack-labelled
    # events is not a clean pre-attack forecast: predicting "attack soon"
    # from "attack now" is detection, and reporting it as forecasting
    # overstates what was demonstrated. Counted always; excluded only when
    # the caller asks.
    windows_with_attack_in_observation: int = 0
    windows_excluded_ongoing_attack: int = 0
    exclude_ongoing_attack_windows: bool = False

    # Event-count chunks examined when time-based windowing produced
    # nothing. These are NOT time windows — the stated durations do not
    # apply to them — but they do produce instances, so they are included
    # in windows_considered to keep the accounting identity intact.
    fallback_chunks_considered: int = 0
    fallback_chunks_excluded: int = 0

    config_was_rescaled: bool = False
    rescale_factor: Optional[float] = None
    used_fallback_chunking: bool = False

    # ── Window-generation coverage (distinct from RECORD selection) ──
    #
    # Three different counts, deliberately named apart:
    #   windows_eligible   — windows the data's time span and stride allow
    #   windows_considered — windows the loop actually examined (<= limit)
    #   windows_generated  — instances emitted (<= considered; the rest were
    #                        excluded by the negative-label validity rules)
    #   windows_omitted    — eligible windows never examined, because the cap
    #                        stopped the loop first
    #
    # `windows_truncated` is the structured signal. The free-text note is
    # kept for a human reader but is NOT the source of truth: a caller must
    # be able to branch on this without parsing prose.
    #
    # This is NOT the same as SelectionCoverage.truncated, which reports that
    # a record-count cap limited which EVENTS were fetched. Both can occur
    # independently and both must be visible.
    windows_limit: int = 0
    windows_eligible: int = 0
    windows_considered: int = 0
    windows_omitted: int = 0
    windows_truncated: bool = False

    event_count: int = 0
    data_span_seconds: float = 0.0
    windows_generated: int = 0
    positive_windows: int = 0
    negative_windows: int = 0

    # ── Prediction-time availability (ADR-069, blueprint section 6) ──
    # "A late event may update a historical record, but it must not be
    # retroactively treated as information available to an earlier
    # forecast." An event observed inside a window but RECEIVED after the
    # window's prediction time is excluded from that window's features.
    #   late_arrival_exclusions    - (window, event) pairs excluded; one
    #                                late event can be excluded from several
    #                                overlapping windows
    #   windows_with_late_arrivals - windows that lost at least one event
    late_arrival_exclusions: int = 0
    windows_with_late_arrivals: int = 0
    notes: list[str] = Field(default_factory=list)

    @property
    def uses_nominal_config(self) -> bool:
        return not self.config_was_rescaled and not self.used_fallback_chunking


# Hard ceiling on generated windows. Window count is driven by the data's
# time span divided by the stride, so a single corrupt timestamp (notably
# the Windows FILETIME epoch, 1601-01-01) implies a span of centuries and
# hundreds of millions of iterations — enough to hang the request thread
# indefinitely. The span is sanitised below AND this bound is enforced, so
# no input can cause unbounded work.
MAX_WINDOWS = 20_000

# Mirrors the ingestion guard: a timestamp outside this range cannot
# describe an observed event and must not define the windowing range.
MIN_PLAUSIBLE_YEAR = 2000
MAX_CLOCK_SKEW_SECONDS = 3600.0


FEATURE_NAMES = [
    "flow_count",
    "distinct_src_ips",
    "distinct_dst_ips",
    "distinct_dst_ports",
    "total_bytes",
    "avg_bytes_per_flow",
    "total_packets",
    "avg_packets_per_flow",
    "tcp_ratio",
    "udp_ratio",
    "avg_duration",
    "byte_rate_per_sec",
]

# The two features that need endpoint addresses (ADR-096).
ADDRESS_DEPENDENT_FEATURES = ("distinct_src_ips", "distinct_dst_ips")

# Feature schemas, named and versioned so two runs are never compared
# across different feature sets without that being visible.
#
# A source with no address columns cannot produce the two counts above.
# Emitting 0 for them would be a FABRICATED MEASUREMENT: "no distinct
# source addresses were observed" is a claim, and a false one — the flows
# had addresses, the export dropped them. The columns are therefore
# REMOVED, and the schema that results is a different schema with a
# different name, not the same schema with two zeroes in it.
FEATURE_SCHEMA_FULL = "prahari.window_features.full.v1"
FEATURE_SCHEMA_ADDRESSLESS = "prahari.window_features.addressless.v1"

ADDRESSLESS_FEATURE_NAMES = [
    n for n in FEATURE_NAMES if n not in ADDRESS_DEPENDENT_FEATURES
]


def feature_names_for(schema: str) -> list[str]:
    """The ordered feature names a schema produces."""
    if schema == FEATURE_SCHEMA_ADDRESSLESS:
        return list(ADDRESSLESS_FEATURE_NAMES)
    return list(FEATURE_NAMES)


class MixedAddressAvailabilityError(ValueError):
    """
    Some events carry addresses and some structurally cannot.

    Refused rather than resolved. Counting distinct addresses over such a
    mixture undercounts by exactly the address-less share, and nothing in
    the resulting number would show it.
    """


class WindowFeatureExtractor:
    """
    Constructs causal feature vectors from normalized network flows.
    """

    def __init__(
        self,
        window_size_seconds: float = 60.0,
        lead_time_seconds: float = 30.0,
        prediction_horizon_seconds: float = 60.0,
        require_labelled_horizon: bool = True,
        min_horizon_events: int = 1,
        exclude_ongoing_attack_windows: bool = False,
        require_complete_windowing: bool = False,
    ):
        # When True, a run that hits the window cap raises instead of
        # returning a silently partial dataset. Off by default so existing
        # behaviour is unchanged; research evaluations that claim to cover a
        # dataset should turn it on.
        self.require_complete_windowing = require_complete_windowing
        # When True, windows already containing an attack are dropped, so the
        # evaluation measures prediction of a NEW incident rather than
        # continuation of one in progress. Off by default because dropping
        # them also discards the majority of positives on bursty data; the
        # count is always reported either way.
        self.exclude_ongoing_attack_windows = exclude_ongoing_attack_windows
        self.last_observation_attack_mask = np.array([], dtype=np.int32)
        self.window_size_seconds = window_size_seconds
        self.lead_time_seconds = lead_time_seconds
        self.prediction_horizon_seconds = prediction_horizon_seconds

        # Blueprint section 7: "y_t = 0 only when the observation window is
        # complete enough to support a negative label."
        #
        # Absence of an attack label is not evidence of absence of attack.
        # A horizon that is empty (a capture gap) or that contains only
        # UNLABELLED events cannot support a negative label — recording one
        # would fabricate ground truth and inflate the negative class.
        # Such windows are EXCLUDED from the dataset rather than labelled 0.
        self.require_labelled_horizon = require_labelled_horizon
        self.min_horizon_events = max(0, int(min_horizon_events))

        # Populated by build_dataset_instances() so callers can report the
        # configuration that was genuinely used.
        self.last_windowing_report: Optional[WindowingReport] = None
        # Decided from the events themselves in build_dataset_instances, and
        # reported; a run under one schema is not comparable with a run
        # under the other (ADR-096).
        self.feature_schema: str = FEATURE_SCHEMA_FULL

    @staticmethod
    def arrived_by(event: NormalizedEvent, prediction_time: datetime) -> bool:
        """
        Whether `event` could have been known at `prediction_time`.

        Only LIVE telemetry with a server receipt time can be tested: there
        `received_at` is the moment PraHari first held the event. For a
        historical import `received_at` is when the FILE was imported -
        years after the events - so applying it would wrongly empty every
        window. Offline replay therefore keeps its declared assumption:
        an imported event is treated as available at its own event time.
        An event with no receipt time is likewise treated as available,
        because there is no evidence of lateness to act on.
        """
        if event.data_category != DataCategory.LIVE_TELEMETRY:
            return True
        if event.received_at is None:
            return True
        return event.received_at <= prediction_time

    def _available(
        self,
        window_events: list[NormalizedEvent],
        prediction_time: datetime,
        report: "WindowingReport",
    ) -> list[NormalizedEvent]:
        """The events of a window that had arrived by its prediction time."""
        kept = [e for e in window_events if self.arrived_by(e, prediction_time)]
        dropped = len(window_events) - len(kept)
        if dropped:
            report.late_arrival_exclusions += dropped
            report.windows_with_late_arrivals += 1
        return kept

    def extract_features_from_window(
        self,
        window_events: list[NormalizedEvent],
        window_duration: float,
    ) -> list[float]:
        """
        Extract a single feature vector from events in an observation window.

        Under the address-less schema the two distinct-address counts are
        OMITTED, not zeroed: a zero there would assert a measurement the
        source cannot support (ADR-096).
        """
        addressless = self.feature_schema == FEATURE_SCHEMA_ADDRESSLESS
        width = len(feature_names_for(self.feature_schema))
        if not window_events:
            return [0.0] * width

        flow_count = float(len(window_events))
        src_ips = set(e.src_ip for e in window_events if e.src_ip)
        dst_ips = set(e.dst_ip for e in window_events if e.dst_ip)
        dst_ports = set(e.dst_port for e in window_events if e.dst_port is not None)

        durations = [e.duration for e in window_events if e.duration is not None]
        packets = [e.packets for e in window_events if e.packets is not None]
        bytes_total = [e.bytes_total for e in window_events if e.bytes_total is not None]

        tot_bytes = sum(bytes_total) if bytes_total else 0.0
        tot_pkts = sum(packets) if packets else 0.0

        tcp_count = sum(1 for e in window_events if e.protocol == "TCP")
        udp_count = sum(1 for e in window_events if e.protocol == "UDP")

        duration_sec = max(1.0, window_duration)

        values = [
            flow_count,
            float(len(src_ips)),
            float(len(dst_ips)),
            float(len(dst_ports)),
            float(tot_bytes),
            float(tot_bytes / flow_count) if flow_count > 0 else 0.0,
            float(tot_pkts),
            float(tot_pkts / flow_count) if flow_count > 0 else 0.0,
            float(tcp_count / flow_count) if flow_count > 0 else 0.0,
            float(udp_count / flow_count) if flow_count > 0 else 0.0,
            float(sum(durations) / len(durations)) if durations else 0.0,
            float(tot_bytes / duration_sec),
        ]
        if addressless:
            drop = {FEATURE_NAMES.index(n) for n in ADDRESS_DEPENDENT_FEATURES}
            values = [v for i, v in enumerate(values) if i not in drop]
        return values

    def build_dataset_instances(
        self,
        events: list[NormalizedEvent],
        step_seconds: float = 15.0,
    ) -> tuple[np.ndarray, np.ndarray, list[datetime]]:
        """
        Slide observation windows across chronological events to create
        (X, y, timestamp) pairs strictly preventing temporal leakage.
        """
        report = WindowingReport(
            nominal_window_seconds=self.window_size_seconds,
            nominal_lead_seconds=self.lead_time_seconds,
            nominal_horizon_seconds=self.prediction_horizon_seconds,
            nominal_stride_seconds=step_seconds,
            effective_window_seconds=self.window_size_seconds,
            effective_lead_seconds=self.lead_time_seconds,
            effective_horizon_seconds=self.prediction_horizon_seconds,
            effective_stride_seconds=step_seconds,
            event_count=len(events),
        )
        self.last_windowing_report = report

        if not events:
            report.notes.append("No events supplied; no windows generated.")
            return _empty_dataset()

        # Exclude events whose timestamps cannot describe an observation.
        # One such record would otherwise stretch the windowing range across
        # centuries.
        now = datetime.now(timezone.utc)
        usable = [
            e for e in events
            if e.observed_at.year >= MIN_PLAUSIBLE_YEAR
            and e.observed_at <= now + timedelta(seconds=MAX_CLOCK_SKEW_SECONDS)
        ]
        discarded = len(events) - len(usable)
        if discarded:
            report.notes.append(
                f"{discarded} event(s) with implausible timestamps were excluded "
                "from windowing; they cannot describe an observed event and would "
                "otherwise distort the observation range."
            )
        if not usable:
            report.notes.append("No events with usable timestamps; no windows generated.")
            return _empty_dataset()

        # Which feature schema these events can support, decided from the
        # events themselves and reported (ADR-096). A mixture is REFUSED:
        # counting distinct addresses over a set where some rows
        # structurally lack them undercounts by exactly the address-less
        # share, and nothing in the resulting number would show it.
        with_addr = sum(1 for e in usable if e.src_ip or e.dst_ip)
        if with_addr == 0:
            self.feature_schema = FEATURE_SCHEMA_ADDRESSLESS
        elif with_addr == len(usable):
            self.feature_schema = FEATURE_SCHEMA_FULL
        else:
            raise MixedAddressAvailabilityError(
                f"{with_addr} of {len(usable)} event(s) carry an endpoint "
                "address and the rest cannot. Distinct-address counts over "
                "that mixture would undercount by the address-less share "
                "with nothing to show it. Select one provenance, or import "
                "the address-less source under its own source id."
            )
        report.feature_schema = self.feature_schema
        report.feature_names = feature_names_for(self.feature_schema)
        if self.feature_schema == FEATURE_SCHEMA_ADDRESSLESS:
            report.notes.append(
                "No event carries an endpoint address, so the two "
                "distinct-address features are OMITTED and the schema is "
                f"{FEATURE_SCHEMA_ADDRESSLESS}. Results under it are not "
                "comparable with results under the full schema."
            )

        sorted_events = sorted(usable, key=lambda e: e.observed_at)
        start_time = sorted_events[0].observed_at
        end_time = sorted_events[-1].observed_at

        total_span = (end_time - start_time).total_seconds()
        min_required_span = self.window_size_seconds + self.lead_time_seconds + self.prediction_horizon_seconds

        # If data span is very short (e.g. test fixture), scale window sizes proportionally to preserve task
        w_size = self.window_size_seconds
        lead_t = self.lead_time_seconds
        pred_h = self.prediction_horizon_seconds
        step_t = step_seconds

        report.data_span_seconds = round(total_span, 3)

        if total_span > 20 and (total_span < min_required_span or (total_span - min_required_span) / step_t < 6):
            scale = min(1.0, total_span / (min_required_span * 2.5))
            w_size = max(5.0, w_size * scale)
            lead_t = max(2.0, lead_t * scale)
            pred_h = max(5.0, pred_h * scale)
            step_t = max(2.0, step_t * scale)
            report.config_was_rescaled = True
            report.rescale_factor = round(scale, 4)
            report.notes.append(
                f"Data span ({round(total_span, 1)}s) is too short for the nominal "
                f"configuration (requires >{round(min_required_span, 1)}s plus margin); "
                f"window parameters were rescaled by {round(scale, 3)}. Evaluation "
                f"results must NOT be cited as using the nominal W/L/H/S values."
            )

        # Round ONCE, then use the rounded values for the loop as well as the
        # report. Previously the report stored rounded values while the loop
        # ran on the unrounded floats, so a run could not be reproduced from
        # its own reported configuration — on a rescaled fixture that was a
        # one-window difference. In a project whose central claim is
        # reproducibility, the reported parameters must be the parameters
        # that were used.
        w_size = round(w_size, 3)
        lead_t = round(lead_t, 3)
        pred_h = round(pred_h, 3)
        step_t = round(step_t, 3)

        report.effective_window_seconds = w_size
        report.effective_lead_seconds = lead_t
        report.effective_horizon_seconds = pred_h
        report.effective_stride_seconds = step_t

        X_list: list[list[float]] = []
        y_list: list[int] = []
        ts_list: list[datetime] = []
        # Per-instance: did the OBSERVATION window already contain an attack?
        # Kept beside the dataset rather than inside X, because a feature
        # saying "an attack is happening now" would let any model score well
        # on a task it was never asked to perform.
        obs_attack_list: list[int] = []
        report.exclude_ongoing_attack_windows = self.exclude_ongoing_attack_windows

        # ── Time index and label prefix sums, built once ──
        #
        # Previously each window re-scanned the whole event list twice (once
        # for the observation interval, once for the horizon), making the
        # pass O(events x windows). On a long span that is the dominant cost
        # and it is pure repetition: the events are already sorted, so the
        # boundaries of a half-open interval are two binary searches.
        #
        # `bisect_left` is used for BOTH ends because every interval here is
        # [lo, hi): the low index is the first event at or after the start,
        # and the high index is the first event at or after the end, so the
        # slice holds exactly `start <= t < end`. Equal timestamps all fall
        # inside the same slice, and because `sorted` is stable the order
        # within a tie is the input order — identical to what the list
        # comprehension produced.
        event_times = [e.observed_at for e in sorted_events]

        # Prefix counts let "does this interval contain an attack / any
        # label" be answered in O(1) instead of scanning the interval. That
        # matters most for windows that are about to be REJECTED: the old
        # code materialised both intervals before discovering the horizon
        # was empty.
        attack_prefix = [0] * (len(sorted_events) + 1)
        labelled_prefix = [0] * (len(sorted_events) + 1)
        for i, e in enumerate(sorted_events):
            label = e.label
            has_text = label is not None and label.strip() != ""
            is_attack = (
                has_text
                and label.strip().lower() not in ("benign", "normal", "unlabeled")
            )
            attack_prefix[i + 1] = attack_prefix[i] + (1 if is_attack else 0)
            labelled_prefix[i + 1] = labelled_prefix[i] + (1 if has_text else 0)

        current_window_end = start_time + timedelta(seconds=w_size)

        # The bound is on ITERATIONS, not on emitted windows. Windows that
        # fail the negative-label validity check are skipped without growing
        # X_list, so a cap on output alone would let the loop spin without
        # limit on a wide time span.
        iterations = 0
        while (
            current_window_end + timedelta(seconds=lead_t + pred_h) <= end_time
            and iterations < MAX_WINDOWS
        ):
            iterations += 1
            window_start = current_window_end - timedelta(seconds=w_size)
            target_start = current_window_end + timedelta(seconds=lead_t)
            target_end = target_start + timedelta(seconds=pred_h)

            # Interval boundaries by binary search. Same half-open
            # semantics as the comprehensions they replace:
            #   observation [window_start, current_window_end)
            #   horizon     [target_start, target_end)
            obs_lo = bisect_left(event_times, window_start)
            obs_hi = bisect_left(event_times, current_window_end)
            fut_lo = bisect_left(event_times, target_start)
            fut_hi = bisect_left(event_times, target_end)

            horizon_count = fut_hi - fut_lo

            # ── Target label ──
            # Positive: at least one event in the horizon carries an attack
            # label. A positive is always valid — the evidence is present.
            has_attack = (attack_prefix[fut_hi] - attack_prefix[fut_lo]) > 0

            observation_has_attack = (
                attack_prefix[obs_hi] - attack_prefix[obs_lo]
            ) > 0
            if observation_has_attack:
                report.windows_with_attack_in_observation += 1
                if self.exclude_ongoing_attack_windows:
                    report.windows_excluded_ongoing_attack += 1
                    current_window_end += timedelta(seconds=step_t)
                    continue

            if has_attack:
                # Materialised only now: a rejected window never pays for it.
                X_list.append(
                    self.extract_features_from_window(
                        self._available(
                            sorted_events[obs_lo:obs_hi], current_window_end, report
                        ),
                        w_size,
                    )
                )
                y_list.append(1)
                ts_list.append(current_window_end)
                obs_attack_list.append(int(observation_has_attack))
            else:
                # Negative labels require a horizon complete enough to
                # support the claim "no attack occurred here".
                if horizon_count < self.min_horizon_events:
                    # Nothing observed in the horizon: a gap, not a negative.
                    report.windows_excluded_empty_horizon += 1
                    current_window_end += timedelta(seconds=step_t)
                    continue

                if self.require_labelled_horizon and (
                    labelled_prefix[fut_hi] - labelled_prefix[fut_lo]
                ) == 0:
                    # Traffic was observed but carries no ground truth, so
                    # its benignity is unknown, not established.
                    report.windows_excluded_unlabelled_horizon += 1
                    current_window_end += timedelta(seconds=step_t)
                    continue

                X_list.append(
                    self.extract_features_from_window(
                        self._available(
                            sorted_events[obs_lo:obs_hi], current_window_end, report
                        ),
                        w_size,
                    )
                )
                y_list.append(0)
                ts_list.append(current_window_end)
                obs_attack_list.append(int(observation_has_attack))

            current_window_end += timedelta(seconds=step_t)

        if not X_list:
            # Fallback if windowing yields 0 slices: generate sequential sub-chunks.
            # This abandons the time-based formulation entirely (chunks are
            # event-count based), so it is recorded as such — results from it
            # cannot be described as time-windowed forecasting.
            report.used_fallback_chunking = True
            report.notes.append(
                "Time-based windowing produced no slices; fell back to event-count "
                "chunking. Resulting instances are NOT time-windowed and the stated "
                "observation/horizon durations do not apply to them."
            )
            chunk_size = max(5, len(sorted_events) // 4)
            for idx in range(0, len(sorted_events) - chunk_size, max(1, chunk_size // 2)):
                chunk = sorted_events[idx:idx + chunk_size]
                future_chunk = sorted_events[idx + chunk_size:idx + chunk_size * 2]
                if not future_chunk:
                    break
                # Counted as considered. `windows_generated` is set from
                # len(X_list) AFTER this loop, so it already includes what
                # the fallback emits; leaving `windows_considered` out of
                # step made the accounting incoherent — rejections could
                # exceed the number of candidates examined.
                report.fallback_chunks_considered += 1
                iterations += 1

                # The exclusion must hold here too. Without this, asking to
                # exclude ongoing-attack windows could EMPTY the time-window
                # loop, trigger this fallback, and have it re-emit chunks
                # whose observation period contains an attack — producing the
                # exact opposite of what was requested, while
                # `windows_excluded_ongoing_attack` reported the control as
                # having worked.
                if self.exclude_ongoing_attack_windows and any(
                    e.label is not None
                    and e.label.strip().lower() not in ("benign", "normal", "unlabeled", "")
                    for e in chunk
                ):
                    report.windows_excluded_ongoing_attack += 1
                    report.fallback_chunks_excluded += 1
                    continue
                has_attack = any(
                    e.label is not None
                    and e.label.strip().lower() not in ("benign", "normal", "unlabeled", "")
                    for e in future_chunk
                )
                # The negative-label validity rule applies here too: this
                # path previously labelled unlabelled chunks as benign,
                # which is the assumption the whole gate exists to prevent.
                if not has_attack:
                    if self.require_labelled_horizon and not any(
                        e.label is not None and e.label.strip() != ""
                        for e in future_chunk
                    ):
                        report.windows_excluded_unlabelled_horizon += 1
                        report.fallback_chunks_excluded += 1
                        continue
                feat = self.extract_features_from_window(
                    self._available(chunk, chunk[-1].observed_at, report), w_size
                )
                X_list.append(feat)
                y_list.append(1 if has_attack else 0)
                ts_list.append(chunk[-1].observed_at)
                obs_attack_list.append(
                    int(any(
                        e.label is not None
                        and e.label.strip().lower() not in ("benign", "normal", "unlabeled", "")
                        for e in chunk
                    ))
                )

        # How many windows the span and stride actually allow. Derived from
        # the same loop bound, so it is a computed quantity rather than an
        # estimate: the loop runs while
        #   (start + W) + k*S + L + H <= end
        last_start = (end_time - start_time).total_seconds() - (w_size + lead_t + pred_h)
        report.windows_limit = MAX_WINDOWS
        report.windows_considered = iterations
        report.windows_eligible = (
            int(last_start // step_t) + 1 if last_start >= 0 and step_t > 0 else 0
        )
        # When the fallback ran, the candidate population is the time windows
        # PLUS the event-count chunks. Counting only the former would leave
        # eligible below considered, which reads as a corrupt report.
        report.windows_eligible += report.fallback_chunks_considered
        report.windows_omitted = max(0, report.windows_eligible - report.windows_considered)
        report.windows_truncated = report.windows_omitted > 0

        if report.windows_truncated:
            report.notes.append(
                f"Window generation stopped at the {MAX_WINDOWS} window safety "
                f"limit after examining {report.windows_considered} of "
                f"{report.windows_eligible} eligible windows; "
                f"{report.windows_omitted} were never examined. Results cover "
                "only the earliest portion of the data. See windows_truncated."
            )
            if self.require_complete_windowing:
                raise WindowCoverageIncomplete(
                    f"Window generation covered {report.windows_considered} of "
                    f"{report.windows_eligible} eligible windows "
                    f"({report.windows_omitted} omitted at the {MAX_WINDOWS} "
                    "limit). This evaluation would describe only the earliest "
                    "part of the data. Widen the stride, narrow the time range, "
                    "or set require_complete_windowing=False and read "
                    "windows_truncated.",
                    report,
                )

        report.require_labelled_horizon = self.require_labelled_horizon
        excluded = (
            report.windows_excluded_empty_horizon
            + report.windows_excluded_unlabelled_horizon
        )
        if excluded:
            report.notes.append(
                f"{excluded} window(s) were EXCLUDED rather than labelled negative: "
                f"{report.windows_excluded_empty_horizon} had no observation in the "
                f"horizon (a gap, not evidence of absence) and "
                f"{report.windows_excluded_unlabelled_horizon} contained only "
                "unlabelled traffic (benignity unknown, not established)."
            )

        report.windows_generated = len(X_list)
        report.positive_windows = int(sum(y_list))
        report.negative_windows = len(y_list) - int(sum(y_list))

        # Exposed as an attribute rather than a fourth return value so every
        # existing caller keeps working. The persistence baseline and the
        # ongoing-attack audit read it from here.
        self.last_observation_attack_mask = np.array(obs_attack_list, dtype=np.int32)

        if not X_list:
            # Windows were considered but none survived the validity rules.
            # The report above already records why; the arrays must still
            # carry the feature dimension so a caller can inspect the shape
            # without a special case for "empty".
            return _empty_dataset()

        return np.array(X_list, dtype=np.float32), np.array(y_list, dtype=np.int32), ts_list
