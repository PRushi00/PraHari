"""
PraHari — Causal Feature Engineering Engine

Extracts retrospective window-based telemetry features without forward leakage.
Observation Window: [t - W, t]
Prediction Horizon: [t + lead_time, t + lead_time + H]
"""

from __future__ import annotations

import math
from datetime import datetime, timedelta, timezone
from typing import Any, Optional
import numpy as np
from pydantic import BaseModel, Field

from app.schemas.events import NormalizedEvent


class WindowingReport(BaseModel):
    """
    Factual record of how windowing actually ran.

    The nominal configuration (W=60s, L=30s, H=60s, S=15s) cannot always be
    applied to a short dataset. When it is adjusted, that adjustment is
    reported here rather than left implicit, so no downstream claim can cite
    the nominal parameters for an evaluation that did not use them.
    """
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

    config_was_rescaled: bool = False
    rescale_factor: Optional[float] = None
    used_fallback_chunking: bool = False

    event_count: int = 0
    data_span_seconds: float = 0.0
    windows_generated: int = 0
    positive_windows: int = 0
    negative_windows: int = 0
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
    ):
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

    def extract_features_from_window(
        self,
        window_events: list[NormalizedEvent],
        window_duration: float,
    ) -> list[float]:
        """Extract a single feature vector from events in an observation window."""
        if not window_events:
            return [0.0] * len(FEATURE_NAMES)

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

        return [
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
            return np.empty((0, len(FEATURE_NAMES))), np.empty((0,)), []

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
            return np.empty((0, len(FEATURE_NAMES))), np.empty((0,)), []

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

        report.effective_window_seconds = round(w_size, 3)
        report.effective_lead_seconds = round(lead_t, 3)
        report.effective_horizon_seconds = round(pred_h, 3)
        report.effective_stride_seconds = round(step_t, 3)

        X_list: list[list[float]] = []
        y_list: list[int] = []
        ts_list: list[datetime] = []

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

            # Observation events: [window_start, current_window_end)
            obs_events = [e for e in sorted_events if window_start <= e.observed_at < current_window_end]

            # Future target events: [target_start, target_end)
            future_events = [e for e in sorted_events if target_start <= e.observed_at < target_end]

            # ── Target label ──
            # Positive: at least one event in the horizon carries an attack
            # label. A positive is always valid — the evidence is present.
            has_attack = any(
                e.label is not None
                and e.label.strip().lower() not in ("benign", "normal", "unlabeled", "")
                for e in future_events
            )

            if has_attack:
                X_list.append(self.extract_features_from_window(obs_events, w_size))
                y_list.append(1)
                ts_list.append(current_window_end)
            else:
                # Negative labels require a horizon complete enough to
                # support the claim "no attack occurred here".
                if len(future_events) < self.min_horizon_events:
                    # Nothing observed in the horizon: a gap, not a negative.
                    report.windows_excluded_empty_horizon += 1
                    current_window_end += timedelta(seconds=step_t)
                    continue

                if self.require_labelled_horizon and not any(
                    e.label is not None and e.label.strip() != ""
                    for e in future_events
                ):
                    # Traffic was observed but carries no ground truth, so
                    # its benignity is unknown, not established.
                    report.windows_excluded_unlabelled_horizon += 1
                    current_window_end += timedelta(seconds=step_t)
                    continue

                X_list.append(self.extract_features_from_window(obs_events, w_size))
                y_list.append(0)
                ts_list.append(current_window_end)

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
                        continue
                feat = self.extract_features_from_window(chunk, w_size)
                X_list.append(feat)
                y_list.append(1 if has_attack else 0)
                ts_list.append(chunk[-1].observed_at)

        if iterations >= MAX_WINDOWS:
            report.notes.append(
                f"Window generation stopped at the {MAX_WINDOWS} window safety "
                "limit; the dataset's time span is too large for this stride. "
                "Results cover only the earliest portion of the data."
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

        return np.array(X_list, dtype=np.float32), np.array(y_list, dtype=np.int32), ts_list
