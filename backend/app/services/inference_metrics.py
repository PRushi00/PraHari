"""
PraHari — Inference latency and throughput (blueprint §10, ADR-106).

§10 requires "inference latency and throughput" among the measurements an
evaluation reports. Nothing measured it: the System Health models block
returned `inference_latency: None` with a comment saying there was no
instrument, which was honest and also a gap.

What is measured, precisely
---------------------------
The wall-clock duration of `ThreatForecastingPipeline.predict_recent_window`
— feature extraction over the observation window plus model scoring.

It deliberately **excludes**:

* the readiness gate, which refuses before any model runs;
* the database read that fetches the window, which measures storage;
* automatic training, which is not inference and is thousands of times
  slower, so one autotrain would dominate every percentile.

A number that mixed those in would describe the endpoint, not the model,
and §16's operational acceptance keeps ingestion and processing delay as
separate measurements for the same reason.

Honesty rules, the same ones `services/admission.py` follows
------------------------------------------------------------
* Nothing measured yields `null`, never `0`. Zero is a measurement and
  would claim instantaneous inference.
* Samples are bounded, so a long-running process cannot grow this
  without limit.
* Latency is recorded per **resolved** model id, because a random forest
  and a NumPy LSTM are different measurements and averaging them answers
  no question anyone asked.
* Counters are per process and reset on restart, like every other figure
  in the System Health report.

Throughput is reported as windows per second derived from the same
samples, plus the observed events-per-window, rather than as an
independent claim: one call scores one window, so a rate quoted without
the window size it was measured at is not reproducible.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Optional

# Bounded for the same reason admission control bounds its own samples.
MAX_SAMPLES = 256


def _percentiles(samples_ms: list[float]) -> dict[str, Optional[float]]:
    """
    Percentiles over retained samples, or nulls when there are none.

    Deliberately the same shape as `AdmissionMetrics.latency_summary` so a
    reader comparing ingestion and inference is comparing like with like.
    """
    ordered = sorted(samples_ms)
    if not ordered:
        return {"samples": 0, "p50_ms": None, "p95_ms": None, "max_ms": None}

    def pct(p: float) -> float:
        idx = min(len(ordered) - 1, int(round((len(ordered) - 1) * p)))
        return round(ordered[idx], 3)

    return {
        "samples": len(ordered),
        "p50_ms": pct(0.50),
        "p95_ms": pct(0.95),
        "max_ms": round(ordered[-1], 3),
    }


@dataclass
class _ModelSamples:
    latencies_ms: list[float] = field(default_factory=list)
    events_in_window: list[int] = field(default_factory=list)

    def record(self, ms: float, events: int) -> None:
        self.latencies_ms.append(ms)
        self.events_in_window.append(events)
        if len(self.latencies_ms) > MAX_SAMPLES:
            drop = len(self.latencies_ms) - MAX_SAMPLES
            del self.latencies_ms[:drop]
            del self.events_in_window[:drop]


class InferenceMetrics:
    """
    Process-wide inference measurements, keyed by resolved model id.

    Guarded by a lock: FastAPI serves requests from a thread pool, and two
    concurrent predictions appending to one list is exactly the race that
    makes a percentile wrong in a way no test would notice.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._by_model: dict[str, _ModelSamples] = {}

    def record(self, model_id: str, duration_ms: float, events_in_window: int) -> None:
        if duration_ms < 0:
            raise ValueError("duration_ms cannot be negative")
        with self._lock:
            self._by_model.setdefault(model_id, _ModelSamples()).record(
                duration_ms, events_in_window
            )

    def reset(self) -> None:
        """Used by tests and by nothing else; the API never clears this."""
        with self._lock:
            self._by_model.clear()

    def summary(self) -> Optional[dict]:
        """
        What System Health reports, or `None` when no inference has run.

        `None` rather than a structure full of nulls: the models block
        already distinguishes "no model" from "no measurement", and a
        populated shape with nothing in it reads as a measurement of zero.
        """
        with self._lock:
            if not self._by_model:
                return None
            per_model: dict[str, dict] = {}
            all_latencies: list[float] = []
            for model_id, s in self._by_model.items():
                block = _percentiles(s.latencies_ms)
                windows = len(s.latencies_ms)
                total_s = sum(s.latencies_ms) / 1000.0
                block["windows_per_second"] = (
                    round(windows / total_s, 3) if total_s > 0 else None
                )
                block["events_per_window_min"] = (
                    min(s.events_in_window) if s.events_in_window else None
                )
                block["events_per_window_max"] = (
                    max(s.events_in_window) if s.events_in_window else None
                )
                per_model[model_id] = block
                all_latencies.extend(s.latencies_ms)

        return {
            "measures": (
                "wall clock of feature extraction plus model scoring "
                "(`predict_recent_window`). EXCLUDES the readiness gate, the "
                "database read that fetches the window, and automatic "
                "training — each of those measures something else."
            ),
            "per_model": per_model,
            "all_models": _percentiles(all_latencies),
            "note": (
                "Per process; reset on restart. Throughput is windows per "
                "second over the same samples, reported beside the "
                "events-per-window range it was measured at, because a rate "
                "without its window size is not reproducible."
            ),
        }


_metrics = InferenceMetrics()


def get_inference_metrics() -> InferenceMetrics:
    return _metrics
