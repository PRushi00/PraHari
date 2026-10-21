"""
PraHari — Inference latency and throughput are measured (§10, ADR-106).

Blueprint §10 lists "inference latency and throughput" among the
measurements an evaluation must report. Nothing measured it: the System
Health models block returned a hardcoded `inference_latency: None` with a
comment saying no instrument existed. Honest, and a gap.

What these pin is mostly about what the number MEANS, because a latency
figure is easy to produce and easy to make meaningless:

* null until something ran — never a zero, and never a structure full of
  nulls, which reads as a measurement;
* recorded per resolved model, because a random forest and a NumPy LSTM
  are different measurements;
* bounded samples, so a long-running process cannot grow the list without
  limit;
* throughput reported beside the events-per-window range it was measured
  at, because a rate without its window size is not reproducible;
* the `measures` string says what is excluded, so nobody reads this as an
  endpoint latency.
"""

from __future__ import annotations

import pytest

from app.services.inference_metrics import (
    MAX_SAMPLES,
    InferenceMetrics,
    get_inference_metrics,
)


@pytest.fixture()
def metrics() -> InferenceMetrics:
    return InferenceMetrics()


# ──────────────────────────────────────────────────────────────────
# Nothing measured is null, not zero
# ──────────────────────────────────────────────────────────────────


def test_nothing_measured_reports_null_not_a_zero_filled_shape(metrics):
    """
    A populated structure whose fields are all null reads as a
    measurement of zero. Absence has to be absence.
    """
    assert metrics.summary() is None


def test_the_process_wide_instrument_starts_empty_or_reports_real_samples():
    """
    The singleton may carry samples from earlier tests in this process;
    what must never happen is a summary that claims samples it lacks.
    """
    summary = get_inference_metrics().summary()
    if summary is not None:
        assert summary["all_models"]["samples"] > 0


# ──────────────────────────────────────────────────────────────────
# Per-model, because averaging two models answers nothing
# ──────────────────────────────────────────────────────────────────


def test_latency_is_recorded_per_resolved_model(metrics):
    metrics.record("random_forest", 12.0, events_in_window=500)
    metrics.record("lstm", 240.0, events_in_window=500)

    summary = metrics.summary()
    assert set(summary["per_model"]) == {"random_forest", "lstm"}
    assert summary["per_model"]["random_forest"]["p50_ms"] == 12.0
    assert summary["per_model"]["lstm"]["p50_ms"] == 240.0
    # The combined view exists, but it does not replace the split one.
    assert summary["all_models"]["samples"] == 2
    assert summary["all_models"]["max_ms"] == 240.0


def test_percentiles_are_over_the_whole_retained_sample(metrics):
    for ms in range(1, 101):
        metrics.record("m", float(ms), events_in_window=10)

    block = metrics.summary()["per_model"]["m"]
    assert block["samples"] == 100
    # Nearest-rank on a 0-indexed sorted list: idx = round((n-1) * p).
    # For 1..100 that is index 50 and index 94, i.e. 51 ms and 95 ms.
    assert block["p50_ms"] == 51.0
    assert block["p95_ms"] == 95.0
    assert block["max_ms"] == 100.0


# ──────────────────────────────────────────────────────────────────
# Bounded
# ──────────────────────────────────────────────────────────────────


def test_samples_are_bounded_so_a_long_run_cannot_grow_without_limit(metrics):
    for i in range(MAX_SAMPLES * 3):
        metrics.record("m", float(i), events_in_window=1)

    block = metrics.summary()["per_model"]["m"]
    assert block["samples"] == MAX_SAMPLES
    # The retained window is the most RECENT samples, so the oldest
    # measurements cannot keep dragging a percentile down forever.
    assert block["max_ms"] == float(MAX_SAMPLES * 3 - 1)


def test_the_events_per_window_range_is_trimmed_with_the_latencies(metrics):
    """
    If the two lists drift out of step, throughput is quoted against a
    window size that was never measured with it.
    """
    for i in range(MAX_SAMPLES + 50):
        metrics.record("m", 1.0, events_in_window=i)

    block = metrics.summary()["per_model"]["m"]
    assert block["samples"] == MAX_SAMPLES
    assert block["events_per_window_max"] == MAX_SAMPLES + 49
    assert block["events_per_window_min"] == 50


# ──────────────────────────────────────────────────────────────────
# Throughput is reported with the window size it was measured at
# ──────────────────────────────────────────────────────────────────


def test_throughput_is_derived_from_the_same_samples(metrics):
    # Ten windows at 100 ms each is one second of work: 10 windows/s.
    for _ in range(10):
        metrics.record("m", 100.0, events_in_window=250)

    block = metrics.summary()["per_model"]["m"]
    assert block["windows_per_second"] == 10.0
    assert block["events_per_window_min"] == 250
    assert block["events_per_window_max"] == 250


def test_the_summary_states_what_it_excludes(metrics):
    """
    Without this the figure is read as endpoint latency, which would
    include a database read and possibly an autotrain.
    """
    metrics.record("m", 5.0, events_in_window=10)
    measures = metrics.summary()["measures"]

    assert "predict_recent_window" in measures
    for excluded in ("gate", "database", "training"):
        assert excluded in measures.lower()


def test_a_negative_duration_is_refused(metrics):
    """A clock going backwards must not silently poison a percentile."""
    with pytest.raises(ValueError):
        metrics.record("m", -1.0, events_in_window=10)


# ──────────────────────────────────────────────────────────────────
# Reaches the System Health report
# ──────────────────────────────────────────────────────────────────


def test_system_health_reports_the_measured_value(monkeypatch, tmp_path):
    """
    An instrument nothing surfaces is not a measurement anyone can read.
    """
    from app.api.v1 import system_health

    instrument = InferenceMetrics()
    instrument.record("random_forest", 7.5, events_in_window=300)
    monkeypatch.setattr(
        system_health, "get_inference_metrics", lambda: instrument
    )

    from app.storage.database import Database

    db = Database(str(tmp_path / "models.db"))
    db.initialize()
    try:
        block = system_health._models_block(db)
    finally:
        db.close()
    assert block.available is True
    latency = block.data["inference_latency"]
    assert latency is not None
    assert latency["per_model"]["random_forest"]["p50_ms"] == 7.5


def test_system_health_reports_null_before_any_inference(monkeypatch, tmp_path):
    from app.api.v1 import system_health

    monkeypatch.setattr(
        system_health, "get_inference_metrics", lambda: InferenceMetrics()
    )

    from app.storage.database import Database

    db = Database(str(tmp_path / "null.db"))
    db.initialize()
    try:
        block = system_health._models_block(db)
    finally:
        db.close()
    assert block.data["inference_latency"] is None
