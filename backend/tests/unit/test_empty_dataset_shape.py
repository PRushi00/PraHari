"""
Every no-data return path must produce the same shape and dtype.

Returning ``(0,)`` from one path and ``(0, n_features)`` from another is
not cosmetic. ``stack_lagged_windows`` reads ``X.shape[1]``, which raises
IndexError on the one-dimensional form. That crash is unreachable today
only because the pipeline refuses fewer than four instances first — a
guard, not a contract, and guards get relaxed.

Documentation addresses only (RFC 5737).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import numpy as np
import pytest

from app.models.feature_extractor import (
    FEATURE_NAMES,
    WindowFeatureExtractor,
)
from app.models.forecaster import stack_lagged_windows
from app.models.lstm_forecaster import to_sequences
from app.schemas.events import (
    DataCategory,
    EventType,
    LabelProvenance,
    NormalizedEvent,
)

BASE = datetime(2026, 3, 1, tzinfo=timezone.utc)
EXPECTED_SHAPE = (0, len(FEATURE_NAMES))


def _event(idx, offset_s, label="Benign", when=None):
    return NormalizedEvent(
        event_id=f"e{idx}",
        source_id="bench",
        data_category=DataCategory.HISTORICAL_IMPORT,
        observed_at=when or (BASE + timedelta(seconds=offset_s)),
        event_type=EventType.NETWORK_FLOW,
        src_ip="192.0.2.10",
        dst_ip="198.51.100.20",
        src_port=40000 + idx,
        dst_port=443,
        protocol="TCP",
        duration=1.5,
        packets=10,
        bytes_total=1000,
        label=label,
        label_provenance=(
            LabelProvenance.DATASET_GROUND_TRUTH if label else LabelProvenance.UNLABELED
        ),
    )


def _extractor(**kw):
    defaults = dict(
        window_size_seconds=60.0, lead_time_seconds=30.0, prediction_horizon_seconds=60.0
    )
    defaults.update(kw)
    return WindowFeatureExtractor(**defaults)


def _assert_empty_contract(X, y, ts):
    assert X.shape == EXPECTED_SHAPE, f"expected {EXPECTED_SHAPE}, got {X.shape}"
    assert X.ndim == 2
    assert X.dtype == np.float32
    assert y.shape == (0,)
    assert y.dtype == np.int32
    assert ts == []
    assert len(X) == len(y) == len(ts) == 0


# ──────────────────────────────────────────────────────────────────
# Every no-data path
# ──────────────────────────────────────────────────────────────────


def test_empty_input():
    _assert_empty_contract(*_extractor().build_dataset_instances([]))


def test_single_event():
    """One event spans no time, so no window can be built."""
    _assert_empty_contract(*_extractor().build_dataset_instances([_event(0, 0)]))


def test_insufficient_temporal_span():
    """Several events inside a few seconds: shorter than W + L + H."""
    events = [_event(i, i) for i in range(5)]
    X, y, ts = _extractor().build_dataset_instances(events)
    _assert_empty_contract(X, y, ts)


def test_only_implausible_timestamps():
    """
    A corpus of FILETIME-epoch records has nothing usable. The exclusion
    must still return the canonical empty shape, with its reason recorded.
    """
    events = [
        _event(i, 0, when=datetime(1601, 1, 1, tzinfo=timezone.utc)) for i in range(10)
    ]
    extractor = _extractor()
    X, y, ts = extractor.build_dataset_instances(events)

    _assert_empty_contract(X, y, ts)
    notes = " ".join(extractor.last_windowing_report.notes).lower()
    assert "implausible" in notes or "usable timestamps" in notes


def test_all_candidate_windows_rejected():
    """
    Windows are generated and then every one fails the negative-label
    validity rule, so the loop runs but emits nothing. This is the path
    that previously returned shape (0,).
    """
    # Unlabelled traffic: no attack labels, and require_labelled_horizon
    # refuses to call an unlabelled horizon benign.
    events = [_event(i, i * 5, label=None) for i in range(400)]
    extractor = _extractor(require_labelled_horizon=True)
    X, y, ts = extractor.build_dataset_instances(events)
    report = extractor.last_windowing_report

    _assert_empty_contract(X, y, ts)
    assert report.windows_considered > 0, "windows must have been considered"
    assert report.windows_excluded_unlabelled_horizon > 0
    assert report.windows_generated == 0


def test_rejection_counters_survive_the_empty_return():
    """The report is the only record those windows existed."""
    events = [_event(i, i * 5, label=None) for i in range(400)]
    extractor = _extractor(require_labelled_horizon=True)
    extractor.build_dataset_instances(events)
    report = extractor.last_windowing_report

    rejected = (
        report.windows_excluded_empty_horizon
        + report.windows_excluded_unlabelled_horizon
    )
    assert report.windows_considered == report.windows_generated + rejected
    assert report.windows_eligible >= report.windows_considered
    assert report.event_count == 400
    assert report.data_span_seconds > 0


# ──────────────────────────────────────────────────────────────────
# Non-empty paths keep their contract
# ──────────────────────────────────────────────────────────────────


def test_multiple_events_at_one_instant_use_the_fallback_path():
    """
    Zero span means time-based windowing yields nothing, so the event-count
    fallback runs. It produces instances, and the report says the stated
    durations do not apply to them.
    """
    events = [_event(i, 0) for i in range(10)]
    extractor = _extractor()
    X, y, ts = extractor.build_dataset_instances(events)
    report = extractor.last_windowing_report

    assert report.used_fallback_chunking is True
    assert X.ndim == 2 and X.shape[1] == len(FEATURE_NAMES)
    assert len(X) == len(y) == len(ts)
    assert any("NOT time-windowed" in n for n in report.notes)


def test_rescaled_short_span_still_returns_a_consistent_matrix():
    """A short span rescales W/L/H/S; the shape contract is unaffected."""
    events = [_event(i, i * 2, "SynthAttack-A" if i % 7 == 0 else "Benign") for i in range(40)]
    extractor = _extractor()
    X, y, ts = extractor.build_dataset_instances(events)
    report = extractor.last_windowing_report

    assert report.config_was_rescaled is True
    assert report.rescale_factor is not None
    assert X.ndim == 2 and X.shape[1] == len(FEATURE_NAMES)
    assert len(X) == len(y) == len(ts)


def test_rows_labels_and_timestamps_stay_aligned():
    events = [_event(i, i, "SynthAttack-A" if i % 11 == 0 else "Benign") for i in range(600)]
    extractor = _extractor()
    X, y, ts = extractor.build_dataset_instances(events)
    mask = extractor.last_observation_attack_mask

    assert len(X) == len(y) == len(ts) == len(mask)
    assert X.shape[1] == len(FEATURE_NAMES)
    assert ts == sorted(ts)


# ──────────────────────────────────────────────────────────────────
# Downstream consumers
# ──────────────────────────────────────────────────────────────────


def test_lag_stacking_does_not_raise_on_an_empty_matrix():
    """
    The concrete motivation: `stack_lagged_windows` reads X.shape[1]. With
    a (0,) matrix that is an IndexError, not an empty result.
    """
    X, y, _ = _extractor().build_dataset_instances([])
    stacked, labels = stack_lagged_windows(X, y, lags=3)

    assert stacked.ndim == 2
    assert stacked.shape[0] == 0
    assert len(labels) == 0


def test_sequence_shaping_does_not_raise_on_an_empty_matrix():
    X, y, _ = _extractor().build_dataset_instances([])
    sequences, labels = to_sequences(X, y, timesteps=4)

    assert sequences.shape[0] == 0
    assert len(labels) == 0


def test_the_pipeline_still_refuses_an_empty_dataset_cleanly():
    """The shape fix must not turn a clear refusal into a silent empty run."""
    from app.models.forecaster import ThreatForecastingPipeline

    with pytest.raises(ValueError) as exc:
        ThreatForecastingPipeline().train_and_evaluate_all([], train_ratio=0.7)
    assert "insufficient" in str(exc.value).lower()


@pytest.mark.parametrize("lags", [1, 3, 5])
def test_empty_matrix_shape_is_stable_across_lag_settings(lags):
    X, y, _ = _extractor().build_dataset_instances([])
    stacked, _ = stack_lagged_windows(X, y, lags=lags)
    assert stacked.shape == (0, len(FEATURE_NAMES) * (lags + 1))
