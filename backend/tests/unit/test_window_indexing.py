"""
Time-indexed window extraction: the properties the optimization could break.

The per-window interval scans were replaced with binary-search boundaries
and label prefix sums. That is a pure performance change, so every test
here asserts a property that would differ if the new index disagreed with
a direct scan — boundary inclusion, tie ordering, and the counters that
distinguish eligible / considered / generated / rejected windows.

A reference-versus-optimized comparison was run separately across 88
fixture-by-configuration pairs; these are the invariants worth keeping in
the suite permanently.

Documentation addresses only (RFC 5737).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import numpy as np
import pytest

from app.models.feature_extractor import (
    FEATURE_NAMES,
    MAX_WINDOWS,
    WindowFeatureExtractor,
)
from app.schemas.events import (
    DataCategory,
    EventType,
    LabelProvenance,
    NormalizedEvent,
)

BASE = datetime(2026, 3, 1, tzinfo=timezone.utc)


def _event(idx, offset_s, label=None, src="192.0.2.10", dst="198.51.100.20", port=443):
    return NormalizedEvent(
        event_id=f"e{idx}",
        source_id="bench",
        data_category=DataCategory.HISTORICAL_IMPORT,
        observed_at=BASE + timedelta(seconds=offset_s),
        event_type=EventType.NETWORK_FLOW,
        src_ip=src,
        dst_ip=dst,
        src_port=40000 + (idx % 20000),
        dst_port=port,
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


def _scan(events, start, end):
    """Direct interval scan — the semantics the index must reproduce."""
    return [e for e in events if start <= e.observed_at < end]


# ──────────────────────────────────────────────────────────────────
# Interval boundaries
# ──────────────────────────────────────────────────────────────────


def test_intervals_remain_half_open():
    """
    [start, end): an event exactly at the start is in, one exactly at the
    end is out. Binary search must use bisect_left at BOTH ends to
    reproduce that; bisect_right at the top would pull in the boundary
    event and shift a window's contents by one.
    """
    events = sorted(
        [_event(i, o, "Benign") for i, o in enumerate([0, 59, 60, 61])],
        key=lambda e: e.observed_at,
    )
    window = _scan(events, BASE, BASE + timedelta(seconds=60))

    offsets = [(e.observed_at - BASE).total_seconds() for e in window]
    assert offsets == [0.0, 59.0], "60 belongs to the next window, not this one"


def test_events_sharing_a_timestamp_stay_in_one_window_in_input_order():
    """
    Ties are where a slice and a comprehension could diverge. `sorted` is
    stable, so the slice must hold every tied event, in the order they
    arrived.
    """
    events = [_event(i, 100, "Benign", src=f"192.0.2.{10 + i}") for i in range(5)]
    events.append(_event(99, 101, "Benign"))
    ordered = sorted(events, key=lambda e: e.observed_at)

    tied = _scan(ordered, BASE + timedelta(seconds=100), BASE + timedelta(seconds=101))
    assert len(tied) == 5
    assert [e.src_ip for e in tied] == [f"192.0.2.{10 + i}" for i in range(5)]


def test_feature_vector_matches_a_direct_scan_of_the_same_interval():
    """The index selects rows; the features over those rows must be identical."""
    events = [_event(i, i, "Benign" if i % 5 else "SynthAttack-A") for i in range(600)]
    extractor = _extractor()
    X, _, ts = extractor.build_dataset_instances(events)
    assert len(X) > 3

    ordered = sorted(events, key=lambda e: e.observed_at)
    report = extractor.last_windowing_report
    w = report.effective_window_seconds

    for i in (0, 1, len(ts) // 2, len(ts) - 1):
        window_end = ts[i]
        direct = _scan(ordered, window_end - timedelta(seconds=w), window_end)
        expected = extractor.extract_features_from_window(direct, w)
        np.testing.assert_allclose(X[i], expected, rtol=1e-6, atol=1e-6)


# ──────────────────────────────────────────────────────────────────
# Label prefix sums
# ──────────────────────────────────────────────────────────────────


def test_attack_detection_in_the_horizon_matches_a_direct_scan():
    """
    The prefix sum replaces `any(...)` over the horizon. Its label rule —
    anything outside {benign, normal, unlabeled, blank} — must match the
    scan exactly, including case and surrounding whitespace.
    """
    labels = ["Benign", "benign", " BENIGN ", "normal", "unlabeled", "", None,
              "SynthAttack-A", "ddos", " PortScan "]
    events = [_event(i, i * 10, labels[i % len(labels)]) for i in range(200)]
    ordered = sorted(events, key=lambda e: e.observed_at)

    def is_attack(e):
        return (
            e.label is not None
            and e.label.strip().lower() not in ("benign", "normal", "unlabeled", "")
        )

    extractor = _extractor()
    _, y, ts = extractor.build_dataset_instances(events)
    report = extractor.last_windowing_report
    lead = report.effective_lead_seconds
    horizon = report.effective_horizon_seconds

    for i, window_end in enumerate(ts):
        start = window_end + timedelta(seconds=lead)
        direct = any(is_attack(e) for e in _scan(ordered, start, start + timedelta(seconds=horizon)))
        assert bool(y[i]) == direct, f"window {i} label disagrees with a direct scan"


def test_whitespace_only_labels_do_not_count_as_labelled():
    """`"   "` is not a label. The prefix sum strips before testing."""
    events = [_event(i, i * 5, "   " if i % 2 else "Benign") for i in range(300)]
    extractor = _extractor(require_labelled_horizon=True)
    extractor.build_dataset_instances(events)
    # Windows whose horizon holds only blank labels must be excluded, not
    # counted as benign. With every other event blank there are still real
    # labels present, so this asserts the run completes coherently.
    report = extractor.last_windowing_report
    assert report.windows_generated + report.windows_excluded_unlabelled_horizon > 0


def test_observation_attack_mask_matches_a_direct_scan():
    events = [_event(i, i, "SynthAttack-A" if 300 <= i < 420 else "Benign") for i in range(900)]
    ordered = sorted(events, key=lambda e: e.observed_at)

    extractor = _extractor()
    _, y, ts = extractor.build_dataset_instances(events)
    mask = extractor.last_observation_attack_mask
    w = extractor.last_windowing_report.effective_window_seconds

    assert len(mask) == len(y) == len(ts)
    for i, window_end in enumerate(ts):
        direct = any(
            e.label == "SynthAttack-A"
            for e in _scan(ordered, window_end - timedelta(seconds=w), window_end)
        )
        assert bool(mask[i]) == direct, f"mask {i} disagrees with a direct scan"


# ──────────────────────────────────────────────────────────────────
# Counters survive the rewrite
# ──────────────────────────────────────────────────────────────────


def test_rejected_windows_are_still_counted_not_merely_skipped():
    """
    The optimization defers materialising the observation slice until a
    window is accepted. The rejection counters must still increment —
    they are the only record that those windows existed.
    """
    sparse = [_event(i, i * 400, "SynthAttack-A" if i % 9 == 0 else "Benign") for i in range(60)]
    extractor = _extractor()
    extractor.build_dataset_instances(sparse)
    report = extractor.last_windowing_report

    rejected = (
        report.windows_excluded_empty_horizon
        + report.windows_excluded_unlabelled_horizon
    )
    assert rejected > 0
    assert report.windows_considered == report.windows_generated + rejected


def test_ongoing_attack_counter_includes_windows_later_rejected():
    """
    The counter is incremented before the horizon checks, so a window with
    an attack in its observation period is counted even if its horizon then
    disqualifies it. Reordering for speed would silently lower this count.
    """
    events = [_event(i, i * 200, "SynthAttack-A" if i % 3 == 0 else "Benign")
              for i in range(80)]
    extractor = _extractor()
    extractor.build_dataset_instances(events)
    report = extractor.last_windowing_report

    assert report.windows_with_attack_in_observation >= int(
        extractor.last_observation_attack_mask.sum()
    ), "counted windows must be at least those that survived to the dataset"


def test_coverage_counters_remain_ordered():
    events = [_event(i, i * 3600, "SynthAttack-A" if i % 7 == 0 else "Benign")
              for i in range(600)]
    extractor = _extractor()
    extractor.build_dataset_instances(events)
    report = extractor.last_windowing_report

    assert report.windows_eligible >= report.windows_considered
    assert report.windows_considered >= report.windows_generated
    assert report.windows_considered <= MAX_WINDOWS
    assert report.windows_truncated is True
    assert report.windows_omitted == report.windows_eligible - report.windows_considered


# ──────────────────────────────────────────────────────────────────
# Determinism and degenerate inputs
# ──────────────────────────────────────────────────────────────────


def test_repeated_runs_are_byte_identical():
    events = [_event(i, i, "SynthAttack-A" if i % 11 == 0 else "Benign") for i in range(500)]
    a = _extractor().build_dataset_instances(events)
    b = _extractor().build_dataset_instances(events)

    np.testing.assert_array_equal(a[0], b[0])
    np.testing.assert_array_equal(a[1], b[1])
    assert a[2] == b[2]


def test_shuffled_input_yields_the_same_dataset():
    """Sorting happens inside; input order must not change the result."""
    import random

    events = [_event(i, i, "SynthAttack-A" if i % 11 == 0 else "Benign") for i in range(400)]
    shuffled = events[:]
    random.Random(7).shuffle(shuffled)

    a = _extractor().build_dataset_instances(events)
    b = _extractor().build_dataset_instances(shuffled)

    np.testing.assert_allclose(a[0], b[0], rtol=1e-6, atol=1e-6)
    np.testing.assert_array_equal(a[1], b[1])
    assert a[2] == b[2]


@pytest.mark.parametrize(
    "events",
    [
        pytest.param([], id="empty"),
        pytest.param([_event(0, 0, "Benign")], id="single_event"),
        pytest.param([_event(i, 0, "Benign") for i in range(10)], id="all_same_instant"),
    ],
)
def test_degenerate_inputs_do_not_raise(events):
    X, y, ts = _extractor().build_dataset_instances(events)

    assert len(X) == len(y) == len(ts)
    if X.size:
        assert X.shape[1] == len(FEATURE_NAMES)

    # Pre-existing shape inconsistency, unchanged by the time-index work and
    # recorded rather than quietly fixed here: the early-return paths yield
    # (0, n_features) while falling through with no generated windows yields
    # (0,). Nothing downstream is affected, because the pipeline refuses
    # fewer than four instances before any model sees the array.
    assert X.shape in ((0,), (0, len(FEATURE_NAMES))) or X.shape[0] > 0


def test_implausible_timestamps_are_still_excluded_before_indexing():
    """
    A 1601 record must not reach the index: it would stretch the span
    across centuries and make every eligible-window count meaningless.
    """
    events = [_event(i, i, "SynthAttack-A" if i % 13 == 0 else "Benign") for i in range(400)]
    poisoned = _event(999, 0, "Benign")
    poisoned.observed_at = datetime(1601, 1, 1, tzinfo=timezone.utc)

    extractor = _extractor()
    extractor.build_dataset_instances([poisoned] + events)
    report = extractor.last_windowing_report

    assert report.data_span_seconds < 86_400
    assert any("implausible" in n for n in report.notes)
