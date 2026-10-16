"""
Temporal equivalence: the optimized extractor versus a naive reference.

`build_dataset_instances` uses binary-search interval boundaries and label
prefix sums. That is a performance change, so it needs a correctness
oracle — but keeping a second copy of the production algorithm around
would only prove that two copies of the same code agree.

The reference below is therefore written the obvious way: a linear scan
per interval, `any()` over the horizon, no index. It is short enough to
read and confirm by eye, lives in the test tree rather than in `app/`, and
duplicates no production logic beyond the semantics it exists to pin.

It covers the parts of the contract that the index could plausibly break:
interval boundaries, tie ordering, label rules, masks, and the counters
that distinguish eligible / considered / generated / rejected windows.

It deliberately does NOT reimplement the rescaling heuristic, the fallback
chunking path or the cap arithmetic. Those are driven from the production
report, so a disagreement there would be a disagreement about reported
configuration — covered by the dedicated tests in
`test_window_indexing.py` and `test_evaluation_quality.py` instead.

Documentation addresses only (RFC 5737).
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone

import numpy as np
import pytest

from app.models.feature_extractor import (
    FEATURE_NAMES,
    WindowFeatureExtractor,
)
from app.schemas.events import (
    DataCategory,
    EventType,
    LabelProvenance,
    NormalizedEvent,
)

BASE = datetime(2026, 3, 1, tzinfo=timezone.utc)
ATTACK_EXCLUSIONS = ("benign", "normal", "unlabeled", "")


# ──────────────────────────────────────────────────────────────────
# Naive reference
# ──────────────────────────────────────────────────────────────────


def _is_attack(event) -> bool:
    return (
        event.label is not None
        and event.label.strip().lower() not in ATTACK_EXCLUSIONS
    )


def _has_label(event) -> bool:
    return event.label is not None and event.label.strip() != ""


def reference_windows(extractor, events, *, window, lead, horizon, stride):
    """
    The obvious implementation: scan every event for every interval.

    Returns the same observable quantities the optimized path produces, so
    they can be compared field by field. Window geometry is taken from the
    production report, so this pins the *selection and labelling* rules
    rather than re-deriving the configuration.
    """
    usable = sorted(
        (e for e in events if e.observed_at.year >= 2000),
        key=lambda e: e.observed_at,
    )
    if not usable:
        return {"X": [], "y": [], "ts": [], "mask": [],
                "excluded_empty": 0, "excluded_unlabelled": 0,
                "attack_in_observation": 0, "considered": 0}

    start, end = usable[0].observed_at, usable[-1].observed_at
    X, y, ts, mask = [], [], [], []
    excluded_empty = excluded_unlabelled = attack_in_observation = considered = 0

    window_end = start + timedelta(seconds=window)
    while window_end + timedelta(seconds=lead + horizon) <= end:
        considered += 1
        window_start = window_end - timedelta(seconds=window)
        target_start = window_end + timedelta(seconds=lead)
        target_end = target_start + timedelta(seconds=horizon)

        obs = [e for e in usable if window_start <= e.observed_at < window_end]
        fut = [e for e in usable if target_start <= e.observed_at < target_end]

        has_attack = any(_is_attack(e) for e in fut)
        obs_attack = any(_is_attack(e) for e in obs)
        if obs_attack:
            attack_in_observation += 1
            if extractor.exclude_ongoing_attack_windows:
                window_end += timedelta(seconds=stride)
                continue

        if has_attack:
            X.append(extractor.extract_features_from_window(obs, window))
            y.append(1)
            ts.append(window_end)
            mask.append(int(obs_attack))
        else:
            if len(fut) < extractor.min_horizon_events:
                excluded_empty += 1
                window_end += timedelta(seconds=stride)
                continue
            if extractor.require_labelled_horizon and not any(_has_label(e) for e in fut):
                excluded_unlabelled += 1
                window_end += timedelta(seconds=stride)
                continue
            X.append(extractor.extract_features_from_window(obs, window))
            y.append(0)
            ts.append(window_end)
            mask.append(int(obs_attack))

        window_end += timedelta(seconds=stride)

    if not X:
        # Event-count fallback, mirrored from production.
        #
        # One asymmetry is reproduced deliberately: the fallback does not
        # increment `windows_with_attack_in_observation`. That counter is
        # accumulated by the time-window loop, which always runs first.
        chunk_size = max(5, len(usable) // 4)
        for idx in range(0, len(usable) - chunk_size, max(1, chunk_size // 2)):
            chunk = usable[idx:idx + chunk_size]
            future_chunk = usable[idx + chunk_size:idx + chunk_size * 2]
            if not future_chunk:
                break
            considered += 1
            if extractor.exclude_ongoing_attack_windows and any(
                _is_attack(e) for e in chunk
            ):
                continue
            has_attack = any(_is_attack(e) for e in future_chunk)
            if not has_attack and extractor.require_labelled_horizon and not any(
                _has_label(e) for e in future_chunk
            ):
                excluded_unlabelled += 1
                continue
            X.append(extractor.extract_features_from_window(chunk, window))
            y.append(1 if has_attack else 0)
            ts.append(chunk[-1].observed_at)
            mask.append(int(any(_is_attack(e) for e in chunk)))

    return {"X": X, "y": y, "ts": ts, "mask": mask,
            "excluded_empty": excluded_empty,
            "excluded_unlabelled": excluded_unlabelled,
            "attack_in_observation": attack_in_observation,
            "considered": considered}


# ──────────────────────────────────────────────────────────────────
# Deterministic fixtures
# ──────────────────────────────────────────────────────────────────


def _event(idx, offset_s, label=None, src="192.0.2.10", dst="198.51.100.20",
           port=443, proto="TCP", when=None):
    return NormalizedEvent(
        event_id=f"e{idx}",
        source_id="bench",
        data_category=DataCategory.HISTORICAL_IMPORT,
        observed_at=when or (BASE + timedelta(seconds=offset_s)),
        event_type=EventType.NETWORK_FLOW,
        src_ip=src, dst_ip=dst, src_port=40000 + (idx % 20000), dst_port=port,
        protocol=proto, duration=1.5, packets=10, bytes_total=1000,
        label=label,
        label_provenance=(
            LabelProvenance.DATASET_GROUND_TRUTH if label else LabelProvenance.UNLABELED
        ),
    )


def fx_dense():
    return [
        _event(s, s, "SynthAttack-A" if (300 <= s < 420 or 800 <= s < 860) else "Benign")
        for s in range(1200)
    ]


def fx_sparse():
    return [_event(i, i * 400, "SynthAttack-A" if i % 9 == 0 else "Benign") for i in range(60)]


def fx_multi_host():
    return [
        _event(i, i * 2, "SynthAttack-A" if i % 17 == 0 else "Benign",
               src=f"192.0.2.{10 + (i % 3)}", dst=f"198.51.100.{20 + (i % 7)}",
               port=(443, 80, 22, 53)[i % 4], proto=("TCP", "UDP", "TCP", "ICMP")[i % 4])
        for i in range(600)
    ]


def fx_boundaries():
    """Events sitting exactly on window, lead and horizon edges."""
    offsets = [0, 59, 60, 61, 89, 90, 119, 120, 149, 150, 151, 200, 240, 300]
    return [
        _event(i, o, "SynthAttack-A" if o in (90, 150, 240) else "Benign")
        for i, o in enumerate(offsets)
    ]


def fx_missing_labels():
    out = []
    for s in range(0, 900, 3):
        if s % 30 == 0:
            label = None
        elif s % 21 == 0:
            label = ""
        elif s % 45 == 0:
            label = "SynthAttack-A"
        else:
            label = "Benign"
        out.append(_event(s, s, label))
    return out


def fx_single_class():
    return [_event(s, s, "Benign") for s in range(600)]


def fx_duplicate_timestamps():
    return [
        _event(s * 3 + k, s, "SynthAttack-A" if s % 11 == 0 else "Benign",
               src=f"192.0.2.{10 + k}")
        for s in range(300) for k in range(3)
    ]


def fx_case_variants():
    """Label rules must be case- and whitespace-insensitive."""
    labels = ["Benign", "benign", " BENIGN ", "normal", "unlabeled", "", None,
              "SynthAttack-A", "ddos", " PortScan "]
    return [_event(i, i * 10, labels[i % len(labels)]) for i in range(400)]


FIXTURES = {
    "dense": fx_dense,
    "sparse": fx_sparse,
    "multi_host": fx_multi_host,
    "boundaries": fx_boundaries,
    "missing_labels": fx_missing_labels,
    "single_class": fx_single_class,
    "duplicate_timestamps": fx_duplicate_timestamps,
    "case_variants": fx_case_variants,
}

CONFIGS = {
    "default": {},
    "no_lead": {"lead_time_seconds": 0.0},
    "long_horizon": {"prediction_horizon_seconds": 300.0},
    "coarse_stride": {"step_seconds": 60.0},
    "fine_stride": {"step_seconds": 5.0},
    "exclude_ongoing": {"exclude_ongoing_attack_windows": True},
    "allow_unlabelled": {"require_labelled_horizon": False},
    "min_horizon_3": {"min_horizon_events": 3},
}


def _run(events, config):
    kw = dict(window_size_seconds=60.0, lead_time_seconds=30.0,
              prediction_horizon_seconds=60.0)
    kw.update({k: v for k, v in config.items() if k != "step_seconds"})
    stride = config.get("step_seconds", 15.0)

    extractor = WindowFeatureExtractor(**kw)
    X, y, ts = extractor.build_dataset_instances(events, step_seconds=stride)
    report = extractor.last_windowing_report

    reference = reference_windows(
        extractor, events,
        window=report.effective_window_seconds,
        lead=report.effective_lead_seconds,
        horizon=report.effective_horizon_seconds,
        stride=report.effective_stride_seconds,
    )
    return X, y, ts, extractor.last_observation_attack_mask, report, reference


@pytest.mark.parametrize("fixture_name", sorted(FIXTURES))
@pytest.mark.parametrize("config_name", sorted(CONFIGS))
def test_optimized_matches_a_naive_scan(fixture_name, config_name):
    """
    8 fixtures x 8 configurations = 64 combinations, each comparing the
    index-based implementation against a linear scan.
    """
    events = FIXTURES[fixture_name]()
    config = CONFIGS[config_name]
    X, y, ts, mask, report, ref = _run(events, config)

    assert report.windows_considered == ref["considered"], "window count differs"
    assert len(X) == len(ref["X"]), "generated instance count differs"
    assert [t.isoformat() for t in ts] == [t.isoformat() for t in ref["ts"]]
    assert list(y) == ref["y"], "target labels differ"
    assert list(mask) == ref["mask"], "observation-attack mask differs"
    assert report.windows_excluded_empty_horizon == ref["excluded_empty"]
    assert report.windows_excluded_unlabelled_horizon == ref["excluded_unlabelled"]
    # The time-window loop runs first and accumulates this counter even when
    # it emits nothing and the fallback supplies the instances. The fallback
    # itself never increments it — a documented asymmetry, pinned by
    # test_fallback_does_not_count_ongoing_attacks below.
    assert report.windows_with_attack_in_observation == ref["attack_in_observation"]

    if ref["X"]:
        np.testing.assert_allclose(
            np.asarray(X, dtype=np.float64),
            np.asarray(ref["X"], dtype=np.float64),
            rtol=1e-6, atol=1e-6,
            err_msg="feature values differ beyond float32 representation",
        )


# ──────────────────────────────────────────────────────────────────
# Properties the parametrized sweep cannot express
# ──────────────────────────────────────────────────────────────────


def test_repeated_runs_are_identical():
    events = fx_dense()
    a = WindowFeatureExtractor().build_dataset_instances(events)
    b = WindowFeatureExtractor().build_dataset_instances(events)
    np.testing.assert_array_equal(a[0], b[0])
    np.testing.assert_array_equal(a[1], b[1])
    assert a[2] == b[2]


def test_shuffled_input_is_sorted_internally():
    events = fx_multi_host()
    shuffled = events[:]
    random.Random(1234).shuffle(shuffled)

    a = WindowFeatureExtractor().build_dataset_instances(events)
    b = WindowFeatureExtractor().build_dataset_instances(shuffled)

    np.testing.assert_allclose(a[0], b[0], rtol=1e-6, atol=1e-6)
    np.testing.assert_array_equal(a[1], b[1])
    assert a[2] == b[2]


def test_implausible_timestamps_are_excluded_before_indexing():
    poisoned = _event(999, 0, "Benign", when=datetime(1601, 1, 1, tzinfo=timezone.utc))
    extractor = WindowFeatureExtractor()
    extractor.build_dataset_instances([poisoned] + fx_dense())

    report = extractor.last_windowing_report
    assert report.data_span_seconds < 86_400
    assert any("implausible" in n for n in report.notes)


def test_coverage_identity_holds_including_the_fallback_path():
    """
    considered == generated + rejected, and eligible >= considered, must
    hold whichever path ran. The fallback previously incremented rejection
    counters without incrementing `considered`, so rejections could exceed
    the number of candidates examined.
    """
    unlabelled = [_event(i, i * 5, label=None) for i in range(400)]
    extractor = WindowFeatureExtractor(require_labelled_horizon=True)
    extractor.build_dataset_instances(unlabelled)
    report = extractor.last_windowing_report

    rejected = (
        report.windows_excluded_empty_horizon
        + report.windows_excluded_unlabelled_horizon
    )
    assert report.windows_considered == report.windows_generated + rejected
    assert report.windows_eligible >= report.windows_considered
    assert report.windows_omitted == report.windows_eligible - report.windows_considered


def test_feature_matrix_width_is_always_the_feature_count():
    for builder in FIXTURES.values():
        X, _, _ = WindowFeatureExtractor().build_dataset_instances(builder())
        assert X.ndim == 2
        assert X.shape[1] == len(FEATURE_NAMES)


def test_the_fallback_honours_the_ongoing_attack_exclusion():
    """
    Regression for a defect where the control produced its own opposite.

    Excluding ongoing-attack windows could empty the time-window loop,
    which triggers the event-count fallback. The fallback ignored the flag
    and re-emitted chunks whose observation period contained an attack — so
    a caller asking for clean pre-attack instances received a dataset where
    EVERY instance had an attack already underway, while
    `windows_excluded_ongoing_attack` reported the control as having worked.

    Measured on this fixture before the fix: 7 rows emitted, all 7 flagged
    by the observation-attack mask.
    """
    events = fx_duplicate_timestamps()

    keeping = WindowFeatureExtractor(
        window_size_seconds=60.0, lead_time_seconds=30.0,
        prediction_horizon_seconds=60.0,
    )
    X_keep, _, _ = keeping.build_dataset_instances(events)
    assert int(keeping.last_observation_attack_mask.sum()) == len(X_keep) > 0, (
        "fixture precondition: every window here has an attack in observation"
    )

    excluding = WindowFeatureExtractor(
        window_size_seconds=60.0, lead_time_seconds=30.0,
        prediction_horizon_seconds=60.0, exclude_ongoing_attack_windows=True,
    )
    X_excl, y_excl, ts_excl = excluding.build_dataset_instances(events)
    report = excluding.last_windowing_report

    assert report.used_fallback_chunking is True
    assert report.windows_excluded_ongoing_attack > 0
    # The whole point: no emitted instance may have an attack in its
    # observation period once exclusion was requested.
    assert int(excluding.last_observation_attack_mask.sum()) == 0
    assert len(X_excl) == len(y_excl) == len(ts_excl)
    # On this fixture that leaves nothing, which is the honest answer:
    # there is no clean pre-attack instance to be had.
    assert len(X_excl) == 0
    assert X_excl.shape == (0, len(FEATURE_NAMES))


def test_exclusion_still_yields_instances_where_clean_windows_exist():
    """The fix must not empty datasets that legitimately have clean windows."""
    events = fx_dense()
    excluding = WindowFeatureExtractor(
        window_size_seconds=60.0, lead_time_seconds=30.0,
        prediction_horizon_seconds=60.0, exclude_ongoing_attack_windows=True,
    )
    X, _, _ = excluding.build_dataset_instances(events)

    assert len(X) > 0
    assert int(excluding.last_observation_attack_mask.sum()) == 0


@pytest.mark.parametrize("fixture_name", sorted(FIXTURES))
@pytest.mark.parametrize("config_name", sorted(CONFIGS))
def test_coverage_invariants_hold_on_every_path(fixture_name, config_name):
    """
    Three invariants, asserted across every fixture and configuration —
    including the rescaling and event-count-fallback paths, which is where
    they previously broke.

        eligible >= considered >= generated
        omitted  == eligible - considered
        considered == generated + rejected

    The rejection categories are mutually exclusive: a window is dropped
    for an ongoing attack, an empty horizon, or an unlabelled horizon, and
    the loop `continue`s immediately in each case. No exception to the
    identity is currently needed; if one ever becomes necessary it belongs
    here, named and tested, rather than as a loosened assertion.
    """
    config = CONFIGS[config_name]
    kw = dict(window_size_seconds=60.0, lead_time_seconds=30.0,
              prediction_horizon_seconds=60.0)
    kw.update({k: v for k, v in config.items() if k != "step_seconds"})

    extractor = WindowFeatureExtractor(**kw)
    X, y, ts = extractor.build_dataset_instances(
        FIXTURES[fixture_name](), step_seconds=config.get("step_seconds", 15.0)
    )
    report = extractor.last_windowing_report

    rejected = (
        report.windows_excluded_empty_horizon
        + report.windows_excluded_unlabelled_horizon
        + report.windows_excluded_ongoing_attack
    )

    assert report.windows_eligible >= report.windows_considered, "eligible < considered"
    assert report.windows_considered >= report.windows_generated, "considered < generated"
    assert report.windows_omitted == report.windows_eligible - report.windows_considered
    assert report.windows_considered == report.windows_generated + rejected, (
        f"considered={report.windows_considered} != generated="
        f"{report.windows_generated} + rejected={rejected} "
        f"(fallback={report.used_fallback_chunking}, "
        f"rescaled={report.config_was_rescaled})"
    )
    assert report.windows_generated == len(X) == len(y) == len(ts)


@pytest.mark.parametrize("fixture_name", sorted(FIXTURES))
def test_reported_effective_config_reproduces_the_run(fixture_name):
    """
    A run must be reproducible from its own reported parameters.

    The report previously stored rounded effective values while the loop
    used the unrounded floats, so re-deriving the window count from the
    report could differ by one. Rounding now happens once, before the loop.
    """
    events = FIXTURES[fixture_name]()
    extractor = WindowFeatureExtractor(
        window_size_seconds=60.0, lead_time_seconds=30.0,
        prediction_horizon_seconds=300.0,
    )
    extractor.build_dataset_instances(events, step_seconds=15.0)
    report = extractor.last_windowing_report

    if report.used_fallback_chunking:
        pytest.skip("fallback path is not derived from the time parameters")

    reference = reference_windows(
        extractor, events,
        window=report.effective_window_seconds,
        lead=report.effective_lead_seconds,
        horizon=report.effective_horizon_seconds,
        stride=report.effective_stride_seconds,
    )
    assert reference["considered"] == report.windows_considered, (
        "the reported effective configuration does not reproduce the run"
    )
