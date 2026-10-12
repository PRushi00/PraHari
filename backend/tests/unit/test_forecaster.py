"""
Unit tests for Causal Feature Extractor and Threat Forecasting Pipeline.
"""

import math
from datetime import datetime, timezone, timedelta
import pytest
import numpy as np

from app.schemas.events import NormalizedEvent, EventType, DataCategory, LabelProvenance
from app.models.feature_extractor import WindowFeatureExtractor, FEATURE_NAMES
from app.models.forecaster import (
    InsufficientEvaluationDataError,
    ThreatForecastingPipeline,
)


def test_window_feature_extractor():
    extractor = WindowFeatureExtractor(window_size_seconds=60.0)
    base_time = datetime(2026, 2, 15, 10, 0, 0, tzinfo=timezone.utc)

    events = [
        NormalizedEvent(
            source_id="test_flow",
            observed_at=base_time + timedelta(seconds=i * 5),
            event_type=EventType.NETWORK_FLOW,
            src_ip="192.168.1.10",
            dst_ip="10.0.0.1",
            src_port=40000 + i,
            dst_port=443,
            protocol="TCP",
            duration=1000.0,
            packets=10,
            bytes_total=1500,
            label="Benign",
        )
        for i in range(10)
    ]

    features = extractor.extract_features_from_window(events, window_duration=60.0)
    assert len(features) == len(FEATURE_NAMES)
    assert features[0] == 10.0  # flow_count
    assert features[1] == 1.0   # distinct_src_ips
    assert features[2] == 1.0   # distinct_dst_ips
    assert features[4] == 15000.0  # total_bytes
    assert features[8] == 1.0   # tcp_ratio


def _build_flows(
    count: int,
    base_time: datetime,
    step_seconds: float = 5.0,
    attack_period: int = 11,
    source_id: str = "sensor_forecast_test",
) -> list[NormalizedEvent]:
    """
    Build a chronological flow sequence with attack activity recurring
    throughout, so both the training period and the strictly-later evaluation
    period contain positive examples.
    """
    events: list[NormalizedEvent] = []
    for i in range(count):
        t = base_time + timedelta(seconds=i * step_seconds)
        is_attack = (i % attack_period) in (0, 1, 2)
        events.append(
            NormalizedEvent(
                source_id=source_id,
                observed_at=t,
                event_type=EventType.NETWORK_FLOW,
                src_ip="192.168.1.50" if not is_attack else "198.51.100.22",
                dst_ip="10.0.0.1",
                src_port=50000 + (i % 10000),
                dst_port=443 if not is_attack else 22,
                protocol="TCP",
                duration=500.0 if not is_attack else 50000.0,
                packets=5 if not is_attack else 25,
                bytes_total=500 if not is_attack else 12000,
                label="Benign" if not is_attack else "SSH-BruteForce",
                label_provenance=LabelProvenance.DATASET_GROUND_TRUTH,
            )
        )
    return events


def test_threat_forecasting_pipeline():
    pipeline = ThreatForecastingPipeline(
        window_size_seconds=30.0,
        lead_time_seconds=10.0,
        prediction_horizon_seconds=30.0,
    )

    base_time = datetime(2026, 2, 15, 8, 0, 0, tzinfo=timezone.utc)
    # 400 flows over ~2000s: long enough to support a leakage-free holdout
    # after the boundary purge. A 60-flow/300s sequence cannot, and the
    # pipeline now refuses it rather than reporting a contaminated score.
    events = _build_flows(400, base_time)

    metrics = pipeline.train_and_evaluate_all(events, train_ratio=0.7)

    # Confirm models were trained and evaluated
    assert "baseline_constant" in metrics
    assert "baseline_threshold" in metrics
    assert "logistic_regression" in metrics
    assert "random_forest_forecaster" in metrics

    rf_metric = metrics["random_forest_forecaster"]
    assert 0.0 <= rf_metric.accuracy <= 1.0
    assert 0.0 <= rf_metric.precision <= 1.0
    assert 0.0 <= rf_metric.recall <= 1.0
    assert 0.0 <= rf_metric.f1 <= 1.0

    # Test live prediction on recent window
    pred = pipeline.predict_recent_window(events[-15:], model_id="random_forest_forecaster")
    assert 0.0 <= pred.propensity_score <= 1.0
    assert isinstance(pred.predicted_incident, bool)
    assert len(pred.top_contributing_features) > 0


# ──────────────────────────────────────────────────────────────────
# Split integrity / leakage-prevention regression tests
# ──────────────────────────────────────────────────────────────────


def test_split_is_chronological_with_purge_and_no_overlap():
    """
    Training must end strictly before evaluation begins, with the
    contaminated boundary windows purged rather than reassigned.
    """
    pipeline = ThreatForecastingPipeline(
        window_size_seconds=30.0,
        lead_time_seconds=10.0,
        prediction_horizon_seconds=30.0,
    )
    events = _build_flows(400, datetime(2026, 3, 1, 9, 0, 0, tzinfo=timezone.utc))
    pipeline.train_and_evaluate_all(events, train_ratio=0.7)

    report = pipeline.last_split_report
    assert report is not None
    assert report.split_strategy == "chronological_train_side_purge"

    # A purge actually happened, sized to the contaminated span (W+L+H)/S.
    assert report.embargo_windows == math.ceil((30.0 + 10.0 + 30.0) / 15.0)
    assert report.purged_instances >= report.embargo_windows - 1
    assert report.purged_instances > 0

    # No instance is in both splits, and all of them are accounted for.
    assert report.train_instances + report.purged_instances + report.test_instances == (
        report.total_instances
    )

    # Training genuinely precedes evaluation in wall-clock time.
    assert report.train_end_timestamp is not None
    assert report.test_start_timestamp is not None
    assert report.train_end_timestamp < report.test_start_timestamp

    # The gap between them covers the contaminated span, so no training
    # label describes data that a test window observes.
    gap = (report.test_start_timestamp - report.train_end_timestamp).total_seconds()
    assert gap >= 30.0 + 10.0 + 30.0


def test_training_refused_when_span_too_short_for_leakage_free_holdout():
    """
    A dataset too short to purge must be refused, not evaluated on its own
    training data.
    """
    pipeline = ThreatForecastingPipeline(
        window_size_seconds=30.0,
        lead_time_seconds=10.0,
        prediction_horizon_seconds=30.0,
    )
    # 30 flows over ~145s: too short to leave an adequate training period
    # once the contaminated boundary windows are purged.
    events = _build_flows(30, datetime(2026, 3, 1, 9, 0, 0, tzinfo=timezone.utc))

    with pytest.raises(InsufficientEvaluationDataError) as exc:
        pipeline.train_and_evaluate_all(events, train_ratio=0.7)

    assert exc.value.split_report is not None
    # The refusal explains itself rather than failing opaquely.
    assert "refused" in str(exc.value).lower()
    # Crucially, no metrics were recorded from a contaminated split.
    assert pipeline.model_metrics == {}


def test_training_refused_when_training_period_is_single_class():
    """
    Attacks occurring only after the training period must not be dragged
    backwards into training to manufacture class balance.
    """
    pipeline = ThreatForecastingPipeline(
        window_size_seconds=30.0,
        lead_time_seconds=10.0,
        prediction_horizon_seconds=30.0,
    )
    base = datetime(2026, 3, 1, 9, 0, 0, tzinfo=timezone.utc)
    events: list[NormalizedEvent] = []
    for i in range(400):
        # All attack activity confined to the final fifth of the timeline.
        is_attack = i >= 320
        events.append(
            NormalizedEvent(
                source_id="late_attack_sensor",
                observed_at=base + timedelta(seconds=i * 5),
                event_type=EventType.NETWORK_FLOW,
                src_ip="192.168.1.50" if not is_attack else "198.51.100.22",
                dst_ip="10.0.0.1",
                src_port=50000 + i,
                dst_port=443 if not is_attack else 22,
                protocol="TCP",
                duration=500.0,
                packets=5,
                bytes_total=500,
                label="Benign" if not is_attack else "SSH-BruteForce",
                label_provenance=LabelProvenance.DATASET_GROUND_TRUTH,
            )
        )

    with pytest.raises(InsufficientEvaluationDataError):
        pipeline.train_and_evaluate_all(events, train_ratio=0.7)
    assert pipeline.model_metrics == {}


def test_metrics_flagged_uninterpretable_without_positive_test_examples():
    """
    Metrics computed on a holdout with no attack windows must carry an
    explicit warning and must not be marked interpretable.
    """
    from app.models.forecaster import evaluate_model_on_split, BaselineConstantModel

    X_train = np.array([[1.0] * len(FEATURE_NAMES)] * 10, dtype=np.float32)
    y_train = np.array([0, 1] * 5, dtype=np.int32)
    X_test = np.array([[1.0] * len(FEATURE_NAMES)] * 8, dtype=np.float32)
    y_test = np.zeros(8, dtype=np.int32)  # zero positives

    metrics, _ = evaluate_model_on_split(
        BaselineConstantModel(), "Majority", "baseline_constant",
        X_train, y_train, X_test, y_test,
    )

    assert metrics.test_positive_count == 0
    assert metrics.metrics_interpretable is False
    assert any("ZERO positive" in w for w in metrics.interpretation_warnings)


def test_prediction_is_labelled_unvalidated_without_a_trained_model():
    """
    An untrained pipeline may still emit a number, but it must be explicitly
    marked as unvalidated and non-actionable.
    """
    pipeline = ThreatForecastingPipeline()
    events = _build_flows(20, datetime(2026, 3, 1, 9, 0, 0, tzinfo=timezone.utc))

    pred = pipeline.predict_recent_window(events, model_id="random_forest_forecaster")

    assert pred.is_validated_model is False
    assert pred.validation_status == "no_model_trained"
    assert pred.is_actionable_forecast is False
    assert "UNVALIDATED" in pred.interpretation
    assert any("No trained model" in c for c in pred.evaluation_caveats)


def test_prediction_bounds_inference_to_the_observation_window():
    """
    Inference features must be computed over the same W-second window used in
    training, not over an arbitrary span of supplied events.
    """
    pipeline = ThreatForecastingPipeline(window_size_seconds=60.0)
    base = datetime(2026, 3, 1, 9, 0, 0, tzinfo=timezone.utc)

    # Events spread over 2 hours; only the last 60s should inform the score.
    old_events = _build_flows(30, base, step_seconds=200.0)
    recent = _build_flows(5, base + timedelta(seconds=6000), step_seconds=5.0)

    pred = pipeline.predict_recent_window(old_events + recent)

    assert pred.observation_window_seconds == 60.0
    assert pred.observation_event_count == len(recent)
    assert pred.observation_window_end == max(e.observed_at for e in recent)


def test_single_corrupt_timestamp_cannot_cause_unbounded_windowing():
    """
    Regression (denial of service): one FILETIME-epoch record implied a span
    of ~425 years, so the windowing loop attempted ~895 million iterations
    and hung the request thread indefinitely.
    """
    import time as _time

    extractor = WindowFeatureExtractor(60.0, 30.0, 60.0)
    base = datetime(2026, 3, 1, 9, 0, 0, tzinfo=timezone.utc)
    events = _build_flows(300, base, step_seconds=5.0)
    events.append(
        NormalizedEvent(
            source_id="bad",
            observed_at=datetime(1601, 1, 1, tzinfo=timezone.utc),
            event_type=EventType.NETWORK_FLOW,
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=1,
            dst_port=443,
            protocol="TCP",
            label="Benign",
        )
    )

    started = _time.time()
    X, y, ts = extractor.build_dataset_instances(events, step_seconds=15.0)
    elapsed = _time.time() - started

    assert elapsed < 5.0, f"windowing took {elapsed:.1f}s — unbounded work regression"
    assert 0 < len(X) < 10_000

    report = extractor.last_windowing_report
    assert report is not None
    assert any("implausible timestamps" in n for n in report.notes)


def test_window_count_is_hard_capped():
    """Even with a plausible but enormous span, window count stays bounded."""
    from app.models.feature_extractor import MAX_WINDOWS

    extractor = WindowFeatureExtractor(60.0, 30.0, 60.0)
    base = datetime(2020, 1, 1, tzinfo=timezone.utc)
    # Two events five years apart: a legitimate range, but far too wide for
    # a 15s stride to enumerate.
    events = [
        NormalizedEvent(
            source_id="s",
            observed_at=base,
            event_type=EventType.NETWORK_FLOW,
            src_ip="10.0.0.1", dst_ip="10.0.0.2",
            src_port=1, dst_port=443, protocol="TCP", label="Benign",
        ),
        NormalizedEvent(
            source_id="s",
            observed_at=base + timedelta(days=365 * 5),
            event_type=EventType.NETWORK_FLOW,
            src_ip="10.0.0.1", dst_ip="10.0.0.2",
            src_port=2, dst_port=443, protocol="TCP", label="PortScan",
        ),
    ]

    X, y, ts = extractor.build_dataset_instances(events, step_seconds=15.0)
    assert len(X) <= MAX_WINDOWS
    assert any("safety limit" in n for n in extractor.last_windowing_report.notes)


def test_windowing_report_discloses_rescaled_configuration():
    """
    When a short dataset forces the nominal W/L/H/S to be rescaled, the
    report must say so, so no result can cite the nominal parameters.
    """
    extractor = WindowFeatureExtractor(
        window_size_seconds=60.0,
        lead_time_seconds=30.0,
        prediction_horizon_seconds=60.0,
    )
    base = datetime(2026, 3, 1, 9, 0, 0, tzinfo=timezone.utc)
    short_events = _build_flows(30, base, step_seconds=4.0)  # ~116s span

    extractor.build_dataset_instances(short_events, step_seconds=15.0)
    report = extractor.last_windowing_report

    assert report is not None
    assert report.config_was_rescaled is True
    assert report.uses_nominal_config is False
    assert report.effective_window_seconds < report.nominal_window_seconds
    assert any("rescaled" in n for n in report.notes)


def test_windowing_report_confirms_nominal_configuration_on_adequate_data():
    """On an adequately long dataset the nominal configuration is used as-is."""
    extractor = WindowFeatureExtractor(
        window_size_seconds=60.0,
        lead_time_seconds=30.0,
        prediction_horizon_seconds=60.0,
    )
    base = datetime(2026, 3, 1, 9, 0, 0, tzinfo=timezone.utc)
    # ~3000s span with attacks recurring every ~200s, so the 60s horizon
    # yields a genuine mix of positive and negative windows.
    events = _build_flows(600, base, step_seconds=5.0, attack_period=40)

    extractor.build_dataset_instances(events, step_seconds=15.0)
    report = extractor.last_windowing_report

    assert report is not None
    assert report.config_was_rescaled is False
    assert report.used_fallback_chunking is False
    assert report.uses_nominal_config is True
    assert report.effective_window_seconds == 60.0
    assert report.effective_horizon_seconds == 60.0
    assert report.windows_generated > 100
    assert report.positive_windows > 0 and report.negative_windows > 0


# ──────────────────────────────────────────────────────────────────
# Negative-label validity (blueprint section 7)
# ──────────────────────────────────────────────────────────────────
#
# "y_t = 0 only when the observation window is complete enough to support
# a negative label." Absence of an attack label is not evidence of absence
# of attack.


def _event(observed_at, label, source="s", port=443):
    return NormalizedEvent(
        source_id=source,
        observed_at=observed_at,
        event_type=EventType.NETWORK_FLOW,
        src_ip="192.0.2.10",
        dst_ip="198.51.100.9",
        src_port=40000,
        dst_port=port,
        protocol="TCP",
        label=label,
        label_provenance=(
            LabelProvenance.DATASET_GROUND_TRUTH if label else LabelProvenance.UNLABELED
        ),
    )


def test_empty_horizon_is_excluded_not_labelled_negative():
    """
    A horizon containing NO observation is a capture gap. Labelling it 0
    would record "no attack occurred" from an absence of data.
    """
    extractor = WindowFeatureExtractor(30.0, 10.0, 30.0)
    base = datetime(2026, 4, 1, 9, 0, 0, tzinfo=timezone.utc)

    # Dense activity, then a long silent gap, then activity again.
    events = [_event(base + timedelta(seconds=i * 2), "Benign") for i in range(30)]
    events += [
        _event(base + timedelta(seconds=600 + i * 2), "Benign") for i in range(30)
    ]

    X, y, ts = extractor.build_dataset_instances(events, step_seconds=15.0)
    report = extractor.last_windowing_report

    assert report is not None
    assert report.windows_excluded_empty_horizon > 0, (
        "windows whose horizon spans the gap must be excluded"
    )
    assert len(X) == len(y) == len(ts)
    assert any("EXCLUDED rather than labelled negative" in n for n in report.notes)


def test_unlabelled_horizon_is_excluded_not_treated_as_benign():
    """
    Traffic observed but carrying no ground truth cannot establish a
    negative. This is the same rule the readiness gate enforces.
    """
    extractor = WindowFeatureExtractor(30.0, 10.0, 30.0)
    base = datetime(2026, 4, 1, 9, 0, 0, tzinfo=timezone.utc)

    # Entirely unlabelled traffic — exactly what live collection produces.
    events = [_event(base + timedelta(seconds=i * 3), None) for i in range(120)]

    X, y, ts = extractor.build_dataset_instances(events, step_seconds=15.0)
    report = extractor.last_windowing_report

    assert report is not None
    # Nothing may be labelled negative from unlabelled traffic.
    assert len(X) == 0, "unlabelled traffic must yield no usable windows"
    assert report.windows_excluded_unlabelled_horizon > 0


def test_labelled_benign_horizon_does_produce_a_valid_negative():
    """A horizon with confirmed-benign labels IS a valid negative."""
    extractor = WindowFeatureExtractor(30.0, 10.0, 30.0)
    base = datetime(2026, 4, 1, 9, 0, 0, tzinfo=timezone.utc)
    events = [_event(base + timedelta(seconds=i * 3), "Benign") for i in range(120)]

    X, y, ts = extractor.build_dataset_instances(events, step_seconds=15.0)
    report = extractor.last_windowing_report

    assert len(X) > 0
    assert set(y.tolist()) == {0}
    assert report.windows_excluded_unlabelled_horizon == 0


def test_positive_labels_are_always_valid():
    """
    A positive needs no completeness argument: the attack evidence is
    present in the horizon regardless of what else is or is not there.
    """
    extractor = WindowFeatureExtractor(30.0, 10.0, 30.0)
    base = datetime(2026, 4, 1, 9, 0, 0, tzinfo=timezone.utc)

    events = [_event(base + timedelta(seconds=i * 3), "Benign") for i in range(40)]
    # A single attack event inside an otherwise unlabelled later period.
    events += [_event(base + timedelta(seconds=130 + i * 3), None) for i in range(20)]
    events += [_event(base + timedelta(seconds=160), "PortScan")]

    X, y, ts = extractor.build_dataset_instances(events, step_seconds=15.0)
    assert 1 in y.tolist(), "an attack-labelled horizon must yield a positive"


def test_requirement_can_be_relaxed_explicitly_for_labelled_datasets():
    """
    A fully labelled historical dataset may legitimately opt out, but it
    must be an explicit decision rather than the silent default.
    """
    strict = WindowFeatureExtractor(30.0, 10.0, 30.0)
    assert strict.require_labelled_horizon is True

    relaxed = WindowFeatureExtractor(30.0, 10.0, 30.0, require_labelled_horizon=False)
    base = datetime(2026, 4, 1, 9, 0, 0, tzinfo=timezone.utc)
    events = [_event(base + timedelta(seconds=i * 3), None) for i in range(120)]

    X, y, _ = relaxed.build_dataset_instances(events, step_seconds=15.0)
    assert len(X) > 0
    assert relaxed.last_windowing_report.require_labelled_horizon is False
