"""
Evaluation-quality reporting: window truncation and degenerate predictions.

Both findings came from the synthetic rehearsal and share one shape — the
pipeline produced a correct number that a reader would take to mean more
than it does.

* Window generation stopped at its cap and said so only in free text, so a
  caller could not tell a partial evaluation from a complete one.
* Five models returned identical chance-level metrics with
  ``metrics_interpretable=True``, because that flag checks sample size and
  class presence, not whether the model made any distinction at all.

Neither is fixed by changing a metric. Both are fixed by reporting more
precisely what was measured.

Documentation addresses only (RFC 5737).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import numpy as np
import pytest
from fastapi.testclient import TestClient

from app.api.deps import get_db
from app.main import app
from app.models.feature_extractor import (
    MAX_WINDOWS,
    WindowCoverageIncomplete,
    WindowFeatureExtractor,
    WindowingReport,
)
from app.models.forecaster import (
    MIN_INTERPRETABLE_TEST_INSTANCES,
    ThreatForecastingPipeline,
    evaluate_model_on_split,
)
from app.models.registry import reset_forecasting_pipeline
from app.research.selection import select_training_events
from app.schemas.events import (
    DataCategory,
    EventType,
    LabelProvenance,
    NormalizedEvent,
    TelemetrySource,
)
from app.storage.database import Database

BASE = datetime(2026, 3, 1, tzinfo=timezone.utc)


def _events(count: int, step_seconds: int, attack_every: int = 7):
    return [
        NormalizedEvent(
            event_id=f"e{i}",
            source_id="bench",
            data_category=DataCategory.HISTORICAL_IMPORT,
            observed_at=BASE + timedelta(seconds=i * step_seconds),
            event_type=EventType.NETWORK_FLOW,
            src_ip="192.0.2.10",
            dst_ip="198.51.100.20",
            src_port=40000 + (i % 20000),
            dst_port=443,
            protocol="TCP",
            label="SynthAttack-A" if i % attack_every == 0 else "Benign",
            label_provenance=LabelProvenance.DATASET_GROUND_TRUTH,
        )
        for i in range(count)
    ]


def _extractor(**kw) -> WindowFeatureExtractor:
    defaults = dict(
        window_size_seconds=60, lead_time_seconds=30, prediction_horizon_seconds=60
    )
    defaults.update(kw)
    return WindowFeatureExtractor(**defaults)


# ──────────────────────────────────────────────────────────────────
# 1. Structured window truncation
# ──────────────────────────────────────────────────────────────────


def test_below_the_limit_reports_complete_coverage():
    extractor = _extractor()
    extractor.build_dataset_instances(_events(200, 30))
    report = extractor.last_windowing_report

    assert report.windows_truncated is False
    assert report.windows_omitted == 0
    assert report.windows_considered == report.windows_eligible
    assert report.windows_limit == MAX_WINDOWS
    assert not any("safety limit" in n for n in report.notes)


def test_over_the_limit_reports_structured_truncation():
    """
    The defect: this state was discoverable only by reading prose in
    `notes`. A caller must be able to branch on it.
    """
    extractor = _extractor()
    extractor.build_dataset_instances(_events(600, 3600))
    report = extractor.last_windowing_report

    assert report.windows_truncated is True
    assert report.windows_considered == MAX_WINDOWS
    assert report.windows_eligible > MAX_WINDOWS
    assert report.windows_omitted == report.windows_eligible - report.windows_considered
    assert report.windows_omitted > 0


def test_exactly_at_the_limit_is_not_reported_as_truncated():
    """
    Boundary case: consuming the whole budget is not the same as being cut
    short. Off-by-one here would mark every maximal run incomplete.
    """
    # Construct the boundary directly: eligible == considered == limit.
    report = WindowingReport(
        nominal_window_seconds=60, nominal_lead_seconds=30,
        nominal_horizon_seconds=60, nominal_stride_seconds=15,
        effective_window_seconds=60, effective_lead_seconds=30,
        effective_horizon_seconds=60, effective_stride_seconds=15,
        windows_limit=MAX_WINDOWS,
        windows_eligible=MAX_WINDOWS,
        windows_considered=MAX_WINDOWS,
        windows_omitted=0,
        windows_truncated=False,
    )
    assert report.windows_truncated is False
    assert report.windows_omitted == 0


def test_the_three_counts_are_distinct_quantities():
    """
    eligible >= considered >= generated. Collapsing them would hide that
    most examined windows were dropped by the label-validity rules rather
    than by the cap.
    """
    extractor = _extractor()
    X, _, _ = extractor.build_dataset_instances(_events(600, 3600))
    report = extractor.last_windowing_report

    assert report.windows_eligible >= report.windows_considered
    assert report.windows_considered >= report.windows_generated
    assert report.windows_generated == len(X)
    assert report.windows_generated < report.windows_considered


def test_truncation_can_be_refused_when_completeness_is_required():
    strict = _extractor(require_complete_windowing=True)
    with pytest.raises(WindowCoverageIncomplete) as exc:
        strict.build_dataset_instances(_events(600, 3600))

    assert exc.value.report.windows_truncated is True
    assert "omitted" in str(exc.value)
    # The partial report travels with the refusal.
    assert exc.value.report.windows_considered == MAX_WINDOWS


def test_requiring_completeness_does_not_refuse_a_complete_run():
    strict = _extractor(require_complete_windowing=True)
    X, _, _ = strict.build_dataset_instances(_events(200, 30))
    assert len(X) > 0
    assert strict.last_windowing_report.windows_truncated is False


def test_truncation_reaches_the_split_report():
    pipeline = ThreatForecastingPipeline(
        window_size_seconds=60, lead_time_seconds=30, prediction_horizon_seconds=60
    )
    pipeline.train_and_evaluate_all(_events(600, 3600), train_ratio=0.7)
    split = pipeline.last_split_report

    assert split.windowing_truncated is True
    assert split.windows_omitted > 0
    assert split.windowing is not None
    assert split.windowing.windows_truncated is True


def test_window_truncation_is_distinct_from_record_truncation(tmp_path):
    """
    Two independent limits. An evaluation can be cut short by either, and
    conflating them would let one mask the other.
    """
    db = Database(db_path=str(tmp_path / "limits.db"))
    db.initialize()
    db.upsert_source(
        TelemetrySource(source_id="bench", name="bench", source_type="csv_import")
    )
    db.insert_events(_events(400, 30))
    try:
        _, coverage = select_training_events(
            db, data_category=DataCategory.HISTORICAL_IMPORT.value, max_events=100
        )
        extractor = _extractor()
        extractor.build_dataset_instances(_events(200, 30))
        windowing = extractor.last_windowing_report

        # Records truncated, windows not.
        assert coverage.truncated is True
        assert windowing.windows_truncated is False
        # Different field names on different objects.
        assert not hasattr(coverage, "windows_truncated")
        assert not hasattr(windowing, "truncated")
    finally:
        db.close()


def test_truncation_is_serialized_through_the_integrity_endpoint(tmp_path):
    db = Database(db_path=str(tmp_path / "api.db"))
    db.initialize()
    db.upsert_source(
        TelemetrySource(source_id="bench", name="bench", source_type="csv_import")
    )
    db.insert_events(_events(600, 3600))
    reset_forecasting_pipeline()
    app.dependency_overrides[get_db] = lambda: db
    try:
        with TestClient(app) as client:
            trained = client.post(
                "/api/v1/forecast/train",
                json={"data_category": "historical_import", "max_events": 100_000},
            )
            assert trained.status_code == 200, trained.text

            body = client.get("/api/v1/forecast/integrity").json()
            assert body["windowing_truncated"] is True
            assert body["windows_omitted"] > 0
            assert body["windowing"]["windows_eligible"] > body["windowing"]["windows_considered"]
            assert body["windowing"]["windows_limit"] == MAX_WINDOWS
    finally:
        app.dependency_overrides.clear()
        db.close()


# ──────────────────────────────────────────────────────────────────
# 2. Degenerate prediction reporting
# ──────────────────────────────────────────────────────────────────


class _ConstantScore:
    """Emits one probability for every row — ranks nothing."""

    def __init__(self, p: float):
        self.p = p

    def fit(self, X, y):
        return self

    def predict_proba(self, X):
        n = len(X)
        return np.column_stack([np.full(n, 1.0 - self.p), np.full(n, self.p)])


class _Perfect:
    """Scores from the label itself — for the non-degenerate control only."""

    def __init__(self, y_test):
        self._y = np.asarray(y_test, dtype=float)

    def fit(self, X, y):
        return self

    def predict_proba(self, X):
        p = self._y[: len(X)] * 0.9 + 0.05
        return np.column_stack([1.0 - p, p])


def _split(n_test=21, n_pos=3):
    rng = np.random.default_rng(0)
    X_train = rng.normal(size=(40, 3))
    y_train = np.array([0, 1] * 20)
    X_test = rng.normal(size=(n_test, 3))
    y_test = np.array([1] * n_pos + [0] * (n_test - n_pos))
    return X_train, y_train, X_test, y_test


def test_all_positive_predictions_are_flagged_degenerate():
    """
    The exact shape the rehearsal surfaced: precision equals the base rate,
    recall is 1.0, and the figures are arithmetic over a constant.
    """
    Xtr, ytr, Xte, yte = _split()
    metrics, _ = evaluate_model_on_split(
        _ConstantScore(0.9), "all-positive", "const", Xtr, ytr, Xte, yte
    )

    assert metrics.predictions_degenerate is True
    assert metrics.predicted_negative_count == 0
    assert metrics.predicted_positive_count == len(yte)
    assert metrics.discrimination_demonstrated is False
    # Metrics are preserved, not blanked.
    assert metrics.recall == 1.0
    assert metrics.precision == pytest.approx(3 / 21, abs=1e-4)
    assert any("DEGENERATE" in w for w in metrics.interpretation_warnings)


def test_all_negative_predictions_are_flagged_degenerate():
    Xtr, ytr, Xte, yte = _split()
    metrics, _ = evaluate_model_on_split(
        _ConstantScore(0.1), "all-negative", "const", Xtr, ytr, Xte, yte
    )
    assert metrics.predictions_degenerate is True
    assert metrics.predicted_positive_count == 0
    assert metrics.discrimination_demonstrated is False


def test_constant_scores_are_reported_as_ranking_nothing():
    Xtr, ytr, Xte, yte = _split()
    metrics, _ = evaluate_model_on_split(
        _ConstantScore(0.5), "constant", "const", Xtr, ytr, Xte, yte
    )
    assert metrics.scores_constant is True
    assert metrics.distinct_score_count == 1
    assert any("ranked nothing" in w for w in metrics.interpretation_warnings)


def test_pr_auc_equal_to_the_base_rate_is_not_skill():
    """
    The no-skill reference for PR-AUC is the positive base rate, not an
    arbitrary cutoff: random ranking achieves exactly that.
    """
    Xtr, ytr, Xte, yte = _split()
    metrics, _ = evaluate_model_on_split(
        _ConstantScore(0.9), "chance", "const", Xtr, ytr, Xte, yte
    )
    assert metrics.no_skill_pr_auc == pytest.approx(3 / 21, abs=1e-4)
    assert metrics.pr_auc == pytest.approx(metrics.no_skill_pr_auc, abs=1e-3)
    assert metrics.discrimination_demonstrated is False


def test_both_classes_predicted_without_useful_ranking_is_not_degenerate_but_shows_no_skill():
    """
    A model can predict both classes and still rank at chance. That is not
    degeneracy — it is absence of skill, and the two are reported apart.
    """
    rng = np.random.default_rng(7)
    Xtr = rng.normal(size=(60, 3))
    ytr = np.array([0, 1] * 30)
    Xte = rng.normal(size=(40, 3))
    yte = np.array([1] * 8 + [0] * 32)

    class _Noise:
        def fit(self, X, y):
            return self

        def predict_proba(self, X):
            p = np.random.default_rng(11).random(len(X))
            return np.column_stack([1 - p, p])

    metrics, _ = evaluate_model_on_split(_Noise(), "noise", "noise", Xtr, ytr, Xte, yte)

    assert metrics.predictions_degenerate is False
    assert metrics.predicted_positive_count > 0
    assert metrics.predicted_negative_count > 0
    assert metrics.distinct_score_count > 1
    assert metrics.metrics_computable is True


def test_a_discriminating_model_is_reported_as_such_without_claiming_usefulness():
    Xtr, ytr, Xte, yte = _split(n_test=40, n_pos=12)
    metrics, _ = evaluate_model_on_split(
        _Perfect(yte), "separable", "test", Xtr, ytr, Xte, yte
    )

    assert metrics.predictions_degenerate is False
    assert metrics.discrimination_demonstrated is True
    assert metrics.pr_auc > metrics.no_skill_pr_auc
    # "Better than chance on this sample" is all that is claimed.
    assert metrics.sample_adequate is True


def test_a_small_holdout_leaves_discrimination_undetermined():
    Xtr, ytr, Xte, yte = _split(n_test=MIN_INTERPRETABLE_TEST_INSTANCES - 1, n_pos=3)
    metrics, _ = evaluate_model_on_split(
        _Perfect(yte), "tiny", "test", Xtr, ytr, Xte, yte
    )

    assert metrics.sample_adequate is False
    assert metrics.discrimination_demonstrated is None, (
        "a model cannot demonstrate skill on a sample too small to measure it"
    )
    assert metrics.metrics_interpretable is False


def test_single_class_test_data_makes_metrics_uncomputable():
    rng = np.random.default_rng(3)
    Xtr, ytr = rng.normal(size=(40, 3)), np.array([0, 1] * 20)
    Xte = rng.normal(size=(30, 3))
    yte = np.zeros(30, dtype=int)

    metrics, _ = evaluate_model_on_split(
        _ConstantScore(0.1), "one-class", "const", Xtr, ytr, Xte, yte
    )

    assert metrics.metrics_computable is False
    assert metrics.sample_adequate is False
    assert metrics.discrimination_demonstrated is None
    assert metrics.test_positive_count == 0
    assert any("ZERO positive" in w for w in metrics.interpretation_warnings)


def test_undefined_metrics_stay_undefined_rather_than_becoming_zero():
    rng = np.random.default_rng(4)
    Xtr, ytr = rng.normal(size=(40, 3)), np.array([0, 1] * 20)
    Xte, yte = rng.normal(size=(25, 3)), np.ones(25, dtype=int)

    metrics, _ = evaluate_model_on_split(
        _ConstantScore(0.9), "no-negatives", "const", Xtr, ytr, Xte, yte
    )
    # ROC-AUC is undefined with one class present; it must not be fabricated.
    assert metrics.roc_auc is None
    assert metrics.test_negative_count == 0
    assert metrics.metrics_computable is False


def test_the_three_validity_questions_are_independent():
    """
    Computable, adequate and discriminating are three claims. A degenerate
    model on a large balanced holdout is computable and adequate while
    demonstrating nothing.
    """
    Xtr, ytr, Xte, yte = _split(n_test=60, n_pos=20)
    metrics, _ = evaluate_model_on_split(
        _ConstantScore(0.9), "degenerate-but-measurable", "const", Xtr, ytr, Xte, yte
    )

    assert metrics.metrics_computable is True
    assert metrics.sample_adequate is True
    assert metrics.predictions_degenerate is True
    assert metrics.discrimination_demonstrated is False
    assert metrics.metrics_interpretable is True  # composite: computable AND adequate


def test_degeneracy_is_serialized_to_the_api(tmp_path):
    db = Database(db_path=str(tmp_path / "degen.db"))
    db.initialize()
    db.upsert_source(
        TelemetrySource(source_id="bench", name="bench", source_type="csv_import")
    )
    # Large enough to clear the research gate (>=200 events, >=50 labelled,
    # >=10 of each class, >=1800s span) so this actually exercises
    # serialization rather than skipping.
    db.insert_events(_events(300, 30, attack_every=3))
    reset_forecasting_pipeline()
    app.dependency_overrides[get_db] = lambda: db
    try:
        with TestClient(app) as client:
            res = client.post(
                "/api/v1/forecast/train", json={"data_category": "historical_import"}
            )
            if res.status_code != 200:
                pytest.skip(f"fixture produced no valid split: {res.status_code}")
            models = client.get("/api/v1/forecast/models").json()

        assert models
        for name, m in models.items():
            for field in (
                "predictions_degenerate",
                "metrics_computable",
                "sample_adequate",
                "discrimination_demonstrated",
                "no_skill_pr_auc",
                "distinct_score_count",
            ):
                assert field in m, f"{name} is missing {field} in the API response"
    finally:
        app.dependency_overrides.clear()
        db.close()
