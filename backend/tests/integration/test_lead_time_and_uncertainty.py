"""
Lead-time curve, bootstrap uncertainty, and the temporal model.

These exist to keep three specific forms of overclaiming out:

  * a lead-time curve that silently omits the leads where no honest
    evaluation was possible, making it look flat where it is undefined;
  * a confidence interval computed from a holdout too small to support one;
  * a "temporal" model that is really the same snapshot classifier, or one
    whose lag features reach back across the train/test boundary.
"""

from __future__ import annotations

import numpy as np
import pytest
from fastapi.testclient import TestClient

from app.adapters.synthetic_replay import SyntheticFlowGenerator
from app.api.deps import get_db
from app.main import app
from app.models.forecaster import (
    TEMPORAL_LAGS,
    ThreatForecastingPipeline,
    stack_lagged_windows,
)
from app.models.registry import reset_forecasting_pipeline
from app.research.evaluation import (
    MIN_BOOTSTRAP_INSTANCES,
    MIN_BOOTSTRAP_POSITIVES,
    bootstrap_interval,
    lead_time_curve,
)
from app.schemas.events import TelemetrySource
from app.storage.database import Database


@pytest.fixture
def events():
    return SyntheticFlowGenerator(seed=5, source_id="s").generate_scenario_batch(
        count=900, attack_ratio=0.3
    )


@pytest.fixture
def client(tmp_path, events):
    db = Database(db_path=str(tmp_path / "lead.db"))
    db.initialize()
    db.upsert_source(
        TelemetrySource(source_id="s", name="S", source_type="synthetic_replay")
    )
    db.insert_events(events)
    reset_forecasting_pipeline()
    app.dependency_overrides[get_db] = lambda: db
    with TestClient(app) as c:
        yield c, db
    app.dependency_overrides.clear()
    db.close()


# ──────────────────────────────────────────────────────────────────
# Temporal model
# ──────────────────────────────────────────────────────────────────


def test_lag_stacking_builds_sequences_and_preserves_order():
    X = np.arange(20, dtype=float).reshape(10, 2)
    y = np.array([0, 0, 1, 0, 1, 1, 0, 0, 1, 0])

    Xs, ys = stack_lagged_windows(X, y, lags=2)

    assert Xs.shape == (8, 6), "each row must hold 3 consecutive windows"
    assert len(ys) == 8
    # Row 0 is windows 0,1,2 in that order — the sequence, not a bag.
    np.testing.assert_array_equal(Xs[0], np.array([0, 1, 2, 3, 4, 5], dtype=float))
    np.testing.assert_array_equal(ys, y[2:])


def test_lag_stacking_is_not_order_invariant():
    """If reversing the sequence gave the same input it would not be temporal."""
    X = np.arange(12, dtype=float).reshape(6, 2)
    y = np.zeros(6, dtype=int)
    forward, _ = stack_lagged_windows(X, y, lags=1)
    backward, _ = stack_lagged_windows(X[::-1], y, lags=1)
    assert not np.array_equal(forward, backward[::-1])


def test_lag_stacking_refuses_when_there_is_no_history():
    X = np.ones((2, 3))
    y = np.array([0, 1])
    Xs, ys = stack_lagged_windows(X, y, lags=5)
    assert len(Xs) == 0 and len(ys) == 0

    with pytest.raises(ValueError):
        stack_lagged_windows(X, y, lags=0)


def test_temporal_model_is_evaluated_on_the_same_split(events):
    pipeline = ThreatForecastingPipeline()
    metrics = pipeline.train_and_evaluate_all(events, train_ratio=0.7)

    assert "temporal_window_stack" in metrics, "the temporal model did not run"
    temporal = metrics["temporal_window_stack"]
    snapshot = metrics["random_forest_forecaster"]

    # Same protocol, so the holdout differs only by the dropped lag prefix.
    assert temporal.test_instances == snapshot.test_instances - TEMPORAL_LAGS
    assert temporal.model_type == "temporal_window_stack"


def test_temporal_holdout_truth_is_stored_separately(events):
    """
    Its holdout is shorter. Resampling its scores against another model's
    labels would misalign them without raising anything.
    """
    pipeline = ThreatForecastingPipeline()
    pipeline.train_and_evaluate_all(events, train_ratio=0.7)
    held = pipeline.last_holdout

    assert held is not None
    rf = held.y_true_for("random_forest_forecaster")
    temporal = held.y_true_for("temporal_window_stack")
    assert len(temporal) == len(rf) - TEMPORAL_LAGS
    assert len(held.scores["temporal_window_stack"]) == len(temporal)


# ──────────────────────────────────────────────────────────────────
# Uncertainty
# ──────────────────────────────────────────────────────────────────


def _separable(n=200, seed=1):
    rng = np.random.default_rng(seed)
    y = (rng.random(n) < 0.3).astype(int)
    scores = np.clip(y * 0.6 + rng.normal(0.2, 0.25, n), 0, 1)
    return y, scores


@pytest.mark.parametrize("metric", ["pr_auc", "precision", "recall"])
def test_interval_brackets_the_point_estimate(metric):
    y, scores = _separable()
    interval = bootstrap_interval(y, scores, metric=metric, resamples=400)

    assert interval.available is True
    assert interval.lower <= interval.point_estimate <= interval.upper
    assert interval.lower < interval.upper, "a zero-width interval is not an interval"
    assert interval.confidence == 0.95


def test_a_wider_confidence_level_gives_a_wider_interval():
    y, scores = _separable()
    narrow = bootstrap_interval(y, scores, confidence=0.80, resamples=400)
    wide = bootstrap_interval(y, scores, confidence=0.99, resamples=400)
    assert (wide.upper - wide.lower) > (narrow.upper - narrow.lower)


def test_interval_is_refused_on_a_holdout_too_small_to_support_one():
    y, scores = _separable(n=MIN_BOOTSTRAP_INSTANCES - 1)
    interval = bootstrap_interval(y, scores)

    assert interval.available is False
    assert interval.lower is None and interval.upper is None
    assert str(MIN_BOOTSTRAP_INSTANCES) in interval.refusal_reason


def test_interval_is_refused_with_too_few_positives():
    y = np.zeros(100, dtype=int)
    y[:MIN_BOOTSTRAP_POSITIVES - 1] = 1
    rng = np.random.default_rng(3)
    interval = bootstrap_interval(y, rng.random(100))

    assert interval.available is False
    assert "positive" in interval.refusal_reason.lower()


def test_interval_is_refused_when_one_class_is_absent():
    scores = np.random.default_rng(4).random(50)
    assert bootstrap_interval(np.ones(50, dtype=int), scores).available is False
    assert bootstrap_interval(np.zeros(50, dtype=int), scores).available is False


def test_bootstrap_is_deterministic_for_a_given_seed():
    y, scores = _separable()
    a = bootstrap_interval(y, scores, resamples=300, seed=7)
    b = bootstrap_interval(y, scores, resamples=300, seed=7)
    assert (a.lower, a.upper) == (b.lower, b.upper)


def test_unknown_metric_is_rejected():
    y, scores = _separable()
    with pytest.raises(ValueError):
        bootstrap_interval(y, scores, metric="accuracy_please")


# ──────────────────────────────────────────────────────────────────
# Lead-time curve
# ──────────────────────────────────────────────────────────────────


def test_curve_evaluates_each_lead_under_one_frozen_protocol(events):
    curve = lead_time_curve(events, lead_times=(0.0, 60.0, 120.0))

    assert len(curve.points) == 3
    assert curve.evaluated_leads >= 1
    assert [p.lead_time_seconds for p in curve.points] == [0.0, 60.0, 120.0]
    assert curve.protocol["observation_window_seconds"] == 60.0
    assert curve.protocol["prediction_horizon_seconds"] == 60.0
    assert curve.protocol["train_ratio"] == 0.7
    assert curve.target_definition


def test_refused_leads_are_reported_not_dropped():
    """
    A curve that omits the leads it could not evaluate implies performance
    was measured there. Tiny dataset: most or all leads must refuse, and
    every one must still appear with a reason.
    """
    tiny = SyntheticFlowGenerator(seed=9, source_id="s").generate_scenario_batch(
        count=25, attack_ratio=0.3
    )
    curve = lead_time_curve(tiny, lead_times=(0.0, 600.0, 3600.0))

    assert len(curve.points) == 3, "a refused lead must still appear in the curve"
    assert curve.refused_leads >= 1
    for point in curve.points:
        if not point.evaluated:
            assert point.refusal_reason, "a refusal must say why"
            assert point.metrics == {}
            assert point.best_pr_auc is None


def test_each_point_reports_its_own_split_accounting(events):
    curve = lead_time_curve(events, lead_times=(0.0, 60.0))
    for point in curve.points:
        if not point.evaluated:
            continue
        assert point.total_instances > 0
        assert point.train_instances > 0
        assert point.test_instances > 0
        assert point.purged_instances >= 0
        assert point.train_instances + point.test_instances <= point.total_instances


def test_baselines_are_excluded_from_the_best_model_choice(events):
    """A baseline winning is a finding, not a model to report as best."""
    curve = lead_time_curve(events, lead_times=(0.0,))
    point = curve.points[0]
    if point.evaluated and point.best_model:
        assert not point.best_model.startswith("baseline_")


# ──────────────────────────────────────────────────────────────────
# API
# ──────────────────────────────────────────────────────────────────


def test_lead_time_endpoint_returns_a_curve(client):
    c, _ = client
    res = c.post(
        "/api/v1/forecast/lead-time-curve",
        json={"source_id": "s", "lead_times_seconds": [0.0, 60.0]},
    )
    assert res.status_code == 200, res.text
    body = res.json()
    assert len(body["points"]) == 2
    assert body["evaluated_leads"] + body["refused_leads"] == 2


def test_lead_time_endpoint_obeys_the_research_gate(tmp_path):
    """A dataset that cannot support one evaluation cannot support five."""
    db = Database(db_path=str(tmp_path / "gate.db"))
    db.initialize()
    db.upsert_source(
        TelemetrySource(source_id="s", name="S", source_type="windows_connection_table")
    )
    reset_forecasting_pipeline()
    app.dependency_overrides[get_db] = lambda: db
    try:
        with TestClient(app) as c:
            res = c.post("/api/v1/forecast/lead-time-curve", json={"source_id": "s"})
            assert res.status_code == 409
            assert res.json()["detail"]["error"] == "forecasting_blocked_by_research_gate"
    finally:
        app.dependency_overrides.clear()
        db.close()


def test_uncertainty_endpoint_requires_an_evaluation_first(client):
    c, _ = client
    res = c.get("/api/v1/forecast/uncertainty")
    assert res.status_code == 409
    assert res.json()["detail"]["error"] == "no_evaluation_in_memory"


def test_uncertainty_endpoint_returns_intervals_after_training(client):
    c, _ = client
    assert c.post("/api/v1/forecast/train", json={"source_id": "s"}).status_code == 200

    res = c.get("/api/v1/forecast/uncertainty")
    assert res.status_code == 200
    intervals = res.json()
    assert {i["metric"] for i in intervals} == {"pr_auc", "precision", "recall"}
    for i in intervals:
        if i["available"]:
            assert i["lower"] <= i["point_estimate"] <= i["upper"]
        else:
            assert i["refusal_reason"]


def test_uncertainty_endpoint_rejects_an_unknown_model(client):
    c, _ = client
    c.post("/api/v1/forecast/train", json={"source_id": "s"})
    res = c.get("/api/v1/forecast/uncertainty?model_id=not_a_model")
    assert res.status_code == 404
    assert "available" in res.json()["detail"]
