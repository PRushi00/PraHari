"""
Generalization (leave-one-group-out transfer) tests.

The failure this guards against is a cross-group number reported without
its within-group counterpart. 0.6 alone is unreadable: it might be a
collapse from 0.95 or a rise from 0.5. The gap is the result.

The second failure it guards against is over-reading a transfer score
between groups that are not actually independent environments.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.adapters.synthetic_replay import SyntheticFlowGenerator
from app.api.deps import get_db
from app.main import app
from app.models.registry import reset_forecasting_pipeline
from app.research.evaluation import generalization_evaluation
from app.schemas.events import DataCategory, TelemetrySource
from app.storage.database import Database


def _env(source_id: str, seed: int, count: int = 700, ratio: float = 0.3):
    return SyntheticFlowGenerator(
        seed=seed, source_id=source_id
    ).generate_scenario_batch(count=count, attack_ratio=ratio)


@pytest.fixture(scope="module")
def two_environments():
    return _env("env_a", 11, ratio=0.30) + _env("env_b", 77, ratio=0.15)


@pytest.fixture
def client(tmp_path, two_environments):
    db = Database(db_path=str(tmp_path / "gen.db"))
    db.initialize()
    for sid in ("env_a", "env_b"):
        db.upsert_source(
            TelemetrySource(source_id=sid, name=sid, source_type="synthetic_replay")
        )
    db.insert_events(two_environments)
    reset_forecasting_pipeline()
    app.dependency_overrides[get_db] = lambda: db
    with TestClient(app) as c:
        yield c, db
    app.dependency_overrides.clear()
    db.close()


# ──────────────────────────────────────────────────────────────────
# The evaluation itself
# ──────────────────────────────────────────────────────────────────


def test_every_group_is_held_out_in_turn(two_environments):
    report = generalization_evaluation(two_environments, group_by="source_id")

    assert set(report.groups) == {"env_a", "env_b"}
    assert len(report.points) == 2
    assert report.evaluated_groups + report.refused_groups == 2


def test_the_held_out_group_contributes_nothing_to_training(two_environments):
    report = generalization_evaluation(two_environments, group_by="source_id")
    for point in report.points:
        assert point.held_out_group not in point.train_groups, (
            "the held-out environment leaked into training"
        )


def test_cross_group_score_is_reported_with_its_within_group_counterpart(
    two_environments,
):
    """A transfer number alone cannot be read; the gap is the result."""
    report = generalization_evaluation(two_environments, group_by="source_id")
    evaluated = [p for p in report.points if p.evaluated]
    assert evaluated, "no group was evaluable"

    for point in evaluated:
        assert point.cross_group_pr_auc is not None
        if point.within_group_pr_auc is not None:
            assert point.transfer_gap == pytest.approx(
                point.within_group_pr_auc - point.cross_group_pr_auc, abs=1e-4
            )


def test_synthetic_only_groups_are_flagged_as_not_independent(two_environments):
    """
    Two groups from the same generator measure the generator's
    consistency, not the model's generality. Reporting a small gap
    without saying so would be the overclaim.
    """
    report = generalization_evaluation(two_environments, group_by="source_id")

    assert report.independent_environments is False
    joined = " ".join(report.notes).lower()
    assert "not independent environments" in joined
    assert "generator" in joined


def test_a_single_group_cannot_support_generalization():
    report = generalization_evaluation(_env("solo", 5), group_by="source_id")

    assert report.usable is False
    assert report.evaluated_groups == 0
    assert any("at least two" in n for n in report.notes)


def test_a_group_without_both_classes_is_refused_with_a_reason():
    benign_only = _env("quiet", 21, count=400, ratio=0.0)
    mixed = _env("busy", 22, count=700, ratio=0.3)

    report = generalization_evaluation(benign_only + mixed, group_by="source_id")

    quiet = [p for p in report.points if p.held_out_group == "quiet"][0]
    assert quiet.evaluated is False
    assert quiet.refusal_reason
    assert "class" in quiet.refusal_reason.lower()
    assert quiet.cross_group_pr_auc is None


def test_refused_groups_still_appear_in_the_report():
    """Dropping them would imply transfer was measured and fine."""
    report = generalization_evaluation(
        _env("tiny", 31, count=30) + _env("big", 32, count=700),
        group_by="source_id",
    )
    assert len(report.points) == 2
    for point in report.points:
        assert point.evaluated or point.refusal_reason


def test_grouping_by_data_category_is_supported(two_environments):
    report = generalization_evaluation(two_environments, group_by="data_category")
    assert report.grouped_by == "data_category"
    # Both environments are synthetic_demo, so this is a single group.
    assert report.usable is False


def test_mean_transfer_gap_is_the_mean_of_the_reported_gaps(two_environments):
    report = generalization_evaluation(two_environments, group_by="source_id")
    gaps = [p.transfer_gap for p in report.points if p.transfer_gap is not None]
    if gaps:
        assert report.mean_transfer_gap == pytest.approx(
            sum(gaps) / len(gaps), abs=1e-4
        )


# ──────────────────────────────────────────────────────────────────
# API
# ──────────────────────────────────────────────────────────────────


def test_endpoint_returns_a_generalization_report(client):
    c, _ = client
    res = c.post("/api/v1/forecast/generalization", json={"group_by": "source_id"})
    assert res.status_code == 200, res.text

    body = res.json()
    assert set(body["groups"]) == {"env_a", "env_b"}
    assert body["independent_environments"] is False
    assert len(body["points"]) == 2
    assert any("not independent" in n.lower() for n in body["notes"])


def test_endpoint_obeys_the_research_gate(tmp_path):
    db = Database(db_path=str(tmp_path / "gate.db"))
    db.initialize()
    db.upsert_source(
        TelemetrySource(source_id="s", name="S", source_type="windows_connection_table")
    )
    reset_forecasting_pipeline()
    app.dependency_overrides[get_db] = lambda: db
    try:
        with TestClient(app) as c:
            res = c.post("/api/v1/forecast/generalization", json={})
            assert res.status_code == 409
            assert res.json()["detail"]["error"] == "forecasting_blocked_by_research_gate"
    finally:
        app.dependency_overrides.clear()
        db.close()


def test_endpoint_rejects_an_unsupported_grouping(client):
    c, _ = client
    res = c.post("/api/v1/forecast/generalization", json={"group_by": "src_ip"})
    assert res.status_code == 422


def test_endpoint_explains_itself_when_no_group_is_evaluable(tmp_path):
    db = Database(db_path=str(tmp_path / "one.db"))
    db.initialize()
    db.upsert_source(
        TelemetrySource(source_id="solo", name="Solo", source_type="synthetic_replay")
    )
    db.insert_events(_env("solo", 44, count=700))
    reset_forecasting_pipeline()
    app.dependency_overrides[get_db] = lambda: db
    try:
        with TestClient(app) as c:
            res = c.post("/api/v1/forecast/generalization", json={})
            assert res.status_code == 422
            detail = res.json()["detail"]
            assert detail["error"] == "no_group_evaluable"
            assert "notes" in detail and detail["notes"]
    finally:
        app.dependency_overrides.clear()
        db.close()
