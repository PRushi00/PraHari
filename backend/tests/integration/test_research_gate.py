"""
Tests for the forecasting research gate.

The gate must hold at the API, not merely in the dashboard: a disabled
button is not a control, and the first client to script against the API
would otherwise receive an unsupportable number.
"""

from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile

import pytest
from fastapi.testclient import TestClient

from app.adapters.synthetic_replay import SyntheticFlowGenerator
from app.api.deps import get_db
from app.main import app
from app.models.registry import reset_forecasting_pipeline
from app.research.readiness import (
    MIN_EVENTS_FOR_TRAINING,
    MIN_POSITIVE_EVENTS,
    MIN_TIME_SPAN_SECONDS,
    OP_PREDICT,
    OP_TRAIN,
    ForecastingBlocked,
    ReadinessState,
    assess_readiness,
    enforce,
)
from app.schemas.events import (
    DataCategory,
    EventType,
    LabelProvenance,
    NormalizedEvent,
    TelemetrySource,
)
from app.storage.database import Database

BASE = datetime(2026, 10, 11, 8, 0, 0, tzinfo=timezone.utc)


def _events(n: int, span_seconds: float, labelled: bool = True, attack_every: int = 4):
    """Build n events spread evenly across span_seconds."""
    step = span_seconds / max(1, n - 1) if n > 1 else 1.0
    out = []
    for i in range(n):
        is_attack = labelled and (i % attack_every == 0)
        out.append(
            NormalizedEvent(
                source_id="s",
                data_category=DataCategory.LIVE_TELEMETRY,
                observed_at=BASE + timedelta(seconds=i * step),
                event_type=EventType.CONNECTION,
                src_ip="192.168.1.5",
                dst_ip="93.184.216.34",
                src_port=40000 + i,
                dst_port=443,
                protocol="TCP",
                label=("PortScan" if is_attack else "Benign") if labelled else None,
                label_provenance=(
                    LabelProvenance.DATASET_GROUND_TRUTH if labelled
                    else LabelProvenance.UNLABELED
                ),
            )
        )
    return out


# ──────────────────────────────────────────────────────────────────
# Readiness states
# ──────────────────────────────────────────────────────────────────


def test_too_few_events_is_insufficient_data():
    report = assess_readiness(_events(20, 3600))
    assert report.state == ReadinessState.INSUFFICIENT_DATA
    assert report.can_train is False
    assert "sufficient_events" in report.unmet_requirements
    assert report.next_steps


def test_short_span_is_insufficient_data_even_with_many_events():
    """Many events packed into a minute cannot support a temporal split."""
    report = assess_readiness(_events(500, 60))
    assert report.state == ReadinessState.INSUFFICIENT_DATA
    assert "sufficient_time_span" in report.unmet_requirements


def test_unlabelled_traffic_is_not_treated_as_benign():
    """
    Ordinary local connections carry no ground truth. Counting them as
    confirmed benign would manufacture a class balance the evidence does
    not support.
    """
    report = assess_readiness(_events(400, 7200, labelled=False))

    assert report.state == ReadinessState.MISSING_OR_INVALID_LABELS
    assert report.can_train is False
    assert report.labelled_events == 0
    assert report.negative_events == 0  # NOT 400
    assert any("not treated as benign" in s.lower() or "not counted as benign" in s.lower()
               for s in [report.summary] + report.next_steps)


def test_single_class_labels_are_inadequate_representation():
    events = _events(400, 7200, labelled=True)
    for e in events:
        e.label = "Benign"  # every record confirmed benign, no incidents
    report = assess_readiness(events)
    assert report.state == ReadinessState.INADEQUATE_CLASS_REPRESENTATION
    assert report.positive_events == 0
    assert "positive_examples" in report.unmet_requirements


def test_implausible_timestamps_are_excluded_from_the_span():
    """
    One FILETIME-epoch record must not satisfy the duration requirement by
    reporting a span of centuries.
    """
    events = _events(400, 7200)
    events[0].observed_at = datetime(1601, 1, 1, tzinfo=timezone.utc)

    report = assess_readiness(events)

    assert report.implausible_timestamp_events == 1
    # Span reflects the plausible records only (~2 hours), not ~425 years.
    assert report.time_span_seconds < 10_000
    assert report.can_train is True


def test_adequate_data_permits_training():
    report = assess_readiness(_events(400, 7200))
    assert report.can_train is True
    assert report.unmet_requirements == []
    assert report.positive_events >= MIN_POSITIVE_EVENTS


def test_trained_but_uninterpretable_metrics_is_not_validated():
    report = assess_readiness(
        _events(400, 7200), has_trained_model=True, model_metrics_interpretable=False
    )
    assert report.state == ReadinessState.TRAINED_NOT_VALIDATED
    assert report.can_serve_validated_forecast is False


def test_validated_state_requires_interpretable_metrics():
    report = assess_readiness(
        _events(400, 7200), has_trained_model=True, model_metrics_interpretable=True
    )
    assert report.state == ReadinessState.VALIDATED_WITH_DOCUMENTED_CONDITIONS
    assert report.can_serve_validated_forecast is True


def test_inadequate_performance_is_its_own_state():
    report = assess_readiness(
        _events(400, 7200),
        has_trained_model=True,
        model_metrics_interpretable=True,
        model_performance_adequate=False,
    )
    assert report.state == ReadinessState.EVALUATED_PERFORMANCE_INADEQUATE


def test_report_states_the_prediction_target_and_horizon():
    report = assess_readiness(_events(400, 7200), prediction_horizon_seconds=60.0)
    assert "attack" in report.prediction_target.lower()
    assert "horizon" in report.prediction_target.lower()
    assert report.prediction_horizon_seconds == 60.0


def test_every_requirement_reports_observed_versus_required():
    report = assess_readiness(_events(10, 60))
    assert len(report.requirements) >= 5
    for req in report.requirements:
        assert req.required and req.observed
        assert isinstance(req.satisfied, bool)


def test_enforce_raises_for_blocked_operations():
    report = assess_readiness(_events(10, 60))
    for op in (OP_TRAIN, OP_PREDICT):
        with pytest.raises(ForecastingBlocked) as exc:
            enforce(op, report)
        assert exc.value.report.state == ReadinessState.INSUFFICIENT_DATA


def test_enforce_permits_when_data_is_adequate():
    report = assess_readiness(_events(400, 7200))
    enforce(OP_TRAIN, report)  # must not raise


# ──────────────────────────────────────────────────────────────────
# Backend enforcement via the API
# ──────────────────────────────────────────────────────────────────


@pytest.fixture
def client_with(tmp_path):
    """Build a client over a database seeded by the caller."""
    created: list[Database] = []

    def _make(events: list[NormalizedEvent]):
        db_path = tmp_path / f"gate_{len(created)}.db"
        db = Database(db_path=str(db_path))
        db.initialize()
        db.upsert_source(
            TelemetrySource(source_id="s", name="S", source_type="windows_connection_table")
        )
        if events:
            db.insert_events(events)
        created.append(db)
        reset_forecasting_pipeline()
        app.dependency_overrides[get_db] = lambda: db
        return TestClient(app), db

    yield _make
    app.dependency_overrides.clear()
    for db in created:
        db.close()


def test_api_refuses_training_on_inadequate_data(client_with):
    client, _ = client_with(_events(30, 300))

    res = client.post("/api/v1/forecast/train", json={})
    assert res.status_code == 409

    detail = res.json()["detail"]
    assert detail["error"] == "forecasting_blocked_by_research_gate"
    assert detail["operation"] == OP_TRAIN
    assert detail["readiness_state"] == ReadinessState.INSUFFICIENT_DATA.value
    assert detail["unmet_requirements"]
    # The refusal names what is required versus what was observed.
    first = detail["unmet_requirements"][0]
    assert {"name", "required", "observed"} <= set(first)
    assert detail["next_steps"]


def test_api_refuses_prediction_on_inadequate_data(client_with):
    """
    The gate also covers prediction: returning an uncalibrated score here,
    however labelled, invites it to be read as a forecast.
    """
    client, _ = client_with(_events(30, 300))
    res = client.post("/api/v1/forecast/predict", json={"threshold": 0.5})
    assert res.status_code == 409
    assert res.json()["detail"]["operation"] == OP_PREDICT


def test_gate_blocks_direct_api_calls_not_just_the_ui(client_with):
    """
    Every forecasting entry point is gated, so no direct request can obtain
    a model or a score from data that cannot support one.
    """
    client, _ = client_with(_events(30, 300))

    assert client.post("/api/v1/forecast/train", json={}).status_code == 409
    assert client.post("/api/v1/forecast/predict", json={}).status_code == 409
    # No model may be advertised as available.
    assert client.get("/api/v1/forecast/models").json() == {}
    # And nothing was recorded as a split.
    assert client.get("/api/v1/forecast/integrity").json() is None


def test_readiness_endpoint_explains_the_block(client_with):
    client, _ = client_with(_events(30, 300))
    report = client.get("/api/v1/forecast/readiness").json()

    assert report["can_train"] is False
    assert report["state"] == ReadinessState.INSUFFICIENT_DATA.value
    assert report["total_events"] == 30
    assert report["unmet_requirements"]
    assert report["prediction_target"]


def test_blocked_attempt_is_audited(client_with):
    client, db = client_with(_events(30, 300))
    client.post("/api/v1/forecast/train", json={})

    with db.get_connection() as conn:
        actions = [r["action"] for r in conn.execute("SELECT action FROM audit_events")]
    assert "train_forecasting_models_blocked" in actions


def test_api_permits_training_when_gate_is_satisfied(client_with):
    """With adequate labelled data spanning enough time, training proceeds."""
    gen = SyntheticFlowGenerator(seed=7, source_id="s")
    client, _ = client_with(gen.generate_scenario_batch(count=800, attack_ratio=0.25))

    readiness = client.get("/api/v1/forecast/readiness").json()
    assert readiness["can_train"] is True

    res = client.post("/api/v1/forecast/train", json={"max_events": 2000})
    assert res.status_code == 200, res.json()
    models = res.json()
    assert "random_forest_forecaster" in models

    # Metrics must arrive with their evaluation context attached.
    rf = models["random_forest_forecaster"]
    assert "metrics_interpretable" in rf
    assert "test_positive_count" in rf

    integrity = client.get("/api/v1/forecast/integrity").json()
    assert integrity is not None
    assert integrity["purged_instances"] > 0


# ──────────────────────────────────────────────────────────────────
# Reproducibility manifest and operational burden (DoD items 7 and 9)
# ──────────────────────────────────────────────────────────────────


def test_split_report_carries_a_reproducibility_manifest(client_with):
    """
    Blueprint sections 8 and 16: an evaluation must be tied to the exact
    inputs that produced it, without embedding telemetry.
    """
    gen = SyntheticFlowGenerator(seed=7, source_id="s")
    client, _ = client_with(gen.generate_scenario_batch(count=800, attack_ratio=0.25))

    assert client.post("/api/v1/forecast/train", json={"max_events": 2000}).status_code == 200
    manifest = client.get("/api/v1/forecast/integrity").json()

    assert manifest["dataset_fingerprint"]
    assert len(manifest["dataset_fingerprint"]) == 16
    assert manifest["event_count"] == 800
    assert manifest["event_time_range"] and len(manifest["event_time_range"]) == 2
    assert manifest["manifest_version"]
    assert manifest["random_seed"] == 42

    # Provenance must make synthetic data obvious rather than implicit.
    assert manifest["data_category_breakdown"] == {"synthetic_demo": 800}
    assert "rule_based" in manifest["label_provenance_breakdown"]

    # The target definition travels with the evaluation.
    target = manifest["target_definition"]
    assert "y=1" in target and "y=0 only when" in target

    # No telemetry values are embedded.
    flat = str(manifest)
    assert "src_ip" not in flat and "dst_ip" not in flat


def test_fingerprint_is_stable_for_identical_input_and_changes_otherwise():
    from app.models.forecaster import ThreatForecastingPipeline

    gen = SyntheticFlowGenerator(seed=11, source_id="s")
    events = gen.generate_scenario_batch(count=800, attack_ratio=0.25)

    p1 = ThreatForecastingPipeline()
    p1.train_and_evaluate_all(events, train_ratio=0.7)
    first = p1.last_split_report.dataset_fingerprint

    p2 = ThreatForecastingPipeline()
    p2.train_and_evaluate_all(events, train_ratio=0.7)
    assert p2.last_split_report.dataset_fingerprint == first

    # A different split protocol is a different experiment.
    p3 = ThreatForecastingPipeline()
    p3.train_and_evaluate_all(events, train_ratio=0.8)
    assert p3.last_split_report.dataset_fingerprint != first


def test_metrics_report_missed_events_and_false_alarm_burden(client_with):
    """
    Rates alone do not convey analyst workload or what the model missed.
    """
    gen = SyntheticFlowGenerator(seed=7, source_id="s")
    client, _ = client_with(gen.generate_scenario_batch(count=800, attack_ratio=0.25))

    models = client.post("/api/v1/forecast/train", json={"max_events": 2000}).json()
    rf = models["random_forest_forecaster"]

    for field in (
        "detected_events", "missed_events", "false_alarms",
        "correct_quiet_windows", "false_alarms_per_100_windows",
        "missed_event_rate",
    ):
        assert field in rf, f"missing burden metric {field}"

    # Counts must reconcile with the confusion matrix.
    cm = rf["confusion_matrix"]
    assert rf["correct_quiet_windows"] == cm[0][0]
    assert rf["false_alarms"] == cm[0][1]
    assert rf["missed_events"] == cm[1][0]
    assert rf["detected_events"] == cm[1][1]

    total = sum(sum(row) for row in cm)
    assert total == rf["test_instances"]


def test_negative_label_exclusions_are_reported(client_with):
    """The count of windows refused a negative label must be visible."""
    gen = SyntheticFlowGenerator(seed=7, source_id="s")
    client, _ = client_with(gen.generate_scenario_batch(count=800, attack_ratio=0.25))
    client.post("/api/v1/forecast/train", json={"max_events": 2000})

    windowing = client.get("/api/v1/forecast/integrity").json()["windowing"]
    assert "windows_excluded_empty_horizon" in windowing
    assert "windows_excluded_unlabelled_horizon" in windowing
    assert windowing["require_labelled_horizon"] is True
