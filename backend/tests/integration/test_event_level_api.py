"""
PraHari — Event-level evaluation through the real pipeline and API (ADR-091).

The unit tests fix the matching arithmetic on hand-built inputs. These
drive the whole path instead: ingest events, train, then ask for the
event-level view of the holdout the training actually produced.

What matters here is that the report describes the SAME evaluation as the
window-level metrics — the same split, the same target, the same fixed
operating point — and that the holdout's window times line up row for row
with the scores of every model, including the two whose sequence shaping
drops leading rows.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import numpy as np
import pytest
from fastapi import status

from app.models.forecaster import (
    LSTM_TIMESTEPS,
    TEMPORAL_LAGS,
    ThreatForecastingPipeline,
)
from app.schemas.events import (
    DataCategory,
    EventType,
    LabelProvenance,
    NormalizedEvent,
)

T0 = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)


def _stream() -> list[NormalizedEvent]:
    """
    A long synthetic stream with recurring attack episodes.

    Bursts are separated by well over the default episode gap, so they are
    distinct documented events, and dense enough inside a burst that the
    windowing produces positives.
    """
    events: list[NormalizedEvent] = []
    seq = 0

    def add(offset: float, label: str, provenance: LabelProvenance) -> None:
        nonlocal seq
        seq += 1
        events.append(
            NormalizedEvent(
                event_id=f"ev-{seq}",
                source_id="src-synth",
                event_type=EventType.NETWORK_FLOW,
                observed_at=T0 + timedelta(seconds=offset),
                data_category=DataCategory.SYNTHETIC_DEMO,
                label=label,
                label_provenance=provenance,
                src_ip="10.0.0.5",
                dst_ip="10.0.0.9",
                dst_port=443,
                protocol="TCP",
                packets=10,
                bytes_total=1200,
                duration=0.4,
            )
        )

    # 4 hours of background, with an attack burst every ~30 minutes.
    for step in range(0, 14_400, 10):
        in_burst = (step % 1800) >= 1680  # last 2 minutes of each half hour
        if in_burst:
            add(step, "DDoS", LabelProvenance.SYNTHETIC_RULE)
        else:
            add(step, "Benign", LabelProvenance.SYNTHETIC_RULE)
    return events


@pytest.fixture(scope="module")
def trained() -> ThreatForecastingPipeline:
    pipeline = ThreatForecastingPipeline(
        window_size_seconds=60.0,
        lead_time_seconds=30.0,
        prediction_horizon_seconds=120.0,
    )
    pipeline.train_and_evaluate_all(_stream(), train_ratio=0.7)
    return pipeline


def test_every_model_holdout_carries_one_time_per_score(trained):
    """A misalignment here would attribute a score to the wrong moment."""
    held = trained.last_holdout
    assert held is not None
    assert held.scores, "no model produced a holdout"

    for model_id, scores in held.scores.items():
        times = held.times_for(model_id)
        assert times is not None, f"{model_id} kept no window times"
        assert len(times) == len(scores), model_id
        assert len(times) == len(held.y_true_for(model_id)), model_id
        assert times == sorted(times), f"{model_id} times are not chronological"


def test_sequence_models_drop_leading_rows_from_the_front(trained):
    """
    Stacking and sequencing drop the FIRST rows, so their holdout must
    start later than the plain models' — not end earlier.
    """
    held = trained.last_holdout
    plain = held.times_for("random_forest_forecaster")
    assert plain is not None

    stacked = held.times_for("temporal_window_stack")
    if stacked is not None:
        assert stacked == plain[TEMPORAL_LAGS:]

    lstm = held.times_for("lstm_forecaster")
    if lstm is not None:
        assert lstm == plain[LSTM_TIMESTEPS - 1:]


def test_holdout_record_refuses_a_misaligned_time_list():
    from app.models.forecaster import HoldoutPredictions

    held = HoldoutPredictions()
    with pytest.raises(ValueError, match="align"):
        held.record("m", np.array([1, 0]), np.array([0.9, 0.1]), [T0])


def test_event_level_counts_events_not_windows(trained):
    """
    The point of the whole module: an attack spanning many windows is one
    event, and a sustained alarm is one warning.
    """
    from app.research.event_level import evaluate_event_level

    held = trained.last_holdout
    model_id = "random_forest_forecaster"
    report = evaluate_event_level(
        _stream(),
        held.times_for(model_id),
        held.scores[model_id],
        lead_seconds=30.0,
        horizon_seconds=120.0,
        model_id=model_id,
    )

    if not report.available:
        pytest.skip(f"holdout could not support an event-level view: {report.refusal_reason}")

    # Far fewer events than positive windows, and no more warnings than
    # positive windows — both are what aggregation is for.
    assert report.events_total >= 1
    assert report.warnings_issued <= report.positive_windows
    assert report.events_total < report.evaluated_windows

    # Internal consistency: every warning has exactly one outcome.
    assert (
        report.detections + report.late_warnings + report.false_alarms
        == report.warnings_issued
    )
    assert report.events_warned + report.events_missed == report.events_total
    assert report.detections == report.events_warned
    assert report.missed_event_rate == pytest.approx(
        report.events_missed / report.events_total
    )


def test_every_reported_lead_time_is_positive_and_within_the_rules(trained):
    """A 'lead time' that is negative or beyond the horizon is not a lead."""
    from app.research.event_level import evaluate_event_level

    held = trained.last_holdout
    model_id = "random_forest_forecaster"
    report = evaluate_event_level(
        _stream(), held.times_for(model_id), held.scores[model_id],
        lead_seconds=30.0, horizon_seconds=120.0, model_id=model_id,
    )
    if not report.available:
        pytest.skip("no event-level view available")

    for event in report.events:
        if event.lead_time_seconds is None:
            continue
        assert event.lead_time_seconds >= report.rules.min_lead_seconds
        assert event.lead_time_seconds <= report.rules.max_lead_seconds


def test_synthetic_provenance_is_declared_in_the_report(trained):
    from app.research.event_level import evaluate_event_level

    held = trained.last_holdout
    model_id = "random_forest_forecaster"
    report = evaluate_event_level(
        _stream(), held.times_for(model_id), held.scores[model_id],
        lead_seconds=30.0, horizon_seconds=120.0, model_id=model_id,
    )
    if not report.available:
        pytest.skip("no event-level view available")

    assert LabelProvenance.SYNTHETIC_RULE.value in report.label_provenance
    assert any("SYNTHETIC" in limitation for limitation in report.limitations)


# ──────────────────────────────────────────────────────────────────
# Through the API
# ──────────────────────────────────────────────────────────────────


@pytest.fixture
def client():
    """A TestClient over a throwaway database, as the other suites build it."""
    import tempfile
    from pathlib import Path

    from fastapi.testclient import TestClient

    from app.api.deps import get_db
    from app.main import app
    from app.schemas.events import TelemetrySource
    from app.storage.database import Database

    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        db_path = tmp.name
    test_db = Database(db_path=db_path)
    test_db.initialize()
    test_db.upsert_source(
        TelemetrySource(source_id="src-api", name="src-api", source_type="json_stream")
    )

    app.dependency_overrides[get_db] = lambda: test_db
    with TestClient(app) as test_client:
        yield test_client, test_db

    app.dependency_overrides.clear()
    test_db.close()
    Path(db_path).unlink(missing_ok=True)


@pytest.fixture(autouse=True)
def _clear_pipeline_holdout():
    """No test may inherit another's holdout."""
    from app.models.registry import get_forecasting_pipeline

    yield
    get_forecasting_pipeline().last_holdout = None


def test_endpoint_refuses_before_any_training(client):
    """No holdout in memory is a 409, not an invented score."""
    from app.models.registry import get_forecasting_pipeline

    test_client, _ = client
    get_forecasting_pipeline().last_holdout = None

    response = test_client.post("/api/v1/forecast/event-level", json={})
    assert response.status_code == status.HTTP_409_CONFLICT
    assert response.json()["detail"]["error"] == "no_evaluation_in_memory"


def test_endpoint_rejects_an_unknown_model(client):
    from app.models.forecaster import HoldoutPredictions
    from app.models.registry import get_forecasting_pipeline

    test_client, _ = client
    held = HoldoutPredictions()
    held.record(
        "random_forest_forecaster", np.array([1, 0]), np.array([0.9, 0.1]),
        [T0, T0 + timedelta(seconds=30)],
    )
    get_forecasting_pipeline().last_holdout = held

    response = test_client.post(
        "/api/v1/forecast/event-level", json={"model_id": "not_a_model"}
    )
    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json()["detail"]["error"] == "unknown_model"


def test_endpoint_refuses_when_no_event_lies_in_the_holdout_reach(client):
    """A refusal with its reason, never a missed-event rate over nothing."""
    from app.models.forecaster import HoldoutPredictions
    from app.models.registry import get_forecasting_pipeline

    test_client, test_db = client
    test_db.insert_events([
        NormalizedEvent(
            event_id="far-attack", source_id="src-api",
            event_type=EventType.NETWORK_FLOW,
            observed_at=T0 + timedelta(seconds=50_000),
            data_category=DataCategory.SYNTHETIC_DEMO,
            label="DDoS", label_provenance=LabelProvenance.SYNTHETIC_RULE,
        )
    ])

    pipeline = get_forecasting_pipeline()
    pipeline.extractor.lead_time_seconds = 30.0
    pipeline.extractor.prediction_horizon_seconds = 120.0
    pipeline.extractor.last_windowing_report = None
    held = HoldoutPredictions()
    held.record(
        "random_forest_forecaster", np.array([1, 0]), np.array([0.95, 0.1]),
        [T0, T0 + timedelta(seconds=60)],
    )
    pipeline.last_holdout = held

    response = test_client.post(
        "/api/v1/forecast/event-level", json={"source_id": "src-api"}
    )
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
    detail = response.json()["detail"]
    assert detail["error"] == "no_event_level_evaluation"
    assert detail["events_out_of_coverage"] == 1


def test_endpoint_reports_the_rules_and_their_fingerprint(client):
    """A lead time without its matching rules cannot be compared."""
    from app.models.forecaster import HoldoutPredictions
    from app.models.registry import get_forecasting_pipeline

    test_client, test_db = client

    events = [
        NormalizedEvent(
            event_id=f"api-{i}", source_id="src-api",
            event_type=EventType.NETWORK_FLOW,
            observed_at=T0 + timedelta(seconds=i * 60),
            data_category=DataCategory.SYNTHETIC_DEMO,
            label="Benign", label_provenance=LabelProvenance.SYNTHETIC_RULE,
        )
        for i in range(10)
    ]
    events.append(
        NormalizedEvent(
            event_id="api-attack", source_id="src-api",
            event_type=EventType.NETWORK_FLOW,
            observed_at=T0 + timedelta(seconds=600),
            data_category=DataCategory.SYNTHETIC_DEMO,
            label="DDoS", label_provenance=LabelProvenance.SYNTHETIC_RULE,
        )
    )
    test_db.insert_events(events)

    pipeline = get_forecasting_pipeline()
    pipeline.extractor.lead_time_seconds = 30.0
    pipeline.extractor.prediction_horizon_seconds = 120.0
    pipeline.extractor.last_windowing_report = None
    held = HoldoutPredictions()
    held.record(
        "random_forest_forecaster",
        np.array([1, 0]), np.array([0.95, 0.1]),
        [T0 + timedelta(seconds=500), T0 + timedelta(seconds=560)],
    )
    pipeline.last_holdout = held

    response = test_client.post(
        "/api/v1/forecast/event-level", json={"source_id": "src-api"}
    )

    assert response.status_code == status.HTTP_200_OK, response.text
    body = response.json()
    assert body["available"] is True
    assert body["events_total"] == 1
    assert body["events_warned"] == 1
    assert body["lead_time"]["min_seconds"] == pytest.approx(100.0)
    assert len(body["rules_fingerprint"]) == 64
    assert body["rules"]["min_lead_seconds"] == pytest.approx(30.0)
    assert body["rules"]["max_lead_seconds"] == pytest.approx(150.0)
    assert body["limitations"]


def test_endpoint_writes_an_audit_entry(client):
    """An evaluation that produced a published number is an audited action."""
    from app.models.forecaster import HoldoutPredictions
    from app.models.registry import get_forecasting_pipeline

    test_client, test_db = client
    test_db.insert_events([
        NormalizedEvent(
            event_id="audit-attack", source_id="src-api",
            event_type=EventType.NETWORK_FLOW,
            observed_at=T0 + timedelta(seconds=600),
            data_category=DataCategory.SYNTHETIC_DEMO,
            label="DDoS", label_provenance=LabelProvenance.SYNTHETIC_RULE,
        )
    ])

    pipeline = get_forecasting_pipeline()
    pipeline.extractor.lead_time_seconds = 30.0
    pipeline.extractor.prediction_horizon_seconds = 120.0
    pipeline.extractor.last_windowing_report = None
    held = HoldoutPredictions()
    held.record(
        "random_forest_forecaster", np.array([1, 0]), np.array([0.95, 0.1]),
        [T0 + timedelta(seconds=500), T0 + timedelta(seconds=560)],
    )
    pipeline.last_holdout = held

    assert test_client.post(
        "/api/v1/forecast/event-level", json={"source_id": "src-api"}
    ).status_code == status.HTTP_200_OK

    audit = test_client.get("/api/v1/audit/logs?limit=50")
    assert audit.status_code == status.HTTP_200_OK, audit.text
    actions = [entry["action"] for entry in audit.json()]
    assert "evaluate_event_level" in actions


# ──────────────────────────────────────────────────────────────────
# Per-scenario performance (§10, ADR-113)
# ──────────────────────────────────────────────────────────────────


def _mixed_scenario_stream():
    """
    Two attack families on one timeline: a dense burst the windowing can
    warn about, and a sparse one it cannot. The aggregate hides the
    difference; the per-scenario breakdown is what shows it.
    """
    out: list[NormalizedEvent] = []
    seq = 0

    def add(offset: float, label: str) -> None:
        nonlocal seq
        seq += 1
        out.append(
            NormalizedEvent(
                event_id=f"sc-{seq}",
                source_id="src-synth",
                event_type=EventType.NETWORK_FLOW,
                observed_at=T0 + timedelta(seconds=offset),
                data_category=DataCategory.SYNTHETIC_DEMO,
                label=label,
                label_provenance=LabelProvenance.SYNTHETIC_RULE,
                src_ip="10.0.0.5", dst_ip="10.0.0.9", dst_port=443,
                protocol="TCP", packets=10, bytes_total=1200, duration=0.4,
            )
        )

    for step in range(0, 14_400, 10):
        slot = step % 3600
        if 1680 <= slot < 1800:
            add(step, "DDoS")
        elif 3480 <= slot < 3600:
            add(step, "BruteForce")
        else:
            add(step, "Benign")
    return out


@pytest.fixture(scope="module")
def mixed_report():
    from app.research.event_level import evaluate_event_level

    pipeline = ThreatForecastingPipeline(
        window_size_seconds=60.0, lead_time_seconds=30.0,
        prediction_horizon_seconds=120.0,
    )
    events = _mixed_scenario_stream()
    pipeline.train_and_evaluate_all(events, train_ratio=0.7)
    held = pipeline.last_holdout
    mid = "baseline_threshold"
    return evaluate_event_level(
        events, held.times_for(mid), held.scores[mid],
        lead_seconds=30.0, horizon_seconds=120.0, threshold=0.5, model_id=mid,
    )


def test_performance_is_broken_down_by_scenario(mixed_report):
    """
    The aggregate missed-event rate cannot say whether a model warns
    about one family and never the other. This can.
    """
    if not mixed_report.available:
        pytest.skip(f"evaluation refused: {mixed_report.refusal_reason}")

    names = {s.scenario for s in mixed_report.by_scenario}
    assert names, "a report with events must break them down"
    assert names <= {"DDoS", "BruteForce", "(unlabelled)"}
    for s in mixed_report.by_scenario:
        assert s.events_warned + s.events_missed == s.events_total
        assert s.missed_event_rate == pytest.approx(
            s.events_missed / s.events_total, abs=1e-6
        )


def test_every_in_scope_event_appears_under_some_scenario(mixed_report):
    if not mixed_report.available:
        pytest.skip(f"evaluation refused: {mixed_report.refusal_reason}")

    # Single-labelled events: the totals must account for all of them.
    total = sum(s.events_total for s in mixed_report.by_scenario)
    assert total >= mixed_report.events_total


def test_the_note_warns_that_multi_label_events_are_double_counted(mixed_report):
    """
    ADR-095 found two distinct attacks sharing one label in the real
    corpus, so an episode CAN carry several. Counting it under each is
    right; letting a reader sum the column without warning is not.
    """
    if not mixed_report.available:
        pytest.skip(f"evaluation refused: {mixed_report.refusal_reason}")

    note = mixed_report.scenarios_note
    assert "more than one label" in note
    assert "exceed events_total" in note
    # And it says what a scenario IS, since the schema has no such field.
    assert "no separate scenario identifier" in note


def test_an_episode_with_two_labels_is_counted_under_both():
    """
    ADR-095 found two distinct attacks sharing one episode in the real
    corpus, so this is not hypothetical. Counting such an event once,
    under whichever label happened to come first, would silently erase
    one scenario from the breakdown.

    Built directly rather than through the pipeline, because the
    synthetic streams above never produce a mixed episode — which is
    exactly why this case needs its own test.
    """
    from app.research.event_level import evaluate_event_level

    events: list[NormalizedEvent] = []
    seq = 0

    def add(offset: float, label: str) -> None:
        nonlocal seq
        seq += 1
        events.append(
            NormalizedEvent(
                event_id=f"mix-{seq}",
                source_id="src-mixed",
                event_type=EventType.NETWORK_FLOW,
                observed_at=T0 + timedelta(seconds=offset),
                data_category=DataCategory.SYNTHETIC_DEMO,
                label=label,
                label_provenance=LabelProvenance.SYNTHETIC_RULE,
            )
        )

    for step in range(0, 2400, 10):
        add(step, "Benign")
    # Two families inside ONE episode: adjacent, well within the 300 s
    # episode gap, so they merge into a single documented event.
    for step in range(2400, 2500, 10):
        add(step, "DDoS")
    for step in range(2500, 2600, 10):
        add(step, "BruteForce")
    for step in range(2600, 4000, 10):
        add(step, "Benign")

    times = [T0 + timedelta(seconds=t) for t in range(0, 4000, 60)]
    scores = [0.9 if 2300 <= t < 2700 else 0.1 for t in range(0, 4000, 60)]

    report = evaluate_event_level(
        events, times, scores,
        lead_seconds=30.0, horizon_seconds=120.0, threshold=0.5,
        model_id="handbuilt",
    )
    assert report.available, report.refusal_reason

    multi = [e for e in report.events if len(e.labels or []) > 1]
    assert multi, "the fixture must produce an episode carrying two labels"

    names = {s.scenario for s in report.by_scenario}
    assert {"DDoS", "BruteForce"} <= names, (
        f"both labels of a mixed episode must appear; got {names}"
    )
    # And the totals exceed events_total precisely because of it.
    assert sum(s.events_total for s in report.by_scenario) > report.events_total
