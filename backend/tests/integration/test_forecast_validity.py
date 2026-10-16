"""
Forecast validity: provenance separation, coverage honesty, ongoing-attack
leakage, and the persistence baseline.

The failure mode throughout is the same: a result that is arithmetically
correct and describes something other than what the reader believes. A
model trained on a silently truncated slice. A "forecast" that is really a
detection of an attack already visible in the observation window. A
baseline nobody ran, so a mediocre model looks good.

Documentation addresses only (RFC 5737).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import numpy as np
import pytest
from fastapi.testclient import TestClient

from app.api.deps import get_db
from app.main import app
from app.models.feature_extractor import WindowFeatureExtractor
from app.models.forecaster import PersistenceBaseline, ThreatForecastingPipeline
from app.models.registry import reset_forecasting_pipeline
from app.research.selection import (
    MixedProvenanceRefused,
    select_training_events,
)
from app.schemas.events import (
    DataCategory,
    EventType,
    LabelProvenance,
    NormalizedEvent,
    TelemetrySource,
)
from app.storage.database import Database

BASE = datetime(2026, 6, 1, 0, 0, 0, tzinfo=timezone.utc)


def _event(idx, offset_s, category, label=None, source="s"):
    return NormalizedEvent(
        event_id=f"{source}-{category.value}-{idx}",
        source_id=source,
        data_category=category,
        observed_at=BASE + timedelta(seconds=offset_s),
        event_type=EventType.NETWORK_FLOW,
        src_ip="192.0.2.10",
        dst_ip="198.51.100.20",
        src_port=40000 + (idx % 1000),
        dst_port=443,
        protocol="TCP",
        label=label,
        label_provenance=(
            LabelProvenance.DATASET_GROUND_TRUTH if label else LabelProvenance.UNLABELED
        ),
    )


@pytest.fixture
def db(tmp_path):
    database = Database(db_path=str(tmp_path / "validity.db"))
    database.initialize()
    for sid in ("bench", "live", "synth"):
        database.upsert_source(
            TelemetrySource(source_id=sid, name=sid, source_type="csv_import")
        )
    yield database
    database.close()


# ──────────────────────────────────────────────────────────────────
# 16–17. Provenance separation
# ──────────────────────────────────────────────────────────────────


def test_benchmark_only_selection_excludes_live_events(db):
    db.insert_events(
        [_event(i, i, DataCategory.HISTORICAL_IMPORT, "Benign", "bench") for i in range(40)]
        + [_event(i, i, DataCategory.LIVE_TELEMETRY, None, "live") for i in range(40)]
    )

    events, coverage = select_training_events(
        db, data_category=DataCategory.HISTORICAL_IMPORT.value, max_events=1000
    )

    assert len(events) == 40
    assert set(coverage.category_breakdown) == {"historical_import"}
    assert coverage.mixed_provenance is False
    assert all(e.data_category is DataCategory.HISTORICAL_IMPORT for e in events)


def test_unfiltered_selection_spanning_provenance_classes_is_refused(db):
    db.insert_events(
        [_event(i, i, DataCategory.HISTORICAL_IMPORT, "Benign", "bench") for i in range(20)]
        + [_event(i, i, DataCategory.LIVE_TELEMETRY, None, "live") for i in range(20)]
    )

    with pytest.raises(MixedProvenanceRefused) as exc:
        select_training_events(db, max_events=1000)

    assert "provenance" in str(exc.value).lower()
    assert set(exc.value.coverage.provenance_classes) == {"benchmark", "live"}


def test_mixing_is_allowed_when_asked_for_and_is_recorded(db):
    db.insert_events(
        [_event(i, i, DataCategory.HISTORICAL_IMPORT, "Benign", "bench") for i in range(20)]
        + [_event(i, i, DataCategory.SYNTHETIC_DEMO, "DDoS", "synth") for i in range(20)]
    )

    events, coverage = select_training_events(
        db, max_events=1000, allow_mixed_provenance=True
    )

    assert len(events) == 40
    assert coverage.mixed_provenance is True
    assert any("MIXED PROVENANCE" in w for w in coverage.warnings)
    assert coverage.category_breakdown == {"historical_import": 20, "synthetic_demo": 20}


def test_source_id_alone_is_not_treated_as_provenance(db):
    """
    A source id is a name an operator chose. Two categories under one name
    must still be detected as mixed.
    """
    db.insert_events(
        [_event(i, i, DataCategory.HISTORICAL_IMPORT, "Benign", "bench") for i in range(20)]
        + [_event(i, i, DataCategory.LIVE_TELEMETRY, None, "bench") for i in range(20)]
    )
    with pytest.raises(MixedProvenanceRefused):
        select_training_events(db, source_id="bench", max_events=1000)


def test_label_distribution_and_provenance_are_reported(db):
    db.insert_events(
        [_event(i, i, DataCategory.HISTORICAL_IMPORT, "Benign", "bench") for i in range(30)]
        + [_event(100 + i, 100 + i, DataCategory.HISTORICAL_IMPORT, "DDoS", "bench") for i in range(10)]
    )
    _, coverage = select_training_events(
        db, data_category=DataCategory.HISTORICAL_IMPORT.value, max_events=1000
    )
    assert coverage.label_distribution == {"Benign": 30, "DDoS": 10}
    assert coverage.label_provenance_breakdown == {"dataset_ground_truth": 40}


# ──────────────────────────────────────────────────────────────────
# 18–19. Coverage honesty and ordering
# ──────────────────────────────────────────────────────────────────


def test_truncation_is_reported_not_silently_applied(db):
    db.insert_events(
        [_event(i, i, DataCategory.HISTORICAL_IMPORT, "Benign", "bench") for i in range(100)]
    )

    _, coverage = select_training_events(
        db, data_category=DataCategory.HISTORICAL_IMPORT.value, max_events=25
    )

    assert coverage.truncated is True
    assert coverage.complete is False
    assert coverage.matching_events_total == 100
    assert coverage.selected_events == 25
    assert coverage.coverage_fraction == pytest.approx(0.25)
    assert any("25 of 100" in w for w in coverage.warnings)
    assert coverage.selection_strategy == "most_recent_by_observed_at"


def test_a_complete_selection_is_marked_complete(db):
    db.insert_events(
        [_event(i, i, DataCategory.HISTORICAL_IMPORT, "Benign", "bench") for i in range(10)]
    )
    _, coverage = select_training_events(
        db, data_category=DataCategory.HISTORICAL_IMPORT.value, max_events=1000
    )
    assert coverage.truncated is False
    assert coverage.complete is True
    assert coverage.warnings == []


def test_selection_is_returned_in_chronological_order(db):
    """
    list_events returns most-recent-first. Every downstream step assumes the
    opposite, so the order is restored at the selection boundary rather than
    relying on each consumer to sort defensively.
    """
    db.insert_events(
        [_event(i, i * 60, DataCategory.HISTORICAL_IMPORT, "Benign", "bench") for i in range(50)]
    )
    events, _ = select_training_events(
        db, data_category=DataCategory.HISTORICAL_IMPORT.value, max_events=1000
    )
    times = [e.observed_at for e in events]
    assert times == sorted(times)


def test_truncated_selection_is_still_chronological(db):
    db.insert_events(
        [_event(i, i * 60, DataCategory.HISTORICAL_IMPORT, "Benign", "bench") for i in range(100)]
    )
    events, coverage = select_training_events(
        db, data_category=DataCategory.HISTORICAL_IMPORT.value, max_events=20
    )
    times = [e.observed_at for e in events]
    assert times == sorted(times)
    assert coverage.selected_time_range[0] == times[0].isoformat()


# ──────────────────────────────────────────────────────────────────
# 20. Ongoing-attack windows
# ──────────────────────────────────────────────────────────────────


def _timed(labels_by_second: dict[int, str], span: int = 1200):
    """One event per second; labels_by_second marks which carry an attack."""
    events = []
    for second in range(span):
        label = labels_by_second.get(second, "Benign")
        events.append(
            _event(second, second, DataCategory.HISTORICAL_IMPORT, label, "bench")
        )
    return events


def test_windows_with_an_attack_already_in_progress_are_counted():
    """
    Predicting "attack soon" from "attack now" is detection. The count must
    be visible, or a detection result reads as a forecasting result.
    """
    attack = {s: "DDoS" for s in range(300, 900)}
    extractor = WindowFeatureExtractor(
        window_size_seconds=60, lead_time_seconds=30, prediction_horizon_seconds=60
    )
    X, y, _ = extractor.build_dataset_instances(_timed(attack))

    report = extractor.last_windowing_report
    assert report.windows_with_attack_in_observation > 0
    assert report.windows_excluded_ongoing_attack == 0  # counted, not dropped
    assert report.exclude_ongoing_attack_windows is False


def test_ongoing_attack_windows_can_be_excluded_on_request():
    attack = {s: "DDoS" for s in range(300, 900)}
    excluding = WindowFeatureExtractor(
        window_size_seconds=60, lead_time_seconds=30,
        prediction_horizon_seconds=60, exclude_ongoing_attack_windows=True,
    )
    X_excl, y_excl, _ = excluding.build_dataset_instances(_timed(attack))

    keeping = WindowFeatureExtractor(
        window_size_seconds=60, lead_time_seconds=30, prediction_horizon_seconds=60
    )
    X_keep, _, _ = keeping.build_dataset_instances(_timed(attack))

    assert excluding.last_windowing_report.windows_excluded_ongoing_attack > 0
    assert len(X_excl) < len(X_keep)


def test_a_quiet_dataset_reports_no_ongoing_attack_windows():
    extractor = WindowFeatureExtractor(
        window_size_seconds=60, lead_time_seconds=30, prediction_horizon_seconds=60
    )
    extractor.build_dataset_instances(_timed({}))
    assert extractor.last_windowing_report.windows_with_attack_in_observation == 0


def test_an_attack_starting_only_after_the_horizon_leaves_observations_clean():
    """Attack strictly in the future: positives exist, none is 'ongoing'."""
    attack = {s: "DDoS" for s in range(1000, 1200)}
    extractor = WindowFeatureExtractor(
        window_size_seconds=60, lead_time_seconds=30, prediction_horizon_seconds=60
    )
    X, y, _ = extractor.build_dataset_instances(_timed(attack))
    mask = extractor.last_observation_attack_mask

    assert len(mask) == len(y)
    # The first positive window must have a clean observation period.
    positives = np.flatnonzero(y == 1)
    assert len(positives) > 0
    assert mask[positives[0]] == 0


def test_the_observation_attack_mask_aligns_with_the_dataset():
    attack = {s: "DDoS" for s in range(300, 900)}
    extractor = WindowFeatureExtractor(
        window_size_seconds=60, lead_time_seconds=30, prediction_horizon_seconds=60
    )
    X, y, ts = extractor.build_dataset_instances(_timed(attack))
    mask = extractor.last_observation_attack_mask
    assert len(mask) == len(X) == len(y) == len(ts)
    assert set(np.unique(mask)).issubset({0, 1})


# ──────────────────────────────────────────────────────────────────
# 22. Persistence baseline
# ──────────────────────────────────────────────────────────────────


def test_persistence_baseline_learns_the_conditional_rates():
    state = np.array([1, 1, 1, 1, 0, 0, 0, 0])
    y = np.array([1, 1, 1, 0, 0, 0, 0, 1])

    model = PersistenceBaseline().fit(state, y)

    assert model.rate_when_active == pytest.approx(0.75)
    assert model.rate_when_quiet == pytest.approx(0.25)
    np.testing.assert_allclose(
        model.predict_proba(np.array([1, 0]))[:, 1], [0.75, 0.25]
    )


def test_persistence_baseline_uses_no_future_label():
    """
    Its only input is the observation-window indicator, which describes
    [t-W, t). Scoring must not depend on y at all.
    """
    state = np.array([1, 0, 1, 0])
    model = PersistenceBaseline().fit(np.array([1, 1, 0, 0]), np.array([1, 0, 0, 0]))
    first = model.predict_proba(state)
    second = model.predict_proba(state)
    np.testing.assert_allclose(first, second)
    assert model.predict_proba(state).shape == (4, 2)


def test_persistence_baseline_handles_a_single_state():
    model = PersistenceBaseline().fit(np.ones(5, dtype=int), np.array([1, 1, 0, 1, 1]))
    assert model.rate_when_active == pytest.approx(0.8)
    assert model.rate_when_quiet == 0.0  # no quiet rows observed; not invented


def test_persistence_baseline_is_evaluated_alongside_the_models():
    from app.adapters.synthetic_replay import SyntheticFlowGenerator

    events = SyntheticFlowGenerator(seed=5, source_id="s").generate_scenario_batch(
        count=900, attack_ratio=0.3, start_time=BASE
    )
    metrics = ThreatForecastingPipeline().train_and_evaluate_all(events, train_ratio=0.7)

    assert "baseline_persistence" in metrics, "the persistence baseline did not run"
    persistence = metrics["baseline_persistence"]
    assert persistence.model_type == "baseline_persistence"
    # Same holdout as the snapshot models.
    assert persistence.test_instances == metrics["random_forest_forecaster"].test_instances


# ──────────────────────────────────────────────────────────────────
# 23. Degenerate evaluation sets
# ──────────────────────────────────────────────────────────────────


def test_an_empty_dataset_is_refused_not_scored(db):
    events, coverage = select_training_events(
        db, data_category=DataCategory.HISTORICAL_IMPORT.value, max_events=100
    )
    assert events == []
    assert coverage.selected_events == 0
    assert coverage.coverage_fraction is None


def test_a_single_class_dataset_cannot_be_trained():
    pipeline = ThreatForecastingPipeline()
    benign_only = _timed({})
    with pytest.raises(ValueError) as exc:
        pipeline.train_and_evaluate_all(benign_only, train_ratio=0.7)
    assert "class" in str(exc.value).lower()


def test_metrics_declare_themselves_uninterpretable_on_a_tiny_holdout():
    from app.adapters.synthetic_replay import SyntheticFlowGenerator

    events = SyntheticFlowGenerator(seed=3, source_id="s").generate_scenario_batch(
        count=200, attack_ratio=0.3, start_time=BASE
    )
    try:
        metrics = ThreatForecastingPipeline().train_and_evaluate_all(events, 0.7)
    except ValueError:
        pytest.skip("dataset too small to produce any split, which is also correct")

    for name, m in metrics.items():
        if m.test_instances is not None and m.test_instances < 20:
            assert m.metrics_interpretable is False, name


# ──────────────────────────────────────────────────────────────────
# API
# ──────────────────────────────────────────────────────────────────


@pytest.fixture
def client(db):
    reset_forecasting_pipeline()
    app.dependency_overrides[get_db] = lambda: db
    with TestClient(app) as c:
        yield c, db
    app.dependency_overrides.clear()


def test_train_endpoint_refuses_mixed_provenance_by_default(client):
    c, database = client
    from app.adapters.synthetic_replay import SyntheticFlowGenerator

    database.insert_events(
        SyntheticFlowGenerator(seed=5, source_id="synth").generate_scenario_batch(
            count=900, attack_ratio=0.3, start_time=BASE
        )
    )
    database.insert_events(
        [_event(i, i, DataCategory.HISTORICAL_IMPORT, "Benign", "bench") for i in range(60)]
    )

    res = c.post("/api/v1/forecast/train", json={})
    assert res.status_code == 409
    body = res.json()["detail"]
    assert body["error"] == "mixed_provenance_training_refused"
    assert "coverage" in body
    assert sorted(body["coverage"]["provenance_classes"]) == ["benchmark", "generated"]


def test_train_endpoint_accepts_a_single_provenance_class(client):
    c, database = client
    from app.adapters.synthetic_replay import SyntheticFlowGenerator

    database.insert_events(
        SyntheticFlowGenerator(seed=5, source_id="synth").generate_scenario_batch(
            count=900, attack_ratio=0.3, start_time=BASE
        )
    )
    res = c.post("/api/v1/forecast/train", json={"data_category": "synthetic_demo"})
    assert res.status_code == 200, res.text


def test_coverage_endpoint_reports_what_the_result_was_computed_over(client):
    c, database = client
    from app.adapters.synthetic_replay import SyntheticFlowGenerator

    database.insert_events(
        SyntheticFlowGenerator(seed=5, source_id="synth").generate_scenario_batch(
            count=900, attack_ratio=0.3, start_time=BASE
        )
    )
    assert c.get("/api/v1/forecast/coverage").json() is None

    c.post("/api/v1/forecast/train", json={"data_category": "synthetic_demo"})
    coverage = c.get("/api/v1/forecast/coverage").json()

    assert coverage["selected_events"] == 900
    assert coverage["matching_events_total"] == 900
    assert coverage["truncated"] is False
    assert coverage["category_breakdown"] == {"synthetic_demo": 900}


def test_coverage_endpoint_exposes_truncation(client):
    c, database = client
    from app.adapters.synthetic_replay import SyntheticFlowGenerator

    database.insert_events(
        SyntheticFlowGenerator(seed=5, source_id="synth").generate_scenario_batch(
            count=900, attack_ratio=0.3, start_time=BASE
        )
    )
    c.post(
        "/api/v1/forecast/train",
        json={"data_category": "synthetic_demo", "max_events": 300},
    )
    coverage = c.get("/api/v1/forecast/coverage").json()

    assert coverage["truncated"] is True
    assert coverage["selected_events"] == 300
    assert coverage["matching_events_total"] == 900
    assert coverage["warnings"]
