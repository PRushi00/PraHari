"""
Tests for the reproducible experiment manifest and replay runner
(blueprint §16, DoD item 13).

The point of a replay runner is not that it produces a number — it is that
it **refuses** when the inputs have changed. Most of these tests exercise
the refusal paths.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.adapters.synthetic_replay import SyntheticFlowGenerator
from app.api.deps import get_db
from app.core.config import AppConfig, get_config
from app.main import app
from app.models.forecaster import ThreatForecastingPipeline
from app.models.registry import reset_forecasting_pipeline
from app.research.experiment import (
    MANIFEST_VERSION,
    NON_DETERMINISTIC_OUTPUTS,
    DatasetSelector,
    ExperimentManifest,
    ManifestInvalidError,
    ReplayMismatchError,
    build_manifest,
    fingerprint_events,
    replay_experiment,
)
from app.schemas.events import (
    DataCategory,
    EventType,
    LabelProvenance,
    NormalizedEvent,
    TelemetrySource,
)
from app.storage.database import Database


@pytest.fixture
def seeded_db(tmp_path):
    db = Database(db_path=str(tmp_path / "exp.db"))
    db.initialize()
    db.upsert_source(
        TelemetrySource(source_id="s", name="S", source_type="synthetic_replay")
    )
    db.insert_events(
        SyntheticFlowGenerator(seed=99, source_id="s").generate_scenario_batch(
            count=800, attack_ratio=0.25
        )
    )
    yield db
    db.close()


def _capture(db, train_ratio: float = 0.7, experiment_id: str = "exp-001"):
    selector = DatasetSelector(source_id="s", max_events=20_000)
    events = db.list_events(source_id="s", limit=20_000)
    pipeline = ThreatForecastingPipeline()
    pipeline.train_and_evaluate_all(events, train_ratio=train_ratio)
    return build_manifest(
        experiment_id=experiment_id,
        events=events,
        selector=selector,
        pipeline=pipeline,
        description="synthetic baseline",
    )


# ──────────────────────────────────────────────────────────────────
# Manifest content
# ──────────────────────────────────────────────────────────────────


def test_manifest_records_everything_needed_to_rebuild(seeded_db):
    m = _capture(seeded_db)

    assert m.manifest_version == MANIFEST_VERSION
    assert m.dataset_fingerprint and len(m.dataset_fingerprint) == 64
    assert m.event_count == 800
    assert m.event_time_range and len(m.event_time_range) == 2

    # Target and window semantics
    assert "y=1" in m.target_definition and "y=0 only when" in m.target_definition
    assert m.windowing.observation_window_seconds > 0
    assert m.windowing.prediction_horizon_seconds > 0
    assert m.windowing.require_labelled_horizon is True

    # The CONFIGURED ratio, not one derived from resulting split sizes.
    assert m.split.train_ratio == 0.7
    assert m.split.strategy == "chronological_train_side_purge"
    assert m.split.random_seed == 42

    # Provenance makes synthetic data obvious.
    assert m.data_category_breakdown == {"synthetic_demo": 800}
    # Synthetic labels must be reported as synthetic, not as locally derived
    # rules and certainly not as ground truth. Every metric this project has
    # produced so far rests on them.
    assert "synthetic_rule" in m.label_provenance_breakdown
    assert "rule_based" not in m.label_provenance_breakdown
    assert "dataset_ground_truth" not in m.label_provenance_breakdown

    # Environment and dependencies, for diagnosis.
    assert m.environment.python_version and m.environment.platform
    assert m.feature_names

    assert m.model_results and "random_forest_forecaster" in m.model_results


def test_manifest_contains_no_telemetry(seeded_db):
    """
    A manifest must be safe to commit or share: counts, hashes, ranges and
    configuration only — never observed addresses or record content.

    Note that FEATURE NAMES such as "distinct_src_ips" legitimately appear;
    they describe a computation, not an observation.
    """
    import re

    m = _capture(seeded_db)
    flat = json.dumps(m.model_dump(mode="json"))

    # No literal IPv4 addresses anywhere.
    addresses = re.findall(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", flat)
    assert not addresses, f"manifest leaks IP addresses: {addresses[:5]}"

    # No per-record telemetry fields.
    for leaked_key in ('"src_ip"', '"dst_ip"', '"src_port"', '"dst_port"',
                       '"raw_reference"', '"event_id"', '"dst_hostname"'):
        assert leaked_key not in flat, f"manifest leaks record field {leaked_key}"

    # Feature names are expected and are not telemetry.
    assert "distinct_src_ips" in flat


def test_manifest_roundtrips_through_disk(seeded_db, tmp_path):
    m = _capture(seeded_db)
    path = m.save(tmp_path / "m.json")
    loaded = ExperimentManifest.load(path)
    assert loaded.dataset_fingerprint == m.dataset_fingerprint
    assert loaded.split.train_ratio == m.split.train_ratio


# ──────────────────────────────────────────────────────────────────
# Deterministic reproduction
# ──────────────────────────────────────────────────────────────────


def test_replay_reproduces_the_original_exactly(seeded_db):
    m = _capture(seeded_db)
    result = replay_experiment(m, seeded_db)

    assert result.dataset_fingerprint_matched is True
    assert result.reproduced is True, f"differences: {result.differences}"
    assert result.differences == []
    assert "confusion_matrix" in result.deterministic_outputs_checked


def test_replay_is_idempotent(seeded_db):
    m = _capture(seeded_db)
    first = replay_experiment(m, seeded_db)
    second = replay_experiment(m, seeded_db)
    assert first.replayed == second.replayed


def test_replay_does_not_modify_telemetry(seeded_db):
    """Replay selects and evaluates; it must never write."""
    before_events = seeded_db.count_events()
    before_sources = len(seeded_db.list_sources())
    fp_before = fingerprint_events(seeded_db.list_events(limit=20_000))

    m = _capture(seeded_db)
    replay_experiment(m, seeded_db)

    assert seeded_db.count_events() == before_events
    assert len(seeded_db.list_sources()) == before_sources
    assert fingerprint_events(seeded_db.list_events(limit=20_000)) == fp_before


# ──────────────────────────────────────────────────────────────────
# Fail-closed behaviour
# ──────────────────────────────────────────────────────────────────


def test_replay_refuses_when_the_dataset_changed(seeded_db):
    """Adding events changes the fingerprint; replay must refuse."""
    m = _capture(seeded_db)

    seeded_db.insert_events([
        NormalizedEvent(
            source_id="s",
            data_category=DataCategory.SYNTHETIC_DEMO,
            observed_at=datetime.now(timezone.utc),
            event_type=EventType.NETWORK_FLOW,
            src_ip="192.0.2.10", dst_ip="198.51.100.9",
            src_port=4000, dst_port=443, protocol="TCP",
            label="Benign", label_provenance=LabelProvenance.RULE_BASED,
        )
    ])

    with pytest.raises(ReplayMismatchError) as exc:
        replay_experiment(m, seeded_db)
    assert any("fingerprint mismatch" in d for d in exc.value.mismatches)
    assert any("has changed" in d for d in exc.value.mismatches)


def test_replay_refuses_when_the_dataset_is_missing(seeded_db, tmp_path):
    """A selector matching nothing is a missing dataset, not an empty run."""
    m = _capture(seeded_db)
    m.dataset = DatasetSelector(source_id="source_that_does_not_exist")

    with pytest.raises(ReplayMismatchError) as exc:
        replay_experiment(m, seeded_db)
    assert any("dataset is unavailable" in d.lower() for d in exc.value.mismatches)


def test_replay_refuses_on_schema_version_change(seeded_db):
    m = _capture(seeded_db)
    m.schema_version = "0.9.0"

    with pytest.raises(ReplayMismatchError) as exc:
        replay_experiment(m, seeded_db)
    assert any("schema version changed" in d.lower() for d in exc.value.mismatches)


def test_replay_refuses_on_feature_set_change(seeded_db):
    m = _capture(seeded_db)
    m.feature_names = m.feature_names + ["a_feature_that_no_longer_exists"]

    with pytest.raises(ReplayMismatchError) as exc:
        replay_experiment(m, seeded_db)
    assert any("feature set changed" in d.lower() for d in exc.value.mismatches)


def test_replay_reports_all_mismatches_at_once(seeded_db):
    m = _capture(seeded_db)
    m.schema_version = "0.9.0"
    m.feature_names = ["only_one"]

    with pytest.raises(ReplayMismatchError) as exc:
        replay_experiment(m, seeded_db)
    assert len(exc.value.mismatches) >= 2


def test_replay_refuses_when_configuration_no_longer_evaluates(seeded_db):
    """A window config that yields no valid split must abort, not guess."""
    m = _capture(seeded_db)
    # A horizon far larger than the data span cannot produce a holdout.
    m.windowing.observation_window_seconds = 100_000.0
    m.windowing.prediction_horizon_seconds = 100_000.0

    with pytest.raises(ReplayMismatchError) as exc:
        replay_experiment(m, seeded_db)
    assert any("no longer yields a valid evaluation" in d for d in exc.value.mismatches)


# ──────────────────────────────────────────────────────────────────
# Manifest validation
# ──────────────────────────────────────────────────────────────────


def test_unsupported_manifest_major_version_is_rejected(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text(json.dumps({"manifest_version": "9.0.0"}), encoding="utf-8")
    with pytest.raises(ManifestInvalidError):
        ExperimentManifest.load(path)


def test_malformed_manifest_is_rejected(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("{not valid json", encoding="utf-8")
    with pytest.raises(ManifestInvalidError) as exc:
        ExperimentManifest.load(path)
    assert "not valid JSON" in str(exc.value)


def test_incomplete_manifest_is_rejected(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text(
        json.dumps({"manifest_version": MANIFEST_VERSION, "experiment_id": "x"}),
        encoding="utf-8",
    )
    with pytest.raises(ManifestInvalidError) as exc:
        ExperimentManifest.load(path)
    assert "failed validation" in str(exc.value)


def test_non_deterministic_outputs_are_documented():
    """Timings vary; the manifest must not claim they are reproducible."""
    assert "training_time_seconds" in NON_DETERMINISTIC_OUTPUTS
    assert "evaluated_at" in NON_DETERMINISTIC_OUTPUTS


# ──────────────────────────────────────────────────────────────────
# API surface
# ──────────────────────────────────────────────────────────────────


@pytest.fixture
def api(seeded_db, tmp_path):
    reset_forecasting_pipeline()
    cfg = AppConfig(database_url=f"sqlite:///{tmp_path / 'exp.db'}")
    # Keep manifests inside the test's temporary tree.
    object.__setattr__(cfg, "_test_root", tmp_path)
    app.dependency_overrides[get_db] = lambda: seeded_db
    app.dependency_overrides[get_config] = lambda: cfg
    with TestClient(app) as client:
        yield client, seeded_db, tmp_path
    app.dependency_overrides.clear()
    reset_forecasting_pipeline()


def test_capture_requires_a_prior_evaluation(api):
    client, _, _ = api
    res = client.post("/api/v1/experiments/capture", json={"experiment_id": "e1"})
    assert res.status_code == 409
    assert res.json()["detail"]["error"] == "no_evaluation_to_capture"


def test_capture_then_replay_through_the_api(api):
    client, _, _ = api

    assert client.post(
        "/api/v1/forecast/train", json={"source_id": "s", "max_events": 20000}
    ).status_code == 200

    captured = client.post(
        "/api/v1/experiments/capture",
        json={"experiment_id": "api-exp-1", "source_id": "s", "description": "api run"},
    )
    assert captured.status_code == 200, captured.json()
    assert captured.json()["dataset_fingerprint"]

    listed = client.get("/api/v1/experiments").json()
    assert "api-exp-1" in listed

    replayed = client.post("/api/v1/experiments/api-exp-1/replay")
    assert replayed.status_code == 200, replayed.json()
    body = replayed.json()
    assert body["reproduced"] is True
    assert body["differences"] == []


def test_replay_api_refuses_a_changed_dataset(api):
    client, db, _ = api
    client.post("/api/v1/forecast/train", json={"source_id": "s", "max_events": 20000})
    client.post(
        "/api/v1/experiments/capture",
        json={"experiment_id": "api-exp-2", "source_id": "s"},
    )

    db.insert_events([
        NormalizedEvent(
            source_id="s",
            data_category=DataCategory.SYNTHETIC_DEMO,
            observed_at=datetime.now(timezone.utc) + timedelta(seconds=5),
            event_type=EventType.NETWORK_FLOW,
            src_ip="192.0.2.11", dst_ip="198.51.100.10",
            src_port=4100, dst_port=443, protocol="TCP",
            label="Benign", label_provenance=LabelProvenance.RULE_BASED,
        )
    ])

    res = client.post("/api/v1/experiments/api-exp-2/replay")
    assert res.status_code == 409
    detail = res.json()["detail"]
    assert detail["error"] == "experiment_not_reproducible"
    assert detail["mismatches"]
    assert "remediation" in detail


def test_unknown_experiment_returns_404(api):
    client, _, _ = api
    assert client.post("/api/v1/experiments/nope/replay").status_code == 404
    assert client.get("/api/v1/experiments/nope").status_code == 404


@pytest.mark.parametrize("bad_id", ["../escape", "a/b", "c:\\evil", "..", "x?y"])
def test_experiment_id_traversal_is_rejected(api, bad_id):
    client, _, _ = api
    res = client.get(f"/api/v1/experiments/{bad_id}")
    assert res.status_code in (400, 404), f"{bad_id} was not rejected"
