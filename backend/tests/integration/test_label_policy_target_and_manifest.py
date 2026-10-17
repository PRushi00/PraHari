"""
PraHari — Label Provenance Policy, Structured Target, Manifest Provenance (ADR-070).

Three defects closed together because they share one cause: the research
record did not say what its evidence was.

1. Training read label TEXT and never its provenance, so a model could be
   trained and scored on another model's predictions, or on a corpus's
   labels merged with a detector's opinions.
2. The feasibility audit's "Data Provenance Integrity" check was
   `passed=True` unconditionally. It could not fail.
3. The manifest stored the target as one sentence of prose and omitted
   the git revision, a configuration hash, package versions, model
   parameters, the threshold procedure and any statement of limitations.

All data here is synthetic and generated per test. Nothing in this module
supports a claim about real-world forecasting performance - which is
precisely what the new manifest fields now say.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone

import pytest

from app.adapters.synthetic_replay import SyntheticFlowGenerator
from app.models.forecaster import ThreatForecastingPipeline
from app.research.experiment import (
    MANIFEST_VERSION,
    DatasetSelector,
    ExperimentManifest,
    build_manifest,
    fingerprint_events,
)
from app.research.feasibility import audit_dataset_feasibility
from app.research.label_policy import (
    LabelProvenanceError,
    assess_label_provenance,
    enforce_label_policy,
)
from app.research.target import TARGET_ID, TARGET_VERSION, build_target_specification
from app.schemas.events import DataCategory, EventType, LabelProvenance, NormalizedEvent

T0 = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)


def _ev(i, label, provenance, category=DataCategory.HISTORICAL_IMPORT, received=None):
    return NormalizedEvent(
        event_id=f"lp-{i}", source_id="lp", data_category=category,
        observed_at=T0 + timedelta(seconds=i), received_at=received,
        event_type=EventType.NETWORK_FLOW, src_ip="192.0.2.1", dst_ip="198.51.100.2",
        src_port=40000 + i, dst_port=443, protocol="TCP",
        label=label, label_provenance=provenance,
    )


def _synthetic(n=800, seed=99):
    return SyntheticFlowGenerator(seed=seed, source_id="s").generate_scenario_batch(
        count=n, attack_ratio=0.25
    )


# ──────────────────────────────────────────────────────────────────
# Label provenance policy
# ──────────────────────────────────────────────────────────────────


def test_a_models_own_predictions_are_never_ground_truth():
    events = [_ev(i, "attack" if i % 3 else "benign", LabelProvenance.MODEL_PREDICTION)
              for i in range(30)]
    with pytest.raises(LabelProvenanceError, match="against itself"):
        enforce_label_policy(events)


def test_dataset_labels_and_detector_opinions_are_not_merged():
    events = (
        [_ev(i, "benign", LabelProvenance.DATASET_GROUND_TRUTH) for i in range(20)]
        + [_ev(100 + i, "ET SCAN", LabelProvenance.DETECTOR_OUTPUT) for i in range(5)]
    )
    with pytest.raises(LabelProvenanceError) as exc:
        enforce_label_policy(events)
    message = str(exc.value)
    assert "dataset_ground_truth" in message and "detector_output" in message
    assert "not merged" in message


def test_training_itself_refuses_mixed_provenance():
    """Enforced at the single training entry point, not only in an audit."""
    events = [e.model_copy(update={"label_provenance": LabelProvenance.DATASET_GROUND_TRUTH})
              for e in _synthetic(400)]
    events[0] = events[0].model_copy(update={"label_provenance": LabelProvenance.DETECTOR_OUTPUT,
                                             "label": "ET POLICY"})
    with pytest.raises(LabelProvenanceError):
        ThreatForecastingPipeline().train_and_evaluate_all(events)


def test_a_single_detector_provenance_is_allowed_and_named_for_what_it_is():
    events = [_ev(i, "ET SCAN" if i % 2 else "benign", LabelProvenance.DETECTOR_OUTPUT)
              for i in range(10)]
    result = enforce_label_policy(events)
    assert result.evidence_class == "detector_alerts"
    assert "DETECTOR'S ALERTS" in result.evidence_meaning


def test_synthetic_labels_are_classified_synthetic_only():
    result = assess_label_provenance(_synthetic(200))
    assert result.evidence_class == "synthetic_only"
    assert "SYNTHETIC-ONLY" in result.evidence_meaning


def test_labels_without_a_declared_provenance_are_reported_not_promoted():
    events = [_ev(i, "attack", LabelProvenance.UNLABELED) for i in range(5)]
    result = enforce_label_policy(events)
    assert result.undeclared_labelled_events == 5
    assert result.evidence_class == "undeclared"
    assert result.label_provenance is None


def test_unlabelled_events_do_not_count_as_a_provenance():
    events = (
        [_ev(i, "benign", LabelProvenance.DATASET_GROUND_TRUTH) for i in range(10)]
        + [_ev(100 + i, None, LabelProvenance.UNLABELED) for i in range(10)]
    )
    assert enforce_label_policy(events).evidence_class == "dataset_labels"


# ──────────────────────────────────────────────────────────────────
# The feasibility check can now fail
# ──────────────────────────────────────────────────────────────────


def _provenance_check(events):
    report = audit_dataset_feasibility(events, dataset_id="lp")
    (check,) = [c for c in report.checks if c.check_name == "Data Provenance Integrity"]
    return check


def test_the_provenance_check_fails_on_model_prediction_labels():
    events = [_ev(i, "attack" if i % 4 == 0 else "benign", LabelProvenance.MODEL_PREDICTION)
              for i in range(60)]
    check = _provenance_check(events)
    assert check.passed is False, "this check used to pass unconditionally"
    assert check.risk_level == "high"


def test_the_provenance_check_fails_on_mixed_provenance():
    events = (
        [_ev(i, "benign", LabelProvenance.DATASET_GROUND_TRUTH) for i in range(50)]
        + [_ev(100 + i, "ET SCAN", LabelProvenance.DETECTOR_OUTPUT) for i in range(10)]
    )
    assert _provenance_check(events).passed is False


def test_the_provenance_check_passes_on_one_coherent_provenance():
    check = _provenance_check(_synthetic(200))
    assert check.passed is True
    assert "synthetic_only" in check.details


# ──────────────────────────────────────────────────────────────────
# Structured target
# ──────────────────────────────────────────────────────────────────


def _spec(**overrides):
    params = dict(window_seconds=60, lead_seconds=30, horizon_seconds=60, stride_seconds=15,
                  min_horizon_events=1, require_labelled_horizon=True,
                  exclude_ongoing_attack_windows=False)
    params.update(overrides)
    return build_target_specification(**params)


def test_the_target_is_identified_and_versioned():
    spec = _spec()
    assert spec.target_id == TARGET_ID
    assert spec.target_version == TARGET_VERSION


def test_equal_rules_give_equal_fingerprints_and_any_change_alters_it():
    assert _spec().fingerprint() == _spec().fingerprint()
    assert _spec().fingerprint() != _spec(horizon_seconds=120).fingerprint()
    assert _spec().fingerprint() != _spec(require_labelled_horizon=False).fingerprint()
    assert _spec().fingerprint() != _spec(exclude_ongoing_attack_windows=True).fingerprint()


def test_the_rules_describe_the_configuration_actually_used():
    strict, loose = _spec(), _spec(require_labelled_horizon=False)
    assert "carries a label" in strict.negative_rule
    assert "carries a label" not in loose.negative_rule
    assert "EXCLUDED" in _spec(exclude_ongoing_attack_windows=True).ongoing_attack_rule
    assert "KEPT" in _spec().ongoing_attack_rule


def test_the_target_refuses_to_be_read_as_more_than_its_labels():
    spec = _spec()
    joined = " ".join(spec.not_equivalent_to)
    for term in ("scenario start", "first labelled malicious flow", "compromise", "confirmed incident"):
        assert term in joined


def test_the_known_shortfalls_are_stated_not_hidden():
    limitations = " ".join(_spec().scope_limitations)
    assert "per WINDOW" in limitations
    assert "Event-level lead time" in limitations and "NOT" in limitations
    assert "suppression is not modelled" in limitations


def test_synthetic_evidence_leads_the_limitations():
    spec = _spec(evidence_class="synthetic_only")
    assert spec.scope_limitations[0].startswith("Labels are SYNTHETIC")


# ──────────────────────────────────────────────────────────────────
# Manifest provenance fields
# ──────────────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def manifest_pair():
    def capture():
        events = _synthetic(800)
        pipeline = ThreatForecastingPipeline()
        pipeline.train_and_evaluate_all(events, train_ratio=0.7)
        return build_manifest(experiment_id="lp-exp", events=events,
                              selector=DatasetSelector(source_id="s"), pipeline=pipeline)
    return capture(), capture()


def test_the_manifest_carries_the_structured_target(manifest_pair):
    m, _ = manifest_pair
    assert m.manifest_version == MANIFEST_VERSION == "1.1.0"
    assert m.target_specification["target_id"] == TARGET_ID
    assert re.fullmatch(r"[0-9a-f]{64}", m.target_fingerprint)
    assert m.target_specification["observation_window_seconds"] == m.windowing.observation_window_seconds


def test_the_manifest_states_what_its_evidence_is(manifest_pair):
    m, _ = manifest_pair
    assert m.label_policy["evidence_class"] == "synthetic_only"
    assert m.limitations[0].startswith("Labels are SYNTHETIC")


def test_the_configuration_hash_is_stable_across_runs_of_one_configuration(manifest_pair):
    a, b = manifest_pair
    assert re.fullmatch(r"[0-9a-f]{64}", a.configuration_hash)
    assert a.configuration_hash == b.configuration_hash


def test_git_revision_is_a_commit_or_honestly_unknown(manifest_pair):
    m, _ = manifest_pair
    assert m.git_revision is None or re.fullmatch(r"[0-9a-f]{40}", m.git_revision)
    if m.git_revision is None:
        assert m.git_worktree_dirty is None


def test_package_versions_and_model_parameters_are_recorded(manifest_pair):
    m, _ = manifest_pair
    assert m.package_versions["numpy"] and m.package_versions["scikit-learn"]
    lr = [p for p in m.model_parameters.values() if p["class"] == "LogisticRegression"]
    assert lr and lr[0]["random_state"] == 42 and "C" in lr[0]


def test_the_threshold_procedure_is_recorded(manifest_pair):
    m, _ = manifest_pair
    assert "never tuned" in m.threshold_selection


def test_a_1_0_0_manifest_still_loads_without_inventing_new_fields(manifest_pair, tmp_path):
    m, _ = manifest_pair
    old = m.model_dump(mode="json")
    old["manifest_version"] = "1.0.0"
    for added in ("target_specification", "target_fingerprint", "label_policy", "git_revision",
                  "git_worktree_dirty", "configuration_hash", "package_versions",
                  "model_parameters", "threshold_selection", "late_arrival_exclusions",
                  "limitations"):
        old.pop(added)
    path = tmp_path / "old.json"
    path.write_text(json.dumps(old), encoding="utf-8")

    loaded = ExperimentManifest.load(path)

    assert loaded.manifest_version == "1.0.0"
    assert loaded.git_revision is None and loaded.configuration_hash is None
    assert loaded.limitations == []


# ──────────────────────────────────────────────────────────────────
# Fingerprint follows what now affects features
# ──────────────────────────────────────────────────────────────────


def test_arrival_time_changes_a_live_fingerprint():
    on_time = [_ev(i, None, LabelProvenance.UNLABELED, DataCategory.LIVE_TELEMETRY,
                   received=T0 + timedelta(seconds=i + 1)) for i in range(5)]
    late = [e.model_copy(update={"received_at": e.received_at + timedelta(minutes=10)})
            for e in on_time]
    assert fingerprint_events(on_time) != fingerprint_events(late)


def test_import_time_does_not_change_a_historical_fingerprint():
    """Every pre-existing fingerprint of imported data stays byte-identical."""
    a = [_ev(i, "benign", LabelProvenance.DATASET_GROUND_TRUTH,
             received=T0 + timedelta(days=1)) for i in range(5)]
    b = [e.model_copy(update={"received_at": T0 + timedelta(days=99)}) for e in a]
    unstamped = [e.model_copy(update={"received_at": None}) for e in a]
    assert fingerprint_events(a) == fingerprint_events(b) == fingerprint_events(unstamped)
