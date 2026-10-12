"""
PraHari — Reproducible Experiment Manifest and Replay Runner

Blueprint §16 requires that an evaluation can be reconstructed from a
recorded manifest. A split report says what *was* done; a manifest must
contain enough to do it *again* and to refuse convincingly when the inputs
have changed.

Design rules enforced here
--------------------------
* **Fail closed.** A dataset fingerprint, schema version, target definition
  or window configuration that does not match aborts the replay with the
  specific mismatch named. Silently substituting a different dataset would
  produce a number that looks like a reproduction and is not one.
* **Read-only against telemetry.** Replay selects and evaluates; it never
  writes events, never mutates sources, and never deletes anything.
* **No telemetry in the manifest.** Only counts, hashes, ranges and
  configuration are recorded, so a manifest is safe to commit or share.
* **Honest determinism.** Fields whose reproduction is guaranteed are
  separated from those that legitimately vary by platform or library
  version (timings, and floating-point detail across BLAS builds).
"""

from __future__ import annotations

import hashlib
import json
import platform
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator

from app.models.feature_extractor import FEATURE_NAMES
from app.schemas.events import SCHEMA_VERSION, NormalizedEvent

MANIFEST_VERSION = "1.0.0"

# Outputs guaranteed identical on a successful replay of the same dataset.
DETERMINISTIC_OUTPUTS = (
    "dataset_fingerprint",
    "instance_count",
    "train_instances",
    "test_instances",
    "purged_instances",
    "train_positive",
    "test_positive",
    "confusion_matrix",
)

# Outputs that may legitimately differ between platforms or library builds.
NON_DETERMINISTIC_OUTPUTS = (
    "training_time_seconds",
    "training_duration_seconds",
    "evaluated_at",
    "generated_at",
)


class DatasetSelector(BaseModel):
    """
    Identifies the exact event set an experiment ran against.

    A selector plus a fingerprint is what makes a replay verifiable: the
    selector re-fetches, and the fingerprint proves it fetched the same
    thing.
    """
    source_id: Optional[str] = None
    data_category: Optional[str] = None
    max_events: int = Field(default=20_000, ge=1, le=1_000_000)

    def describe(self) -> str:
        parts = [
            f"source_id={self.source_id or '<all>'}",
            f"data_category={self.data_category or '<all>'}",
            f"max_events={self.max_events}",
        ]
        return ", ".join(parts)


class WindowConfig(BaseModel):
    observation_window_seconds: float
    lead_time_seconds: float
    prediction_horizon_seconds: float
    stride_seconds: float
    require_labelled_horizon: bool = True
    min_horizon_events: int = 1


class SplitConfig(BaseModel):
    train_ratio: float = Field(ge=0.5, le=0.9)
    strategy: str = "chronological_train_side_purge"
    random_seed: int = 42


class EnvironmentRecord(BaseModel):
    """
    Captured for diagnosis, NOT used as a replay precondition.

    Refusing to replay on a different Python patch release would make
    manifests useless; reporting the difference when results diverge is
    what actually helps.
    """
    python_version: str
    platform: str
    numpy_version: Optional[str] = None
    sklearn_version: Optional[str] = None


class ExperimentManifest(BaseModel):
    """A versioned, self-describing record of one evaluation."""
    manifest_version: str = MANIFEST_VERSION
    experiment_id: str
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    description: str = ""

    # What it ran against
    dataset: DatasetSelector
    dataset_fingerprint: str
    event_count: int
    event_time_range: Optional[list[str]] = None
    schema_version: str = SCHEMA_VERSION
    source_breakdown: dict[str, int] = Field(default_factory=dict)
    data_category_breakdown: dict[str, int] = Field(default_factory=dict)
    label_provenance_breakdown: dict[str, int] = Field(default_factory=dict)

    # What it was predicting
    target_definition: str
    windowing: WindowConfig
    split: SplitConfig
    feature_names: list[str] = Field(default_factory=lambda: list(FEATURE_NAMES))

    # What it produced (the values a replay must reproduce)
    instance_count: int = 0
    train_instances: int = 0
    test_instances: int = 0
    purged_instances: int = 0
    train_positive: int = 0
    test_positive: int = 0
    model_results: dict[str, dict[str, Any]] = Field(default_factory=dict)

    environment: EnvironmentRecord

    @field_validator("manifest_version")
    @classmethod
    def _supported_version(cls, v: str) -> str:
        major = v.split(".")[0]
        if major != MANIFEST_VERSION.split(".")[0]:
            raise ValueError(
                f"Unsupported manifest major version {v!r}; this build "
                f"understands {MANIFEST_VERSION}."
            )
        return v

    def save(self, path: Path) -> Path:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(self.model_dump(mode="json"), indent=2, sort_keys=True),
            encoding="utf-8",
        )
        return path

    @classmethod
    def load(cls, path: Path) -> "ExperimentManifest":
        raw = Path(path).read_text(encoding="utf-8")
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ManifestInvalidError(f"Manifest is not valid JSON: {exc}") from exc
        try:
            return cls.model_validate(data)
        except Exception as exc:  # noqa: BLE001
            raise ManifestInvalidError(f"Manifest failed validation: {exc}") from exc


class ManifestInvalidError(ValueError):
    """The manifest itself is malformed or an unsupported version."""


class ReplayMismatchError(RuntimeError):
    """
    The environment no longer matches the manifest.

    Carries every mismatch so the operator sees all of them at once rather
    than fixing one and rediscovering the next.
    """

    def __init__(self, mismatches: list[str]):
        self.mismatches = mismatches
        super().__init__(
            "Experiment cannot be replayed faithfully:\n  - "
            + "\n  - ".join(mismatches)
        )


def fingerprint_events(events: list[NormalizedEvent]) -> str:
    """
    Content fingerprint of an event set.

    Derived from stable identity and ordering, not from object identity, so
    the same records re-fetched in the same order hash identically. Contains
    no telemetry values itself.
    """
    hasher = hashlib.sha256()
    hasher.update(f"{SCHEMA_VERSION}|{len(events)}|".encode())
    for e in sorted(events, key=lambda e: (e.observed_at, e.event_id)):
        hasher.update(
            f"{e.event_id}|{e.observed_at.isoformat()}|{e.label or ''}|"
            f"{e.source_id}|{e.data_category.value}".encode()
        )
    return hasher.hexdigest()


def _environment() -> EnvironmentRecord:
    try:
        import numpy
        numpy_version = numpy.__version__
    except Exception:  # noqa: BLE001
        numpy_version = None
    try:
        import sklearn
        sklearn_version = sklearn.__version__
    except Exception:  # noqa: BLE001
        sklearn_version = None
    return EnvironmentRecord(
        python_version=sys.version.split()[0],
        platform=f"{platform.system()} {platform.release()}",
        numpy_version=numpy_version,
        sklearn_version=sklearn_version,
    )


def build_manifest(
    *,
    experiment_id: str,
    events: list[NormalizedEvent],
    selector: DatasetSelector,
    pipeline,
    description: str = "",
) -> ExperimentManifest:
    """Capture a manifest from a pipeline that has just been evaluated."""
    report = pipeline.last_split_report
    if report is None:
        raise ValueError(
            "Cannot build a manifest before an evaluation has produced a "
            "split report."
        )

    windowing = report.windowing
    times = sorted(e.observed_at for e in events) if events else []

    src: dict[str, int] = {}
    cat: dict[str, int] = {}
    prov: dict[str, int] = {}
    for e in events:
        src[e.source_id] = src.get(e.source_id, 0) + 1
        cat[e.data_category.value] = cat.get(e.data_category.value, 0) + 1
        prov[e.label_provenance.value] = prov.get(e.label_provenance.value, 0) + 1

    model_results = {
        name: {
            "accuracy": m.accuracy,
            "precision": m.precision,
            "recall": m.recall,
            "f1": m.f1,
            "pr_auc": m.pr_auc,
            "roc_auc": m.roc_auc,
            "brier_score": m.brier_score,
            "confusion_matrix": m.confusion_matrix,
            "detected_events": m.detected_events,
            "missed_events": m.missed_events,
            "false_alarms": m.false_alarms,
            "metrics_interpretable": m.metrics_interpretable,
        }
        for name, m in pipeline.model_metrics.items()
    }

    return ExperimentManifest(
        experiment_id=experiment_id,
        description=description,
        dataset=selector,
        dataset_fingerprint=fingerprint_events(events),
        event_count=len(events),
        event_time_range=[times[0].isoformat(), times[-1].isoformat()] if times else None,
        source_breakdown=src,
        data_category_breakdown=cat,
        label_provenance_breakdown=prov,
        target_definition=report.target_definition,
        windowing=WindowConfig(
            observation_window_seconds=(
                windowing.effective_window_seconds if windowing
                else pipeline.extractor.window_size_seconds
            ),
            lead_time_seconds=(
                windowing.effective_lead_seconds if windowing
                else pipeline.extractor.lead_time_seconds
            ),
            prediction_horizon_seconds=(
                windowing.effective_horizon_seconds if windowing
                else pipeline.extractor.prediction_horizon_seconds
            ),
            stride_seconds=windowing.effective_stride_seconds if windowing else 15.0,
            require_labelled_horizon=getattr(
                pipeline.extractor, "require_labelled_horizon", True
            ),
            min_horizon_events=getattr(pipeline.extractor, "min_horizon_events", 1),
        ),
        split=SplitConfig(
            # The configured ratio, not one derived from the resulting
            # split sizes — purging makes those differ.
            train_ratio=report.configured_train_ratio,
            strategy=report.split_strategy,
            random_seed=report.random_seed,
        ),
        instance_count=report.total_instances,
        train_instances=report.train_instances,
        test_instances=report.test_instances,
        purged_instances=report.purged_instances,
        train_positive=report.train_positive,
        test_positive=report.test_positive,
        model_results=model_results,
        environment=_environment(),
    )


class ReplayResult(BaseModel):
    """Outcome of replaying a manifest."""
    experiment_id: str
    replayed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    reproduced: bool
    dataset_fingerprint_matched: bool
    differences: list[str] = Field(default_factory=list)
    deterministic_outputs_checked: list[str] = Field(default_factory=list)
    original: dict[str, Any] = Field(default_factory=dict)
    replayed: dict[str, Any] = Field(default_factory=dict)
    environment_original: Optional[EnvironmentRecord] = None
    environment_current: Optional[EnvironmentRecord] = None
    notes: list[str] = Field(default_factory=list)


def replay_experiment(
    manifest: ExperimentManifest,
    db,
    *,
    strict_fingerprint: bool = True,
) -> ReplayResult:
    """
    Reconstruct an experiment from its manifest.

    Read-only with respect to telemetry: it selects events, rebuilds the
    windows and split with the recorded configuration, retrains, and
    compares the deterministic outputs.

    Raises ReplayMismatchError when the dataset or contract no longer
    matches, rather than producing a number that merely resembles the
    original.
    """
    from app.models.forecaster import (
        InsufficientEvaluationDataError,
        ThreatForecastingPipeline,
    )

    mismatches: list[str] = []

    if manifest.schema_version != SCHEMA_VERSION:
        mismatches.append(
            f"Event schema version changed: manifest {manifest.schema_version} "
            f"vs current {SCHEMA_VERSION}. Window and label semantics may differ."
        )

    missing_features = [f for f in manifest.feature_names if f not in FEATURE_NAMES]
    extra_features = [f for f in FEATURE_NAMES if f not in manifest.feature_names]
    if missing_features or extra_features:
        mismatches.append(
            "Feature set changed: "
            f"removed={missing_features or 'none'}, added={extra_features or 'none'}. "
            "Metrics would not be comparable."
        )

    # Re-select the dataset exactly as the manifest describes.
    events = db.list_events(
        source_id=manifest.dataset.source_id,
        data_category=manifest.dataset.data_category,
        limit=manifest.dataset.max_events,
    )

    if not events:
        mismatches.append(
            f"No events match the manifest's dataset selector "
            f"({manifest.dataset.describe()}). The dataset is unavailable."
        )
        raise ReplayMismatchError(mismatches)

    current_fp = fingerprint_events(events)
    fp_matched = current_fp == manifest.dataset_fingerprint
    if not fp_matched:
        detail = (
            f"Dataset fingerprint mismatch: manifest {manifest.dataset_fingerprint[:16]}… "
            f"vs current {current_fp[:16]}… "
            f"(manifest recorded {manifest.event_count} events, selector now returns "
            f"{len(events)}). The underlying data has changed."
        )
        if strict_fingerprint:
            mismatches.append(detail)

    if mismatches:
        raise ReplayMismatchError(mismatches)

    # Rebuild with the recorded configuration.
    pipeline = ThreatForecastingPipeline(
        window_size_seconds=manifest.windowing.observation_window_seconds,
        lead_time_seconds=manifest.windowing.lead_time_seconds,
        prediction_horizon_seconds=manifest.windowing.prediction_horizon_seconds,
    )
    pipeline.extractor.require_labelled_horizon = manifest.windowing.require_labelled_horizon
    pipeline.extractor.min_horizon_events = manifest.windowing.min_horizon_events

    notes: list[str] = []
    try:
        pipeline.train_and_evaluate_all(events, train_ratio=manifest.split.train_ratio)
    except InsufficientEvaluationDataError as exc:
        raise ReplayMismatchError([
            "The recorded configuration no longer yields a valid evaluation on "
            f"this dataset: {exc}"
        ]) from exc

    report = pipeline.last_split_report
    replayed = {
        "dataset_fingerprint": current_fp,
        "instance_count": report.total_instances,
        "train_instances": report.train_instances,
        "test_instances": report.test_instances,
        "purged_instances": report.purged_instances,
        "train_positive": report.train_positive,
        "test_positive": report.test_positive,
    }
    original = {
        "dataset_fingerprint": manifest.dataset_fingerprint,
        "instance_count": manifest.instance_count,
        "train_instances": manifest.train_instances,
        "test_instances": manifest.test_instances,
        "purged_instances": manifest.purged_instances,
        "train_positive": manifest.train_positive,
        "test_positive": manifest.test_positive,
    }

    differences = [
        f"{key}: manifest={original[key]!r} replay={replayed[key]!r}"
        for key in original
        if original[key] != replayed[key]
    ]

    # Per-model confusion matrices are deterministic given a fixed seed.
    for name, recorded in manifest.model_results.items():
        current = pipeline.model_metrics.get(name)
        if current is None:
            differences.append(f"{name}: present in manifest, absent on replay")
            continue
        if recorded.get("confusion_matrix") != current.confusion_matrix:
            differences.append(
                f"{name}.confusion_matrix: manifest="
                f"{recorded.get('confusion_matrix')} replay={current.confusion_matrix}"
            )

    current_env = _environment()
    if current_env.sklearn_version != manifest.environment.sklearn_version:
        notes.append(
            f"scikit-learn differs (manifest {manifest.environment.sklearn_version}, "
            f"current {current_env.sklearn_version}); small numeric differences are "
            "expected and are not themselves a reproduction failure."
        )
    if current_env.platform != manifest.environment.platform:
        notes.append(
            f"Platform differs (manifest {manifest.environment.platform}, current "
            f"{current_env.platform}); timings will differ."
        )

    return ReplayResult(
        experiment_id=manifest.experiment_id,
        reproduced=not differences,
        dataset_fingerprint_matched=fp_matched,
        differences=differences,
        deterministic_outputs_checked=list(DETERMINISTIC_OUTPUTS),
        original=original,
        replayed=replayed,
        environment_original=manifest.environment,
        environment_current=current_env,
        notes=notes,
    )
