"""
PraHari — Experiment Manifest and Replay API

Capture a reproducible manifest from the most recent evaluation, and replay
a manifest to verify it still reproduces.

Replay is read-only with respect to telemetry: it selects and evaluates. It
writes no events, mutates no sources, and deletes nothing.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from app.api.deps import get_db
from app.core.config import AppConfig, get_config
from app.models.registry import get_forecasting_pipeline
from app.research.experiment import (
    DatasetSelector,
    ExperimentManifest,
    ManifestInvalidError,
    ReplayMismatchError,
    ReplayResult,
    build_manifest,
    replay_experiment,
)
from app.storage.database import Database

router = APIRouter(prefix="/experiments", tags=["Reproducible Experiments"])


def _experiments_dir(config: AppConfig) -> Path:
    path = config.get_experiments_dir()
    path.mkdir(parents=True, exist_ok=True)
    return path


def _safe_manifest_path(config: AppConfig, experiment_id: str) -> Path:
    """
    Resolve an experiment id to a path inside the experiments directory.

    Rejects traversal rather than trusting the id, since it arrives from a
    request.
    """
    if not experiment_id or any(c in experiment_id for c in '/\\..:*?"<>|'):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid experiment id: {experiment_id!r}",
        )
    base = _experiments_dir(config)
    candidate = (base / f"{experiment_id}.json").resolve()
    if not candidate.is_relative_to(base.resolve()):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Experiment id resolves outside the experiments directory",
        )
    return candidate


class CaptureRequest(BaseModel):
    experiment_id: str = Field(..., min_length=1, max_length=120)
    description: str = Field(default="", max_length=500)
    source_id: Optional[str] = None
    data_category: Optional[str] = None
    max_events: int = Field(default=20_000, ge=1, le=1_000_000)


@router.post("/capture", response_model=ExperimentManifest)
def capture_manifest(
    req: CaptureRequest,
    db: Database = Depends(get_db),
    config: AppConfig = Depends(get_config),
) -> ExperimentManifest:
    """
    Record a manifest describing the most recent evaluation.

    Requires that models have been trained, because a manifest without
    results cannot be verified against anything.
    """
    pipeline = get_forecasting_pipeline()
    if not pipeline.model_metrics or pipeline.last_split_report is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "error": "no_evaluation_to_capture",
                "message": (
                    "No evaluation has been performed in this process, so there "
                    "is nothing to record. Train models first."
                ),
            },
        )

    selector = DatasetSelector(
        source_id=req.source_id,
        data_category=req.data_category,
        max_events=req.max_events,
    )
    events = db.list_events(
        source_id=selector.source_id,
        data_category=selector.data_category,
        limit=selector.max_events,
    )
    manifest = build_manifest(
        experiment_id=req.experiment_id,
        events=events,
        selector=selector,
        pipeline=pipeline,
        description=req.description,
    )
    manifest.save(_safe_manifest_path(config, req.experiment_id))

    db.log_audit(
        action="capture_experiment_manifest",
        resource_type="experiment",
        resource_id=req.experiment_id,
        details=(
            f"Captured manifest over {manifest.event_count} events "
            f"(fingerprint {manifest.dataset_fingerprint[:16]})"
        ),
    )
    return manifest


@router.get("", response_model=list[str])
def list_experiments(config: AppConfig = Depends(get_config)) -> list[str]:
    """Experiment ids with a stored manifest."""
    return sorted(p.stem for p in _experiments_dir(config).glob("*.json"))


@router.get("/{experiment_id}", response_model=ExperimentManifest)
def get_manifest(
    experiment_id: str,
    config: AppConfig = Depends(get_config),
) -> ExperimentManifest:
    path = _safe_manifest_path(config, experiment_id)
    if not path.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No manifest for experiment {experiment_id!r}",
        )
    try:
        return ExperimentManifest.load(path)
    except ManifestInvalidError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": "manifest_invalid", "message": str(exc)},
        )


@router.post("/{experiment_id}/replay", response_model=ReplayResult)
def replay(
    experiment_id: str,
    db: Database = Depends(get_db),
    config: AppConfig = Depends(get_config),
) -> ReplayResult:
    """
    Replay a stored manifest against the current database.

    Fails closed: a changed dataset fingerprint, schema version or feature
    set aborts with the mismatch named, rather than reporting a number from
    different inputs as a reproduction.
    """
    path = _safe_manifest_path(config, experiment_id)
    if not path.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No manifest for experiment {experiment_id!r}",
        )

    try:
        manifest = ExperimentManifest.load(path)
    except ManifestInvalidError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": "manifest_invalid", "message": str(exc)},
        )

    try:
        result = replay_experiment(manifest, db)
    except ReplayMismatchError as exc:
        db.log_audit(
            action="replay_experiment_refused",
            resource_type="experiment",
            resource_id=experiment_id,
            details="; ".join(exc.mismatches)[:400],
        )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "error": "experiment_not_reproducible",
                "message": str(exc),
                "mismatches": exc.mismatches,
                "remediation": (
                    "Replay requires the same dataset, schema and feature set. "
                    "Capture a new manifest if the inputs have legitimately changed."
                ),
            },
        )

    db.log_audit(
        action="replay_experiment",
        resource_type="experiment",
        resource_id=experiment_id,
        details=(
            f"Reproduced={result.reproduced}, "
            f"{len(result.differences)} difference(s)"
        ),
    )
    return result
