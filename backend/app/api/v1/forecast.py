"""
PraHari — Forecasting & Threat Prediction API Endpoints

Every endpoint here consults the research gate first. The gate is enforced
in the backend, so a direct API call is refused on the same terms as a
dashboard click — a disabled button is not a control.
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from app.api.deps import get_db
from app.models.forecaster import (
    InsufficientEvaluationDataError,
    ModelMetrics,
    PredictionResult,
    SplitIntegrityReport,
)
from app.models.registry import get_forecasting_pipeline
from app.research.readiness import (
    OP_PREDICT,
    OP_TRAIN,
    ForecastingBlocked,
    ReadinessReport,
    ReadinessState,
    assess_readiness,
    enforce,
)
from app.storage.database import Database

router = APIRouter(prefix="/forecast", tags=["Threat Forecasting"])


class TrainModelsRequest(BaseModel):
    source_id: Optional[str] = Field(default=None, description="Scope training to a telemetry source")
    max_events: int = Field(default=20_000, ge=10, le=100_000)
    train_ratio: float = Field(default=0.7, ge=0.5, le=0.9)


class PredictRequest(BaseModel):
    source_id: Optional[str] = None
    model_id: Optional[str] = "random_forest_forecaster"
    threshold: float = Field(default=0.5, ge=0.0, le=1.0)
    window_limit: int = Field(default=100, ge=5, le=1000)


def _current_readiness(db: Database, source_id: Optional[str] = None) -> ReadinessReport:
    """Assess readiness from stored telemetry plus the pipeline's own state."""
    pipeline = get_forecasting_pipeline()
    events = db.list_events(source_id=source_id, limit=50_000)

    has_model = bool(pipeline.trained_models)
    interpretable = any(
        m.metrics_interpretable for m in pipeline.model_metrics.values()
    ) if pipeline.model_metrics else False

    return assess_readiness(
        events,
        observation_window_seconds=pipeline.extractor.window_size_seconds,
        lead_time_seconds=pipeline.extractor.lead_time_seconds,
        prediction_horizon_seconds=pipeline.extractor.prediction_horizon_seconds,
        has_trained_model=has_model,
        model_metrics_interpretable=interpretable,
    )


def _blocked_response(operation: str, report: ReadinessReport) -> HTTPException:
    """A refusal that states the reason and exactly what remains unmet."""
    return HTTPException(
        status_code=status.HTTP_409_CONFLICT,
        detail={
            "error": "forecasting_blocked_by_research_gate",
            "operation": operation,
            "readiness_state": report.state.value,
            "message": report.summary,
            "unmet_requirements": [
                {
                    "name": r.name,
                    "required": r.required,
                    "observed": r.observed,
                    "detail": r.detail,
                }
                for r in report.requirements
                if not r.satisfied
            ],
            "next_steps": report.next_steps,
            "prediction_target": report.prediction_target,
        },
    )


@router.get("/readiness", response_model=ReadinessReport)
def get_readiness(
    source_id: Optional[str] = Query(default=None),
    db: Database = Depends(get_db),
) -> ReadinessReport:
    """
    Report forecasting readiness: the state, the prerequisites, which are
    unmet, and what would satisfy them.
    """
    return _current_readiness(db, source_id)


@router.post("/train", response_model=dict[str, ModelMetrics])
def train_forecasting_models(
    req: TrainModelsRequest,
    db: Database = Depends(get_db),
) -> dict[str, ModelMetrics]:
    """
    Train and evaluate forecasting models under a strict temporal split.

    Refused by the research gate when the data cannot support it, and
    refused again by the pipeline if no leakage-free split can be built.
    """
    report = _current_readiness(db, req.source_id)
    try:
        enforce(OP_TRAIN, report)
    except ForecastingBlocked:
        db.log_audit(
            action="train_forecasting_models_blocked",
            resource_type="research_gate",
            resource_id=report.state.value,
            details=f"Gate refused training: {report.summary}",
        )
        raise _blocked_response(OP_TRAIN, report)

    events = db.list_events(source_id=req.source_id, limit=req.max_events)
    pipeline = get_forecasting_pipeline()
    try:
        metrics_dict = pipeline.train_and_evaluate_all(events, train_ratio=req.train_ratio)
    except InsufficientEvaluationDataError as e:
        split = e.split_report
        db.log_audit(
            action="train_forecasting_models_refused",
            resource_type="model_pipeline",
            resource_id="multi_model_benchmark",
            details=f"Refused on {len(events)} events: {str(e)[:300]}",
        )
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "error": "insufficient_data_for_honest_evaluation",
                "readiness_state": ReadinessState.INVALID_EVALUATION_CONDITIONS.value,
                "message": str(e),
                "events_considered": len(events),
                "split_report": split.model_dump(mode="json") if split else None,
                "remediation": (
                    "Supply telemetry spanning more time, with labelled attack and "
                    "benign activity occurring in both the earlier (training) and "
                    "later (evaluation) periods."
                ),
            },
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": "training_precondition_failed", "message": str(e)},
        )

    db.log_audit(
        action="train_forecasting_models",
        resource_type="model_pipeline",
        resource_id="multi_model_benchmark",
        details=f"Trained {len(metrics_dict)} models across {len(events)} events",
    )
    return metrics_dict


@router.get("/integrity", response_model=Optional[SplitIntegrityReport])
def get_split_integrity_report() -> Optional[SplitIntegrityReport]:
    """
    How the most recent train/test split was constructed: window
    configuration actually used, purge size, and class counts on each side.
    Any reported metric must be read together with this.
    """
    return get_forecasting_pipeline().last_split_report


@router.get("/models", response_model=dict[str, ModelMetrics])
def get_model_evaluations() -> dict[str, ModelMetrics]:
    """
    Metrics for models that have genuinely been trained and evaluated.

    Returns an empty object when nothing has been trained — never a
    placeholder model.
    """
    return get_forecasting_pipeline().model_metrics


@router.post("/predict", response_model=PredictionResult)
def predict_threat_propensity(
    req: PredictRequest,
    db: Database = Depends(get_db),
) -> PredictionResult:
    """
    Compute an incident propensity score for the most recent observation
    window.

    Refused outright when the data cannot support forecasting: returning an
    uncalibrated heuristic score here, however it is labelled, invites it to
    be read as a forecast.
    """
    report = _current_readiness(db, req.source_id)
    try:
        enforce(OP_PREDICT, report)
    except ForecastingBlocked:
        db.log_audit(
            action="predict_blocked",
            resource_type="research_gate",
            resource_id=report.state.value,
            details=f"Gate refused prediction: {report.summary}",
        )
        raise _blocked_response(OP_PREDICT, report)

    events = db.list_events(source_id=req.source_id, limit=req.window_limit)
    if not events:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No recent events available for an inference observation window.",
        )

    pipeline = get_forecasting_pipeline()
    autotrain_note: Optional[str] = None
    if not pipeline.trained_models:
        all_events = db.list_events(limit=10_000)
        try:
            pipeline.train_and_evaluate_all(all_events)
        except InsufficientEvaluationDataError as e:
            autotrain_note = (
                f"Automatic training was refused: {e} No validated model is available."
            )
        except Exception as e:  # noqa: BLE001
            autotrain_note = f"Automatic training failed ({type(e).__name__}: {e})."

    result = pipeline.predict_recent_window(
        recent_events=events,
        model_id=req.model_id,
        threshold=req.threshold,
    )
    if autotrain_note:
        result.evaluation_caveats.insert(0, autotrain_note)
    return result
