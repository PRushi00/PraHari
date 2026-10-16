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
from app.research.selection import (
    MixedProvenanceRefused,
    SelectionCoverage,
    select_training_events,
)
from app.research.evaluation import (
    DEFAULT_LEAD_TIMES,
    DEFAULT_RESAMPLES,
    GeneralizationReport,
    LeadTimeCurve,
    UncertaintyInterval,
    bootstrap_interval,
    generalization_evaluation,
    lead_time_curve,
)
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
    data_category: Optional[str] = Field(
        default=None,
        description=(
            "Authoritative provenance filter (historical_import, live_telemetry, "
            "synthetic_demo, ...). Preferred over source_id, which is only a name."
        ),
    )
    allow_mixed_provenance: bool = Field(
        default=False,
        description=(
            "Required to pool benchmark, live and generated data in one training "
            "set. Refused by default; the composition is recorded when allowed."
        ),
    )
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

    try:
        events, coverage = select_training_events(
            db,
            source_id=req.source_id,
            data_category=req.data_category,
            max_events=req.max_events,
            allow_mixed_provenance=req.allow_mixed_provenance,
        )
    except MixedProvenanceRefused as exc:
        db.log_audit(
            action="train_forecasting_models_refused",
            resource_type="provenance",
            resource_id="mixed_provenance",
            details=str(exc)[:400],
        )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "error": "mixed_provenance_training_refused",
                "message": str(exc),
                "coverage": exc.coverage.model_dump(mode="json"),
                "remedy": (
                    "Filter with data_category, or set allow_mixed_provenance=true "
                    "to accept the pooled population deliberately."
                ),
            },
        )

    pipeline = get_forecasting_pipeline()
    pipeline.last_selection_coverage = coverage
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


@router.get("/coverage", response_model=Optional[SelectionCoverage])
def get_selection_coverage() -> Optional[SelectionCoverage]:
    """
    What the last evaluation was actually computed over.

    Reports the selected count against the total matching count, whether the
    selection was truncated, the strategy used, the time range covered, and
    the source/category/label composition. A truncated selection is stated
    rather than left to be inferred from a metric that looks fine.
    """
    return getattr(get_forecasting_pipeline(), "last_selection_coverage", None)


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


# ──────────────────────────────────────────────────────────────────
# Lead time and uncertainty
# ──────────────────────────────────────────────────────────────────


class LeadTimeRequest(BaseModel):
    source_id: Optional[str] = None
    max_events: int = Field(default=20_000, ge=100, le=200_000)
    train_ratio: float = Field(default=0.7, gt=0.1, lt=0.95)
    observation_window_seconds: float = Field(default=60.0, gt=0)
    prediction_horizon_seconds: float = Field(default=60.0, gt=0)
    lead_times_seconds: list[float] = Field(
        default_factory=lambda: list(DEFAULT_LEAD_TIMES),
        max_length=12,
        description="Lead times to evaluate. Each is a separate full run.",
    )


@router.post("/lead-time-curve", response_model=LeadTimeCurve)
def evaluate_lead_time_curve(
    req: LeadTimeRequest,
    db: Database = Depends(get_db),
) -> LeadTimeCurve:
    """
    Evaluate how far ahead the models can warn.

    Runs the complete protocol once per lead time, holding everything else
    constant. Subject to the same research gate as training: a dataset that
    cannot support one honest evaluation cannot support five.

    A lead time with no valid split is returned as a refusal with its
    reason, not omitted — omitting it would imply the curve is flat there.
    """
    report = _current_readiness(db, req.source_id)
    try:
        enforce(OP_TRAIN, report)
    except ForecastingBlocked:
        db.log_audit(
            action="lead_time_curve_blocked",
            resource_type="research_gate",
            resource_id=report.state.value,
            details=f"Gate refused lead-time evaluation: {report.summary}",
        )
        raise _blocked_response(OP_TRAIN, report)

    events = db.list_events(source_id=req.source_id, limit=req.max_events)
    curve = lead_time_curve(
        events,
        lead_times=tuple(sorted(set(req.lead_times_seconds))),
        window_seconds=req.observation_window_seconds,
        horizon_seconds=req.prediction_horizon_seconds,
        train_ratio=req.train_ratio,
    )

    if not curve.usable:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "error": "no_lead_time_evaluable",
                "message": (
                    "No lead time produced an honest evaluation on this "
                    "dataset. Each refusal and its reason is included."
                ),
                "points": [p.model_dump(mode="json") for p in curve.points],
            },
        )

    db.log_audit(
        action="evaluate_lead_time_curve",
        resource_type="forecasting",
        resource_id="lead_time_curve",
        details=(
            f"Evaluated {curve.evaluated_leads} lead time(s), "
            f"refused {curve.refused_leads}, over {len(events)} events"
        ),
    )
    return curve


@router.get("/uncertainty", response_model=list[UncertaintyInterval])
def get_metric_uncertainty(
    model_id: Optional[str] = Query(
        default=None, description="Defaults to the active model."
    ),
    resamples: int = Query(default=DEFAULT_RESAMPLES, ge=100, le=10_000),
    confidence: float = Query(default=0.95, gt=0.5, lt=0.999),
) -> list[UncertaintyInterval]:
    """
    Bootstrap confidence intervals for the last evaluation's metrics.

    Refuses with a stated reason when the holdout cannot support an
    interval, rather than returning a narrow range computed from almost
    nothing.
    """
    pipeline = get_forecasting_pipeline()
    held = pipeline.last_holdout
    if held is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "error": "no_evaluation_in_memory",
                "message": (
                    "No evaluation has been performed in this process, so "
                    "there are no held-out predictions to resample. Train first."
                ),
            },
        )

    target = model_id or pipeline.active_model_id
    scores = held.scores.get(target)
    if scores is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error": "unknown_model",
                "message": f"No held-out predictions for model {target!r}.",
                "available": sorted(held.scores),
            },
        )

    return [
        bootstrap_interval(
            held.y_true_for(target), scores, metric=m,
            resamples=resamples, confidence=confidence,
        )
        for m in ("pr_auc", "precision", "recall")
    ]


class GeneralizationRequest(BaseModel):
    source_id: Optional[str] = None
    max_events: int = Field(default=20_000, ge=100, le=200_000)
    group_by: str = Field(
        default="source_id",
        pattern="^(source_id|data_category)$",
        description="Which attribute separates one environment from another.",
    )
    train_ratio: float = Field(default=0.7, gt=0.1, lt=0.95)
    observation_window_seconds: float = Field(default=60.0, gt=0)
    lead_time_seconds: float = Field(default=30.0, ge=0)
    prediction_horizon_seconds: float = Field(default=60.0, gt=0)


@router.post("/generalization", response_model=GeneralizationReport)
def evaluate_generalization(
    req: GeneralizationRequest,
    db: Database = Depends(get_db),
) -> GeneralizationReport:
    """
    Leave-one-group-out transfer evaluation.

    Answers a different question from the chronological split: not whether
    the model predicts this environment's future, but whether anything it
    learned applies to an environment it never saw. A model can do the
    first well and the second not at all, which is how a security
    forecaster usually fails in deployment.

    The within-group score is reported beside the cross-group one, because
    a cross-group number alone cannot be read — 0.6 might be a collapse
    from 0.95 or a rise from 0.5.

    The report states whether the groups are genuinely independent
    environments. Several synthetic groups from one generator are not, and
    the response says so rather than letting the gap be over-read.
    """
    report = _current_readiness(db, req.source_id)
    try:
        enforce(OP_TRAIN, report)
    except ForecastingBlocked:
        db.log_audit(
            action="generalization_blocked",
            resource_type="research_gate",
            resource_id=report.state.value,
            details=f"Gate refused generalization evaluation: {report.summary}",
        )
        raise _blocked_response(OP_TRAIN, report)

    events = db.list_events(source_id=req.source_id, limit=req.max_events)
    result = generalization_evaluation(
        events,
        group_by=req.group_by,
        window_seconds=req.observation_window_seconds,
        lead_seconds=req.lead_time_seconds,
        horizon_seconds=req.prediction_horizon_seconds,
        train_ratio=req.train_ratio,
    )

    if not result.usable:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "error": "no_group_evaluable",
                "message": (
                    "No held-out group produced an interpretable score. "
                    "Generalization needs at least two groups, each with "
                    "both classes present."
                ),
                "groups": result.groups,
                "points": [p.model_dump(mode="json") for p in result.points],
                "notes": result.notes,
            },
        )

    db.log_audit(
        action="evaluate_generalization",
        resource_type="forecasting",
        resource_id=f"generalization:{req.group_by}",
        details=(
            f"Evaluated {result.evaluated_groups} group(s), refused "
            f"{result.refused_groups}; mean transfer gap "
            f"{result.mean_transfer_gap}"
        ),
    )
    return result
