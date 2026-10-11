"""
PraHari — Forecasting & Threat Prediction API Endpoints

Provides endpoints for:
- Training and comparing competitive baseline and ML models
- Querying comparative model evaluations (Precision, Recall, F1, PR-AUC, ROC-AUC)
- Live inference and explainable threat propensity scoring
"""

from __future__ import annotations

from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from app.api.deps import get_db
from app.storage.database import Database
from app.models.registry import get_forecasting_pipeline
from app.models.forecaster import ModelMetrics, PredictionResult

router = APIRouter(prefix="/forecast", tags=["Threat Forecasting"])


class TrainModelsRequest(BaseModel):
    source_id: Optional[str] = Field(default=None, description="Scope training to specific telemetry source")
    max_events: int = Field(default=20_000, ge=10, le=100_000)
    train_ratio: float = Field(default=0.7, ge=0.5, le=0.9)


class PredictRequest(BaseModel):
    source_id: Optional[str] = None
    model_id: Optional[str] = "random_forest_forecaster"
    threshold: float = Field(default=0.5, ge=0.0, le=1.0)
    window_limit: int = Field(default=100, ge=5, le=1000)


@router.post("/train", response_model=dict[str, ModelMetrics])
def train_forecasting_models(
    req: TrainModelsRequest,
    db: Database = Depends(get_db),
) -> dict[str, ModelMetrics]:
    """
    Train and evaluate all forecasting models (baselines, logistic regression, random forest)
    on persisted telemetry using a strict temporal split.
    """
    events = db.list_events(source_id=req.source_id, limit=req.max_events)
    if len(events) < 10:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Insufficient events for training ({len(events)} found, minimum 10 required). Import or seed telemetry first.",
        )

    pipeline = get_forecasting_pipeline()
    try:
        metrics_dict = pipeline.train_and_evaluate_all(events, train_ratio=req.train_ratio)
        db.log_audit(
            action="train_forecasting_models",
            resource_type="model_pipeline",
            resource_id="multi_model_benchmark",
            details=f"Trained {len(metrics_dict)} models across {len(events)} events",
        )
        return metrics_dict
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Model training failed: {str(e)}",
        )


@router.get("/models", response_model=dict[str, ModelMetrics])
def get_model_evaluations() -> dict[str, ModelMetrics]:
    """Retrieve performance metrics and comparisons for all evaluated models."""
    pipeline = get_forecasting_pipeline()
    return pipeline.model_metrics


@router.post("/predict", response_model=PredictionResult)
def predict_threat_propensity(
    req: PredictRequest,
    db: Database = Depends(get_db),
) -> PredictionResult:
    """
    Compute threat incident propensity score for the most recent observation window.
    Returns probability, prediction decision, confidence, and top feature contributions.
    """
    events = db.list_events(source_id=req.source_id, limit=req.window_limit)
    if not events:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No recent events available in database for inference observation window.",
        )

    pipeline = get_forecasting_pipeline()
    # If models haven't been trained yet, auto-train on available data
    if not pipeline.trained_models:
        all_events = db.list_events(limit=10_000)
        if len(all_events) >= 10:
            try:
                pipeline.train_and_evaluate_all(all_events)
            except Exception:
                pass

    result = pipeline.predict_recent_window(
        recent_events=events,
        model_id=req.model_id,
        threshold=req.threshold,
    )
    return result
