"""
PraHari — Model Registry & Prediction Service

Coordinates model lifecycles, active model selection, evaluation reports,
and serving predictions.
"""

from __future__ import annotations

from typing import Optional
from app.models.forecaster import ThreatForecastingPipeline, ModelMetrics, PredictionResult
from app.schemas.events import NormalizedEvent

_pipeline_instance: Optional[ThreatForecastingPipeline] = None


def get_forecasting_pipeline() -> ThreatForecastingPipeline:
    """Singleton getter for the forecasting pipeline."""
    global _pipeline_instance
    if _pipeline_instance is None:
        _pipeline_instance = ThreatForecastingPipeline()
    return _pipeline_instance


def reset_forecasting_pipeline() -> None:
    """Reset the forecasting pipeline singleton (for tests)."""
    global _pipeline_instance
    _pipeline_instance = ThreatForecastingPipeline()

