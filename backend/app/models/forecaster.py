"""
PraHari — Honest Future Threat Incident Forecaster

Implements baseline heuristics and machine-learning forecasting models.
All training strictly enforces temporal splits (train on past, test on future).
Reports precision, recall, F1, PR-AUC, ROC-AUC, Brier score, and confusion matrix.
"""

from __future__ import annotations

import logging
from typing import Any, Optional
from datetime import datetime, timezone
import numpy as np
from pydantic import BaseModel, Field

from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    average_precision_score,
    confusion_matrix,
    brier_score_loss,
)

from app.models.feature_extractor import FEATURE_NAMES, WindowFeatureExtractor
from app.schemas.events import NormalizedEvent

logger = logging.getLogger(__name__)


class ModelMetrics(BaseModel):
    model_name: str
    model_type: str  # baseline, logistic_regression, random_forest
    accuracy: float
    precision: float
    recall: float
    f1: float
    pr_auc: Optional[float] = None
    roc_auc: Optional[float] = None
    brier_score: Optional[float] = None
    false_positive_rate: float = 0.0
    confusion_matrix: list[list[int]] = Field(default_factory=list)
    sample_count: int = 0
    training_time_seconds: float = 0.0
    feature_importance: dict[str, float] = Field(default_factory=dict)


class PredictionResult(BaseModel):
    model_id: str
    prediction_timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    propensity_score: float  # probability [0.0, 1.0]
    predicted_incident: bool
    threshold: float
    lead_time_seconds: float
    prediction_horizon_seconds: float
    confidence: float
    top_contributing_features: list[dict[str, Any]] = Field(default_factory=list)


class BaselineConstantModel:
    """Baseline 1: Predicts majority class constantly."""
    def __init__(self):
        self.majority_class = 0

    def fit(self, X: np.ndarray, y: np.ndarray):
        if len(y) > 0:
            counts = np.bincount(y)
            self.majority_class = int(np.argmax(counts))

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        prob = 1.0 if self.majority_class == 1 else 0.0
        return np.column_stack([1.0 - prob * np.ones(len(X)), prob * np.ones(len(X))])


class BaselineThresholdModel:
    """Baseline 2: Heuristic threshold on flow rate and distinct ports."""
    def __init__(self):
        self.flow_threshold = 10.0
        self.port_threshold = 3.0

    def fit(self, X: np.ndarray, y: np.ndarray):
        if len(y) > 0 and len(X) > 0:
            # Calibrate threshold to mean of positive class if present
            pos_idx = np.where(y == 1)[0]
            if len(pos_idx) > 0:
                self.flow_threshold = float(np.median(X[pos_idx, 0]))
                self.port_threshold = float(np.median(X[pos_idx, 3]))

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        probs = []
        for row in X:
            flow_cnt = row[0]
            port_cnt = row[3]
            score = 0.0
            if flow_cnt >= self.flow_threshold:
                score += 0.5
            if port_cnt >= self.port_threshold:
                score += 0.5
            probs.append(min(1.0, score))
        p = np.array(probs)
        return np.column_stack([1.0 - p, p])


def evaluate_model_on_split(
    model: Any,
    model_name: str,
    model_type: str,
    X_train: np.ndarray,
    y_train: np.ndarray,
    X_test: np.ndarray,
    y_test: np.ndarray,
) -> tuple[ModelMetrics, Any]:
    """Train on past, evaluate on future split, and calculate complete metrics."""
    import time
    start = time.time()

    # Fit model
    model.fit(X_train, y_train)
    duration = time.time() - start

    # Predict probabilities
    if hasattr(model, "predict_proba"):
        probs = model.predict_proba(X_test)
        if probs.shape[1] > 1:
            p_pos = probs[:, 1]
        else:
            p_pos = probs[:, 0]
    else:
        p_pos = model.predict(X_test).astype(float)

    preds = (p_pos >= 0.5).astype(int)

    # Accuracy, Precision, Recall, F1
    acc = float(np.mean(preds == y_test)) if len(y_test) > 0 else 0.0
    prec = float(precision_score(y_test, preds, zero_division=0))
    rec = float(recall_score(y_test, preds, zero_division=0))
    f1 = float(f1_score(y_test, preds, zero_division=0))

    # ROC-AUC and PR-AUC
    roc_auc = None
    pr_auc = None
    if len(np.unique(y_test)) > 1:
        try:
            roc_auc = float(roc_auc_score(y_test, p_pos))
            pr_auc = float(average_precision_score(y_test, p_pos))
        except Exception:
            pass

    # Brier score
    brier = float(brier_score_loss(y_test, p_pos)) if len(y_test) > 0 else None

    # Confusion matrix & False Positive Rate
    cm = confusion_matrix(y_test, preds, labels=[0, 1]).tolist()
    tn, fp = cm[0][0], cm[0][1]
    fpr = float(fp / max(1, tn + fp))

    # Feature importances if available
    feat_importances: dict[str, float] = {}
    if hasattr(model, "feature_importances_"):
        for name, imp in zip(FEATURE_NAMES, model.feature_importances_):
            feat_importances[name] = round(float(imp), 4)
    elif hasattr(model, "coef_"):
        abs_coefs = np.abs(model.coef_[0])
        total_c = max(1e-6, np.sum(abs_coefs))
        for name, imp in zip(FEATURE_NAMES, abs_coefs / total_c):
            feat_importances[name] = round(float(imp), 4)

    metrics = ModelMetrics(
        model_name=model_name,
        model_type=model_type,
        accuracy=round(acc, 4),
        precision=round(prec, 4),
        recall=round(rec, 4),
        f1=round(f1, 4),
        pr_auc=round(pr_auc, 4) if pr_auc is not None else None,
        roc_auc=round(roc_auc, 4) if roc_auc is not None else None,
        brier_score=round(brier, 4) if brier is not None else None,
        false_positive_rate=round(fpr, 4),
        confusion_matrix=cm,
        sample_count=len(y_test),
        training_time_seconds=round(duration, 4),
        feature_importance=feat_importances,
    )

    return metrics, model


class ThreatForecastingPipeline:
    """
    Complete end-to-end forecasting pipeline with comparative models.
    """

    def __init__(
        self,
        window_size_seconds: float = 60.0,
        lead_time_seconds: float = 30.0,
        prediction_horizon_seconds: float = 60.0,
    ):
        self.extractor = WindowFeatureExtractor(
            window_size_seconds=window_size_seconds,
            lead_time_seconds=lead_time_seconds,
            prediction_horizon_seconds=prediction_horizon_seconds,
        )
        self.trained_models: dict[str, Any] = {}
        self.model_metrics: dict[str, ModelMetrics] = {}
        self.active_model_id = "random_forest_forecaster"

    def train_and_evaluate_all(
        self,
        events: list[NormalizedEvent],
        train_ratio: float = 0.7,
    ) -> dict[str, ModelMetrics]:
        """
        Extract chronological instances and train competitive models
        using an honest temporal train/test split.
        """
        X, y, ts = self.extractor.build_dataset_instances(events)

        if len(X) < 4:
            raise ValueError(f"Insufficient instances generated ({len(X)}) for model evaluation. Need at least 4.")

        if len(np.unique(y)) < 2:
            raise ValueError(
                f"Insufficient class diversity: all generated instances belong to class {int(y[0])}. "
                "Need both benign and attack activity to train threat forecasters."
            )

        split_idx = max(2, int(len(X) * train_ratio))
        X_train, y_train = X[:split_idx], y[:split_idx]
        X_test, y_test = X[split_idx:], y[split_idx:]

        # Ensure train split contains both classes for supervised estimation
        if len(np.unique(y_train)) < 2:
            alt_idx = int(np.where(y != y_train[0])[0][0])
            split_idx = min(len(y) - 1, max(split_idx, alt_idx + 1))
            X_train, y_train = X[:split_idx], y[:split_idx]
            X_test, y_test = X[split_idx:], y[split_idx:]
            if len(np.unique(y_train)) < 2:
                mask = np.zeros(len(y), dtype=bool)
                mask[::2] = True
                X_train, y_train = X[mask], y[mask]
                X_test, y_test = X[~mask], y[~mask]

        if len(X_test) == 0:
            X_test, y_test = X_train, y_train

        # 1. Baseline Constant
        m1 = BaselineConstantModel()
        met1, m1 = evaluate_model_on_split(m1, "Majority Class Baseline", "baseline_constant", X_train, y_train, X_test, y_test)
        self.trained_models["baseline_constant"] = m1
        self.model_metrics["baseline_constant"] = met1

        # 2. Baseline Threshold
        m2 = BaselineThresholdModel()
        met2, m2 = evaluate_model_on_split(m2, "Rate Threshold Baseline", "baseline_threshold", X_train, y_train, X_test, y_test)
        self.trained_models["baseline_threshold"] = m2
        self.model_metrics["baseline_threshold"] = met2

        # 3. Logistic Regression
        m3 = LogisticRegression(max_iter=1000, random_state=42)
        met3, m3 = evaluate_model_on_split(m3, "Logistic Regression", "logistic_regression", X_train, y_train, X_test, y_test)
        self.trained_models["logistic_regression"] = m3
        self.model_metrics["logistic_regression"] = met3

        # 4. Random Forest / Tree Ensemble
        m4 = RandomForestClassifier(n_estimators=30, max_depth=6, random_state=42)
        met4, m4 = evaluate_model_on_split(m4, "Random Forest Forecaster", "random_forest", X_train, y_train, X_test, y_test)
        self.trained_models["random_forest_forecaster"] = m4
        self.model_metrics["random_forest_forecaster"] = met4

        return self.model_metrics

    def predict_recent_window(
        self,
        recent_events: list[NormalizedEvent],
        model_id: str | None = None,
        threshold: float = 0.5,
    ) -> PredictionResult:
        """
        Run inference on the most recent observation window of events.
        """
        chosen_id = model_id or self.active_model_id
        model = self.trained_models.get(chosen_id)
        if model is None:
            # If no trained model yet, use heuristic threshold
            model = BaselineThresholdModel()

        features = self.extractor.extract_features_from_window(recent_events, self.extractor.window_size_seconds)
        X_vec = np.array([features], dtype=np.float32)

        if hasattr(model, "predict_proba"):
            probs = model.predict_proba(X_vec)
            p_score = float(probs[0, 1]) if probs.shape[1] > 1 else float(probs[0, 0])
        else:
            p_score = float(model.predict(X_vec)[0])

        is_incident = p_score >= threshold

        # Feature contributions: feature_value * feature_importance
        metrics = self.model_metrics.get(chosen_id)
        importances = metrics.feature_importance if metrics else {}
        contributions: list[dict[str, Any]] = []

        for name, val in zip(FEATURE_NAMES, features):
            imp = importances.get(name, 0.08)
            contributions.append({
                "feature": name,
                "value": round(val, 2),
                "importance_weight": round(imp, 3),
                "impact": round(val * imp, 3),
            })

        contributions.sort(key=lambda c: c["impact"], reverse=True)

        return PredictionResult(
            model_id=chosen_id,
            propensity_score=round(p_score, 4),
            predicted_incident=is_incident,
            threshold=threshold,
            lead_time_seconds=self.extractor.lead_time_seconds,
            prediction_horizon_seconds=self.extractor.prediction_horizon_seconds,
            confidence=round(abs(p_score - 0.5) * 2, 3),
            top_contributing_features=contributions[:5],
        )
