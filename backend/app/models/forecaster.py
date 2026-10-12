"""
PraHari — Honest Future Threat Incident Forecaster

Implements baseline heuristics and machine-learning forecasting models.
All training strictly enforces temporal splits (train on past, test on future).
Reports precision, recall, F1, PR-AUC, ROC-AUC, Brier score, and confusion matrix.
"""

from __future__ import annotations

import hashlib
import logging
import math
from typing import Any, Optional
from datetime import datetime, timedelta, timezone
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

from app.models.feature_extractor import (
    FEATURE_NAMES,
    WindowFeatureExtractor,
    WindowingReport,
)
from app.schemas.events import NormalizedEvent

logger = logging.getLogger(__name__)


class SplitIntegrityReport(BaseModel):
    """
    Exactly how the train/test split was formed.

    Published alongside metrics so that any reported score can be checked
    against the split that produced it.
    """
    total_instances: int
    train_instances: int
    test_instances: int
    purged_instances: int
    embargo_windows: int
    embargo_seconds: float
    train_positive: int
    train_negative: int
    test_positive: int
    test_negative: int
    split_strategy: str
    train_end_timestamp: Optional[datetime] = None
    test_start_timestamp: Optional[datetime] = None
    windowing: Optional[WindowingReport] = None

    # ── Reproducibility manifest (blueprint sections 8 and 16) ──
    # Enough to reconstruct exactly which instances were used, without
    # embedding any telemetry.
    manifest_version: str = "1.0.0"
    dataset_fingerprint: Optional[str] = None
    source_breakdown: dict[str, int] = Field(default_factory=dict)
    label_provenance_breakdown: dict[str, int] = Field(default_factory=dict)
    data_category_breakdown: dict[str, int] = Field(default_factory=dict)
    event_count: int = 0
    event_time_range: Optional[list[str]] = None
    random_seed: int = 42
    # The train_ratio the caller ACTUALLY passed. Deriving it from
    # train_instances/total_instances is wrong: purging removes windows
    # between the splits, so the derived value is smaller than the
    # configured one and replaying with it produces a different split.
    configured_train_ratio: float = 0.7
    target_definition: str = ""

    @property
    def test_has_positives(self) -> bool:
        return self.test_positive > 0


class InsufficientEvaluationDataError(ValueError):
    """
    Raised when an honest, leakage-free evaluation cannot be produced.

    Carries the split report so the caller can explain precisely why
    evaluation was refused instead of returning an unsupportable score.
    """

    def __init__(self, message: str, split_report: Optional[SplitIntegrityReport] = None):
        super().__init__(message)
        self.split_report = split_report


class ModelMetrics(BaseModel):
    model_name: str
    model_type: str  # baseline, logistic_regression, random_forest
    accuracy: float
    precision: float
    recall: float
    f1: float
    f1_score: Optional[float] = None
    pr_auc: Optional[float] = None
    roc_auc: Optional[float] = None
    brier_score: Optional[float] = None
    false_positive_rate: float = 0.0
    confusion_matrix: list[list[int]] = Field(default_factory=list)
    sample_count: int = 0
    train_instances: Optional[int] = 0
    test_instances: Optional[int] = 0
    training_time_seconds: float = 0.0
    training_duration_seconds: Optional[float] = 0.0
    feature_importance: dict[str, float] = Field(default_factory=dict)
    feature_importances: Optional[dict[str, float]] = None

    # ── Self-describing evaluation context ──
    # These travel with every metric so a score can never be read without the
    # conditions that produced it.
    # ── Operational burden (blueprint section 10) ──
    # Rates alone do not tell an analyst how much work a model creates or
    # how much it misses, so the raw event counts are reported too.
    detected_events: int = 0      # TP — events correctly warned about
    missed_events: int = 0        # FN — events that occurred with no warning
    false_alarms: int = 0         # FP — warnings with no event
    correct_quiet_windows: int = 0  # TN
    false_alarms_per_100_windows: Optional[float] = None
    missed_event_rate: Optional[float] = None

    evaluated_on_holdout: bool = True
    test_positive_count: int = 0
    test_negative_count: int = 0
    metrics_interpretable: bool = True
    interpretation_warnings: list[str] = Field(default_factory=list)


class PredictionResult(BaseModel):
    model_id: str
    model_name: Optional[str] = None
    prediction_id: Optional[str] = None
    predicted_at: Optional[str] = None
    prediction_timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    propensity_score: float  # probability [0.0, 1.0]
    predicted_incident: bool
    threshold: float
    threshold_used: Optional[float] = None
    lead_time_seconds: float
    prediction_horizon_seconds: float
    horizon_seconds: Optional[float] = None
    confidence: float
    top_contributing_features: list[dict[str, Any]] = Field(default_factory=list)

    # ── Validation provenance (required reading for any consumer) ──
    # A probability is only a forecast if the model that produced it was
    # evaluated on a leakage-free holdout containing positive examples.
    # Until then these fields mark the score as unvalidated output.
    is_validated_model: bool = False
    validation_status: str = "no_model_trained"
    is_actionable_forecast: bool = False
    interpretation: str = ""
    evaluation_caveats: list[str] = Field(default_factory=list)

    # Actual observation window used for inference, so the score can be
    # checked against the data that produced it.
    observation_window_seconds: float = 0.0
    observation_event_count: int = 0
    observation_window_start: Optional[datetime] = None
    observation_window_end: Optional[datetime] = None


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
    fn, tp = cm[1][0], cm[1][1]
    fpr = float(fp / max(1, tn + fp))

    # Operational burden, stated as counts rather than only as rates.
    n_windows = len(y_test)
    false_alarms_per_100 = (
        round(fp / n_windows * 100, 2) if n_windows else None
    )
    missed_rate = round(fn / (fn + tp), 4) if (fn + tp) > 0 else None

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

    # Describe what the test split actually contained. With no positive
    # examples, precision/recall/F1/PR-AUC are not merely poor — they are
    # undefined as measures of detection ability, and the figures below must
    # not be read as evidence either way.
    test_pos = int(np.sum(y_test == 1))
    test_neg = int(np.sum(y_test == 0))
    interpretation_warnings: list[str] = []
    if test_pos == 0:
        interpretation_warnings.append(
            "Test split contains ZERO positive (attack) windows. Recall, F1, PR-AUC "
            "and ROC-AUC are undefined or degenerate; precision cannot be estimated. "
            "These figures do not demonstrate predictive ability."
        )
    if test_neg == 0:
        interpretation_warnings.append(
            "Test split contains ZERO negative windows; false-positive rate and "
            "specificity cannot be estimated."
        )
    if len(y_test) < 20:
        interpretation_warnings.append(
            f"Test split contains only {len(y_test)} windows; metrics carry very wide "
            "confidence intervals and are not a reliable performance estimate."
        )

    metrics = ModelMetrics(
        model_name=model_name,
        model_type=model_type,
        detected_events=int(tp),
        missed_events=int(fn),
        false_alarms=int(fp),
        correct_quiet_windows=int(tn),
        false_alarms_per_100_windows=false_alarms_per_100,
        missed_event_rate=missed_rate,
        evaluated_on_holdout=True,
        test_positive_count=test_pos,
        test_negative_count=test_neg,
        metrics_interpretable=(test_pos > 0 and test_neg > 0 and len(y_test) >= 20),
        interpretation_warnings=interpretation_warnings,
        accuracy=round(acc, 4),
        precision=round(prec, 4),
        recall=round(rec, 4),
        f1=round(f1, 4),
        f1_score=round(f1, 4),
        pr_auc=round(pr_auc, 4) if pr_auc is not None else None,
        roc_auc=round(roc_auc, 4) if roc_auc is not None else None,
        brier_score=round(brier, 4) if brier is not None else None,
        false_positive_rate=round(fpr, 4),
        confusion_matrix=cm,
        sample_count=len(y_test),
        train_instances=len(y_train),
        test_instances=len(y_test),
        training_time_seconds=round(duration, 4),
        training_duration_seconds=round(duration, 4),
        feature_importance=feat_importances,
        feature_importances=feat_importances,
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
        self.last_split_report: Optional[SplitIntegrityReport] = None

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

        # ── Chronological split with purge/embargo ──────────────────────
        #
        # Adjacent sliding windows overlap: with window W and stride S each
        # feature vector shares W-S seconds of telemetry with its neighbour,
        # and a window's label describes the period [t+L, t+L+H], which is
        # data that *later* windows observe. A bare index split therefore
        # leaks — the first test windows re-observe telemetry that training
        # windows already saw and that training labels already described.
        #
        # The boundary windows spanning that overlap are purged. Nothing is
        # reassigned across the boundary: training is strictly earlier than
        # testing, and when purging leaves an inadequate test set the method
        # reports that rather than falling back to a split that would inflate
        # the score.
        report = self.extractor.last_windowing_report
        eff_window = report.effective_window_seconds if report else self.extractor.window_size_seconds
        eff_lead = report.effective_lead_seconds if report else self.extractor.lead_time_seconds
        eff_horizon = report.effective_horizon_seconds if report else self.extractor.prediction_horizon_seconds
        eff_stride = report.effective_stride_seconds if report else 15.0

        if report is not None and report.used_fallback_chunking:
            # Event-count chunks are not time-windowed; purge by one chunk.
            embargo_windows = 1
        else:
            contaminated_seconds = eff_window + eff_lead + eff_horizon
            embargo_windows = int(math.ceil(contaminated_seconds / max(1e-6, eff_stride)))

        # Purge from the TRAINING side and keep the holdout intact. Training
        # windows whose label horizon reaches into the test period are the
        # contaminated ones, so they are the ones to drop; discarding test
        # windows instead would spend the scarce evaluation data to fix a
        # training-side problem.
        test_start = max(2, int(len(X) * train_ratio))
        train_end = max(0, test_start - embargo_windows + 1)

        X_train, y_train = X[:train_end], y[:train_end]
        X_test, y_test = X[test_start:], y[test_start:]

        purged = int(test_start - train_end)

        # A fingerprint of the exact instance set, so an evaluation can be
        # tied to its inputs without storing any telemetry.
        fingerprint_src = "|".join([
            str(len(events)),
            str(len(X)),
            f"{eff_window}/{eff_lead}/{eff_horizon}/{eff_stride}",
            str(train_ratio),
            str(int(y.sum())),
            (min(e.observed_at for e in events).isoformat() if events else ""),
            (max(e.observed_at for e in events).isoformat() if events else ""),
        ])
        dataset_fingerprint = hashlib.sha256(
            fingerprint_src.encode("utf-8")
        ).hexdigest()[:16]

        src_breakdown: dict[str, int] = {}
        prov_breakdown: dict[str, int] = {}
        cat_breakdown: dict[str, int] = {}
        for e in events:
            src_breakdown[e.source_id] = src_breakdown.get(e.source_id, 0) + 1
            prov_breakdown[e.label_provenance.value] = (
                prov_breakdown.get(e.label_provenance.value, 0) + 1
            )
            cat_breakdown[e.data_category.value] = (
                cat_breakdown.get(e.data_category.value, 0) + 1
            )

        times = sorted(e.observed_at for e in events) if events else []

        self.last_split_report = SplitIntegrityReport(
            configured_train_ratio=train_ratio,
            dataset_fingerprint=dataset_fingerprint,
            source_breakdown=src_breakdown,
            label_provenance_breakdown=prov_breakdown,
            data_category_breakdown=cat_breakdown,
            event_count=len(events),
            event_time_range=(
                [times[0].isoformat(), times[-1].isoformat()] if times else None
            ),
            target_definition=(
                f"y=1 if an attack-labelled event occurs in "
                f"(t+{eff_lead}s, t+{eff_lead}s+{eff_horizon}s]; y=0 only when that "
                f"horizon is observed and labelled. Features from [t-{eff_window}s, t)."
            ),
            total_instances=int(len(X)),
            train_instances=int(len(X_train)),
            test_instances=int(len(X_test)),
            purged_instances=purged,
            embargo_windows=int(embargo_windows),
            embargo_seconds=round(embargo_windows * eff_stride, 3),
            train_positive=int(y_train.sum()),
            train_negative=int(len(y_train) - y_train.sum()),
            test_positive=int(y_test.sum()) if len(y_test) else 0,
            test_negative=int(len(y_test) - y_test.sum()) if len(y_test) else 0,
            split_strategy="chronological_train_side_purge",
            train_end_timestamp=ts[train_end - 1] if ts and 0 < train_end <= len(ts) else None,
            test_start_timestamp=ts[test_start] if ts and test_start < len(ts) else None,
            windowing=report,
        )

        span_requirement = (
            f"W={eff_window}s / L={eff_lead}s / H={eff_horizon}s / S={eff_stride}s "
            f"requires a purge of {embargo_windows} windows between train and test"
        )

        if len(X_train) < 4:
            raise InsufficientEvaluationDataError(
                f"Only {len(X_train)} training windows remain after purging {purged} "
                f"contaminated boundary window(s) from {len(X)} total windows "
                f"({span_requirement}). The dataset does not span enough time to train "
                "on past data and evaluate on strictly later data without overlap. "
                "Shrinking the purge or reusing boundary windows would leak future "
                "information into training, so training is refused.",
                split_report=self.last_split_report,
            )

        if len(X_test) == 0:
            raise InsufficientEvaluationDataError(
                f"No evaluation windows remain ({len(X)} total windows, "
                f"train={len(X_train)}, {span_requirement}). Evaluating on the training "
                "split instead would report a fitted-data score as a holdout score, "
                "so evaluation is refused.",
                split_report=self.last_split_report,
            )

        if len(np.unique(y_train)) < 2:
            raise InsufficientEvaluationDataError(
                f"The leakage-free training period ({len(y_train)} windows ending "
                f"before the purge boundary) contains only class {int(y_train[0])}. "
                "Supervised training requires both benign and attack windows to occur "
                "within the training period itself. Reassigning later windows into "
                "training to manufacture class balance would leak future information, "
                "so training is refused.",
                split_report=self.last_split_report,
            )

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

        # ── Establish validation status before producing any number ──
        caveats: list[str] = []
        if model is None:
            # No trained model exists. An uncalibrated heuristic still yields a
            # number, but it must be labelled as such — never as a forecast.
            model = BaselineThresholdModel()
            validation_status = "no_model_trained"
            is_validated_model = False
            caveats.append(
                f"No trained model '{chosen_id}' exists. The score below comes from an "
                "uncalibrated heuristic threshold, not from a trained or evaluated model."
            )
        else:
            metrics = self.model_metrics.get(chosen_id)
            if metrics is None:
                validation_status = "trained_not_evaluated"
                is_validated_model = False
                caveats.append("Model was trained but no evaluation metrics are recorded.")
            elif not metrics.metrics_interpretable:
                validation_status = "evaluated_but_not_validated"
                is_validated_model = False
                caveats.extend(metrics.interpretation_warnings)
            else:
                validation_status = "validated_on_purged_holdout"
                is_validated_model = True

        if self.last_split_report is not None and not self.last_split_report.test_has_positives:
            if "Evaluation holdout contained no attack windows" not in caveats:
                caveats.append(
                    "Evaluation holdout contained no attack windows, so predictive "
                    "skill for attack events is unmeasured."
                )

        # ── Restrict inference to a genuine observation window ──
        # Training features are computed over a fixed W-second window. Feeding
        # inference an arbitrary count of events (which may span hours) makes
        # rate features incomparable with the ones the model learned from, so
        # the window is bounded by time here, exactly as in training.
        window_seconds = self.extractor.window_size_seconds
        window_events = list(recent_events)
        window_start: Optional[datetime] = None
        window_end: Optional[datetime] = None
        if window_events:
            window_end = max(e.observed_at for e in window_events)
            window_start = window_end - timedelta(seconds=window_seconds)
            window_events = [e for e in window_events if e.observed_at >= window_start]
            if not window_events:
                window_events = list(recent_events)
                caveats.append(
                    "No events fell inside the most recent observation window; "
                    "features were computed over all supplied events instead and are "
                    "not comparable with the training distribution."
                )

        features = self.extractor.extract_features_from_window(window_events, window_seconds)
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

        if is_validated_model:
            interpretation = (
                "Propensity score from a model evaluated on a purged chronological "
                "holdout. Treat as a statistical indicator for triage, not as a "
                "confirmed future attack."
            )
        else:
            interpretation = (
                "UNVALIDATED OUTPUT — not a forecast. This score has no demonstrated "
                "predictive accuracy and must not be used to claim that an attack will "
                "occur. See evaluation_caveats."
            )

        now_dt = datetime.now(timezone.utc)
        return PredictionResult(
            is_validated_model=is_validated_model,
            validation_status=validation_status,
            is_actionable_forecast=is_validated_model,
            interpretation=interpretation,
            evaluation_caveats=caveats,
            observation_window_seconds=window_seconds,
            observation_event_count=len(window_events),
            observation_window_start=window_start,
            observation_window_end=window_end,
            model_id=chosen_id,
            model_name=chosen_id,
            prediction_id=f"pred-{int(now_dt.timestamp())}",
            predicted_at=now_dt.isoformat(),
            prediction_timestamp=now_dt,
            propensity_score=round(p_score, 4),
            predicted_incident=is_incident,
            threshold=threshold,
            threshold_used=threshold,
            lead_time_seconds=self.extractor.lead_time_seconds,
            prediction_horizon_seconds=self.extractor.prediction_horizon_seconds,
            horizon_seconds=self.extractor.prediction_horizon_seconds,
            confidence=round(abs(p_score - 0.5) * 2, 3),
            top_contributing_features=contributions[:5],
        )
