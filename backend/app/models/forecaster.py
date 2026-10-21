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
from app.models.lstm_forecaster import LSTMForecaster, to_sequences
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

    # Mirrored from the windowing report so a caller reading split integrity
    # cannot miss it. Deliberately named apart from SelectionCoverage's
    # `truncated`, which reports a RECORD-count cap: the two are independent
    # and an evaluation can be limited by either, or both.
    windowing_truncated: bool = False
    windows_omitted: int = 0

    # ── Reproducibility manifest (blueprint sections 8 and 16) ──
    # Enough to reconstruct exactly which instances were used, without
    # embedding any telemetry.
    manifest_version: str = "1.0.0"

    # Content fingerprint of the event set, computed with the SAME function
    # the experiment manifest uses, so the two agree. Previously this field
    # held a hash of counts and window parameters, which could never match
    # the manifest's value although both were called "dataset_fingerprint".
    dataset_fingerprint: Optional[str] = None

    # Hash of the evaluation SETUP (instance counts, window parameters,
    # split ratio, positives, time range). Useful for spotting that a run
    # used a different protocol; it is not content-addressed over the
    # records and must not be read as a dataset identity.
    split_configuration_fingerprint: Optional[str] = None
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

    # ── Three separate questions, deliberately not collapsed ──
    #
    # A number that can be calculated, an evaluation large enough to mean
    # something, and a model that actually discriminates are three different
    # claims. Reporting one flag for all three is how a chance-level result
    # gets read as a weak-but-real one.
    #
    #   metrics_computable  — both classes present, so precision / recall /
    #                         PR-AUC / ROC-AUC are mathematically defined
    #   sample_adequate     — enough held-out instances for the figures to
    #                         carry a usable confidence interval
    #   predictions_degenerate — the model emitted a single class, or ranked
    #                         nothing (constant scores). Metrics are still
    #                         computed and reported; they simply describe a
    #                         model that made no distinctions
    #   discrimination_demonstrated — PR-AUC above the no-skill base rate on
    #                         an adequate sample. None when undeterminable.
    #                         True here means "better than chance on this
    #                         sample", NOT "a useful forecasting model"
    metrics_computable: bool = True
    sample_adequate: bool = True
    predictions_degenerate: bool = False
    predicted_positive_count: int = 0
    predicted_negative_count: int = 0
    distinct_score_count: int = 0
    scores_constant: bool = False
    no_skill_pr_auc: Optional[float] = None
    discrimination_demonstrated: Optional[bool] = None

    # Composite kept for existing consumers: computable AND adequate.
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


# ──────────────────────────────────────────────────────────────────
# Temporal (sequence) modelling
# ──────────────────────────────────────────────────────────────────

# Below this many held-out instances the figures carry confidence intervals
# too wide to support any comparison between models.
MIN_INTERPRETABLE_TEST_INSTANCES = 20

TEMPORAL_LAGS = 3

# LSTM sequence settings. Deliberately small: on the few hundred sequences
# this data yields, a larger network memorises the training period rather
# than learning anything that transfers.
LSTM_TIMESTEPS = 4
LSTM_HIDDEN = 12
LSTM_EPOCHS = 120
LSTM_LEARNING_RATE = 0.03


def stack_lagged_windows(
    X: np.ndarray, y: np.ndarray, lags: int = TEMPORAL_LAGS
) -> tuple[np.ndarray, np.ndarray]:
    """
    Turn each instance into a short sequence of consecutive windows.

    Instance *i* becomes the concatenation of windows ``i-lags … i``, so the
    model sees how the features **moved** rather than a single snapshot.
    That is what makes it a temporal model: order matters, and the same
    feature values in a different sequence give a different input.

    Stacking is applied **separately to the training and test matrices**,
    never to the full dataset before splitting. Done before the split, a
    test instance near the boundary would carry training-period windows in
    its lags, re-importing exactly the contamination the purge removes. The
    cost is the first ``lags`` instances of each side, which are dropped
    because they have no complete history.

    This is NOT an LSTM — see the module note on what that would require.
    """
    if lags < 1:
        raise ValueError("lags must be at least 1")
    if len(X) <= lags:
        return np.empty((0, X.shape[1] * (lags + 1))), np.empty((0,))

    rows = [
        np.concatenate([X[i - k] for k in range(lags, -1, -1)])
        for i in range(lags, len(X))
    ]
    return np.asarray(rows), y[lags:]


class PersistenceBaseline:
    """
    "An attack is happening now, so one will happen next."

    The baseline that matters most on bursty attack data and the one most
    often missing from published results. A long DDoS episode spans many
    consecutive windows, so simply carrying the current state forward scores
    very well — and any model that cannot beat it has demonstrated nothing
    about forecasting.

    It is fitted on the OBSERVATION-window attack indicator only. That
    indicator describes `[t-W, t)`, strictly before the target interval
    `[t+L, t+L+H)`, so no future label is used. It is passed in separately
    rather than added to the feature matrix, because a feature meaning
    "an attack is in progress" would hand every other model the same
    shortcut and turn the whole evaluation into detection.
    """

    def __init__(self) -> None:
        self.rate_when_active: float = 0.5
        self.rate_when_quiet: float = 0.5

    def fit(self, observation_attack: np.ndarray, y: np.ndarray) -> "PersistenceBaseline":
        observation_attack = np.asarray(observation_attack).astype(int).ravel()
        y = np.asarray(y).astype(int).ravel()
        active = observation_attack == 1
        quiet = ~active
        # Empirical P(incident ahead | state now), from TRAINING rows only.
        self.rate_when_active = float(y[active].mean()) if active.any() else 0.5
        self.rate_when_quiet = float(y[quiet].mean()) if quiet.any() else 0.0
        return self

    def predict_proba(self, observation_attack: np.ndarray) -> np.ndarray:
        state = np.asarray(observation_attack).astype(int).ravel()
        p = np.where(state == 1, self.rate_when_active, self.rate_when_quiet)
        return np.column_stack([1.0 - p, p])

    def predict(self, observation_attack: np.ndarray) -> np.ndarray:
        return (self.predict_proba(observation_attack)[:, 1] >= 0.5).astype(int)


def score_positive_class(model: Any, X: np.ndarray) -> np.ndarray:
    """Probability of the positive class, or a hard prediction as a fallback."""
    if hasattr(model, "predict_proba"):
        probs = model.predict_proba(X)
        return probs[:, 1] if probs.shape[1] > 1 else probs[:, 0]
    return np.asarray(model.predict(X)).astype(float)


class HoldoutPredictions:
    """
    Held-out truth and scores from the last evaluation, kept in memory so
    uncertainty can be estimated without retraining.

    Truth is stored **per model** because the temporal model's holdout is
    shorter: lag stacking drops the first instances, which have no complete
    history. Resampling one model's scores against another's labels would
    silently misalign them.
    """

    def __init__(self) -> None:
        self.scores: dict[str, np.ndarray] = {}
        self._truth: dict[str, np.ndarray] = {}
        self._times: dict[str, list[datetime]] = {}
        # The window feature rows behind the scores, kept ONLY for models
        # whose input is one window's canonical feature vector (ADR-109).
        # Persistence takes an indicator, the temporal stack is lag-stacked
        # and the LSTM is three-dimensional: for those a row here would not
        # line up with FEATURE_NAMES, so none is stored and the
        # investigation says contributions are unavailable rather than
        # attributing a score to the wrong names.
        self._features: dict[str, np.ndarray] = {}

    def record(
        self,
        model_id: str,
        y_true: np.ndarray,
        scores: np.ndarray,
        times: Optional[list[datetime]] = None,
        features: Optional[np.ndarray] = None,
    ) -> None:
        y_true = np.asarray(y_true).astype(int)
        scores = np.asarray(scores).astype(float)
        self._truth[model_id] = y_true
        self.scores[model_id] = scores
        if times is not None:
            # Event-level evaluation matches warnings to events by time, so a
            # misalignment here would silently attribute one window's score to
            # another window's moment. Refused rather than trimmed.
            if len(times) != len(scores):
                raise ValueError(
                    f"{model_id}: {len(times)} prediction time(s) for "
                    f"{len(scores)} score(s). The holdout's times must align "
                    "row for row with its scores."
                )
            self._times[model_id] = list(times)

        if features is not None:
            features = np.asarray(features, dtype=float)
            # Same reasoning as the times check above: a misalignment here
            # would explain one window's score with another window's
            # features, which is worse than having no explanation.
            if len(features) != len(scores):
                raise ValueError(
                    f"{model_id}: {len(features)} feature row(s) for "
                    f"{len(scores)} score(s). The holdout's features must "
                    "align row for row with its scores."
                )
            self._features[model_id] = features

    def y_true_for(self, model_id: str) -> np.ndarray:
        return self._truth[model_id]

    def features_for(self, model_id: str) -> Optional[np.ndarray]:
        """Window feature rows, or None when this model has no comparable ones."""
        return self._features.get(model_id)

    def times_for(self, model_id: str) -> Optional[list[datetime]]:
        """Window end times for this model's holdout, when they were kept."""
        return self._times.get(model_id)


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
    if len(y_test) < MIN_INTERPRETABLE_TEST_INSTANCES:
        interpretation_warnings.append(
            f"Test split contains only {len(y_test)} windows; metrics carry very wide "
            "confidence intervals and are not a reliable performance estimate."
        )

    # ── Degeneracy: did the model actually make distinctions? ──
    predicted_pos = int(np.sum(preds == 1))
    predicted_neg = int(np.sum(preds == 0))
    distinct_scores = int(len(np.unique(np.round(p_pos, 10))))
    scores_constant = distinct_scores <= 1
    degenerate = (predicted_pos == 0 or predicted_neg == 0) or scores_constant

    computable = test_pos > 0 and test_neg > 0
    adequate = computable and len(y_test) >= MIN_INTERPRETABLE_TEST_INSTANCES

    # The no-skill reference for PR-AUC is the positive base rate, not an
    # arbitrary cutoff: a classifier that ranks at random achieves it.
    no_skill = (test_pos / len(y_test)) if len(y_test) else None

    discrimination: Optional[bool] = None
    if not adequate:
        discrimination = None
    elif degenerate:
        discrimination = False
    elif pr_auc is not None and no_skill is not None:
        discrimination = bool(pr_auc > no_skill)

    if degenerate:
        if scores_constant:
            interpretation_warnings.append(
                f"DEGENERATE: the model produced a single score "
                f"({float(p_pos[0]) if len(p_pos) else float('nan'):.4f}) for every "
                "held-out window, so it ranked nothing. The metrics below are "
                "arithmetic over a constant prediction, not evidence of skill."
            )
        else:
            only = "positive" if predicted_neg == 0 else "negative"
            interpretation_warnings.append(
                f"DEGENERATE: the model predicted the {only} class for all "
                f"{len(y_test)} held-out windows. Recall and precision reduce to "
                "the class balance; this is not evidence of discrimination."
            )
    if discrimination is False and not degenerate:
        interpretation_warnings.append(
            f"PR-AUC {pr_auc} does not exceed the no-skill base rate "
            f"{round(no_skill, 4) if no_skill is not None else None}; the model "
            "did not outperform random ranking on this sample."
        )

    metrics = ModelMetrics(
        model_name=model_name,
        model_type=model_type,
        metrics_computable=computable,
        sample_adequate=adequate,
        predictions_degenerate=degenerate,
        predicted_positive_count=predicted_pos,
        predicted_negative_count=predicted_neg,
        distinct_score_count=distinct_scores,
        scores_constant=scores_constant,
        no_skill_pr_auc=round(no_skill, 4) if no_skill is not None else None,
        discrimination_demonstrated=discrimination,
        detected_events=int(tp),
        missed_events=int(fn),
        false_alarms=int(fp),
        correct_quiet_windows=int(tn),
        false_alarms_per_100_windows=false_alarms_per_100,
        missed_event_rate=missed_rate,
        evaluated_on_holdout=True,
        test_positive_count=test_pos,
        test_negative_count=test_neg,
        metrics_interpretable=adequate,
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
        self.last_holdout: Optional[HoldoutPredictions] = None
        # Set by the API layer: what was selected, out of what, and whether
        # the selection was truncated. Carried here so every consumer of a
        # result can see the coverage it was computed over.
        self.last_selection_coverage: Any = None

    def train_and_evaluate_all(
        self,
        events: list[NormalizedEvent],
        train_ratio: float = 0.7,
    ) -> dict[str, ModelMetrics]:
        """
        Extract chronological instances and train competitive models
        using an honest temporal train/test split.
        """
        # Before any window is built (ADR-070): a model's predictions are
        # never ground truth, and incompatible label provenances are never
        # merged. Raises LabelProvenanceError, a ValueError.
        from app.research.label_policy import enforce_label_policy

        self.last_label_policy = enforce_label_policy(events)
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
        # Prediction times for the holdout rows, in the same order. Carried so
        # warnings can be matched to events in time (ADR-091).
        ts_test: list[datetime] = list(ts[test_start:]) if ts else []

        purged = int(test_start - train_end)

        # Two distinct fingerprints, deliberately named for what they are.
        #
        # The setup hash ties an evaluation to the protocol that produced
        # it. It is NOT a dataset identity: two different corpora with the
        # same counts, positives and time range would collide.
        split_configuration_fingerprint = hashlib.sha256(
            "|".join([
                str(len(events)),
                str(len(X)),
                f"{eff_window}/{eff_lead}/{eff_horizon}/{eff_stride}",
                str(train_ratio),
                str(int(y.sum())),
                (min(e.observed_at for e in events).isoformat() if events else ""),
                (max(e.observed_at for e in events).isoformat() if events else ""),
            ]).encode("utf-8")
        ).hexdigest()[:16]

        # The dataset identity is content-addressed over the records, using
        # the same function the experiment manifest uses so that the value
        # reported here and the value stored in a manifest are comparable.
        from app.research.experiment import fingerprint_events

        dataset_fingerprint = fingerprint_events(events)

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
            split_configuration_fingerprint=split_configuration_fingerprint,
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
            windowing_truncated=bool(report.windows_truncated) if report else False,
            windows_omitted=int(report.windows_omitted) if report else 0,
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

        holdout = HoldoutPredictions()

        # 0. Persistence baseline — "attack now ⇒ attack next".
        #
        # Uses the same rows and the same split as every other model. It is
        # skipped rather than faked when the observation-attack indicator is
        # unavailable (for example after fallback chunking changed the row
        # count).
        obs_mask = getattr(self.extractor, "last_observation_attack_mask", None)
        if obs_mask is not None and len(obs_mask) == len(y):
            m0 = PersistenceBaseline()
            met0, m0 = evaluate_model_on_split(
                m0, "Persistence Baseline (attack now ⇒ attack next)",
                "baseline_persistence",
                obs_mask[:train_end], y_train,
                obs_mask[test_start:], y_test,
            )
            self.trained_models["baseline_persistence"] = m0
            self.model_metrics["baseline_persistence"] = met0
            holdout.record(
                "baseline_persistence", y_test,
                score_positive_class(m0, obs_mask[test_start:]),
                ts_test,
            )
        else:
            logger.info(
                "Persistence baseline skipped: observation-attack indicator "
                "unavailable or misaligned (%s vs %d instances).",
                None if obs_mask is None else len(obs_mask), len(y),
            )

        # 1. Baseline Constant
        m1 = BaselineConstantModel()
        met1, m1 = evaluate_model_on_split(m1, "Majority Class Baseline", "baseline_constant", X_train, y_train, X_test, y_test)
        self.trained_models["baseline_constant"] = m1
        self.model_metrics["baseline_constant"] = met1
        holdout.record("baseline_constant", y_test, score_positive_class(m1, X_test), ts_test, features=X_test)

        # 2. Baseline Threshold
        m2 = BaselineThresholdModel()
        met2, m2 = evaluate_model_on_split(m2, "Rate Threshold Baseline", "baseline_threshold", X_train, y_train, X_test, y_test)
        self.trained_models["baseline_threshold"] = m2
        self.model_metrics["baseline_threshold"] = met2
        holdout.record("baseline_threshold", y_test, score_positive_class(m2, X_test), ts_test, features=X_test)

        # 3. Logistic Regression
        m3 = LogisticRegression(max_iter=1000, random_state=42)
        met3, m3 = evaluate_model_on_split(m3, "Logistic Regression", "logistic_regression", X_train, y_train, X_test, y_test)
        self.trained_models["logistic_regression"] = m3
        self.model_metrics["logistic_regression"] = met3
        holdout.record("logistic_regression", y_test, score_positive_class(m3, X_test), ts_test, features=X_test)

        # 4. Random Forest / Tree Ensemble
        m4 = RandomForestClassifier(n_estimators=30, max_depth=6, random_state=42)
        met4, m4 = evaluate_model_on_split(m4, "Random Forest Forecaster", "random_forest", X_train, y_train, X_test, y_test)
        self.trained_models["random_forest_forecaster"] = m4
        self.model_metrics["random_forest_forecaster"] = met4
        holdout.record("random_forest_forecaster", y_test, score_positive_class(m4, X_test), ts_test, features=X_test)

        # 5. Temporal window-sequence model.
        #
        # Evaluated under the SAME target, dataset and split as the others,
        # so the comparison is like for like. It is skipped — not faked —
        # when stacking leaves too little data or only one class, because a
        # metric computed on such a holdout would not be interpretable.
        Xtr_seq, ytr_seq = stack_lagged_windows(X_train, y_train)
        Xte_seq, yte_seq = stack_lagged_windows(X_test, y_test)
        if (
            len(Xtr_seq) >= 4
            and len(Xte_seq) >= 1
            and len(np.unique(ytr_seq)) == 2
        ):
            m5 = RandomForestClassifier(n_estimators=30, max_depth=6, random_state=42)
            met5, m5 = evaluate_model_on_split(
                m5,
                f"Temporal Window Sequence (lag {TEMPORAL_LAGS})",
                "temporal_window_stack",
                Xtr_seq, ytr_seq, Xte_seq, yte_seq,
            )
            self.trained_models["temporal_window_stack"] = m5
            self.model_metrics["temporal_window_stack"] = met5
            # Its holdout is shorter than the others by TEMPORAL_LAGS.
            holdout.record(
                "temporal_window_stack", yte_seq,
                score_positive_class(m5, Xte_seq), ts_test[TEMPORAL_LAGS:],
            )
        else:
            logger.info(
                "Temporal window-sequence model skipped: lag stacking left "
                "%d train / %d test instances with %d class(es).",
                len(Xtr_seq), len(Xte_seq), len(np.unique(ytr_seq)) if len(ytr_seq) else 0,
            )

        # 6. LSTM sequence model (the blueprint's intended architecture).
        #
        # Sequences are built AFTER the split, separately per side, for the
        # same reason as the stacked temporal model: a test sequence built
        # before the split would reach back into the training period.
        #
        # Skipped — not faked — when the split leaves too little data or one
        # class, because a metric from such a holdout is uninterpretable.
        Xtr_lstm, ytr_lstm = to_sequences(X_train, y_train, LSTM_TIMESTEPS)
        Xte_lstm, yte_lstm = to_sequences(X_test, y_test, LSTM_TIMESTEPS)
        if (
            len(Xtr_lstm) >= 8
            and len(Xte_lstm) >= 1
            and len(np.unique(ytr_lstm)) == 2
        ):
            try:
                m6 = LSTMForecaster(
                    hidden_size=LSTM_HIDDEN,
                    epochs=LSTM_EPOCHS,
                    learning_rate=LSTM_LEARNING_RATE,
                    seed=42,
                )
                met6, m6 = evaluate_model_on_split(
                    m6, f"LSTM Sequence (t={LSTM_TIMESTEPS})", "lstm",
                    Xtr_lstm, ytr_lstm, Xte_lstm, yte_lstm,
                )
                self.trained_models["lstm_forecaster"] = m6
                self.model_metrics["lstm_forecaster"] = met6
                holdout.record(
                    "lstm_forecaster", yte_lstm,
                    score_positive_class(m6, Xte_lstm),
                    ts_test[LSTM_TIMESTEPS - 1:],
                )
            except Exception:  # noqa: BLE001
                # A failed LSTM must not take the whole evaluation with it;
                # the other five models are still valid results.
                logger.warning("LSTM evaluation failed; omitted", exc_info=True)
        else:
            logger.info(
                "LSTM skipped: %d train / %d test sequences, %d class(es).",
                len(Xtr_lstm), len(Xte_lstm),
                len(np.unique(ytr_lstm)) if len(ytr_lstm) else 0,
            )

        self.last_holdout = holdout
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
