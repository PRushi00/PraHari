"""
PraHari — Lead-Time and Uncertainty Evaluation

Two questions a single precision/recall pair cannot answer:

**How far ahead can it warn?**
A forecaster evaluated at one lead time says nothing about how performance
decays as the warning window grows. The lead-time sweep re-runs the whole
protocol at several lead times and reports the curve — including the leads
at which no honest evaluation is possible, which are *reported as refusals*
rather than dropped from the curve. Silently omitting them would make the
curve look flat where it is actually undefined.

**How much of the number is noise?**
A point estimate from a small holdout is not a measurement. Percentile
bootstrap intervals are computed by resampling the held-out instances, and
an interval is **refused** when the holdout cannot support one — too few
instances, or one class absent — rather than returned as a reassuringly
narrow range computed from nothing.

Neither function invents data. Both operate on the same windows, the same
target definition and the same purged chronological split as the headline
evaluation.
"""

from __future__ import annotations

import logging
from typing import Callable, Optional

import numpy as np
from pydantic import BaseModel, Field
from sklearn.metrics import average_precision_score, precision_score, recall_score

from app.models.forecaster import (
    LSTM_TIMESTEPS,
    InsufficientEvaluationDataError,
    ModelMetrics,
    ThreatForecastingPipeline,
    score_positive_class,
    stack_lagged_windows,
)
from app.models.lstm_forecaster import to_sequences
from app.schemas.events import NormalizedEvent

logger = logging.getLogger(__name__)

# A bootstrap over a handful of instances produces an interval that looks
# precise and means nothing. These are the floors below which one is refused.
MIN_BOOTSTRAP_INSTANCES = 20
MIN_BOOTSTRAP_POSITIVES = 5
DEFAULT_RESAMPLES = 1000
DEFAULT_SEED = 42

DEFAULT_LEAD_TIMES = (0.0, 30.0, 60.0, 120.0, 300.0)


# ──────────────────────────────────────────────────────────────────
# Uncertainty
# ──────────────────────────────────────────────────────────────────


class UncertaintyInterval(BaseModel):
    """A percentile bootstrap interval, or an explicit refusal to give one."""

    metric: str
    available: bool
    point_estimate: Optional[float] = None
    lower: Optional[float] = None
    upper: Optional[float] = None
    confidence: float = 0.95
    resamples: int = 0
    instances: int = 0
    positives: int = 0
    refusal_reason: Optional[str] = None
    method: str = "percentile bootstrap over held-out instances"


_METRICS: dict[str, Callable[[np.ndarray, np.ndarray], float]] = {
    "pr_auc": lambda y, s: float(average_precision_score(y, s)),
    "precision": lambda y, s: float(precision_score(y, (s >= 0.5).astype(int), zero_division=0)),
    "recall": lambda y, s: float(recall_score(y, (s >= 0.5).astype(int), zero_division=0)),
}


def bootstrap_interval(
    y_true: np.ndarray,
    y_score: np.ndarray,
    metric: str = "pr_auc",
    resamples: int = DEFAULT_RESAMPLES,
    confidence: float = 0.95,
    seed: int = DEFAULT_SEED,
) -> UncertaintyInterval:
    """
    Percentile bootstrap interval for one metric on a held-out set.

    Refuses, with a stated reason, when the holdout is too small or has one
    class. Resamples that lose a class are skipped rather than scored as 0,
    because such a resample does not represent a possible evaluation.
    """
    y_true = np.asarray(y_true).astype(int)
    y_score = np.asarray(y_score).astype(float)

    if metric not in _METRICS:
        raise ValueError(f"Unknown metric {metric!r}. Known: {sorted(_METRICS)}")

    n = len(y_true)
    positives = int(y_true.sum())
    base = UncertaintyInterval(
        metric=metric, available=False, confidence=confidence,
        instances=n, positives=positives,
    )

    if n < MIN_BOOTSTRAP_INSTANCES:
        base.refusal_reason = (
            f"Only {n} held-out instance(s); at least {MIN_BOOTSTRAP_INSTANCES} "
            "are needed before an interval describes anything."
        )
        return base
    if positives < MIN_BOOTSTRAP_POSITIVES:
        base.refusal_reason = (
            f"Only {positives} positive instance(s) in the holdout; at least "
            f"{MIN_BOOTSTRAP_POSITIVES} are needed. An interval from fewer "
            "would be driven by which single events happened to land in the test period."
        )
        return base
    if positives == n:
        base.refusal_reason = "The holdout contains no negative instances."
        return base

    fn = _METRICS[metric]
    point = fn(y_true, y_score)

    rng = np.random.default_rng(seed)
    samples: list[float] = []
    for _ in range(resamples):
        idx = rng.integers(0, n, n)
        ys, ss = y_true[idx], y_score[idx]
        if len(np.unique(ys)) < 2:
            continue  # degenerate resample: not a possible evaluation
        samples.append(fn(ys, ss))

    if len(samples) < resamples // 2:
        base.point_estimate = round(point, 4)
        base.refusal_reason = (
            f"Only {len(samples)} of {resamples} resamples retained both "
            "classes, so the interval would be unstable. The point estimate "
            "stands on its own."
        )
        return base

    alpha = (1.0 - confidence) / 2.0
    lower, upper = np.percentile(samples, [100 * alpha, 100 * (1 - alpha)])
    return UncertaintyInterval(
        metric=metric,
        available=True,
        point_estimate=round(point, 4),
        lower=round(float(lower), 4),
        upper=round(float(upper), 4),
        confidence=confidence,
        resamples=len(samples),
        instances=n,
        positives=positives,
    )


# ──────────────────────────────────────────────────────────────────
# Lead-time sweep
# ──────────────────────────────────────────────────────────────────


class LeadTimePoint(BaseModel):
    """One lead time's result, or the reason there is none."""

    lead_time_seconds: float
    evaluated: bool
    refusal_reason: Optional[str] = None

    total_instances: int = 0
    train_instances: int = 0
    test_instances: int = 0
    purged_instances: int = 0
    test_positives: int = 0

    metrics: dict[str, ModelMetrics] = Field(default_factory=dict)
    best_model: Optional[str] = None
    best_pr_auc: Optional[float] = None
    metrics_interpretable: bool = False


class LeadTimeCurve(BaseModel):
    """
    Performance against warning time, under one frozen protocol.

    `protocol` records the parameters held constant, so a reader can see that
    only the lead time varied.
    """

    protocol: dict[str, float] = Field(default_factory=dict)
    target_definition: str = ""
    points: list[LeadTimePoint] = Field(default_factory=list)
    evaluated_leads: int = 0
    refused_leads: int = 0
    notes: list[str] = Field(
        default_factory=lambda: [
            "Every point uses the same events, window, horizon, stride, split ratio and seed; only the lead time varies.",
            "A lead with no honest split is reported as a refusal, not omitted — omitting it would imply the curve is flat there.",
            "A longer lead gives more warning but less relevant recent evidence; a decaying curve is the expected shape.",
            "These are not evidence of real-world effectiveness unless the underlying labels are real.",
        ]
    )

    @property
    def usable(self) -> bool:
        return self.evaluated_leads > 0


def lead_time_curve(
    events: list[NormalizedEvent],
    lead_times: tuple[float, ...] = DEFAULT_LEAD_TIMES,
    window_seconds: float = 60.0,
    horizon_seconds: float = 60.0,
    train_ratio: float = 0.7,
) -> LeadTimeCurve:
    """
    Evaluate the same models at several lead times.

    Each lead gets its own pipeline so nothing carries over between runs. A
    lead whose windowing or split cannot support an honest evaluation is
    recorded with its reason.
    """
    curve = LeadTimeCurve(
        protocol={
            "observation_window_seconds": window_seconds,
            "prediction_horizon_seconds": horizon_seconds,
            "train_ratio": train_ratio,
            "random_seed": float(DEFAULT_SEED),
        }
    )

    for lead in lead_times:
        point = LeadTimePoint(lead_time_seconds=lead, evaluated=False)
        pipeline = ThreatForecastingPipeline(
            window_size_seconds=window_seconds,
            lead_time_seconds=lead,
            prediction_horizon_seconds=horizon_seconds,
        )

        try:
            metrics = pipeline.train_and_evaluate_all(events, train_ratio=train_ratio)
        except InsufficientEvaluationDataError as exc:
            point.refusal_reason = f"No leakage-free split at this lead time: {exc}"
            curve.points.append(point)
            curve.refused_leads += 1
            continue
        except ValueError as exc:
            point.refusal_reason = f"Dataset cannot support this lead time: {exc}"
            curve.points.append(point)
            curve.refused_leads += 1
            continue

        report = pipeline.last_split_report
        if report is not None:
            point.total_instances = report.total_instances
            point.train_instances = report.train_instances
            point.test_instances = report.test_instances
            point.purged_instances = report.purged_instances
            point.test_positives = report.test_positive
            if not curve.target_definition:
                curve.target_definition = report.target_definition or ""

        point.metrics = metrics
        point.evaluated = True

        scored = {
            name: m.pr_auc
            for name, m in metrics.items()
            if m.pr_auc is not None and not name.startswith("baseline_")
        }
        if scored:
            best = max(scored, key=lambda k: scored[k])
            point.best_model = best
            point.best_pr_auc = scored[best]
        point.metrics_interpretable = any(
            m.metrics_interpretable for m in metrics.values()
        )

        curve.points.append(point)
        curve.evaluated_leads += 1

    return curve


# ──────────────────────────────────────────────────────────────────
# Generalization: does it transfer to an environment it never saw?
# ──────────────────────────────────────────────────────────────────


class GeneralizationPoint(BaseModel):
    """One held-out group's result, or the reason there is none."""

    held_out_group: str
    evaluated: bool
    refusal_reason: Optional[str] = None

    train_groups: list[str] = Field(default_factory=list)
    train_events: int = 0
    test_events: int = 0
    test_instances: int = 0
    test_positives: int = 0

    cross_group_pr_auc: Optional[float] = None
    cross_group_precision: Optional[float] = None
    cross_group_recall: Optional[float] = None
    within_group_pr_auc: Optional[float] = None
    transfer_gap: Optional[float] = None
    model_id: Optional[str] = None


class GeneralizationReport(BaseModel):
    """
    Leave-one-group-out transfer, with the within-group score beside it.

    A cross-group number on its own is not interpretable: 0.6 could be a
    large drop from 0.95 or a rise from 0.5. The gap is the result.
    """

    grouped_by: str
    groups: dict[str, int] = Field(default_factory=dict)
    points: list[GeneralizationPoint] = Field(default_factory=list)
    evaluated_groups: int = 0
    refused_groups: int = 0
    mean_transfer_gap: Optional[float] = None
    independent_environments: bool = False
    notes: list[str] = Field(default_factory=list)

    @property
    def usable(self) -> bool:
        return self.evaluated_groups > 0


def _group_events(
    events: list[NormalizedEvent], by: str
) -> dict[str, list[NormalizedEvent]]:
    grouped: dict[str, list[NormalizedEvent]] = {}
    for e in events:
        key = e.source_id if by == "source_id" else e.data_category.value
        grouped.setdefault(key, []).append(e)
    return grouped


def _best_scored_model(metrics: dict[str, ModelMetrics]) -> Optional[str]:
    scored = {
        name: m.pr_auc
        for name, m in metrics.items()
        if m.pr_auc is not None and not name.startswith("baseline_")
    }
    return max(scored, key=lambda k: scored[k]) if scored else None


def generalization_evaluation(
    events: list[NormalizedEvent],
    group_by: str = "source_id",
    window_seconds: float = 60.0,
    lead_seconds: float = 30.0,
    horizon_seconds: float = 60.0,
    train_ratio: float = 0.7,
) -> GeneralizationReport:
    """
    Train on every group but one, evaluate on the one held out.

    This answers a different question from the chronological split: not
    "does it predict the future of this environment" but "does anything it
    learned apply to an environment it never saw". A model can do the first
    well and the second not at all, which is the usual way a security
    forecaster fails in deployment.

    The within-group score is computed too, by the ordinary chronological
    protocol on the held-out group alone, so the **gap** can be read
    directly rather than inferred.

    Groups that cannot support an honest evaluation are reported with their
    reason, never dropped.
    """
    grouped = _group_events(events, group_by)
    report = GeneralizationReport(
        grouped_by=group_by,
        groups={k: len(v) for k, v in grouped.items()},
    )

    # Whether the groups are genuinely independent environments decides what
    # a transfer score is worth. Several synthetic groups from one generator
    # are not independent: good transfer between them measures the
    # generator's consistency, not the model's generality.
    categories = {e.data_category.value for e in events}
    report.independent_environments = (
        len(grouped) >= 2 and categories != {"synthetic_demo"}
    )
    report.notes = [
        "Leave-one-group-out: the held-out group contributes nothing to training.",
        "The within-group score uses the ordinary chronological protocol on that group alone.",
        "transfer_gap = within_group_pr_auc - cross_group_pr_auc. Positive means performance dropped on the unseen environment.",
    ]
    if not report.independent_environments:
        report.notes.append(
            "WARNING: every group here is synthetic_demo, produced by the same "
            "generator. These are not independent environments, so a small gap "
            "measures the generator's consistency, not the model's generality. "
            "A real generalization claim needs groups collected separately."
        )

    if len(grouped) < 2:
        report.notes.append(
            f"Only {len(grouped)} group(s) under {group_by!r}; "
            "generalization needs at least two."
        )
        return report

    def _pipeline() -> ThreatForecastingPipeline:
        return ThreatForecastingPipeline(
            window_size_seconds=window_seconds,
            lead_time_seconds=lead_seconds,
            prediction_horizon_seconds=horizon_seconds,
        )

    for held_out, held_events in grouped.items():
        point = GeneralizationPoint(held_out_group=held_out, evaluated=False)
        train_events = [e for k, v in grouped.items() if k != held_out for e in v]
        point.train_groups = sorted(k for k in grouped if k != held_out)
        point.train_events = len(train_events)
        point.test_events = len(held_events)

        # Cross-group: fit on the others, score the held-out group.
        try:
            trainer = _pipeline()
            trainer.train_and_evaluate_all(train_events, train_ratio=train_ratio)
        except (InsufficientEvaluationDataError, ValueError) as exc:
            point.refusal_reason = f"Training groups cannot support a fit: {exc}"
            report.points.append(point)
            report.refused_groups += 1
            continue

        model_id = _best_scored_model(trainer.model_metrics)
        if model_id is None:
            point.refusal_reason = "No non-baseline model produced a usable score."
            report.points.append(point)
            report.refused_groups += 1
            continue
        point.model_id = model_id

        extractor = _pipeline().extractor
        try:
            X_held, y_held, _ = extractor.build_dataset_instances(held_events)
        except Exception as exc:  # noqa: BLE001
            point.refusal_reason = f"Held-out group could not be windowed: {exc}"
            report.points.append(point)
            report.refused_groups += 1
            continue

        point.test_instances = int(len(X_held))
        point.test_positives = int(y_held.sum()) if len(y_held) else 0

        if (
            len(X_held) == 0
            or point.test_positives == 0
            or point.test_positives == len(y_held)
        ):
            point.refusal_reason = (
                f"Held-out group yields {len(X_held)} instance(s) with "
                f"{point.test_positives} positive(s); both classes are needed "
                "for an interpretable score."
            )
            report.points.append(point)
            report.refused_groups += 1
            continue

        model = trainer.trained_models.get(model_id)
        X_eval, y_eval = X_held, y_held
        if model_id == "temporal_window_stack":
            X_eval, y_eval = stack_lagged_windows(X_held, y_held)
        elif model_id == "lstm_forecaster":
            X_eval, y_eval = to_sequences(X_held, y_held, LSTM_TIMESTEPS)

        if len(X_eval) == 0 or len(np.unique(y_eval)) < 2:
            point.refusal_reason = (
                "Sequence shaping left the held-out group without both classes."
            )
            report.points.append(point)
            report.refused_groups += 1
            continue

        scores = score_positive_class(model, X_eval)
        preds = (scores >= 0.5).astype(int)
        point.cross_group_pr_auc = round(
            float(average_precision_score(y_eval, scores)), 4
        )
        point.cross_group_precision = round(
            float(precision_score(y_eval, preds, zero_division=0)), 4
        )
        point.cross_group_recall = round(
            float(recall_score(y_eval, preds, zero_division=0)), 4
        )

        # Within-group: the ordinary protocol on the held-out group alone.
        try:
            local = _pipeline()
            local_metrics = local.train_and_evaluate_all(
                held_events, train_ratio=train_ratio
            )
            local_id = _best_scored_model(local_metrics)
            if local_id and local_metrics[local_id].pr_auc is not None:
                point.within_group_pr_auc = local_metrics[local_id].pr_auc
                point.transfer_gap = round(
                    point.within_group_pr_auc - point.cross_group_pr_auc, 4
                )
        except (InsufficientEvaluationDataError, ValueError):
            # No within-group baseline is available; the cross-group number
            # stands alone and the gap stays None rather than being guessed.
            pass

        point.evaluated = True
        report.points.append(point)
        report.evaluated_groups += 1

    gaps = [p.transfer_gap for p in report.points if p.transfer_gap is not None]
    if gaps:
        report.mean_transfer_gap = round(sum(gaps) / len(gaps), 4)

    return report
