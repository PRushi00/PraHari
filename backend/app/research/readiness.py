"""
PraHari — Forecasting Research Gate

Decides, from the data alone, whether a forecasting operation may proceed —
and says precisely why when it may not.

This gate is enforced in the backend. Hiding a button in the dashboard is
not a control: a direct API call would bypass it, and the first consumer to
script against the API would get an unsupportable number back. Every
forecasting entry point consults this module.

Readiness is reported as one of several explicit states rather than a
boolean, because "cannot forecast" has very different causes — too little
data, no labels, no attack examples in the evaluation period, a model that
trained but was never validated — and each implies a different next step.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field

from app.schemas.events import (
    DataCategory,
    LabelProvenance,
    NormalizedEvent,
    is_plausible_timestamp,
)

# A supervised forecaster needs enough windows to train on the past and
# evaluate on strictly later data after the contaminated boundary is purged.
MIN_EVENTS_FOR_TRAINING = 200
MIN_LABELLED_EVENTS = 50
MIN_POSITIVE_EVENTS = 10
MIN_NEGATIVE_EVENTS = 10
MIN_TIME_SPAN_SECONDS = 1800.0  # 30 minutes

# Mirrors the adapter's guard: a stored timestamp outside this range cannot
# describe an observed event and must not contribute to the span.
# Re-exported from the schema module, which owns the single definition.
# Kept as names here because existing tests and callers import them.
from app.schemas.events import (  # noqa: E402
    MAX_CLOCK_SKEW_SECONDS,
    MIN_PLAUSIBLE_YEAR,
)


class ReadinessState(str, Enum):
    """
    Where the data and models stand, in increasing order of readiness.

    The first state that applies is reported, so the operator is told the
    nearest blocking problem rather than the last one checked.
    """
    INSUFFICIENT_DATA = "insufficient_data"
    MISSING_OR_INVALID_LABELS = "missing_or_invalid_labels"
    INVALID_EVALUATION_CONDITIONS = "invalid_evaluation_conditions"
    INADEQUATE_CLASS_REPRESENTATION = "inadequate_class_representation"
    EVALUATED_PERFORMANCE_INADEQUATE = "evaluated_performance_inadequate"
    TRAINED_NOT_VALIDATED = "trained_not_validated"
    VALIDATED_WITH_DOCUMENTED_CONDITIONS = "validated_with_documented_conditions"


# Operations the gate governs.
OP_TRAIN = "train"
OP_PREDICT = "predict"


class Requirement(BaseModel):
    """One prerequisite, with the observed value against the needed one."""
    name: str
    satisfied: bool
    required: str
    observed: str
    detail: str = ""


class ReadinessReport(BaseModel):
    """Full assessment of whether forecasting may proceed."""
    state: ReadinessState
    can_train: bool
    can_serve_validated_forecast: bool
    summary: str
    requirements: list[Requirement] = Field(default_factory=list)
    unmet_requirements: list[str] = Field(default_factory=list)
    next_steps: list[str] = Field(default_factory=list)

    # Observed dataset facts
    total_events: int = 0
    implausible_timestamp_events: int = 0
    labelled_events: int = 0
    positive_events: int = 0
    negative_events: int = 0
    time_span_seconds: float = 0.0
    data_categories: dict[str, int] = Field(default_factory=dict)
    label_provenances: dict[str, int] = Field(default_factory=dict)

    # Labels that are not statements about what happened. A detector's
    # signature is its own opinion, a model prediction is an inference, and a
    # synthetic rule describes invented data. They are still labels and are
    # still counted, but a result computed over them is not evidence about
    # real incidents, so they are surfaced rather than silently pooled with
    # corpus ground truth.
    non_ground_truth_labelled_events: int = 0
    label_caveats: list[str] = Field(default_factory=list)

    # Target definition this assessment is made against
    prediction_target: str = ""
    prediction_horizon_seconds: float = 0.0
    observation_window_seconds: float = 0.0
    lead_time_seconds: float = 0.0

    evaluated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ForecastingBlocked(Exception):
    """Raised when a forecasting operation is refused by the gate."""

    def __init__(self, operation: str, report: ReadinessReport):
        self.operation = operation
        self.report = report
        super().__init__(
            f"Forecasting operation '{operation}' blocked: {report.summary}"
        )


TARGET_DESCRIPTION = (
    "Binary: will at least one event labelled as an attack be observed in the "
    "window [t + lead_time, t + lead_time + horizon], given only telemetry from "
    "[t - W, t]?"
)


def _is_attack_label(label: Optional[str]) -> bool:
    return bool(label) and label.strip().lower() not in ("benign", "normal", "unlabeled", "")


def assess_readiness(
    events: list[NormalizedEvent],
    observation_window_seconds: float = 60.0,
    lead_time_seconds: float = 30.0,
    prediction_horizon_seconds: float = 60.0,
    has_trained_model: bool = False,
    model_metrics_interpretable: bool = False,
    model_performance_adequate: Optional[bool] = None,
    dataset_event_count: Optional[int] = None,
    dataset_span_seconds: Optional[float] = None,
    dataset_label_counts: Optional[dict[str, int]] = None,
) -> ReadinessReport:
    """
    Assess whether the supplied telemetry can support honest forecasting.

    Crucially, unlabelled traffic is **not** counted as benign. Ordinary
    local connections carry no ground truth: treating them as confirmed
    negatives would manufacture a class balance that the evidence does not
    support and produce a model evaluated against an invented target.

    `events` may be a SAMPLE of a larger store. When it is, the caller
    passes `dataset_event_count` and `dataset_span_seconds` measured over
    the whole selection, and the sufficiency requirements use those rather
    than the sample's own extent (ADR-095). Without that, a dense corpus
    is judged on whatever slice the sample happened to cover: 50,000 events
    of CSE-CIC-IDS2018 span 104 seconds, so a 30-minute dataset was
    reported as "insufficient time span". Label and quality ratios are
    still read from the sample, which is what a sample can honestly give.
    """
    total = len(events)
    labelled = [e for e in events if e.label and e.label.strip()]
    positives = [e for e in labelled if _is_attack_label(e.label)]
    negatives = [e for e in labelled if not _is_attack_label(e.label)]

    # Implausible timestamps (notably the Windows FILETIME epoch, 1601) are
    # excluded from the span. One such record would otherwise report a span
    # of centuries and satisfy the duration requirement on nonsense.
    now = datetime.now(timezone.utc)
    plausible_times = sorted(
        e.observed_at for e in events if is_plausible_timestamp(e.observed_at, now)
    )
    implausible_count = total - len(plausible_times)
    sample_span = (
        (plausible_times[-1] - plausible_times[0]).total_seconds()
        if len(plausible_times) >= 2
        else 0.0
    )
    # Measured over the whole selection when the caller supplied it; the
    # sample's own extent otherwise.
    span = sample_span if dataset_span_seconds is None else float(dataset_span_seconds)
    counted = total if dataset_event_count is None else int(dataset_event_count)

    # Whether a corpus contains ANY positive is a property of the corpus.
    # A sample taken from one end of the capture cannot answer it: the
    # last 50,000 flows of a day whose attacks ran in the morning are all
    # benign, and reading "0 positive" from that refuses a dataset which
    # holds 52,498 of them (ADR-095).
    if dataset_label_counts is None:
        n_labelled, n_positive, n_negative = len(labelled), len(positives), len(negatives)
        counts_from_sample = True
    else:
        n_labelled = sum(c for lab, c in dataset_label_counts.items() if lab.strip())
        n_positive = sum(
            c for lab, c in dataset_label_counts.items() if _is_attack_label(lab)
        )
        n_negative = n_labelled - n_positive
        counts_from_sample = False

    def _observed(value: int, word: str) -> str:
        return f"{value} {word}" + ("" if counts_from_sample else " (whole dataset)")

    categories: dict[str, int] = {}
    provenances: dict[str, int] = {}
    for e in events:
        categories[e.data_category.value] = categories.get(e.data_category.value, 0) + 1
        provenances[e.label_provenance.value] = provenances.get(e.label_provenance.value, 0) + 1

    requirements = [
        Requirement(
            name="sufficient_events",
            satisfied=counted >= MIN_EVENTS_FOR_TRAINING,
            required=f">= {MIN_EVENTS_FOR_TRAINING} stored events",
            observed=(
                f"{counted} events"
                + (f" (label/quality read from a {total}-event sample)"
                   if counted != total else "")
            ),
            detail="Needed to produce enough temporal windows to train and evaluate separately.",
        ),
        Requirement(
            name="sufficient_time_span",
            satisfied=span >= MIN_TIME_SPAN_SECONDS,
            required=f">= {int(MIN_TIME_SPAN_SECONDS)}s of elapsed observation",
            observed=f"{int(span)}s",
            detail=(
                "Training must end before evaluation begins, with the contaminated "
                "boundary purged between them. A short span leaves no room for that."
                + (
                    f" {implausible_count} record(s) with implausible timestamps were "
                    "excluded from this measurement."
                    if implausible_count
                    else ""
                )
            ),
        ),
        Requirement(
            name="labels_present",
            satisfied=n_labelled >= MIN_LABELLED_EVENTS,
            required=f">= {MIN_LABELLED_EVENTS} labelled events",
            observed=_observed(n_labelled, "labelled"),
            detail=(
                "Supervised forecasting needs labels. Unlabelled traffic is not "
                "counted as benign: absence of a label is not evidence of safety. "
                "Labels that are a detector's or a model's output, or that were "
                "generated synthetically, are counted here but reported "
                "separately — they are not ground truth."
            ),
        ),
        Requirement(
            name="positive_examples",
            satisfied=n_positive >= MIN_POSITIVE_EVENTS,
            required=f">= {MIN_POSITIVE_EVENTS} events labelled as incidents",
            observed=_observed(n_positive, "positive"),
            detail="Without incident examples there is nothing to learn or measure.",
        ),
        Requirement(
            name="negative_examples",
            satisfied=n_negative >= MIN_NEGATIVE_EVENTS,
            required=f">= {MIN_NEGATIVE_EVENTS} events labelled benign",
            observed=_observed(n_negative, "negative"),
            detail="Confirmed-benign examples are needed to estimate false alarms.",
        ),
    ]

    unmet = [r.name for r in requirements if not r.satisfied]

    # ── Label-provenance caveats (reported, never silently blocking) ──
    NOT_GROUND_TRUTH = {
        LabelProvenance.DETECTOR_OUTPUT: (
            "{n} labelled event(s) carry a detector's signature as their label. "
            "That is the detector's opinion, not confirmation that an incident "
            "occurred. A model trained on these learns to predict that "
            "detector's alerts."
        ),
        LabelProvenance.MODEL_PREDICTION: (
            "{n} labelled event(s) are labelled by a model's own prediction. "
            "Training on these would evaluate a model against itself."
        ),
        LabelProvenance.SYNTHETIC_RULE: (
            "{n} labelled event(s) were generated synthetically. Results over "
            "them demonstrate that the pipeline runs; they are not evidence of "
            "real-world forecasting effectiveness."
        ),
    }
    label_caveats: list[str] = []
    non_ground_truth = 0
    for provenance, template in NOT_GROUND_TRUTH.items():
        count = sum(
            1 for e in labelled if e.label_provenance is provenance
        )
        if count:
            non_ground_truth += count
            label_caveats.append(template.format(n=count))

    # ── Determine state: report the nearest blocking cause ──
    if not requirements[0].satisfied or not requirements[1].satisfied:
        state = ReadinessState.INSUFFICIENT_DATA
        summary = (
            f"Insufficient data: {counted} events spanning {int(span)}s. "
            f"At least {MIN_EVENTS_FOR_TRAINING} events over "
            f"{int(MIN_TIME_SPAN_SECONDS)}s are required."
        )
        next_steps = [
            "Continue collecting telemetry, or import a historical dataset covering a longer period.",
        ]
    elif not requirements[2].satisfied:
        state = ReadinessState.MISSING_OR_INVALID_LABELS
        summary = (
            f"Only {len(labelled)} of {total} events carry a label. Locally "
            "observed traffic has no incident ground truth, and unlabelled "
            "traffic is not treated as benign."
        )
        next_steps = [
            "Import a labelled dataset, or supply analyst annotations for the observed period.",
            "Do not label ordinary traffic benign by assumption — that fabricates ground truth.",
        ]
    elif not requirements[3].satisfied or not requirements[4].satisfied:
        state = ReadinessState.INADEQUATE_CLASS_REPRESENTATION
        summary = (
            f"Inadequate class representation: {n_positive} incident and "
            f"{n_negative} benign labelled events. Both classes must be "
            "present in sufficient number."
        )
        next_steps = [
            f"Obtain at least {MIN_POSITIVE_EVENTS} labelled incident events and "
            f"{MIN_NEGATIVE_EVENTS} labelled benign events.",
            "Both classes must also occur in the earlier (training) and later (evaluation) periods.",
        ]
    elif has_trained_model and model_performance_adequate is False:
        state = ReadinessState.EVALUATED_PERFORMANCE_INADEQUATE
        summary = "A model was evaluated on a valid holdout but did not perform adequately."
        next_steps = ["Improve features or obtain more representative incident data."]
    elif has_trained_model and not model_metrics_interpretable:
        state = ReadinessState.TRAINED_NOT_VALIDATED
        summary = (
            "A model exists but its evaluation is not interpretable (for example "
            "the holdout contained no incident windows), so it is not validated."
        )
        next_steps = ["Evaluate against a holdout containing incident examples."]
    elif has_trained_model and model_metrics_interpretable:
        state = ReadinessState.VALIDATED_WITH_DOCUMENTED_CONDITIONS
        summary = "A model has been evaluated on a purged chronological holdout with both classes present."
        next_steps = []
    else:
        state = ReadinessState.INVALID_EVALUATION_CONDITIONS
        summary = (
            "Data prerequisites are met but no model has been trained and "
            "evaluated yet."
        )
        next_steps = ["Run training to produce an evaluated model."]

    data_ok = not unmet
    return ReadinessReport(
        state=state,
        # Training may be attempted once the data prerequisites hold. The
        # pipeline still refuses later if a leakage-free split cannot be built.
        can_train=data_ok,
        can_serve_validated_forecast=(
            state is ReadinessState.VALIDATED_WITH_DOCUMENTED_CONDITIONS
        ),
        summary=summary,
        requirements=requirements,
        unmet_requirements=unmet,
        next_steps=next_steps,
        total_events=total,
        implausible_timestamp_events=implausible_count,
        labelled_events=len(labelled),
        positive_events=len(positives),
        negative_events=len(negatives),
        time_span_seconds=round(span, 1),
        data_categories=categories,
        label_provenances=provenances,
        non_ground_truth_labelled_events=non_ground_truth,
        label_caveats=label_caveats,
        prediction_target=TARGET_DESCRIPTION,
        prediction_horizon_seconds=prediction_horizon_seconds,
        observation_window_seconds=observation_window_seconds,
        lead_time_seconds=lead_time_seconds,
    )


def enforce(operation: str, report: ReadinessReport) -> None:
    """
    Raise ForecastingBlocked unless the gate permits the operation.

    Called by the API before any training runs, so the control holds for
    direct API clients and not only for the dashboard.
    """
    if operation == OP_TRAIN and not report.can_train:
        raise ForecastingBlocked(operation, report)
    if operation == OP_PREDICT and not report.can_train:
        # Prediction from data that cannot support training would be an
        # unvalidated heuristic dressed as a forecast.
        raise ForecastingBlocked(operation, report)
