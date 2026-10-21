"""
PraHari — Probability calibration, measured as a reliability curve
(blueprint §10, ADR-107).

§10 requires calibration among the reported measurements. Only a Brier
score existed. A Brier score is a single number that mixes calibration
with discrimination: a model can improve it by becoming sharper while
staying badly calibrated, and it cannot answer the question an operator
actually has — *when this model says 0.8, does the thing happen about
80 % of the time?*

A reliability curve answers that directly: predicted probability against
observed frequency, per bin, with the count each bin rests on.

Why the counts travel with every bin
------------------------------------
An observed frequency computed from three windows is noise with a
decimal point. This project has twice been misled by a statistic whose
sample size was not in view — window recall 1.000 on a single-class
holdout (ADR-091) and PR-AUC 0.9925 measuring attack continuation
(ADR-096) — so every bin carries `count`, bins below
`MIN_BIN_FOR_FREQUENCY` are marked `frequency_reliable: False`, and the
summary error is reported twice: over all bins, and over only the
reliable ones.

Nothing is smoothed, interpolated or dropped to make the curve look
continuous. An empty bin is reported as empty with a count of zero,
because "the model never predicted in this range" is a finding about the
model, not a hole to fill.

What it refuses
---------------
* A holdout with one class. Observed frequency is then 0 or 1 in every
  populated bin regardless of the probabilities, so the curve describes
  the holdout, not the model. This is the ADR-091 refusal applied to
  calibration.
* Fewer than `MIN_SAMPLES` scored windows in total.
* Probabilities outside [0, 1], which mean the caller passed scores
  rather than probabilities and every number here would be meaningless.

Expected Calibration Error is count-weighted, which is the usual
definition and is stated in the report rather than assumed, because an
unweighted mean over bins lets a three-sample bin outvote a
three-hundred-sample one.
"""

from __future__ import annotations

import math
from typing import Optional, Sequence

from pydantic import BaseModel, Field

# A frequency below this many samples is reported, but not trusted. Four
# is the same floor `event_level.py` uses before it will quote quartiles.
MIN_BIN_FOR_FREQUENCY = 4

# Below this, no curve is produced at all: ten bins over a handful of
# windows is a list of individual predictions wearing a histogram's name.
MIN_SAMPLES = 20

DEFAULT_BINS = 10


class CalibrationBin(BaseModel):
    """One probability range, and what actually happened inside it."""

    lower: float
    upper: float
    count: int = 0
    mean_predicted: Optional[float] = None
    observed_frequency: Optional[float] = None
    # Signed, so over- and under-confidence are distinguishable rather
    # than collapsed into a magnitude.
    gap: Optional[float] = None
    frequency_reliable: bool = False
    note: str = ""


class CalibrationReport(BaseModel):
    """A reliability curve under one explicit binning."""

    available: bool = False
    refusal_reason: Optional[str] = None
    model_id: Optional[str] = None

    n_samples: int = 0
    n_positive: int = 0
    n_bins: int = DEFAULT_BINS
    bins: list[CalibrationBin] = Field(default_factory=list)

    # Summary errors. Both are reported because they answer different
    # questions and can disagree sharply.
    expected_calibration_error: Optional[float] = None
    expected_calibration_error_reliable_bins_only: Optional[float] = None
    max_calibration_error: Optional[float] = None
    brier_score: Optional[float] = None

    reliable_bins: int = 0
    populated_bins: int = 0
    samples_in_reliable_bins: int = 0

    method: str = ""
    limitations: list[str] = Field(default_factory=list)


def _brier(probabilities: Sequence[float], outcomes: Sequence[int]) -> float:
    n = len(outcomes)
    return sum((p - y) ** 2 for p, y in zip(probabilities, outcomes)) / n


def measure_calibration(
    probabilities: Sequence[float],
    outcomes: Sequence[int],
    *,
    model_id: Optional[str] = None,
    n_bins: int = DEFAULT_BINS,
) -> CalibrationReport:
    """
    Build a reliability curve, or refuse and say why.

    `probabilities` are predicted probabilities of the positive class and
    `outcomes` the realised binary labels, aligned element-wise.
    """
    report = CalibrationReport(model_id=model_id, n_bins=n_bins)
    report.method = (
        f"Equal-width binning into {n_bins} bins over [0, 1]. Each bin "
        "reports its own sample count; a bin with fewer than "
        f"{MIN_BIN_FOR_FREQUENCY} samples is marked frequency_reliable: "
        "false rather than dropped or smoothed. Expected calibration "
        "error is count-weighted."
    )

    if len(probabilities) != len(outcomes):
        report.refusal_reason = (
            f"{len(probabilities)} probabilities against {len(outcomes)} "
            "outcomes: they must be aligned element-wise."
        )
        return report

    n = len(outcomes)
    report.n_samples = n
    if n < MIN_SAMPLES:
        report.refusal_reason = (
            f"{n} scored windows is below the {MIN_SAMPLES} required for a "
            f"{n_bins}-bin curve. Fewer samples than this makes each bin a "
            "list of individual predictions rather than a frequency."
        )
        return report

    for p in probabilities:
        if not (0.0 <= float(p) <= 1.0) or math.isnan(float(p)):
            report.refusal_reason = (
                f"Predicted value {p} is not a probability in [0, 1]. "
                "Calibration compares probabilities with frequencies; a "
                "decision score cannot be compared with one."
            )
            return report

    report.n_positive = int(sum(1 for y in outcomes if y))
    if report.n_positive == 0 or report.n_positive == n:
        only = "positive" if report.n_positive == n else "negative"
        report.refusal_reason = (
            f"The holdout is single-class ({only} only, {n} windows). "
            "Observed frequency would be 0 or 1 in every populated bin "
            "whatever the model predicted, so the curve would describe "
            "the holdout rather than the model."
        )
        return report

    edges = [i / n_bins for i in range(n_bins + 1)]
    buckets: list[list[tuple[float, int]]] = [[] for _ in range(n_bins)]
    for p, y in zip(probabilities, outcomes):
        p = float(p)
        # The top edge belongs to the last bin; otherwise a prediction of
        # exactly 1.0 would fall outside every bucket.
        idx = min(n_bins - 1, int(p * n_bins))
        buckets[idx].append((p, int(bool(y))))

    weighted_error = 0.0
    weighted_error_reliable = 0.0
    reliable_samples = 0
    max_error = 0.0

    for i, bucket in enumerate(buckets):
        b = CalibrationBin(lower=round(edges[i], 6), upper=round(edges[i + 1], 6))
        b.count = len(bucket)
        if not bucket:
            b.note = (
                "The model never predicted in this range. Empty, not "
                "missing — this is a fact about the model."
            )
            report.bins.append(b)
            continue

        report.populated_bins += 1
        mean_p = sum(p for p, _ in bucket) / len(bucket)
        freq = sum(y for _, y in bucket) / len(bucket)
        b.mean_predicted = round(mean_p, 6)
        b.observed_frequency = round(freq, 6)
        b.gap = round(freq - mean_p, 6)
        b.frequency_reliable = len(bucket) >= MIN_BIN_FOR_FREQUENCY
        if not b.frequency_reliable:
            b.note = (
                f"{len(bucket)} sample(s): the frequency is reported but "
                "carries no useful precision."
            )

        err = abs(freq - mean_p)
        weighted_error += err * len(bucket)
        max_error = max(max_error, err)
        if b.frequency_reliable:
            report.reliable_bins += 1
            reliable_samples += len(bucket)
            weighted_error_reliable += err * len(bucket)

        report.bins.append(b)

    report.samples_in_reliable_bins = reliable_samples
    report.expected_calibration_error = round(weighted_error / n, 6)
    report.expected_calibration_error_reliable_bins_only = (
        round(weighted_error_reliable / reliable_samples, 6)
        if reliable_samples
        else None
    )
    report.max_calibration_error = round(max_error, 6)
    report.brier_score = round(_brier(probabilities, outcomes), 6)
    report.available = True

    report.limitations = [
        "Equal-width bins. A model whose predictions cluster in one range "
        "leaves most bins empty, which is visible in the counts and is a "
        "fact about the model, not a defect in the measurement.",
        "Calibration is measured on the holdout the model was evaluated "
        "on. It says nothing about calibration on data from another "
        "period, deployment or dataset.",
        "A well-calibrated model can still be useless: calibration is "
        "independent of discrimination. Read it beside PR-AUC and the "
        "event-level report, never instead of them.",
    ]
    if report.reliable_bins < report.populated_bins:
        report.limitations.append(
            f"{report.populated_bins - report.reliable_bins} of "
            f"{report.populated_bins} populated bins hold fewer than "
            f"{MIN_BIN_FOR_FREQUENCY} samples. The curve through those "
            "points is not evidence."
        )
    return report
