"""
PraHari — Calibration is a curve with its sample sizes in view (ADR-107).

§10 requires calibration. Only a Brier score existed, which mixes
calibration with discrimination and cannot answer the operator's actual
question: when this model says 0.8, does the thing happen about 80 % of
the time?

These pin the honesty properties rather than the arithmetic, because the
arithmetic is easy and the ways a reliability curve misleads are not:

* a single-class holdout is REFUSED, not scored — the ADR-091 refusal
  applied to calibration, since observed frequency would be 0 or 1 in
  every bin whatever the model predicted;
* every bin carries its count, and a bin below four samples is marked
  unreliable rather than dropped or smoothed;
* an empty bin is reported as empty, because "the model never predicted
  in this range" is a finding;
* the error is reported twice — over all bins and over reliable bins
  only — because those can disagree sharply, and one number would hide
  which;
* a decision score is refused, since comparing it with a frequency is
  meaningless.
"""

from __future__ import annotations

import pytest

from app.research.calibration import (
    MIN_BIN_FOR_FREQUENCY,
    MIN_SAMPLES,
    measure_calibration,
)


def _perfectly_calibrated(per_bin: int = 100) -> tuple[list[float], list[int]]:
    """
    Ten bins; in the bin centred on p, exactly p of the samples are
    positive. A correct implementation must report ~0 error.
    """
    probs: list[float] = []
    outs: list[int] = []
    for b in range(10):
        p = (b + 0.5) / 10
        positives = round(p * per_bin)
        probs.extend([p] * per_bin)
        outs.extend([1] * positives + [0] * (per_bin - positives))
    return probs, outs


# ──────────────────────────────────────────────────────────────────
# Refusals
# ──────────────────────────────────────────────────────────────────


def test_a_single_class_holdout_is_refused():
    """
    ADR-091's refusal, applied to calibration. With only negatives the
    observed frequency is 0 in every populated bin regardless of the
    probabilities, so the curve describes the holdout.
    """
    report = measure_calibration([0.1, 0.5, 0.9] * 20, [0] * 60)

    assert report.available is False
    assert "single-class" in report.refusal_reason
    assert report.expected_calibration_error is None


def test_an_all_positive_holdout_is_refused_too():
    report = measure_calibration([0.1, 0.5, 0.9] * 20, [1] * 60)

    assert report.available is False
    assert "positive only" in report.refusal_reason


def test_too_few_samples_is_refused():
    report = measure_calibration([0.5] * (MIN_SAMPLES - 1), [0, 1] * 9 + [1])

    assert report.available is False
    assert str(MIN_SAMPLES) in report.refusal_reason


def test_a_decision_score_is_refused():
    """
    A score outside [0, 1] means the caller passed decision values. A
    frequency cannot be compared with one.
    """
    probs, outs = _perfectly_calibrated(per_bin=5)
    probs[0] = 4.2

    report = measure_calibration(probs, outs)
    assert report.available is False
    assert "not a probability" in report.refusal_reason


def test_misaligned_inputs_are_refused():
    report = measure_calibration([0.5] * 30, [0, 1] * 10)

    assert report.available is False
    assert "aligned element-wise" in report.refusal_reason


# ──────────────────────────────────────────────────────────────────
# The measurement itself
# ──────────────────────────────────────────────────────────────────


def test_a_perfectly_calibrated_model_reports_near_zero_error():
    probs, outs = _perfectly_calibrated()

    report = measure_calibration(probs, outs, model_id="synthetic")
    assert report.available is True
    assert report.expected_calibration_error < 0.01
    assert report.max_calibration_error < 0.02
    assert report.populated_bins == 10
    assert report.reliable_bins == 10


def test_an_overconfident_model_is_caught_with_a_signed_gap():
    """
    Predicts 0.9 but is right half the time. The gap must be negative —
    over- and under-confidence have to stay distinguishable.
    """
    probs = [0.9] * 100
    outs = [1] * 50 + [0] * 50

    report = measure_calibration(probs, outs)
    assert report.available is True
    top = [b for b in report.bins if b.count][0]
    assert top.mean_predicted == pytest.approx(0.9)
    assert top.observed_frequency == pytest.approx(0.5)
    assert top.gap == pytest.approx(-0.4)
    assert report.expected_calibration_error == pytest.approx(0.4, abs=1e-6)


def test_an_underconfident_model_reports_a_positive_gap():
    probs = [0.1] * 100
    outs = [1] * 60 + [0] * 40

    report = measure_calibration(probs, outs)
    bin_ = [b for b in report.bins if b.count][0]
    assert bin_.gap == pytest.approx(0.5)


# ──────────────────────────────────────────────────────────────────
# Sample sizes stay in view
# ──────────────────────────────────────────────────────────────────


def test_a_thin_bin_is_marked_unreliable_rather_than_dropped():
    """
    An observed frequency from three windows is noise with a decimal
    point. It is reported — dropping it would hide that the model
    predicted there — but never as evidence.
    """
    probs = [0.05] * 40 + [0.95] * (MIN_BIN_FOR_FREQUENCY - 1)
    outs = [0] * 40 + [1] * (MIN_BIN_FOR_FREQUENCY - 1)

    report = measure_calibration(probs, outs)
    assert report.available is True

    thin = [b for b in report.bins if 0 < b.count < MIN_BIN_FOR_FREQUENCY]
    assert thin, "the thin bin must still appear"
    assert all(b.frequency_reliable is False for b in thin)
    assert all(b.observed_frequency is not None for b in thin)
    assert any("no useful precision" in b.note for b in thin)


def test_the_error_is_reported_over_all_bins_and_over_reliable_bins_only():
    """
    These disagree whenever a thin bin is badly calibrated, and a single
    number would hide which population it described.
    """
    # 40 well-calibrated samples (0.05 predicted, 2/40 = 0.05 observed),
    # plus 3 wildly wrong ones. Both classes present, or the report
    # correctly refuses before measuring anything.
    probs = [0.05] * 40 + [0.95] * 3
    outs = [1] * 2 + [0] * 38 + [0] * 3

    report = measure_calibration(probs, outs)
    assert report.expected_calibration_error is not None
    assert report.expected_calibration_error_reliable_bins_only is not None
    assert (
        report.expected_calibration_error
        > report.expected_calibration_error_reliable_bins_only
    )
    assert report.samples_in_reliable_bins == 40


def test_an_empty_bin_is_reported_as_empty():
    probs = [0.05] * 60
    outs = ([0] * 50) + ([1] * 10)

    report = measure_calibration(probs, outs)
    empty = [b for b in report.bins if b.count == 0]
    assert len(empty) == 9
    assert all(b.observed_frequency is None for b in empty)
    assert all(b.mean_predicted is None for b in empty)
    assert all("never predicted" in b.note for b in empty)


def test_the_error_is_count_weighted_not_a_mean_over_bins():
    """
    An unweighted mean over bins lets a 1-sample bin outvote a
    300-sample one. 300 perfect samples plus 1 wrong one must report an
    error near zero.
    """
    # 0.05 predicted with 15/300 = 0.05 observed: error ~0 on 300
    # samples. One sample at 0.95 that does not happen: error 0.95.
    probs = [0.05] * 300 + [0.95]
    outs = [1] * 15 + [0] * 285 + [0]

    report = measure_calibration(probs, outs)
    # Count-weighted: ~(0.0*300 + 0.95*1) / 301 = 0.003
    assert report.expected_calibration_error < 0.01
    # An unweighted mean over the two populated bins would be ~0.475,
    # so this is the assertion that distinguishes the two definitions.
    assert report.expected_calibration_error < 0.1


def test_a_probability_of_exactly_one_lands_in_the_last_bin():
    """Off-by-one at the top edge would silently drop the most
    confident predictions from the curve."""
    probs = [1.0] * 30 + [0.05] * 30
    outs = [1] * 30 + [0] * 30

    report = measure_calibration(probs, outs)
    assert report.available is True
    assert sum(b.count for b in report.bins) == 60
    assert report.bins[-1].count == 30


def test_every_sample_is_accounted_for_in_some_bin():
    probs, outs = _perfectly_calibrated(per_bin=37)

    report = measure_calibration(probs, outs)
    assert sum(b.count for b in report.bins) == len(outs) == report.n_samples


def test_the_method_and_limitations_travel_with_the_report():
    probs, outs = _perfectly_calibrated(per_bin=25)

    report = measure_calibration(probs, outs)
    assert "count-weighted" in report.method
    assert str(MIN_BIN_FOR_FREQUENCY) in report.method
    # A reader must be told calibration is not discrimination.
    assert any("discrimination" in lim for lim in report.limitations)
