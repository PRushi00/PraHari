"""
Measurement integrity: timestamps, denominators and mixed populations.

Reproduced in a browser against the real dataset: the Analytics page showed
an observation window starting 1/1/1601 and the Feasibility page scored
"Temporal Monotonicity & Ordering" at 100% PASSED over a span of
13,436,268,232 seconds — about 425 years — while the readiness gate, over
the very same dataset, correctly reported 65,260 seconds.

Three modules implemented the same timestamp policy independently. Two did
it right and one had never implemented it at all.

Documentation addresses only (RFC 5737).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.research.feasibility import audit_dataset_feasibility
from app.research.readiness import assess_readiness
from app.schemas.events import (
    DataCategory,
    EventType,
    LabelProvenance,
    NormalizedEvent,
    is_plausible_timestamp,
)
from app.services.analysis import compute_descriptive_analysis

NOW = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def _event(idx: int, when: datetime, label=None, duration=None, pkts=None, byts=None):
    return NormalizedEvent(
        event_id=f"e{idx}",
        source_id="s",
        data_category=DataCategory.LIVE_TELEMETRY,
        observed_at=when,
        event_type=EventType.CONNECTION,
        src_ip="192.0.2.10",
        dst_ip="198.51.100.20",
        src_port=40000 + idx,
        dst_port=443,
        protocol="TCP",
        duration=duration,
        packets=pkts,
        bytes_total=byts,
        label=label,
        label_provenance=(
            LabelProvenance.DATASET_GROUND_TRUTH if label else LabelProvenance.UNLABELED
        ),
    )


# ──────────────────────────────────────────────────────────────────
# One policy, one definition
# ──────────────────────────────────────────────────────────────────


def test_filetime_epoch_is_not_a_plausible_timestamp():
    assert is_plausible_timestamp(FILETIME_EPOCH, now=NOW) is False
    assert is_plausible_timestamp(datetime(1999, 12, 31, tzinfo=timezone.utc), now=NOW) is False
    assert is_plausible_timestamp(NOW, now=NOW) is True
    assert is_plausible_timestamp(None) is False


def test_far_future_is_rejected_but_small_skew_is_tolerated():
    assert is_plausible_timestamp(NOW + timedelta(minutes=30), now=NOW) is True
    assert is_plausible_timestamp(NOW + timedelta(hours=5), now=NOW) is False


def test_naive_datetimes_are_read_as_utc():
    assert is_plausible_timestamp(datetime(2026, 6, 1, 12, 0, 0), now=NOW) is True


# ──────────────────────────────────────────────────────────────────
# The three modules must now agree
# ──────────────────────────────────────────────────────────────────


@pytest.fixture
def poisoned():
    """One FILETIME record among otherwise sane telemetry."""
    events = [_event(i, NOW + timedelta(seconds=60 * i)) for i in range(60)]
    events.append(_event(999, FILETIME_EPOCH))
    return events


def test_analysis_excludes_the_implausible_timestamp_from_its_range(poisoned):
    analysis = compute_descriptive_analysis(poisoned, source_id="s")

    assert analysis.total_events == 61
    assert analysis.implausible_timestamp_events == 1
    assert analysis.time_range_start.year >= 2000, (
        "the 1601 record must not define the observation window"
    )
    span = (analysis.time_range_end - analysis.time_range_start).total_seconds()
    assert span < 86_400, f"span of {span}s implies the epoch record leaked back in"


def test_feasibility_refuses_to_pass_temporal_integrity_with_a_broken_clock(poisoned):
    report = audit_dataset_feasibility(poisoned, dataset_id="poisoned")
    temporal = [c for c in report.checks if "Temporal" in c.check_name][0]

    assert temporal.passed is False, (
        "a dataset with a broken time axis scored 100% temporal integrity"
    )
    assert "implausible" in temporal.details.lower()
    assert report.metrics["implausible_timestamp_events"] == 1
    assert report.metrics["time_span_seconds"] < 86_400


def test_all_three_modules_report_a_consistent_span(poisoned):
    """
    The original defect was not a wrong number, it was three numbers. The
    readiness gate said hours while the feasibility audit said centuries.
    """
    analysis = compute_descriptive_analysis(poisoned, source_id="s")
    feasibility = audit_dataset_feasibility(poisoned, dataset_id="x")
    readiness = assess_readiness(poisoned)

    analysis_span = (
        analysis.time_range_end - analysis.time_range_start
    ).total_seconds()
    feasibility_span = feasibility.metrics["time_span_seconds"]

    assert abs(analysis_span - feasibility_span) < 1.0
    assert abs(analysis_span - readiness.time_span_seconds) < 1.0


def test_a_clean_dataset_still_passes_temporal_integrity():
    clean = [_event(i, NOW + timedelta(seconds=60 * i)) for i in range(60)]
    temporal = [
        c for c in audit_dataset_feasibility(clean, dataset_id="clean").checks
        if "Temporal" in c.check_name
    ][0]
    assert temporal.passed is True
    assert "implausible" not in temporal.details.lower()


# ──────────────────────────────────────────────────────────────────
# Averages need their denominator
# ──────────────────────────────────────────────────────────────────


def test_averages_publish_how_many_records_they_were_computed_over():
    """
    On this host 3,469 of 3,669 records come from a source that cannot
    measure bytes at all. An "average bytes" with no denominator reads as a
    property of the dataset when it describes 5% of it.
    """
    measured = [
        _event(i, NOW + timedelta(seconds=i), duration=1.0, pkts=10, byts=1000)
        for i in range(10)
    ]
    unmeasured = [_event(100 + i, NOW + timedelta(seconds=i)) for i in range(90)]

    analysis = compute_descriptive_analysis(measured + unmeasured, source_id="s")

    assert analysis.total_events == 100
    assert analysis.duration_measured_count == 10
    assert analysis.packets_measured_count == 10
    assert analysis.bytes_measured_count == 10
    assert analysis.avg_bytes == 1000, "the average is over the 10 that measured it"
    assert analysis.duration_measured_count != analysis.total_events


def test_a_source_that_measures_nothing_reports_zero_not_a_fabricated_average():
    analysis = compute_descriptive_analysis(
        [_event(i, NOW + timedelta(seconds=i)) for i in range(20)], source_id="s"
    )
    assert analysis.avg_bytes is None
    assert analysis.avg_packets is None
    assert analysis.avg_duration is None
    assert analysis.bytes_measured_count == 0


# ──────────────────────────────────────────────────────────────────
# Class balance is a property of the labelled population
# ──────────────────────────────────────────────────────────────────


def test_attack_ratio_is_over_labelled_events_not_every_event():
    """
    Dividing 50 attack labels by 3,669 total events gave "1.4% attack" for a
    dataset whose labelled part is 25% attacks. The fraction mixed two
    populations and understated the imbalance.
    """
    labelled = (
        [_event(i, NOW + timedelta(seconds=i), label="Benign") for i in range(150)]
        + [_event(200 + i, NOW + timedelta(seconds=200 + i), label="DDoS") for i in range(50)]
    )
    unlabelled = [_event(500 + i, NOW + timedelta(seconds=500 + i)) for i in range(800)]

    report = audit_dataset_feasibility(labelled + unlabelled, dataset_id="mixed")

    assert report.metrics["attack_count"] == 50
    assert report.metrics["benign_count"] == 150
    assert report.metrics["labelled_events"] == 200
    assert report.metrics["unlabelled_events"] == 800
    assert report.metrics["attack_ratio"] == pytest.approx(0.25, abs=0.01)

    label_check = [c for c in report.checks if "Label" in c.check_name][0]
    assert "200 labelled" in label_check.details
    assert "carry no label" in label_check.details
