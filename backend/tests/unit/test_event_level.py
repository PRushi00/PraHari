"""
PraHari — Event-level warning evaluation (ADR-091).

The window-level metrics cannot answer blueprint §10's question. These
tests pin the behaviour that makes the event-level answer honest:

* one attack spanning many windows is ONE event, and a sustained alarm is
  ONE warning;
* the lead time is measured to the FIRST qualifying warning;
* an event the holdout could never have warned about is excluded, not
  counted as a miss;
* a warning issued too late, or during the event, is neither a detection
  nor a false alarm;
* with no documented event at all, the report refuses instead of scoring
  a perfect run over nothing.

Each test fixes the arithmetic by hand, so a change in the matching rules
breaks a test rather than silently moving a published number.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import numpy as np
import pytest

from app.research.event_level import (
    DEFAULT_THRESHOLD,
    MatchingRules,
    aggregate_warnings,
    build_documented_events,
    evaluate_event_level,
)
from app.schemas.events import (
    DataCategory,
    EventType,
    LabelProvenance,
    NormalizedEvent,
)

T0 = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)


def _event(offset_seconds: float, label: str | None = None, source: str = "src-a",
           provenance: LabelProvenance = LabelProvenance.DATASET_GROUND_TRUTH) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=f"e-{source}-{offset_seconds}",
        source_id=source,
        event_type=EventType.NETWORK_FLOW,
        observed_at=T0 + timedelta(seconds=offset_seconds),
        data_category=DataCategory.HISTORICAL_IMPORT,
        label=label,
        label_provenance=provenance if label else LabelProvenance.UNLABELED,
    )


def _times(offsets: list[float]) -> list[datetime]:
    return [T0 + timedelta(seconds=o) for o in offsets]


# ──────────────────────────────────────────────────────────────────
# Episode construction
# ──────────────────────────────────────────────────────────────────


def test_one_attack_across_many_records_is_one_event():
    """The defect window-level counting had: 40 records, 40 'events'."""
    events = [_event(o, "DDoS") for o in range(0, 400, 10)]
    documented = build_documented_events(events, episode_gap_seconds=300.0)

    assert len(documented) == 1
    assert documented[0].labelled_records == 40
    assert documented[0].started_at == T0
    assert documented[0].ended_at == T0 + timedelta(seconds=390)


def test_a_gap_beyond_the_threshold_separates_events():
    events = [_event(0, "PortScan"), _event(60, "PortScan"), _event(1000, "DDoS")]
    documented = build_documented_events(events, episode_gap_seconds=300.0)

    assert [d.labelled_records for d in documented] == [2, 1]
    assert documented[1].started_at == T0 + timedelta(seconds=1000)


def test_benign_records_never_open_an_event():
    events = [_event(0, "Benign"), _event(10, "normal"), _event(20, None), _event(30, "  ")]
    assert build_documented_events(events) == []


# ──────────────────────────────────────────────────────────────────
# Warning aggregation and suppression
# ──────────────────────────────────────────────────────────────────


def test_a_sustained_alarm_is_one_warning():
    times = _times([0, 30, 60, 90, 120])
    scores = np.array([0.9, 0.9, 0.9, 0.9, 0.9])

    issued = aggregate_warnings(times, scores, DEFAULT_THRESHOLD, suppression_seconds=60.0)

    assert len(issued) == 1
    assert issued[0].windows == 5
    assert issued[0].issued_at == T0
    assert issued[0].last_window_at == T0 + timedelta(seconds=120)


def test_a_quiet_interval_beyond_suppression_raises_a_second_warning():
    times = _times([0, 30, 600, 630])
    scores = np.array([0.9, 0.9, 0.9, 0.9])

    issued = aggregate_warnings(times, scores, DEFAULT_THRESHOLD, suppression_seconds=60.0)

    assert [w.windows for w in issued] == [2, 2]
    assert issued[1].issued_at == T0 + timedelta(seconds=600)


def test_windows_below_the_threshold_raise_nothing():
    times = _times([0, 30, 60])
    assert aggregate_warnings(times, np.array([0.1, 0.49, 0.0]), 0.5, 60.0) == []


def test_peak_score_is_the_highest_contributing_window():
    issued = aggregate_warnings(_times([0, 30]), np.array([0.6, 0.95]), 0.5, 60.0)
    assert issued[0].peak_score == pytest.approx(0.95)


# ──────────────────────────────────────────────────────────────────
# Matching and lead time
# ──────────────────────────────────────────────────────────────────


def test_lead_time_is_measured_to_the_first_qualifying_warning():
    """
    Event at t=600. L=30, H=120, so a warning qualifies when issued
    between 30s and 150s before the event: prediction times in [450, 570].

    Windows at 450 and 540 both qualify; the lead must come from 450 — the
    FIRST qualifying warning — giving 150s, not 60s.
    """
    events = [_event(o, "Benign") for o in range(0, 600, 60)]
    events += [_event(600 + o, "DDoS") for o in range(0, 120, 10)]

    times = _times([450, 540])
    scores = np.array([0.9, 0.9])

    report = evaluate_event_level(
        events, times, scores,
        lead_seconds=30.0, horizon_seconds=120.0,
        suppression_seconds=10.0,  # keep the two windows separate warnings
    )

    assert report.available
    assert report.events_total == 1
    assert report.events_warned == 1
    assert report.lead_time.count == 1
    assert report.lead_time.min_seconds == pytest.approx(150.0)
    assert report.events[0].detecting_warning_index == 0


def test_a_warning_outside_the_qualifying_interval_does_not_detect():
    """
    Too early is not a warning about this event. Event at t=600, qualifying
    interval [450, 570]; a warning at t=100 is a false alarm, and the event
    is missed.
    """
    events = [_event(o, "Benign") for o in range(0, 600, 60)]
    events += [_event(600, "DDoS")]

    report = evaluate_event_level(
        events, _times([100, 460]), np.array([0.9, 0.1]),
        lead_seconds=30.0, horizon_seconds=120.0,
    )

    assert report.events_total == 1
    assert report.events_missed == 1
    assert report.missed_event_rate == pytest.approx(1.0)
    assert report.false_alarms == 1
    assert report.lead_time.count == 0


def test_a_warning_during_the_event_is_late_not_a_detection():
    events = [_event(o, "Benign") for o in range(0, 600, 60)]
    events += [_event(600 + o, "DDoS") for o in range(0, 300, 30)]

    # The only window sits inside the event's span, and also inside the
    # holdout's reach for it, so the event is in scope and unwarned.
    report = evaluate_event_level(
        events, _times([460, 700]), np.array([0.1, 0.9]),
        lead_seconds=30.0, horizon_seconds=120.0,
    )

    assert report.events_total == 1
    assert report.events_warned == 0
    assert report.events_missed == 1
    assert report.late_warnings == 1
    assert report.false_alarms == 0
    assert report.detections == 0
    assert report.events[0].late_warning_indices == [0]


def test_one_warning_is_never_credited_to_two_events():
    """
    Two events whose qualifying intervals both contain the single warning.
    The earlier event claims it; the later is missed, not double-credited.
    """
    events = [_event(o, "Benign") for o in range(0, 600, 60)]
    events += [_event(600, "DDoS"), _event(660, "PortScan")]

    # episode_gap below 60 keeps them two distinct documented events.
    report = evaluate_event_level(
        events, _times([540]), np.array([0.95]),
        lead_seconds=30.0, horizon_seconds=120.0,
        episode_gap_seconds=30.0,
    )

    assert report.events_total == 2
    assert report.events_warned == 1
    assert report.events_missed == 1
    assert report.detections == 1
    assert report.events[0].warned is True
    assert report.events[1].warned is False


def test_an_event_the_holdout_could_not_reach_is_excluded_not_missed():
    """
    An event in the training period is not the holdout's failure. It must
    not appear in the denominator.
    """
    events = [_event(o, "Benign") for o in range(0, 2000, 60)]
    events += [_event(100, "DDoS")]           # long before the holdout
    events += [_event(1800, "PortScan")]      # within the holdout's reach

    report = evaluate_event_level(
        events, _times([1650, 1700, 1750]), np.array([0.1, 0.9, 0.1]),
        lead_seconds=30.0, horizon_seconds=120.0,
        episode_gap_seconds=30.0,
    )

    assert report.events_out_of_coverage == 1
    assert report.events_total == 1
    assert report.events_warned == 1
    excluded = [e for e in report.events if not e.in_coverage]
    assert len(excluded) == 1
    assert "qualifying interval" in excluded[0].out_of_coverage_reason


def test_false_alarms_are_reported_per_hour_over_the_evaluated_span():
    events = [_event(o, "Benign") for o in range(0, 7200, 60)]
    events += [_event(3600, "DDoS")]

    # The window at 3500 lies in the event's qualifying interval [3450, 3570],
    # so the event is in scope; it scores below the threshold, so the event is
    # missed. The windows at 100 and 5000 are two separated false alarms.
    report = evaluate_event_level(
        events, _times([100, 3500, 5000]), np.array([0.9, 0.1, 0.9]),
        lead_seconds=30.0, horizon_seconds=120.0,
        suppression_seconds=60.0,
    )

    assert report.events_total == 1
    assert report.events_missed == 1
    assert report.evaluated_span_seconds == pytest.approx(4900.0)
    assert report.false_alarms == 2
    assert report.false_alarms_per_hour == pytest.approx(2 / (4900 / 3600), rel=1e-3)


# ──────────────────────────────────────────────────────────────────
# Refusals
# ──────────────────────────────────────────────────────────────────


def test_no_documented_event_is_a_refusal_not_a_perfect_score():
    events = [_event(o, "Benign") for o in range(0, 600, 60)]

    report = evaluate_event_level(
        events, _times([100, 200]), np.array([0.1, 0.1]),
        lead_seconds=30.0, horizon_seconds=120.0,
    )

    assert report.available is False
    assert report.missed_event_rate is None
    assert "no documented event" in report.refusal_reason.lower()


def test_every_event_out_of_reach_is_a_refusal():
    events = [_event(o, "Benign") for o in range(0, 600, 60)]
    events += [_event(5000, "DDoS")]

    report = evaluate_event_level(
        events, _times([100, 200]), np.array([0.9, 0.1]),
        lead_seconds=30.0, horizon_seconds=120.0,
    )

    assert report.available is False
    assert report.events_out_of_coverage == 1
    assert "outside the evaluated holdout" in report.refusal_reason


def test_misaligned_times_and_scores_are_refused_not_trimmed():
    events = [_event(0, "DDoS")]
    report = evaluate_event_level(
        events, _times([0, 30, 60]), np.array([0.9, 0.9]),
        lead_seconds=30.0, horizon_seconds=120.0,
    )

    assert report.available is False
    assert "misalign" in report.refusal_reason


def test_empty_holdout_is_refused():
    report = evaluate_event_level(
        [_event(0, "DDoS")], [], np.array([]),
        lead_seconds=30.0, horizon_seconds=120.0,
    )
    assert report.available is False
    assert "no evaluated windows" in report.refusal_reason.lower()


# ──────────────────────────────────────────────────────────────────
# Honesty of the report itself
# ──────────────────────────────────────────────────────────────────


def test_quartiles_are_refused_below_four_warned_events():
    events = [_event(o, "Benign") for o in range(0, 600, 60)]
    events += [_event(600, "DDoS")]

    report = evaluate_event_level(
        events, _times([500]), np.array([0.9]),
        lead_seconds=30.0, horizon_seconds=120.0,
    )

    assert report.lead_time.count == 1
    assert report.lead_time.quartiles_available is False
    assert report.lead_time.p25_seconds is None
    assert "too few for quartiles" in report.lead_time.note


def test_synthetic_labels_are_declared_before_any_number():
    events = [_event(o, "Benign", provenance=LabelProvenance.SYNTHETIC_RULE)
              for o in range(0, 600, 60)]
    events += [_event(600, "DDoS", provenance=LabelProvenance.SYNTHETIC_RULE)]

    report = evaluate_event_level(
        events, _times([500]), np.array([0.9]),
        lead_seconds=30.0, horizon_seconds=120.0,
    )

    assert report.available
    assert "SYNTHETIC" in report.limitations[0]
    assert LabelProvenance.SYNTHETIC_RULE.value in report.label_provenance


def test_detector_output_is_declared_as_opinion_not_ground_truth():
    events = [_event(o, "Benign") for o in range(0, 600, 60)]
    events += [_event(600, "Suricata Alert", provenance=LabelProvenance.DETECTOR_OUTPUT)]

    report = evaluate_event_level(
        events, _times([500]), np.array([0.9]),
        lead_seconds=30.0, horizon_seconds=120.0,
    )

    assert "DETECTOR OUTPUT" in report.limitations[0]


def test_rules_are_fingerprinted_and_a_changed_rule_changes_the_hash():
    base = MatchingRules(
        episode_gap_seconds=300.0, min_lead_seconds=30.0,
        max_lead_seconds=150.0, suppression_seconds=300.0, threshold=0.5,
    )
    same = MatchingRules(
        episode_gap_seconds=300.0, min_lead_seconds=30.0,
        max_lead_seconds=150.0, suppression_seconds=300.0, threshold=0.5,
    )
    looser = MatchingRules(
        episode_gap_seconds=900.0, min_lead_seconds=30.0,
        max_lead_seconds=150.0, suppression_seconds=300.0, threshold=0.5,
    )

    assert base.fingerprint() == same.fingerprint()
    assert base.fingerprint() != looser.fingerprint()


def test_the_qualifying_interval_comes_from_the_target_not_a_free_parameter():
    """L and H decide matching, so it cannot be widened until results improve."""
    report = evaluate_event_level(
        [_event(0, "DDoS")], _times([0]), np.array([0.9]),
        lead_seconds=45.0, horizon_seconds=90.0,
    )
    assert report.rules.min_lead_seconds == pytest.approx(45.0)
    assert report.rules.max_lead_seconds == pytest.approx(135.0)


def test_a_permanently_active_alarm_is_not_flattered_by_suppression():
    """
    The case that forced `alarm_duty_cycle` into the report.

    A model that flags every window scores a perfect WINDOW recall. Under
    suppression its continuous alarm collapses to a single warning, so a
    reader looking only at the warning count would see "1 false alarm" and
    conclude it was quiet. It warned about nothing: the alarm began long
    before any qualifying interval and never said anything new.
    """
    events = [_event(o, "Benign") for o in range(0, 1200, 60)]
    events += [_event(1200 + o, "DDoS") for o in range(0, 60, 10)]

    times = _times(list(range(0, 1200, 15)))
    scores = np.full(len(times), 0.9)

    report = evaluate_event_level(
        events, times, scores,
        lead_seconds=30.0, horizon_seconds=120.0,
        suppression_seconds=300.0,
    )

    assert report.available
    assert report.alarm_duty_cycle == pytest.approx(1.0)
    assert report.warnings_issued == 1          # suppression did collapse it
    assert report.events_warned == 0            # and it warned of nothing
    assert report.events_missed == 1
    # The duty cycle must be declared before the count can be misread.
    assert any("duty cycle" in limitation for limitation in report.limitations)


def test_a_quiet_model_reports_a_low_duty_cycle():
    """The contrast that makes the duty cycle readable."""
    events = [_event(o, "Benign") for o in range(0, 1200, 60)]
    events += [_event(1200, "DDoS")]

    times = _times(list(range(0, 1200, 15)))
    scores = np.full(len(times), 0.1)
    scores[times.index(T0 + timedelta(seconds=1080))] = 0.9  # one qualifying window

    report = evaluate_event_level(
        events, times, scores,
        lead_seconds=30.0, horizon_seconds=120.0,
    )

    assert report.alarm_duty_cycle == pytest.approx(1 / len(times), rel=1e-3)
    assert report.events_warned == 1
    assert report.lead_time.min_seconds == pytest.approx(120.0)
    assert not any("duty cycle" in l for l in report.limitations)
