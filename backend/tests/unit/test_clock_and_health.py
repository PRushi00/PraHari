"""
Clock-integrity and source-health diagnostics.

Both modules exist to report what the stored evidence supports, so most of
these tests assert a *refusal* to claim more than that:

* a positive ingest lag must never be reported as clock skew, because it
  contains delay this system does not measure;
* a negative lag yields a lower bound, never a point estimate;
* silence must never be reported as disconnection;
* a source whose newest event is in the future gets no freshness verdict
  at all.

Documentation addresses only (RFC 5737).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.schemas.events import (
    DataCategory,
    EventType,
    LabelProvenance,
    NormalizedEvent,
    QualityFlag,
    TelemetrySource,
)
from app.services.clock_integrity import (
    MIN_SAMPLES_FOR_VERDICT,
    LagReference,
    NEGATIVE_LAG_EVIDENCE_SECONDS,
    ClockVerdict,
    analyze_clock_integrity,
    analyze_per_source,
)
from app.services.source_health import (
    DEFAULT_FRESH_SECONDS,
    DEFAULT_STALE_SECONDS,
    HealthState,
    evaluate_source_health,
    summarize_source_health,
)

NOW = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)


def _event(idx, observed_offset, lag_seconds=1.0, source="sensor-a", flags=None,
           measured_receipt=True):
    """
    An event whose lag is exactly `lag_seconds`.

    `measured_receipt=True` sets `received_at` — a receipt captured at the
    API boundary, the only reference against which a clock bound may be
    asserted. With it False the event carries `ingested_at` only, as a
    locally collected or imported record does.
    """
    observed = NOW + timedelta(seconds=observed_offset)
    reference = observed + timedelta(seconds=lag_seconds)
    return NormalizedEvent(
        event_id=f"{source}-{idx}",
        source_id=source,
        data_category=DataCategory.LIVE_TELEMETRY,
        observed_at=observed,
        ingested_at=reference,
        received_at=reference if measured_receipt else None,
        event_type=EventType.CONNECTION,
        src_ip="192.0.2.10",
        dst_ip="198.51.100.20",
        src_port=40000 + idx,
        dst_port=443,
        protocol="TCP",
        label_provenance=LabelProvenance.UNLABELED,
        quality_flags=flags or [],
    )


def _source(**kw):
    defaults = dict(
        source_id="sensor-a", name="Sensor A",
        source_type="windows_connection_table", enabled=True,
        status="active", event_count=100,
        last_event_at=NOW - timedelta(seconds=10),
    )
    defaults.update(kw)
    return TelemetrySource(**defaults)


# ──────────────────────────────────────────────────────────────────
# Clock integrity — what it refuses to claim
# ──────────────────────────────────────────────────────────────────


def test_a_positive_lag_is_never_reported_as_skew():
    """
    The central guarantee. A consistent 30-second lag could be a 30-second
    clock offset, 30 seconds of batching, or any mix. The module must not
    pick one.
    """
    events = [_event(i, i, lag_seconds=30.0) for i in range(100)]
    report = analyze_clock_integrity(events, source_id="sensor-a", now=NOW + timedelta(hours=1))

    assert report.verdict is ClockVerdict.NO_ANOMALY_DETECTED
    assert report.lag_median_seconds == 30.0
    assert report.clock_ahead_lower_bound_seconds is None, (
        "a positive lag supports no skew claim whatsoever"
    )
    assert report.has_clock_evidence is False
    joined = " ".join(report.limitations).lower()
    assert "collection, transport, queueing" in joined
    assert any("does not establish" in n.lower() for n in report.notes)


def test_a_negative_lag_yields_a_lower_bound_not_an_estimate():
    """
    Delay cannot be negative, so an event ingested 45s before its stated
    observation time proves the source clock leads by AT LEAST 45s.
    """
    events = [_event(i, i, lag_seconds=-45.0) for i in range(60)]
    report = analyze_clock_integrity(events, source_id="sensor-a", now=NOW + timedelta(hours=1))

    assert report.verdict is ClockVerdict.SOURCE_CLOCK_AHEAD
    assert report.clock_ahead_lower_bound_seconds == 45.0
    assert report.negative_lag_beyond_threshold == 60
    assert any("at least" in n for n in report.notes)
    assert any("may be larger; it cannot be smaller" in n for n in report.notes)


def test_the_bound_uses_the_most_extreme_negative_lag():
    events = [_event(i, i, lag_seconds=-10.0) for i in range(50)]
    events.append(_event(99, 99, lag_seconds=-120.0))
    report = analyze_clock_integrity(events, now=NOW + timedelta(hours=1))

    assert report.clock_ahead_lower_bound_seconds == 120.0


def test_sub_threshold_negative_lag_is_counted_but_not_a_verdict():
    """Rounding and scheduling can produce a fraction of a second."""
    events = [_event(i, i, lag_seconds=-0.5) for i in range(60)]
    report = analyze_clock_integrity(events, now=NOW + timedelta(hours=1))

    assert report.negative_lag_count == 60
    assert report.negative_lag_beyond_threshold == 0
    assert report.verdict is not ClockVerdict.SOURCE_CLOCK_AHEAD
    # The bound is still reported — it is true regardless of the threshold.
    assert report.clock_ahead_lower_bound_seconds == 0.5
    assert report.negative_lag_threshold_seconds == NEGATIVE_LAG_EVIDENCE_SECONDS


def test_too_few_samples_yields_insufficient_evidence():
    events = [_event(i, i, lag_seconds=-45.0) for i in range(MIN_SAMPLES_FOR_VERDICT - 1)]
    report = analyze_clock_integrity(events, now=NOW + timedelta(hours=1))

    assert report.verdict is ClockVerdict.INSUFFICIENT_EVIDENCE
    assert report.usable_samples == MIN_SAMPLES_FOR_VERDICT - 1
    # Statistics are still reported; only the verdict is withheld.
    assert report.lag_min_seconds == -45.0


def test_no_events_is_insufficient_evidence_not_a_clean_bill():
    report = analyze_clock_integrity([], source_id="sensor-a")
    assert report.verdict is ClockVerdict.INSUFFICIENT_EVIDENCE
    assert report.usable_samples == 0
    assert report.lag_median_seconds is None


def test_implausible_timestamps_are_excluded_and_counted():
    """One FILETIME record would otherwise dominate every percentile."""
    events = [_event(i, i, lag_seconds=2.0) for i in range(50)]
    poisoned = _event(999, 0, lag_seconds=2.0)
    poisoned.observed_at = datetime(1601, 1, 1, tzinfo=timezone.utc)
    events.append(poisoned)

    report = analyze_clock_integrity(events, now=NOW + timedelta(hours=1))

    assert report.events_examined == 51
    assert report.usable_samples == 50
    assert report.events_with_implausible_timestamps == 1
    assert report.interval_start.year >= 2000


def test_entirely_unusable_timestamps_are_reported_as_such():
    events = []
    for i in range(40):
        e = _event(i, i)
        e.observed_at = datetime(1601, 1, 1, tzinfo=timezone.utc)
        events.append(e)

    report = analyze_clock_integrity(events, now=NOW + timedelta(hours=1))
    assert report.verdict is ClockVerdict.UNUSABLE_TIMESTAMPS
    assert report.lag_median_seconds is None


def test_timezone_uncertainty_is_surfaced_as_a_limitation():
    events = [
        _event(i, i, lag_seconds=2.0, flags=[QualityFlag.TIMESTAMP_UNCERTAINTY])
        for i in range(40)
    ]
    report = analyze_clock_integrity(events, now=NOW + timedelta(hours=1))

    assert report.events_with_timestamp_uncertainty_flag == 40
    assert any("whole hours" in lim for lim in report.limitations)


def _arrival_sequence(observed_offsets):
    """Events whose ARRIVAL order is the list order, ingest 1s apart."""
    out = []
    for i, observed_offset in enumerate(observed_offsets):
        event = _event(i, observed_offset)
        event.ingested_at = NOW + timedelta(seconds=10_000 + i)
        out.append(event)
    return out


def test_backward_ordering_is_detected_without_attributing_a_cause():
    """
    An event that ARRIVED later while claiming an earlier observation time.
    """
    offsets = [i * 10 for i in range(60)]
    offsets[30] = -500  # arrives 31st, claims a much earlier time
    report = analyze_clock_integrity(
        _arrival_sequence(offsets), now=NOW + timedelta(hours=4)
    )

    assert report.out_of_order_events >= 1
    assert report.largest_backward_step_seconds > 0
    assert report.verdict is ClockVerdict.ORDERING_ANOMALY
    assert any("cannot distinguish them" in n for n in report.notes)


def test_retrieval_order_does_not_create_phantom_ordering_anomalies():
    """
    Regression for a defect found by driving the endpoint, not by a unit
    test: `Database.list_events` returns `ORDER BY observed_at DESC`, and
    the check originally walked the supplied order, so every well-behaved
    source was reported as a continuous backward march.

    Ordering is assessed by arrival (ingested_at), so the order in which a
    caller hands events over is irrelevant.
    """
    ascending = _arrival_sequence([i * 10 for i in range(60)])
    descending = list(reversed(ascending))

    a = analyze_clock_integrity(ascending, now=NOW + timedelta(hours=4))
    b = analyze_clock_integrity(descending, now=NOW + timedelta(hours=4))

    assert a.out_of_order_events == 0
    assert b.out_of_order_events == 0, "retrieval order must not fabricate anomalies"
    assert a.verdict is b.verdict is ClockVerdict.NO_ANOMALY_DETECTED


def test_a_bulk_insert_sharing_an_ingest_time_is_not_an_ordering_anomaly():
    """Within one batch there is no arrival order to violate."""
    events = []
    shared = NOW + timedelta(seconds=10_000)
    for i, offset in enumerate(reversed(range(60))):
        event = _event(i, offset * 10)
        event.ingested_at = shared
        events.append(event)

    report = analyze_clock_integrity(events, now=NOW + timedelta(hours=4))
    assert report.out_of_order_events == 0


def test_interval_covered_is_reported():
    events = [_event(i, i * 60, lag_seconds=1.0) for i in range(40)]
    report = analyze_clock_integrity(events, now=NOW + timedelta(days=1))

    assert report.interval_start == NOW
    assert report.interval_end == NOW + timedelta(seconds=39 * 60)
    assert report.interval_seconds == pytest.approx(39 * 60)


def test_per_source_grouping_is_independent():
    events = (
        [_event(i, i, lag_seconds=2.0, source="good") for i in range(40)]
        + [_event(i, i, lag_seconds=-60.0, source="fast-clock") for i in range(40)]
    )
    reports = analyze_per_source(events, now=NOW + timedelta(hours=1))

    assert set(reports) == {"good", "fast-clock"}
    assert reports["good"].verdict is ClockVerdict.NO_ANOMALY_DETECTED
    assert reports["fast-clock"].verdict is ClockVerdict.SOURCE_CLOCK_AHEAD
    assert reports["good"].clock_ahead_lower_bound_seconds is None


def test_the_diagnostic_mutates_nothing():
    events = [_event(i, i, lag_seconds=-30.0) for i in range(40)]
    before = [(e.observed_at, e.ingested_at) for e in events]

    analyze_clock_integrity(events, now=NOW + timedelta(hours=1))

    assert [(e.observed_at, e.ingested_at) for e in events] == before


# ──────────────────────────────────────────────────────────────────
# Source health — states and boundaries
# ──────────────────────────────────────────────────────────────────


def test_a_recent_event_is_reporting():
    health = evaluate_source_health(_source(last_event_at=NOW - timedelta(seconds=10)), now=NOW)
    assert health.state is HealthState.REPORTING
    assert health.is_reporting is True
    assert health.seconds_since_last_event == 10.0


@pytest.mark.parametrize(
    "age,expected",
    [
        (DEFAULT_FRESH_SECONDS - 1, HealthState.REPORTING),
        (DEFAULT_FRESH_SECONDS, HealthState.REPORTING),       # inclusive boundary
        (DEFAULT_FRESH_SECONDS + 1, HealthState.STALE),
        (DEFAULT_STALE_SECONDS, HealthState.STALE),           # inclusive boundary
        (DEFAULT_STALE_SECONDS + 1, HealthState.SILENT),
    ],
)
def test_threshold_boundaries_are_inclusive_at_the_lower_edge(age, expected):
    health = evaluate_source_health(
        _source(last_event_at=NOW - timedelta(seconds=age)), now=NOW
    )
    assert health.state is expected


def test_silence_is_never_reported_as_disconnection():
    health = evaluate_source_health(
        _source(last_event_at=NOW - timedelta(days=7)), now=NOW
    )
    assert health.state is HealthState.SILENT
    joined = " ".join(health.reasons + health.limitations).lower()
    assert "whether it is running is unknown" in joined
    assert "down" not in joined.replace("shutdown", "")


def test_a_never_seen_source_is_distinct_from_a_silent_one():
    health = evaluate_source_health(_source(last_event_at=None, event_count=0), now=NOW)
    assert health.state is HealthState.NEVER_SEEN
    assert health.state is not HealthState.SILENT
    assert any("not the same as silent" in r for r in health.reasons)


def test_inconsistent_counters_yield_unknown_rather_than_a_guess():
    """event_count > 0 with no last_event_at means the record is unreliable."""
    health = evaluate_source_health(_source(last_event_at=None, event_count=42), now=NOW)
    assert health.state is HealthState.UNKNOWN
    assert any("inconsistent" in r for r in health.reasons)


def test_a_disabled_source_is_not_judged_on_freshness():
    health = evaluate_source_health(
        _source(enabled=False, last_event_at=NOW - timedelta(days=30)), now=NOW
    )
    assert health.state is HealthState.DISABLED
    assert "no telemetry is expected" in " ".join(health.reasons)


def test_a_recorded_error_outranks_apparent_freshness():
    """A source can fail immediately after its last successful event."""
    health = evaluate_source_health(
        _source(status="error", last_event_at=NOW - timedelta(seconds=1)), now=NOW
    )
    assert health.state is HealthState.ERROR


def test_a_future_last_event_gives_no_freshness_verdict():
    """
    The source's newest event is ahead of this host's clock. Delay cannot
    be negative, so this is clock evidence, not freshness evidence.
    """
    health = evaluate_source_health(
        _source(last_event_at=NOW + timedelta(seconds=600)), now=NOW
    )
    assert health.state is HealthState.UNKNOWN
    assert any("future" in r for r in health.reasons)
    assert any("clock leads ours" in r for r in health.reasons)


def test_an_implausible_last_event_yields_unknown():
    health = evaluate_source_health(
        _source(last_event_at=datetime(1601, 1, 1, tzinfo=timezone.utc)), now=NOW
    )
    assert health.state is HealthState.UNKNOWN


def test_health_states_declare_their_clock_dependence():
    health = evaluate_source_health(_source(), now=NOW)
    assert health.clock_dependent is True
    assert "event time" in health.freshness_basis
    assert any("clock" in lim for lim in health.limitations)


def test_inverted_thresholds_are_rejected():
    with pytest.raises(ValueError):
        evaluate_source_health(_source(), now=NOW, fresh_seconds=100, stale_seconds=10)


def test_summary_counts_every_state():
    sources = [
        _source(source_id="fresh", last_event_at=NOW - timedelta(seconds=5)),
        _source(source_id="stale", last_event_at=NOW - timedelta(seconds=600)),
        _source(source_id="silent", last_event_at=NOW - timedelta(days=3)),
        _source(source_id="never", last_event_at=None, event_count=0),
        _source(source_id="off", enabled=False),
        _source(source_id="broken", status="error"),
    ]
    summary = summarize_source_health(sources, now=NOW)

    assert summary.counts_by_state == {
        "reporting": 1, "stale": 1, "silent": 1,
        "never_seen": 1, "disabled": 1, "error": 1,
    }
    assert [h.source_id for h in summary.sources] == sorted(s.source_id for s in sources)
    assert any("no heartbeat" in n.lower() for n in summary.notes)


def test_evaluation_does_not_mutate_the_source_record():
    source = _source()
    snapshot = source.model_dump()
    evaluate_source_health(source, now=NOW)
    assert source.model_dump() == snapshot


# ──────────────────────────────────────────────────────────────────
# Phase 2 — receipt time versus construction time
# ──────────────────────────────────────────────────────────────────


def test_a_measured_receipt_is_the_reference_when_present():
    events = [_event(i, i, lag_seconds=5.0) for i in range(40)]
    report = analyze_clock_integrity(events, now=NOW + timedelta(hours=1))

    assert report.lag_reference is LagReference.RECEIVED_AT
    assert report.samples_with_received_at == 40
    assert report.samples_without_received_at == 0


def test_without_a_receipt_the_reference_is_construction_time():
    events = [
        _event(i, i, lag_seconds=5.0, measured_receipt=False) for i in range(40)
    ]
    report = analyze_clock_integrity(events, now=NOW + timedelta(hours=1))

    assert report.lag_reference is LagReference.INGESTED_AT
    assert report.samples_without_received_at == 40
    assert any("object construction, not arrival" in lim for lim in report.limitations)


def test_no_clock_bound_is_claimed_without_a_measured_receipt():
    """
    The bound rests on transit time >= 0, which holds for a receipt at the
    API boundary. It does NOT hold for construction time: an imported
    corpus is routinely normalized at a time unrelated to its event times,
    and a backdated corpus produces a negative lag that means nothing about
    any clock.
    """
    events = [
        _event(i, i, lag_seconds=-300.0, measured_receipt=False) for i in range(60)
    ]
    report = analyze_clock_integrity(events, now=NOW + timedelta(hours=1))

    assert report.lag_min_seconds == -300.0
    assert report.clock_ahead_lower_bound_seconds is None
    assert report.verdict is not ClockVerdict.SOURCE_CLOCK_AHEAD
    assert any("No clock bound is claimed" in n for n in report.notes)


def test_a_historical_import_does_not_fabricate_a_clock_conclusion():
    """A corpus from 2018 normalized today: a huge positive lag, no meaning."""
    events = []
    for i in range(50):
        observed = datetime(2018, 2, 14, 10, 0, 0, tzinfo=timezone.utc) + timedelta(seconds=i)
        events.append(
            NormalizedEvent(
                event_id=f"hist-{i}", source_id="corpus",
                data_category=DataCategory.HISTORICAL_IMPORT,
                observed_at=observed, ingested_at=NOW, received_at=None,
                event_type=EventType.NETWORK_FLOW,
                src_ip="192.0.2.10", dst_ip="198.51.100.20",
                src_port=40000 + i, dst_port=443, protocol="TCP",
                label_provenance=LabelProvenance.DATASET_GROUND_TRUTH,
            )
        )
    report = analyze_clock_integrity(events, source_id="corpus", now=NOW)

    assert report.lag_reference is LagReference.INGESTED_AT
    assert report.lag_median_seconds > 200_000_000  # years, as expected
    assert report.clock_ahead_lower_bound_seconds is None
    assert report.verdict is not ClockVerdict.SOURCE_CLOCK_AHEAD


def test_mixed_references_are_reported_as_mixed():
    events = (
        [_event(i, i, lag_seconds=2.0) for i in range(30)]
        + [_event(100 + i, i, lag_seconds=2.0, measured_receipt=False) for i in range(30)]
    )
    report = analyze_clock_integrity(events, now=NOW + timedelta(hours=1))

    assert report.lag_reference is LagReference.MIXED
    assert report.samples_with_received_at == 30
    assert report.samples_without_received_at == 30
    assert report.clock_ahead_lower_bound_seconds is None


def test_a_delayed_live_event_yields_a_positive_lag_and_no_skew_claim():
    events = [_event(i, i, lag_seconds=120.0) for i in range(40)]
    report = analyze_clock_integrity(events, now=NOW + timedelta(hours=1))

    assert report.lag_reference is LagReference.RECEIVED_AT
    assert report.lag_median_seconds == 120.0
    assert report.clock_ahead_lower_bound_seconds is None
    assert report.verdict is ClockVerdict.NO_ANOMALY_DETECTED


def test_a_future_event_timestamp_against_a_measured_receipt_bounds_the_clock():
    """Received before it supposedly happened: transit cannot be negative."""
    events = [_event(i, i, lag_seconds=-600.0) for i in range(40)]
    report = analyze_clock_integrity(events, now=NOW + timedelta(hours=1))

    assert report.verdict is ClockVerdict.SOURCE_CLOCK_AHEAD
    assert report.clock_ahead_lower_bound_seconds == 600.0
