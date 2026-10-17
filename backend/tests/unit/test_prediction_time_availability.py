"""
PraHari — Late Events Are Not Available to Earlier Forecasts (ADR-069).

Blueprint section 6: "A late event may update a historical record, but it
must not be retroactively treated as information available to an earlier
forecast."

Before this, the feature extractor selected each observation window by
`observed_at` alone and never read `received_at`. A live event observed at
t-5s but received at t+300s was therefore counted in the features of the
forecast made at t - information the system could not have held at the
moment it claimed to predict. That is leakage, and it flatters any model
evaluated on stream-ingested telemetry.

The tests compare three datasets that differ only in one event:
  A - the event is present but ARRIVED LATE
  B - the event is absent
  C - the event is present and arrived ON TIME
For every forecast made before the late arrival, A must be identical to B
(the event was invisible) and C must differ (an on-time event counts).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import numpy as np
import pytest

from app.models.feature_extractor import FEATURE_NAMES, WindowFeatureExtractor
from app.schemas.events import (
    DataCategory,
    EventType,
    LabelProvenance,
    NormalizedEvent,
)

T0 = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
LATE_OBSERVED = 500        # seconds after T0
LATE_RECEIVED = 800        # 300 s after it was observed
FLOW_COUNT = FEATURE_NAMES.index("flow_count")


def _ev(i: int, sec: float, *, label="benign", received=None,
        category=DataCategory.LIVE_TELEMETRY, port=443) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=f"e-{i}",
        source_id="avail",
        data_category=category,
        observed_at=T0 + timedelta(seconds=sec),
        received_at=received,
        event_type=EventType.NETWORK_FLOW,
        src_ip="192.0.2.10",
        dst_ip="198.51.100.20",
        src_port=40000 + (i % 20000),
        dst_port=port,
        protocol="TCP",
        label=label,
        label_provenance=LabelProvenance.TEST_FIXTURE
        if hasattr(LabelProvenance, "TEST_FIXTURE") else LabelProvenance.SYNTHETIC_RULE,
    )


def _base(category=DataCategory.LIVE_TELEMETRY, receipt_delay=1.0, import_time=None):
    events = []
    for i, sec in enumerate(range(0, 1800, 2)):
        label = "attack" if 900 <= sec < 910 else "benign"
        if import_time is not None:
            received = import_time
        else:
            received = T0 + timedelta(seconds=sec + receipt_delay)
        events.append(_ev(i, sec, label=label, received=received, category=category))
    return events


def _late_event(received_sec: float, category=DataCategory.LIVE_TELEMETRY, received=None):
    return _ev(
        99_999, LATE_OBSERVED, port=9999, category=category,
        received=received if received is not None else T0 + timedelta(seconds=received_sec),
    )


def _build(events):
    extractor = WindowFeatureExtractor(
        window_size_seconds=60, lead_time_seconds=30, prediction_horizon_seconds=60,
    )
    X, y, ts = extractor.build_dataset_instances(events, step_seconds=15)
    return X, y, ts, extractor.last_windowing_report


def _affected(ts) -> list[int]:
    """Windows whose observation interval contains the late event's time,
    and whose prediction time precedes its arrival."""
    observed = T0 + timedelta(seconds=LATE_OBSERVED)
    received = T0 + timedelta(seconds=LATE_RECEIVED)
    return [
        k for k, t in enumerate(ts)
        if t - timedelta(seconds=60) <= observed < t and t < received
    ]


# ──────────────────────────────────────────────────────────────────
# The rule itself
# ──────────────────────────────────────────────────────────────────


def test_a_live_event_received_after_the_prediction_time_is_unavailable():
    e = _late_event(LATE_RECEIVED)
    assert not WindowFeatureExtractor.arrived_by(e, T0 + timedelta(seconds=LATE_OBSERVED + 30))


def test_a_live_event_received_by_the_prediction_time_is_available():
    e = _late_event(LATE_RECEIVED)
    assert WindowFeatureExtractor.arrived_by(e, T0 + timedelta(seconds=LATE_RECEIVED))


def test_a_live_event_with_no_receipt_time_is_treated_as_available():
    """No evidence of lateness: the local collector does not stamp receipt."""
    e = _ev(1, LATE_OBSERVED, received=None)
    assert WindowFeatureExtractor.arrived_by(e, T0 + timedelta(seconds=LATE_OBSERVED + 1))


def test_an_imported_events_receipt_time_is_not_treated_as_arrival():
    """
    For a historical import `received_at` is when the FILE was imported.
    Treating it as arrival would make every window empty.
    """
    imported = T0 + timedelta(days=365)
    e = _late_event(0, category=DataCategory.HISTORICAL_IMPORT, received=imported)
    assert WindowFeatureExtractor.arrived_by(e, T0 + timedelta(seconds=LATE_OBSERVED + 1))


# ──────────────────────────────────────────────────────────────────
# End to end through window construction
# ──────────────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def three_datasets():
    a = _build(_base() + [_late_event(LATE_RECEIVED)])       # present, late
    b = _build(_base())                                        # absent
    c = _build(_base() + [_late_event(LATE_OBSERVED + 1)])    # present, on time
    return a, b, c


def test_the_three_datasets_share_one_window_grid(three_datasets):
    (_, _, ts_a, _), (_, _, ts_b, _), (_, _, ts_c, _) = three_datasets
    assert ts_a == ts_b == ts_c
    assert _affected(ts_a), "the fixture must place forecasts before the late arrival"


def test_a_late_event_is_invisible_to_every_earlier_forecast(three_datasets):
    (X_a, y_a, ts, _), (X_b, y_b, _, _), _ = three_datasets

    for k in _affected(ts):
        assert np.array_equal(X_a[k], X_b[k]), (
            f"the forecast at {ts[k].isoformat()} used an event that arrived later"
        )
    assert np.array_equal(y_a, y_b), "availability changes features, never labels"


def test_an_on_time_event_is_counted_so_the_test_can_fail(three_datasets):
    """Guards the test above against passing vacuously."""
    _, (X_b, _, ts, _), (X_c, _, _, _) = three_datasets

    for k in _affected(ts):
        assert X_c[k][FLOW_COUNT] == X_b[k][FLOW_COUNT] + 1


def test_late_exclusions_are_reported_not_silent(three_datasets):
    (_, _, ts, report_a), (_, _, _, report_b), (_, _, _, report_c) = three_datasets

    n = len(_affected(ts))
    assert report_a.late_arrival_exclusions == n
    assert report_a.windows_with_late_arrivals == n
    assert report_b.late_arrival_exclusions == 0
    assert report_c.late_arrival_exclusions == 0


def test_a_historical_import_is_never_affected():
    imported = T0 + timedelta(days=365)
    events = _base(category=DataCategory.HISTORICAL_IMPORT, import_time=imported)
    events.append(_late_event(0, category=DataCategory.HISTORICAL_IMPORT, received=imported))

    X, _, ts, report = _build(events)
    X_b, _, _, _ = _build(_base(category=DataCategory.HISTORICAL_IMPORT, import_time=imported))

    assert report.late_arrival_exclusions == 0
    for k in _affected(ts):
        assert X[k][FLOW_COUNT] == X_b[k][FLOW_COUNT] + 1, (
            "an imported event is available at its own event time"
        )
