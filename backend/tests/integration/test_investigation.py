"""
PraHari — Drilling from a warning to its evidence (§11, ADR-109).

§11 asks for a drill-down from a warning to "its input window,
contributing features, source references and related events". These pin
the properties that make such a view trustworthy rather than decorative:

* a model whose holdout has no comparable feature rows gets NO
  contributions and a reason — never an attribution against the wrong
  feature names;
* the attribution ships with what it is not, because `value x global
  importance` is easy to read as a local explanation and is not one;
* source counts are computed over the WHOLE window, so a truncated view
  cannot misreport who contributed;
* an unknown warning index is refused.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import numpy as np
import pytest

from app.models.feature_extractor import FEATURE_NAMES
from app.research.investigation import (
    MAX_WINDOW_EVENTS,
    investigate_warning,
)
from app.schemas.events import (
    DataCategory,
    EventType,
    LabelProvenance,
    NormalizedEvent,
)

T0 = datetime(2026, 10, 21, 12, 0, tzinfo=timezone.utc)


class _Warning:
    """The shape `IssuedWarning` presents to this function."""

    def __init__(self, index: int, issued: datetime, last: datetime):
        self.warning_index = index
        self.issued_at = issued
        self.last_window_at = last
        self.windows = 3
        self.peak_score = 0.91
        self.outcome = "detection"
        self.matched_event_index = 0
        self.lead_time_seconds = 45.0


def _event(i: int, at: datetime, source: str = "host-a") -> NormalizedEvent:
    return NormalizedEvent(
        event_id=f"evt-{source}-{i:05d}",
        source_id=source,
        observed_at=at,
        event_type=EventType.CONNECTION,
        data_category=DataCategory.LIVE_TELEMETRY,
        schema_version="1.0.0",
        label_provenance=LabelProvenance.UNLABELED,
    )


@pytest.fixture()
def scenario():
    warning = _Warning(0, T0 + timedelta(seconds=120), T0 + timedelta(seconds=180))
    events = []
    # Well before (outside the related window), related-before, in-window,
    # related-after.
    events += [_event(i, T0 - timedelta(seconds=900 + i)) for i in range(3)]
    events += [_event(100 + i, T0 + timedelta(seconds=i)) for i in range(5)]
    events += [
        _event(200 + i, T0 + timedelta(seconds=60 + i * 10), "host-a")
        for i in range(8)
    ]
    events += [
        _event(300 + i, T0 + timedelta(seconds=130 + i * 5), "host-b")
        for i in range(4)
    ]
    events += [_event(400 + i, T0 + timedelta(seconds=200 + i)) for i in range(6)]
    times = [T0 + timedelta(seconds=150)]
    features = np.array([[float(i + 1) for i in range(len(FEATURE_NAMES))]])
    return warning, events, times, features


# ──────────────────────────────────────────────────────────────────
# Refusals
# ──────────────────────────────────────────────────────────────────


def test_an_unknown_warning_index_is_refused(scenario):
    warning, events, times, features = scenario

    report = investigate_warning(
        warning_index=7,
        warnings=[warning],
        events=events,
        model_id="random_forest_forecaster",
        prediction_times=times,
        features=features,
    )

    assert report.available is False
    assert "No warning with index 7" in report.refusal_reason


def test_a_model_without_comparable_features_gets_no_contributions(scenario):
    """
    Persistence takes an attack indicator, the temporal stack is
    lag-stacked, the LSTM is three-dimensional. Attributing any of those
    to FEATURE_NAMES would name the wrong things.
    """
    warning, events, times, _ = scenario

    report = investigate_warning(
        warning_index=0,
        warnings=[warning],
        events=events,
        model_id="lstm_forecaster",
        prediction_times=times,
        features=None,
    )

    assert report.available is True
    assert report.contributions == []
    assert report.contributions_available is False
    assert "not one window's canonical feature vector" in (
        report.contributions_unavailable_reason
    )


# ──────────────────────────────────────────────────────────────────
# The four things §11 asks for
# ──────────────────────────────────────────────────────────────────


def test_the_input_window_holds_the_events_the_model_saw(scenario):
    warning, events, times, features = scenario

    report = investigate_warning(
        warning_index=0,
        warnings=[warning],
        events=events,
        model_id="random_forest_forecaster",
        prediction_times=times,
        features=features,
        observation_window_seconds=60.0,
    )

    # Window runs from issued_at - 60s (= T0+60) to last_window_at (T0+180).
    assert report.window_event_count == 12
    for e in report.window_events:
        assert T0 + timedelta(seconds=60) <= e.observed_at <= T0 + timedelta(seconds=180)


def test_source_references_are_counted_over_the_whole_window(scenario):
    warning, events, times, features = scenario

    report = investigate_warning(
        warning_index=0,
        warnings=[warning],
        events=events,
        model_id="random_forest_forecaster",
        prediction_times=times,
        features=features,
    )

    by_id = {s.source_id: s for s in report.sources}
    assert set(by_id) == {"host-a", "host-b"}
    assert by_id["host-a"].events_in_window == 8
    assert by_id["host-b"].events_in_window == 4
    assert sum(s.events_in_window for s in report.sources) == report.window_event_count


def test_source_counts_survive_truncation(scenario):
    """
    A truncated view must not misreport who contributed: the counts are
    over the whole window, not the shown subset.
    """
    warning, _, times, features = scenario
    many = [
        _event(i, T0 + timedelta(seconds=60, milliseconds=i), "host-a")
        for i in range(MAX_WINDOW_EVENTS + 40)
    ]

    report = investigate_warning(
        warning_index=0,
        warnings=[warning],
        events=many,
        model_id="random_forest_forecaster",
        prediction_times=times,
        features=features,
    )

    assert report.window_truncated is True
    assert report.window_events_shown == MAX_WINDOW_EVENTS
    assert report.window_event_count == MAX_WINDOW_EVENTS + 40
    assert report.sources[0].events_in_window == MAX_WINDOW_EVENTS + 40


def test_related_events_either_side_are_separated(scenario):
    warning, events, times, features = scenario

    report = investigate_warning(
        warning_index=0,
        warnings=[warning],
        events=events,
        model_id="random_forest_forecaster",
        prediction_times=times,
        features=features,
    )

    assert report.related_before, "activity before the window must be visible"
    assert report.related_after, "activity after the window must be visible"
    assert all(e.observed_at < T0 + timedelta(seconds=60) for e in report.related_before)
    assert all(e.observed_at > T0 + timedelta(seconds=180) for e in report.related_after)


def test_contributions_are_ranked_and_use_the_live_paths_formula(scenario):
    warning, events, times, features = scenario
    importances = {FEATURE_NAMES[0]: 0.5, FEATURE_NAMES[1]: 0.1}

    report = investigate_warning(
        warning_index=0,
        warnings=[warning],
        events=events,
        model_id="random_forest_forecaster",
        prediction_times=times,
        features=features,
        importances=importances,
    )

    assert report.contributions_available is True
    assert len(report.contributions) == len(FEATURE_NAMES)
    # value x importance, ranked by impact.
    impacts = [c.impact for c in report.contributions]
    assert impacts == sorted(impacts, reverse=True)
    first = next(c for c in report.contributions if c.feature == FEATURE_NAMES[0])
    assert first.value == 1.0
    assert first.importance_weight == 0.5
    assert first.impact == 0.5
    # A feature with no published importance falls back to the live
    # path's 0.08, so the two never disagree.
    unlisted = next(c for c in report.contributions if c.feature == FEATURE_NAMES[2])
    assert unlisted.importance_weight == 0.08


# ──────────────────────────────────────────────────────────────────
# The attribution says what it is not
# ──────────────────────────────────────────────────────────────────


def test_the_attribution_carries_its_limitations(scenario):
    """
    `value x global importance` reads as a local explanation and is not
    one. Shipping the number without that is the misleading part.
    """
    warning, events, times, features = scenario

    report = investigate_warning(
        warning_index=0,
        warnings=[warning],
        events=events,
        model_id="random_forest_forecaster",
        prediction_times=times,
        features=features,
    )

    assert "global" in report.attribution_method.lower()
    joined = " ".join(report.attribution_limitations).lower()
    assert "not a local explanation" in joined
    assert "shap" in joined
    assert "do not sum to the score" in joined
