"""
PraHari — Drilling from a warning to its evidence (blueprint §11, ADR-109).

§11 lists an Investigation view: a drill-down "from a warning to its input
window, contributing features, source references and related events".
Feature contributions existed on the Forecast page for a *live* prediction;
the drill-down from a *recorded* warning did not, because nothing tied a
warning back to the window that produced it.

This builds that link from what the evaluation already holds: the
event-level report's `IssuedWarning` gives a window range, the holdout
gives the scores and (for models whose input is a window feature vector)
the feature rows, and the event store gives the records inside the range.

The four things §11 asks for, and what each rests on
----------------------------------------------------
* **Input window** — the events actually stored between the warning's
  first and last window, read from the store at investigation time.
* **Contributing features** — `value x global importance`, the SAME
  attribution the live prediction path uses. Reusing it is deliberate:
  two different numbers for one concept would be worse than one crude
  number. What it is NOT is stated in the response, because it is easy to
  read as a local explanation and it is not one (see below).
* **Source references** — which sources contributed records, with counts,
  since a window spanning two hosts is a different thing to investigate
  than one host's traffic.
* **Related events** — records immediately before and after the window,
  so an analyst can see whether the activity began earlier.

Why the attribution carries a health warning
--------------------------------------------
`value x global importance` multiplies a window's feature value by the
model's importance **over the whole training set**. That is not a local
explanation: a feature with high global importance sitting at its
baseline in this window contributes nothing locally, yet this product
still reports it as large. A real local attribution needs SHAP or
permutation on the row, which would be a new dependency and a new claim.
So the number is shipped with `attribution_method` and
`attribution_limitations` saying exactly that, rather than being dressed
up as an explanation.

What it refuses
---------------
* A model whose holdout carries no comparable feature rows — persistence
  takes an indicator, the temporal stack is lag-stacked and the LSTM is
  three-dimensional. Contributions are reported absent with the reason,
  never computed against mismatched names.
* A warning index that does not exist in the report.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Optional, Sequence

import numpy as np
from pydantic import BaseModel, Field

from app.models.feature_extractor import FEATURE_NAMES
from app.schemas.events import NormalizedEvent

# How far either side of the window to look for related activity. One
# window's width would hide a slow build-up; an hour would bury it.
RELATED_WINDOW_SECONDS = 300.0

# A drill-down is for reading, not for bulk export.
MAX_WINDOW_EVENTS = 200
MAX_RELATED_EVENTS = 50


class FeatureContribution(BaseModel):
    feature: str
    value: float
    importance_weight: float
    impact: float


class SourceReference(BaseModel):
    source_id: str
    events_in_window: int
    first_at: Optional[datetime] = None
    last_at: Optional[datetime] = None


class WarningInvestigation(BaseModel):
    """One warning, and the evidence behind it."""

    available: bool = False
    refusal_reason: Optional[str] = None

    model_id: Optional[str] = None
    warning_index: int = 0
    outcome: str = ""
    issued_at: Optional[datetime] = None
    last_window_at: Optional[datetime] = None
    windows: int = 0
    peak_score: Optional[float] = None
    matched_event_index: Optional[int] = None
    lead_time_seconds: Optional[float] = None

    # Input window
    window_event_count: int = 0
    window_events_shown: int = 0
    window_events: list[NormalizedEvent] = Field(default_factory=list)
    window_truncated: bool = False

    # Contributing features
    contributions: list[FeatureContribution] = Field(default_factory=list)
    contributions_available: bool = False
    contributions_unavailable_reason: Optional[str] = None
    attribution_method: str = ""
    attribution_limitations: list[str] = Field(default_factory=list)

    # Source references
    sources: list[SourceReference] = Field(default_factory=list)

    # Related events
    related_before: list[NormalizedEvent] = Field(default_factory=list)
    related_after: list[NormalizedEvent] = Field(default_factory=list)
    related_window_seconds: float = RELATED_WINDOW_SECONDS

    notes: list[str] = Field(default_factory=list)


ATTRIBUTION_METHOD = (
    "feature value x the model's GLOBAL feature importance, the same "
    "attribution the live prediction path uses."
)

ATTRIBUTION_LIMITATIONS = [
    "This is not a local explanation. The importance is computed over the "
    "whole training set, so a feature sitting at its baseline in this "
    "window still scores highly if it matters globally.",
    "The products are comparable with each other within one window; they "
    "are not probabilities and do not sum to the score.",
    "A real local attribution (SHAP, or permutation on this row) would be "
    "a different measurement and is not implemented.",
]


def _contributions(
    feature_row: Sequence[float],
    importances: dict[str, float],
) -> list[FeatureContribution]:
    out: list[FeatureContribution] = []
    for name, value in zip(FEATURE_NAMES, feature_row):
        # 0.08 is the live path's fallback when a model publishes no
        # importance for a feature; kept identical so the two agree.
        weight = float(importances.get(name, 0.08))
        out.append(
            FeatureContribution(
                feature=name,
                value=round(float(value), 4),
                importance_weight=round(weight, 4),
                impact=round(float(value) * weight, 4),
            )
        )
    out.sort(key=lambda c: c.impact, reverse=True)
    return out


def investigate_warning(
    *,
    warning_index: int,
    warnings: Sequence,
    events: Sequence[NormalizedEvent],
    model_id: str,
    prediction_times: Optional[Sequence[datetime]] = None,
    features: Optional[np.ndarray] = None,
    importances: Optional[dict[str, float]] = None,
    observation_window_seconds: float = 60.0,
) -> WarningInvestigation:
    """Assemble the evidence behind one `IssuedWarning`, or refuse."""
    report = WarningInvestigation(
        model_id=model_id,
        warning_index=warning_index,
        attribution_method=ATTRIBUTION_METHOD,
        attribution_limitations=list(ATTRIBUTION_LIMITATIONS),
        related_window_seconds=RELATED_WINDOW_SECONDS,
    )

    match = next(
        (w for w in warnings if getattr(w, "warning_index", None) == warning_index),
        None,
    )
    if match is None:
        report.refusal_reason = (
            f"No warning with index {warning_index} in this report. "
            f"It carries {len(warnings)} warning(s)."
        )
        return report

    report.outcome = getattr(match, "outcome", "")
    report.issued_at = match.issued_at
    report.last_window_at = match.last_window_at
    report.windows = match.windows
    report.peak_score = match.peak_score
    report.matched_event_index = getattr(match, "matched_event_index", None)
    report.lead_time_seconds = getattr(match, "lead_time_seconds", None)

    # The input window spans from one observation window before the first
    # scored window to the last scored window: that is the evidence the
    # model actually saw.
    window_start = match.issued_at - timedelta(seconds=observation_window_seconds)
    window_end = match.last_window_at

    in_window = [e for e in events if window_start <= e.observed_at <= window_end]
    in_window.sort(key=lambda e: e.observed_at)
    report.window_event_count = len(in_window)
    report.window_events = in_window[:MAX_WINDOW_EVENTS]
    report.window_events_shown = len(report.window_events)
    report.window_truncated = len(in_window) > MAX_WINDOW_EVENTS
    if report.window_truncated:
        report.notes.append(
            f"{len(in_window)} events fall in this window; the first "
            f"{MAX_WINDOW_EVENTS} are shown. The count above is the whole "
            "window, not the shown subset."
        )

    # Source references, counted over the WHOLE window rather than the
    # shown subset, so a truncated view cannot misreport who contributed.
    by_source: dict[str, list[datetime]] = {}
    for e in in_window:
        by_source.setdefault(e.source_id, []).append(e.observed_at)
    report.sources = [
        SourceReference(
            source_id=sid,
            events_in_window=len(times),
            first_at=min(times),
            last_at=max(times),
        )
        for sid, times in sorted(by_source.items())
    ]

    # Related activity either side.
    before_from = window_start - timedelta(seconds=RELATED_WINDOW_SECONDS)
    after_to = window_end + timedelta(seconds=RELATED_WINDOW_SECONDS)
    before = [e for e in events if before_from <= e.observed_at < window_start]
    after = [e for e in events if window_end < e.observed_at <= after_to]
    before.sort(key=lambda e: e.observed_at)
    after.sort(key=lambda e: e.observed_at)
    report.related_before = before[-MAX_RELATED_EVENTS:]
    report.related_after = after[:MAX_RELATED_EVENTS]

    # Contributions, only where the model's input is a window feature row.
    if features is None:
        report.contributions_unavailable_reason = (
            f"Model {model_id!r} has no comparable feature rows in the "
            "holdout. Its input is not one window's canonical feature "
            "vector — persistence takes an attack indicator, the temporal "
            "stack is lag-stacked and the LSTM is three-dimensional — so "
            "attributing its score to FEATURE_NAMES would name the wrong "
            "things."
        )
    elif prediction_times is None:
        report.contributions_unavailable_reason = (
            "The holdout carries no prediction times for this model, so the "
            "feature row for this warning cannot be located."
        )
    else:
        # The warning's peak window is the one worth explaining.
        idx = next(
            (
                i
                for i, t in enumerate(prediction_times)
                if match.issued_at <= t <= match.last_window_at
            ),
            None,
        )
        if idx is None or idx >= len(features):
            report.contributions_unavailable_reason = (
                "No scored window falls inside this warning's range, so "
                "there is no feature row to attribute."
            )
        else:
            report.contributions = _contributions(
                features[idx], importances or {}
            )
            report.contributions_available = True

    report.available = True
    return report
