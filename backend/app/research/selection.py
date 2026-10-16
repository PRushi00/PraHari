"""
PraHari — Provenance-Aware, Coverage-Honest Dataset Selection

Two failures this exists to prevent.

**Silent mixing.** Selecting training data by ``source_id`` alone lets a
labelled benchmark corpus and the operator's unlabelled live telemetry end
up in one training set. The resulting model is trained on two populations
with different label semantics and different measurement units, and nothing
downstream records that it happened.

**Silent truncation.** ``list_events`` applies ``ORDER BY observed_at DESC
LIMIT n``. Ask for 100,000 events from a corpus of several million and you
get the most recent 100,000 — the tail of the final capture day — with no
indication that 97% of the data was dropped. Every metric then describes a
slice nobody chose.

Both are reported here as data, not as log lines, so the API, the
experiment manifest and the dashboard all carry the same account.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field

from app.schemas.events import DataCategory, NormalizedEvent
from app.storage.database import Database

logger = logging.getLogger(__name__)

# Categories that are research material rather than observation of this host.
BENCHMARK_CATEGORIES = {
    DataCategory.HISTORICAL_IMPORT.value,
    DataCategory.HISTORICAL_REPLAY.value,
}
LIVE_CATEGORIES = {DataCategory.LIVE_TELEMETRY.value}
GENERATED_CATEGORIES = {
    DataCategory.SYNTHETIC_DEMO.value,
    DataCategory.TEST_FIXTURE.value,
}


class SelectionCoverage(BaseModel):
    """What was selected, out of what, and what was left behind."""

    requested_max_events: int
    matching_events_total: int
    selected_events: int
    truncated: bool = False
    coverage_fraction: Optional[float] = None
    selection_strategy: str = "most_recent_by_observed_at"

    selected_time_range: Optional[list[str]] = None
    full_time_range: Optional[list[str]] = None

    source_breakdown: dict[str, int] = Field(default_factory=dict)
    category_breakdown: dict[str, int] = Field(default_factory=dict)
    label_provenance_breakdown: dict[str, int] = Field(default_factory=dict)
    label_distribution: dict[str, int] = Field(default_factory=dict)

    mixed_provenance: bool = False
    provenance_classes: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)

    @property
    def complete(self) -> bool:
        return not self.truncated


class MixedProvenanceRefused(ValueError):
    """Training would pool benchmark, live and/or generated data."""

    def __init__(self, message: str, coverage: SelectionCoverage):
        self.coverage = coverage
        super().__init__(message)


def _provenance_class(category: str) -> str:
    if category in BENCHMARK_CATEGORIES:
        return "benchmark"
    if category in LIVE_CATEGORIES:
        return "live"
    if category in GENERATED_CATEGORIES:
        return "generated"
    return "other"


def select_training_events(
    db: Database,
    *,
    source_id: Optional[str] = None,
    data_category: Optional[str] = None,
    max_events: int = 20_000,
    allow_mixed_provenance: bool = False,
) -> tuple[list[NormalizedEvent], SelectionCoverage]:
    """
    Select events for an experiment, refusing unintended mixtures.

    Filtering is by **data_category** as well as source, because the
    category is the authoritative provenance field — a source id is a name
    an operator chose and carries no guarantee.

    Raises ``MixedProvenanceRefused`` when the selection spans more than one
    provenance class and the caller has not explicitly opted in. Mixing is
    sometimes legitimate; doing it by accident never is.
    """
    total = db.count_events(source_id=source_id, data_category=data_category)
    events = db.list_events(
        source_id=source_id, data_category=data_category, limit=max_events
    )

    # list_events returns most-recent-first; every downstream step assumes
    # chronological order, so restore it here rather than relying on the
    # pipeline to sort defensively.
    events = sorted(events, key=lambda e: (e.observed_at, e.event_id))

    coverage = SelectionCoverage(
        requested_max_events=max_events,
        matching_events_total=total,
        selected_events=len(events),
        truncated=total > len(events),
        coverage_fraction=round(len(events) / total, 6) if total else None,
    )

    for event in events:
        coverage.source_breakdown[event.source_id] = (
            coverage.source_breakdown.get(event.source_id, 0) + 1
        )
        category = event.data_category.value
        coverage.category_breakdown[category] = (
            coverage.category_breakdown.get(category, 0) + 1
        )
        provenance = event.label_provenance.value
        coverage.label_provenance_breakdown[provenance] = (
            coverage.label_provenance_breakdown.get(provenance, 0) + 1
        )
        key = (event.label or "<unlabelled>").strip() or "<unlabelled>"
        coverage.label_distribution[key] = coverage.label_distribution.get(key, 0) + 1

    if events:
        coverage.selected_time_range = [
            events[0].observed_at.isoformat(),
            events[-1].observed_at.isoformat(),
        ]

    classes = sorted({_provenance_class(c) for c in coverage.category_breakdown})
    coverage.provenance_classes = classes
    coverage.mixed_provenance = len(classes) > 1

    if coverage.truncated:
        coverage.warnings.append(
            f"Selected {len(events)} of {total} matching events "
            f"({coverage.coverage_fraction:.1%}) using "
            f"'{coverage.selection_strategy}'. Results describe that subset, "
            "not the full dataset."
        )

    if coverage.mixed_provenance:
        detail = ", ".join(
            f"{c}={coverage.category_breakdown.get(c, 0)}"
            for c in sorted(coverage.category_breakdown)
        )
        message = (
            f"Selection spans {len(classes)} provenance classes ({', '.join(classes)}): "
            f"{detail}. Benchmark labels and unlabelled live telemetry have "
            "different label semantics and measurement units; pooling them "
            "produces a model whose training population cannot be described."
        )
        if not allow_mixed_provenance:
            raise MixedProvenanceRefused(message, coverage)
        coverage.warnings.append(
            "MIXED PROVENANCE (explicitly allowed): " + message
        )

    return events, coverage
