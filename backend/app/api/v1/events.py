"""
PraHari — Normalized Events API Endpoints
"""

from __future__ import annotations

from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel

from app.api.deps import get_db
from app.storage.database import Database
from app.schemas.events import NormalizedEvent, EventType

router = APIRouter(prefix="/events", tags=["Normalized Events"])


class PaginatedEventsResponse(BaseModel):
    total: int
    limit: int
    offset: int
    events: list[NormalizedEvent]


class EventSummaryStats(BaseModel):
    total_events: int
    sources_count: int
    labels: dict[str, int]
    event_types: dict[str, int]


@router.get("", response_model=PaginatedEventsResponse)
def list_events(
    source_id: Optional[str] = Query(default=None, description="Filter by telemetry source ID"),
    label: Optional[str] = Query(default=None, description="Filter by ground truth / attack label"),
    event_type: Optional[EventType] = Query(default=None, description="Filter by event type"),
    limit: int = Query(default=50, ge=1, le=500, description="Page limit"),
    offset: int = Query(default=0, ge=0, description="Page offset"),
    db: Database = Depends(get_db),
) -> PaginatedEventsResponse:
    """Retrieve paginated normalized security events with optional filtering."""
    ev_type_val = event_type.value if event_type else None
    events = db.list_events(
        source_id=source_id,
        label=label,
        event_type=ev_type_val,
        limit=limit,
        offset=offset,
    )
    total = db.count_events(source_id=source_id, label=label)
    return PaginatedEventsResponse(
        total=total,
        limit=limit,
        offset=offset,
        events=events,
    )


@router.get("/stats/summary", response_model=EventSummaryStats)
def get_event_stats(db: Database = Depends(get_db)) -> EventSummaryStats:
    """Retrieve quick aggregated summary stats across all events."""
    total = db.count_events()
    sources = db.list_sources()
    # Pull recent events to gather top distribution
    sample = db.list_events(limit=1000)
    labels: dict[str, int] = {}
    event_types: dict[str, int] = {}
    for ev in sample:
        l = ev.label or "unlabeled"
        labels[l] = labels.get(l, 0) + 1
        t = ev.event_type.value
        event_types[t] = event_types.get(t, 0) + 1

    return EventSummaryStats(
        total_events=total,
        sources_count=len(sources),
        labels=labels,
        event_types=event_types,
    )


@router.get("/{event_id}", response_model=NormalizedEvent)
def get_event(event_id: str, db: Database = Depends(get_db)) -> NormalizedEvent:
    """Retrieve a single normalized event by its unique ID."""
    event = db.get_event(event_id)
    if not event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Event '{event_id}' not found",
        )
    return event
