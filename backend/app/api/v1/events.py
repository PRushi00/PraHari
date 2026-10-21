"""
PraHari — Normalized Events API Endpoints
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field

from app.adapters.capabilities import get_capability
from app.api.auth import scope_source
from app.api.deps import get_db
from app.services.enrichment import get_enrichment_service
from app.storage.database import Database
from app.schemas.events import (
    DataCategory,
    DomainAttribution,
    EventType,
    NormalizedEvent,
    SourceCapability,
)

router = APIRouter(prefix="/events", tags=["Normalized Events"])


def _parse_raw_reference(raw_reference: Optional[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    if not raw_reference:
        return out
    for part in raw_reference.split(";"):
        if "=" in part:
            k, _, v = part.partition("=")
            out[k.strip()] = v.strip()
    return out


class ConnectionDetail(BaseModel):
    """
    A normalized event presented as a connection record, with everything
    known about it and an explicit account of what is not known.
    """
    event: NormalizedEvent

    # Decoded adapter provenance
    connection_state: Optional[str] = None
    process_name: Optional[str] = None
    process_id: Optional[int] = None

    # Hostname inference — separate from the record, with its evidence
    domain_attribution: Optional[DomainAttribution] = None

    # What the producing source can and cannot report
    source_type: Optional[str] = None
    unsupported_fields: list[str] = Field(default_factory=list)
    source_limitations: list[str] = Field(default_factory=list)


class PaginatedEventsResponse(BaseModel):
    total: int
    limit: int
    offset: int
    events: list[NormalizedEvent]


class PaginatedConnectionsResponse(BaseModel):
    total: int
    limit: int
    offset: int
    returned: int
    connections: list[ConnectionDetail]
    filters_applied: dict = Field(default_factory=dict)
    enrichment_note: str = ""


class EventSummaryStats(BaseModel):
    total_events: int
    sources_count: int
    labels: dict[str, int]
    event_types: dict[str, int]
    data_categories: dict[str, int]


@router.get("", response_model=PaginatedEventsResponse)
def list_events(
    source_id: Optional[str] = Query(default=None, description="Filter by telemetry source ID"),
    label: Optional[str] = Query(default=None, description="Filter by ground truth / attack label"),
    event_type: Optional[EventType] = Query(default=None, description="Filter by event type"),
    data_category: Optional[DataCategory] = Query(
        default=None, description="Filter by provenance category (e.g. live_telemetry)"
    ),
    limit: int = Query(default=50, ge=1, le=500, description="Page limit"),
    offset: int = Query(default=0, ge=0, description="Page offset"),
    request: Request = None,  # type: ignore[assignment]
    db: Database = Depends(get_db),
) -> PaginatedEventsResponse:
    """
    Retrieve paginated normalized events with optional filtering.

    In central mode the result is confined to the authenticated principal's
    own source; an explicit request for another source is refused.
    """
    source_id = scope_source(request, source_id) if request else source_id
    events = db.list_events(
        source_id=source_id,
        label=label,
        event_type=event_type.value if event_type else None,
        data_category=data_category.value if data_category else None,
        limit=limit,
        offset=offset,
    )
    # total must reflect the SAME filters as the returned page, or the UI
    # shows a count that contradicts its own rows.
    total = db.count_events(
        source_id=source_id,
        label=label,
        event_type=event_type.value if event_type else None,
        data_category=data_category.value if data_category else None,
    )
    return PaginatedEventsResponse(total=total, limit=limit, offset=offset, events=events)


@router.get("/connections", response_model=PaginatedConnectionsResponse)
def list_connections(
    source_id: Optional[str] = Query(default=None),
    data_category: Optional[DataCategory] = Query(default=None),
    dst_port: Optional[int] = Query(default=None, ge=0, le=65535),
    protocol: Optional[str] = Query(default=None),
    connection_state: Optional[str] = Query(default=None),
    process: Optional[str] = Query(default=None, description="Substring match on process name"),
    dst_ip: Optional[str] = Query(default=None, description="Substring match on destination IP"),
    hostname: Optional[str] = Query(default=None, description="Substring match on attributed hostname"),
    include_enrichment: bool = Query(
        default=True, description="Attach hostname attribution with evidence"
    ),
    allow_reverse_dns: bool = Query(
        default=False,
        description=(
            "Permit PTR fallback when no local DNS evidence exists. Names the "
            "address owner only, never the requested hostname, and sends DNS queries."
        ),
    ),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    request: Request = None,  # type: ignore[assignment]
    db: Database = Depends(get_db),
) -> PaginatedConnectionsResponse:
    """
    Connection-intelligence view: events enriched with decoded provenance,
    process attribution, hostname inference and source capability.

    Filters that depend on enrichment or decoded provenance (hostname,
    process, connection state) are applied to the page after it is fetched,
    so `returned` can be smaller than `limit`. `total` always refers to the
    database-level filters only — it is not silently adjusted to match.
    """
    source_id = scope_source(request, source_id) if request else source_id
    events = db.list_events(
        source_id=source_id,
        data_category=data_category.value if data_category else None,
        limit=limit,
        offset=offset,
    )
    total = db.count_events(
        source_id=source_id,
        data_category=data_category.value if data_category else None,
    )

    # Database-level value filters
    if dst_port is not None:
        events = [e for e in events if e.dst_port == dst_port]
    if protocol:
        events = [e for e in events if (e.protocol or "").upper() == protocol.upper()]
    if dst_ip:
        events = [e for e in events if dst_ip in (e.dst_ip or "")]

    source_types = {s.source_id: s.source_type for s in db.list_sources()}

    attributions: dict[str, DomainAttribution] = {}
    if include_enrichment and events:
        attributions = get_enrichment_service(db).attribute_events(
            events, allow_reverse_dns=allow_reverse_dns
        )

    details: list[ConnectionDetail] = []
    for ev in events:
        meta = _parse_raw_reference(ev.raw_reference)
        state = meta.get("state")
        proc_name = meta.get("process")
        pid_raw = meta.get("pid")
        try:
            pid = int(pid_raw) if pid_raw else None
        except ValueError:
            pid = None

        if connection_state and (state or "").lower() != connection_state.lower():
            continue
        if process and process.lower() not in (proc_name or "").lower():
            continue

        attribution = attributions.get(ev.event_id)
        if hostname:
            attributed = (attribution.hostname if attribution else None) or ev.dst_hostname or ""
            if hostname.lower() not in attributed.lower():
                continue

        stype = source_types.get(ev.source_id)
        capability = get_capability(stype)

        details.append(
            ConnectionDetail(
                event=ev,
                connection_state=state,
                process_name=proc_name,
                process_id=pid,
                domain_attribution=attribution,
                source_type=stype,
                unsupported_fields=capability.unsupported_fields(),
                source_limitations=capability.limitations,
            )
        )

    note = (
        "Hostnames are inferred from local DNS evidence and carry a confidence "
        "and method; they are not recorded by the connection itself. Unknown "
        "values are shown as unknown and are never guessed."
        if include_enrichment
        else "Enrichment disabled for this request."
    )

    return PaginatedConnectionsResponse(
        total=total,
        limit=limit,
        offset=offset,
        returned=len(details),
        connections=details,
        filters_applied={
            k: v
            for k, v in {
                "source_id": source_id,
                "data_category": data_category.value if data_category else None,
                "dst_port": dst_port,
                "protocol": protocol,
                "connection_state": connection_state,
                "process": process,
                "dst_ip": dst_ip,
                "hostname": hostname,
            }.items()
            if v is not None
        },
        enrichment_note=note,
    )


@router.get("/capabilities", response_model=list[SourceCapability])
def list_source_capabilities(db: Database = Depends(get_db)) -> list[SourceCapability]:
    """
    Report what each registered source can structurally provide.

    Consumers use this to tell a field the source cannot measure from one
    that is genuinely missing.
    """
    seen: dict[str, SourceCapability] = {}
    for source in db.list_sources():
        cap = get_capability(source.source_type)
        seen[cap.source_type] = cap
    return list(seen.values())


@router.get("/stats/summary", response_model=EventSummaryStats)
def get_event_stats(db: Database = Depends(get_db)) -> EventSummaryStats:
    """Aggregated counts across stored events."""
    total = db.count_events()
    sources = db.list_sources()

    # Measured over every stored event, by GROUP BY. This was previously
    # counted from `list_events(limit=1000)`, so past 1000 events the
    # breakdowns described only the newest 1000 while `total_events` beside
    # them described all of them — with nothing in the response saying so.
    # A corpus whose attacks were older than that window reported none.
    # ADR-095 is the same defect, found in readiness and fixed there only.
    breakdown = db.event_breakdown()
    labels = {(k or "unlabeled"): v for k, v in breakdown["labels"].items()}
    event_types = breakdown["event_types"]
    categories = breakdown["data_categories"]

    return EventSummaryStats(
        total_events=total,
        sources_count=len(sources),
        labels=labels,
        event_types=event_types,
        data_categories=categories,
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
