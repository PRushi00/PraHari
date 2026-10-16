"""
PraHari — Telemetry Sources API Endpoints
"""

from __future__ import annotations

from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from app.api.auth import require_admin_in_central
from app.api.deps import get_db
from app.storage.database import Database
from app.schemas.events import TelemetrySource

from app.services.clock_integrity import (
    ClockIntegrityReport,
    analyze_clock_integrity,
    analyze_per_source,
)
from app.services.source_health import (
    DEFAULT_FRESH_SECONDS,
    DEFAULT_STALE_SECONDS,
    SourceHealthSummary,
    summarize_source_health,
)

router = APIRouter(prefix="/sources", tags=["Telemetry Sources"])


class CreateSourceRequest(BaseModel):
    source_id: str = Field(..., min_length=1, max_length=128, description="Unique identifier for the telemetry source")
    name: str = Field(..., min_length=1, max_length=256, description="Human-readable name")
    source_type: str = Field(..., description="Type of source, e.g. csv_import, zeek, suricata")
    description: Optional[str] = Field(default="", description="Optional description of the source")


@router.get("", response_model=list[TelemetrySource])
def list_sources(db: Database = Depends(get_db)) -> list[TelemetrySource]:
    """Retrieve all configured telemetry sources."""
    return db.list_sources()


@router.post("", response_model=TelemetrySource, status_code=status.HTTP_201_CREATED)
def create_source(
    req: CreateSourceRequest,
    db: Database = Depends(get_db),
) -> TelemetrySource:
    """Register a new telemetry source."""
    existing = db.get_source(req.source_id)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Telemetry source with ID '{req.source_id}' already exists",
        )
    source = TelemetrySource(
        source_id=req.source_id,
        name=req.name,
        source_type=req.source_type,
        description=req.description or "",
    )
    db.upsert_source(source)
    db.log_audit(
        action="create_source",
        resource_type="telemetry_source",
        resource_id=source.source_id,
        details=f"Created source {source.name} ({source.source_type})",
    )
    return source


@router.get("/health", response_model=SourceHealthSummary)
def get_source_health(
    fresh_seconds: float = Query(
        default=DEFAULT_FRESH_SECONDS, gt=0,
        description="An event newer than this counts as reporting.",
    ),
    stale_seconds: float = Query(
        default=DEFAULT_STALE_SECONDS, gt=0,
        description="Beyond this, the source is reported silent.",
    ),
    db: Database = Depends(get_db),
) -> SourceHealthSummary:
    """
    Per-source freshness, with the basis for each verdict.

    Freshness is derived from **event time reported by the source**, so it
    is only as trustworthy as that source's clock — see
    `GET /sources/clock-integrity`. PraHari has no heartbeat, so "silent"
    means "no events recorded", never "the host is down".
    """
    if fresh_seconds > stale_seconds:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "error": "invalid_thresholds",
                "message": "fresh_seconds must not exceed stale_seconds.",
            },
        )
    return summarize_source_health(
        db.list_sources(),
        fresh_seconds=fresh_seconds,
        stale_seconds=stale_seconds,
        last_received_by_source=db.latest_received_at_by_source(),
    )


@router.get("/clock-integrity", response_model=list[ClockIntegrityReport])
def get_clock_integrity(
    source_id: Optional[str] = Query(default=None),
    max_events: int = Query(default=5000, ge=1, le=50_000),
    db: Database = Depends(get_db),
) -> list[ClockIntegrityReport]:
    """
    Ingest-lag diagnostics per source.

    **This is not a clock-skew measurement.** PraHari has no trusted
    reference clock, so the reported lag (`ingested_at - observed_at`)
    contains clock offset *and* collection, transport and queueing delay,
    inseparably. The one sound inference is a lower bound: delay cannot be
    negative, so an event ingested before its stated observation time proves
    the source's clock leads this host's by at least that much.

    No timestamp is modified by this endpoint.
    """
    events = db.list_events(source_id=source_id, limit=max_events)
    reports = analyze_per_source(events)
    if source_id and source_id not in reports:
        # A known source with no events still deserves a report rather than
        # an empty list that reads as "nothing wrong".
        reports[source_id] = analyze_clock_integrity([], source_id=source_id)
    return list(reports.values())


class SourceEnabledRequest(BaseModel):
    enabled: bool = Field(..., description="Whether the source may report.")
    reason: str = Field(default="", max_length=500)


@router.patch("/{source_id}/enabled", response_model=TelemetrySource)
def set_source_enabled(
    source_id: str,
    req: SourceEnabledRequest,
    db: Database = Depends(get_db),
    _: object = Depends(require_admin_in_central),
) -> TelemetrySource:
    """
    Enable or disable a telemetry source.

    Administrative in central mode; unrestricted on a loopback
    deployment, which is unauthenticated by design.

    Disabling does NOT delete anything and does not reject already
    stored telemetry — it records that no further data is expected, which
    is what `SourceHealth.DISABLED` reports. Only the `enabled` column is
    written, so counters and last-event time survive the toggle.
    """
    if not db.set_source_enabled(source_id, req.enabled):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error": "source_not_found",
                "message": f"No telemetry source {source_id!r} is registered.",
            },
        )

    db.log_audit(
        action="set_source_enabled",
        resource_type="telemetry_source",
        resource_id=source_id,
        details=(
            f"enabled={req.enabled}"
            + (f"; reason={req.reason}" if req.reason else "")
        ),
    )
    updated = db.get_source(source_id)
    if updated is None:  # pragma: no cover - defensive
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "source_not_found", "message": source_id},
        )
    return updated


@router.get("/{source_id}", response_model=TelemetrySource)
def get_source(source_id: str, db: Database = Depends(get_db)) -> TelemetrySource:
    """Retrieve details of a single telemetry source."""
    source = db.get_source(source_id)
    if not source:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Telemetry source '{source_id}' not found",
        )
    return source
