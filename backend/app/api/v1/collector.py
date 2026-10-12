"""
PraHari — Live Windows Telemetry Collector API Endpoints

Operator control and observability for genuine local network telemetry
collection. The collector must be started explicitly; nothing here runs
automatically on application startup.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from app.api.deps import get_db
from app.services.collector import (
    CollectorStatus,
    PollResult,
    get_collector,
)
from app.storage.database import Database

router = APIRouter(prefix="/collector", tags=["Live Telemetry Collector"])


class StartCollectorRequest(BaseModel):
    interval_seconds: float = Field(
        default=15.0,
        ge=2.0,
        le=3600.0,
        description="Seconds between connection-table polls.",
    )


@router.get("/status", response_model=CollectorStatus)
def get_collector_status(db: Database = Depends(get_db)) -> CollectorStatus:
    """
    Report live collector state, ingestion accounting, collection gaps,
    and the honest capability limits of this telemetry source.
    """
    return get_collector(db).status()


@router.post("/start", response_model=CollectorStatus)
async def start_collector(
    req: StartCollectorRequest,
    db: Database = Depends(get_db),
) -> CollectorStatus:
    """Start background collection of live Windows connection telemetry."""
    collector = get_collector(db)
    if not collector.platform_supported:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail=(
                "Windows connection-table collection is not available on this "
                f"platform ({collector.status().platform_name}). No live source started."
            ),
        )
    return await collector.start(interval_seconds=req.interval_seconds)


@router.post("/stop", response_model=CollectorStatus)
async def stop_collector(db: Database = Depends(get_db)) -> CollectorStatus:
    """Stop background collection cleanly, releasing the polling task."""
    return await get_collector(db).stop()


@router.post("/poll", response_model=PollResult)
async def poll_collector_once(db: Database = Depends(get_db)) -> PollResult:
    """
    Execute exactly one collection poll synchronously.

    Useful for verifying the live path end-to-end without starting the
    background loop. Returns the real per-poll accounting, including
    suppressed repeat observations of still-open connections.
    """
    collector = get_collector(db)
    if not collector.platform_supported:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail=(
                "Windows connection-table collection is not available on this "
                f"platform ({collector.status().platform_name})."
            ),
        )
    result = await collector.poll_once()
    if not result.succeeded:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Collection poll failed: {result.error}",
        )
    return result
