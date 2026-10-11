"""
PraHari — Telemetry Sources API Endpoints
"""

from __future__ import annotations

from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from app.api.deps import get_db
from app.storage.database import Database
from app.schemas.events import TelemetrySource

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
