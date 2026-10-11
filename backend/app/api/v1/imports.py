"""
PraHari — CSV Import API Endpoints
"""

from __future__ import annotations

from typing import Optional
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form, status
from pydantic import BaseModel, Field

from app.api.deps import get_db
from app.storage.database import Database
from app.adapters.csv_import import import_csv_string
from app.schemas.events import DataCategory, ImportSummary, TelemetrySource

router = APIRouter(prefix="/import", tags=["Data Import"])


class RawCsvImportRequest(BaseModel):
    source_id: str = Field(..., description="Telemetry source identifier")
    source_name: Optional[str] = Field(default=None, description="Optional name for the source if auto-creating")
    csv_content: str = Field(..., description="Raw CSV textual content")
    data_category: DataCategory = Field(default=DataCategory.HISTORICAL_IMPORT, description="Data provenance category")
    max_records: int = Field(default=50_000, ge=1, le=100_000)


@router.post("/csv/raw", response_model=ImportSummary)
def import_raw_csv(
    req: RawCsvImportRequest,
    db: Database = Depends(get_db),
) -> ImportSummary:
    """Import CSV data from raw textual content with full validation and canonical normalization."""
    # Ensure source exists
    source = db.get_source(req.source_id)
    if not source:
        source = TelemetrySource(
            source_id=req.source_id,
            name=req.source_name or f"Source {req.source_id}",
            source_type="csv_import",
            description="Auto-registered during CSV raw import",
        )
        db.upsert_source(source)

    events, summary = import_csv_string(
        csv_content=req.csv_content,
        source_id=req.source_id,
        data_category=req.data_category,
        max_records=req.max_records,
    )

    if events:
        db.insert_events(events)
        source.event_count += len(events)
        source.last_event_at = max(e.observed_at for e in events)
        db.upsert_source(source)

    db.save_import_summary(summary)
    db.log_audit(
        action="import_csv_raw",
        resource_type="import_summary",
        resource_id=summary.import_id,
        details=f"Imported {summary.accepted_records} events, rejected {summary.rejected_records} for source {req.source_id}",
    )
    return summary


@router.post("/csv/file", response_model=ImportSummary)
async def import_csv_file_upload(
    file: UploadFile = File(...),
    source_id: str = Form(...),
    source_name: Optional[str] = Form(default=None),
    data_category: DataCategory = Form(default=DataCategory.HISTORICAL_IMPORT),
    db: Database = Depends(get_db),
) -> ImportSummary:
    """Import CSV data from an uploaded file."""
    if not file.filename.endswith(".csv") and not file.filename.endswith(".txt"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="File must be a CSV or TXT file",
        )

    content_bytes = await file.read()
    try:
        content_str = content_bytes.decode("utf-8-sig")
    except UnicodeDecodeError:
        try:
            content_str = content_bytes.decode("latin-1")
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unable to decode file encoding: {e}",
            )

    source = db.get_source(source_id)
    if not source:
        source = TelemetrySource(
            source_id=source_id,
            name=source_name or file.filename,
            source_type="csv_import",
            description=f"Auto-registered from file upload: {file.filename}",
        )
        db.upsert_source(source)

    events, summary = import_csv_string(
        csv_content=content_str,
        source_id=source_id,
        data_category=data_category,
    )
    summary.source_file = file.filename

    if events:
        db.insert_events(events)
        source.event_count += len(events)
        source.last_event_at = max(e.observed_at for e in events)
        db.upsert_source(source)

    db.save_import_summary(summary)
    db.log_audit(
        action="import_csv_file",
        resource_type="import_summary",
        resource_id=summary.import_id,
        details=f"Imported {summary.accepted_records} events from {file.filename}",
    )
    return summary


@router.get("/history", response_model=list[ImportSummary])
def get_import_history(
    source_id: Optional[str] = None,
    db: Database = Depends(get_db),
) -> list[ImportSummary]:
    """Retrieve history of past data imports."""
    return db.list_import_summaries(source_id=source_id)
