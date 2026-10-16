"""
PraHari — CSV Import API Endpoints
"""

from __future__ import annotations

from typing import Optional
from datetime import datetime, timezone
from fastapi import Request, APIRouter, Depends, HTTPException, UploadFile, File, Form, status
from pydantic import BaseModel, Field

from app.api.auth import resolve_ingest_source
from app.api.deps import get_db
from app.core.config import AppConfig, get_config
from app.core.research_store import is_operational_database, requires_research_store
from app.storage.database import Database
from app.adapters.csv_import import import_csv_string
from app.schemas.events import DataCategory, ImportSummary, TelemetrySource

def _refuse_research_import_into_operational_store(
    data_category: DataCategory, db: Database, config: AppConfig
) -> None:
    """
    Stop a benchmark corpus landing in the operator's live telemetry.

    The general CSV endpoints are a convenience reader for ad-hoc files. A
    research category arriving here, with the operational database as the
    target, is almost certainly a mis-aimed benchmark import — the one
    accident that would contaminate the only copy of genuine local
    observations. It is refused before a single row is read.

    Imports into any other database (a test fixture, a scratch file) are
    unaffected, so this does not change existing behaviour for anything
    except the operational store itself.
    """
    if not requires_research_store(data_category.value):
        return
    if not is_operational_database(db.db_path, config):
        return
    raise HTTPException(
        status_code=status.HTTP_409_CONFLICT,
        detail={
            "error": "research_import_into_operational_database",
            "message": (
                f"Refusing to import data_category={data_category.value!r} into the "
                f"operational telemetry database at {db.db_path}. Benchmark corpora "
                "are kept in a separate research store."
            ),
            "remedy": (
                "Use POST /api/v1/research/import/csv with "
                "PRAHARI_RESEARCH_DATABASE_URL configured, or import under a "
                "non-research data_category if this really is local telemetry."
            ),
        },
    )


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
    request: Request,
    db: Database = Depends(get_db),
    config: AppConfig = Depends(get_config),
) -> ImportSummary:
    """Import CSV data from raw textual content with full validation and canonical normalization."""
    _refuse_research_import_into_operational_store(req.data_category, db, config)

    # An import writes events like any other path, so it is scoped like any
    # other path. A historical corpus is still filed under a source, and a
    # credential must not file it under someone else's.
    source_id = resolve_ingest_source(request, req.source_id)

    # Ensure source exists
    source = db.get_source(source_id)
    if not source:
        source = TelemetrySource(
            source_id=source_id,
            name=req.source_name or f"Source {source_id}",
            source_type="csv_import",
            description="Auto-registered during CSV raw import",
        )
        db.upsert_source(source)

    # The request's own ceiling is a hard upper bound from the schema; the
    # configured one is the operator's policy. Taking the lower of the two
    # means lowering `max_import_records` actually does something — it was
    # a config value nothing read (ADR-054 regression review).
    effective_max = min(req.max_records, config.max_import_records)

    events, summary = import_csv_string(
        csv_content=req.csv_content,
        source_id=source_id,
        data_category=req.data_category,
        max_records=effective_max,
    )

    if events:
        db.insert_events(events)
        # Counters are recomputed from storage rather than incremented by batch
        # size, so deduplicated records cannot inflate the source's totals.
        db.refresh_source_activity(
            source.source_id,
            last_event_at=max(e.observed_at for e in events),
            status="active",
        )

    db.save_import_summary(summary)
    db.log_audit(
        action="import_csv_raw",
        resource_type="import_summary",
        resource_id=summary.import_id,
        details=f"Imported {summary.accepted_records} events, rejected {summary.rejected_records} for source {source_id}",
    )
    return summary


@router.post("/csv/file", response_model=ImportSummary)
async def import_csv_file_upload(
    request: Request,
    file: UploadFile = File(...),
    source_id: str = Form(...),
    source_name: Optional[str] = Form(default=None),
    data_category: DataCategory = Form(default=DataCategory.HISTORICAL_IMPORT),
    db: Database = Depends(get_db),
    config: AppConfig = Depends(get_config),
) -> ImportSummary:
    """Import CSV data from an uploaded file."""
    _refuse_research_import_into_operational_store(data_category, db, config)
    source_id = resolve_ingest_source(request, source_id)
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
        # Counters are recomputed from storage rather than incremented by batch
        # size, so deduplicated records cannot inflate the source's totals.
        db.refresh_source_activity(
            source.source_id,
            last_event_at=max(e.observed_at for e in events),
            status="active",
        )

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
