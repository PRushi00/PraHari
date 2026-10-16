"""
PraHari — Research Benchmark Import API

The authorized path for third-party labelled corpora.

Every route here resolves the **research** database and refuses if one is
not configured, is invalid, or resolves to the operational telemetry store.
The refusal happens before any row is read, so a misconfiguration cannot
result in a partial write.

No route in this module downloads anything. The operator places a file on
disk; PraHari hashes and reads it locally.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from app.adapters.research_csv import (
    COLUMN_CANDIDATES,
    DurationUnit,
    ResearchCsvError,
    ResearchCsvPolicy,
    TimestampFormat,
    import_research_csv,
    sha256_bytes,
    sha256_file,
)
from app.api.auth import resolve_ingest_source
from app.core.config import AppConfig, get_config
from app.core.research_store import (
    ResearchDatabaseCollision,
    ResearchDatabaseInvalid,
    ResearchDatabaseNotConfigured,
    ResearchStoreError,
    assert_safe_research_target,
    resolve_research_database,
)
from app.research.import_manifest import (
    ImportManifest,
    build_manifest,
    list_manifests,
    save_manifest,
)
from app.schemas.events import DataCategory, TelemetrySource
from app.storage.database import Database

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/research/import", tags=["Research Import"])

_research_db: Optional[Database] = None
_research_db_path: Optional[str] = None


def _refusal(exc: ResearchStoreError) -> HTTPException:
    code = {
        ResearchDatabaseNotConfigured: "research_database_not_configured",
        ResearchDatabaseCollision: "research_database_collides_with_operational",
        ResearchDatabaseInvalid: "research_database_invalid",
    }.get(type(exc), "research_database_unavailable")
    return HTTPException(
        status_code=status.HTTP_409_CONFLICT,
        detail={
            "error": code,
            "message": str(exc),
            "remedy": (
                "Set PRAHARI_RESEARCH_DATABASE_URL to a dedicated SQLite path "
                "that is not the operational telemetry database. PraHari does "
                "not fall back to the operational store."
            ),
        },
    )


def get_research_db(config: AppConfig = Depends(get_config)) -> Database:
    """
    The research database, or a refusal.

    Deliberately a separate dependency from ``get_db``: nothing in this
    module can reach the operational connection, and the safety check runs
    again on the resolved path before the handle is returned.
    """
    global _research_db, _research_db_path

    try:
        path = resolve_research_database(config)
    except ResearchStoreError as exc:
        raise _refusal(exc)

    assert_safe_research_target(path, config)

    if _research_db is None or _research_db_path != str(path):
        database = Database(db_path=str(path))
        database.initialize()
        _research_db = database
        _research_db_path = str(path)
        logger.info("Research store ready at %s", path)

    return _research_db


def reset_research_db() -> None:
    """Drop the cached handle. Used by tests between temporary databases."""
    global _research_db, _research_db_path
    if _research_db is not None:
        try:
            _research_db.close()
        except Exception:  # noqa: BLE001
            logger.debug("Research store already closed", exc_info=True)
    _research_db = None
    _research_db_path = None


class ResearchImportRequest(BaseModel):
    """
    An import the operator has to describe before it runs.

    None of these can be inferred from the bytes, and guessing any of them
    is how a corpus gets silently misread.
    """

    file_path: str = Field(..., description="Local path to a CSV already on disk.")
    dataset_name: str = Field(..., min_length=1, max_length=200)
    dataset_release: Optional[str] = Field(default=None, max_length=200)
    source_id: str = Field(..., min_length=1, max_length=128)
    timestamp_format: TimestampFormat = TimestampFormat.AUTO
    source_timezone: Optional[str] = Field(
        default=None,
        description="IANA name if the source documents one. Leave null if unknown.",
    )
    duration_unit: DurationUnit = Field(
        default=DurationUnit.UNKNOWN,
        description="CICFlowMeter Flow Duration is microseconds. Unknown means the column is not imported.",
    )
    require_bidirectional_counts: bool = True
    max_records: int = Field(default=1_000_000, ge=1, le=5_000_000)
    dry_run: bool = Field(
        default=True,
        description="Default true: parse, account and report without writing.",
    )


class ResearchImportResult(BaseModel):
    dry_run: bool
    research_database: str
    events_normalized: int
    events_persisted: int
    manifest: ImportManifest
    manifest_path: Optional[str] = None


@router.get("/status")
def research_store_status(config: AppConfig = Depends(get_config)) -> dict:
    """Whether a research store is configured, without creating one."""
    try:
        path = resolve_research_database(config)
    except ResearchStoreError as exc:
        return {
            "configured": False,
            "reason": str(exc),
            "operational_database": str(config.get_database_path()),
            "fail_closed": True,
        }
    return {
        "configured": True,
        "research_database": str(path),
        "operational_database": str(config.get_database_path()),
        "exists": path.exists(),
        "fail_closed": True,
    }


@router.post("/csv", response_model=ResearchImportResult)
def import_research_csv_file(
    req: ResearchImportRequest,
    request: Request,
    db: Database = Depends(get_research_db),
    config: AppConfig = Depends(get_config),
) -> ResearchImportResult:
    """
    Import a benchmark CSV into the research store.

    Dry run by default: the file is parsed, hashed and accounted for, and a
    manifest is produced, but nothing is written. A real import must be
    asked for explicitly.
    """
    source = Path(req.file_path)
    if not source.exists() or not source.is_file():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "source_file_not_found", "message": f"{source} is not a file."},
        )

    # Re-assert on the handle actually in hand, not only on configuration.
    assert_safe_research_target(db.db_path, config)

    raw = source.read_bytes()
    digest = sha256_bytes(raw)
    on_disk = sha256_file(str(source))
    if digest != on_disk:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "error": "source_file_changed_during_read",
                "message": "The file changed while being read; the import was abandoned.",
            },
        )

    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        text = raw.decode("latin-1")

    # Research data lands in an isolated store, but it is still filed under
    # a source id, so the same boundary applies: a credential may not import
    # a corpus under another source's name.
    source_id = resolve_ingest_source(request, req.source_id)

    policy = ResearchCsvPolicy(
        timestamp_format=req.timestamp_format,
        source_timezone=req.source_timezone,
        duration_unit=req.duration_unit,
        require_bidirectional_counts=req.require_bidirectional_counts,
        max_records=req.max_records,
    )

    try:
        events, quality = import_research_csv(
            csv_text=text,
            source_id=source_id,
            source_sha256=digest,
            policy=policy,
            data_category=DataCategory.HISTORICAL_IMPORT,
        )
    except ResearchCsvError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": "unusable_csv", "message": str(exc)},
        )

    conversions = []
    if req.duration_unit is not DurationUnit.UNKNOWN:
        conversions.append(
            f"duration: {req.duration_unit.value} -> seconds (canonical schema unit)"
        )

    manifest = build_manifest(
        dataset_name=req.dataset_name,
        dataset_release=req.dataset_release,
        source_filename=source.name,
        source_sha256=digest,
        source_size_bytes=len(raw),
        source_id=source_id,
        data_category=DataCategory.HISTORICAL_IMPORT.value,
        policy=policy.describe(),
        quality=quality,
        unit_conversions=conversions,
        field_mapping={k: " | ".join(v) for k, v in COLUMN_CANDIDATES.items()},
    )

    persisted = 0
    manifest_file: Optional[str] = None

    if not req.dry_run:
        if db.get_source(source_id) is None:
            db.upsert_source(
                TelemetrySource(
                    source_id=source_id,
                    name=req.dataset_name,
                    source_type="csv_import",
                    description=f"Research corpus {req.dataset_name} ({source.name})",
                )
            )
        if events:
            before = db.count_events(source_id=source_id)
            db.insert_events(events)
            persisted = db.count_events(source_id=source_id) - before
            db.refresh_source_activity(
                source_id,
                last_event_at=max(e.observed_at for e in events),
                status="active",
            )
        manifest_file = str(
            save_manifest(manifest, Path(db.db_path).parent / "manifests")
        )
        db.log_audit(
            action="research_import_csv",
            resource_type="research_corpus",
            resource_id=source_id,
            details=(
                f"{req.dataset_name} sha256={digest[:16]} accepted={quality.accepted} "
                f"rejected={quality.rejected} persisted={persisted}"
            ),
        )

    return ResearchImportResult(
        dry_run=req.dry_run,
        research_database=str(db.db_path),
        events_normalized=len(events),
        events_persisted=persisted,
        manifest=manifest,
        manifest_path=manifest_file,
    )


@router.get("/manifests", response_model=list[ImportManifest])
def list_import_manifests(db: Database = Depends(get_research_db)) -> list[ImportManifest]:
    """Every recorded research import for the configured store."""
    return list_manifests(Path(db.db_path).parent / "manifests")
