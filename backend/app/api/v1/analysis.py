"""
PraHari — Descriptive Analysis API Endpoints
"""

from __future__ import annotations

from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from app.api.auth import require_admin_in_central
from app.api.deps import get_db
from app.core.config import AppConfig, get_config
from app.research.label_policy import describe_breakdown
from app.services.analysis import compute_descriptive_analysis
from app.services.enrichment import get_enrichment_service
from app.storage.database import Database
from app.schemas.events import DataCategory, DescriptiveAnalysis

router = APIRouter(prefix="/analysis", tags=["Descriptive Analysis"])


class RunAnalysisRequest(BaseModel):
    source_id: Optional[str] = Field(
        default=None, description="Source ID to analyze, or omit for all sources"
    )
    # A FILTER over which events to analyze — not a declaration of what the
    # data is. The resulting analysis derives its own category from the
    # events it actually summarized.
    data_category: Optional[DataCategory] = Field(
        default=None,
        description=(
            "Optional filter: analyze only events in this category. This does "
            "NOT label the result; the result's category is derived from the "
            "analyzed events."
        ),
    )
    max_events: int = Field(default=50_000, ge=1, le=100_000)
    include_hostnames: bool = Field(
        default=True,
        description="Aggregate inferred destination hostnames where DNS evidence exists.",
    )


def _source_type_map(db: Database) -> dict[str, str]:
    """source_id -> source_type, used to resolve capability profiles."""
    return {s.source_id: s.source_type for s in db.list_sources()}


def _build_analysis(
    db: Database,
    source_id: Optional[str],
    data_category: Optional[DataCategory],
    max_events: int,
    include_hostnames: bool,
) -> DescriptiveAnalysis:
    events = db.list_events(
        source_id=source_id,
        data_category=data_category.value if data_category else None,
        limit=max_events,
    )
    resolver = None
    if include_hostnames:
        enrichment = get_enrichment_service(db)
        resolver = enrichment.hostname_for_event
    return compute_descriptive_analysis(
        events=events,
        source_id=source_id or "all_sources",
        source_types=_source_type_map(db),
        hostname_resolver=resolver,
    )


@router.post("/run", response_model=DescriptiveAnalysis)
def run_analysis(
    req: RunAnalysisRequest,
    db: Database = Depends(get_db),
) -> DescriptiveAnalysis:
    """
    Compute descriptive statistics on persisted events.

    Factual summary only — NOT forecasting and NOT detection. The result's
    `data_category`, `data_categories` and `source_breakdown` are derived
    from the analyzed events, so an analysis cannot be mislabelled by its
    caller.
    """
    analysis = _build_analysis(
        db, req.source_id, req.data_category, req.max_events, req.include_hostnames
    )
    db.save_analysis(analysis)
    analysis.persisted = True
    analysis.is_current = True
    db.log_audit(
        action="run_descriptive_analysis",
        resource_type="descriptive_analysis",
        resource_id=analysis.analysis_id,
        details=(
            f"Computed analysis across {analysis.total_events} events for "
            f"{analysis.source_id} "
            f"(categories: {describe_breakdown(analysis.data_categories)})"
        ),
    )
    return analysis


@router.get("/latest", response_model=Optional[DescriptiveAnalysis])
def get_latest_analysis(
    source_id: Optional[str] = Query(default=None),
    recompute_if_stale: bool = Query(
        default=True,
        description=(
            "Recompute when stored events have changed since the saved analysis, "
            "so the dashboard cannot display a stale summary as current."
        ),
    ),
    db: Database = Depends(get_db),
) -> Optional[DescriptiveAnalysis]:
    """
    Retrieve the most recent descriptive analysis.

    **This route never writes.** A GET that persisted a row meant any
    browser page load, prefetch, probe or `curl` silently appended to the
    operational database, and because each recomputation minted a fresh
    `analysis_id` nothing was ever replaced (ADR-062).

    A saved analysis is a snapshot. If events have been ingested since it
    was computed, its totals no longer describe the database, so by
    default a fresh one is COMPUTED FOR THIS RESPONSE and returned with
    `persisted=False`. Persisting remains the job of POST /analysis/run.

    Set `recompute_if_stale=false` to receive the stored snapshot instead,
    flagged `is_current=False`.
    """
    analysis = db.get_latest_analysis(source_id=source_id)
    current_total = db.count_events(source_id=source_id)

    if analysis is None:
        if current_total == 0:
            return None
        # Nothing stored yet. Compute for this response and say plainly
        # that it was not saved.
        fresh = _build_analysis(db, source_id, None, 50_000, True)
        fresh.persisted = False
        fresh.is_current = True
        return fresh

    if analysis.total_events == current_total:
        analysis.persisted = True
        analysis.is_current = True
        return analysis

    # The stored snapshot has been overtaken by newer events.
    if not recompute_if_stale:
        # Return it as stored, flagged, so a caller that asked for the
        # snapshot is not misled about its currency.
        analysis.persisted = True
        analysis.is_current = False
        return analysis

    fresh = _build_analysis(db, source_id, None, 50_000, True)
    fresh.persisted = False
    fresh.is_current = True
    return fresh


@router.get("", response_model=list[DescriptiveAnalysis])
def list_analyses(db: Database = Depends(get_db)) -> list[DescriptiveAnalysis]:
    """List all stored descriptive analyses."""
    return db.list_analyses()

# ──────────────────────────────────────────────────────────────────
# Analysis history (ADR-064)
#
# An analysis is a HISTORICAL RECORD of what PraHari computed, carrying
# its own totals, provenance and measured counts — not a cache entry. So
# nothing expires it automatically: not a timer, not startup, not a read.
# Trimming it is an explicit, confirmed, audited administrative act.
# ──────────────────────────────────────────────────────────────────

ANALYSIS_PRUNE_CONFIRMATION = "DELETE_ANALYSIS_HISTORY"


class AnalysisPruneRequest(BaseModel):
    keep: int = Field(
        ...,
        ge=1,
        description=(
            "How many of the most recent analyses to KEEP. Must be at "
            "least 1: this operation trims history, it does not empty it."
        ),
    )
    source_id: Optional[str] = Field(default=None)
    confirm: Optional[str] = Field(
        default=None,
        description=(
            f"Must be exactly {ANALYSIS_PRUNE_CONFIRMATION!r} to delete. "
            "Omit for a dry run that only reports what would be removed."
        ),
    )
    reason: str = Field(default="", max_length=500)


@router.post("/prune")
def prune_analysis_history(
    req: AnalysisPruneRequest,
    db: Database = Depends(get_db),
    config: AppConfig = Depends(get_config),
    _: object = Depends(require_admin_in_central),
) -> dict:
    """
    Trim stored analysis history, keeping the most recent `keep` records.

    **Dry run by default.** Without the confirmation token nothing is
    deleted and the response reports exactly which analyses would be —
    the same preview-then-confirm shape the telemetry retention service
    uses, because this is the only operation in PraHari that deletes a
    historical record.

    Administrative in central mode; unrestricted on a loopback
    deployment, matching the rest of the API.
    """
    total = db.count_analyses(source_id=req.source_id)
    candidates = db.analyses_exceeding_limit(req.keep, source_id=req.source_id)

    if req.confirm != ANALYSIS_PRUNE_CONFIRMATION:
        return {
            "dry_run": True,
            "deleted": 0,
            "total_analyses": total,
            "keep": req.keep,
            "would_delete": len(candidates),
            "would_delete_ids": candidates[:50],
            "confirmation_required": ANALYSIS_PRUNE_CONFIRMATION,
            "note": (
                "Nothing was deleted. Re-send with the confirmation token "
                "to proceed. Analyses are historical records; this is the "
                "only operation that removes one."
            ),
        }

    deleted = db.prune_analyses(req.keep, source_id=req.source_id)
    db.log_audit(
        action="prune_analysis_history",
        resource_type="descriptive_analysis",
        resource_id=req.source_id or "all_sources",
        details=(
            f"Deleted {deleted} of {total} analyses, keeping the newest "
            f"{req.keep}" + (f"; reason={req.reason}" if req.reason else "")
        ),
    )
    return {
        "dry_run": False,
        "deleted": deleted,
        "total_analyses": db.count_analyses(source_id=req.source_id),
        "keep": req.keep,
        "configured_suggestion": config.analysis_history_limit or None,
        "note": (
            "Deleted on explicit confirmation. No automatic retention "
            "applies to analysis history."
        ),
    }
