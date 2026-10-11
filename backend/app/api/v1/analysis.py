"""
PraHari — Descriptive Analysis API Endpoints
"""

from __future__ import annotations

from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from app.api.deps import get_db
from app.storage.database import Database
from app.services.analysis import compute_descriptive_analysis
from app.schemas.events import DescriptiveAnalysis, DataCategory

router = APIRouter(prefix="/analysis", tags=["Descriptive Analysis"])


class RunAnalysisRequest(BaseModel):
    source_id: Optional[str] = Field(default=None, description="Source ID to analyze, or omit for all sources")
    data_category: DataCategory = Field(default=DataCategory.HISTORICAL_IMPORT)
    max_events: int = Field(default=50_000, ge=1, le=100_000)


@router.post("/run", response_model=DescriptiveAnalysis)
def run_analysis(
    req: RunAnalysisRequest,
    db: Database = Depends(get_db),
) -> DescriptiveAnalysis:
    """
    Compute descriptive historical analysis on persisted events.
    Factual summary only — NOT forecasting.
    """
    events = db.list_events(source_id=req.source_id, limit=req.max_events)
    target_source_id = req.source_id or "all_sources"
    analysis = compute_descriptive_analysis(
        events=events,
        source_id=target_source_id,
        data_category=req.data_category,
    )
    db.save_analysis(analysis)
    db.log_audit(
        action="run_descriptive_analysis",
        resource_type="descriptive_analysis",
        resource_id=analysis.analysis_id,
        details=f"Computed analysis across {analysis.total_events} events for {target_source_id}",
    )
    return analysis


@router.get("/latest", response_model=Optional[DescriptiveAnalysis])
def get_latest_analysis(
    source_id: Optional[str] = Query(default=None),
    db: Database = Depends(get_db),
) -> Optional[DescriptiveAnalysis]:
    """Retrieve the most recently computed descriptive analysis."""
    analysis = db.get_latest_analysis(source_id=source_id)
    if not analysis:
        # If no saved analysis exists yet, but events do exist, compute one on the fly!
        events = db.list_events(source_id=source_id, limit=50000)
        if events:
            analysis = compute_descriptive_analysis(
                events=events,
                source_id=source_id or "all_sources",
            )
            db.save_analysis(analysis)
    return analysis


@router.get("", response_model=list[DescriptiveAnalysis])
def list_analyses(db: Database = Depends(get_db)) -> list[DescriptiveAnalysis]:
    """List all historical descriptive analyses."""
    return db.list_analyses()
