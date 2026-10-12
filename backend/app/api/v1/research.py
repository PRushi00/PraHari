"""
PraHari — Research Feasibility API Endpoints

Provides endpoints to audit datasets against scientific guardrails
prior to allowing predictive forecasting models.
"""

from __future__ import annotations

from typing import Optional
from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel

from app.api.deps import get_db
from app.storage.database import Database
from app.research.feasibility import FeasibilityReport, audit_dataset_feasibility

router = APIRouter(prefix="/research", tags=["Research Feasibility"])

_latest_report: Optional[FeasibilityReport] = None


class AuditRequest(BaseModel):
    """Optional scoping for an audit run."""
    source_id: Optional[str] = None


@router.post("/audit", response_model=FeasibilityReport)
def run_dataset_audit(
    source_id: Optional[str] = Query(default=None, description="Optional source ID to scope audit"),
    body: Optional[AuditRequest] = None,
    db: Database = Depends(get_db),
) -> FeasibilityReport:
    """
    Execute the Research Feasibility Audit on persisted events.
    Audits temporal order, label distribution, provenance, and quality flags.
    """
    global _latest_report
    # Accept the scope from either the query string or a JSON body: the
    # dashboard sends it in the body, so a query-only signature silently
    # ignored the requested scope and audited every source instead.
    if source_id is None and body is not None:
        source_id = body.source_id
    events = db.list_events(source_id=source_id, limit=50_000)
    dataset_name = source_id or "all_persisted_telemetry"
    report = audit_dataset_feasibility(events, dataset_id=dataset_name)
    _latest_report = report
    db.log_audit(
        action="run_research_feasibility_audit",
        resource_type="feasibility_report",
        resource_id=dataset_name,
        details=f"Audit completed: score={report.overall_score}, passed={report.gate_passed}, rec={report.recommendation}",
    )
    return report


@router.get("/audit", response_model=Optional[FeasibilityReport])
def get_latest_audit(
    source_id: Optional[str] = Query(default=None),
    db: Database = Depends(get_db),
) -> Optional[FeasibilityReport]:
    """Retrieve the latest feasibility audit or run one if not yet computed."""
    global _latest_report
    if _latest_report is None:
        events = db.list_events(source_id=source_id, limit=50_000)
        if events:
            _latest_report = audit_dataset_feasibility(events, dataset_id=source_id or "all_persisted_telemetry")
    return _latest_report
