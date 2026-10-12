"""
PraHari — Retention API

Age-based pruning of eligible telemetry.

Deleting collected telemetry is irreversible, so enforcement requires an
explicit confirmation token in the request body. A preview is always
available and changes nothing.
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from app.api.deps import get_db
from app.core.config import AppConfig, get_config
from app.services.retention import (
    DEFAULT_ELIGIBLE_CATEGORIES,
    MAX_BATCH_SIZE,
    RetentionPolicy,
    RetentionResult,
    RetentionService,
)
from app.storage.database import Database

router = APIRouter(prefix="/retention", tags=["Retention"])

# Required verbatim to enforce. A boolean flag is too easy to set by
# accident in a client, a script, or a half-written request.
CONFIRMATION_TOKEN = "DELETE-EXPIRED-TELEMETRY"


class RetentionRequest(BaseModel):
    retention_days: Optional[int] = Field(
        default=None, ge=1, le=36_500,
        description="Overrides the configured retention_days for this run.",
    )
    eligible_categories: Optional[list[str]] = Field(
        default=None,
        description="Data categories eligible for pruning. Defaults to live, replay and synthetic.",
    )
    source_id: Optional[str] = Field(
        default=None, description="Restrict pruning to one telemetry source."
    )
    batch_size: int = Field(default=500, ge=1, le=MAX_BATCH_SIZE)
    max_deletions: Optional[int] = Field(
        default=None, ge=1, description="Ceiling on deletions for this run."
    )


class EnforceRequest(RetentionRequest):
    confirm: str = Field(
        ...,
        description=f"Must be exactly {CONFIRMATION_TOKEN!r} to proceed.",
    )


def _policy(req: RetentionRequest, config: AppConfig) -> RetentionPolicy:
    return RetentionPolicy(
        retention_days=req.retention_days or config.retention_days,
        eligible_categories=req.eligible_categories or list(DEFAULT_ELIGIBLE_CATEGORIES),
        source_id=req.source_id,
        batch_size=req.batch_size,
        max_deletions=req.max_deletions,
    )


@router.get("/policy")
def get_policy(config: AppConfig = Depends(get_config)) -> dict:
    """Report the configured retention policy and how it is applied."""
    return {
        "retention_days": config.retention_days,
        "default_eligible_categories": list(DEFAULT_ELIGIBLE_CATEGORIES),
        "enforcement": "manual",
        "automatic_pruning": False,
        "confirmation_required": True,
        "notes": [
            "Retention is NOT enforced automatically: no scheduler, no startup hook.",
            "An operator must call POST /retention/enforce with the confirmation token.",
            "Age is measured from observed_at (event time) in UTC, not ingestion time.",
            "Telemetry sources, import summaries, analyses and audit records are never pruned by this service.",
            "Test fixtures are excluded from the default eligible categories.",
        ],
    }


@router.post("/preview", response_model=RetentionResult)
def preview_retention(
    req: RetentionRequest,
    db: Database = Depends(get_db),
    config: AppConfig = Depends(get_config),
) -> RetentionResult:
    """Report what enforcement would remove. Changes nothing."""
    try:
        return RetentionService(db).preview(_policy(req, config))
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": "invalid_retention_policy", "message": str(exc)},
        )


@router.post("/enforce", response_model=RetentionResult)
def enforce_retention(
    req: EnforceRequest,
    db: Database = Depends(get_db),
    config: AppConfig = Depends(get_config),
) -> RetentionResult:
    """
    Delete eligible telemetry older than the retention cutoff.

    Irreversible. Requires the exact confirmation token.
    """
    if req.confirm != CONFIRMATION_TOKEN:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "confirmation_required",
                "message": (
                    "Retention enforcement permanently deletes telemetry and "
                    f"requires confirm={CONFIRMATION_TOKEN!r}. "
                    "Use POST /retention/preview to see what would be removed."
                ),
            },
        )

    try:
        return RetentionService(db).enforce(_policy(req, config))
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": "invalid_retention_policy", "message": str(exc)},
        )
