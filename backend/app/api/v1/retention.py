"""
PraHari — Retention API

Age-based pruning of eligible telemetry.

Deleting collected telemetry is irreversible, so enforcement requires an
explicit confirmation token in the request body. A preview is always
available and changes nothing.
"""

from __future__ import annotations

import logging

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from app.api.auth import require_admin_in_central
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

logger = logging.getLogger(__name__)

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


RETENTION_DAYS_KEY = "retention_days"
MIN_RETENTION_DAYS = 1
MAX_RETENTION_DAYS = 36_500  # a century; beyond this the value is a mistake


class RetentionPolicyUpdate(BaseModel):
    """An operator's override of the configured retention period."""

    retention_days: Optional[int] = Field(
        default=None,
        ge=MIN_RETENTION_DAYS,
        le=MAX_RETENTION_DAYS,
        description=(
            "Days of telemetry to keep. Omit (null) to clear the override "
            "and fall back to the configured default."
        ),
    )
    reason: str = Field(default="", max_length=500)


def effective_retention_days(db: Database, config: AppConfig) -> tuple[int, str]:
    """
    The retention period actually in force, and where it came from.

    Precedence is explicit and reported: a stored operator override beats
    the configured default. An unreadable override is ignored rather than
    guessed at, so a corrupt row cannot silently shorten retention — the
    direction that destroys data.
    """
    raw = db.get_setting(RETENTION_DAYS_KEY)
    if raw is None:
        return config.retention_days, "configured_default"
    try:
        value = int(raw)
    except (TypeError, ValueError):
        logger.error(
            "Stored retention override %r is not an integer; using the "
            "configured default instead.", raw,
        )
        return config.retention_days, "configured_default_override_unreadable"
    if not (MIN_RETENTION_DAYS <= value <= MAX_RETENTION_DAYS):
        logger.error(
            "Stored retention override %d is out of range; using the "
            "configured default instead.", value,
        )
        return config.retention_days, "configured_default_override_out_of_range"
    return value, "operator_override"


@router.put("/policy")
def update_policy(
    req: RetentionPolicyUpdate,
    db: Database = Depends(get_db),
    config: AppConfig = Depends(get_config),
    _: object = Depends(require_admin_in_central),
) -> dict:
    """
    Set or clear the retention-period override.

    **Changes a policy. Deletes nothing.** Pruning still happens only when
    an operator calls POST /retention/enforce with its confirmation token,
    so shortening retention here cannot destroy data as a side effect —
    which is why this endpoint and enforcement stay separate.

    Administrative in central mode; unrestricted on a loopback
    deployment, matching the rest of the API.
    """
    previous, previous_origin = effective_retention_days(db, config)

    if req.retention_days is None:
        cleared = db.clear_setting(RETENTION_DAYS_KEY)
        action_detail = (
            f"cleared override (was {previous} via {previous_origin}); "
            f"configured default {config.retention_days} now applies"
        )
    else:
        db.set_setting(RETENTION_DAYS_KEY, str(req.retention_days))
        cleared = False
        action_detail = f"retention_days {previous} -> {req.retention_days}"

    db.log_audit(
        action="update_retention_policy",
        resource_type="configuration",
        resource_id=RETENTION_DAYS_KEY,
        details=action_detail + (f"; reason={req.reason}" if req.reason else ""),
    )

    # Re-read rather than echoing the request: the response must describe
    # what was persisted, not what was asked for.
    effective, origin = effective_retention_days(db, config)
    return {
        "retention_days": effective,
        "origin": origin,
        "configured_default": config.retention_days,
        "override_cleared": cleared,
        "previous_retention_days": previous,
        "note": (
            "Policy only. No record was deleted by this call; enforcement "
            "remains a separate, confirmed operation."
        ),
    }


@router.get("/policy")
def get_policy(
    db: Database = Depends(get_db),
    config: AppConfig = Depends(get_config),
) -> dict:
    """Report the configured retention policy and how it is applied."""
    effective, origin = effective_retention_days(db, config)
    return {
        "retention_days": effective,
        "origin": origin,
        "configured_default": config.retention_days,
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
