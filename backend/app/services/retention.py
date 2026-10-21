"""
PraHari — Retention Enforcement

`retention_days` was reported but never enforced, so the store grew without
bound and the stated policy was a claim rather than a behaviour.

Deliberate design choices
-------------------------
* **Dry run is the default.** Every call reports what it *would* delete
  until `confirm=True` is passed. Deletion of collected telemetry is not
  something to trigger by accident.
* **Never automatic.** Nothing schedules this. There is no startup hook and
  no background task; an operator (or an explicit test) invokes it.
* **Scoped by policy, not by convenience.** Only event categories the
  policy names are eligible. Telemetry sources, import summaries, analyses
  and audit records are never removed by this service — an audit trail that
  deletes itself is not an audit trail.
* **Bounded and resumable.** Work proceeds in batches inside transactions,
  so an interruption leaves a consistent database with some batches
  committed rather than a half-applied delete.
* **Age is computed from `observed_at`**, the event time, in UTC. Using
  ingestion time would delete old telemetry that was imported recently.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from pydantic import BaseModel, Field

from app.schemas.events import DataCategory
from app.storage.database import Database

logger = logging.getLogger(__name__)

DEFAULT_BATCH_SIZE = 500
MAX_BATCH_SIZE = 10_000

# Categories eligible for age-based pruning by default. Test fixtures are
# excluded because they are reference data, not accumulated telemetry.
DEFAULT_ELIGIBLE_CATEGORIES: tuple[str, ...] = (
    DataCategory.LIVE_TELEMETRY.value,
    DataCategory.HISTORICAL_REPLAY.value,
    DataCategory.SYNTHETIC_DEMO.value,
)


class RetentionPolicy(BaseModel):
    """What may be removed, and from where."""
    retention_days: int = Field(..., ge=1, le=36_500)
    eligible_categories: list[str] = Field(
        default_factory=lambda: list(DEFAULT_ELIGIBLE_CATEGORIES)
    )
    # Scoping to one source lets an operator prune a single noisy sensor.
    source_id: Optional[str] = None
    batch_size: int = Field(default=DEFAULT_BATCH_SIZE, ge=1, le=MAX_BATCH_SIZE)
    # A ceiling so one invocation cannot remove the entire store.
    max_deletions: Optional[int] = Field(default=None, ge=1)

    def cutoff(self, now: Optional[datetime] = None) -> datetime:
        """
        Events observed strictly before this instant are eligible.

        Computed in UTC so a local-time clock cannot shift the boundary.
        """
        reference = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        return reference - timedelta(days=self.retention_days)


class RetentionResult(BaseModel):
    """Outcome of a retention run."""
    dry_run: bool
    executed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    cutoff: datetime
    retention_days: int
    eligible_categories: list[str]
    source_id: Optional[str] = None

    candidates: int = 0
    deleted: int = 0
    batches: int = 0
    reached_max_deletions: bool = False

    # What was examined but deliberately left alone.
    protected_categories: list[str] = Field(default_factory=list)
    retained_newer_than_cutoff: int = 0

    notes: list[str] = Field(default_factory=list)

    @property
    def would_delete(self) -> int:
        return self.candidates if self.dry_run else self.deleted


class RetentionService:
    """Age-based pruning of eligible telemetry."""

    def __init__(self, db: Database):
        self.db = db

    # ──────────────── inspection ────────────────

    def preview(
        self,
        policy: RetentionPolicy,
        now: Optional[datetime] = None,
    ) -> RetentionResult:
        """Report what a run would remove, changing nothing."""
        return self._run(policy, confirm=False, now=now)

    def enforce(
        self,
        policy: RetentionPolicy,
        now: Optional[datetime] = None,
    ) -> RetentionResult:
        """
        Delete eligible events older than the cutoff.

        Destructive. Callers must have obtained explicit operator intent.
        """
        return self._run(policy, confirm=True, now=now)

    # ──────────────── implementation ────────────────

    def _run(
        self,
        policy: RetentionPolicy,
        *,
        confirm: bool,
        now: Optional[datetime] = None,
    ) -> RetentionResult:
        cutoff = policy.cutoff(now)
        cutoff_iso = cutoff.isoformat()

        eligible = [c for c in policy.eligible_categories if c]
        if not eligible:
            raise ValueError(
                "A retention policy must name at least one eligible category; "
                "an empty list would be ambiguous between 'nothing' and 'everything'."
            )

        all_categories = {c.value for c in DataCategory}
        protected = sorted(all_categories - set(eligible))

        result = RetentionResult(
            dry_run=not confirm,
            cutoff=cutoff,
            retention_days=policy.retention_days,
            eligible_categories=eligible,
            source_id=policy.source_id,
            protected_categories=protected,
        )

        # The queries live behind the storage contract (ADR-093); the
        # policy - eligibility, budget, batching, confirmation - stays here.
        result.candidates = self.db.count_events_before(
            cutoff_iso, eligible, policy.source_id
        )
        result.retained_newer_than_cutoff = self.db.count_events_at_or_after(
            cutoff_iso, eligible, policy.source_id
        )

        if not confirm:
            result.notes.append(
                f"DRY RUN — nothing was deleted. {result.candidates} event(s) "
                f"observed before {cutoff_iso} are eligible under this policy."
            )
            if protected:
                result.notes.append(
                    "Categories NOT eligible under this policy and therefore "
                    f"untouched: {', '.join(protected)}."
                )
            return result

        budget = policy.max_deletions
        deleted_total = 0
        batches = 0

        while True:
            if budget is not None and deleted_total >= budget:
                result.reached_max_deletions = True
                break

            limit = policy.batch_size
            if budget is not None:
                limit = min(limit, budget - deleted_total)
            if limit <= 0:
                break

            # Each batch is its own transaction: an interruption leaves the
            # store consistent, with completed batches durable.
            ids = self.db.oldest_event_ids_before(
                cutoff_iso, eligible, policy.source_id, limit
            )
            if not ids:
                break
            self.db.delete_events_by_id(ids)
            deleted_total += len(ids)
            batches += 1
            logger.info(
                "Retention: deleted batch of %d (total %d)", len(ids), deleted_total
            )

        result.deleted = deleted_total
        result.batches = batches

        # Source counters are derived from storage, so refresh them rather
        # than letting them report rows that no longer exist.
        affected = (
            [policy.source_id] if policy.source_id
            else [s.source_id for s in self.db.list_sources()]
        )
        for source_id in affected:
            try:
                self.db.refresh_source_activity(source_id)
            except Exception:  # noqa: BLE001
                logger.warning("Could not refresh counters for %s", source_id)

        self.db.log_audit(
            action="enforce_retention",
            resource_type="normalized_events",
            resource_id=policy.source_id or "all_sources",
            details=(
                f"Deleted {deleted_total} event(s) older than {cutoff_iso} "
                f"in {batches} batch(es); categories={','.join(eligible)}; "
                f"retention_days={policy.retention_days}"
            ),
        )
        result.notes.append(
            f"Deleted {deleted_total} event(s) in {batches} batch(es). "
            f"Categories not covered by this policy were untouched."
        )
        if result.reached_max_deletions:
            result.notes.append(
                f"Stopped at the max_deletions ceiling ({policy.max_deletions}); "
                "older events may remain. Run again to continue."
            )
        return result
