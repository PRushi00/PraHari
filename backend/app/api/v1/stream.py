"""
PraHari — Telemetry Streaming & Replay Endpoints

Provides endpoints for:
- Ingesting structured NDJSON / Zeek / Suricata logs
- Replaying controlled synthetic flow batches (for offline evaluation)
- Tracking operational health across all telemetry adapters
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional
from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, status
from pydantic import BaseModel, Field

from app.api.auth import resolve_ingest_source
from app.services.admission import (
    IngestionOverloaded,
    get_admission_controller,
)
from app.api.deps import get_db
from app.storage.database import Database, EventIdentityConflictError
from app.adapters.base import AdapterHealth, get_adapter_registry
from app.adapters.json_stream import JsonStreamAdapter
from app.adapters.synthetic_replay import SyntheticFlowGenerator
from app.schemas.events import DataCategory, ImportSummary, TelemetrySource

router = APIRouter(prefix="/stream", tags=["Telemetry Stream & Replay"])

_synth_generator = SyntheticFlowGenerator(source_id="synthetic_generator")


class IngestNdjsonRequest(BaseModel):
    source_id: str = Field(..., description="Telemetry source ID")
    ndjson_content: str = Field(..., description="Newline-delimited JSON payload")
    data_category: DataCategory = Field(default=DataCategory.HISTORICAL_IMPORT)
    idempotency_key: Optional[str] = Field(
        default=None,
        description="Optional sender-provided batch idempotency key for safe retries.",
    )


class TriggerReplayRequest(BaseModel):
    source_id: str = Field(default="synthetic_replay_sensor")
    source_name: str = Field(default="Synthetic Flow Generator")
    count: int = Field(default=100, ge=10, le=5000)
    attack_ratio: float = Field(default=0.25, ge=0.0, le=1.0)


@router.post("/ingest/ndjson", response_model=ImportSummary)
def ingest_ndjson_stream(
    req: IngestNdjsonRequest,
    request: Request,
    idempotency_key_header: Optional[str] = Header(default=None, alias="Idempotency-Key"),
    x_idempotency_key_header: Optional[str] = Header(default=None, alias="X-Idempotency-Key"),
    db: Database = Depends(get_db),
) -> ImportSummary:
    """Ingest newline-delimited JSON records (supports Zeek conn.log & Suricata EVE)."""
    # Receipt time, captured at the API boundary — the first point at which
    # this backend can attest to anything. Taken BEFORE parsing so a large
    # or slow batch does not push the recorded receipt later than the actual
    # arrival. The client cannot supply or influence it: there is no such
    # field on IngestNdjsonRequest.
    received_at = datetime.now(timezone.utc)
    idempotency_key = req.idempotency_key or idempotency_key_header or x_idempotency_key_header

    # The authenticated identity, not the request body, decides where this
    # telemetry is filed. Resolved BEFORE anything is parsed or registered,
    # and used for every subsequent step — including the adapter id, which
    # is the idempotency namespace (ADR-050).
    source_id = resolve_ingest_source(request, req.source_id)

    # Bounded admission (blueprint §6). Reserved BEFORE parsing, so a
    # flood of large bodies cannot all be normalized into memory at once.
    # Rejected immediately rather than buffered: ingestion is synchronous
    # and the response reports what was actually stored, so queueing here
    # would answer the caller before the data is durable.
    controller = get_admission_controller()
    try:
        admission = controller.admit()
    except IngestionOverloaded as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            headers={"Retry-After": "1"},
            detail={
                "error": "ingestion_overloaded",
                "message": (
                    "Too much ingestion is already in flight. Nothing was "
                    "stored; retry this batch."
                ),
                "in_flight": exc.in_flight,
                "capacity": exc.capacity,
                "stored_records": 0,
            },
        ) from exc

    with admission:
        return _ingest_ndjson_admitted(
            req=req,
            db=db,
            source_id=source_id,
            received_at=received_at,
            idempotency_key=idempotency_key,
            controller=controller,
            admission=admission,
        )


def _ingest_ndjson_admitted(
    *, req, db, source_id, received_at, idempotency_key, controller, admission
) -> ImportSummary:
    """
    The ingest body, running inside an admission slot.

    Split out so the slot is held for exactly the work it bounds, and
    released by the context manager however this returns or raises.
    """
    source = db.get_source(source_id)
    if not source:
        source = TelemetrySource(
            source_id=source_id,
            name=f"Stream Source {source_id}",
            source_type="json_stream",
            description="Auto-registered during NDJSON stream ingest",
        )
        db.upsert_source(source)

    adapter = get_adapter_registry().get_or_register(
        source_id,
        lambda: JsonStreamAdapter(adapter_id=source_id),
    )
    events, summary = adapter.import_ndjson_string(
        ndjson_content=req.ndjson_content,
        data_category=req.data_category,
        idempotency_key=idempotency_key,
    )

    for event in events:
        # Stamped after normalization because the adapter constructs the
        # objects, but with the time captured at the boundary above.
        event.received_at = received_at

    stored = 0
    if events:
        try:
            stored = db.insert_events(events)
        except EventIdentityConflictError as exc:
            # The whole batch rolled back (get_connection rolls back on any
            # exception), so nothing from this request was written. Record
            # the refusal: a 409 that leaves no trace is indistinguishable
            # from a request that never arrived.
            controller.record_failure("conflict")
            db.log_audit(
                action="ingest_ndjson_stream_conflict",
                resource_type="telemetry_source",
                resource_id=source_id,
                details=f"Rejected {len(events)} event(s), nothing stored: {exc}",
            )
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "error": "event_identity_conflict",
                    "message": str(exc),
                    "source_id": source_id,
                    "stored_records": 0,
                },
            ) from exc

    # What parsed is not what was written. A retry parses perfectly and
    # stores nothing, and the caller is entitled to know which happened.
    #
    # Recorded on EVERY path (ADR-068), including a batch in which every
    # record was rejected. That case used to skip this block entirely, so
    # the response said "not reported" for a count that was measured -
    # zero - and the rejections never reached /system/health. A sensor
    # whose every record fails validation is the failure an operator most
    # needs to see, and it was the one health could not show.
    summary.stored_records = stored
    summary.duplicate_records = len(events) - stored
    controller.record_batch(
        stored=stored,
        duplicates=len(events) - stored,
        rejected=summary.rejected_records,
        elapsed_ms=admission.elapsed_ms(),
    )

    if events:
        db.refresh_source_activity(
            source_id,
            last_event_at=max(e.observed_at for e in events),
            status="active",
        )

    db.save_import_summary(summary)
    db.log_audit(
        action="ingest_ndjson_stream",
        resource_type="import_summary",
        resource_id=summary.import_id,
        details=(
            f"Accepted {summary.accepted_records} JSON events "
            f"(stored {summary.stored_records}, "
            f"duplicates {summary.duplicate_records}), "
            f"rejected {summary.rejected_records}"
        ),
    )
    return summary


@router.post("/replay/synthetic", response_model=ImportSummary)
def trigger_synthetic_replay(
    req: TriggerReplayRequest,
    request: Request,
    db: Database = Depends(get_db),
) -> ImportSummary:
    """
    Generate and ingest a controlled batch of synthetic network flow events.
    Simulates background enterprise traffic interleaved with attack patterns.
    """
    # Replay writes events like any other path, so it is scoped the same way.
    source_id = resolve_ingest_source(request, req.source_id)

    source = db.get_source(source_id)
    if not source:
        source = TelemetrySource(
            source_id=source_id,
            name=req.source_name,
            source_type="synthetic_replay",
            description="Controlled deterministic flow replay generator",
        )
        db.upsert_source(source)

    started_at = datetime.now(timezone.utc)
    generator = SyntheticFlowGenerator(source_id=source_id)
    events = generator.generate_scenario_batch(
        count=req.count,
        attack_ratio=req.attack_ratio,
    )

    db.insert_events(events)
    db.refresh_source_activity(
        source_id,
        last_event_at=max(e.observed_at for e in events),
        status="active",
    )

    # Every other ingestion path records both ends of the operation; this
    # one did not, so the summary reported no completion time and elapsed
    # duration was unavailable downstream.
    summary = ImportSummary(
        source_id=source_id,
        source_file="<synthetic_generator>",
        data_category=DataCategory.SYNTHETIC,
        started_at=started_at,
        completed_at=datetime.now(timezone.utc),
        total_records=req.count,
        accepted_records=len(events),
        rejected_records=0,
        warnings_count=0,
        rejection_reasons={},
    )
    db.save_import_summary(summary)
    db.log_audit(
        action="trigger_synthetic_replay",
        resource_type="import_summary",
        resource_id=summary.import_id,
        details=f"Generated {len(events)} synthetic events with attack_ratio={req.attack_ratio}",
    )
    return summary


@router.get("/adapters", response_model=list[AdapterHealth])
def get_adapters_health() -> list[AdapterHealth]:
    """
    Retrieve operational health for adapters that have actually run.

    Figures come from the live adapter registry. An adapter that has not been
    exercised in this process is absent rather than reported with placeholder
    counters, so an empty list genuinely means "nothing has ingested yet".
    """
    return get_adapter_registry().health_report()
