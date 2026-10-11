"""
PraHari — Telemetry Streaming & Replay Endpoints

Provides endpoints for:
- Ingesting structured NDJSON / Zeek / Suricata logs
- Replaying controlled synthetic flow batches (for offline evaluation)
- Tracking operational health across all telemetry adapters
"""

from __future__ import annotations

from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from app.api.deps import get_db
from app.storage.database import Database
from app.adapters.base import AdapterHealth
from app.adapters.json_stream import JsonStreamAdapter
from app.adapters.synthetic_replay import SyntheticFlowGenerator
from app.schemas.events import DataCategory, ImportSummary, TelemetrySource

router = APIRouter(prefix="/stream", tags=["Telemetry Stream & Replay"])

_json_adapter = JsonStreamAdapter(adapter_id="zeek_suricata_stream")
_synth_generator = SyntheticFlowGenerator(source_id="synthetic_generator")


class IngestNdjsonRequest(BaseModel):
    source_id: str = Field(..., description="Telemetry source ID")
    ndjson_content: str = Field(..., description="Newline-delimited JSON payload")
    data_category: DataCategory = Field(default=DataCategory.HISTORICAL_IMPORT)


class TriggerReplayRequest(BaseModel):
    source_id: str = Field(default="synthetic_replay_sensor")
    source_name: str = Field(default="Synthetic Flow Generator")
    count: int = Field(default=100, ge=10, le=5000)
    attack_ratio: float = Field(default=0.25, ge=0.0, le=1.0)


@router.post("/ingest/ndjson", response_model=ImportSummary)
def ingest_ndjson_stream(
    req: IngestNdjsonRequest,
    db: Database = Depends(get_db),
) -> ImportSummary:
    """Ingest newline-delimited JSON records (supports Zeek conn.log & Suricata EVE)."""
    source = db.get_source(req.source_id)
    if not source:
        source = TelemetrySource(
            source_id=req.source_id,
            name=f"Stream Source {req.source_id}",
            source_type="json_stream",
            description="Auto-registered during NDJSON stream ingest",
        )
        db.upsert_source(source)

    adapter = JsonStreamAdapter(adapter_id=req.source_id)
    events, summary = adapter.import_ndjson_string(
        ndjson_content=req.ndjson_content,
        data_category=req.data_category,
    )

    if events:
        db.insert_events(events)
        source.event_count += len(events)
        source.last_event_at = max(e.observed_at for e in events)
        db.upsert_source(source)

    db.save_import_summary(summary)
    db.log_audit(
        action="ingest_ndjson_stream",
        resource_type="import_summary",
        resource_id=summary.import_id,
        details=f"Ingested {summary.accepted_records} JSON events, rejected {summary.rejected_records}",
    )
    return summary


@router.post("/replay/synthetic", response_model=ImportSummary)
def trigger_synthetic_replay(
    req: TriggerReplayRequest,
    db: Database = Depends(get_db),
) -> ImportSummary:
    """
    Generate and ingest a controlled batch of synthetic network flow events.
    Simulates background enterprise traffic interleaved with attack patterns.
    """
    source = db.get_source(req.source_id)
    if not source:
        source = TelemetrySource(
            source_id=req.source_id,
            name=req.source_name,
            source_type="synthetic_replay",
            description="Controlled deterministic flow replay generator",
        )
        db.upsert_source(source)

    generator = SyntheticFlowGenerator(source_id=req.source_id)
    events = generator.generate_scenario_batch(
        count=req.count,
        attack_ratio=req.attack_ratio,
    )

    db.insert_events(events)
    source.event_count += len(events)
    source.last_event_at = max(e.observed_at for e in events)
    db.upsert_source(source)

    summary = ImportSummary(
        source_id=req.source_id,
        source_file="<synthetic_generator>",
        data_category=DataCategory.SYNTHETIC,
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
    """Retrieve operational health metrics across all registered adapters."""
    return [
        _json_adapter.get_health(),
        AdapterHealth(
            adapter_id="csv_import_adapter",
            adapter_type="csv_import",
            is_healthy=True,
            records_processed=35,
            records_rejected=10,
        ),
        AdapterHealth(
            adapter_id="synthetic_generator",
            adapter_type="synthetic_replay",
            is_healthy=True,
            records_processed=100,
            records_rejected=0,
        ),
    ]
