"""
PraHari — Application-Layer Telemetry Ingestion (opt-in, disabled by default)

Accepts HTTP request metadata from an **authorized producer that the
operator runs themselves** — for example a browser extension they install,
or a local inspection proxy they configure deliberately.

What PraHari does and does not do
---------------------------------
PraHari provides the *receiving* half only. It never:

  * configures a system or browser proxy,
  * installs or trusts a root certificate,
  * decrypts TLS,
  * changes browser security settings,
  * captures packets, or
  * requires elevated privileges.

Those steps belong to the producer and need the operator's explicit,
separate decision. Until a producer exists and this endpoint is enabled, no
HTTP data enters PraHari and the dashboard shows application-layer fields as
unavailable.

Privacy
-------
Only request *metadata* is accepted. Bodies, cookies, authorization headers
and credentials are not fields of the accepted payload at all, so they
cannot be stored even by mistake. Query strings are stripped unless the
operator sets ``PRAHARI_APPLAYER_RETAIN_QUERY_STRINGS=true``, because they
routinely carry search terms, tokens and identifiers.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field, field_validator

from app.api.deps import get_db
from app.core.config import AppConfig, get_config
from app.schemas.events import (
    SCHEMA_VERSION,
    DataCategory,
    EventType,
    ImportSummary,
    LabelProvenance,
    NormalizedEvent,
    QualityFlag,
    TelemetrySource,
)
from app.storage.database import Database

router = APIRouter(prefix="/applayer", tags=["Application-Layer Telemetry"])

APPLAYER_SOURCE_TYPE = "application_layer"

# Rejected outright rather than stripped, so a misconfigured producer fails
# loudly instead of quietly shipping secrets that PraHari then discards.
_FORBIDDEN_FIELDS = (
    "body", "request_body", "response_body", "cookies", "cookie",
    "authorization", "auth_header", "headers", "credentials", "token",
    "password", "set_cookie",
)


class HttpRequestRecord(BaseModel):
    """
    One observed HTTP request, as reported by an authorized producer.

    The schema deliberately has no field for a body, header set, cookie or
    credential.
    """
    model_config = {"extra": "forbid"}

    observed_at: datetime = Field(..., description="When the request was issued")
    method: str = Field(..., max_length=16)
    url: str = Field(..., max_length=2048, description="Request URL; query string stripped unless retained")
    status_code: Optional[int] = Field(default=None, ge=100, le=599)
    duration_ms: Optional[float] = Field(default=None, ge=0)
    dst_ip: Optional[str] = Field(default=None, max_length=64)
    dst_port: Optional[int] = Field(default=None, ge=0, le=65535)
    process_name: Optional[str] = Field(default=None, max_length=128)

    @field_validator("method")
    @classmethod
    def _upper_method(cls, v: str) -> str:
        return v.strip().upper()


class AppLayerIngestRequest(BaseModel):
    source_id: str = Field(default="application_layer_probe", min_length=1, max_length=128)
    source_name: str = Field(default="Application-Layer Probe (operator-configured)")
    producer: str = Field(
        ...,
        min_length=1,
        max_length=128,
        description="Identifies the producer, e.g. 'browser-extension' or 'local-proxy'.",
    )
    records: list[HttpRequestRecord] = Field(..., max_length=5000)

    @field_validator("source_id")
    @classmethod
    def _must_be_identifiable(cls, v: str) -> str:
        # Keeps app-layer data from masquerading as the TCP collector's source.
        if v == "windows_local_host":
            raise ValueError(
                "Application-layer telemetry must not reuse the connection "
                "collector's source id; it is a different source with "
                "different capabilities."
            )
        return v


def _require_enabled(config: AppConfig) -> None:
    if not config.enable_application_layer_ingest:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "application_layer_ingest_disabled",
                "message": (
                    "Application-layer telemetry ingestion is disabled. It is "
                    "opt-in because it requires an operator-configured producer "
                    "(a browser extension or a local inspection proxy), which "
                    "has privacy and trust implications PraHari will not assume."
                ),
                "how_to_enable": "Set PRAHARI_ENABLE_APPLICATION_LAYER_INGEST=true and restart.",
                "note": (
                    "Enabling this endpoint does not itself capture anything. "
                    "PraHari never configures a proxy, installs a certificate, "
                    "or decrypts TLS."
                ),
            },
        )


def _sanitize_url(url: str, retain_query: bool) -> tuple[str, Optional[str], list[str]]:
    """
    Split a URL into (host, path, warnings), stripping the query by default.

    Query strings carry search terms, session identifiers and tokens far
    more often than they carry anything a connection analysis needs.
    """
    warnings: list[str] = []
    try:
        parts = urlsplit(url)
    except ValueError:
        return "", None, ["unparseable_url"]

    host = (parts.hostname or "").lower()
    path = parts.path or "/"
    if parts.query:
        if retain_query:
            path = f"{path}?{parts.query}"
            warnings.append("query_string_retained_by_operator_configuration")
        else:
            warnings.append("query_string_stripped")
    return host, path, warnings


@router.get("/status")
def get_applayer_status(config: AppConfig = Depends(get_config)) -> dict:
    """Report whether application-layer ingestion is enabled, and its terms."""
    return {
        "enabled": config.enable_application_layer_ingest,
        "retain_query_strings": config.applayer_retain_query_strings,
        "source_type": APPLAYER_SOURCE_TYPE,
        "accepted_fields": [
            "observed_at", "method", "url", "status_code", "duration_ms",
            "dst_ip", "dst_port", "process_name",
        ],
        "never_accepted": list(_FORBIDDEN_FIELDS),
        "producer_required": True,
        "notes": [
            "PraHari receives application-layer metadata; it never captures it.",
            "No proxy is configured, no certificate installed, no TLS decrypted.",
            "A producer must be configured by the operator as a separate, explicit decision.",
            "Query strings are stripped unless explicitly retained by configuration.",
            "The Windows connection-table collector is NOT an HTTP source and never populates these fields.",
        ],
    }


@router.post("/ingest", response_model=ImportSummary)
def ingest_application_layer(
    req: AppLayerIngestRequest,
    db: Database = Depends(get_db),
    config: AppConfig = Depends(get_config),
) -> ImportSummary:
    """Ingest HTTP request metadata from an authorized producer."""
    _require_enabled(config)

    source = db.get_source(req.source_id)
    if source is None:
        source = TelemetrySource(
            source_id=req.source_id,
            name=req.source_name,
            source_type=APPLAYER_SOURCE_TYPE,
            description=(
                f"Operator-configured application-layer producer: {req.producer}. "
                "Reports HTTP request metadata only; no bodies, cookies or credentials."
            ),
        )
        db.upsert_source(source)

    summary = ImportSummary(
        source_id=req.source_id,
        source_file=f"<applayer:{req.producer}>",
        data_category=DataCategory.LIVE_TELEMETRY,
    )

    events: list[NormalizedEvent] = []
    rejection_reasons: dict[str, int] = {}
    warnings_count = 0

    for idx, rec in enumerate(req.records, start=1):
        host, path, warnings = _sanitize_url(rec.url, config.applayer_retain_query_strings)
        if not host:
            rejection_reasons["unparseable_or_hostless_url"] = (
                rejection_reasons.get("unparseable_or_hostless_url", 0) + 1
            )
            continue

        observed_at = rec.observed_at
        if observed_at.tzinfo is None:
            observed_at = observed_at.replace(tzinfo=timezone.utc)

        quality_flags = [QualityFlag.SOURCE_LIMITED]
        if warnings:
            warnings_count += 1

        # Deterministic id so a producer retrying a batch cannot duplicate it.
        fingerprint = hashlib.sha256(
            "|".join([
                req.source_id, rec.method, host, path or "",
                observed_at.isoformat(), str(rec.status_code),
            ]).encode("utf-8")
        ).hexdigest()

        events.append(
            NormalizedEvent(
                event_id=f"{fingerprint[0:8]}-{fingerprint[8:12]}-{fingerprint[12:16]}"
                         f"-{fingerprint[16:20]}-{fingerprint[20:32]}",
                schema_version=SCHEMA_VERSION,
                source_id=req.source_id,
                data_category=DataCategory.LIVE_TELEMETRY,
                observed_at=observed_at,
                event_type=EventType.HTTP_REQUEST,
                dst_ip=rec.dst_ip,
                dst_port=rec.dst_port,
                protocol="TCP",
                app_protocol="HTTPS" if rec.url.lower().startswith("https://") else "HTTP",
                http_method=rec.method,
                http_path=path,
                http_status_code=rec.status_code,
                http_duration_ms=rec.duration_ms,
                # Reported by the producer, which knows the requested host —
                # this is a report, not a DNS inference.
                dst_hostname=host,
                label=None,
                label_provenance=LabelProvenance.UNLABELED,
                quality_flags=quality_flags,
                raw_reference=(
                    f"applayer:{req.producer}"
                    + (f";process={rec.process_name}" if rec.process_name else "")
                ),
            )
        )

    inserted = db.insert_events(events) if events else 0
    if events:
        db.refresh_source_activity(
            req.source_id,
            last_event_at=max(e.observed_at for e in events),
            status="active",
        )

    summary.total_records = len(req.records)
    summary.accepted_records = len(events)
    summary.rejected_records = len(req.records) - len(events)
    summary.warnings_count = warnings_count
    summary.rejection_reasons = rejection_reasons
    summary.completed_at = datetime.now(timezone.utc)

    db.save_import_summary(summary)
    db.log_audit(
        action="ingest_application_layer",
        resource_type="import_summary",
        resource_id=summary.import_id,
        details=(
            f"Producer '{req.producer}': {summary.accepted_records} accepted, "
            f"{inserted} newly persisted, {summary.rejected_records} rejected"
        ),
    )
    return summary
