"""
PraHari — Domain Enrichment API Endpoints

Hostname attribution for destination addresses, always returned together
with the evidence that supports it and the limits of that evidence.

Nothing here modifies a connection record: enrichment is computed alongside
events and can be ignored entirely.
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from app.api.auth import require_admin_in_central
from app.services.dns_collector import (
    MAX_INTERVAL_SECONDS,
    MIN_INTERVAL_SECONDS,
    DnsCollectorStatus,
    get_dns_collector,
)
from app.api.deps import get_db
from app.schemas.events import DomainAttribution
from app.services.enrichment import (
    diagnose_dns_visibility,
    get_enrichment_service,
    windows_only_dns_message,
)
from app.storage.database import Database

router = APIRouter(prefix="/enrichment", tags=["Domain Enrichment"])


class DnsEventCollectResult(BaseModel):
    """
    What a read of the DNS-Client event log yielded, and what it refused.

    Every counter is reported, including the records this adapter does
    not interpret, so a partial read is never presented as a complete
    one (ADR-120).
    """

    succeeded: bool
    error: Optional[str] = None
    records_read: int = 0
    successful_records: int = 0
    observations_recorded: int = 0
    skipped_failed_query: int = 0
    skipped_no_results: int = 0
    skipped_malformed: int = 0
    uninterpreted_by_event_id: dict[str, int] = {}
    notes: list[str] = []
    collected_at: Optional[str] = None


class DnsRefreshResult(BaseModel):
    succeeded: bool
    error: Optional[str] = None
    entries_read: int = 0
    address_records: int = 0
    skipped_non_address_records: int = 0
    observations_recorded: int = 0
    refreshed_at: Optional[str] = None
    cache_appears_unavailable: bool = False
    diagnosis: Optional[str] = None


class DnsObservationItem(BaseModel):
    hostname: str
    observed_at: str
    method: str
    ttl_seconds: Optional[int] = None


class IpAttributionResponse(BaseModel):
    ip_address: str
    attribution: DomainAttribution
    observations: list[DnsObservationItem] = Field(default_factory=list)


@router.get("/status")
def get_enrichment_status(db: Database = Depends(get_db)) -> dict:
    """
    Report enrichment coverage, method and limits.

    Includes an explicit diagnosis when the local DNS cache yields nothing,
    so an empty result is not mistaken for "this host contacted no domains".
    """
    return get_enrichment_service(db).status()


@router.get("/dns/diagnose")
def diagnose_dns(db: Database = Depends(get_db)) -> dict:
    """
    Explain why local DNS evidence is or is not available on this host.

    Read-only: inspects resolver configuration and cache occupancy. It
    changes nothing, flushes nothing, and sends no DNS query. Needed
    because an empty cache alone does not distinguish "this host resolves
    names in a way PraHari cannot observe" from "PraHari is failing to read
    something that is there".

    Windows only: elsewhere it answers in the same shape, stating so,
    without spawning PowerShell.
    """
    if sys.platform != "win32":
        message = windows_only_dns_message()
        return {
            "checked_at": datetime.now(timezone.utc).isoformat(),
            "cache_entries": 0,
            "likely_causes": [],
            "conclusion": message,
            "error": message,
        }
    return diagnose_dns_visibility()


@router.post("/dns/refresh", response_model=DnsRefreshResult)
def refresh_dns_observations(db: Database = Depends(get_db)) -> DnsRefreshResult:
    """
    Snapshot the local Windows DNS client cache into the observation store.

    Sends no DNS queries and contacts no external service — it reads answers
    this machine already received. Off Windows it reports `succeeded:
    false` with the reason, and spawns nothing.
    """
    return DnsRefreshResult(**get_enrichment_service(db).refresh_from_dns_cache())


class DnsObservationRow(BaseModel):
    """One recorded resolution, with the evidence that produced it."""

    ip_address: str
    hostname: str
    observed_at: str
    method: str
    ttl_seconds: Optional[int] = None
    source_id: Optional[str] = None


class DnsObservationsPage(BaseModel):
    total_stored: int
    returned: int
    observations: list[DnsObservationRow] = []
    method_filter: Optional[str] = None
    note: str = ""


@router.get("/dns/observations", response_model=DnsObservationsPage)
def list_dns_observations(
    limit: int = Query(100, ge=1, le=1000),
    method: Optional[str] = Query(
        None,
        description=(
            "Filter by evidence source, e.g. `dns_query_log` or "
            "`dns_cache_observation`. They are different kinds of evidence "
            "and are not merged."
        ),
    ),
    db: Database = Depends(get_db),
) -> DnsObservationsPage:
    """
    The DNS resolutions PraHari has recorded, newest first (ADR-122).

    Each row carries the address, the name, when it was observed and
    **which evidence source produced it**. A hostname without its
    address and method is not evidence of anything, so none of the three
    is omitted.

    This is the store, not a live query: it reports what was collected,
    and an empty result means nothing has been collected — not that this
    host resolved nothing. `/dns/diagnose` explains which.
    """
    rows = db.recent_dns_observations(limit=limit, method=method)
    total = db.count_dns_observations()
    return DnsObservationsPage(
        total_stored=total,
        returned=len(rows),
        observations=[DnsObservationRow(**r) for r in rows],
        method_filter=method,
        note=(
            "Every row is a locally observed resolution with its evidence "
            "source. An address commonly serves many names, so a row is "
            "evidence that a name resolved to an address at a moment — not "
            "that a given connection used that name."
            if rows
            else
            "No DNS evidence has been collected. That is not the same as "
            "this host resolving nothing: see /enrichment/dns/diagnose for "
            "which host sources are available and why."
        ),
    )


@router.post("/dns/events/collect", response_model=DnsEventCollectResult)
def collect_dns_event_log(
    max_events: int = Query(
        500, ge=1, le=5000,
        description="Upper bound on records read from the circular log in one call.",
    ),
    db: Database = Depends(get_db),
) -> DnsEventCollectResult:
    """
    Snapshot the Windows DNS-Client event log into the observation store.

    A second evidence source alongside the cache, not a replacement: both
    write `dns_observations` and are told apart by `method`, so this
    changes nothing the cache path does (ADR-120).

    Read-only. It enables no channel, clears no log and sends no query.
    Where the channel is absent, disabled, or unreadable by this account,
    that specific reason is returned rather than a generic failure —
    they are three different operator actions.

    Only event id 3008 is interpreted. 3006 and 1001 appear in the same
    channel and no field of either has been observed, so they are
    counted and reported, never parsed.
    """
    return DnsEventCollectResult(
        **get_enrichment_service(db).collect_from_dns_event_log(max_events=max_events)
    )


@router.get("/ip/{ip_address}", response_model=IpAttributionResponse)
def attribute_ip(
    ip_address: str,
    allow_reverse_dns: bool = Query(
        default=False,
        description=(
            "Fall back to a PTR lookup when no local DNS evidence exists. "
            "This names the ADDRESS OWNER (often a CDN edge), never the "
            "hostname the application requested, and sends a DNS query."
        ),
    ),
    db: Database = Depends(get_db),
) -> IpAttributionResponse:
    """Best defensible hostname for one address, with its supporting evidence."""
    service = get_enrichment_service(db)
    observations = db.get_dns_observations_for_ip(ip_address)
    attribution = service.attribute_ip(ip_address, observations=observations)

    if not attribution.is_attributed and allow_reverse_dns:
        attribution = service.reverse_lookup(ip_address)

    return IpAttributionResponse(
        ip_address=ip_address,
        attribution=attribution,
        observations=[DnsObservationItem(**o) for o in observations],
    )


class ManualDnsObservation(BaseModel):
    """
    A DNS resolution supplied by an authorized external observer.

    Provided so a legitimately configured source (for example a local
    resolver log the operator already keeps) can contribute evidence without
    PraHari changing any system configuration itself.
    """
    ip_address: str = Field(..., min_length=3, max_length=64)
    hostname: str = Field(..., min_length=1, max_length=253)
    observed_at: str = Field(..., description="ISO-8601 timestamp of the resolution")
    ttl_seconds: Optional[int] = Field(default=None, ge=0)


@router.post("/dns/observations", status_code=status.HTTP_201_CREATED)
def submit_dns_observations(
    observations: list[ManualDnsObservation],
    db: Database = Depends(get_db),
) -> dict:
    """Record DNS resolutions observed by an authorized external source."""
    if len(observations) > 5000:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="At most 5000 observations per request.",
        )
    payload = [
        {
            "ip_address": o.ip_address,
            "hostname": o.hostname.lower().rstrip("."),
            "observed_at": o.observed_at,
            "method": "dns_query_log",
            "ttl_seconds": o.ttl_seconds,
            "source_id": "external_dns_log",
        }
        for o in observations
    ]
    recorded = db.record_dns_observations(payload)
    db.log_audit(
        action="submit_dns_observations",
        resource_type="dns_observations",
        resource_id="external_dns_log",
        details=f"Recorded {recorded} of {len(observations)} submitted observations",
    )
    return {"submitted": len(observations), "recorded": recorded}


# ---------------------------------------------------------------------
# Continuous DNS collection (ADR-127)
# ---------------------------------------------------------------------


class DnsCollectorControl(BaseModel):
    """Start parameters. Both optional; omitted means keep current."""

    interval_seconds: Optional[float] = Field(
        default=None,
        ge=MIN_INTERVAL_SECONDS,
        le=MAX_INTERVAL_SECONDS,
        description="Seconds between polls of the DNS-Client channel.",
    )
    batch_size: Optional[int] = Field(
        default=None,
        ge=1,
        le=5000,
        description="Records read per poll. A full batch polls again at once.",
    )


@router.get("/dns/collector/status", response_model=DnsCollectorStatus)
def dns_collector_status(db: Database = Depends(get_db)) -> DnsCollectorStatus:
    """
    What continuous DNS collection is doing, and on what evidence.

    Read-only. Reports `unsupported` rather than an error where the
    channel is not a thing this platform has.
    """
    return get_dns_collector(db).status()


@router.post("/dns/collector/start", response_model=DnsCollectorStatus)
async def start_dns_collector(
    req: DnsCollectorControl,
    db: Database = Depends(get_db),
    # Admin-only in central mode (ADR-126). Collection control is a
    # deployment-wide operation, not one scoped to a caller's source.
    _: object = Depends(require_admin_in_central),
) -> DnsCollectorStatus:
    """
    Begin polling the DNS-Client channel on an interval.

    Enables no channel and changes no Windows configuration: where the
    channel is off, this reports that and collects nothing (ADR-121).
    """
    return await get_dns_collector(db).start(
        interval_seconds=req.interval_seconds, batch_size=req.batch_size
    )


@router.post("/dns/collector/stop", response_model=DnsCollectorStatus)
async def stop_dns_collector(
    db: Database = Depends(get_db),
    _: object = Depends(require_admin_in_central),
) -> DnsCollectorStatus:
    """Stop polling cleanly, releasing the task. Safe when not running."""
    return await get_dns_collector(db).stop()
