"""
PraHari — Domain Enrichment API Endpoints

Hostname attribution for destination addresses, always returned together
with the evidence that supports it and the limits of that evidence.

Nothing here modifies a connection record: enrichment is computed alongside
events and can be ignored entirely.
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from app.api.deps import get_db
from app.schemas.events import DomainAttribution
from app.services.enrichment import diagnose_dns_visibility, get_enrichment_service
from app.storage.database import Database

router = APIRouter(prefix="/enrichment", tags=["Domain Enrichment"])


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
    """
    return diagnose_dns_visibility()


@router.post("/dns/refresh", response_model=DnsRefreshResult)
def refresh_dns_observations(db: Database = Depends(get_db)) -> DnsRefreshResult:
    """
    Snapshot the local Windows DNS client cache into the observation store.

    Sends no DNS queries and contacts no external service — it reads answers
    this machine already received.
    """
    return DnsRefreshResult(**get_enrichment_service(db).refresh_from_dns_cache())


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
