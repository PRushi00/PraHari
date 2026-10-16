"""
PraHari — Additional Windows Host Observation Endpoints

Two sources that broaden telemetry coverage without capturing packets:

  * UDP endpoint table  -> canonical events (EventType.UDP_ENDPOINT)
  * Interface counters  -> their own payload, never canonical events

Both are explicit, operator-triggered reads. Nothing here runs on startup,
and nothing changes network configuration.
"""

from __future__ import annotations

import logging
import sys
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from app.adapters.capabilities import get_capability
from app.adapters.windows_host_observations import (
    INTERFACE_SOURCE_TYPE,
    UDP_SOURCE_TYPE,
    InterfaceStatisticsProbe,
    InterfaceStatisticsSnapshot,
    WindowsUdpEndpointAdapter,
    query_udp_endpoints,
)
from app.adapters.windows_telemetry import WindowsTelemetryUnavailable
from app.api.deps import get_db
from app.schemas.events import DataCategory, SourceCapability, TelemetrySource
from app.storage.database import Database

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/hostobs", tags=["Host Observations"])

UDP_SOURCE_ID = "windows_udp_endpoints"

# One probe per process so a delta can be offered between reads. Counters are
# not events, so this state is intentionally not persisted.
_interface_probe = InterfaceStatisticsProbe()


def _platform_supported() -> bool:
    return sys.platform == "win32"


def _require_windows(what: str) -> None:
    if not _platform_supported():
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail={
                "error": "unsupported_platform",
                "message": f"{what} is a Windows source; this host reports '{sys.platform}'.",
            },
        )


class UdpPollResult(BaseModel):
    """Accounting for one UDP endpoint poll."""

    polled_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source_id: str = UDP_SOURCE_ID
    endpoints_observed: int = 0
    events_normalized: int = 0
    events_persisted: int = 0
    repeats_suppressed: int = 0
    rejected: int = 0
    rejection_reasons: list[str] = Field(default_factory=list)
    notes: list[str] = Field(
        default_factory=lambda: [
            "A UDP endpoint is a locally bound socket, not a conversation. No remote peer exists to report.",
            "Destination fields are 'not applicable' for this source, not missing.",
            "Event ids are deterministic, so re-polling the same socket persists nothing new.",
        ]
    )


@router.get("/capabilities", response_model=list[SourceCapability])
def list_host_observation_capabilities() -> list[SourceCapability]:
    """Declared capabilities of the two additional host sources."""
    return [get_capability(UDP_SOURCE_TYPE), get_capability(INTERFACE_SOURCE_TYPE)]


@router.post("/udp/poll", response_model=UdpPollResult)
def poll_udp_endpoints(
    persist: bool = True,
    db: Database = Depends(get_db),
) -> UdpPollResult:
    """
    Read the Windows UDP endpoint table once.

    Unprivileged and read-only. With ``persist=false`` the poll is normalized
    and accounted for but nothing is written, which is useful for inspecting
    the source without adding to the operational dataset.
    """
    _require_windows("UDP endpoint collection")

    try:
        rows = query_udp_endpoints()
    except WindowsTelemetryUnavailable as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": "udp_table_unavailable", "message": str(exc)},
        )

    polled_at = datetime.now(timezone.utc)
    adapter = WindowsUdpEndpointAdapter(adapter_id=UDP_SOURCE_ID)
    events, rejections = adapter.normalize_batch(
        rows, data_category=DataCategory.LIVE_TELEMETRY, polled_at=polled_at
    )

    persisted = 0
    repeats = 0
    if persist and events:
        source = db.get_source(UDP_SOURCE_ID)
        if source is None:
            db.upsert_source(
                TelemetrySource(
                    source_id=UDP_SOURCE_ID,
                    name="Windows UDP Endpoints",
                    source_type=UDP_SOURCE_TYPE,
                    description="Locally bound UDP sockets (Get-NetUDPEndpoint).",
                )
            )
        before = db.count_events(source_id=UDP_SOURCE_ID)
        db.insert_events(events)
        after = db.count_events(source_id=UDP_SOURCE_ID)
        persisted = after - before
        # Deterministic ids mean an already-known socket inserts nothing.
        repeats = len(events) - persisted
        db.refresh_source_activity(
            UDP_SOURCE_ID,
            last_event_at=max(e.observed_at for e in events),
            status="active",
        )
        db.log_audit(
            action="poll_udp_endpoints",
            resource_type="telemetry_source",
            resource_id=UDP_SOURCE_ID,
            details=(
                f"Observed {len(rows)} UDP endpoints, persisted {persisted} new, "
                f"{repeats} already known"
            ),
        )

    return UdpPollResult(
        polled_at=polled_at,
        endpoints_observed=len(rows),
        events_normalized=len(events),
        events_persisted=persisted,
        repeats_suppressed=repeats,
        rejected=len(rejections),
        rejection_reasons=rejections[:20],
    )


@router.get("/interfaces", response_model=InterfaceStatisticsSnapshot)
def read_interface_statistics() -> InterfaceStatisticsSnapshot:
    """
    Read per-interface cumulative byte and packet counters.

    These are the only genuine volume measurements available on this host
    without packet capture — and they are **interface-level and cumulative**,
    so they cannot be attributed to a connection, a process or a destination.
    The payload states that scope explicitly.

    A delta against the previous read in this process is included when one
    exists. Across an adapter reset no delta is derived, because a decreasing
    counter does not describe anything that happened on the wire.
    """
    _require_windows("Interface statistics")
    try:
        return _interface_probe.read()
    except WindowsTelemetryUnavailable as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": "interface_statistics_unavailable", "message": str(exc)},
        )
