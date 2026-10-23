"""
PraHari — System Health (blueprint §11 "System health" view)

§11 requires one view carrying "ingestion latency, queue depth, parser
errors, rejected records, storage status, and inference latency". Those
measurements existed across several services and were not reachable in
one response, so the dashboard could not show them.

The honesty rules of §12 govern every field here:

* A number is present only when it was **measured**. Anything not
  measured is `null`, never `0` — zero is itself a measurement and
  claiming it would be a fabrication.
* Each block carries an `available` flag and, when unavailable, a
  `reason`, so the UI can distinguish *nothing happened* from *we cannot
  tell*.
* `queue_depth` is null with a note, because PraHari has no queue. See
  `services/admission.py`.
"""

from __future__ import annotations

import logging
import platform
import sys
import time
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from app.adapters.base import get_adapter_registry
from app.api.deps import get_db
from app.core.config import AppConfig, get_config
from app.schemas.events import SCHEMA_VERSION
from app.services.admission import get_admission_controller
from app.services.inference_metrics import get_inference_metrics
from app.services.source_health import summarize_source_health
from app.storage.database import Database

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/system", tags=["System Health"])

_PROCESS_STARTED = time.time()


class Block(BaseModel):
    """
    One measurable area.

    `available` false means PraHari could not measure this, and `reason`
    says why. It never means "zero".
    """

    available: bool
    reason: Optional[str] = None
    data: dict[str, Any] = Field(default_factory=dict)


class SystemHealthReport(BaseModel):
    generated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    schema_version: str = SCHEMA_VERSION
    deployment_mode: str
    uptime_seconds: float

    ingestion: Block
    sources: Block
    storage: Block
    models: Block
    adapters: Block
    limits: Block

    notes: list[str] = Field(
        default_factory=lambda: [
            "Every number here is measured by this backend. A field that was "
            "not measured is null, never 0.",
            "PraHari has no ingestion queue, so queue_depth is null rather "
            "than 0. See ingestion.admission_model.",
            "Counters are per process and reset when the backend restarts.",
            "Source freshness states describe PraHari's evidence, not whether "
            "a remote host is running.",
        ]
    )


def _ingestion_block() -> Block:
    """Measured ingestion counters from the admission controller."""
    try:
        data = get_admission_controller().snapshot()
        # These count the HTTP ingestion API only. The host collector is an
        # in-process producer: it writes through the storage layer directly
        # and never calls this backend over the network, so it is counted in
        # `adapters`, not here. Without this, an operator reading
        # `events_stored: 0` beside a storage block holding hundreds of
        # collected events has to guess which number is wrong — and neither
        # is.
        data["scope"] = "http_ingestion_api_only"
        data["scope_note"] = (
            "Counts requests to the ingestion API (POST /stream/ingest/*, "
            "/imports/*). The in-process host collector writes directly to "
            "storage and is reported under `adapters`; zero here does not "
            "mean nothing was collected."
        )
        return Block(available=True, data=data)
    except Exception as exc:  # pragma: no cover - defensive
        logger.exception("Ingestion metrics unavailable")
        return Block(available=False, reason=f"metrics unavailable: {exc}")


def _sources_block(db: Database) -> Block:
    try:
        sources = db.list_sources()
    except Exception as exc:
        return Block(available=False, reason=f"source table unreadable: {exc}")

    if not sources:
        return Block(
            available=True,
            data={
                "total": 0,
                "counts_by_state": {},
                "sources": [],
                "note": "No telemetry source is registered yet.",
            },
        )

    try:
        receipts = db.latest_received_at_by_source()
    except Exception:
        receipts = {}

    summary = summarize_source_health(sources, last_received_by_source=receipts)
    return Block(
        available=True,
        data={
            "total": len(summary.sources),
            "counts_by_state": summary.counts_by_state,
            "fresh_threshold_seconds": summary.fresh_threshold_seconds,
            "stale_threshold_seconds": summary.stale_threshold_seconds,
            "sources": [
                {
                    "source_id": h.source_id,
                    "name": h.name,
                    "source_type": h.source_type,
                    "state": h.state.value,
                    "enabled": h.enabled,
                    "event_count": h.event_count,
                    "last_event_at": h.last_event_at,
                    "seconds_since_last_event": h.seconds_since_last_event,
                    "last_received_at": h.last_received_at,
                    "seconds_since_last_receipt": h.seconds_since_last_receipt,
                    "receipt_evidence_available": h.receipt_evidence_available,
                    "clock_dependent": h.clock_dependent,
                    "freshness_basis": h.freshness_basis,
                }
                for h in summary.sources
            ],
            "notes": summary.notes,
        },
    )


def _storage_block(db: Database, config: AppConfig) -> Block:
    try:
        # The backend describes itself (ADR-093): the PRAGMAs this used to
        # run are SQLite's, and a second backend reports what IS true of it
        # rather than a plausible-looking stand-in. `received_at_column_present`
        # is migration state, so an operator can see whether a schema
        # addition has been applied without opening the store.
        diagnostics = db.storage_diagnostics()
        return Block(
            available=True,
            data={**diagnostics, "retention_days": config.retention_days},
        )
    except Exception as exc:
        return Block(available=False, reason=f"storage unreadable: {exc}")


def _models_block(db: Database) -> Block:
    """
    Model availability. Absent is reported as absent — §9 forbids
    substituting a demo score when a model is missing.
    """
    try:
        from app.models.registry import get_forecasting_pipeline

        pipeline = get_forecasting_pipeline()
        names = sorted(pipeline.trained_models.keys())
    except Exception as exc:
        return Block(
            available=False,
            reason=(
                f"Model registry unreachable ({exc}). Inference is "
                "unavailable; no score will be substituted."
            ),
        )

    return Block(
        available=True,
        data={
            "trained_models": names,
            "model_count": len(names),
            "inference_available": bool(names),
            "note": (
                "Models trained in THIS process only; the registry is "
                "in-memory and empty after a restart until training runs."
                if not names else
                "Metrics for these models come from the data they were "
                "trained on in this process."
            ),
            # Measured since ADR-106. Still null — not a zero-filled
            # structure — until a prediction has actually run, because an
            # empty shape full of nulls reads as a measurement.
            "inference_latency": get_inference_metrics().summary(),
        },
    )


def _adapters_block() -> Block:
    try:
        reports = get_adapter_registry().health_report()
    except Exception as exc:
        return Block(available=False, reason=f"adapter registry unreadable: {exc}")

    return Block(
        available=True,
        data={
            "active_adapters": len(reports),
            "adapters": [r.model_dump() for r in reports],
            "note": (
                "Only adapters exercised in this process appear. An empty "
                "list means nothing has ingested yet, not that no adapter "
                "exists."
            ),
        },
    )


def _limits_block(config: AppConfig) -> Block:
    """
    The configured limits AND whether each is actually enforced.

    Reporting a configured number without its enforcement state is how
    `max_request_size_mb` came to be published as a security boundary
    while nothing read it (ADR-052).
    """
    return Block(
        available=True,
        data={
            "max_request_size_mb": config.max_request_size_mb,
            "request_size_limit_enforced": True,
            "max_import_records": config.max_import_records,
            "import_record_limit_enforced": True,
            "rate_limit_requests": config.rate_limit_requests,
            "rate_limit_window_seconds": config.rate_limit_window_seconds,
            "rate_limit_enforced": config.rate_limit_requests > 0,
            "ingestion_capacity": get_admission_controller().max_concurrent,
            "admission_control_enforced": True,
        },
    )


@router.get("/health", response_model=SystemHealthReport)
def system_health(
    db: Database = Depends(get_db),
    config: AppConfig = Depends(get_config),
) -> SystemHealthReport:
    """
    One response carrying every operational measurement the dashboard's
    System Health view needs.

    Read-only: it starts nothing, collects nothing, and changes no state.
    """
    return SystemHealthReport(
        deployment_mode=config.deployment_mode.value,
        uptime_seconds=round(time.time() - _PROCESS_STARTED, 3),
        ingestion=_ingestion_block(),
        sources=_sources_block(db),
        storage=_storage_block(db, config),
        models=_models_block(db),
        adapters=_adapters_block(),
        limits=_limits_block(config),
    )


@router.get("/runtime")
def runtime_info(config: AppConfig = Depends(get_config)) -> dict:
    """
    Environment facts for troubleshooting (§15). No secrets: the
    configuration surfaced here is limited to non-sensitive values.
    """
    return {
        "python_version": sys.version.split()[0],
        "platform": sys.platform,
        "platform_release": platform.release(),
        "machine": platform.machine(),
        "deployment_mode": config.deployment_mode.value,
        "schema_version": SCHEMA_VERSION,
        "uptime_seconds": round(time.time() - _PROCESS_STARTED, 3),
        "host_telemetry_supported": sys.platform == "win32"
        or sys.platform.startswith("linux"),
    }


# ---------------------------------------------------------------------
# Host identity (ADR-125)
# ---------------------------------------------------------------------


class HostIdentity(BaseModel):
    """
    What this machine is, as far as the process can tell from inside it.

    Every field is nullable with a reason, for the same reason the rest
    of this module is: the dashboard's host card previously had to show
    the **API process's** uptime because nothing reported the machine's,
    and a wrong number wearing the right label is worse than a blank.

    None of this is a network measurement. `local_ip` is the address the
    kernel would source from for a route to a public address; it is read
    from an unconnected UDP socket, which sends no packet, and it says
    nothing about what that interface can see.
    """

    hostname: Optional[str] = None
    hostname_reason: Optional[str] = None

    local_ip: Optional[str] = None
    local_ip_reason: Optional[str] = None

    operating_system: Optional[str] = None

    #: Seconds since the machine booted. Null when it cannot be read —
    #: never the process uptime, which is a different quantity.
    host_uptime_seconds: Optional[float] = None
    host_uptime_reason: Optional[str] = None
    host_uptime_source: Optional[str] = None

    #: Seconds since THIS API process started. Always available, and
    #: kept under a name that cannot be mistaken for the machine's.
    process_uptime_seconds: float

    measured_at: datetime
    limitations: list[str] = Field(default_factory=list)


def _read_hostname() -> tuple[Optional[str], Optional[str]]:
    import socket

    try:
        name = socket.gethostname()
    except OSError as exc:
        return None, f"gethostname failed: {type(exc).__name__}"
    return (name, None) if name else (None, "the host reports an empty name")


def _read_local_ip() -> tuple[Optional[str], Optional[str]]:
    """
    The address this host would use to reach the outside world.

    An unconnected UDP socket is `connect()`ed to a public address to
    make the kernel choose a route. UDP connect sends nothing — no
    packet leaves the machine, and nothing is contacted.
    """
    import socket

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("198.51.100.1", 9))  # TEST-NET-3, reserved, unroutable
        return sock.getsockname()[0], None
    except OSError as exc:
        # No default route, or no network at all. Both are real states.
        return None, f"no route could be resolved: {type(exc).__name__}"
    finally:
        sock.close()


def _read_host_uptime() -> tuple[Optional[float], Optional[str], Optional[str]]:
    """Seconds since boot, by whichever means this platform offers."""
    try:
        import psutil  # type: ignore[import-untyped]

        return round(time.time() - psutil.boot_time(), 3), None, "psutil.boot_time"
    except ImportError:
        pass
    except Exception as exc:  # noqa: BLE001
        return None, f"psutil could not read boot time: {type(exc).__name__}", None

    # psutil is not a declared dependency, so Linux gets a stdlib path.
    try:
        with open("/proc/uptime", "r", encoding="ascii") as handle:
            return round(float(handle.read().split()[0]), 3), None, "/proc/uptime"
    except (OSError, ValueError, IndexError):
        pass

    return (
        None,
        "no boot time is readable here: psutil is not installed and "
        "/proc/uptime does not exist on this platform",
        None,
    )


@router.get("/host", response_model=HostIdentity)
def host_identity() -> HostIdentity:
    """
    Identify the machine PraHari runs on.

    Read-only and local: it opens no connection, sends no packet, and
    changes nothing.
    """
    hostname, hostname_reason = _read_hostname()
    local_ip, local_ip_reason = _read_local_ip()
    uptime, uptime_reason, uptime_source = _read_host_uptime()

    limitations = [
        "Identifies the machine PraHari runs on. It is not a network scan "
        "and says nothing about any other device.",
        "local_ip is the address the kernel would source from for an "
        "outbound route. The host may hold other addresses on other "
        "interfaces, and this one is not evidence of what it can observe.",
    ]

    return HostIdentity(
        hostname=hostname,
        hostname_reason=hostname_reason,
        local_ip=local_ip,
        local_ip_reason=local_ip_reason,
        operating_system=f"{platform.system()} {platform.release()}".strip() or None,
        host_uptime_seconds=uptime,
        host_uptime_reason=uptime_reason,
        host_uptime_source=uptime_source,
        process_uptime_seconds=round(time.time() - _PROCESS_STARTED, 3),
        measured_at=datetime.now(timezone.utc),
        limitations=limitations,
    )
