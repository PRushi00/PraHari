"""
PraHari — Audit & System Security Configuration Endpoints

Provides visibility into administrative actions, security configuration,
and deployment boundary compliance.
"""

from __future__ import annotations

from typing import Any, Optional
import ipaddress

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel

from app.api.auth import require_admin_in_central
from app.api.deps import get_db
from app.core.config import AppConfig, get_config
from app.storage.database import Database
from app.schemas.events import SCHEMA_VERSION

router = APIRouter(prefix="/audit", tags=["Audit & Security"])


class AuditLogItem(BaseModel):
    id: int
    timestamp: str
    action: str
    resource_type: str
    resource_id: str
    details: str
    user_identity: str
    request_id: Optional[str] = None


class SystemConfigReport(BaseModel):
    app_name: str
    app_version: str
    schema_version: str
    deployment_mode: str
    host_binding: str
    port: int
    # True only with evidence (ADR-089): configured for loopback, serving on
    # the configured port, and no request seen arriving elsewhere. False when
    # exposure is proven or the configured host is not loopback. None when
    # the configuration does not describe the listener, so neither is known.
    loopback_enforced: Optional[bool]
    authentication_required: bool
    max_request_size_mb: int
    database_url: str
    retention_days: int
    # Enforcement, reported separately from the configured value. The
    # size limit was a configuration number with nothing reading it, and
    # publishing it here implied a control that did not exist (ADR-052).
    request_size_limit_enforced: bool = True
    rate_limit_requests: int = 0
    rate_limit_window_seconds: float = 0.0
    rate_limit_enforced: bool = False
    # What was MEASURED, beside what is configured (ADR-078). `host_binding`
    # and `port` are configuration; uvicorn's --host/--port do not update
    # them, so a server started on another port or on 0.0.0.0 used to report
    # 127.0.0.1:8000. These come from the request itself: the local address
    # this request actually arrived on.
    serving_host: Optional[str] = None
    serving_port: Optional[int] = None
    listener_matches_configuration: Optional[bool] = None
    binding_evidence: str = ""
    security_boundaries: dict[str, Any]


@router.get("/logs", response_model=list[AuditLogItem])
def list_audit_logs(
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    resource_type: Optional[str] = Query(default=None),
    db: Database = Depends(get_db),
    _: object = Depends(require_admin_in_central),
) -> list[AuditLogItem]:
    """
    Chronologically ordered audit entries, newest first.

    Goes through the storage contract (ADR-093) rather than opening a
    connection here, so the route does not depend on which backend is
    configured. `request_id` is None on an entry written before the column
    existed and on anything with no request behind it (ADR-063).

    `offset` and `resource_type` were already being sent by the dashboard
    and silently ignored; they are honoured now that the query has one
    home.
    """
    return [
        AuditLogItem(**row)
        for row in db.list_audit_events(
            limit=limit, offset=offset, resource_type=resource_type
        )
    ]


@router.get("/config", response_model=SystemConfigReport)
def get_system_security_config(
    request: Request,
    config: AppConfig = Depends(get_config),
    db: Database = Depends(get_db),
    _: object = Depends(require_admin_in_central),
) -> SystemConfigReport:
    """
    Inspect active system configuration and operational security boundaries.

    Every boundary below is derived from live state. Publishing fixed `true`
    values here would assert guarantees the running system may not actually
    provide — the most misleading possible content for a security surface.
    """
    is_loopback = config.host in ("127.0.0.1", "localhost", "::1")

    # The application cannot see the address uvicorn bound - that is set on
    # uvicorn's command line - but every request records the local address
    # it arrived on. That proves two things and no more:
    #   * the real serving port, and
    #   * EXPOSURE, if a request ever arrives on a non-loopback address.
    # Arrival on loopback does not prove a loopback-only bind (0.0.0.0 also
    # accepts loopback connections), so that case is reported as unverified
    # rather than as enforcement.
    server = request.scope.get("server") or (None, None)
    serving_host, serving_port = server[0], server[1]
    try:
        arrival_ip = ipaddress.ip_address(serving_host) if serving_host else None
    except ValueError:
        arrival_ip = None  # e.g. a test client's "testserver": no evidence
    # A dual-stack bind reports a local IPv4 client as ::ffff:127.0.0.1, which
    # Python 3.12 does not call loopback. Judge the IPv4 address it carries.
    if isinstance(arrival_ip, ipaddress.IPv6Address) and arrival_ip.ipv4_mapped:
        arrival_ip = arrival_ip.ipv4_mapped
    proven_exposed = arrival_ip is not None and not arrival_ip.is_loopback
    listener_matches = (
        serving_port == config.port if isinstance(serving_port, int) else None
    )
    if proven_exposed:
        binding_evidence = (
            f"EXPOSED: this request arrived on non-loopback address "
            f"{serving_host}, so the server is reachable beyond loopback "
            f"whatever the configuration says."
        )
    elif listener_matches is None:
        binding_evidence = (
            "UNKNOWN: the serving port could not be read from this request, so "
            "the configured binding cannot be compared with the listener."
        )
    elif listener_matches is False:
        binding_evidence = (
            f"UNVERIFIED: serving on port {serving_port}, but the configuration "
            f"says {config.port}, so the configured binding does not describe "
            f"this server. Start it through the launcher, or set PRAHARI_HOST "
            f"and PRAHARI_PORT to match uvicorn's --host and --port."
        )
    else:
        arrival = (
            "this request arrived on loopback, which a wildcard bind would also accept"
            if arrival_ip is not None
            else "this request's arrival address is not an IP address, so it is no evidence"
        )
        binding_evidence = (
            "CONFIGURED: the configured port and the serving port agree. The "
            f"bound address itself is not observable from inside the application; {arrival}."
        )

    # Derive the live telemetry collection posture from the collector itself.
    collector_state = "stopped"
    packet_capture_in_use = False
    try:
        from app.services.collector import get_collector

        status_obj = get_collector(db).status()
        collector_state = status_obj.state
        # The only live collector PraHari implements reads the OS connection
        # table. It performs no packet capture and opens no raw sockets.
        packet_capture_in_use = False
    except Exception:  # noqa: BLE001
        collector_state = "unknown"

    # The research gate is advisory: /research/audit reports feasibility, and
    # forecasting refuses to emit validated results without a leakage-free
    # holdout, but a gate verdict does not by itself block the endpoints.
    gate_enforcement = (
        "advisory_plus_evaluation_guard: feasibility is reported via "
        "/research/audit; /forecast/train refuses evaluation that would leak, "
        "and predictions are labelled unvalidated until a purged holdout with "
        "positive examples exists. A REJECT verdict does not disable the API."
    )

    return SystemConfigReport(
        app_name=config.app_name,
        app_version=config.app_version,
        schema_version=SCHEMA_VERSION,
        deployment_mode=config.deployment_mode.value,
        host_binding=config.host,
        port=config.port,
        loopback_enforced=(
            False if (proven_exposed or not is_loopback)
            else (True if listener_matches is True else None)
        ),
        authentication_required=config.require_authentication,
        max_request_size_mb=config.max_request_size_mb,
        database_url=config.database_url,
        retention_days=config.retention_days,
        request_size_limit_enforced=True,
        rate_limit_requests=config.rate_limit_requests,
        rate_limit_window_seconds=config.rate_limit_window_seconds,
        rate_limit_enforced=config.rate_limit_requests > 0,
        serving_host=serving_host,
        serving_port=serving_port if isinstance(serving_port, int) else None,
        listener_matches_configuration=listener_matches,
        binding_evidence=binding_evidence,
        security_boundaries={
            "packet_capture_in_use": packet_capture_in_use,
            "live_collector_state": collector_state,
            "live_collection_method": (
                "windows_connection_table_polling (metadata only; no packet "
                "capture, no promiscuous mode, no elevated privileges)"
            ),
            "service_exposure": (
                f"reachable_on_{serving_host}" if proven_exposed
                else f"bound_to_{config.host}" if not is_loopback
                else "loopback_only" if listener_matches is True
                else "loopback_configured_unverified"
            ),
            "authentication_required": config.require_authentication,
            "raw_payload_storage_enabled": config.raw_payload_storage,
            "external_telemetry_transmission": False,
            "research_gate_enforcement": gate_enforcement,
        },
    )
