"""
PraHari — Audit & System Security Configuration Endpoints

Provides visibility into administrative actions, security configuration,
and deployment boundary compliance.
"""

from __future__ import annotations

from typing import Any
from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel

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


class SystemConfigReport(BaseModel):
    app_name: str
    app_version: str
    schema_version: str
    deployment_mode: str
    host_binding: str
    port: int
    loopback_enforced: bool
    authentication_required: bool
    max_request_size_mb: int
    database_url: str
    retention_days: int
    security_boundaries: dict[str, Any]


@router.get("/logs", response_model=list[AuditLogItem])
def list_audit_logs(
    limit: int = Query(default=100, ge=1, le=500),
    db: Database = Depends(get_db),
) -> list[AuditLogItem]:
    """Retrieve chronologically ordered audit logs from the persistence store."""
    with db.get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM audit_events ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [
            AuditLogItem(
                id=r["id"],
                timestamp=r["timestamp"],
                action=r["action"],
                resource_type=r["resource_type"] or "",
                resource_id=r["resource_id"] or "",
                details=r["details"] or "",
                user_identity=r["user_identity"] or "system",
            )
            for r in rows
        ]


@router.get("/config", response_model=SystemConfigReport)
def get_system_security_config(
    config: AppConfig = Depends(get_config),
) -> SystemConfigReport:
    """Inspect active system configuration and operational security boundaries."""
    is_loopback = config.host in ("127.0.0.1", "localhost", "::1")
    return SystemConfigReport(
        app_name=config.app_name,
        app_version=config.app_version,
        schema_version=SCHEMA_VERSION,
        deployment_mode=config.deployment_mode.value,
        host_binding=config.host,
        port=config.port,
        loopback_enforced=is_loopback,
        authentication_required=config.require_authentication,
        max_request_size_mb=config.max_request_size_mb,
        database_url=config.database_url,
        retention_days=config.retention_days,
        security_boundaries={
            "live_sniffing_disabled": True,
            "cloud_costs_prevention": True,
            "host_network_mutation_prohibited": True,
            "research_gate_enforced": True,
        },
    )
