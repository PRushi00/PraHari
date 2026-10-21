"""
PraHari — Health Check API Endpoint
"""

from __future__ import annotations

import os
import time
from datetime import datetime, timezone
from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.core.config import AppConfig, get_config
from app.api.deps import get_db
from app.storage.database import Database
from app.schemas.events import SCHEMA_VERSION

router = APIRouter()
START_TIME = time.time()


class HealthResponse(BaseModel):
    status: str
    app_name: str
    app_version: str
    schema_version: str
    deployment_mode: str
    uptime_seconds: float
    database: dict
    timestamp: str


@router.get("/health", response_model=HealthResponse)
def health_check(
    config: AppConfig = Depends(get_config),
    db: Database = Depends(get_db),
) -> HealthResponse:
    """System health check endpoint verifying database connectivity."""
    db_ok = False
    events_count = 0
    sources_count = 0
    try:
        sources = db.list_sources()
        sources_count = len(sources)
        events_count = db.count_events()
        db_ok = True
    except Exception as e:
        db_ok = False

    return HealthResponse(
        status="healthy" if db_ok else "degraded",
        app_name=config.app_name,
        app_version=config.app_version,
        schema_version=SCHEMA_VERSION,
        deployment_mode=config.deployment_mode.value,
        uptime_seconds=round(time.time() - START_TIME, 2),
        database={
            "connected": db_ok,
            "path": config.store_descriptor(),
            "sources_count": sources_count,
            "events_count": events_count,
        },
        timestamp=datetime.now(timezone.utc).isoformat(),
    )
