"""
PraHari — API v1 Router

Aggregates all API v1 endpoints into the primary API gateway.
"""

from __future__ import annotations

from fastapi import APIRouter

from app.api.v1.health import router as health_router
from app.api.v1.sources import router as sources_router
from app.api.v1.events import router as events_router
from app.api.v1.imports import router as imports_router
from app.api.v1.analysis import router as analysis_router
from app.api.v1.research import router as research_router
from app.api.v1.forecast import router as forecast_router
from app.api.v1.stream import router as stream_router
from app.api.v1.audit import router as audit_router
from app.api.v1.collector import router as collector_router
from app.api.v1.enrichment import router as enrichment_router
from app.api.v1.applayer import router as applayer_router
from app.api.v1.experiments import router as experiments_router
from app.api.v1.retention import router as retention_router

api_v1_router = APIRouter()

api_v1_router.include_router(health_router)
api_v1_router.include_router(sources_router)
api_v1_router.include_router(events_router)
api_v1_router.include_router(imports_router)
api_v1_router.include_router(analysis_router)
api_v1_router.include_router(research_router)
api_v1_router.include_router(forecast_router)
api_v1_router.include_router(stream_router)
api_v1_router.include_router(audit_router)
api_v1_router.include_router(collector_router)
api_v1_router.include_router(enrichment_router)
api_v1_router.include_router(applayer_router)
api_v1_router.include_router(experiments_router)
api_v1_router.include_router(retention_router)
