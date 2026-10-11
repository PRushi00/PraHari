"""
PraHari — API v1 Router

Aggregates all API v1 endpoints.
"""

from __future__ import annotations

from fastapi import APIRouter

from app.api.v1.health import router as health_router
from app.api.v1.sources import router as sources_router
from app.api.v1.events import router as events_router
from app.api.v1.imports import router as imports_router
from app.api.v1.analysis import router as analysis_router

api_v1_router = APIRouter()

api_v1_router.include_router(health_router)
api_v1_router.include_router(sources_router)
api_v1_router.include_router(events_router)
api_v1_router.include_router(imports_router)
api_v1_router.include_router(analysis_router)
