"""
PraHari — The Digital Sentinel
Main Application Entrypoint
"""

from __future__ import annotations

import logging
from pathlib import Path
import time
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.core.config import get_config
from app.api.deps import get_db
from app.api.v1.router import api_v1_router
from app.schemas.events import SCHEMA_VERSION

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("prahari")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Startup and shutdown lifecycle."""
    config = get_config()
    logger.info("Initializing PraHari backend (mode: %s)...", config.deployment_mode.value)
    db = get_db(config)
    db.initialize()
    logger.info("PraHari database ready at %s", config.get_database_path())
    yield
    logger.info("PraHari backend shutting down...")
    db.close()


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    config = get_config()

    app = FastAPI(
        title=config.app_name,
        version=config.app_version,
        description=(
            "Cross-platform cybersecurity telemetry ingestion, canonical normalization, "
            "and factual descriptive analytics platform."
        ),
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url="/redoc",
    )

    # CORS configuration
    app.add_middleware(
        CORSMiddleware,
        allow_origins=config.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Request timing middleware
    @app.middleware("http")
    async def add_process_time_header(request: Request, call_next):
        start_time = time.time()
        response = await call_next(request)
        process_time = time.time() - start_time
        response.headers["X-Process-Time"] = f"{process_time:.4f}s"
        response.headers["X-Schema-Version"] = SCHEMA_VERSION
        return response

    # Global Exception Handler
    @app.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception):
        logger.error("Unhandled exception: %s", exc, exc_info=True)
        return JSONResponse(
            status_code=500,
            content={
                "error": "Internal Server Error",
                "detail": str(exc) if config.debug else "An unexpected error occurred",
                "path": request.url.path,
            },
        )

    # Mount v1 router at /api/v1 and /api
    app.include_router(api_v1_router, prefix="/api/v1")
    app.include_router(api_v1_router, prefix="/api")

    # Serve compiled production frontend SPA if present
    dist_dir = Path(__file__).resolve().parent.parent.parent / "frontend" / "dist"
    if dist_dir.exists() and (dist_dir / "index.html").exists():
        from fastapi.staticfiles import StaticFiles
        app.mount("/", StaticFiles(directory=str(dist_dir), html=True), name="frontend")
    else:
        @app.get("/", tags=["Root"])
        def root():
            return {
                "name": config.app_name,
                "version": config.app_version,
                "schema_version": SCHEMA_VERSION,
                "deployment_mode": config.deployment_mode.value,
                "docs": "/docs",
                "health": "/api/v1/health",
            }

    return app


app = create_app()
