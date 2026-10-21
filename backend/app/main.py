"""
PraHari — The Digital Sentinel
Main Application Entrypoint
"""

from __future__ import annotations

import logging
from pathlib import Path
import time
from contextlib import asynccontextmanager
from typing import AsyncGenerator, Optional

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.core.config import DeploymentMode, get_config
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
    # Fail closed on a bad host-collector identity (ADR-099) before anything
    # is served. Deferring it to the first status poll would mean a server
    # that looks healthy and only reveals the misconfiguration once an
    # operator opens the dashboard.
    collector_source_id = config.resolved_collector_source_id()
    logger.info("Host collector will file telemetry as %s", collector_source_id)
    db = get_db(config)
    db.initialize()
    logger.info("PraHari database ready at %s", config.store_descriptor())
    yield
    logger.info("PraHari backend shutting down...")

    # Stop live telemetry collection cleanly so the polling task is released
    # and the source is not left advertising itself as active.
    try:
        from app.services.collector import get_collector

        collector = get_collector(db)
        if collector.is_running:
            logger.info("Stopping live telemetry collector...")
            await collector.stop()
    except Exception:  # noqa: BLE001
        logger.warning("Error while stopping telemetry collector", exc_info=True)

    db.close()


def create_app(frontend_dist: Optional[Path] = None) -> FastAPI:
    """
    Create and configure the FastAPI application.

    ``frontend_dist`` overrides where the compiled SPA is looked for; the
    default is the checkout's ``frontend/dist``. It exists so the SPA
    fallback and its traversal guards can be tested against a known build
    whether or not this checkout has run ``npm run build``.
    """
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

    # ── Rate limiting (blueprint §4.2, §12) ──
    # Added BEFORE the auth middleware so it ends up INSIDE it: Starlette
    # runs the most recently added middleware outermost. Running inside
    # auth lets the limiter key on the authenticated credential rather
    # than on an address shared by every sensor behind one gateway.
    #
    # The cost of that choice, stated rather than hidden: an
    # UNAUTHENTICATED flood still reaches the credential check and pays
    # for PBKDF2 before being counted. The size limit outside it bounds
    # how large each such request may be, but not how many arrive.
    if config.rate_limit_requests > 0:
        from app.api.limits import FixedWindowRateLimiter, RateLimitMiddleware

        app.add_middleware(
            RateLimitMiddleware,
            limiter=FixedWindowRateLimiter(
                max_requests=config.rate_limit_requests,
                window_seconds=config.rate_limit_window_seconds,
            ),
            exempt_paths=("/api/v1/health",),
        )
        logger.info(
            "Rate limiting: %d requests per %.0fs per caller",
            config.rate_limit_requests, config.rate_limit_window_seconds,
        )
    else:
        logger.warning("Rate limiting is DISABLED by configuration")

    # ── Central-mode authentication (fail closed) ──
    # Local/loopback deployment is unauthenticated by design. Central mode
    # accepts telemetry from distinct remote sources, so it REFUSES TO START
    # without credentials rather than starting open.
    if config.deployment_mode is DeploymentMode.CENTRAL:
        from app.api.auth import CentralAuthMiddleware
        from app.core.security import CredentialStore, MissingCredentialsError

        try:
            store = CredentialStore.load(config)
        except MissingCredentialsError as exc:
            raise RuntimeError(
                f"Refusing to start in CENTRAL deployment mode: {exc}"
            ) from exc

        app.add_middleware(
            CentralAuthMiddleware,
            store=store,
            public_paths=config.central_public_paths,
        )
        logger.info(
            "Central mode: authentication enabled with %d credential(s)",
            len(store),
        )
    else:
        logger.info(
            "Local mode: loopback deployment, authentication not required"
        )

    # ── Request size limit (blueprint §4.2, §12) ──
    # Added after auth so it runs OUTSIDE it: an oversized body is refused
    # on its Content-Length before the server reads it or does any
    # credential work. `max_request_size_mb` existed in the configuration
    # and was reported by /audit/config long before anything read it.
    from app.api.limits import BYTES_PER_MB, RequestSizeLimitMiddleware

    app.add_middleware(
        RequestSizeLimitMiddleware,
        max_bytes=config.max_request_size_mb * BYTES_PER_MB,
    )

    # ── Request correlation ids (ADR-063) ──
    # Added LAST of the custom middlewares so it runs OUTERMOST: the id
    # must exist before auth, limits or a route can write an audit entry.
    # Installed in both deployment modes, because the write that motivated
    # it came from a loopback deployment.
    from app.api.request_context import RequestIdMiddleware

    app.add_middleware(RequestIdMiddleware)

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
    dist_dir = (
        frontend_dist
        if frontend_dist is not None
        else Path(__file__).resolve().parent.parent.parent / "frontend" / "dist"
    )
    if dist_dir.exists() and (dist_dir / "index.html").exists():
        from fastapi.staticfiles import StaticFiles
        from fastapi.responses import FileResponse

        assets_dir = dist_dir / "assets"
        if assets_dir.exists():
            app.mount("/assets", StaticFiles(directory=str(assets_dir)), name="assets")

        @app.get("/{full_path:path}", include_in_schema=False)
        async def spa_fallback(full_path: str):
            # API paths must never fall through to the SPA shell. Without this
            # an unknown or misspelled endpoint returns HTTP 200 with HTML,
            # which silently breaks API clients (they receive a page where
            # they expect JSON) and hides genuinely missing routes.
            if full_path == "api" or full_path.startswith("api/"):
                return JSONResponse(
                    status_code=404,
                    content={"detail": f"API endpoint '/{full_path}' not found"},
                )

            # Explicit path traversal check
            if ".." in full_path or full_path.startswith("/"):
                return JSONResponse(status_code=400, content={"detail": "Invalid path traversal attempt"})

            # Check if requesting a direct static file in dist (like favicon.svg)
            target = dist_dir / full_path
            try:
                resolved_target = target.resolve()
                resolved_dist = dist_dir.resolve()
                if not resolved_target.is_relative_to(resolved_dist):
                    return JSONResponse(status_code=400, content={"detail": "Path outside static directory"})
                if resolved_target.is_file():
                    return FileResponse(resolved_target)
            except Exception:
                return JSONResponse(status_code=400, content={"detail": "Invalid path resolution"})

            # Missing assets under assets/ or any missing static file with an extension return 404
            if full_path.startswith("assets/") or ("." in full_path.split("/")[-1]):
                return JSONResponse(status_code=404, content={"detail": "File not found"})

            # Fallback to SPA index.html for client-side routing paths (e.g. /events, /forecast)
            return FileResponse(dist_dir / "index.html")
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
