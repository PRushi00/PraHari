"""
PraHari — Application Configuration

Validated, profile-based configuration. Secrets come from environment
variables, never committed to source control.
"""

from __future__ import annotations

import os
from enum import Enum
from pathlib import Path
from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings


class DeploymentMode(str, Enum):
    LOCAL = "local"
    CENTRAL = "central"


class AppConfig(BaseSettings):
    """
    Validated application configuration.

    Values can be set via environment variables (prefixed with PRAHARI_)
    or a .env file.
    """

    # Deployment
    deployment_mode: DeploymentMode = DeploymentMode.LOCAL
    app_name: str = "PraHari — The Digital Sentinel"
    app_version: str = "0.1.0"
    debug: bool = False

    # Server
    host: str = "127.0.0.1"  # Loopback by default — safe local default
    port: int = 8000
    cors_origins: list[str] = Field(default=["http://localhost:5173", "http://127.0.0.1:5173"])

    # Database
    database_url: str = "sqlite:///./prahari.db"
    test_database_url: str = "sqlite:///./prahari_test.db"

    # Paths
    data_dir: str = "./data"
    models_dir: str = "./models"
    fixtures_dir: str = "./tests/fixtures"

    # Logging
    log_level: str = "INFO"
    log_format: str = "json"

    # Request limits
    max_request_size_mb: int = 50
    max_import_records: int = 100_000

    # Retention
    retention_days: int = 365
    raw_payload_storage: bool = False

    # ── Security ──
    # Local (loopback) mode is unauthenticated by design. CENTRAL mode
    # requires credentials and refuses to start without them; see
    # app/core/security.py.
    require_authentication: bool = False  # Local mode default
    # Path to a JSON credential file holding HASHES only. Never commit it.
    credentials_file: str = ""
    # Public routes that stay reachable without a credential in central
    # mode, so an operator can diagnose a deployment that is otherwise
    # refusing them.
    central_public_paths: list[str] = Field(
        default=["/api/v1/health", "/docs", "/redoc", "/openapi.json"]
    )

    # ── Optional application-layer telemetry ──
    # Disabled by default. Enabling only opens an ingestion endpoint for an
    # authorized producer the operator runs themselves; PraHari never
    # configures a proxy, installs a certificate, or intercepts traffic.
    enable_application_layer_ingest: bool = False
    # Query strings frequently carry search terms, tokens and identifiers,
    # so they are stripped unless the operator explicitly opts in.
    applayer_retain_query_strings: bool = False

    model_config = {
        "env_prefix": "PRAHARI_",
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "extra": "ignore",
    }

    def get_database_path(self) -> Path:
        """
        Absolute path of the SQLite database file.

        A relative URL such as ``sqlite:///./prahari.db`` is resolved against
        the PROJECT ROOT, not the process working directory. Resolving
        against the CWD silently produced different databases depending on
        how the app was started — the launcher (run from the project root)
        and a backend-directory invocation each created their own file, so
        telemetry collected through one was invisible to the other.
        """
        raw = self.database_url
        if raw.startswith("sqlite:///"):
            candidate = Path(raw[len("sqlite:///"):])
        else:
            candidate = Path("prahari.db")

        if candidate.is_absolute():
            return candidate
        return (self.project_root / candidate).resolve()

    @property
    def project_root(self) -> Path:
        """
        Repository root — the directory containing ``backend/`` and
        ``frontend/``. Derived from this file's location so it does not
        depend on the working directory.
        """
        return Path(__file__).resolve().parent.parent.parent.parent


@lru_cache()
def get_config() -> AppConfig:
    """Get cached application configuration."""
    return AppConfig()
