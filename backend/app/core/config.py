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

    # Security
    require_authentication: bool = False  # Local mode default
    api_key: str = ""  # Must be set for centralized mode

    model_config = {
        "env_prefix": "PRAHARI_",
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "extra": "ignore",
    }

    def get_database_path(self) -> Path:
        """Extract SQLite database file path from URL."""
        if self.database_url.startswith("sqlite:///"):
            return Path(self.database_url.replace("sqlite:///", ""))
        return Path("prahari.db")


@lru_cache()
def get_config() -> AppConfig:
    """Get cached application configuration."""
    return AppConfig()
