"""
PraHari — API Dependencies

Dependency injection for FastAPI routes.
"""

from __future__ import annotations

from typing import Generator
from fastapi import Depends

from app.core.config import AppConfig, get_config
from app.storage.database import Database

_db_instance = None


def get_db(config: AppConfig = Depends(get_config)):
    """
    The configured telemetry store, as a singleton.

    Selects the backend from the URL's scheme (ADR-097). Both satisfy
    `storage.contract.TelemetryStore`, so nothing downstream branches on
    which one is in use; the return type is deliberately the contract,
    not `Database`.

    A PostgreSQL URL used to be a silent no-op that read the local SQLite
    file (ADR-094). It now does what it says.
    """
    global _db_instance
    if _db_instance is None:
        if config.store_scheme() == "postgresql":
            from app.storage.postgres import PostgresStore

            store = PostgresStore(config.database_url, schema=config.postgres_schema)
        else:
            store = Database(db_path=str(config.get_database_path()))
        store.initialize()
        _db_instance = store
    return _db_instance


def reset_db_singleton() -> None:
    """Drop the cached store. For tests that switch configuration."""
    global _db_instance
    _db_instance = None
