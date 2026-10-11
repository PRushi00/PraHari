"""
PraHari — API Dependencies

Dependency injection for FastAPI routes.
"""

from __future__ import annotations

from typing import Generator
from fastapi import Depends

from app.core.config import AppConfig, get_config
from app.storage.database import Database

_db_instance: Database | None = None


def get_db(config: AppConfig = Depends(get_config)) -> Database:
    """Provide a singleton Database instance configured from AppConfig."""
    global _db_instance
    if _db_instance is None:
        db_path = str(config.get_database_path())
        _db_instance = Database(db_path=db_path)
        _db_instance.initialize()
    return _db_instance
