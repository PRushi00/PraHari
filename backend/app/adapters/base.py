"""
PraHari — Base Telemetry Adapter Interface

Defines the contract for pluggable telemetry adapters.
Each adapter maps heterogeneous security telemetry into the canonical NormalizedEvent schema.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Optional
from datetime import datetime, timezone
from pydantic import BaseModel, Field

from app.schemas.events import NormalizedEvent, ValidationResult, DataCategory


class AdapterHealth(BaseModel):
    adapter_id: str
    adapter_type: str
    is_healthy: bool
    last_active_at: Optional[datetime] = None
    records_processed: int = 0
    records_rejected: int = 0
    error_message: Optional[str] = None


class BaseTelemetryAdapter(ABC):
    """
    Abstract base class for all PraHari telemetry ingestion adapters.
    """

    def __init__(self, adapter_id: str, adapter_type: str):
        self.adapter_id = adapter_id
        self.adapter_type = adapter_type
        self.records_processed = 0
        self.records_rejected = 0
        self.last_active_at: Optional[datetime] = None
        self.last_error: Optional[str] = None

    @abstractmethod
    def validate_and_normalize(
        self,
        raw_record: dict[str, Any],
        record_index: int,
        data_category: DataCategory = DataCategory.HISTORICAL_IMPORT,
    ) -> ValidationResult:
        """Validate raw input and transform into canonical NormalizedEvent."""
        pass

    def get_health(self) -> AdapterHealth:
        """Return operational health status of this adapter."""
        return AdapterHealth(
            adapter_id=self.adapter_id,
            adapter_type=self.adapter_type,
            is_healthy=self.last_error is None,
            last_active_at=self.last_active_at,
            records_processed=self.records_processed,
            records_rejected=self.records_rejected,
            error_message=self.last_error,
        )

    def record_success(self) -> None:
        self.records_processed += 1
        self.last_active_at = datetime.now(timezone.utc)
        self.last_error = None

    def record_failure(self, error: str) -> None:
        self.records_rejected += 1
        self.last_active_at = datetime.now(timezone.utc)
        self.last_error = error
