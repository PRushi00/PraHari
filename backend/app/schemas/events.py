"""
PraHari — Canonical Event Schema (v1.0.0)

Defines the versioned event schema used throughout PraHari's ingestion,
storage, analysis, and API layers. All telemetry — whether from historical
CSV imports, live adapters, or test fixtures — is normalized into this
canonical form before persistence.

Schema version: 1.0.0
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field, field_validator


SCHEMA_VERSION = "1.0.0"


class EventType(str, Enum):
    """Supported canonical event types."""
    NETWORK_FLOW = "network_flow"
    CONNECTION = "connection"
    DNS_QUERY = "dns_query"
    HTTP_REQUEST = "http_request"
    ALERT = "alert"
    HOST_EVENT = "host_event"
    UNKNOWN = "unknown"


class DataCategory(str, Enum):
    """Category distinguishing the origin/nature of ingested data."""
    LIVE_TELEMETRY = "live_telemetry"
    HISTORICAL_IMPORT = "historical_import"
    HISTORICAL_REPLAY = "historical_replay"
    SYNTHETIC_DEMO = "synthetic_demo"
    SYNTHETIC = "synthetic_demo"
    TEST_FIXTURE = "test_fixture"


class LabelProvenance(str, Enum):
    """How a label was assigned to an event."""
    DATASET_GROUND_TRUTH = "dataset_ground_truth"
    RULE_BASED = "rule_based"
    SYNTHETIC_RULE = "rule_based"
    MODEL_PREDICTION = "model_prediction"
    ANALYST_ANNOTATION = "analyst_annotation"
    UNLABELED = "unlabeled"


class QualityFlag(str, Enum):
    """Data quality indicators attached to normalized events."""
    MISSING_FIELD = "missing_field"
    PARSE_WARNING = "parse_warning"
    TIMESTAMP_UNCERTAINTY = "timestamp_uncertainty"
    TRUNCATED = "truncated"
    DUPLICATE_CANDIDATE = "duplicate_candidate"
    SCHEMA_WARNING = "schema_warning"
    INVALID_VALUE = "invalid_value"
    SYNTHETIC_SAMPLE = "synthetic_sample"


class NormalizedEvent(BaseModel):
    """
    Canonical normalized event record.

    This is the single source of truth for event representation in PraHari.
    All adapters must produce events conforming to this schema.
    """

    # Identity
    event_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique event identifier. Generated if not provided by source."
    )
    schema_version: str = Field(
        default=SCHEMA_VERSION,
        description="Version of the canonical event schema."
    )

    # Source provenance
    source_id: str = Field(
        ...,
        description="Identifier of the telemetry source that produced this event."
    )
    data_category: DataCategory = Field(
        default=DataCategory.HISTORICAL_IMPORT,
        description="Category of data origin (live, historical, test, etc.)."
    )

    # Timestamps
    observed_at: datetime = Field(
        ...,
        description="When the event was observed at the source (event time)."
    )
    ingested_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="When PraHari ingested/processed this event."
    )

    # Event classification
    event_type: EventType = Field(
        default=EventType.NETWORK_FLOW,
        description="Canonical event type."
    )

    # Network fields (optional — not all events are network flows)
    src_ip: Optional[str] = Field(
        default=None,
        description="Source IP address."
    )
    dst_ip: Optional[str] = Field(
        default=None,
        description="Destination IP address."
    )
    src_port: Optional[int] = Field(
        default=None,
        ge=0, le=65535,
        description="Source port number."
    )
    dst_port: Optional[int] = Field(
        default=None,
        ge=0, le=65535,
        description="Destination port number."
    )
    protocol: Optional[str] = Field(
        default=None,
        description="Network protocol (e.g., TCP, UDP, ICMP)."
    )

    # Flow metrics (optional)
    duration: Optional[float] = Field(
        default=None,
        ge=0,
        description="Flow duration in seconds."
    )
    packets: Optional[int] = Field(
        default=None,
        ge=0,
        description="Total packets in the flow."
    )
    bytes_total: Optional[int] = Field(
        default=None,
        ge=0,
        description="Total bytes in the flow."
    )

    # Labels
    label: Optional[str] = Field(
        default=None,
        description="Label assigned to this event (e.g., 'Benign', 'DDoS')."
    )
    label_provenance: LabelProvenance = Field(
        default=LabelProvenance.UNLABELED,
        description="How the label was assigned."
    )

    # Data quality
    quality_flags: list[QualityFlag] = Field(
        default_factory=list,
        description="Data quality indicators for this event."
    )

    # Raw reference
    raw_reference: Optional[str] = Field(
        default=None,
        description="Optional reference to original source record (file:line, ID, etc.)."
    )

    @field_validator("observed_at", mode="before")
    @classmethod
    def parse_observed_at(cls, v):
        """Accept ISO format strings and ensure timezone awareness."""
        if isinstance(v, str):
            dt = datetime.fromisoformat(v)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        if isinstance(v, datetime) and v.tzinfo is None:
            return v.replace(tzinfo=timezone.utc)
        return v

    @field_validator("protocol", mode="before")
    @classmethod
    def normalize_protocol(cls, v):
        """Normalize protocol names to uppercase."""
        if isinstance(v, str):
            return v.strip().upper()
        return v

    model_config = {
        "json_schema_extra": {
            "example": {
                "event_id": "550e8400-e29b-41d4-a716-446655440000",
                "schema_version": "1.0.0",
                "source_id": "csv-import-cic-ids2018",
                "data_category": "historical_import",
                "observed_at": "2018-02-14T09:00:00+00:00",
                "event_type": "network_flow",
                "src_ip": "192.168.1.10",
                "dst_ip": "10.0.0.1",
                "src_port": 54321,
                "dst_port": 80,
                "protocol": "TCP",
                "duration": 1.5,
                "packets": 12,
                "bytes_total": 1024,
                "label": "Benign",
                "label_provenance": "dataset_ground_truth",
                "quality_flags": [],
            }
        }
    }


class ValidationResult(BaseModel):
    """Result of validating a raw record before normalization."""
    is_valid: bool
    event: Optional[NormalizedEvent] = None
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    raw_reference: Optional[str] = None


class ImportSummary(BaseModel):
    """Summary of a data import operation."""
    import_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    source_id: str
    source_file: Optional[str] = None
    data_category: DataCategory
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: Optional[datetime] = None
    total_records: int = 0
    accepted_records: int = 0
    rejected_records: int = 0
    warnings_count: int = 0
    rejection_reasons: dict[str, int] = Field(default_factory=dict)
    schema_version: str = SCHEMA_VERSION


class TelemetrySource(BaseModel):
    """Registered telemetry source."""
    source_id: str
    name: str
    source_type: str  # e.g., "csv_import", "zeek", "live_capture"
    description: Optional[str] = None
    enabled: bool = True
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_event_at: Optional[datetime] = None
    event_count: int = 0
    status: str = "active"  # active, disabled, error, disconnected


class DescriptiveAnalysis(BaseModel):
    """
    Results of descriptive historical analysis.

    This is NOT forecasting. It summarizes observed historical data.
    """
    analysis_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    analysis_type: str = "descriptive_historical"
    source_id: str
    computed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    schema_version: str = SCHEMA_VERSION
    data_category: DataCategory = DataCategory.HISTORICAL_IMPORT

    # Counts
    total_events: int = 0
    events_by_type: dict[str, int] = Field(default_factory=dict)
    events_by_label: dict[str, int] = Field(default_factory=dict)
    events_by_protocol: dict[str, int] = Field(default_factory=dict)

    # Time range
    time_range_start: Optional[datetime] = None
    time_range_end: Optional[datetime] = None

    # Data quality
    missing_field_counts: dict[str, int] = Field(default_factory=dict)
    quality_flag_counts: dict[str, int] = Field(default_factory=dict)
    records_with_warnings: int = 0

    # Network summary
    unique_src_ips: int = 0
    unique_dst_ips: int = 0
    unique_src_ports: int = 0
    unique_dst_ports: int = 0
    top_src_ips: list[dict] = Field(default_factory=list)
    top_dst_ips: list[dict] = Field(default_factory=list)
    top_dst_ports: list[dict] = Field(default_factory=list)

    # Flow metrics summary
    avg_duration: Optional[float] = None
    avg_packets: Optional[float] = None
    avg_bytes: Optional[float] = None
    total_bytes: Optional[int] = None
