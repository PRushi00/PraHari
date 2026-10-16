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
    # A locally bound UDP socket. NOT a conversation: UDP is connectionless
    # and the OS records no peer, so these carry no destination.
    UDP_ENDPOINT = "udp_endpoint"
    ALERT = "alert"
    HOST_EVENT = "host_event"
    UNKNOWN = "unknown"


class DataCategory(str, Enum):
    """Category distinguishing the origin/nature of ingested data."""
    LIVE_TELEMETRY = "live_telemetry"
    HISTORICAL_IMPORT = "historical_import"
    # Used only by aggregate results (e.g. an analysis spanning several
    # categories). A stored event is never MIXED or UNDETERMINED.
    MIXED = "mixed"
    # An aggregate over zero events: no provenance can be derived, and
    # claiming any particular category would be an invention.
    UNDETERMINED = "undetermined"
    HISTORICAL_REPLAY = "historical_replay"
    SYNTHETIC_DEMO = "synthetic_demo"
    SYNTHETIC = "synthetic_demo"
    TEST_FIXTURE = "test_fixture"


class LabelProvenance(str, Enum):
    """
    How a label was assigned to an event.

    These are not interchangeable. A label's provenance determines whether it
    may be treated as a training target: dataset ground truth and analyst
    annotation are evidence about what happened, whereas a detector's output
    or a generator's rule is evidence about what some *system decided*.
    """

    # A label supplied by the corpus itself (e.g. a CSE-CIC-IDS2018 flow label).
    DATASET_GROUND_TRUTH = "dataset_ground_truth"

    # Derived locally by a deterministic rule over observed fields.
    RULE_BASED = "rule_based"

    # Produced by the synthetic generator. MUST remain distinguishable from
    # RULE_BASED: synthetic labels describe data that was invented, so a
    # metric computed over them is not evidence about real traffic.
    SYNTHETIC_RULE = "synthetic_rule"

    # Emitted by a detector (Suricata signature, Zeek notice, EDR verdict).
    # This is the detector's opinion, NOT confirmation that an attack
    # occurred, and must never be presented as ground truth.
    DETECTOR_OUTPUT = "detector_output"

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
    # Informational, NOT a data defect: the telemetry source is structurally
    # incapable of providing one or more canonical fields. Distinguished from
    # MISSING_FIELD, which means a field the source *can* provide was absent.
    SOURCE_LIMITED = "source_limited"


class FieldAvailability(str, Enum):
    """
    Why a canonical field does or does not carry a value.

    A null is not self-explanatory: "the source cannot measure this" and
    "the source should have provided this but did not" are different facts
    with different consequences. Collapsing them makes a structurally
    limited source look like a broken one.
    """
    POPULATED = "populated"                    # value present and valid
    MISSING_UNEXPECTED = "missing_unexpected"  # source supports it; value absent
    UNSUPPORTED_BY_SOURCE = "unsupported_by_source"  # source cannot provide it
    NOT_APPLICABLE = "not_applicable"          # meaningless for this event type
    INVALID = "invalid"                        # present but failed validation


# Canonical fields whose availability varies by telemetry source.
# ──────────────────────────────────────────────────────────────────
# Timestamp plausibility — ONE policy, in one place
# ──────────────────────────────────────────────────────────────────
#
# Windows reports an unset socket creation time as the FILETIME epoch
# (1601-01-01). A single such record implies a ~425-year observation span,
# which silently corrupts every time-ordered calculation: window
# generation, split boundaries, rate features, and any audit that measures
# elapsed observation.
#
# This policy previously existed as three separate copies — in the adapter,
# the readiness gate and (not at all) in the descriptive analysis. They
# disagreed: readiness reported an 18-hour span for the same dataset the
# feasibility audit scored at 100% temporal integrity across 425 years.
# One definition, imported everywhere, is the fix.

MIN_PLAUSIBLE_YEAR = 2000
MAX_CLOCK_SKEW_SECONDS = 3600.0


def is_plausible_timestamp(
    value: "datetime | None", now: "datetime | None" = None
) -> bool:
    """
    True when a timestamp could describe a real observation on this host.

    Rejects pre-2000 values (the FILETIME epoch and similar sentinels) and
    anything more than an hour in the future (clock skew beyond this is not
    skew). Naive datetimes are read as UTC.
    """
    if value is None:
        return False
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    if value.year < MIN_PLAUSIBLE_YEAR:
        return False
    reference = now or datetime.now(timezone.utc)
    if reference.tzinfo is None:
        reference = reference.replace(tzinfo=timezone.utc)
    return (value - reference).total_seconds() <= MAX_CLOCK_SKEW_SECONDS


CAPABILITY_FIELDS = (
    "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
    "duration", "packets", "bytes_total",
    "label",
    "http_method", "http_path", "http_status_code", "http_duration_ms",
    "dst_hostname",
)


class SourceCapability(BaseModel):
    """
    What a telemetry source is structurally able to report.

    Declared once per source rather than inferred per event, so analytics can
    tell "this source never measures bytes" from "this record lost its byte
    count". Consumers must not treat an UNSUPPORTED_BY_SOURCE field as a
    data-quality defect.
    """
    source_type: str
    description: str = ""
    # field name -> availability when the source is working correctly
    fields: dict[str, FieldAvailability] = Field(default_factory=dict)
    # Plain-language limits, surfaced in the API and UI verbatim.
    limitations: list[str] = Field(default_factory=list)

    def availability_of(self, field: str) -> FieldAvailability:
        return self.fields.get(field, FieldAvailability.UNSUPPORTED_BY_SOURCE)

    def supports(self, field: str) -> bool:
        return self.availability_of(field) in (
            FieldAvailability.POPULATED,
            FieldAvailability.MISSING_UNEXPECTED,
        )

    def unsupported_fields(self) -> list[str]:
        return sorted(
            f for f in CAPABILITY_FIELDS
            if self.fields.get(f, FieldAvailability.UNSUPPORTED_BY_SOURCE)
            in (FieldAvailability.UNSUPPORTED_BY_SOURCE, FieldAvailability.NOT_APPLICABLE)
        )


class DomainAttributionMethod(str, Enum):
    """How a destination hostname was associated with a connection."""
    DNS_CACHE_OBSERVATION = "dns_cache_observation"
    DNS_QUERY_LOG = "dns_query_log"
    APPLICATION_LAYER_REPORTED = "application_layer_reported"
    REVERSE_DNS = "reverse_dns"
    NONE = "none"


class AttributionConfidence(str, Enum):
    """
    Confidence that a hostname is the name the application actually used.

    Deliberately coarse: the evidence available locally does not support
    finer gradations, and a numeric score would imply precision we do not have.
    """
    HIGH = "high"        # single recent local resolution for this exact IP
    MEDIUM = "medium"    # recent resolution, but shared/CDN IP or several candidates
    LOW = "low"          # stale, ambiguous, or weakly correlated evidence
    NONE = "none"        # no defensible association


class DomainAttribution(BaseModel):
    """
    A hostname association for a destination IP, carried with its evidence.

    This is an inference, never a fact recorded by the connection itself. The
    original connection record and its destination IP are preserved
    regardless of whether attribution succeeds.
    """
    hostname: Optional[str] = None
    method: DomainAttributionMethod = DomainAttributionMethod.NONE
    confidence: AttributionConfidence = AttributionConfidence.NONE
    evidence_observed_at: Optional[datetime] = None
    evidence_age_seconds: Optional[float] = None
    # Other hostnames seen resolving to the same IP, which is why a shared or
    # CDN address cannot be attributed with high confidence.
    candidate_hostnames: list[str] = Field(default_factory=list)
    candidate_count: int = 0
    limitations: list[str] = Field(default_factory=list)

    identifies_requested_host: bool = Field(
        default=False,
        description=(
            "True only when the evidence speaks to the hostname the application "
            "actually requested (a DNS resolution it performed, or a direct "
            "report from an application-layer source). False for reverse DNS, "
            "which names whoever owns the address — often a CDN edge — and is "
            "frequently unrelated to the site the user visited."
        ),
    )
    attribution_kind: str = Field(
        default="none",
        description="'requested_host', 'infrastructure_owner', or 'none'.",
    )

    @property
    def is_attributed(self) -> bool:
        return self.hostname is not None


# Flags that describe PROVENANCE or a known SOURCE LIMIT rather than a
# defect in the record. Counting these as quality warnings makes every
# synthetic fixture and every record from a structurally limited sensor
# look malformed, which buries the genuine defects.
NON_DEFECT_QUALITY_FLAGS: frozenset = frozenset(
    {QualityFlag.SOURCE_LIMITED, QualityFlag.SYNTHETIC_SAMPLE}
)


def is_quality_defect(flag: "QualityFlag") -> bool:
    """True when a flag indicates something actually wrong with the record."""
    return flag not in NON_DEFECT_QUALITY_FLAGS


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
        description=(
            "When this event object was CONSTRUCTED inside the backend. "
            "Close to processing time, but NOT a receipt timestamp: for a "
            "bulk import it is when the row was normalized, not when the "
            "data arrived. Use received_at for receipt."
        ),
    )
    received_at: Optional[datetime] = Field(
        default=None,
        description=(
            "Server receipt time, captured at the API boundary when a remote "
            "source SUBMITTED this event. Never supplied by the client. "
            "None means 'no measured receipt time' and is the correct value "
            "for events the backend produced itself (local collection), for "
            "historical imports whose original arrival time is unknown, and "
            "for records written before this field existed. It is never "
            "backfilled or inferred."
        ),
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

    # ── Application-layer fields ──
    # Populated ONLY by an authorized application-layer telemetry source.
    # The Windows connection-table collector cannot observe any of these and
    # always leaves them null; a value here means an app-layer source
    # reported it, never that it was inferred from a port number.
    app_protocol: Optional[str] = Field(
        default=None,
        description="Application protocol as REPORTED by an app-layer source (never inferred from port)."
    )
    http_method: Optional[str] = Field(
        default=None, description="HTTP request method, if reported by an app-layer source."
    )
    http_path: Optional[str] = Field(
        default=None, description="HTTP request path, if reported by an app-layer source."
    )
    http_status_code: Optional[int] = Field(
        default=None, ge=100, le=599,
        description="HTTP response status, if reported by an app-layer source. Never a TCP state."
    )
    http_duration_ms: Optional[float] = Field(
        default=None, ge=0,
        description="HTTP request duration in ms, if reported by an app-layer source."
    )
    dst_hostname: Optional[str] = Field(
        default=None,
        description=(
            "Destination hostname as REPORTED by the source itself (e.g. an "
            "app-layer source that knows the requested host). Hostnames merely "
            "inferred from DNS observations are NOT stored here; they are "
            "returned as a separate DomainAttribution with evidence."
        ),
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

    # ── Storage outcome (ADR-050) ──
    #
    # accepted_records counts what PARSED and validated. It says nothing
    # about what was STORED: a retry of an already-ingested batch parses
    # perfectly and stores nothing. These two separate the cases so a
    # caller is not told "accepted 500" for a request that wrote no rows.
    #
    # Optional, and None on every path that does not report storage
    # (file imports, synthetic replay), so existing consumers are
    # unaffected. Neither field is persisted to import_summaries — see
    # save_import_summary — so no migration is required.
    stored_records: Optional[int] = Field(
        default=None,
        description="Rows newly written by this request. None when not reported.",
    )
    duplicate_records: Optional[int] = Field(
        default=None,
        description=(
            "Records that parsed and were already present under the same "
            "event identity with identical canonical content, so nothing "
            "was written. None when not reported."
        ),
    )


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

    # Records whose observed_at could not describe a real observation
    # (FILETIME epoch, far future). Excluded from the range above.
    implausible_timestamp_events: Optional[int] = None

    # How many records actually carried each measurement. The averages below
    # are over these counts, not over total_events — on a mixed dataset the
    # two differ by an order of magnitude.
    duration_measured_count: Optional[int] = None
    packets_measured_count: Optional[int] = None
    bytes_measured_count: Optional[int] = None

    # ── Derived provenance ──
    # Computed FROM the analyzed events, never supplied by the caller. The
    # caller may choose WHICH events to analyze; it may not declare what they
    # are. (A caller-declared category previously stamped every analysis
    # 'historical_import' regardless of the data it summarized.)
    data_categories: dict[str, int] = Field(
        default_factory=dict,
        description="Event count per data_category actually present in the analyzed set.",
    )
    source_breakdown: dict[str, int] = Field(
        default_factory=dict,
        description="Event count per source_id actually present in the analyzed set.",
    )
    is_mixed_provenance: bool = Field(
        default=False,
        description="True when the analyzed set spans more than one data_category.",
    )

    # Data quality
    missing_field_counts: dict[str, int] = Field(
        default_factory=dict,
        description=(
            "Fields absent where the contributing source DOES support them. "
            "Genuine gaps — see unsupported_field_counts for structural limits."
        ),
    )
    unsupported_field_counts: dict[str, int] = Field(
        default_factory=dict,
        description=(
            "Fields absent because the contributing source cannot provide them. "
            "NOT a data-quality defect; reported separately so a structurally "
            "limited source is not mistaken for a failing one."
        ),
    )
    source_limitations: list[str] = Field(
        default_factory=list,
        description="Plain-language limits of the sources contributing to this analysis.",
    )
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

    # ── Connection intelligence (populated where the data supports it) ──
    events_by_connection_state: dict[str, int] = Field(default_factory=dict)
    events_by_process: dict[str, int] = Field(default_factory=dict)
    top_dst_hostnames: list[dict] = Field(default_factory=list)
    hostname_attributed_count: int = Field(
        default=0, description="Events for which a destination hostname could be attributed."
    )
    events_per_hour: dict[str, int] = Field(
        default_factory=dict, description="Observation counts bucketed by UTC hour."
    )

    # Flow metrics summary
    avg_duration: Optional[float] = None
    avg_packets: Optional[float] = None
    avg_bytes: Optional[float] = None
    total_bytes: Optional[int] = None
