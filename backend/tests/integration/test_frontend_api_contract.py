"""
Frontend/backend contract tests.

These exist because of a specific production failure: the dashboard's
`FeasibilityReport` TypeScript interface described a schema the backend had
never produced (`audit_id`, `overall_feasibility_score`,
`temporal_monotonicity`, …). The interface was internally consistent, so
`tsc` accepted it, and the mismatch only appeared at runtime as
`undefined.toFixed(...)` — which, with no error boundary, unmounted the
entire React tree and blanked the application.

Type-checking the frontend alone cannot catch this: the types were the
thing that was wrong. These tests compare the TypeScript interfaces against
the live OpenAPI schema, so a divergence fails CI instead of the dashboard.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import app

FRONTEND_TYPES = (
    Path(__file__).resolve().parents[3] / "frontend" / "src" / "types" / "index.ts"
)

# TypeScript interface -> backend OpenAPI schema component.
MODEL_PAIRS = [
    ("FeasibilityReport", "FeasibilityReport"),
    ("FeasibilityCheckResult", "FeasibilityCheckResult"),
    ("NormalizedEvent", "NormalizedEvent"),
    ("TelemetrySource", "TelemetrySource"),
    ("DescriptiveAnalysis", "DescriptiveAnalysis"),
    ("ImportSummary", "ImportSummary"),
    ("ModelMetrics", "ModelMetrics"),
    ("PredictionResult", "PredictionResult"),
    ("CollectorStatus", "CollectorStatus"),
    ("PollResult", "PollResult"),
    ("ReadinessReport", "ReadinessReport"),
    ("SplitIntegrityReport", "SplitIntegrityReport"),
    ("DomainAttribution", "DomainAttribution"),
    ("SourceCapability", "SourceCapability"),
    ("AuditLog", "AuditLogItem"),
    ("AdapterHealth", "AdapterHealth"),
    ("SecurityConfig", "SystemConfigReport"),
    ("HealthResponse", "HealthResponse"),
    ("EventSummaryStats", "EventSummaryStats"),
    ("ConnectionDetail", "ConnectionDetail"),
    ("CollectionGap", "CollectionGap"),
    ("FeatureContribution", None),  # built in code, not a Pydantic model
    ("ReadinessRequirement", "Requirement"),
]

# Interfaces that intentionally have no backend counterpart: purely local
# view-models, enums, or aliases. Anything NOT listed here and NOT paired
# above fails `test_every_interface_is_accounted_for`, so a new interface
# cannot silently escape contract checking.
#
# This list exists because the Stream & Replay crash slipped through: the
# frontend declared `SyntheticReplayResponse` with invented fields
# (duration_seconds, simulated_attack_ratio, …) while the endpoint actually
# returns an ImportSummary. No schema of that name existed, so the original
# comparison skipped it silently and `duration_seconds.toFixed(2)` threw.
LOCAL_ONLY_INTERFACES = {
    "PaginatedEventsResponse",      # inline response model
    "PaginatedConnectionsResponse",  # inline response model
    "FeasibilityMetric",            # removed legacy helper shape
    "FeatureContribution",          # dict built in forecaster code
    "AppLayerStatus",               # plain dict response
    "EnrichmentStatus",             # plain dict response
    "SyntheticReplayResponse",      # alias of ImportSummary
    # Enum unions — checked by value, not by field, below.
    "DataCategory",
    "EventType",
    "LabelProvenance",
    "QualityFlag",
}

# Frontend union type -> backend Enum class. Checked by VALUE.
ENUM_PAIRS = [
    ("DataCategory", "DataCategory"),
    ("EventType", "EventType"),
    ("LabelProvenance", "LabelProvenance"),
    ("QualityFlag", "QualityFlag"),
]


@pytest.fixture(scope="module")
def openapi_schemas() -> dict:
    with TestClient(app) as client:
        spec = client.get("/openapi.json").json()
    return spec["components"]["schemas"]


@pytest.fixture(scope="module")
def ts_source() -> str:
    assert FRONTEND_TYPES.exists(), f"frontend types not found at {FRONTEND_TYPES}"
    return FRONTEND_TYPES.read_text(encoding="utf-8")


def _ts_fields(source: str, interface: str) -> set[str] | None:
    """
    Top-level field names declared on a TypeScript interface.

    Brace-aware: fields of a nested inline object (such as
    ``HealthResponse.database``) belong to that nested object, not to the
    interface, and must not be compared against the parent schema.
    """
    match = re.search(rf"export interface {interface} \{{(.*?)\n\}}", source, re.S)
    if not match:
        return None
    body = match.group(1)
    # Strip comments so commented-out examples are not read as fields.
    body = re.sub(r"//.*", "", body)
    body = re.sub(r"/\*.*?\*/", "", body, flags=re.S)

    fields: set[str] = set()
    depth = 0
    for line in body.splitlines():
        stripped = line.strip()
        if depth == 0:
            m = re.match(r"([A-Za-z_][A-Za-z0-9_]*)\??\s*:", stripped)
            if m:
                fields.add(m.group(1))
        depth = max(0, depth + stripped.count("{") - stripped.count("}"))
    return fields


def _schema_fields(schemas: dict, name: str) -> set[str] | None:
    schema = schemas.get(name)
    if schema is None:
        return None
    return set(schema.get("properties", {}).keys())


@pytest.mark.parametrize(
    "ts_name,schema_name", [(t, s) for t, s in MODEL_PAIRS if s is not None]
)
def test_frontend_type_has_no_phantom_fields(
    ts_name, schema_name, openapi_schemas, ts_source
):
    """
    Every field the dashboard declares must exist in the API response.

    A phantom field is `undefined` at runtime; calling a method on it
    throws during render.
    """
    ts_fields = _ts_fields(ts_source, ts_name)
    schema_fields = _schema_fields(openapi_schemas, schema_name)

    assert ts_fields is not None, f"TypeScript interface {ts_name} not found"
    assert schema_fields is not None, f"OpenAPI schema {schema_name} not found"

    phantom = ts_fields - schema_fields
    assert not phantom, (
        f"{ts_name} declares field(s) the backend never returns: "
        f"{sorted(phantom)}. These are undefined at runtime and will throw "
        f"if a method is called on them. Backend provides: {sorted(schema_fields)}"
    )


def test_feasibility_report_contract_specifically(openapi_schemas, ts_source):
    """
    Pin the exact fields the Feasibility page renders.

    Regression for the blank-page failure.
    """
    schema_fields = _schema_fields(openapi_schemas, "FeasibilityReport")
    assert schema_fields is not None

    for required in (
        "dataset_id", "evaluated_at", "gate_passed",
        "overall_score", "recommendation", "checks", "metrics",
    ):
        assert required in schema_fields, f"backend lost field {required}"

    # The fields the broken page used must stay absent, so a reintroduction
    # is caught rather than silently reviving the crash.
    for phantom in (
        "audit_id", "overall_feasibility_score", "temporal_monotonicity",
        "class_balance", "label_provenance", "source_diversity",
        "causal_leakage_risk", "advisory_warnings", "total_events",
    ):
        assert phantom not in schema_fields

    ts_fields = _ts_fields(ts_source, "FeasibilityReport")
    assert ts_fields == schema_fields, (
        "Feasibility TypeScript interface and backend schema have diverged: "
        f"frontend-only={sorted(ts_fields - schema_fields)}, "
        f"backend-only={sorted(schema_fields - ts_fields)}"
    )


def test_prediction_feature_attribution_uses_impact_not_contribution():
    """
    The dashboard previously read `feat.contribution`, which the backend
    never emits — `undefined.toFixed(3)` crashed the Forecasting page after
    a prediction.
    """
    from app.models.forecaster import ThreatForecastingPipeline
    from datetime import datetime, timedelta, timezone
    from app.schemas.events import EventType, NormalizedEvent

    pipeline = ThreatForecastingPipeline()
    base = datetime.now(timezone.utc) - timedelta(minutes=5)
    events = [
        NormalizedEvent(
            source_id="s",
            observed_at=base + timedelta(seconds=i * 5),
            event_type=EventType.NETWORK_FLOW,
            src_ip="10.0.0.1", dst_ip="10.0.0.2",
            src_port=1000 + i, dst_port=443, protocol="TCP",
        )
        for i in range(20)
    ]
    result = pipeline.predict_recent_window(events)

    assert result.top_contributing_features
    for feat in result.top_contributing_features:
        assert "impact" in feat
        assert "value" in feat
        assert "feature" in feat
        assert "contribution" not in feat, (
            "field renamed — update the dashboard before changing this"
        )


def test_audit_log_contract_uses_timestamp_and_id(openapi_schemas, ts_source):
    """The dashboard previously read log.created_at / log.log_id."""
    schema_fields = _schema_fields(openapi_schemas, "AuditLogItem")
    assert schema_fields is not None
    assert "timestamp" in schema_fields and "id" in schema_fields
    assert "created_at" not in schema_fields and "log_id" not in schema_fields

    ts_fields = _ts_fields(ts_source, "AuditLog")
    assert ts_fields is not None
    assert "created_at" not in ts_fields and "log_id" not in ts_fields


def test_every_interface_is_accounted_for(ts_source, openapi_schemas):
    """
    No TypeScript interface may escape contract checking by accident.

    Every exported interface must either be paired with a backend schema in
    MODEL_PAIRS or declared local-only. The Stream & Replay crash happened
    precisely because an unpaired interface was skipped silently.
    """
    declared = set(re.findall(r"export interface ([A-Za-z0-9_]+)", ts_source))
    declared |= set(re.findall(r"export type ([A-Za-z0-9_]+)\s*=", ts_source))

    paired = {t for t, _ in MODEL_PAIRS}
    unaccounted = declared - paired - LOCAL_ONLY_INTERFACES

    assert not unaccounted, (
        "These frontend interfaces are neither paired with a backend schema "
        f"nor declared local-only: {sorted(unaccounted)}. Add each to "
        "MODEL_PAIRS (if the API returns it) or to LOCAL_ONLY_INTERFACES "
        "(if it is a view-model), so it cannot silently drift from the API."
    )


def test_synthetic_replay_returns_import_summary(openapi_schemas):
    """
    Regression: the Stream & Replay page read `duration_seconds` and
    `simulated_attack_ratio` from this endpoint. It returns an
    ImportSummary, which has neither, so `.toFixed(2)` threw.
    """
    spec_fields = _schema_fields(openapi_schemas, "ImportSummary")
    assert spec_fields is not None

    for phantom in (
        "duration_seconds", "simulated_attack_ratio",
        "generated_records", "status",
    ):
        assert phantom not in spec_fields, (
            f"ImportSummary unexpectedly gained {phantom}; update the frontend"
        )

    # The fields the page now renders must exist.
    for required in (
        "total_records", "accepted_records", "rejected_records",
        "started_at", "completed_at", "data_category",
    ):
        assert required in spec_fields, f"ImportSummary lost {required}"


def test_replay_endpoint_response_model_is_import_summary():
    """The route itself must keep returning ImportSummary."""
    with TestClient(app) as client:
        spec = client.get("/openapi.json").json()
    path = spec["paths"]["/api/v1/stream/replay/synthetic"]["post"]
    ref = path["responses"]["200"]["content"]["application/json"]["schema"]["$ref"]
    assert ref.endswith("/ImportSummary"), ref


def _ts_union_values(source: str, type_name: str) -> set[str] | None:
    """String literal members of an exported TypeScript union type."""
    match = re.search(
        rf"export type {type_name}\s*=(.*?);", source, re.S
    )
    if not match:
        return None
    body = re.sub(r"//.*", "", match.group(1))
    return set(re.findall(r'"([^"]+)"', body))


@pytest.mark.parametrize("ts_name,enum_name", ENUM_PAIRS)
def test_enum_unions_match_backend_values(ts_name, enum_name, ts_source):
    """
    Frontend union types must list exactly the backend enum's values.

    These had drifted severely: DataCategory omitted "live_telemetry" and
    EventType omitted "connection" — the two values the live Windows
    collector actually emits. Type erasure means this never crashes, so
    nothing else would catch it.
    """
    import app.schemas.events as events_module

    enum_cls = getattr(events_module, enum_name)
    backend_values = {m.value for m in enum_cls}
    ts_values = _ts_union_values(ts_source, ts_name)

    assert ts_values is not None, f"union type {ts_name} not found"
    assert ts_values == backend_values, (
        f"{ts_name} has drifted from backend {enum_name}: "
        f"frontend-only={sorted(ts_values - backend_values)}, "
        f"backend-only={sorted(backend_values - ts_values)}"
    )
