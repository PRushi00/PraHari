"""
PraHari — Telemetry Source Capability Declarations

States, per source type, which canonical fields that source can structurally
provide. Analytics and the UI consult this to tell two very different things
apart:

  * a field the source **cannot measure** (a known limit of the sensor), and
  * a field the source **should have provided** but did not (a real defect).

Collapsing those makes a structurally limited source — such as the Windows
connection table, which exposes no byte or packet counts — look as though it
is failing validation on every record.
"""

from __future__ import annotations

from app.schemas.events import (
    CAPABILITY_FIELDS,
    FieldAvailability,
    SourceCapability,
)

POP = FieldAvailability.POPULATED
MISS = FieldAvailability.MISSING_UNEXPECTED
UNSUP = FieldAvailability.UNSUPPORTED_BY_SOURCE


def _cap(source_type: str, description: str, supported: dict, limitations: list[str]) -> SourceCapability:
    """Build a capability with every unlisted field marked unsupported."""
    fields = {f: UNSUP for f in CAPABILITY_FIELDS}
    fields.update(supported)
    return SourceCapability(
        source_type=source_type,
        description=description,
        fields=fields,
        limitations=limitations,
    )


# ──────────────────────────────────────────────────────────────────
# Declarations
# ──────────────────────────────────────────────────────────────────

WINDOWS_CONNECTION_TABLE = _cap(
    source_type="windows_connection_table",
    description="Local Windows TCP connection table (Get-NetTCPConnection).",
    supported={
        "src_ip": POP,
        "dst_ip": POP,
        "src_port": POP,
        "dst_port": POP,
        "protocol": POP,
    },
    limitations=[
        "Connection metadata only — this is not packet capture and not flow accounting.",
        "Byte counts, packet counts and completed-flow duration are not exposed by the Windows connection table and are therefore never populated.",
        "Application-layer detail (HTTP method, path, status, timing) is not observable from this source.",
        "A destination hostname is not reported by this source; hostnames are inferred separately from local DNS observations and carry their own confidence.",
        "Snapshot polling: connections opening and closing entirely between polls are never observed.",
        "No attack labels exist for locally observed traffic, so none are assigned.",
    ],
)

CSV_IMPORT = _cap(
    source_type="csv_import",
    description="Historical flow records imported from CSV (e.g. CIC-IDS format).",
    supported={
        "src_ip": POP, "dst_ip": POP, "src_port": POP, "dst_port": POP,
        "protocol": POP, "duration": POP, "packets": POP, "bytes_total": POP,
        "label": POP,
    },
    limitations=[
        "Historical import — not live observation of this host.",
        "Field completeness depends on the originating dataset's columns.",
    ],
)

JSON_STREAM = _cap(
    source_type="json_stream",
    description="Zeek conn.log / Suricata EVE NDJSON records.",
    supported={
        "src_ip": POP, "dst_ip": POP, "src_port": POP, "dst_port": POP,
        "protocol": POP, "duration": POP, "packets": POP, "bytes_total": POP,
        "label": POP,
    },
    limitations=[
        "Field completeness depends on the emitting sensor's configuration.",
        "Flow metrics are present only when the sensor records them.",
    ],
)

SYNTHETIC_REPLAY = _cap(
    source_type="synthetic_replay",
    description="Fabricated records for offline testing and demonstration.",
    supported={
        "src_ip": POP, "dst_ip": POP, "src_port": POP, "dst_port": POP,
        "protocol": POP, "duration": POP, "packets": POP, "bytes_total": POP,
        "label": POP,
    },
    limitations=[
        "SYNTHETIC: these records are generated, not observed. They must never "
        "be used as evidence of real-world behaviour or model performance.",
    ],
)

APPLICATION_LAYER = _cap(
    source_type="application_layer",
    description=(
        "Authorized application-layer telemetry source reporting HTTP request "
        "metadata (opt-in; disabled by default)."
    ),
    supported={
        "src_ip": MISS, "dst_ip": POP, "dst_port": POP, "protocol": POP,
        "http_method": POP, "http_path": POP, "http_status_code": POP,
        "http_duration_ms": POP, "dst_hostname": POP,
    },
    limitations=[
        "Reports only requests made through the instrumented application; it is not host-wide.",
        "Request and response bodies, cookies, credentials and authorization headers are never collected.",
        "Query strings are redacted unless explicitly enabled by the operator.",
    ],
)

AGGREGATE = _cap(
    source_type="aggregate",
    description="Placeholder source representing an analysis across several sources.",
    supported={},
    limitations=["Not a telemetry source; capabilities depend on the underlying sources."],
)

UNKNOWN = _cap(
    source_type="unknown",
    description="Source type with no declared capability profile.",
    supported={f: MISS for f in CAPABILITY_FIELDS},
    limitations=["No capability profile is declared for this source type; field absence cannot be interpreted."],
)


_REGISTRY: dict[str, SourceCapability] = {
    c.source_type: c
    for c in (
        WINDOWS_CONNECTION_TABLE,
        CSV_IMPORT,
        JSON_STREAM,
        SYNTHETIC_REPLAY,
        APPLICATION_LAYER,
        AGGREGATE,
    )
}


def get_capability(source_type: str | None) -> SourceCapability:
    """
    Capability profile for a source type.

    An unrecognised type returns the UNKNOWN profile, which marks every field
    as "supported but missing" — the conservative reading, since absence
    cannot be excused by a limit that has not been declared.
    """
    if not source_type:
        return UNKNOWN
    return _REGISTRY.get(source_type, UNKNOWN)


def list_capabilities() -> list[SourceCapability]:
    """All declared capability profiles."""
    return list(_REGISTRY.values())
