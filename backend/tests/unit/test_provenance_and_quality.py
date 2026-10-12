"""
Regression tests for telemetry provenance and data-quality semantics.

Two classes of defect are covered:

  * **Provenance loss / misclassification.** An analysis must describe the
    data it summarized. A caller-supplied category previously stamped every
    analysis ``historical_import`` — including analyses of live telemetry.

  * **Quality misreporting.** A field the source cannot measure is not a
    defect. Reporting it as one marks every record from a limited source as
    faulty and buries genuine gaps.
"""

from datetime import datetime, timedelta, timezone

import pytest

from app.adapters.capabilities import get_capability
from app.schemas.events import (
    DataCategory,
    EventType,
    FieldAvailability,
    LabelProvenance,
    NormalizedEvent,
    QualityFlag,
)
from app.services.analysis import compute_descriptive_analysis

BASE = datetime(2026, 10, 11, 12, 0, 0, tzinfo=timezone.utc)


def _live_connection(i: int = 0, **kw) -> NormalizedEvent:
    """A live Windows connection record, with its genuine field absences."""
    defaults = dict(
        source_id="windows_local_host",
        data_category=DataCategory.LIVE_TELEMETRY,
        observed_at=BASE + timedelta(seconds=i * 10),
        event_type=EventType.CONNECTION,
        src_ip="192.0.2.10",
        dst_ip=f"93.184.216.{10 + i}",
        src_port=50000 + i,
        dst_port=443,
        protocol="TCP",
        duration=None,
        packets=None,
        bytes_total=None,
        label=None,
        label_provenance=LabelProvenance.UNLABELED,
        quality_flags=[QualityFlag.SOURCE_LIMITED],
        raw_reference=f"windows:tcp;state=Established;pid={1000 + i};process=msedge",
    )
    defaults.update(kw)
    return NormalizedEvent(**defaults)


def _imported_flow(i: int = 0, **kw) -> NormalizedEvent:
    defaults = dict(
        source_id="perimeter_flow_sensor",
        data_category=DataCategory.HISTORICAL_IMPORT,
        observed_at=BASE + timedelta(seconds=i * 10),
        event_type=EventType.NETWORK_FLOW,
        src_ip="10.0.0.5",
        dst_ip="10.0.0.9",
        src_port=40000 + i,
        dst_port=80,
        protocol="TCP",
        duration=1.5,
        packets=12,
        bytes_total=1024,
        label="Benign",
        label_provenance=LabelProvenance.DATASET_GROUND_TRUTH,
    )
    defaults.update(kw)
    return NormalizedEvent(**defaults)


WINDOWS_TYPES = {"windows_local_host": "windows_connection_table"}
CSV_TYPES = {"perimeter_flow_sensor": "csv_import"}
BOTH_TYPES = {**WINDOWS_TYPES, **CSV_TYPES}


# ──────────────────────────────────────────────────────────────────
# Provenance derivation
# ──────────────────────────────────────────────────────────────────


def test_live_telemetry_analysis_is_not_labelled_historical():
    """
    Regression: analysing live telemetry produced an analysis stamped
    'historical_import', because the category came from a request default
    rather than from the data.
    """
    events = [_live_connection(i) for i in range(5)]
    analysis = compute_descriptive_analysis(events, "all_sources", source_types=WINDOWS_TYPES)

    assert analysis.data_category == DataCategory.LIVE_TELEMETRY
    assert analysis.data_categories == {"live_telemetry": 5}
    assert analysis.is_mixed_provenance is False


def test_imported_analysis_is_labelled_historical():
    events = [_imported_flow(i) for i in range(4)]
    analysis = compute_descriptive_analysis(events, "all_sources", source_types=CSV_TYPES)
    assert analysis.data_category == DataCategory.HISTORICAL_IMPORT
    assert analysis.data_categories == {"historical_import": 4}


def test_mixed_sources_are_reported_as_mixed_not_as_one_category():
    """An analysis spanning categories must not claim to be any single one."""
    events = [_live_connection(i) for i in range(3)] + [_imported_flow(i) for i in range(2)]
    analysis = compute_descriptive_analysis(events, "all_sources", source_types=BOTH_TYPES)

    assert analysis.is_mixed_provenance is True
    assert analysis.data_category == DataCategory.MIXED
    assert analysis.data_categories == {"live_telemetry": 3, "historical_import": 2}
    assert analysis.source_breakdown == {
        "windows_local_host": 3,
        "perimeter_flow_sensor": 2,
    }


def test_empty_analysis_is_undetermined_not_invented():
    analysis = compute_descriptive_analysis([], "all_sources", source_types={})
    assert analysis.data_category == DataCategory.UNDETERMINED
    assert analysis.total_events == 0
    assert analysis.data_categories == {}


def test_source_breakdown_totals_match_event_count():
    events = [_live_connection(i) for i in range(6)] + [_imported_flow(i) for i in range(3)]
    analysis = compute_descriptive_analysis(events, "all_sources", source_types=BOTH_TYPES)

    assert sum(analysis.source_breakdown.values()) == analysis.total_events
    assert sum(analysis.data_categories.values()) == analysis.total_events


# ──────────────────────────────────────────────────────────────────
# Data-quality semantics
# ──────────────────────────────────────────────────────────────────


def test_unsupported_fields_are_not_reported_as_missing():
    """
    duration/packets/bytes_total are unobtainable from the connection table.
    They belong in unsupported_field_counts, never in missing_field_counts.
    """
    events = [_live_connection(i) for i in range(5)]
    analysis = compute_descriptive_analysis(events, "windows_local_host", source_types=WINDOWS_TYPES)

    assert analysis.unsupported_field_counts == {
        "duration": 5, "packets": 5, "bytes_total": 5,
    }
    # No genuine gaps: every field this source supports was populated.
    assert analysis.missing_field_counts == {}


def test_genuinely_missing_field_is_reported_as_missing():
    """A field the source DOES support, absent, is a real gap."""
    events = [_imported_flow(i) for i in range(3)]
    events[0].bytes_total = None  # CSV import supports this; its absence is a defect
    analysis = compute_descriptive_analysis(events, "perimeter_flow_sensor", source_types=CSV_TYPES)

    assert analysis.missing_field_counts.get("bytes_total") == 1
    assert "bytes_total" not in analysis.unsupported_field_counts


def test_source_limited_flag_does_not_count_as_a_warned_record():
    """
    A structural limit must not make every record look defective. Before
    this distinction existed, all live records were reported as warned.
    """
    events = [_live_connection(i) for i in range(10)]
    analysis = compute_descriptive_analysis(events, "windows_local_host", source_types=WINDOWS_TYPES)

    assert analysis.records_with_warnings == 0
    # The flag is still counted, so the limitation remains visible.
    assert analysis.quality_flag_counts.get("source_limited") == 10


def test_real_quality_warning_still_counts():
    events = [_live_connection(i) for i in range(4)]
    events[0].quality_flags = [QualityFlag.SOURCE_LIMITED, QualityFlag.TIMESTAMP_UNCERTAINTY]
    analysis = compute_descriptive_analysis(events, "windows_local_host", source_types=WINDOWS_TYPES)

    assert analysis.records_with_warnings == 1
    assert analysis.quality_flag_counts["timestamp_uncertainty"] == 1


def test_averages_stay_none_rather_than_zero_for_unsupported_metrics():
    """A metric that cannot be computed must be absent, never zero."""
    events = [_live_connection(i) for i in range(5)]
    analysis = compute_descriptive_analysis(events, "windows_local_host", source_types=WINDOWS_TYPES)

    assert analysis.avg_bytes is None
    assert analysis.avg_packets is None
    assert analysis.avg_duration is None
    assert analysis.total_bytes is None


def test_source_limitations_are_surfaced():
    events = [_live_connection(i) for i in range(2)]
    analysis = compute_descriptive_analysis(events, "windows_local_host", source_types=WINDOWS_TYPES)

    joined = " ".join(analysis.source_limitations).lower()
    assert "connection metadata only" in joined
    assert "byte counts" in joined


def test_unknown_source_type_treats_absence_as_missing_not_excused():
    """
    Absence cannot be excused by a limit that was never declared, so an
    unrecognised source type is read conservatively.
    """
    events = [_live_connection(i) for i in range(3)]
    analysis = compute_descriptive_analysis(
        events, "all_sources", source_types={"windows_local_host": "something_unregistered"}
    )
    assert analysis.missing_field_counts.get("bytes_total") == 3
    assert "bytes_total" not in analysis.unsupported_field_counts


# ──────────────────────────────────────────────────────────────────
# Capability declarations
# ──────────────────────────────────────────────────────────────────


def test_windows_capability_declares_its_real_limits():
    cap = get_capability("windows_connection_table")

    assert cap.supports("dst_ip") is True
    assert cap.supports("dst_port") is True
    assert cap.supports("bytes_total") is False
    assert cap.supports("packets") is False
    assert cap.supports("duration") is False
    # It cannot observe application-layer detail at all.
    assert cap.supports("http_method") is False
    assert cap.supports("http_status_code") is False
    assert cap.availability_of("bytes_total") == FieldAvailability.UNSUPPORTED_BY_SOURCE

    unsupported = cap.unsupported_fields()
    assert "bytes_total" in unsupported and "http_status_code" in unsupported


def test_csv_capability_supports_flow_metrics():
    cap = get_capability("csv_import")
    assert cap.supports("bytes_total") is True
    assert cap.supports("packets") is True
    assert cap.supports("label") is True


def test_application_layer_capability_is_the_only_http_source():
    app_cap = get_capability("application_layer")
    assert app_cap.supports("http_method") is True
    assert app_cap.supports("http_status_code") is True

    for other in ("windows_connection_table", "csv_import", "json_stream", "synthetic_replay"):
        assert get_capability(other).supports("http_status_code") is False, other


# ──────────────────────────────────────────────────────────────────
# Connection intelligence aggregates
# ──────────────────────────────────────────────────────────────────


def test_connection_state_and_process_are_aggregated_from_provenance():
    events = [
        _live_connection(0, raw_reference="windows:tcp;state=Established;pid=1;process=opera"),
        _live_connection(1, raw_reference="windows:tcp;state=Established;pid=2;process=opera"),
        _live_connection(2, raw_reference="windows:tcp;state=CloseWait;pid=3;process=msedge"),
    ]
    analysis = compute_descriptive_analysis(events, "windows_local_host", source_types=WINDOWS_TYPES)

    assert analysis.events_by_connection_state == {"Established": 2, "CloseWait": 1}
    assert analysis.events_by_process == {"opera": 2, "msedge": 1}


def test_process_falls_back_to_pid_when_name_unavailable():
    events = [_live_connection(0, raw_reference="windows:tcp;state=Established;pid=4242")]
    analysis = compute_descriptive_analysis(events, "windows_local_host", source_types=WINDOWS_TYPES)
    assert analysis.events_by_process == {"pid:4242": 1}


def test_hostname_aggregation_uses_resolver_without_mutating_events():
    events = [_live_connection(i) for i in range(3)]
    original_ips = [e.dst_ip for e in events]

    analysis = compute_descriptive_analysis(
        events,
        "windows_local_host",
        source_types=WINDOWS_TYPES,
        hostname_resolver=lambda e: "cdn.example.net",
    )

    assert analysis.hostname_attributed_count == 3
    assert analysis.top_dst_hostnames[0] == {"hostname": "cdn.example.net", "count": 3}
    # Enrichment must never alter the underlying records.
    assert [e.dst_ip for e in events] == original_ips
    assert all(e.dst_hostname is None for e in events)


def test_hostname_resolver_failure_does_not_break_analysis():
    events = [_live_connection(i) for i in range(3)]

    def _boom(_event):
        raise RuntimeError("resolver unavailable")

    analysis = compute_descriptive_analysis(
        events, "windows_local_host", source_types=WINDOWS_TYPES, hostname_resolver=_boom
    )
    assert analysis.total_events == 3
    assert analysis.hostname_attributed_count == 0


def test_events_per_hour_buckets_observations():
    events = [
        _live_connection(0, observed_at=BASE),
        _live_connection(1, observed_at=BASE + timedelta(minutes=5)),
        _live_connection(2, observed_at=BASE + timedelta(hours=2)),
    ]
    analysis = compute_descriptive_analysis(events, "windows_local_host", source_types=WINDOWS_TYPES)

    assert analysis.events_per_hour == {
        "2026-10-11T12:00Z": 2,
        "2026-10-11T14:00Z": 1,
    }
