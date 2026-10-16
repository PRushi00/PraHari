"""
PraHari — NetFlow / IPFIX Adapter (ADR-057, blueprint §5).

Synthetic fixtures throughout, in the real export shapes produced by
nfdump, SiLK rwcut and YAF. No network listener is opened and no live
flow data is read: this adapter ingests what an authorized collector
exported, and is not itself a collector.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app.adapters.netflow import NetFlowAdapter, _parse_protocol, _parse_timestamp
from app.schemas.events import DataCategory, EventType, LabelProvenance, QualityFlag

# nfdump -o csv: bidirectional counters, epoch-ish timestamps.
NFDUMP_CSV = """\
ts,te,td,sa,da,sp,dp,pr,ipkt,ibyt,opkt,obyt
2026-06-01 12:00:00,2026-06-01 12:00:05,5.000,192.0.2.10,198.51.100.20,40001,443,TCP,12,1500,10,900
2026-06-01 12:00:10,2026-06-01 12:00:11,1.000,192.0.2.11,198.51.100.21,40002,53,UDP,2,180,2,220
"""

# SiLK rwcut: different names, numeric protocol, ISO timestamps.
SILK_CSV = """\
sIP,dIP,sPort,dPort,protocol,packets,bytes,sTime,duration
10.0.0.5,10.0.0.9,51000,22,6,40,6000,2026-06-01T12:05:00Z,12.5
"""

# IPFIX information-element names.
IPFIX_CSV = """\
flowStartSeconds,sourceIPv4Address,destinationIPv4Address,sourceTransportPort,destinationTransportPort,protocolIdentifier,packetDeltaCount,octetDeltaCount
1780660800,203.0.113.4,198.51.100.7,33000,80,6,8,640
"""


@pytest.fixture
def adapter():
    return NetFlowAdapter(adapter_id="flow-exporter-1")


# ──────────────────────────────────────────────────────────────────
# Field-name variation across exporters
# ──────────────────────────────────────────────────────────────────


def test_nfdump_export_parses(adapter):
    events, summary = adapter.import_csv_string(NFDUMP_CSV)

    assert summary.total_records == 2
    assert summary.accepted_records == 2
    assert events[0].src_ip == "192.0.2.10"
    assert events[0].dst_port == 443
    assert events[0].protocol == "TCP"


def test_silk_export_parses_with_a_numeric_protocol(adapter):
    events, summary = adapter.import_csv_string(SILK_CSV)

    assert summary.accepted_records == 1
    assert events[0].protocol == "TCP", "protocol 6 must resolve to TCP"
    assert events[0].src_port == 51000
    assert events[0].duration == 12.5


def test_ipfix_information_element_names_parse(adapter):
    events, summary = adapter.import_csv_string(IPFIX_CSV)

    assert summary.accepted_records == 1
    assert events[0].src_ip == "203.0.113.4"
    assert events[0].bytes_total == 640


def test_every_exporter_produces_the_same_canonical_shape(adapter):
    """The point of the adapter layer: one contract, many exporters."""
    for text in (NFDUMP_CSV, SILK_CSV, IPFIX_CSV):
        events, _ = NetFlowAdapter(adapter_id="x").import_csv_string(text)
        for e in events:
            assert e.event_type is EventType.NETWORK_FLOW
            assert e.label_provenance is LabelProvenance.UNLABELED
            assert e.observed_at.tzinfo is not None


# ──────────────────────────────────────────────────────────────────
# Semantics that are routinely got wrong
# ──────────────────────────────────────────────────────────────────


def test_bidirectional_counters_are_summed(adapter):
    events, _ = adapter.import_csv_string(NFDUMP_CSV)

    assert events[0].bytes_total == 1500 + 900
    assert events[0].packets == 12 + 10


def test_a_unidirectional_count_is_flagged_not_silently_halved(adapter):
    one_way = (
        "ts,sa,da,sp,dp,pr,ipkt,ibyt\n"
        "2026-06-01 12:00:00,192.0.2.10,198.51.100.20,40001,443,TCP,5,500\n"
    )

    result = adapter.validate_and_normalize(
        dict(zip(one_way.splitlines()[0].split(","),
                 one_way.splitlines()[1].split(","))), 0
    )

    assert result.is_valid
    assert result.event.bytes_total == 500
    assert "unidirectional_byte_count" in result.warnings
    assert QualityFlag.MISSING_FIELD in result.event.quality_flags


def test_observed_at_is_the_flow_start_not_its_end(adapter):
    """
    Dating a long flow to when it finished would shift it into a later
    window and corrupt every temporal feature built from it.
    """
    events, _ = adapter.import_csv_string(NFDUMP_CSV)

    assert events[0].observed_at == datetime(
        2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc
    )


def test_duration_is_derived_from_the_endpoints_when_absent(adapter):
    no_duration = (
        "ts,te,sa,da,sp,dp,pr,ibyt\n"
        "2026-06-01 12:00:00,2026-06-01 12:00:30,192.0.2.1,198.51.100.1,1,2,TCP,10\n"
    )

    events, _ = adapter.import_csv_string(no_duration)

    assert events[0].duration == 30.0


# ──────────────────────────────────────────────────────────────────
# Refusing rather than guessing
# ──────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "row, expected_error",
    [
        ({"sa": "192.0.2.1", "da": "198.51.100.1", "pr": "TCP"},
         "missing_or_unparseable_flow_start"),
        ({"ts": "2026-06-01 12:00:00", "da": "198.51.100.1", "pr": "TCP"},
         "missing_or_invalid_endpoint_address"),
        ({"ts": "2026-06-01 12:00:00", "sa": "192.0.2.1", "da": "198.51.100.1"},
         "missing_protocol"),
        ({"ts": "2026-06-01 12:00:00", "sa": "not-an-ip",
          "da": "198.51.100.1", "pr": "TCP"},
         "missing_or_invalid_endpoint_address"),
    ],
)
def test_a_record_missing_a_required_field_is_refused(adapter, row, expected_error):
    """§5.3: reject incompatible required fields rather than mis-mapping."""
    result = adapter.validate_and_normalize(row, 0)

    assert not result.is_valid
    assert expected_error in result.errors


def test_an_unparseable_timestamp_is_not_defaulted_to_now():
    """Defaulting would silently re-date the flow to the import moment."""
    assert _parse_timestamp("not-a-date") is None
    assert _parse_timestamp("") is None
    assert _parse_timestamp(None) is None


def test_rejections_are_counted_and_explained(adapter):
    mixed = (
        "ts,sa,da,sp,dp,pr,ibyt\n"
        "2026-06-01 12:00:00,192.0.2.1,198.51.100.1,1,2,TCP,10\n"
        "not-a-date,192.0.2.2,198.51.100.2,1,2,TCP,10\n"
    )

    events, summary = adapter.import_csv_string(mixed)

    assert summary.total_records == 2
    assert summary.accepted_records == 1
    assert summary.rejected_records == 1
    assert summary.rejection_reasons["missing_or_unparseable_flow_start"] == 1


def test_a_flow_with_no_volume_counters_is_kept_but_flagged(adapter):
    result = adapter.validate_and_normalize(
        {"ts": "2026-06-01 12:00:00", "sa": "192.0.2.1",
         "da": "198.51.100.1", "pr": "TCP"}, 0
    )

    assert result.is_valid
    assert "no_volume_counters_present" in result.warnings
    assert result.event.bytes_total is None, "absent is not zero"


# ──────────────────────────────────────────────────────────────────
# Identity and bounded parsing
# ──────────────────────────────────────────────────────────────────


def test_identity_is_deterministic_so_a_reimport_is_idempotent(adapter):
    first, _ = adapter.import_csv_string(NFDUMP_CSV)
    second, _ = NetFlowAdapter(adapter_id="flow-exporter-1").import_csv_string(
        NFDUMP_CSV
    )

    assert [e.event_id for e in first] == [e.event_id for e in second], (
        "collectors emit overlapping files; re-import must not duplicate"
    )


def test_distinct_flows_get_distinct_identities(adapter):
    events, _ = adapter.import_csv_string(NFDUMP_CSV)

    assert events[0].event_id != events[1].event_id


def test_identity_is_scoped_to_the_exporter():
    a, _ = NetFlowAdapter(adapter_id="exporter-a").import_csv_string(NFDUMP_CSV)
    b, _ = NetFlowAdapter(adapter_id="exporter-b").import_csv_string(NFDUMP_CSV)

    assert a[0].event_id != b[0].event_id, (
        "two exporters reporting the same flow are two observations"
    )


def test_parsing_is_bounded_and_says_so(adapter):
    header = "ts,sa,da,sp,dp,pr,ibyt\n"
    rows = "".join(
        f"2026-06-01 12:00:00,192.0.2.1,198.51.100.1,{1000 + i},443,TCP,10\n"
        for i in range(50)
    )

    events, summary = adapter.import_csv_string(header + rows, max_records=10)

    assert summary.total_records == 10
    assert len(events) == 10
    assert "truncated_at_max_records" in summary.rejection_reasons


def test_the_nfdump_trailing_summary_block_is_not_parsed_as_flows(adapter):
    with_summary = NFDUMP_CSV + "\nSummary: total flows: 2, total bytes: 2400\n"

    _, summary = adapter.import_csv_string(with_summary)

    assert summary.total_records == 2, "the summary block was parsed as a record"


def test_an_empty_export_is_not_an_error(adapter):
    events, summary = adapter.import_csv_string("ts,sa,da,sp,dp,pr\n")

    assert events == []
    assert summary.total_records == 0
    assert summary.rejected_records == 0


# ──────────────────────────────────────────────────────────────────
# Protocol mapping
# ──────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "raw, expected",
    [("6", "TCP"), ("17", "UDP"), ("1", "ICMP"), ("tcp", "TCP"),
     ("UDP", "UDP"), ("47", "GRE"), ("253", "PROTO_253")],
)
def test_protocol_numbers_and_names_both_resolve(raw, expected):
    assert _parse_protocol(raw) == expected


def test_an_unknown_protocol_number_is_labelled_not_dropped():
    """Keeping the number visible beats discarding the record."""
    assert _parse_protocol("200") == "PROTO_200"


def test_adapter_counters_track_what_it_did(adapter):
    adapter.import_csv_string(NFDUMP_CSV)

    assert adapter.records_processed == 2
    assert adapter.records_rejected == 0
    assert adapter.last_active_at is not None
