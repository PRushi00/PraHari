"""
Zeek and Suricata ingestion contract tests.

PraHari has no network sensor of its own: the supported route for real
network telemetry is an existing sensor writing JSON that the JSON stream
adapter normalizes. These tests pin that contract against the shapes those
tools actually emit, and against the provenance rules that decide whether a
label may be treated as ground truth.

All addresses are documentation ranges (RFC 5737 / RFC 3849). No real
telemetry appears in this file.
"""

from __future__ import annotations

from datetime import timezone

import pytest

from app.adapters.json_stream import JsonStreamAdapter
from app.research.readiness import assess_readiness
from app.schemas.events import (
    DataCategory,
    EventType,
    LabelProvenance,
    QualityFlag,
)


@pytest.fixture
def adapter() -> JsonStreamAdapter:
    return JsonStreamAdapter(adapter_id="sensor_contract")


def _ok(adapter, record, index=0):
    result = adapter.validate_and_normalize(record, record_index=index)
    assert result.is_valid is True, result.errors
    return result


# ──────────────────────────────────────────────────────────────────
# Zeek conn.log
# ──────────────────────────────────────────────────────────────────


def test_zeek_dotted_and_nested_id_forms_agree(adapter):
    """
    Zeek JSON writes the connection id either flattened ("id.orig_h") or
    nested under "id", depending on the logging configuration. Both are the
    same connection and must normalize identically.
    """
    dotted = _ok(adapter, {
        "ts": 1700000000.0,
        "id.orig_h": "192.0.2.10", "id.orig_p": 44321,
        "id.resp_h": "198.51.100.20", "id.resp_p": 443,
        "proto": "tcp",
    }).event
    nested = _ok(adapter, {
        "ts": 1700000000.0,
        "id": {"orig_h": "192.0.2.10", "orig_p": 44321,
               "resp_h": "198.51.100.20", "resp_p": 443},
        "proto": "tcp",
    }, index=1).event

    for field in ("src_ip", "dst_ip", "src_port", "dst_port", "protocol", "observed_at"):
        assert getattr(dotted, field) == getattr(nested, field), field


def test_zeek_zero_bytes_is_recorded_not_discarded(adapter):
    """
    Regression: the byte lookup was an `or` chain, so a flow that genuinely
    transferred 0 bytes fell through to the next key and ended up as None --
    "we measured zero" became "we measured nothing".
    """
    event = _ok(adapter, {
        "ts": 1700000000.0,
        "id.orig_h": "192.0.2.11", "id.resp_h": "198.51.100.21",
        "id.orig_p": 50000, "id.resp_p": 80,
        "orig_bytes": 0, "resp_bytes": 0,
        "proto": "tcp",
    }).event

    assert event.bytes_total == 0
    assert event.bytes_total is not None


def test_explicit_zero_counters_are_recorded_not_discarded(adapter):
    """
    Same falsy-zero trap on the flat "bytes"/"packets" keys that Suricata and
    generic JSON producers use, rather than the Zeek orig_/resp_ pair.
    """
    event = _ok(adapter, {
        "ts": 1700000000.0,
        "id.orig_h": "192.0.2.16", "id.resp_h": "198.51.100.26",
        "id.orig_p": 50010, "id.resp_p": 443,
        "bytes": 0, "packets": 0,
        "proto": "tcp",
    }).event

    assert event.bytes_total == 0, "a recorded zero became 'no measurement'"
    assert event.packets == 0, "a recorded zero became 'no measurement'"


def test_zeek_zero_duration_is_recorded_not_discarded(adapter):
    """Regression: a single-packet flow has duration 0.0, which is falsy."""
    event = _ok(adapter, {
        "ts": 1700000000.0,
        "id.orig_h": "192.0.2.12", "id.resp_h": "198.51.100.22",
        "id.orig_p": 50001, "id.resp_p": 53,
        "duration": 0.0, "proto": "udp",
    }).event

    assert event.duration == 0.0
    assert event.duration is not None


def test_zeek_port_zero_survives(adapter):
    event = _ok(adapter, {
        "ts": 1700000000.0,
        "id.orig_h": "192.0.2.13", "id.resp_h": "198.51.100.23",
        "id.orig_p": 0, "id.resp_p": 0,
        "proto": "icmp",
    }).event
    assert event.src_port == 0 and event.dst_port == 0


def test_zeek_unset_marker_never_becomes_zero(adapter):
    """
    Zeek writes "-" for a field that exists but has no value. Reading that as
    0 would invent a measurement; it must stay absent.
    """
    event = _ok(adapter, {
        "ts": 1700000000.0,
        "id.orig_h": "192.0.2.14", "id.resp_h": "198.51.100.24",
        "id.orig_p": 50002, "id.resp_p": 443,
        "duration": "-", "bytes": "-", "packets": "-",
        "proto": "tcp",
    }).event

    assert event.duration is None
    assert event.bytes_total is None
    assert event.packets is None


def test_zeek_ipv6_endpoints_are_accepted(adapter):
    event = _ok(adapter, {
        "ts": 1700000000.0,
        "id.orig_h": "2001:db8::1", "id.resp_h": "2001:db8::2",
        "id.orig_p": 50003, "id.resp_p": 443,
        "proto": "tcp",
    }).event
    assert event.src_ip == "2001:db8::1"
    assert event.dst_ip == "2001:db8::2"


def test_zeek_millisecond_timestamps_are_distinguished_from_seconds(adapter):
    secs = _ok(adapter, {
        "ts": 1700000000.0,
        "id.orig_h": "192.0.2.15", "id.resp_h": "198.51.100.25",
        "id.orig_p": 1, "id.resp_p": 2, "proto": "tcp",
    }).event
    millis = _ok(adapter, {
        "ts": 1700000000000,
        "id.orig_h": "192.0.2.15", "id.resp_h": "198.51.100.25",
        "id.orig_p": 1, "id.resp_p": 2, "proto": "tcp",
    }, index=1).event

    assert secs.observed_at == millis.observed_at
    assert secs.observed_at.tzinfo == timezone.utc


# ──────────────────────────────────────────────────────────────────
# Suricata EVE
# ──────────────────────────────────────────────────────────────────


def test_suricata_dns_event_maps_to_dns_query(adapter):
    """
    Regression: this previously raised AttributeError because the code
    referenced EventType.DNS, which does not exist.
    """
    event = _ok(adapter, {
        "timestamp": "2026-03-15T14:30:00.000000Z",
        "event_type": "dns",
        "src_ip": "192.0.2.30", "dest_ip": "198.51.100.53",
        "src_port": 55000, "dest_port": 53, "proto": "UDP",
        "dns": {"rrname": "example.test", "rrtype": "A"},
    }).event
    assert event.event_type is EventType.DNS_QUERY


def test_suricata_http_event_maps_to_http_request(adapter):
    event = _ok(adapter, {
        "timestamp": "2026-03-15T14:30:01.000000Z",
        "event_type": "http",
        "src_ip": "192.0.2.31", "dest_ip": "198.51.100.80",
        "src_port": 55001, "dest_port": 80, "proto": "TCP",
        "http": {"hostname": "example.test", "status": 200},
    }).event
    assert event.event_type is EventType.HTTP_REQUEST


def test_suricata_non_utc_offset_is_converted_not_truncated(adapter):
    """
    Suricata writes local time with an offset. Windowing is chronological,
    so dropping the offset would shift every event by hours.
    """
    event = _ok(adapter, {
        "timestamp": "2026-03-15T20:00:00.000000+05:30",
        "event_type": "flow",
        "src_ip": "192.0.2.32", "dest_ip": "198.51.100.32",
        "src_port": 55002, "dest_port": 443, "proto": "TCP",
    }).event

    assert event.observed_at.astimezone(timezone.utc).hour == 14
    assert event.observed_at.astimezone(timezone.utc).minute == 30


def test_suricata_one_sided_flow_counters_are_summed(adapter):
    event = _ok(adapter, {
        "timestamp": "2026-03-15T14:30:02.000000Z",
        "event_type": "flow",
        "src_ip": "192.0.2.33", "dest_ip": "198.51.100.33",
        "src_port": 55003, "dest_port": 443, "proto": "TCP",
        "flow": {"bytes_toserver": 512, "pkts_toserver": 4},
    }).event
    assert event.bytes_total == 512
    assert event.packets == 4


# ──────────────────────────────────────────────────────────────────
# Label provenance -- the integrity rules
# ──────────────────────────────────────────────────────────────────


def test_suricata_signature_is_detector_output_not_ground_truth(adapter):
    """
    An IDS signature is the detector's opinion. Recording it as ground truth
    would let a forecaster be trained to predict one detector's alerts while
    the metrics claim it predicts attacks.
    """
    result = adapter.validate_and_normalize({
        "timestamp": "2026-03-15T14:30:03.000000Z",
        "event_type": "alert",
        "src_ip": "192.0.2.34", "dest_ip": "198.51.100.34",
        "src_port": 55004, "dest_port": 445, "proto": "TCP",
        "alert": {"signature": "ET EXPLOIT SMB Remote Code Execution",
                  "severity": 1,
                  "category": "Attempted Administrator Privilege Gain"},
    }, record_index=0)

    event = result.event
    assert result.is_valid is True
    assert event.label == "ET EXPLOIT SMB Remote Code Execution"
    assert event.label_provenance is LabelProvenance.DETECTOR_OUTPUT
    assert event.label_provenance is not LabelProvenance.DATASET_GROUND_TRUTH
    assert "label_is_detector_output_not_ground_truth" in result.warnings
    assert event.event_type is EventType.ALERT


def test_corpus_label_is_ground_truth_and_keeps_the_observed_event_type(adapter):
    """
    Regression: any labelled record was rewritten to EventType.ALERT, so an
    imported labelled corpus reported as nothing but alerts. The label says
    how the record was annotated; the event type says what was observed.
    """
    event = _ok(adapter, {
        "timestamp": "2026-03-15T14:30:04.000000Z",
        "event_type": "flow",
        "src_ip": "192.0.2.35", "dest_ip": "198.51.100.35",
        "src_port": 55005, "dest_port": 443, "proto": "TCP",
        "label": "DDoS",
    }).event

    assert event.label == "DDoS"
    assert event.label_provenance is LabelProvenance.DATASET_GROUND_TRUTH
    assert event.event_type is EventType.NETWORK_FLOW


def test_corpus_label_wins_over_a_detector_signature(adapter):
    """When a corpus states the truth, the detector's guess is not the label."""
    event = _ok(adapter, {
        "timestamp": "2026-03-15T14:30:05.000000Z",
        "event_type": "alert",
        "src_ip": "192.0.2.36", "dest_ip": "198.51.100.36",
        "src_port": 55006, "dest_port": 445, "proto": "TCP",
        "label": "Benign",
        "alert": {"signature": "ET SCAN Possible Nmap"},
    }).event

    assert event.label == "Benign"
    assert event.label_provenance is LabelProvenance.DATASET_GROUND_TRUTH


def test_unlabelled_flow_stays_unlabelled(adapter):
    event = _ok(adapter, {
        "timestamp": "2026-03-15T14:30:06.000000Z",
        "event_type": "flow",
        "src_ip": "192.0.2.37", "dest_ip": "198.51.100.37",
        "src_port": 55007, "dest_port": 443, "proto": "TCP",
    }).event
    assert event.label is None
    assert event.label_provenance is LabelProvenance.UNLABELED


def test_synthetic_provenance_is_distinct_from_rule_based():
    """
    Regression: SYNTHETIC_RULE was declared with the same value as
    RULE_BASED, making it a silent alias. Synthetic labels were therefore
    indistinguishable from locally derived ones in every provenance
    breakdown -- including the experiment manifest, which exists to prove
    what a result was computed on.
    """
    assert LabelProvenance.SYNTHETIC_RULE is not LabelProvenance.RULE_BASED
    assert LabelProvenance.SYNTHETIC_RULE.value == "synthetic_rule"
    values = [m.value for m in LabelProvenance]
    assert len(values) == len(set(values)), "a provenance value is aliased"


def test_readiness_reports_detector_labels_as_not_ground_truth(adapter):
    """
    The gate still counts detector labels -- they are labels -- but it must
    say what they are, rather than letting them pass as ground truth.
    """
    events = []
    for i in range(60):
        events.append(_ok(adapter, {
            "timestamp": f"2026-03-15T14:{i % 60:02d}:00.000000Z",
            "event_type": "alert",
            "src_ip": "192.0.2.40", "dest_ip": "198.51.100.40",
            "src_port": 55100 + i, "dest_port": 445, "proto": "TCP",
            "alert": {"signature": "ET EXPLOIT Example"},
        }, index=i).event)

    report = assess_readiness(events)

    assert report.non_ground_truth_labelled_events == 60
    assert any("detector" in c.lower() for c in report.label_caveats)
    assert "detector_output" in report.label_provenances
    assert "dataset_ground_truth" not in report.label_provenances


# ──────────────────────────────────────────────────────────────────
# Batch behaviour
# ──────────────────────────────────────────────────────────────────


def test_mixed_batch_reconciles_and_does_not_abort(adapter):
    """
    One malformed record must not discard the rest, and the summary must
    account for every line.
    """
    lines = [
        '{"ts": 1700000000.0, "id.orig_h": "192.0.2.50", "id.resp_h": "198.51.100.50", "id.orig_p": 1, "id.resp_p": 2, "proto": "tcp"}',
        '{"ts": 1700000001.0, "id.orig_h": "not-an-ip", "id.resp_h": "198.51.100.50", "id.orig_p": 1, "id.resp_p": 2, "proto": "tcp"}',
        '{"id.orig_h": "192.0.2.51", "id.resp_h": "198.51.100.51", "id.orig_p": 1, "id.resp_p": 2, "proto": "tcp"}',
        '{"ts": 1700000003.0, "id": "scalar-not-an-object", "src_ip": "192.0.2.52", "dest_ip": "198.51.100.52", "src_port": 1, "dest_port": 2, "proto": "tcp"}',
    ]
    events, summary = adapter.import_ndjson_string(
        "\n".join(lines), data_category=DataCategory.HISTORICAL_IMPORT
    )

    assert summary.total_records == 4
    assert summary.accepted_records + summary.rejected_records == summary.total_records
    assert len(events) == summary.accepted_records
    # The invalid IP and the missing timestamp are rejected with reasons.
    assert summary.rejected_records == 2
    assert summary.rejection_reasons

    # The scalar "id" is a schema warning, not a crash and not a rejection.
    scalar = [e for e in events if e.src_ip == "192.0.2.52"]
    assert len(scalar) == 1
    assert QualityFlag.SCHEMA_WARNING in scalar[0].quality_flags


def test_unknown_sensor_fields_are_ignored_not_fatal(adapter):
    event = _ok(adapter, {
        "ts": 1700000000.0,
        "id.orig_h": "192.0.2.60", "id.resp_h": "198.51.100.60",
        "id.orig_p": 1, "id.resp_p": 2, "proto": "tcp",
        "community_id": "1:abcdef", "zeek_future_field": {"nested": [1, 2, 3]},
    }).event
    assert event.src_ip == "192.0.2.60"


def test_unrecognised_protocol_is_passed_through_not_rewritten(adapter):
    event = _ok(adapter, {
        "ts": 1700000000.0,
        "id.orig_h": "192.0.2.61", "id.resp_h": "198.51.100.61",
        "id.orig_p": 1, "id.resp_p": 2, "proto": "sctp",
    }).event
    assert event.protocol == "SCTP"
