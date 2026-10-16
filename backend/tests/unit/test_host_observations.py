"""
UDP endpoint and interface-counter source tests.

Normalization is pure, so these run on any platform with fixtures. The two
sources measure different things and the tests exist mainly to keep them
from being conflated with each other, or with flow metrics.

Documentation addresses only (RFC 5737 / RFC 3849).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.adapters.capabilities import get_capability
from app.adapters.windows_host_observations import (
    INTERFACE_SOURCE_TYPE,
    UDP_SOURCE_TYPE,
    InterfaceStatisticsProbe,
    WindowsUdpEndpointAdapter,
    compute_deltas,
    parse_interface_counters,
)
from app.schemas.events import (
    EventType,
    FieldAvailability,
    LabelProvenance,
    QualityFlag,
)

NOW = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)


@pytest.fixture
def adapter() -> WindowsUdpEndpointAdapter:
    return WindowsUdpEndpointAdapter(adapter_id="udp_test")


def _row(port=53531, addr="192.0.2.10", pid=4321, created="2026-06-01T11:59:00+00:00"):
    return {
        "local_address": addr,
        "local_port": port,
        "owning_pid": pid,
        "process_name": "examplebrowser",
        "creation_time": created,
    }


# ──────────────────────────────────────────────────────────────────
# UDP endpoints are not connections
# ──────────────────────────────────────────────────────────────────


def test_udp_endpoint_has_no_destination(adapter):
    """
    The single most important property of this source. UDP is
    connectionless and Windows records no peer, so inventing one — a
    wildcard, a broadcast address, anything — would manufacture a
    destination that was never observed and corrupt every
    destination-based aggregation.
    """
    result = adapter.validate_and_normalize(_row(), 0, polled_at=NOW)
    assert result.is_valid is True
    event = result.event

    assert event.event_type is EventType.UDP_ENDPOINT
    assert event.event_type is not EventType.CONNECTION
    assert event.dst_ip is None
    assert event.dst_port is None
    assert event.protocol == "UDP"
    assert event.src_ip == "192.0.2.10"
    assert event.src_port == 53531


def test_destination_is_declared_not_applicable_not_missing():
    """
    A missing destination here is a property of UDP, not a defect in the
    data. The capability profile has to say so, or every record is scored
    as incomplete.
    """
    cap = get_capability(UDP_SOURCE_TYPE)
    assert cap.fields["dst_ip"] is FieldAvailability.NOT_APPLICABLE
    assert cap.fields["dst_port"] is FieldAvailability.NOT_APPLICABLE
    assert cap.fields["src_ip"] is FieldAvailability.POPULATED
    assert cap.fields["dst_ip"] is not FieldAvailability.MISSING_UNEXPECTED


def test_volume_and_duration_are_never_invented(adapter):
    event = adapter.validate_and_normalize(_row(), 0, polled_at=NOW).event
    assert event.bytes_total is None
    assert event.packets is None
    assert event.duration is None
    assert QualityFlag.SOURCE_LIMITED in event.quality_flags


def test_no_label_is_assigned_to_a_local_socket(adapter):
    event = adapter.validate_and_normalize(_row(), 0, polled_at=NOW).event
    assert event.label is None
    assert event.label_provenance is LabelProvenance.UNLABELED


# ──────────────────────────────────────────────────────────────────
# Identity and robustness
# ──────────────────────────────────────────────────────────────────


def test_event_id_is_deterministic_so_polling_is_idempotent(adapter):
    a = adapter.validate_and_normalize(_row(), 0, polled_at=NOW).event
    b = adapter.validate_and_normalize(_row(), 1, polled_at=NOW + timedelta(minutes=5)).event
    assert a.event_id == b.event_id, "re-polling the same socket must not create a new event"

    other = adapter.validate_and_normalize(_row(port=53532), 2, polled_at=NOW).event
    assert other.event_id != a.event_id


def test_ipv6_zone_index_is_stripped(adapter):
    """fe80::1%47 — the %47 is a local interface scope, not the address."""
    event = adapter.validate_and_normalize(
        _row(addr="2001:db8::1%47"), 0, polled_at=NOW
    ).event
    assert event.src_ip == "2001:db8::1"


def test_wildcard_bind_is_kept_as_observed(adapter):
    """`::` is what the OS reported; it is a real bind, not a bad value."""
    event = adapter.validate_and_normalize(_row(addr="::"), 0, polled_at=NOW).event
    assert event.src_ip == "::"


def test_filetime_epoch_timestamp_is_refused(adapter):
    """
    Windows reports an unset CreationTime as 1601-01-01. Accepting it would
    imply a four-century observation span and poison every time-ordered
    calculation downstream.
    """
    result = adapter.validate_and_normalize(
        _row(created="1601-01-01T00:00:00+00:00"), 0, polled_at=NOW
    )
    assert result.is_valid is True
    assert result.event.observed_at == NOW
    assert QualityFlag.TIMESTAMP_UNCERTAINTY in result.event.quality_flags
    assert "implausible_creation_time_before_2000" in result.warnings


def test_invalid_rows_are_rejected_with_reasons_not_dropped_silently(adapter):
    rows = [
        _row(),
        {"local_address": "not-an-ip", "local_port": 1, "owning_pid": 1},
        {"local_address": "192.0.2.11", "local_port": 99999, "owning_pid": 1},
        _row(),  # exact duplicate within one snapshot
    ]
    events, rejections = adapter.normalize_batch(rows, polled_at=NOW)

    assert len(events) == 1, "the duplicate must not be counted twice"
    assert len(rejections) == 2
    assert any("invalid local_address" in r for r in rejections)
    assert any("out of range" in r for r in rejections)


def test_process_name_is_recorded_but_never_the_command_line(adapter):
    event = adapter.validate_and_normalize(_row(), 0, polled_at=NOW).event
    assert "process=examplebrowser" in event.raw_reference
    assert "pid=4321" in event.raw_reference
    # Command lines carry file paths, URLs and tokens this question does not
    # need, so the collector never requests them.
    assert "--" not in event.raw_reference
    assert "\\" not in event.raw_reference


# ──────────────────────────────────────────────────────────────────
# Interface counters are a different measurement type
# ──────────────────────────────────────────────────────────────────


def _counters(name="Wi-Fi", rb=1000, sb=500, rp=10, sp=5):
    return {
        "name": name,
        "received_bytes": rb,
        "sent_bytes": sb,
        "received_unicast_packets": rp,
        "sent_unicast_packets": sp,
        "received_discarded": 0,
        "outbound_discarded": 0,
    }


def test_interface_counters_declare_they_are_not_flow_metrics():
    cap = get_capability(INTERFACE_SOURCE_TYPE)
    joined = " ".join(cap.limitations).lower()
    assert "not flow metrics" in joined
    assert "cumulative" in joined
    # No canonical per-event field applies to an interface counter.
    assert all(
        v is not FieldAvailability.POPULATED for v in cap.fields.values()
    ), "an interface counter is not a per-event measurement"


def test_snapshot_states_its_measurement_scope():
    probe = InterfaceStatisticsProbe(query_fn=lambda: [_counters()])
    snap = probe.read(now=NOW)

    assert snap.measurement_scope == "interface_cumulative"
    assert snap.attributable_to_flow is False
    assert snap.attributable_to_process is False
    assert snap.deltas == [], "the first reading has nothing to difference against"


def test_delta_is_the_difference_between_two_readings():
    probe = InterfaceStatisticsProbe(
        query_fn=lambda: [_counters(rb=1000, sb=500, rp=10, sp=5)]
    )
    first = probe.read(now=NOW)

    probe._query_fn = lambda: [_counters(rb=1600, sb=700, rp=16, sp=9)]
    second = probe.read(now=NOW + timedelta(seconds=30))

    assert len(second.deltas) == 1
    d = second.deltas[0]
    assert d.received_bytes == 600
    assert d.sent_bytes == 200
    assert d.received_packets == 6
    assert d.sent_packets == 4
    assert d.interval_seconds == 30.0
    assert d.counter_reset_detected is False
    assert first.deltas == []


def test_a_counter_reset_yields_no_delta_rather_than_a_wrong_one():
    """
    Disable/enable, sleep or a driver reload resets the counters. Reporting
    the drop as a negative, or wrapping it into a large positive, would both
    describe traffic that never happened.
    """
    probe = InterfaceStatisticsProbe(query_fn=lambda: [_counters(rb=5000, sb=4000)])
    probe.read(now=NOW)

    probe._query_fn = lambda: [_counters(rb=12, sb=8)]
    after = probe.read(now=NOW + timedelta(seconds=10))

    d = after.deltas[0]
    assert d.counter_reset_detected is True
    assert d.received_bytes is None
    assert d.sent_bytes is None
    assert "reset" in (d.note or "").lower()


def test_a_newly_appearing_interface_reports_no_delta():
    probe = InterfaceStatisticsProbe(query_fn=lambda: [_counters(name="Wi-Fi")])
    probe.read(now=NOW)

    probe._query_fn = lambda: [_counters(name="Wi-Fi"), _counters(name="Ethernet")]
    after = probe.read(now=NOW + timedelta(seconds=10))

    eth = [d for d in after.deltas if d.name == "Ethernet"][0]
    assert eth.received_bytes is None
    assert "not present in the previous reading" in (eth.note or "")


def test_unparseable_counter_rows_are_skipped_not_guessed():
    rows = [_counters(), {"name": "Broken", "received_bytes": "lots"}, {"name": ""}]
    parsed = parse_interface_counters(rows)
    assert [p.name for p in parsed] == ["Wi-Fi"]


def test_compute_deltas_without_a_previous_reading_returns_nothing():
    assert compute_deltas(None, parse_interface_counters([_counters()]), NOW) == []
