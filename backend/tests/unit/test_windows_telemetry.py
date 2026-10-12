"""
Unit tests for the Windows connection-table telemetry adapter.

These tests exercise normalization with injected raw records, so they run on
any platform and never depend on live host state. Tests that require genuine
OS collection live in tests/integration/test_windows_collector.py and are
skipped off Windows.
"""

from datetime import datetime, timedelta, timezone

import pytest

from app.adapters.windows_telemetry import (
    WINDOWS_SOURCE_TYPE,
    WindowsConnectionAdapter,
)
from app.schemas.events import (
    DataCategory,
    EventType,
    LabelProvenance,
    QualityFlag,
)


def _conn(**overrides) -> dict:
    """A representative connection-table record."""
    base = {
        "protocol": "TCP",
        "local_address": "192.0.2.10",
        "local_port": 65441,
        "remote_address": "140.82.113.21",
        "remote_port": 443,
        "state": "Established",
        "owning_pid": 12132,
        "creation_time": "2026-10-11T16:36:26.0000000Z",
    }
    base.update(overrides)
    return base


# ──────────────────────────────────────────────────────────────────
# Field mapping
# ──────────────────────────────────────────────────────────────────


def test_maps_connection_into_canonical_schema():
    adapter = WindowsConnectionAdapter(adapter_id="windows_local_host")
    result = adapter.validate_and_normalize(_conn(), 1)

    assert result.is_valid
    ev = result.event
    assert ev is not None
    assert ev.source_id == "windows_local_host"
    assert ev.data_category == DataCategory.LIVE_TELEMETRY
    # Connection metadata is NOT a flow record and must not claim to be one.
    assert ev.event_type == EventType.CONNECTION
    assert ev.src_ip == "192.0.2.10"
    assert ev.dst_ip == "140.82.113.21"
    assert ev.src_port == 65441
    assert ev.dst_port == 443
    assert ev.protocol == "TCP"
    assert adapter.adapter_type == WINDOWS_SOURCE_TYPE


def test_uses_os_creation_time_as_event_time():
    """observed_at must be the real connection start, not the poll time."""
    adapter = WindowsConnectionAdapter()
    poll_time = datetime(2026, 10, 11, 18, 0, 0, tzinfo=timezone.utc)
    record = _conn()
    record["observed_at"] = poll_time.isoformat()

    ev = adapter.validate_and_normalize(record, 1).event
    assert ev is not None
    assert ev.observed_at == datetime(2026, 10, 11, 16, 36, 26, tzinfo=timezone.utc)
    assert ev.observed_at != poll_time
    # A trustworthy OS timestamp carries no uncertainty flag.
    assert QualityFlag.TIMESTAMP_UNCERTAINTY not in ev.quality_flags


def test_parses_seven_digit_dotnet_fractional_seconds():
    """.NET 'o' format emits 7 fractional digits; this must not fail."""
    adapter = WindowsConnectionAdapter()
    ev = adapter.validate_and_normalize(
        _conn(creation_time="2026-10-11T16:36:26.1234567Z"), 1
    ).event
    assert ev is not None
    assert ev.observed_at.year == 2026
    assert ev.observed_at.microsecond == 123456


def test_filetime_epoch_is_rejected_not_accepted_as_an_event_time():
    """
    Windows reports an unset CreationTime as 1601-01-01 (the FILETIME
    epoch), seen on PID 0 TimeWait sockets. Accepting it corrupted the
    observation window of every analysis that included such a record.
    """
    adapter = WindowsConnectionAdapter()
    poll_time = datetime(2026, 10, 11, 18, 0, 0, tzinfo=timezone.utc)
    record = _conn(creation_time="1601-01-01T00:00:00.0000000Z", state="TimeWait", owning_pid=0)
    record["observed_at"] = poll_time.isoformat()

    result = adapter.validate_and_normalize(record, 1)
    ev = result.event

    assert result.is_valid is True          # the connection itself is usable
    assert ev is not None
    assert ev.observed_at == poll_time      # poll time, not 1601
    assert ev.observed_at.year == 2026
    assert QualityFlag.INVALID_VALUE in ev.quality_flags
    assert QualityFlag.TIMESTAMP_UNCERTAINTY in ev.quality_flags
    assert "implausible_creation_time_discarded" in result.warnings


def test_future_creation_time_is_rejected():
    """A start time in the future cannot describe an observed connection."""
    adapter = WindowsConnectionAdapter()
    future = datetime.now(timezone.utc) + timedelta(days=2)
    poll_time = datetime.now(timezone.utc)
    record = _conn(creation_time=future.isoformat())
    record["observed_at"] = poll_time.isoformat()

    ev = adapter.validate_and_normalize(record, 1).event
    assert ev is not None
    assert ev.observed_at < future
    assert QualityFlag.INVALID_VALUE in ev.quality_flags


def test_small_clock_skew_is_tolerated():
    """A few seconds of skew is normal and must not discard a good timestamp."""
    adapter = WindowsConnectionAdapter()
    slightly_ahead = datetime.now(timezone.utc) + timedelta(seconds=30)
    ev = adapter.validate_and_normalize(_conn(creation_time=slightly_ahead.isoformat()), 1).event
    assert ev is not None
    assert QualityFlag.INVALID_VALUE not in ev.quality_flags


def test_falls_back_to_poll_time_and_flags_uncertainty():
    adapter = WindowsConnectionAdapter()
    poll_time = datetime(2026, 10, 11, 18, 0, 0, tzinfo=timezone.utc)
    record = _conn(creation_time=None)
    record["observed_at"] = poll_time.isoformat()

    result = adapter.validate_and_normalize(record, 1)
    ev = result.event
    assert ev is not None
    assert ev.observed_at == poll_time
    assert QualityFlag.TIMESTAMP_UNCERTAINTY in ev.quality_flags
    assert "creation_time_unavailable_used_poll_time" in result.warnings


def test_unavailable_metrics_are_null_and_flagged_not_invented():
    """
    The connection table exposes no byte/packet/duration data. Those fields
    must be null and marked as a SOURCE LIMIT — never estimated, and never
    reported as a data defect.
    """
    adapter = WindowsConnectionAdapter()
    ev = adapter.validate_and_normalize(_conn(), 1).event

    assert ev is not None
    assert ev.bytes_total is None
    assert ev.packets is None
    assert ev.duration is None

    # A field the source cannot provide is a structural limit...
    assert QualityFlag.SOURCE_LIMITED in ev.quality_flags
    # ...not a missing-data defect. Using MISSING_FIELD here would mark every
    # record from this source as defective and hide genuine gaps.
    assert QualityFlag.MISSING_FIELD not in ev.quality_flags


def test_app_layer_fields_are_never_populated_by_this_source():
    """
    The TCP collector must never be represented as an HTTP collector: a port
    number is not evidence of an application protocol.
    """
    adapter = WindowsConnectionAdapter()
    ev = adapter.validate_and_normalize(_conn(remote_port=443), 1).event

    assert ev is not None
    assert ev.dst_port == 443
    # Port 443 is conventionally HTTPS, but this source observed no
    # application-layer traffic, so nothing may be asserted about it.
    assert ev.app_protocol is None
    assert ev.http_method is None
    assert ev.http_path is None
    assert ev.http_status_code is None
    assert ev.http_duration_ms is None
    # Nor does it know the hostname the application asked for.
    assert ev.dst_hostname is None


def test_process_name_recorded_when_available_and_omitted_when_not():
    adapter = WindowsConnectionAdapter()

    with_name = adapter.validate_and_normalize(_conn(process_name="msedge"), 1).event
    assert with_name is not None
    assert "process=msedge" in with_name.raw_reference

    # A process owned by another user is not visible without elevation; the
    # name must simply be absent rather than guessed.
    without = adapter.validate_and_normalize(_conn(process_name=None), 2).event
    assert without is not None
    assert "process=" not in without.raw_reference
    assert "pid=12132" in without.raw_reference


def test_no_attack_label_is_invented_for_local_traffic():
    adapter = WindowsConnectionAdapter()
    ev = adapter.validate_and_normalize(_conn(), 1).event
    assert ev is not None
    assert ev.label is None
    assert ev.label_provenance == LabelProvenance.UNLABELED


def test_state_and_pid_recorded_as_provenance_without_payload():
    adapter = WindowsConnectionAdapter()
    ev = adapter.validate_and_normalize(_conn(), 1).event
    assert ev is not None
    assert "state=Established" in ev.raw_reference
    assert "pid=12132" in ev.raw_reference


# ──────────────────────────────────────────────────────────────────
# Validation
# ──────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "overrides, expected_fragment",
    [
        ({"remote_address": "0.0.0.0"}, "unspecified remote_address"),
        ({"remote_address": "::"}, "unspecified remote_address"),
        ({"remote_address": "not-an-ip"}, "invalid remote_address"),
        ({"local_address": ""}, "missing local_address"),
        ({"remote_port": 99999}, "remote_port out of range"),
        ({"remote_port": None}, "missing remote_port"),
        ({"local_port": "abc"}, "invalid local_port"),
    ],
)
def test_rejects_unusable_records_with_explicit_reasons(overrides, expected_fragment):
    adapter = WindowsConnectionAdapter()
    result = adapter.validate_and_normalize(_conn(**overrides), 1)

    assert result.is_valid is False
    assert result.event is None
    assert any(expected_fragment in e for e in result.errors), result.errors


def test_loopback_filtered_by_policy_not_counted_as_rejection():
    """
    Loopback-only connections are out of scope, not malformed. They must be
    reported as filtered so the rejection count keeps meaning "unusable data".
    """
    record = _conn(local_address="127.0.0.1", remote_address="127.0.0.1", remote_port=65421)

    excluded = WindowsConnectionAdapter(include_loopback=False)
    assert excluded.is_excluded_by_policy(record) == "loopback_only_connection_out_of_scope"
    events, summary = excluded.normalize_batch([dict(record)])
    assert events == []
    assert summary.accepted_records == 0
    assert summary.rejected_records == 0          # not a rejection
    assert summary.rejection_reasons["_filtered_by_policy"] == 1
    assert excluded.filtered_by_policy == 1

    included = WindowsConnectionAdapter(include_loopback=True)
    assert included.is_excluded_by_policy(record) is None
    assert included.validate_and_normalize(record, 1).is_valid is True


def test_ipv6_connections_are_supported():
    adapter = WindowsConnectionAdapter()
    ev = adapter.validate_and_normalize(
        _conn(local_address="2001:db8::1", remote_address="2606:4700::1111"), 1
    ).event
    assert ev is not None
    assert ev.src_ip == "2001:db8::1"
    assert ev.dst_ip == "2606:4700::1111"


# ──────────────────────────────────────────────────────────────────
# Deterministic identity / repeated polling
# ──────────────────────────────────────────────────────────────────


def test_same_connection_yields_same_event_id_across_polls():
    """Repeated polling must be idempotent at the storage layer."""
    adapter = WindowsConnectionAdapter()
    record = _conn()
    assert adapter.event_id_for(dict(record)) == adapter.event_id_for(dict(record))


def test_new_connection_reusing_port_is_a_distinct_event():
    """
    An ephemeral port reused by a later connection must not be mistaken for
    the same connection.
    """
    adapter = WindowsConnectionAdapter()
    first = _conn(creation_time="2026-10-11T16:36:26.0000000Z")
    second = _conn(creation_time="2026-10-11T17:10:00.0000000Z")
    assert adapter.event_id_for(first) != adapter.event_id_for(second)


def test_repeat_observations_are_suppressed_not_counted_as_new():
    """
    Polling twice over a set of still-open connections must not inflate
    accepted counts, and suppressed repeats must not be reported as
    rejections either.
    """
    adapter = WindowsConnectionAdapter()
    records = [
        _conn(local_port=1000 + i, remote_address=f"93.184.216.{i}")
        for i in range(5)
    ]

    events1, summary1 = adapter.normalize_batch([dict(r) for r in records])
    assert len(events1) == 5
    assert summary1.accepted_records == 5
    assert summary1.rejected_records == 0

    events2, summary2 = adapter.normalize_batch([dict(r) for r in records])
    assert events2 == []
    assert summary2.total_records == 5
    assert summary2.accepted_records == 0
    # Suppressed repeats are neither accepted nor rejected.
    assert summary2.rejected_records == 0
    assert summary2.rejection_reasons["_duplicates_suppressed"] == 5
    assert adapter.duplicates_suppressed == 5


def test_batch_accounting_balances_all_four_outcomes():
    adapter = WindowsConnectionAdapter()
    records = [
        _conn(local_port=2000),                                      # accepted
        _conn(local_port=2001, remote_address="0.0.0.0"),             # rejected
        _conn(local_port=2002, remote_port=70000),                   # rejected
        _conn(local_port=2000),                                      # duplicate
        _conn(local_address="127.0.0.1", remote_address="127.0.0.1"),  # filtered
    ]
    events, summary = adapter.normalize_batch(records)

    duplicates = summary.rejection_reasons.get("_duplicates_suppressed", 0)
    filtered = summary.rejection_reasons.get("_filtered_by_policy", 0)
    assert summary.total_records == 5
    assert summary.accepted_records == len(events) == 1
    assert duplicates == 1
    assert filtered == 1
    assert summary.rejected_records == 2
    # Every observed record is accounted for exactly once, under exactly one
    # outcome: accepted, rejected, duplicate, or filtered.
    assert (
        summary.accepted_records
        + summary.rejected_records
        + duplicates
        + filtered
    ) == 5


def test_mixed_batch_persists_valid_records_despite_bad_ones():
    """A malformed record must not discard the rest of the poll."""
    adapter = WindowsConnectionAdapter()
    records = [
        _conn(local_port=3000),
        "not-a-dict",  # type: ignore[list-item]
        _conn(local_port=3001, remote_address="203.0.113.7"),
    ]
    events, summary = adapter.normalize_batch(records)  # type: ignore[arg-type]

    assert len(events) == 2
    assert summary.rejection_reasons.get("non_object_record") == 1


def test_fingerprint_cache_pruning_does_not_change_event_ids():
    """
    Bounding dedup memory must not alter identity: storage keys on the
    deterministic event_id, so a pruned cache cannot create duplicate rows.
    """
    adapter = WindowsConnectionAdapter()
    record = _conn()
    original_id = adapter.event_id_for(record)

    adapter.normalize_batch([dict(record)])
    adapter.prune_fingerprint_cache(max_entries=0)

    events, _ = adapter.normalize_batch([dict(record)])
    assert len(events) == 1
    assert events[0].event_id == original_id
