"""
Windows DNS-Client event log adapter (ADR-120).

The whole risk here is that a parser turns an unverified assumption into
an attributed hostname. Discovery (ADR-119) produced exactly ONE record
whose fields were seen:

    Id 3008, TimeCreated 2026-10-22T12:09:56.4674908Z, ProcessId 13268,
    QueryName localhost, QueryType 1, QueryOptions 720575941721587776,
    QueryStatus 0, QueryResults "127.0.0.1;"

Event ids 3006 and 1001 were observed in the same channel and **no field
of either has ever been seen**. These tests pin that the adapter counts
them and refuses to parse them, that a failed or empty query records no
resolution, and that every record read is accounted for.
"""

from __future__ import annotations

import pytest

from app.adapters.windows_dns_events import (
    CHANNEL,
    DnsEventLogUnavailable,
    QUERY_COMPLETED_EVENT_ID,
    UNINTERPRETED_EVENT_IDS,
    collect_dns_observations,
    parse_dns_events,
    read_dns_events,
)
from app.schemas.events import DomainAttributionMethod


#: The record captured on the operator's machine, verbatim. Every string
#: here came off a real event; nothing is invented.
REAL_3008 = {
    "Id": 3008,
    "TimeCreated": "2026-10-22T12:09:56.4674908Z",
    "ProcessId": "13268",
    "QueryName": "localhost",
    "QueryType": "1",
    "QueryOptions": "720575941721587776",
    "QueryStatus": "0",
    "QueryResults": "127.0.0.1;",
}


def _record(**over):
    out = dict(REAL_3008)
    out.update(over)
    return out


# ──────────────────────────────────────────────────────────────────
# The record we actually saw
# ──────────────────────────────────────────────────────────────────


def test_the_real_observed_record_parses_exactly():
    report = parse_dns_events([REAL_3008])

    assert len(report.observations) == 1
    obs = report.observations[0]
    assert obs.hostname == "localhost"
    assert obs.ip_address == "127.0.0.1"
    assert obs.query_type == 1
    assert obs.logging_process_id == 13268
    assert obs.method == DomainAttributionMethod.DNS_QUERY_LOG.value
    # The bitfield is carried verbatim, never decoded.
    assert obs.query_options_raw == "720575941721587776"


def test_the_timestamp_is_utc_and_loses_no_whole_microsecond():
    """
    Windows reports 100-nanosecond precision. The sub-microsecond digit
    is truncated, not rounded: a timestamp is evidence, and rounding it
    upward invents time that did not pass.
    """
    obs = parse_dns_events([REAL_3008]).observations[0]
    assert obs.observed_at.startswith("2026-10-22T12:09:56.467490")
    assert obs.observed_at.endswith("+00:00")


def test_a_naive_timestamp_is_read_as_utc_not_local():
    # Treating it as local time would silently shift every record by the
    # collector host's offset.
    obs = parse_dns_events(
        [_record(TimeCreated="2026-10-22T12:09:56")]
    ).observations[0]
    assert obs.observed_at == "2026-10-22T12:09:56+00:00"


def test_the_storage_shape_carries_no_invented_ttl():
    # The channel reports no TTL. Null, never guessed.
    rows = [o.as_observation("windows_dns_events") for o in parse_dns_events([REAL_3008]).observations]
    assert rows == [
        {
            "ip_address": "127.0.0.1",
            "hostname": "localhost",
            "observed_at": rows[0]["observed_at"],
            "method": "dns_query_log",
            "ttl_seconds": None,
            "source_id": "windows_dns_events",
        }
    ]


# ──────────────────────────────────────────────────────────────────
# Event ids whose fields nobody has seen
# ──────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("event_id", UNINTERPRETED_EVENT_IDS)
def test_an_uninterpreted_event_id_is_counted_never_parsed(event_id):
    """
    3006 and 1001 were observed in the channel. No field of either has
    been seen. Parsing one on the assumption it resembles 3008 is how a
    guess becomes an attributed hostname.
    """
    report = parse_dns_events([_record(Id=event_id, QueryName="example.com")])

    assert report.observations == []
    assert report.uninterpreted_by_event_id == {event_id: 1}
    assert report.reconciles()
    assert any(str(event_id) in note for note in report.notes)
    assert any("would be a guess" in note for note in report.notes)


def test_an_entirely_unseen_event_id_is_also_not_parsed():
    report = parse_dns_events([_record(Id=9999)])
    assert report.observations == []
    assert report.uninterpreted_by_event_id == {9999: 1}


def test_only_3008_is_interpreted():
    # Guards the constant itself: widening it silently would change what
    # this adapter claims to understand.
    assert QUERY_COMPLETED_EVENT_ID == 3008
    assert 3008 not in UNINTERPRETED_EVENT_IDS


# ──────────────────────────────────────────────────────────────────
# Queries that resolved nothing
# ──────────────────────────────────────────────────────────────────


def test_a_failed_query_records_no_resolution():
    """
    QueryStatus != 0 means the lookup did not succeed, so there is no
    name-to-address fact. That it was attempted is not a resolution.
    """
    report = parse_dns_events([_record(QueryStatus="9003", QueryResults="")])

    assert report.observations == []
    assert report.skipped_failed_query == 1
    assert report.reconciles()
    assert any("did not succeed" in note for note in report.notes)


def test_a_successful_query_with_no_addresses_records_no_resolution():
    report = parse_dns_events([_record(QueryResults="")])

    assert report.observations == []
    assert report.skipped_no_results == 1
    assert any("not what it resolved to" in note for note in report.notes)


def test_a_non_address_result_is_dropped_not_stored_as_an_address():
    # A CNAME target is not an `ip_address`. Storing one would make the
    # attribution table lie about what that column holds.
    report = parse_dns_events(
        [_record(QueryResults="cdn.example.net;93.184.216.34;")]
    )
    assert [o.ip_address for o in report.observations] == ["93.184.216.34"]


def test_several_addresses_become_several_observations_from_one_record():
    report = parse_dns_events(
        [_record(QueryName="example.com", QueryResults="93.184.216.34;2606:2800:220:1:248:1893:25c8:1946;")]
    )
    assert len(report.observations) == 2
    assert report.successful_records == 1
    assert {o.hostname for o in report.observations} == {"example.com"}
    assert report.reconciles()


# ──────────────────────────────────────────────────────────────────
# Malformed input
# ──────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "over",
    [
        {"QueryName": ""},
        {"QueryName": None},
        {"TimeCreated": "not-a-timestamp"},
        {"TimeCreated": None},
        {"QueryStatus": "not-a-number"},
        {"Id": "not-a-number"},
    ],
)
def test_a_malformed_record_is_skipped_and_counted(over):
    report = parse_dns_events([_record(**over)])
    assert report.observations == []
    assert report.reconciles(), "a skipped record escaped the accounting"


def test_a_non_dict_record_is_skipped():
    report = parse_dns_events(["not a record", 42, None])  # type: ignore[list-item]
    assert report.observations == []
    assert report.skipped_malformed == 3
    assert report.reconciles()


def test_an_empty_read_is_distinguishable_from_a_failed_one():
    report = parse_dns_events([])
    assert report.records_read == 0
    assert report.observations == []
    assert report.notes == []
    assert report.reconciles()


# ──────────────────────────────────────────────────────────────────
# Duplicates
# ──────────────────────────────────────────────────────────────────


def test_the_same_event_read_twice_yields_identical_rows():
    """
    The adapter does not deduplicate; storage does, on
    UNIQUE(ip_address, hostname, observed_at) with INSERT OR IGNORE.

    What matters here is that re-reading an overlapping window produces
    rows identical in those three columns, so the storage constraint can
    actually collapse them.
    """
    first = parse_dns_events([REAL_3008]).observations[0].as_observation("s")
    second = parse_dns_events([REAL_3008]).observations[0].as_observation("s")

    key = lambda row: (row["ip_address"], row["hostname"], row["observed_at"])
    assert key(first) == key(second)


def test_two_resolutions_of_one_name_at_different_times_are_both_kept():
    # Append-only by design: a later answer does not erase an earlier
    # one, because a shared address legitimately maps to many names.
    report = parse_dns_events(
        [
            REAL_3008,
            _record(TimeCreated="2026-10-22T12:10:56.0000000Z"),
        ]
    )
    stamps = {o.observed_at for o in report.observations}
    assert len(stamps) == 2


# ──────────────────────────────────────────────────────────────────
# The source being unavailable
# ──────────────────────────────────────────────────────────────────


def _proc(stdout: str, returncode: int = 0, stderr: str = ""):
    class _P:
        pass

    p = _P()
    p.stdout = stdout
    p.returncode = returncode
    p.stderr = stderr
    return p


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        ('{"error":"channel_absent"}', "does not exist on this host"),
        ('{"error":"channel_disabled"}', "disabled, which is the Windows"),
        (
            '{"error":"channel_unreadable","detail":"Access is denied"}',
            "could not be read by this account",
        ),
    ],
)
def test_each_unavailable_reason_is_reported_distinctly(monkeypatch, payload, expected):
    """
    Absent, disabled and unreadable are three different operator
    actions. Collapsing them into "no DNS evidence" hides which applies.
    """
    import subprocess as sp

    monkeypatch.setattr(sp, "run", lambda *a, **k: _proc(payload))

    with pytest.raises(DnsEventLogUnavailable) as excinfo:
        read_dns_events()
    assert expected in str(excinfo.value)
    assert CHANNEL in str(excinfo.value)


def test_missing_powershell_is_reported_not_swallowed(monkeypatch):
    import subprocess as sp

    def _boom(*a, **k):
        raise FileNotFoundError("powershell")

    monkeypatch.setattr(sp, "run", _boom)
    with pytest.raises(DnsEventLogUnavailable, match="not found"):
        read_dns_events()


def test_a_timeout_is_reported_not_swallowed(monkeypatch):
    import subprocess as sp

    def _boom(*a, **k):
        raise sp.TimeoutExpired(cmd="powershell", timeout=30.0)

    monkeypatch.setattr(sp, "run", _boom)
    with pytest.raises(DnsEventLogUnavailable, match="timed out"):
        read_dns_events()


def test_unparseable_output_is_reported_not_treated_as_empty(monkeypatch):
    import subprocess as sp

    monkeypatch.setattr(sp, "run", lambda *a, **k: _proc("<html>nope</html>"))
    with pytest.raises(DnsEventLogUnavailable, match="unparseable"):
        read_dns_events()


def test_a_nonzero_exit_is_reported(monkeypatch):
    import subprocess as sp

    monkeypatch.setattr(
        sp, "run", lambda *a, **k: _proc("", returncode=1, stderr="boom")
    )
    with pytest.raises(DnsEventLogUnavailable, match="exit 1"):
        read_dns_events()


def test_max_events_is_validated_before_a_process_is_spawned(monkeypatch):
    import subprocess as sp

    def _never(*a, **k):
        raise AssertionError("a process was spawned for an invalid argument")

    monkeypatch.setattr(sp, "run", _never)
    with pytest.raises(ValueError, match="at least 1"):
        read_dns_events(max_events=0)


def test_collect_returns_storage_rows_and_the_report_together(monkeypatch):
    """
    The report travels with the rows. A caller that stored them without
    it would present a partial read as a complete one.
    """
    import subprocess as sp
    import json as _json

    payload = _json.dumps(
        {"records": [REAL_3008, _record(Id=3006), _record(QueryStatus="9003")]}
    )
    monkeypatch.setattr(sp, "run", lambda *a, **k: _proc(payload))

    rows, report = collect_dns_observations(source_id="windows_dns_events")

    assert len(rows) == 1
    assert rows[0]["method"] == "dns_query_log"
    assert rows[0]["source_id"] == "windows_dns_events"
    assert report.records_read == 3
    assert report.uninterpreted_by_event_id == {3006: 1}
    assert report.skipped_failed_query == 1
    assert report.reconciles()


# ──────────────────────────────────────────────────────────────────
# Corrections from real field evidence (ADR-121)
# ──────────────────────────────────────────────────────────────────


def test_the_record_pid_is_not_presented_as_the_requesting_application():
    """
    3006 and 3008 are the only two ids in this channel with no
    `ClientPID`. The PID on the record identifies the process that
    EMITTED it, which is not established to be the one that resolved the
    name.

    So the field is named `logging_process_id`. A field called
    `process_id` beside a hostname reads as "this app looked this up",
    which is attribution nobody has earned here.
    """
    obs = parse_dns_events([REAL_3008]).observations[0]

    assert obs.logging_process_id == 13268
    assert not hasattr(obs, "process_id"), (
        "a bare `process_id` invites reading the emitter as the requester"
    )
    # And it never reaches storage, where it would sit beside a hostname.
    assert "process_id" not in obs.as_observation()
    assert "logging_process_id" not in obs.as_observation()


def test_a_typed_cname_in_query_results_is_not_read_as_an_address():
    """
    Measured on event 3020, which interleaves typed CNAMEs with
    addresses:  `type: 5 host;...;1.2.3.4;`

    A naive `;` split reads `type: 5 host` as an address. 3020 is not
    parsed today, but 3008 shares the field and the hazard is in the
    format, not the id.
    """
    report = parse_dns_events(
        [_record(QueryName="cdn.example.com",
                 QueryResults="type: 5 edge.example.net;93.184.216.34;")]
    )

    assert [o.ip_address for o in report.observations] == ["93.184.216.34"]
    assert all("type:" not in o.ip_address for o in report.observations)


@pytest.mark.parametrize("status", ["9701", "121"])
def test_a_documented_non_error_status_records_no_resolution(status):
    """
    9701 is a cache miss and 121 a NETBIOS timeout. Both are normal, not
    malformed — they are counted as queries that did not resolve, not as
    records the parser failed to read. The distinction matters: a rising
    malformed count means the parser is wrong, a rising unresolved count
    means the network is.
    """
    report = parse_dns_events([_record(QueryStatus=status, QueryResults="")])

    assert report.skipped_failed_query == 1
    assert report.skipped_malformed == 0
    assert report.reconciles()
