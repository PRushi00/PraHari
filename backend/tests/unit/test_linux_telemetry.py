"""
PraHari — Linux Host Connection Adapter (ADR-053, blueprint §4.4, §5).

The parsing and decoding here is pure, so it is tested on any platform
against real `/proc/net/tcp` text. The two tests that touch a live
`/proc` are skipped elsewhere and say so, rather than being silently
absent from the count.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from app.adapters.linux_telemetry import (
    DEFAULT_TCP_STATES,
    LinuxTelemetryUnavailable,
    TCP_STATES,
    _decode_ipv4,
    _decode_ipv6,
    build_inode_process_map,
    parse_proc_net_line,
    query_linux_connections,
    read_proc_net,
)

IS_LINUX = sys.platform.startswith("linux")

# Real /proc/net/tcp text. Columns: sl local rem st tx:rx retr uid to inode ...
PROC_TCP_SAMPLE = """\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 34567 1 0000000000000000 100 0 0 10 0
   1: 0A00020F:A1B2 0A000201:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 34568 1 0000000000000000 20 4 30 10 -1
   2: 0100007F:C350 0100007F:1F90 06 00000000:00000000 00:00000000 00000000     0        0 0 1 0000000000000000 0 0 0 0 0
"""

PROC_TCP6_SAMPLE = """\
  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:0050 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 44001 1 0000000000000000 100 0 0 10 0
"""


# ──────────────────────────────────────────────────────────────────
# Address decoding
# ──────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "hex_addr, expected",
    [
        ("0100007F", "127.0.0.1"),
        ("00000000", "0.0.0.0"),
        ("0A00020F", "15.2.0.10"),
        ("0101A8C0", "192.168.1.1"),
    ],
)
def test_ipv4_addresses_decode_from_host_byte_order(hex_addr, expected):
    assert _decode_ipv4(hex_addr) == expected


def test_ipv6_unspecified_address_decodes():
    assert _decode_ipv6("0" * 32) == "::"


def test_ipv6_loopback_decodes():
    # ::1 — the final word holds 0x01000000 in /proc's word-swapped form.
    assert _decode_ipv6("00000000000000000000000001000000") == "::1"


def test_a_malformed_ipv6_length_is_rejected_rather_than_padded():
    with pytest.raises(ValueError):
        _decode_ipv6("00FF")


# ──────────────────────────────────────────────────────────────────
# Row parsing
# ──────────────────────────────────────────────────────────────────


def test_a_listening_socket_parses_into_the_canonical_raw_shape():
    row = parse_proc_net_line(PROC_TCP_SAMPLE.splitlines()[1])

    assert row is not None
    assert row["local_address"] == "127.0.0.1"
    assert row["local_port"] == 8080
    assert row["remote_address"] == "0.0.0.0"
    assert row["remote_port"] == 0
    assert row["protocol"] == "TCP"
    assert row["state"] == "Listen"


def test_an_established_connection_parses():
    row = parse_proc_net_line(PROC_TCP_SAMPLE.splitlines()[2])

    assert row["state"] == "Established"
    assert row["local_port"] == 0xA1B2
    assert row["remote_port"] == 443


def test_creation_time_is_absent_rather_than_set_to_now():
    """
    /proc exposes no socket creation time. Defaulting it to the poll
    instant would misdate every connection as having just started.
    """
    row = parse_proc_net_line(PROC_TCP_SAMPLE.splitlines()[1])

    assert row["creation_time"] is None


def test_process_attribution_starts_absent_not_guessed():
    row = parse_proc_net_line(PROC_TCP_SAMPLE.splitlines()[1])

    assert row["owning_pid"] is None
    assert row["process_name"] is None


@pytest.mark.parametrize(
    "line",
    [
        "",
        "   0: garbage",
        "   0: NOTHEX:ZZZZ 00000000:0000 0A 0 0 0 0 0 0 0",
        "   0: 0100007F 00000000:0000 0A 0 0 0 0 0 0 0",  # no :port
    ],
)
def test_an_unparseable_row_is_skipped_not_half_filled(line):
    """A half-decoded connection is worse than a skipped one: it looks
    like evidence."""
    assert parse_proc_net_line(line) is None


def test_an_unknown_state_code_is_labelled_not_dropped():
    line = "   0: 0100007F:1F90 00000000:0000 FF 0 0 0 0 0 999 1"
    row = parse_proc_net_line(line)

    assert row is not None
    assert "Unknown" in row["state"]


def test_every_documented_state_code_has_a_name():
    assert set(TCP_STATES) == set(range(0x01, 0x0C))


# ──────────────────────────────────────────────────────────────────
# Table reading
# ──────────────────────────────────────────────────────────────────


def test_reading_a_table_skips_the_header(tmp_path):
    f = tmp_path / "tcp"
    f.write_text(PROC_TCP_SAMPLE, encoding="utf-8")

    rows = read_proc_net(str(f))

    assert len(rows) == 3
    assert all("local_address" in r for r in rows)


def test_a_missing_ipv6_table_is_not_an_error(tmp_path):
    """tcp6 is legitimately absent when IPv6 is disabled."""
    assert read_proc_net(str(tmp_path / "does-not-exist"), ipv6=True) == []


def test_ipv6_rows_parse_from_the_ipv6_table(tmp_path):
    f = tmp_path / "tcp6"
    f.write_text(PROC_TCP6_SAMPLE, encoding="utf-8")

    rows = read_proc_net(str(f), ipv6=True)

    assert len(rows) == 1
    assert rows[0]["local_address"] == "::"
    assert rows[0]["local_port"] == 80


# ──────────────────────────────────────────────────────────────────
# The query function
# ──────────────────────────────────────────────────────────────────


def test_an_absent_proc_table_raises_rather_than_returning_empty(tmp_path):
    """
    Empty means "no connections". Unavailable means "we cannot see". The
    two must not be conflated — §6 forbids turning a collection failure
    into benign traffic.
    """
    with pytest.raises(LinuxTelemetryUnavailable):
        query_linux_connections(proc_tcp=str(tmp_path / "nope"))


def test_the_query_filters_to_the_requested_states(tmp_path):
    tcp = tmp_path / "tcp"
    tcp.write_text(PROC_TCP_SAMPLE, encoding="utf-8")

    established = query_linux_connections(
        states=("Established",),
        include_process_names=False,
        proc_tcp=str(tcp),
        proc_tcp6=str(tmp_path / "absent"),
    )

    assert len(established) == 1
    assert established[0]["state"] == "Established"


def test_the_internal_inode_join_key_is_not_emitted_as_telemetry(tmp_path):
    tcp = tmp_path / "tcp"
    tcp.write_text(PROC_TCP_SAMPLE, encoding="utf-8")

    rows = query_linux_connections(
        include_process_names=False,
        proc_tcp=str(tcp),
        proc_tcp6=str(tmp_path / "absent"),
    )

    assert rows
    assert all("inode" not in r for r in rows)


def test_the_raw_shape_matches_what_the_windows_adapter_consumes(tmp_path):
    """
    The whole point of this adapter: the collector, normalization and the
    deterministic event id are unchanged because the record shape is.
    """
    tcp = tmp_path / "tcp"
    tcp.write_text(PROC_TCP_SAMPLE, encoding="utf-8")

    row = query_linux_connections(
        include_process_names=False,
        proc_tcp=str(tcp),
        proc_tcp6=str(tmp_path / "absent"),
    )[0]

    required = {
        "local_address", "local_port", "remote_address", "remote_port",
        "protocol", "state", "owning_pid", "process_name", "creation_time",
    }
    assert required <= set(row)


def test_the_windows_adapter_normalizes_a_linux_record_unchanged(tmp_path):
    """
    Drive a Linux-produced record through the existing normalization and
    confirm it yields a canonical event with a deterministic identity.
    """
    from app.adapters.windows_telemetry import WindowsConnectionAdapter

    tcp = tmp_path / "tcp"
    tcp.write_text(PROC_TCP_SAMPLE, encoding="utf-8")
    rows = query_linux_connections(
        states=("Established",),
        include_process_names=False,
        proc_tcp=str(tcp),
        proc_tcp6=str(tmp_path / "absent"),
    )

    adapter = WindowsConnectionAdapter(adapter_id="linux_local_host")
    first = adapter.validate_and_normalize(rows[0], 0)
    second = adapter.validate_and_normalize(rows[0], 0)

    assert first.is_valid, first.errors
    assert first.event.event_id == second.event.event_id, (
        "the same connection polled twice must keep one identity"
    )
    assert first.event.dst_port == 443


# ──────────────────────────────────────────────────────────────────
# Process attribution, against a synthetic /proc
# ──────────────────────────────────────────────────────────────────


def test_inode_attribution_maps_a_socket_to_its_process(tmp_path):
    if sys.platform == "win32":
        pytest.skip("symlink creation in /proc/<pid>/fd requires a POSIX host")

    proc = tmp_path / "proc"
    pid_dir = proc / "4242"
    fd_dir = pid_dir / "fd"
    fd_dir.mkdir(parents=True)
    (pid_dir / "comm").write_text("my-daemon\n", encoding="utf-8")
    (fd_dir / "3").symlink_to("socket:[34568]")

    mapping = build_inode_process_map(str(proc))

    assert mapping.get(34568) == (4242, "my-daemon")


def test_attribution_reports_the_name_only_never_the_command_line(tmp_path):
    """
    /proc/<pid>/cmdline routinely carries passwords and tokens passed as
    arguments. Only `comm` is read.
    """
    if sys.platform == "win32":
        pytest.skip("symlink creation in /proc/<pid>/fd requires a POSIX host")

    proc = tmp_path / "proc"
    fd_dir = proc / "99" / "fd"
    fd_dir.mkdir(parents=True)
    (proc / "99" / "comm").write_text("safe-name\n", encoding="utf-8")
    (proc / "99" / "cmdline").write_text(
        "safe-name\x00--password\x00hunter2\x00", encoding="utf-8"
    )
    (fd_dir / "5").symlink_to("socket:[777]")

    pid, name = build_inode_process_map(str(proc))[777]

    assert name == "safe-name"
    assert "hunter2" not in name


def test_a_nonexistent_proc_root_yields_no_attribution_rather_than_failing():
    assert build_inode_process_map("/definitely/not/a/proc") == {}


# ──────────────────────────────────────────────────────────────────
# Live host — only where there is one
# ──────────────────────────────────────────────────────────────────


@pytest.mark.skipif(not IS_LINUX, reason="requires a live Linux /proc")
def test_the_live_linux_table_is_readable():
    rows = query_linux_connections(include_process_names=False)

    assert isinstance(rows, list)
    for row in rows:
        assert row["protocol"] == "TCP"
        assert isinstance(row["local_port"], int)


@pytest.mark.skipif(not IS_LINUX, reason="requires a live Linux /proc")
def test_the_collector_selects_the_linux_query_on_linux():
    from app.services.collector import default_host_query_fn

    assert default_host_query_fn() is query_linux_connections


@pytest.mark.skipif(IS_LINUX, reason="asserts the non-Linux selection")
def test_the_collector_selects_the_windows_query_off_linux():
    from app.adapters.windows_telemetry import query_windows_connections
    from app.services.collector import default_host_query_fn

    assert default_host_query_fn() is query_windows_connections
