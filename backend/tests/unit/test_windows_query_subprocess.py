"""
PraHari — The Windows Connection-Table Query at the Subprocess Boundary.

`query_windows_connections` turns a PowerShell child process into records.
Its success path is proven live (`live_windows`); every way that child can
fail was handled in code but tested nowhere. These tests exercise each
branch through the function itself.

What is real and what is not
----------------------------
* The missing-executable case is REAL: the operating system is asked to
  start a program that does not exist.
* Timeout, nonzero exit and the output shapes are produced by substituting
  `subprocess.run` with a stand-in that returns what PowerShell would.
  They prove PraHari's handling of those outcomes, not that PowerShell
  produces them - that part is the live test's job.

Platform-neutral: no PowerShell is started.
"""

from __future__ import annotations

import json
import subprocess

import pytest

from app.adapters import windows_telemetry as wt
from app.adapters.windows_telemetry import (
    DEFAULT_TCP_STATES,
    VALID_TCP_STATES,
    WindowsTelemetryUnavailable,
    query_windows_connections,
)

ROW = {
    "protocol": "TCP", "local_address": "192.0.2.10", "local_port": 50000,
    "remote_address": "198.51.100.20", "remote_port": 443,
    "state": "Established", "creation_time": "2026-10-17T10:00:00Z",
}


class FakeRun:
    """Stands in for subprocess.run and records how it was called."""

    def __init__(self, *, stdout="", stderr="", returncode=0, raises=None):
        self.result = subprocess.CompletedProcess(args=[], returncode=returncode,
                                                  stdout=stdout, stderr=stderr)
        self.raises = raises
        self.calls: list[tuple[tuple, dict]] = []

    def __call__(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        if self.raises is not None:
            raise self.raises
        return self.result


@pytest.fixture
def fake(monkeypatch):
    def install(**kw):
        stub = FakeRun(**kw)
        monkeypatch.setattr(wt.subprocess, "run", stub)
        return stub
    return install


# ──────────────────────────────────────────────────────────────────
# Failure branches: each becomes WindowsTelemetryUnavailable, never a crash
# ──────────────────────────────────────────────────────────────────


def test_a_missing_powershell_is_reported_not_raised_raw():
    """Real: the OS is asked to start a program that does not exist."""
    with pytest.raises(WindowsTelemetryUnavailable, match="not found"):
        query_windows_connections(powershell_path="prahari-no-such-powershell-xyz.exe")


def test_a_timeout_is_reported_with_its_bound(fake):
    fake(raises=subprocess.TimeoutExpired(cmd="powershell", timeout=3))
    with pytest.raises(WindowsTelemetryUnavailable, match=r"timed out after 3"):
        query_windows_connections(timeout_seconds=3)


def test_a_nonzero_exit_carries_powershells_own_error(fake):
    fake(returncode=1, stderr="Get-NetTCPConnection : Access is denied.")
    with pytest.raises(WindowsTelemetryUnavailable) as exc:
        query_windows_connections()
    assert "exit 1" in str(exc.value)
    assert "Access is denied" in str(exc.value)


def test_a_huge_error_message_is_bounded(fake):
    fake(returncode=1, stderr="E" * 10_000)
    with pytest.raises(WindowsTelemetryUnavailable) as exc:
        query_windows_connections()
    assert len(str(exc.value)) < 600


def test_unparseable_output_is_refused_not_guessed(fake):
    fake(stdout="WARNING: something unexpected\n{not json")
    with pytest.raises(WindowsTelemetryUnavailable, match="unparseable"):
        query_windows_connections()


# ──────────────────────────────────────────────────────────────────
# Output shapes PowerShell actually produces
# ──────────────────────────────────────────────────────────────────


def test_no_connections_is_an_empty_list_not_an_error(fake):
    fake(stdout="   \n")
    assert query_windows_connections() == []


def test_a_single_connection_unwrapped_by_powershell_is_still_a_list(fake):
    """ConvertTo-Json emits a bare object, not an array, for one row."""
    fake(stdout=json.dumps(ROW))
    assert query_windows_connections() == [ROW]


def test_non_object_items_are_dropped_from_a_list(fake):
    fake(stdout=json.dumps([ROW, "junk", 42, None, ROW]))
    assert query_windows_connections() == [ROW, ROW]


def test_a_json_scalar_is_no_records(fake):
    fake(stdout="42")
    assert query_windows_connections() == []


# ──────────────────────────────────────────────────────────────────
# How the child is started
# ──────────────────────────────────────────────────────────────────


def test_the_child_is_started_as_an_argument_list_never_through_a_shell(fake):
    stub = fake(stdout="[]")
    query_windows_connections(powershell_path="powershell")

    (args, kwargs), = stub.calls
    argv = args[0]
    assert isinstance(argv, list), "a string command would go through a shell"
    assert argv[:4] == ["powershell", "-NoProfile", "-NonInteractive", "-Command"]
    assert not kwargs.get("shell"), "shell=True would reinterpret the script"
    assert kwargs.get("timeout") is not None, "an unbounded child can hang a poll"


# ──────────────────────────────────────────────────────────────────
# The states allow-list
# ──────────────────────────────────────────────────────────────────


def test_every_default_state_is_a_real_windows_state():
    assert set(DEFAULT_TCP_STATES) <= VALID_TCP_STATES


@pytest.mark.parametrize("states", [
    ("Established'; Remove-Item C:\\Windows\\Temp\\x; '",),
    ("Established", "$(Get-Process)"),
    ("established",),          # PowerShell would accept it; the allow-list is stricter
    (),
])
def test_an_unknown_state_is_refused_before_anything_is_spawned(fake, states):
    stub = fake(stdout="[]")
    with pytest.raises(ValueError):
        query_windows_connections(states=states)
    assert stub.calls == [], "the child must never start with an unvetted state"


def test_a_valid_custom_subset_is_accepted(fake):
    stub = fake(stdout="[]")
    query_windows_connections(states=("Listen", "Established"))
    script = stub.calls[0][0][0][-1]
    assert "'Listen','Established'" in script
