"""
PraHari — `start_prahari.ps1 -CheckOnly` Is a Check.

Before this, -CheckOnly created a virtual environment and ran pip install
when the venv was missing, ran `npm ci` - which deletes and reinstalls
node_modules - and a production build when the bundle was missing, and
then reported success, even with the port already taken.

Each test copies ONLY the launcher script into an empty temporary
directory and runs it there with real Windows PowerShell, so a missing
prerequisite is genuinely missing and nothing the script might create can
land in the repository. The repository's own venv, node_modules and
frontend/dist are never involved. Every test asserts on the directory's
contents afterwards: a check that creates files has failed.
"""

from __future__ import annotations

import shutil
import socket
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="the launcher is Windows PowerShell")

LAUNCHER = Path(__file__).resolve().parents[3] / "start_prahari.ps1"


def _snapshot(root: Path) -> set[str]:
    return {p.relative_to(root).as_posix() for p in root.rglob("*")}


def _check_only(root: Path, port: int) -> subprocess.CompletedProcess:
    script = root / "start_prahari.ps1"
    return subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
         "-File", str(script), "-CheckOnly", "-Port", str(port)],
        capture_output=True, text=True, timeout=120, cwd=str(root),
    )


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def bare(tmp_path):
    shutil.copy2(LAUNCHER, tmp_path / "start_prahari.ps1")
    return tmp_path


@pytest.fixture
def provisioned(bare):
    """Prerequisites present as files, so nothing would need creating."""
    (bare / "backend" / ".venv" / "Scripts").mkdir(parents=True)
    (bare / "backend" / ".venv" / "Scripts" / "python.exe").write_bytes(b"")
    (bare / "frontend" / "dist").mkdir(parents=True)
    (bare / "frontend" / "dist" / "index.html").write_text("<html></html>", encoding="utf-8")
    return bare


def test_missing_prerequisites_are_reported_and_nothing_is_created(bare):
    before = _snapshot(bare)

    result = _check_only(bare, _free_port())

    assert result.returncode == 1, result.stdout + result.stderr
    assert "virtual environment missing" in result.stdout
    assert "Frontend bundle missing" in result.stdout
    assert "Nothing was created, installed or built" in result.stdout
    assert _snapshot(bare) == before, (
        "a preflight check created files: " + str(sorted(_snapshot(bare) - before))
    )


def test_a_provisioned_layout_passes_and_is_left_untouched(provisioned):
    before = _snapshot(provisioned)

    result = _check_only(provisioned, _free_port())

    assert result.returncode == 0, result.stdout + result.stderr
    assert "[SUCCESS]" in result.stdout
    assert _snapshot(provisioned) == before


def test_a_port_already_listened_on_fails_the_check(provisioned):
    """The listener is this test's own socket, on loopback, closed afterwards."""
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        port = listener.getsockname()[1]

        result = _check_only(provisioned, port)

    assert result.returncode == 1, result.stdout + result.stderr
    assert f"Port {port} is already being listened on" in result.stdout
    assert "[SUCCESS]" not in result.stdout


def test_a_launch_does_not_leak_configuration_into_the_callers_session(provisioned):
    r"""
    The launcher sets PRAHARI_HOST/PRAHARI_PORT for the server it starts.
    Run as `.\start_prahari.ps1` from an open PowerShell it shares that
    session's environment, and the values used to remain after it returned,
    silently reconfiguring anything started later in the same window.

    `python.exe` here is an empty placeholder file, so the launch fails at
    once and no server can start; the caller's environment is then read in
    the same PowerShell process.
    """
    script = str(provisioned / "start_prahari.ps1")
    probe = (
        "$env:PRAHARI_PORT = 'caller-value'; $env:PRAHARI_HOST = $null; "
        f"try {{ & '{script}' -Port {_free_port()} *> $null }} catch {{}}; "
        "'PORT=[' + $env:PRAHARI_PORT + '] HOST=[' + $env:PRAHARI_HOST + ']'"
    )
    result = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
         "-Command", probe],
        capture_output=True, text=True, timeout=120, cwd=str(provisioned),
    )

    assert "PORT=[caller-value] HOST=[]" in result.stdout, result.stdout + result.stderr
