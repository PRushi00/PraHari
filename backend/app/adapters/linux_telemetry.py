"""
PraHari — Linux Host Connection Telemetry (blueprint §4.4, §5)

The blueprint names Windows and Linux as the initial support targets, and
`WindowsTelemetryCollectorService` was already platform-neutral apart from
one `sys.platform == "win32"` gate and its PowerShell query function. The
gap was the adapter, not the service — so this module supplies a Linux
query function emitting the **same raw record shape**, and nothing in the
collector, normalization, identity or storage path changes.

Source: `/proc/net/tcp` and `/proc/net/tcp6`, read directly.

Why not `ss` or `netstat`
-------------------------
Both are external binaries that may be absent, and both would need their
human-readable output parsed. `/proc` is the kernel's own interface, is
present on any Linux with procfs, needs no package, and is readable
unprivileged. Reading a file is also cheaper than spawning a process on
every poll.

Honest limits, reported rather than papered over
------------------------------------------------
* **Process attribution is partial without elevation.** `/proc/net/tcp`
  gives a socket inode, not a PID. Resolving it means scanning
  `/proc/<pid>/fd`, which only succeeds for processes owned by the same
  user. Another user's connection appears with no process name — absent,
  never guessed.
* **Polling has the same blind spot as the Windows table.** A connection
  that opens and closes between two polls is never seen. This is a
  property of sampling a table, not a defect of this adapter.
* **IPv6 addresses in `/proc` are in a word-swapped byte order** that
  differs between kernels' endianness. The conversion here is written for
  little-endian hosts, which is every mainstream Linux target; a
  big-endian host would need a different word order, and the adapter says
  so rather than silently emitting wrong addresses.
"""

from __future__ import annotations

import logging
import os
import socket
import struct
import sys
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

PROC_TCP = "/proc/net/tcp"
PROC_TCP6 = "/proc/net/tcp6"

# /proc/net/tcp reports the state as a hex code. Names match the strings
# the Windows adapter emits, so the canonical event does not depend on
# which host produced it.
TCP_STATES: dict[int, str] = {
    0x01: "Established",
    0x02: "SynSent",
    0x03: "SynReceived",
    0x04: "FinWait1",
    0x05: "FinWait2",
    0x06: "TimeWait",
    0x07: "Closed",
    0x08: "CloseWait",
    0x09: "LastAck",
    0x0A: "Listen",
    0x0B: "Closing",
}

DEFAULT_TCP_STATES: tuple[str, ...] = ("Established", "Listen", "CloseWait", "TimeWait")


class LinuxTelemetryUnavailable(RuntimeError):
    """The Linux connection table cannot be read on this host."""


def platform_is_linux() -> bool:
    return sys.platform.startswith("linux")


# ──────────────────────────────────────────────────────────────────
# Address decoding (pure — unit-testable on any platform)
# ──────────────────────────────────────────────────────────────────


def _decode_ipv4(hex_addr: str) -> str:
    """
    "0100007F" -> "127.0.0.1".

    /proc writes the 32-bit address in host byte order as hex, so on a
    little-endian host the octets are reversed relative to dotted form.
    """
    packed = struct.pack("<I", int(hex_addr, 16))
    return socket.inet_ntop(socket.AF_INET, packed)


def _decode_ipv6(hex_addr: str) -> str:
    """
    Decode a 32-hex-character /proc IPv6 address.

    The kernel writes four 32-bit words, each in host byte order, so each
    4-byte group is reversed on a little-endian host while the groups
    themselves stay in order.
    """
    if len(hex_addr) != 32:
        raise ValueError(f"expected 32 hex characters, got {len(hex_addr)}")
    words = [hex_addr[i:i + 8] for i in range(0, 32, 8)]
    packed = b"".join(struct.pack("<I", int(w, 16)) for w in words)
    return socket.inet_ntop(socket.AF_INET6, packed)


def parse_proc_net_line(line: str, ipv6: bool = False) -> Optional[dict[str, Any]]:
    """
    Parse one `/proc/net/tcp[6]` data row into the canonical raw shape.

    Returns None for a row that cannot be understood, rather than a
    partially-filled record: a half-decoded connection is worse than a
    skipped one, because it looks like evidence.
    """
    fields = line.split()
    # sl local_address rem_address st tx:rx retrnsmt uid timeout inode ...
    if len(fields) < 10:
        return None

    try:
        local_hex, local_port_hex = fields[1].split(":")
        remote_hex, remote_port_hex = fields[2].split(":")
        state_code = int(fields[3], 16)
        inode = int(fields[9])
        decode = _decode_ipv6 if ipv6 else _decode_ipv4
        record: dict[str, Any] = {
            "local_address": decode(local_hex),
            "local_port": int(local_port_hex, 16),
            "remote_address": decode(remote_hex),
            "remote_port": int(remote_port_hex, 16),
            "protocol": "TCP",
            "state": TCP_STATES.get(state_code, f"Unknown({state_code:#04x})"),
            "inode": inode,
            # Filled in later only where attribution actually succeeds.
            "owning_pid": None,
            "process_name": None,
            # /proc exposes no socket creation time, so this stays absent
            # rather than being set to "now", which would misdate every
            # connection as having just started.
            "creation_time": None,
        }
        return record
    except (ValueError, IndexError) as exc:
        logger.debug("Unparseable /proc/net row skipped: %s", exc)
        return None


def read_proc_net(path: str, ipv6: bool = False) -> list[dict[str, Any]]:
    """Read and parse one /proc/net/tcp-style table. Missing file -> []."""
    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        # tcp6 is legitimately absent when IPv6 is disabled. Not an error.
        return []
    except PermissionError as exc:
        raise LinuxTelemetryUnavailable(f"Cannot read {path}: {exc}") from exc

    rows = []
    for line in text.splitlines()[1:]:  # first line is the header
        record = parse_proc_net_line(line, ipv6=ipv6)
        if record is not None:
            rows.append(record)
    return rows


# ──────────────────────────────────────────────────────────────────
# Process attribution (best effort, never guessed)
# ──────────────────────────────────────────────────────────────────


def build_inode_process_map(proc_root: str = "/proc") -> dict[int, tuple[int, str]]:
    """
    Map socket inode -> (pid, process name) for processes we may inspect.

    Everything here is best effort by design. A process owned by another
    user raises PermissionError on its fd directory and is skipped, which
    is why attribution is partial without elevation. A process that exits
    mid-scan raises FileNotFoundError and is likewise skipped.
    """
    mapping: dict[int, tuple[int, str]] = {}
    root = Path(proc_root)
    try:
        entries = list(root.iterdir())
    except OSError:
        return mapping

    for entry in entries:
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        fd_dir = entry / "fd"
        try:
            fds = list(fd_dir.iterdir())
        except (PermissionError, FileNotFoundError, NotADirectoryError, OSError):
            continue

        name = ""
        for fd in fds:
            try:
                target = os.readlink(fd)
            except OSError:
                continue
            if not target.startswith("socket:["):
                continue
            try:
                inode = int(target[len("socket:["):-1])
            except ValueError:
                continue
            if not name:
                name = _read_process_name(entry)
            mapping[inode] = (pid, name)
    return mapping


def _read_process_name(proc_entry: Path) -> str:
    """
    The executable name only — never the command line.

    `/proc/<pid>/cmdline` routinely contains passwords, tokens and file
    paths passed as arguments. `comm` is the bare name, which is what the
    Windows adapter reports too.
    """
    try:
        return (proc_entry / "comm").read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return ""


# ──────────────────────────────────────────────────────────────────
# The query function the collector injects
# ──────────────────────────────────────────────────────────────────


def query_linux_connections(
    states: tuple[str, ...] = DEFAULT_TCP_STATES,
    include_process_names: bool = True,
    proc_tcp: str = PROC_TCP,
    proc_tcp6: str = PROC_TCP6,
    proc_root: str = "/proc",
) -> list[dict[str, Any]]:
    """
    Query the live Linux TCP connection table.

    Signature and return shape deliberately mirror
    `query_windows_connections`, so the collector, the canonical event and
    the deterministic event id are identical on both platforms.

    Raises LinuxTelemetryUnavailable when the table cannot be read at all.
    """
    if not Path(proc_tcp).exists():
        raise LinuxTelemetryUnavailable(
            f"{proc_tcp} is not present; Linux connection-table collection "
            "is unavailable on this host (procfs may not be mounted)."
        )

    rows = read_proc_net(proc_tcp, ipv6=False) + read_proc_net(proc_tcp6, ipv6=True)

    wanted = {s.lower() for s in states}
    rows = [r for r in rows if str(r.get("state", "")).lower() in wanted]

    if include_process_names and rows:
        inode_map = build_inode_process_map(proc_root)
        for row in rows:
            attributed = inode_map.get(row.get("inode"))
            if attributed:
                row["owning_pid"], row["process_name"] = attributed
            # Otherwise both stay None: not visible without elevation, and
            # reported as absent rather than invented.

    for row in rows:
        row.pop("inode", None)  # an internal join key, not telemetry
    return rows
