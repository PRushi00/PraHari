"""
PraHari — Additional Windows Host Observations

Two further *genuine* local sources, both unprivileged, both read-only, and
both deliberately kept separate from the TCP connection table because they
measure different things.

1. UDP endpoint table (``Get-NetUDPEndpoint``)
---------------------------------------------
Windows exposes locally **bound UDP sockets**, not UDP conversations. There
is no remote peer in this table, because UDP is connectionless and the OS
does not track one for an unconnected socket.

So a UDP endpoint record answers "which process holds which local UDP port",
and nothing else. It is emitted as ``EventType.UDP_ENDPOINT`` with
``dst_ip`` / ``dst_port`` marked **not applicable** — not "missing". Writing
these into the schema as connections, with a wildcard or inferred
destination, would manufacture peers that were never observed and would
corrupt every destination-based aggregation.

2. Interface statistics (``Get-NetAdapterStatistics``)
------------------------------------------------------
Real, OS-measured byte and packet counters — the only genuine volume
measurement available on this host without packet capture. They are
**cumulative, per network interface, since the adapter last reset**.

They are therefore *not* flow metrics and are never written into
``normalized_events``. A per-interface counter cannot be attributed to a
connection, a process or a destination, and summing it alongside flow byte
counts from an imported dataset would produce a number that means nothing.
They are reported through their own endpoint, with the measurement scope
stated in the payload.

Neither source captures packets, inspects payload, requires elevation,
installs anything, or touches network configuration.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import subprocess
from datetime import datetime, timezone
from typing import Any, Callable, Optional

from pydantic import BaseModel, Field

from app.adapters.base import BaseTelemetryAdapter
from app.adapters.windows_telemetry import (
    MAX_CLOCK_SKEW_SECONDS,
    MIN_PLAUSIBLE_YEAR,
    WindowsTelemetryUnavailable,
)
from app.schemas.events import (
    SCHEMA_VERSION,
    DataCategory,
    EventType,
    LabelProvenance,
    NormalizedEvent,
    QualityFlag,
    ValidationResult,
)

logger = logging.getLogger(__name__)

UDP_SOURCE_TYPE = "windows_udp_endpoint"
INTERFACE_SOURCE_TYPE = "windows_interface_counters"


# ──────────────────────────────────────────────────────────────────
# PowerShell probes
# ──────────────────────────────────────────────────────────────────

_PS_UDP_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$procNames = @{{}}
if (${include_process}) {{
    Get-Process -ErrorAction SilentlyContinue | ForEach-Object {{
        $procNames[[int]$_.Id] = [string]$_.ProcessName
    }}
}}
$rows = Get-NetUDPEndpoint -ErrorAction SilentlyContinue | ForEach-Object {{
    $opid = [int]$_.OwningProcess
    $pname = $null
    if ($procNames.ContainsKey($opid)) {{ $pname = $procNames[$opid] }}
    [pscustomobject]@{{
        local_address = [string]$_.LocalAddress
        local_port    = [int]$_.LocalPort
        owning_pid    = $opid
        process_name  = $pname
        creation_time = if ($_.CreationTime) {{ $_.CreationTime.ToUniversalTime().ToString('o') }} else {{ $null }}
    }}
}}
if ($null -eq $rows) {{ '[]' }} else {{ ConvertTo-Json -InputObject @($rows) -Compress -Depth 3 }}
"""

_PS_INTERFACE_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$rows = Get-NetAdapterStatistics -ErrorAction SilentlyContinue | ForEach-Object {
    [pscustomobject]@{
        name                     = [string]$_.Name
        received_bytes           = [int64]$_.ReceivedBytes
        sent_bytes               = [int64]$_.SentBytes
        received_unicast_packets = [int64]$_.ReceivedUnicastPackets
        sent_unicast_packets     = [int64]$_.SentUnicastPackets
        received_discarded       = [int64]$_.ReceivedDiscardedPackets
        outbound_discarded       = [int64]$_.OutboundDiscardedPackets
    }
}
if ($null -eq $rows) { '[]' } else { ConvertTo-Json -InputObject @($rows) -Compress -Depth 3 }
"""


def _run_powershell(
    script: str, timeout_seconds: float, powershell_path: str, what: str
) -> list[dict[str, Any]]:
    try:
        proc = subprocess.run(
            [powershell_path, "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except FileNotFoundError as exc:
        raise WindowsTelemetryUnavailable(
            f"PowerShell executable '{powershell_path}' not found; {what} is "
            "unavailable on this host."
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise WindowsTelemetryUnavailable(
            f"{what} timed out after {timeout_seconds}s"
        ) from exc

    if proc.returncode != 0:
        raise WindowsTelemetryUnavailable(
            f"{what} failed (exit {proc.returncode}): "
            f"{(proc.stderr or '').strip()[:400]}"
        )

    raw = (proc.stdout or "").strip()
    if not raw:
        return []
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise WindowsTelemetryUnavailable(
            f"{what} returned unparseable output: {raw[:200]!r}"
        ) from exc

    if isinstance(parsed, dict):
        return [parsed]
    if isinstance(parsed, list):
        return [r for r in parsed if isinstance(r, dict)]
    return []


def query_udp_endpoints(
    timeout_seconds: float = 20.0,
    powershell_path: str = "powershell",
    include_process_names: bool = True,
) -> list[dict[str, Any]]:
    """Query the live Windows UDP endpoint table. Read-only, unprivileged."""
    return _run_powershell(
        _PS_UDP_SCRIPT.format(
            include_process="true" if include_process_names else "false"
        ),
        timeout_seconds,
        powershell_path,
        "UDP endpoint query",
    )


def query_interface_statistics(
    timeout_seconds: float = 20.0,
    powershell_path: str = "powershell",
) -> list[dict[str, Any]]:
    """Query per-interface cumulative counters. Read-only, unprivileged."""
    return _run_powershell(
        _PS_INTERFACE_SCRIPT,
        timeout_seconds,
        powershell_path,
        "Interface statistics query",
    )


# ──────────────────────────────────────────────────────────────────
# UDP endpoint normalization (pure — testable on any platform)
# ──────────────────────────────────────────────────────────────────


def _parse_timestamp(raw: Any, warnings: list[str], flags: list[QualityFlag]):
    """
    Parse a creation time, rejecting the FILETIME epoch and far-future values.

    Identical policy to the TCP collector: an implausible timestamp is
    treated as absent, never as a real observation time, because one 1601
    value poisons every time-ordered calculation downstream.
    """
    if raw in (None, ""):
        return None
    try:
        parsed = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        warnings.append("unparseable_creation_time")
        flags.append(QualityFlag.TIMESTAMP_UNCERTAINTY)
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    parsed = parsed.astimezone(timezone.utc)

    now = datetime.now(timezone.utc)
    if parsed.year < MIN_PLAUSIBLE_YEAR:
        warnings.append("implausible_creation_time_before_2000")
        flags.append(QualityFlag.TIMESTAMP_UNCERTAINTY)
        return None
    if (parsed - now).total_seconds() > MAX_CLOCK_SKEW_SECONDS:
        warnings.append("implausible_creation_time_in_future")
        flags.append(QualityFlag.TIMESTAMP_UNCERTAINTY)
        return None
    return parsed


class WindowsUdpEndpointAdapter(BaseTelemetryAdapter):
    """
    Maps bound UDP sockets into canonical events.

    An event here records *a local socket binding*, not a conversation. The
    destination fields stay empty because no destination was observed, and
    the capability profile declares them not applicable so their absence is
    never scored as a data-quality defect.
    """

    def __init__(self, adapter_id: str = "windows_udp_endpoints"):
        super().__init__(adapter_id=adapter_id, adapter_type=UDP_SOURCE_TYPE)

    @staticmethod
    def build_event_id(record: dict[str, Any]) -> str:
        """
        Deterministic identity: the same bound socket observed on repeated
        polls yields the same id, so polling is idempotent at the storage
        layer and never inflates unique-event counts.
        """
        material = "|".join(
            str(record.get(k) or "")
            for k in ("local_address", "local_port", "owning_pid", "creation_time")
        )
        return hashlib.sha256(f"udp|{material}".encode()).hexdigest()

    def validate_and_normalize(
        self,
        raw_record: dict[str, Any],
        record_index: int,
        data_category: DataCategory = DataCategory.LIVE_TELEMETRY,
        polled_at: Optional[datetime] = None,
    ) -> ValidationResult:
        errors: list[str] = []
        warnings: list[str] = []
        flags: list[QualityFlag] = []
        raw_ref = f"windows_udp:{record_index}"

        local_address = str(raw_record.get("local_address") or "").strip()
        if not local_address:
            errors.append(f"Record {record_index}: missing local_address")
        else:
            # Strip the IPv6 zone index (fe80::1%47) before validation; the
            # scope id is a local interface detail, not part of the address.
            candidate = local_address.split("%", 1)[0]
            try:
                ipaddress.ip_address(candidate)
                local_address = candidate
            except ValueError:
                errors.append(
                    f"Record {record_index}: invalid local_address "
                    f"'{local_address}'"
                )

        local_port = raw_record.get("local_port")
        try:
            local_port = int(local_port)
            if not 0 <= local_port <= 65535:
                errors.append(f"Record {record_index}: local_port out of range")
                local_port = None
        except (TypeError, ValueError):
            errors.append(f"Record {record_index}: invalid local_port")
            local_port = None

        observed_at = _parse_timestamp(raw_record.get("creation_time"), warnings, flags)
        if observed_at is None:
            observed_at = polled_at or datetime.now(timezone.utc)
            if "unparseable_creation_time" not in warnings:
                warnings.append("creation_time_absent_using_poll_time")
                flags.append(QualityFlag.TIMESTAMP_UNCERTAINTY)

        # Process attribution travels in raw_reference, matching the TCP
        # collector. Name only — never the command line, which routinely
        # carries file paths, URLs and tokens this question does not need.
        pid = raw_record.get("owning_pid")
        process_name = str(raw_record.get("process_name") or "").strip()
        if not process_name:
            warnings.append("process_name_unavailable")
        ref_bits = ["windows:udp_endpoint"]
        if pid not in (None, ""):
            ref_bits.append(f"pid={pid}")
        if process_name:
            ref_bits.append(f"process={process_name}")
        raw_ref = ";".join(ref_bits)

        # Volume, duration and a peer are structurally absent here, not
        # missing by accident.
        flags.append(QualityFlag.SOURCE_LIMITED)

        if errors:
            self.record_failure(errors[0])
            return ValidationResult(
                is_valid=False, errors=errors, warnings=warnings, raw_reference=raw_ref
            )

        event = NormalizedEvent(
            event_id=self.build_event_id(raw_record),
            schema_version=SCHEMA_VERSION,
            source_id=self.adapter_id,
            data_category=data_category,
            observed_at=observed_at,
            event_type=EventType.UDP_ENDPOINT,
            src_ip=local_address,
            src_port=local_port,
            # No peer exists for a bound UDP socket. Left empty deliberately.
            dst_ip=None,
            dst_port=None,
            protocol="UDP",
            # Volume and duration are not measurable from an endpoint table.
            duration=None,
            packets=None,
            bytes_total=None,
            label=None,
            label_provenance=LabelProvenance.UNLABELED,
            quality_flags=flags,
            raw_reference=raw_ref,
        )
        self.record_success()
        return ValidationResult(
            is_valid=True, event=event, warnings=warnings, raw_reference=raw_ref
        )

    def normalize_batch(
        self,
        records: list[dict[str, Any]],
        data_category: DataCategory = DataCategory.LIVE_TELEMETRY,
        polled_at: Optional[datetime] = None,
    ) -> tuple[list[NormalizedEvent], list[str]]:
        """Normalize a poll, returning events and one reason per rejection."""
        events: list[NormalizedEvent] = []
        rejections: list[str] = []
        seen: set[str] = set()
        for index, record in enumerate(records):
            result = self.validate_and_normalize(
                record, index, data_category=data_category, polled_at=polled_at
            )
            if not result.is_valid or result.event is None:
                rejections.extend(result.errors)
                continue
            if result.event.event_id in seen:
                continue  # same socket reported twice in one snapshot
            seen.add(result.event.event_id)
            events.append(result.event)
        return events, rejections


# ──────────────────────────────────────────────────────────────────
# Interface counters — a different measurement type, kept apart
# ──────────────────────────────────────────────────────────────────


class InterfaceCounters(BaseModel):
    """Cumulative counters for one network interface."""

    name: str
    received_bytes: int
    sent_bytes: int
    received_unicast_packets: int
    sent_unicast_packets: int
    received_discarded: int = 0
    outbound_discarded: int = 0


class InterfaceDelta(BaseModel):
    """Change in one interface's counters between two observations."""

    name: str
    interval_seconds: float
    received_bytes: Optional[int] = None
    sent_bytes: Optional[int] = None
    received_packets: Optional[int] = None
    sent_packets: Optional[int] = None
    counter_reset_detected: bool = False
    note: Optional[str] = None


class InterfaceStatisticsSnapshot(BaseModel):
    """
    A reading of the host's interface counters.

    ``measurement_scope`` travels with the payload so a consumer cannot mistake
    these for per-flow metrics. They are not comparable with, and must never be
    summed alongside, the byte counts of an imported flow dataset.
    """

    observed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    measurement_scope: str = "interface_cumulative"
    measurement_unit: str = "bytes and packets, cumulative since adapter reset"
    attributable_to_flow: bool = False
    attributable_to_process: bool = False
    interfaces: list[InterfaceCounters] = Field(default_factory=list)
    deltas: list[InterfaceDelta] = Field(default_factory=list)
    notes: list[str] = Field(
        default_factory=lambda: [
            "Counters are per interface and cumulative; they cannot be attributed to a connection, process or destination.",
            "These are NOT flow metrics and are never written into normalized_events.",
            "A delta is reported only between two observations in the same process; the first reading has none.",
            "Loopback and virtual adapters are included as the OS reports them.",
        ]
    )


def parse_interface_counters(rows: list[dict[str, Any]]) -> list[InterfaceCounters]:
    """Parse raw rows, skipping any that are not usable rather than guessing."""
    parsed: list[InterfaceCounters] = []
    for row in rows:
        name = str(row.get("name") or "").strip()
        if not name:
            continue
        try:
            parsed.append(
                InterfaceCounters(
                    name=name,
                    received_bytes=int(row.get("received_bytes") or 0),
                    sent_bytes=int(row.get("sent_bytes") or 0),
                    received_unicast_packets=int(row.get("received_unicast_packets") or 0),
                    sent_unicast_packets=int(row.get("sent_unicast_packets") or 0),
                    received_discarded=int(row.get("received_discarded") or 0),
                    outbound_discarded=int(row.get("outbound_discarded") or 0),
                )
            )
        except (TypeError, ValueError):
            logger.warning("Skipping unparseable interface counter row for %r", name)
    return parsed


def compute_deltas(
    previous: Optional[InterfaceStatisticsSnapshot],
    current: list[InterfaceCounters],
    now: datetime,
) -> list[InterfaceDelta]:
    """
    Difference two readings.

    A counter that went **down** means the adapter reset (disable/enable,
    sleep, driver reload). The drop is reported as a reset with no delta
    rather than as a negative or a wrapped-around positive number, because
    neither would describe anything that happened on the wire.
    """
    if previous is None:
        return []

    before = {i.name: i for i in previous.interfaces}
    interval = (now - previous.observed_at).total_seconds()
    deltas: list[InterfaceDelta] = []

    for iface in current:
        prior = before.get(iface.name)
        if prior is None:
            deltas.append(
                InterfaceDelta(
                    name=iface.name,
                    interval_seconds=round(interval, 3),
                    note="Interface was not present in the previous reading; no delta.",
                )
            )
            continue

        reset = (
            iface.received_bytes < prior.received_bytes
            or iface.sent_bytes < prior.sent_bytes
            or iface.received_unicast_packets < prior.received_unicast_packets
            or iface.sent_unicast_packets < prior.sent_unicast_packets
        )
        if reset:
            deltas.append(
                InterfaceDelta(
                    name=iface.name,
                    interval_seconds=round(interval, 3),
                    counter_reset_detected=True,
                    note=(
                        "A counter decreased, so the adapter's counters were "
                        "reset between readings. No delta can be derived."
                    ),
                )
            )
            continue

        deltas.append(
            InterfaceDelta(
                name=iface.name,
                interval_seconds=round(interval, 3),
                received_bytes=iface.received_bytes - prior.received_bytes,
                sent_bytes=iface.sent_bytes - prior.sent_bytes,
                received_packets=iface.received_unicast_packets
                - prior.received_unicast_packets,
                sent_packets=iface.sent_unicast_packets - prior.sent_unicast_packets,
            )
        )
    return deltas


class InterfaceStatisticsProbe:
    """
    Holds the previous reading so a delta can be offered alongside the
    cumulative values. State lives in this process only; nothing is persisted,
    because these counters are not events.
    """

    def __init__(self, query_fn: Callable[[], list[dict[str, Any]]] = query_interface_statistics):
        self._query_fn = query_fn
        self._previous: Optional[InterfaceStatisticsSnapshot] = None

    def read(self, now: Optional[datetime] = None) -> InterfaceStatisticsSnapshot:
        now = now or datetime.now(timezone.utc)
        counters = parse_interface_counters(self._query_fn())
        snapshot = InterfaceStatisticsSnapshot(
            observed_at=now,
            interfaces=counters,
            deltas=compute_deltas(self._previous, counters, now),
        )
        self._previous = snapshot
        return snapshot
