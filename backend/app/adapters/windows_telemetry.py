"""
PraHari — Windows Connection-Table Telemetry Adapter & Collector

Collects GENUINE network telemetry from the local Windows host by polling the
operating system's TCP connection table (``Get-NetTCPConnection``).

Visibility boundaries (important — do not overstate this source)
---------------------------------------------------------------
This is **connection metadata**, not packet capture and not flow accounting.
The Windows connection table exposes, per connection:

  * the 5-tuple (local address/port, remote address/port, protocol)
  * the TCP state (Established, TimeWait, ...)
  * the owning process ID
  * the connection creation time

It does **not** expose byte counts, packet counts, completed-flow duration,
application-layer protocol, or payload. Those fields are therefore left as
``None`` and flagged ``MISSING_FIELD``; the adapter never invents them.

Because collection is **snapshot polling**, connections that open and close
entirely between two polls are never observed. This is an inherent visibility
gap of this source, reported by the collector rather than hidden.

UDP is intentionally not collected: Windows exposes only local UDP endpoint
binds (``Get-NetUDPEndpoint``) with no remote peer, so no meaningful
source→destination record can be constructed from it.

Requires no administrator rights, no driver, no promiscuous mode, and no
third-party dependency.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import subprocess
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Optional

from app.adapters.base import BaseTelemetryAdapter
from app.schemas.events import (
    SCHEMA_VERSION,
    DataCategory,
    EventType,
    ImportSummary,
    LabelProvenance,
    NormalizedEvent,
    QualityFlag,
    ValidationResult,
)

logger = logging.getLogger(__name__)

WINDOWS_SOURCE_TYPE = "windows_connection_table"

# TCP states worth collecting: states that imply an actual peer association.
# 'Listen' and 'Bound' sockets have no remote endpoint, so they are excluded.
DEFAULT_TCP_STATES = (
    "Established",
    "SynSent",
    "SynReceived",
    "FinWait1",
    "FinWait2",
    "CloseWait",
    "Closing",
    "LastAck",
    "TimeWait",
)

# PowerShell emits one JSON object per connection. Timestamps are forced to
# round-trip ISO-8601 UTC ('o') so host locale settings cannot corrupt them.
_PS_COLLECT_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$states = @({states})

# Owning-process NAMES are resolved in the same pass. Only the name is taken:
# never the command line, arguments or module paths, which routinely contain
# file paths, URLs and tokens that this security question does not need.
$procNames = @{{}}
if (${include_process}) {{
    Get-Process -ErrorAction SilentlyContinue | ForEach-Object {{
        $procNames[[int]$_.Id] = [string]$_.ProcessName
    }}
}}

$rows = Get-NetTCPConnection -ErrorAction SilentlyContinue |
    Where-Object {{ $states -contains [string]$_.State }} |
    ForEach-Object {{
        $opid = [int]$_.OwningProcess
        $pname = $null
        if ($procNames.ContainsKey($opid)) {{ $pname = $procNames[$opid] }}
        [pscustomobject]@{{
            protocol       = 'TCP'
            local_address  = [string]$_.LocalAddress
            local_port     = [int]$_.LocalPort
            remote_address = [string]$_.RemoteAddress
            remote_port    = [int]$_.RemotePort
            state          = [string]$_.State
            owning_pid     = $opid
            process_name   = $pname
            creation_time  = if ($_.CreationTime) {{ $_.CreationTime.ToUniversalTime().ToString('o') }} else {{ $null }}
        }}
    }}
if ($null -eq $rows) {{ '[]' }} else {{ ConvertTo-Json -InputObject @($rows) -Compress -Depth 3 }}
"""


# Windows reports an unset CreationTime as the FILETIME epoch (1601-01-01).
# Accepting that as a real event time silently corrupts every time-ordered
# calculation downstream — observation windows, rate features, temporal
# splits — so timestamps outside a plausible range are treated as absent.
MIN_PLAUSIBLE_YEAR = 2000
MAX_CLOCK_SKEW_SECONDS = 3600.0


class WindowsTelemetryUnavailable(RuntimeError):
    """Raised when the Windows connection table cannot be queried."""


def _is_loopback(addr: str) -> bool:
    try:
        return ipaddress.ip_address(addr).is_loopback
    except ValueError:
        return False


def _is_unspecified(addr: str) -> bool:
    """0.0.0.0 / :: — a wildcard bind, not a real peer."""
    try:
        return ipaddress.ip_address(addr).is_unspecified
    except ValueError:
        return False


# ──────────────────────────────────────────────────────────────────
# Collection (operating-system facing)
# ──────────────────────────────────────────────────────────────────


def query_windows_connections(
    states: tuple[str, ...] = DEFAULT_TCP_STATES,
    timeout_seconds: float = 20.0,
    powershell_path: str = "powershell",
    include_process_names: bool = True,
) -> list[dict[str, Any]]:
    """
    Query the live Windows TCP connection table.

    Returns raw connection dictionaries exactly as reported by the OS.
    Raises WindowsTelemetryUnavailable if the table cannot be read.

    ``include_process_names`` also resolves each connection's owning process
    name. Processes owned by other users are not visible without elevation;
    their names simply come back absent, which is reported rather than guessed.
    """
    state_literal = ",".join(f"'{s}'" for s in states)
    script = _PS_COLLECT_SCRIPT.format(
        states=state_literal,
        include_process="true" if include_process_names else "false",
    )

    try:
        proc = subprocess.run(
            [
                powershell_path,
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                script,
            ],
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            # Never inherit a console window when launched from a GUI context.
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except FileNotFoundError as exc:
        raise WindowsTelemetryUnavailable(
            f"PowerShell executable '{powershell_path}' not found; "
            "Windows connection-table collection is unavailable on this host."
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise WindowsTelemetryUnavailable(
            f"Connection-table query timed out after {timeout_seconds}s"
        ) from exc

    if proc.returncode != 0:
        raise WindowsTelemetryUnavailable(
            f"Connection-table query failed (exit {proc.returncode}): "
            f"{(proc.stderr or '').strip()[:400]}"
        )

    raw = (proc.stdout or "").strip()
    if not raw:
        return []

    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise WindowsTelemetryUnavailable(
            f"Connection-table query returned unparseable output: {raw[:200]!r}"
        ) from exc

    if isinstance(parsed, dict):  # single connection — PowerShell unwraps arrays of 1
        return [parsed]
    if isinstance(parsed, list):
        return [r for r in parsed if isinstance(r, dict)]
    return []


# ──────────────────────────────────────────────────────────────────
# Normalization (pure — unit-testable on any platform)
# ──────────────────────────────────────────────────────────────────


class WindowsConnectionAdapter(BaseTelemetryAdapter):
    """
    Maps raw Windows connection-table records into canonical NormalizedEvents.

    Event identity is **deterministic**: the same OS connection observed across
    many polls always produces the same ``event_id``, so repeated polling is
    idempotent at the storage layer and never inflates unique event counts.
    """

    def __init__(
        self,
        adapter_id: str = "windows_local_host",
        include_loopback: bool = False,
    ):
        super().__init__(adapter_id=adapter_id, adapter_type=WINDOWS_SOURCE_TYPE)
        self.include_loopback = include_loopback
        # Observations suppressed because the identical connection was already
        # normalized in an earlier poll. Tracked separately from rejections so
        # ingestion accounting stays truthful.
        self.duplicates_suppressed = 0
        # Records deliberately excluded by collector configuration. These are
        # NOT rejections: nothing is wrong with them, they are simply out of
        # scope. Counting them as rejected would overstate data-quality
        # failures and make a healthy collector look broken.
        self.filtered_by_policy = 0
        self._seen_fingerprints: set[str] = set()
        self._last_batch_fingerprints: list[str] = []

    def is_excluded_by_policy(self, record: dict[str, Any]) -> Optional[str]:
        """
        Return a reason if this record is out of collection scope, else None.

        Scope decisions are kept separate from validation so that accepted,
        rejected and filtered counts each mean exactly one thing.
        """
        if not self.include_loopback:
            src = str(record.get("local_address") or "").strip()
            dst = str(record.get("remote_address") or "").strip()
            if src and dst and _is_loopback(src) and _is_loopback(dst):
                return "loopback_only_connection_out_of_scope"
        return None

    # ---- identity -------------------------------------------------

    def fingerprint(self, record: dict[str, Any]) -> str:
        """
        Stable identity for one OS connection.

        Includes creation_time so that a *new* connection reusing an ephemeral
        port is treated as a distinct event rather than a duplicate.
        """
        parts = [
            self.adapter_id,
            str(record.get("protocol", "")).upper(),
            str(record.get("local_address", "")),
            str(record.get("local_port", "")),
            str(record.get("remote_address", "")),
            str(record.get("remote_port", "")),
            str(record.get("owning_pid", "")),
            str(record.get("creation_time", "")),
        ]
        return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()

    def event_id_for(self, record: dict[str, Any]) -> str:
        """Deterministic event_id derived from the connection fingerprint."""
        fp = self.fingerprint(record)
        # Format as a UUID-shaped string for consistency with other adapters.
        return f"{fp[0:8]}-{fp[8:12]}-{fp[12:16]}-{fp[16:20]}-{fp[20:32]}"

    # ---- normalization --------------------------------------------

    def validate_and_normalize(
        self,
        raw_record: dict[str, Any],
        record_index: int,
        data_category: DataCategory = DataCategory.LIVE_TELEMETRY,
    ) -> ValidationResult:
        errors: list[str] = []
        warnings: list[str] = []
        quality_flags: list[QualityFlag] = []
        raw_ref = f"windows:tcp:{record_index}"

        # --- endpoints (required) ---
        src_raw = str(raw_record.get("local_address") or "").strip()
        dst_raw = str(raw_record.get("remote_address") or "").strip()

        src_ip: Optional[str] = None
        dst_ip: Optional[str] = None

        if not src_raw:
            errors.append(f"Record {record_index}: missing local_address")
        else:
            try:
                src_ip = str(ipaddress.ip_address(src_raw))
            except ValueError:
                errors.append(f"Record {record_index}: invalid local_address: '{src_raw}'")

        if not dst_raw:
            errors.append(f"Record {record_index}: missing remote_address")
        elif _is_unspecified(dst_raw):
            # A wildcard remote address means the socket has no peer; such a
            # record carries no destination and must not be stored as a flow.
            errors.append(
                f"Record {record_index}: unspecified remote_address "
                f"'{dst_raw}' (socket has no peer)"
            )
        else:
            try:
                dst_ip = str(ipaddress.ip_address(dst_raw))
            except ValueError:
                errors.append(f"Record {record_index}: invalid remote_address: '{dst_raw}'")

        # --- ports (required for a TCP connection) ---
        src_port = self._coerce_port(raw_record.get("local_port"), "local_port", record_index, errors)
        dst_port = self._coerce_port(raw_record.get("remote_port"), "remote_port", record_index, errors)

        # --- protocol ---
        protocol = str(raw_record.get("protocol") or "TCP").strip().upper() or "TCP"

        # --- timestamp: prefer genuine OS connection creation time ---
        observed_at: Optional[datetime] = None
        ctime_raw = raw_record.get("creation_time")
        if ctime_raw:
            observed_at = self._parse_iso_utc(ctime_raw)
            if observed_at is None:
                warnings.append("unparseable_creation_time")
                quality_flags.append(QualityFlag.TIMESTAMP_UNCERTAINTY)
            elif not self._is_plausible(observed_at):
                # Typically the FILETIME epoch (1601-01-01) on sockets with
                # no recorded start, such as PID 0 TimeWait entries.
                warnings.append("implausible_creation_time_discarded")
                quality_flags.append(QualityFlag.INVALID_VALUE)
                observed_at = None

        if observed_at is None:
            # Fall back to the observation (poll) time, explicitly flagged:
            # this is when PraHari saw the connection, not when it started.
            fallback = raw_record.get("observed_at")
            observed_at = self._parse_iso_utc(fallback) if fallback else None
            if observed_at is None:
                observed_at = datetime.now(timezone.utc)
            if QualityFlag.TIMESTAMP_UNCERTAINTY not in quality_flags:
                quality_flags.append(QualityFlag.TIMESTAMP_UNCERTAINTY)
            warnings.append("creation_time_unavailable_used_poll_time")

        if errors:
            self.record_failure(errors[0])
            return ValidationResult(
                is_valid=False,
                errors=errors,
                warnings=warnings,
                raw_reference=raw_ref,
            )

        # --- fields this source genuinely cannot provide ---
        # bytes_total / packets / duration are NOT available from the Windows
        # connection table. They stay None and the record carries
        # SOURCE_LIMITED, marking a known limit of the sensor.
        #
        # MISSING_FIELD is deliberately NOT used: that flag means "a field
        # this source can provide was absent", i.e. a data defect. Applying
        # it to a field the source can never provide would mark every record
        # defective and hide genuine gaps.
        quality_flags.append(QualityFlag.SOURCE_LIMITED)

        state = str(raw_record.get("state") or "").strip()
        pid = raw_record.get("owning_pid")
        process_name = str(raw_record.get("process_name") or "").strip()
        ref_bits = ["windows:tcp"]
        if state:
            ref_bits.append(f"state={state}")
        if pid not in (None, ""):
            ref_bits.append(f"pid={pid}")
        if process_name:
            # Name only — never the command line.
            ref_bits.append(f"process={process_name}")
        raw_reference = ";".join(ref_bits)

        event = NormalizedEvent(
            event_id=self.event_id_for(raw_record),
            schema_version=SCHEMA_VERSION,
            source_id=self.adapter_id,
            data_category=data_category,
            observed_at=observed_at,
            # CONNECTION, not NETWORK_FLOW: this is connection metadata and
            # carries no flow accounting.
            event_type=EventType.CONNECTION,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            duration=None,
            packets=None,
            bytes_total=None,
            # No ground truth exists for locally observed traffic. PraHari does
            # not invent attack labels for it.
            label=None,
            label_provenance=LabelProvenance.UNLABELED,
            quality_flags=quality_flags,
            raw_reference=raw_reference,
        )

        self.record_success()
        return ValidationResult(
            is_valid=True,
            event=event,
            warnings=warnings,
            raw_reference=raw_ref,
        )

    # ---- batch normalization --------------------------------------

    def normalize_batch(
        self,
        records: list[dict[str, Any]],
        data_category: DataCategory = DataCategory.LIVE_TELEMETRY,
        poll_time: Optional[datetime] = None,
    ) -> tuple[list[NormalizedEvent], ImportSummary]:
        """
        Normalize one poll's worth of connection records.

        Connections already seen in a previous poll are suppressed here (not
        counted as accepted and not counted as rejected) so that per-poll
        accounting reflects genuinely new observations.
        """
        summary = ImportSummary(
            source_id=self.adapter_id,
            source_file="<windows_connection_table>",
            data_category=data_category,
        )
        events: list[NormalizedEvent] = []
        rejection_reasons: dict[str, int] = {}
        warnings_count = 0
        duplicates = 0
        filtered = 0
        poll_iso = (poll_time or datetime.now(timezone.utc)).isoformat()
        self._last_batch_fingerprints = []

        for idx, record in enumerate(records, start=1):
            if not isinstance(record, dict):
                rejection_reasons["non_object_record"] = (
                    rejection_reasons.get("non_object_record", 0) + 1
                )
                continue

            record.setdefault("observed_at", poll_iso)

            # Out-of-scope records are filtered before validation so they are
            # never mistaken for malformed data.
            if self.is_excluded_by_policy(record) is not None:
                filtered += 1
                continue

            fp = self.fingerprint(record)
            if fp in self._seen_fingerprints:
                duplicates += 1
                continue

            result = self.validate_and_normalize(record, idx, data_category)
            if result.is_valid and result.event:
                self._seen_fingerprints.add(fp)
                self._last_batch_fingerprints.append(fp)
                events.append(result.event)
                if result.warnings:
                    warnings_count += 1
            else:
                for err in result.errors:
                    reason = err.split(":", 1)[1].strip() if ":" in err else err
                    reason = reason.split(":")[0].strip()[:80] or "unspecified"
                    rejection_reasons[reason] = rejection_reasons.get(reason, 0) + 1

        self.duplicates_suppressed += duplicates
        self.filtered_by_policy += filtered

        summary.total_records = len(records)
        summary.accepted_records = len(events)
        # Duplicates and policy-filtered records are neither accepted nor
        # rejected: one is a repeat observation of a connection already
        # recorded, the other is simply out of collection scope. Only
        # genuinely unusable records count as rejected.
        summary.rejected_records = len(records) - len(events) - duplicates - filtered
        summary.warnings_count = warnings_count
        summary.rejection_reasons = dict(rejection_reasons)
        if duplicates:
            summary.rejection_reasons["_duplicates_suppressed"] = duplicates
        if filtered:
            summary.rejection_reasons["_filtered_by_policy"] = filtered
        summary.completed_at = datetime.now(timezone.utc)
        return events, summary

    def forget_last_batch(self) -> None:
        """
        Un-mark the connections first seen in the latest batch.

        For a caller whose write of that batch failed: those connections
        were never stored, so the next poll must observe them as new rather
        than suppress them as repeats (ADR-077).
        """
        self._seen_fingerprints.difference_update(self._last_batch_fingerprints)
        self._last_batch_fingerprints = []

    def prune_fingerprint_cache(self, max_entries: int = 50_000) -> None:
        """
        Bound in-memory dedup state.

        Clearing the cache can only cause an already-stored connection to be
        re-normalized; storage keys on the deterministic event_id, so no
        duplicate row results.
        """
        if len(self._seen_fingerprints) > max_entries:
            self._seen_fingerprints.clear()

    # ---- helpers ---------------------------------------------------

    @staticmethod
    def _coerce_port(
        value: Any,
        field: str,
        record_index: int,
        errors: list[str],
    ) -> Optional[int]:
        if value is None or value == "":
            errors.append(f"Record {record_index}: missing {field}")
            return None
        try:
            port = int(value)
        except (TypeError, ValueError):
            errors.append(f"Record {record_index}: invalid {field}: '{value}'")
            return None
        if not (0 <= port <= 65535):
            errors.append(f"Record {record_index}: {field} out of range: {port}")
            return None
        return port

    @staticmethod
    def _is_plausible(dt: datetime) -> bool:
        """
        Reject timestamps that cannot describe an observed connection.

        Guards against the FILETIME epoch and against clocks reporting a
        start time in the future.
        """
        if dt.year < MIN_PLAUSIBLE_YEAR:
            return False
        now = datetime.now(timezone.utc)
        return dt <= now + timedelta(seconds=MAX_CLOCK_SKEW_SECONDS)

    @staticmethod
    def _parse_iso_utc(value: Any) -> Optional[datetime]:
        """Parse an ISO-8601 timestamp into an aware UTC datetime."""
        if isinstance(value, datetime):
            return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        if not isinstance(value, str) or not value.strip():
            return None
        text = value.strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        # .NET 'o' format emits 7 fractional digits; fromisoformat accepts at
        # most 6 before Python 3.11, so truncate defensively.
        if "." in text:
            head, _, tail = text.partition(".")
            digits = ""
            rest = ""
            for i, ch in enumerate(tail):
                if ch.isdigit():
                    digits += ch
                else:
                    rest = tail[i:]
                    break
            text = f"{head}.{digits[:6]}{rest}"
        try:
            dt = datetime.fromisoformat(text)
        except ValueError:
            return None
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
