"""
PraHari — Research Benchmark CSV Adapter

A strict importer for third-party labelled flow corpora (CICFlowMeter
output such as CSE-CIC-IDS2018, and formats shaped like it).

It is deliberately separate from ``csv_import.py``. That adapter is a
permissive, best-effort reader for ad-hoc files; this one refuses anything
it cannot establish, because a benchmark corpus is the evidential basis for
every forecasting claim the project makes. A silently mis-parsed column
there does not produce an obvious failure — it produces a plausible number.

What this adapter will not do
-----------------------------
* Guess between ``dd/mm/yyyy`` and ``mm/dd/yyyy``. An ambiguous date is
  rejected unless the operator states the format.
* Claim a timezone the source does not document.
* Convert units it has not been told the units of.
* Treat a repeated header row as an observation (and so never as an attack).
* Turn an invalid value into a missing value without recording why.
* Report forward-direction counts under a field documented as a total.

Nothing in this module downloads anything. It reads bytes the operator has
already placed on disk, and hashes them locally.
"""

from __future__ import annotations

import csv
import hashlib
import ipaddress
import logging
import math
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from io import StringIO
from typing import Any, Iterable, Optional

from app.schemas.events import (
    SCHEMA_VERSION,
    DataCategory,
    EventType,
    LabelProvenance,
    NormalizedEvent,
    QualityFlag,
)

logger = logging.getLogger(__name__)

ADAPTER_VERSION = "research_csv/1.0.0"

# ──────────────────────────────────────────────────────────────────
# Explicit policies
# ──────────────────────────────────────────────────────────────────


class TimestampFormat(str, Enum):
    """
    How a date column is to be read.

    ``AUTO`` resolves only unambiguous values. A date whose day and month
    could be swapped is REJECTED under AUTO rather than resolved by
    whichever pattern happens to be tried first.
    """

    AUTO = "auto"
    DAY_FIRST = "day_first"      # dd/mm/yyyy
    MONTH_FIRST = "month_first"  # mm/dd/yyyy
    ISO = "iso"                  # yyyy-mm-dd[ T]hh:mm:ss


class DurationUnit(str, Enum):
    """
    Unit of the source duration column.

    The canonical schema documents ``duration`` in **seconds**.
    CICFlowMeter's ``Flow Duration`` is **microseconds**, so it must be
    declared and converted. ``UNKNOWN`` means the column is not imported at
    all — an unconverted microsecond value is a 10^6x error that no
    downstream check would catch.
    """

    SECONDS = "seconds"
    MILLISECONDS = "milliseconds"
    MICROSECONDS = "microseconds"
    UNKNOWN = "unknown"


_DURATION_TO_SECONDS = {
    DurationUnit.SECONDS: 1.0,
    DurationUnit.MILLISECONDS: 1e-3,
    DurationUnit.MICROSECONDS: 1e-6,
}


@dataclass
class ResearchCsvPolicy:
    """Everything the operator must state before a corpus can be imported."""

    timestamp_format: TimestampFormat = TimestampFormat.AUTO
    # None means "the source does not document one". The value is recorded
    # as unknown and the events are flagged; it is never silently called UTC.
    source_timezone: Optional[str] = None
    duration_unit: DurationUnit = DurationUnit.UNKNOWN
    # CICFlowMeter reports forward and backward counts separately. When only
    # the forward column is present, the result is NOT a total.
    require_bidirectional_counts: bool = True
    max_records: int = 1_000_000

    def describe(self) -> dict[str, Any]:
        return {
            "timestamp_format": self.timestamp_format.value,
            "source_timezone": self.source_timezone or "unknown",
            "duration_unit": self.duration_unit.value,
            "require_bidirectional_counts": self.require_bidirectional_counts,
            "max_records": self.max_records,
        }


# ──────────────────────────────────────────────────────────────────
# Column mapping (CICFlowMeter-V3 shaped)
# ──────────────────────────────────────────────────────────────────

COLUMN_CANDIDATES: dict[str, tuple[str, ...]] = {
    "timestamp": ("Timestamp", "timestamp"),
    "src_ip": ("Src IP", "Source IP", "src_ip"),
    "dst_ip": ("Dst IP", "Destination IP", "dst_ip"),
    "src_port": ("Src Port", "Source Port", "src_port"),
    "dst_port": ("Dst Port", "Destination Port", "dst_port"),
    "protocol": ("Protocol", "protocol"),
    "duration": ("Flow Duration", "flow_duration"),
    "fwd_packets": ("Tot Fwd Pkts", "Total Fwd Packets", "tot_fwd_pkts"),
    "bwd_packets": ("Tot Bwd Pkts", "Total Backward Packets", "tot_bwd_pkts"),
    "fwd_bytes": ("TotLen Fwd Pkts", "Total Length of Fwd Packets", "totlen_fwd_pkts"),
    "bwd_bytes": ("TotLen Bwd Pkts", "Total Length of Bwd Packets", "totlen_bwd_pkts"),
    "label": ("Label", "label"),
}

PROTOCOL_NUMBERS = {"6": "TCP", "17": "UDP", "1": "ICMP", "0": "HOPOPT"}

# Textual non-finite spellings CICFlowMeter and pandas exports produce.
NON_FINITE_TOKENS = {
    "inf", "+inf", "-inf", "infinity", "+infinity", "-infinity",
    "nan", "-nan", "+nan",
}

_AMBIGUOUS_SLASH_DATE = re.compile(r"^\s*(\d{1,2})[/-](\d{1,2})[/-](\d{4})")


# ──────────────────────────────────────────────────────────────────
# Quality accounting
# ──────────────────────────────────────────────────────────────────


@dataclass
class ImportQuality:
    """
    Deterministic accounting for one import.

    ``rows_read`` must equal accepted + rejected + skipped_header +
    skipped_blank. A reconciliation that does not balance means rows went
    somewhere unrecorded, which is itself a finding.
    """

    rows_read: int = 0
    accepted: int = 0
    rejected: int = 0
    skipped_header_rows: int = 0
    skipped_blank_rows: int = 0
    # Rows whose RAW TEXT is byte-identical to an earlier row. A documented
    # CICFlowMeter artefact. Counted, never dropped.
    duplicate_rows_exact: int = 0
    # Rows whose canonical fields (time, 5-tuple, label) match an earlier
    # row. A superset of the above: a byte-identical row also matches
    # canonically. Two distinct flows can legitimately look like this, so
    # these are counted and kept rather than deduplicated.
    near_duplicate_flows: int = 0
    missing_values: dict[str, int] = field(default_factory=dict)
    malformed_values: dict[str, int] = field(default_factory=dict)
    invalid_negative_values: dict[str, int] = field(default_factory=dict)
    non_finite_values: dict[str, int] = field(default_factory=dict)
    rejection_reasons: dict[str, int] = field(default_factory=dict)
    truncated_at_max_records: bool = False
    warnings: list[str] = field(default_factory=list)

    def note(self, bucket: dict[str, int], key: str) -> None:
        bucket[key] = bucket.get(key, 0) + 1

    def reject(self, reason: str) -> None:
        self.rejected += 1
        self.note(self.rejection_reasons, reason)

    def reconciles(self) -> bool:
        return self.rows_read == (
            self.accepted
            + self.rejected
            + self.skipped_header_rows
            + self.skipped_blank_rows
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "rows_read": self.rows_read,
            "accepted": self.accepted,
            "rejected": self.rejected,
            "skipped_header_rows": self.skipped_header_rows,
            "skipped_blank_rows": self.skipped_blank_rows,
            "duplicate_rows_exact": self.duplicate_rows_exact,
            "near_duplicate_flows": self.near_duplicate_flows,
            "missing_values": dict(self.missing_values),
            "malformed_values": dict(self.malformed_values),
            "invalid_negative_values": dict(self.invalid_negative_values),
            "non_finite_values": dict(self.non_finite_values),
            "rejection_reasons": dict(self.rejection_reasons),
            "truncated_at_max_records": self.truncated_at_max_records,
            "reconciles": self.reconciles(),
            "warnings": list(self.warnings),
        }


class ResearchCsvError(ValueError):
    """The file or policy cannot support a defensible import."""


# ──────────────────────────────────────────────────────────────────
# Parsing primitives
# ──────────────────────────────────────────────────────────────────


def sha256_file(path: str) -> str:
    """SHA-256 of a local file, streamed. Never fetches anything."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def looks_like_header_row(row: dict[str, Any], header: Iterable[str]) -> bool:
    """
    True when a body row is a repeat of the header.

    CSE-CIC-IDS2018 CSVs are documented to contain embedded header lines.
    Normalising one yields ``label="Label"``, which the attack-label rule
    ("anything not benign") would score as an **attack** — injecting
    fabricated positives into the target.
    """
    header_set = {str(h).strip().lower() for h in header if h}
    if not header_set:
        return False
    values = [str(v).strip().lower() for v in row.values() if v is not None and str(v).strip()]
    if not values:
        return False
    matches = sum(1 for v in values if v in header_set)
    return matches >= max(2, int(len(values) * 0.6))


def _is_ambiguous_slash_date(value: str) -> bool:
    """dd/mm vs mm/dd cannot be told apart when both parts are 1..12."""
    match = _AMBIGUOUS_SLASH_DATE.match(value)
    if not match:
        return False
    first, second = int(match.group(1)), int(match.group(2))
    return 1 <= first <= 12 and 1 <= second <= 12


def parse_timestamp(
    value: Optional[str], policy: ResearchCsvPolicy
) -> tuple[Optional[datetime], Optional[str], list[str]]:
    """
    Parse a timestamp under an explicit policy.

    Returns ``(datetime, rejection_reason, warnings)``. The datetime carries
    UTC tzinfo for storage because the schema is timezone-aware, but when
    the source timezone is undocumented a warning records that the offset is
    an assumption, not a fact. The manifest repeats it.
    """
    warnings: list[str] = []
    if value is None or not str(value).strip():
        return None, "missing_timestamp", warnings

    raw = str(value).strip()

    if policy.timestamp_format is TimestampFormat.AUTO and _is_ambiguous_slash_date(raw):
        return (
            None,
            "ambiguous_date_format",
            ["Date could be read as dd/mm/yyyy or mm/dd/yyyy."],
        )

    if policy.timestamp_format is TimestampFormat.DAY_FIRST:
        formats = ("%d/%m/%Y %H:%M:%S", "%d/%m/%Y %H:%M", "%d-%m-%Y %H:%M:%S", "%d/%m/%Y")
    elif policy.timestamp_format is TimestampFormat.MONTH_FIRST:
        formats = ("%m/%d/%Y %H:%M:%S", "%m/%d/%Y %H:%M", "%m-%d-%Y %H:%M:%S", "%m/%d/%Y")
    elif policy.timestamp_format is TimestampFormat.ISO:
        formats = ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S.%f")
    else:
        formats = (
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%S.%f",
            "%d/%m/%Y %H:%M:%S",
        )

    parsed: Optional[datetime] = None
    for fmt in formats:
        try:
            parsed = datetime.strptime(raw, fmt)
            break
        except ValueError:
            continue

    if parsed is None:
        # ISO with an explicit offset is unambiguous and always acceptable.
        try:
            parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            return None, "unparseable_timestamp", warnings

    if parsed.tzinfo is not None:
        return parsed.astimezone(timezone.utc), None, warnings

    if policy.source_timezone:
        warnings.append(f"naive_timestamp_interpreted_as_{policy.source_timezone}")
    else:
        warnings.append("source_timezone_unknown_stored_as_utc")
    return parsed.replace(tzinfo=timezone.utc), None, warnings


def parse_numeric(
    raw: Optional[str],
    column: str,
    quality: ImportQuality,
    allow_negative: bool = False,
) -> tuple[Optional[float], Optional[str]]:
    """
    Parse one numeric cell under an explicit policy.

    Distinguishes four outcomes instead of collapsing them to ``None``:
    missing, malformed, non-finite, and invalid-negative. Each is counted
    against its column so the import summary says *which* columns were
    unusable rather than only that something was.
    """
    if raw is None or not str(raw).strip():
        quality.note(quality.missing_values, column)
        return None, None

    text = str(raw).strip()
    if text.lower() in NON_FINITE_TOKENS:
        # CICFlowMeter emits Infinity/NaN in rate columns when duration
        # approaches zero. A non-finite value must never reach a model or a
        # JSON response.
        quality.note(quality.non_finite_values, column)
        return None, None

    try:
        number = float(text)
    except (TypeError, ValueError):
        quality.note(quality.malformed_values, column)
        return None, f"malformed_{column}"

    if not math.isfinite(number):
        quality.note(quality.non_finite_values, column)
        return None, None

    if number < 0 and not allow_negative:
        # A negative packet or byte count is invalid, not absent. Recorded
        # distinctly so it cannot be mistaken for an unmeasured field.
        quality.note(quality.invalid_negative_values, column)
        return None, None

    return number, None


def deterministic_event_id(
    source_sha256: str, row_index: int, canonical_row: str
) -> str:
    """
    Stable identity for an imported row.

    Derived from the **source file's bytes**, the row's position in it, and
    the row's normalised content. Re-importing the same file therefore
    produces the same ids, so a repeat import inserts nothing new rather
    than silently duplicating the corpus.

    File+row identity is used rather than content alone on purpose: two
    genuinely distinct flows can have identical feature values, and
    collapsing them would delete real observations. The trade-off is that
    the *same* corpus re-released under a different filename, or re-exported
    with different byte content, is treated as a different dataset — which
    is the conservative direction.
    """
    material = f"{source_sha256}|{row_index}|{canonical_row}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _canonical_row(values: dict[str, Any]) -> str:
    return "|".join(f"{k}={values.get(k)}" for k in sorted(values))


def _find(row: dict[str, Any], keys: tuple[str, ...]) -> Optional[str]:
    lowered = {str(k).strip().lower(): v for k, v in row.items() if k is not None}
    for key in keys:
        if key in row and row[key] is not None:
            return str(row[key]).strip()
        value = lowered.get(key.strip().lower())
        if value is not None:
            return str(value).strip()
    return None


# ──────────────────────────────────────────────────────────────────
# Import
# ──────────────────────────────────────────────────────────────────


def import_research_csv(
    csv_text: str,
    source_id: str,
    source_sha256: str,
    policy: ResearchCsvPolicy,
    data_category: DataCategory = DataCategory.HISTORICAL_IMPORT,
) -> tuple[list[NormalizedEvent], ImportQuality]:
    """
    Normalize a benchmark CSV under an explicit policy.

    ``source_sha256`` is the hash of the exact file bytes, computed locally
    by the caller. It proves byte identity only — it says nothing about
    whether the labels are correct or the file is authentic.
    """
    reader = csv.DictReader(StringIO(csv_text))
    header = list(reader.fieldnames or [])
    if not header:
        raise ResearchCsvError("CSV has no header row; refusing to guess columns.")

    quality = ImportQuality()
    events: list[NormalizedEvent] = []
    seen_ids: set[str] = set()
    seen_content: dict[str, int] = {}
    # Byte-identical raw rows. Event identity is (file, row index, content)
    # by design — see ADR-037 — so two rows in one file can never collide on
    # identity, which left `duplicate_rows_exact` permanently zero for a
    # single-file import. The useful question for an operator auditing a
    # corpus is "did the same raw row text appear twice", which is a
    # documented CICFlowMeter artefact, so that is what it now counts.
    #
    # Nothing is dropped either way. Both counters report; neither filters.
    seen_raw_rows: set[str] = set()

    # Declare up front what the policy leaves unusable, so the operator sees
    # it in the summary rather than discovering a silently empty column.
    if policy.duration_unit is DurationUnit.UNKNOWN:
        quality.warnings.append(
            "duration_unit is 'unknown': the duration column is NOT imported. "
            "Declare the source unit (CICFlowMeter Flow Duration is microseconds)."
        )
    if not policy.source_timezone:
        quality.warnings.append(
            "source_timezone is unknown: naive timestamps are stored as UTC and "
            "flagged. Absolute times may be offset; relative ordering within one "
            "file is unaffected."
        )

    bwd_packets_present = _find({k: "" for k in header}, COLUMN_CANDIDATES["bwd_packets"]) is not None
    bwd_bytes_present = _find({k: "" for k in header}, COLUMN_CANDIDATES["bwd_bytes"]) is not None

    for index, row in enumerate(reader):
        if quality.rows_read >= policy.max_records:
            quality.truncated_at_max_records = True
            quality.warnings.append(
                f"Stopped at max_records={policy.max_records}; the file contains "
                "more rows. This import covers only its beginning."
            )
            break

        quality.rows_read += 1

        if not any(str(v).strip() for v in row.values() if v is not None):
            quality.skipped_blank_rows += 1
            continue

        if looks_like_header_row(row, header):
            quality.skipped_header_rows += 1
            continue

        rejection: Optional[str] = None
        warnings: list[str] = []
        flags: list[QualityFlag] = []

        observed_at, ts_reject, ts_warnings = parse_timestamp(
            _find(row, COLUMN_CANDIDATES["timestamp"]), policy
        )
        warnings.extend(ts_warnings)
        if ts_reject:
            quality.reject(ts_reject)
            continue
        if any("unknown" in w or "interpreted_as" in w for w in ts_warnings):
            flags.append(QualityFlag.TIMESTAMP_UNCERTAINTY)

        src_ip_raw = _find(row, COLUMN_CANDIDATES["src_ip"])
        dst_ip_raw = _find(row, COLUMN_CANDIDATES["dst_ip"])
        src_ip = dst_ip = None
        for raw_value, setter in ((src_ip_raw, "src"), (dst_ip_raw, "dst")):
            if not raw_value:
                rejection = rejection or f"missing_{setter}_ip"
                continue
            try:
                ipaddress.ip_address(raw_value)
            except ValueError:
                rejection = rejection or f"invalid_{setter}_ip"
                continue
            if setter == "src":
                src_ip = raw_value
            else:
                dst_ip = raw_value
        if rejection:
            quality.reject(rejection)
            continue

        ports: dict[str, Optional[int]] = {}
        for key in ("src_port", "dst_port"):
            value, reject = parse_numeric(_find(row, COLUMN_CANDIDATES[key]), key, quality)
            if reject:
                rejection = reject
                break
            if value is None:
                ports[key] = None
            elif 0 <= value <= 65535:
                ports[key] = int(value)
            else:
                rejection = f"{key}_out_of_range"
                break
        if rejection:
            quality.reject(rejection)
            continue

        protocol_raw = _find(row, COLUMN_CANDIDATES["protocol"])
        protocol = None
        if protocol_raw:
            protocol = PROTOCOL_NUMBERS.get(protocol_raw, protocol_raw.upper())

        # ── Duration: converted only under a declared unit ──
        duration_seconds: Optional[float] = None
        if policy.duration_unit is not DurationUnit.UNKNOWN:
            raw_duration, reject = parse_numeric(
                _find(row, COLUMN_CANDIDATES["duration"]), "duration", quality
            )
            if reject:
                quality.reject(reject)
                continue
            if raw_duration is not None:
                duration_seconds = raw_duration * _DURATION_TO_SECONDS[policy.duration_unit]

        # ── Packets and bytes: totals only when both directions exist ──
        fwd_packets, _ = parse_numeric(
            _find(row, COLUMN_CANDIDATES["fwd_packets"]), "fwd_packets", quality
        )
        bwd_packets, _ = parse_numeric(
            _find(row, COLUMN_CANDIDATES["bwd_packets"]), "bwd_packets", quality
        )
        fwd_bytes, _ = parse_numeric(
            _find(row, COLUMN_CANDIDATES["fwd_bytes"]), "fwd_bytes", quality
        )
        bwd_bytes, _ = parse_numeric(
            _find(row, COLUMN_CANDIDATES["bwd_bytes"]), "bwd_bytes", quality
        )

        packets_total = _combine_directions(
            fwd_packets, bwd_packets, bwd_packets_present, policy
        )
        bytes_total = _combine_directions(
            fwd_bytes, bwd_bytes, bwd_bytes_present, policy
        )
        if packets_total is None and fwd_packets is not None:
            flags.append(QualityFlag.SOURCE_LIMITED)

        label_raw = _find(row, COLUMN_CANDIDATES["label"])
        label = label_raw.strip() if label_raw else None
        provenance = (
            LabelProvenance.DATASET_GROUND_TRUTH if label else LabelProvenance.UNLABELED
        )

        canonical = _canonical_row(
            {
                "ts": observed_at.isoformat(),
                "src": f"{src_ip}:{ports.get('src_port')}",
                "dst": f"{dst_ip}:{ports.get('dst_port')}",
                "proto": protocol,
                "label": label,
            }
        )
        event_id = deterministic_event_id(source_sha256, index, canonical)

        if event_id in seen_ids:
            # Unreachable within one file (row index is unique), retained as
            # a guard in case a caller ever feeds concatenated input.
            continue
        seen_ids.add(event_id)

        raw_signature = "".join(
            "" if row.get(column) is None else str(row.get(column))
            for column in header
        )
        if raw_signature in seen_raw_rows:
            quality.duplicate_rows_exact += 1
        else:
            seen_raw_rows.add(raw_signature)

        if canonical in seen_content:
            # Same 5-tuple, time and label at a different row position. These
            # may be genuinely distinct flows, so they are KEPT and counted —
            # dropping them would delete real observations. A row that is
            # byte-identical is already counted above, so this counts only
            # the looser case: the canonical fields agree while the full row
            # differs (an unmapped column changed).
            quality.near_duplicate_flows += 1
        else:
            seen_content[canonical] = index

        events.append(
            NormalizedEvent(
                event_id=event_id,
                schema_version=SCHEMA_VERSION,
                source_id=source_id,
                data_category=data_category,
                observed_at=observed_at,
                event_type=EventType.NETWORK_FLOW,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=ports.get("src_port"),
                dst_port=ports.get("dst_port"),
                protocol=protocol,
                duration=duration_seconds,
                packets=int(packets_total) if packets_total is not None else None,
                bytes_total=int(bytes_total) if bytes_total is not None else None,
                label=label,
                label_provenance=provenance,
                quality_flags=flags,
                raw_reference=f"research_csv:{source_sha256[:16]}:row:{index}",
            )
        )
        quality.accepted += 1

    return events, quality


def _combine_directions(
    forward: Optional[float],
    backward: Optional[float],
    backward_column_present: bool,
    policy: ResearchCsvPolicy,
) -> Optional[float]:
    """
    Produce a bidirectional total, or nothing.

    The canonical field is documented as a total. Returning a forward-only
    count under that name misstates the measurement, so when the backward
    column is absent and the policy requires bidirectional counts, the field
    is left empty rather than half-filled.
    """
    if forward is None and backward is None:
        return None
    if backward_column_present:
        # A present-but-empty backward cell is treated as unmeasured, not as
        # a genuine zero; a partial sum would be wrong in the same way.
        if forward is None or backward is None:
            return None
        return forward + backward
    if policy.require_bidirectional_counts:
        return None
    return forward
