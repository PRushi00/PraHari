"""
PraHari — CSV Import Adapter

Reads historical CSV files (e.g., CIC-IDS2018 format), validates each
row, and normalizes valid records into the canonical NormalizedEvent
schema. Invalid records are rejected with explicit reasons.

This is a file/replay adapter — it does NOT collect live telemetry.
"""

from __future__ import annotations

import csv
import ipaddress
import math
import re
import logging
import uuid
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
from typing import Optional

from app.schemas.events import (
    SCHEMA_VERSION,
    DataCategory,
    EventType,
    LabelProvenance,
    NormalizedEvent,
    QualityFlag,
    ValidationResult,
    ImportSummary,
)

logger = logging.getLogger(__name__)

_AMBIGUOUS_SLASH_DATE = re.compile(r"^\s*(\d{1,2})[/-](\d{1,2})[/-](\d{4})")

# ──────────────────────────────────────────────────────────────────
# Known field mappings for CIC-IDS2018 CSV format
# ──────────────────────────────────────────────────────────────────

CIC_FIELD_MAP = {
    "src_ip": ["Src IP", "src_ip", "Source IP"],
    "dst_ip": ["Dst IP", "dst_ip", "Destination IP"],
    "src_port": ["Src Port", "src_port", "Source Port"],
    "dst_port": ["Dst Port", "dst_port", "Destination Port"],
    "protocol": ["Protocol", "protocol"],
    "timestamp": ["Timestamp", "timestamp", "Flow Start", "observed_at"],
    "duration": ["Flow Duration", "duration", "Duration"],
    "packets": ["Tot Fwd Pkts", "Total Fwd Packets", "packets", "Fwd Packets"],
    "bytes": ["TotLen Fwd Pkts", "Total Length of Fwd Packets", "bytes_total", "Fwd Bytes"],
    "label": ["Label", "label"],
}

PROTOCOL_MAP = {
    "6": "TCP",
    "17": "UDP",
    "1": "ICMP",
    "0": "HOPOPT",
    "tcp": "TCP",
    "udp": "UDP",
    "icmp": "ICMP",
}


def _find_field(row: dict, candidates: list[str]) -> Optional[str]:
    """Find a value from a row using multiple candidate field names."""
    for name in candidates:
        # Try exact match
        if name in row:
            return row[name].strip() if isinstance(row[name], str) else str(row[name])
        # Try case-insensitive match
        for key in row:
            if key.strip().lower() == name.strip().lower():
                val = row[key]
                return val.strip() if isinstance(val, str) else str(val)
    return None


def _parse_timestamp(value: Optional[str]) -> tuple[Optional[datetime], list[str]]:
    """Parse a timestamp string, returning (datetime, warnings)."""
    warnings = []
    if not value:
        return None, ["missing_timestamp"]

    # A slash date whose first two components are both 1..12 cannot be read
    # without knowing the convention: 02/03/2018 is 2 March or 3 February.
    # Trying day-first then month-first "succeeds" on the first pattern and
    # silently reorders the dataset — and chronological order is what every
    # window, split and purge depends on. Such a value is rejected here; the
    # research importer (adapters/research_csv.py) takes an explicit format
    # for corpora where the convention is known.
    ambiguous = _AMBIGUOUS_SLASH_DATE.match(value.strip())
    if ambiguous:
        first, second = int(ambiguous.group(1)), int(ambiguous.group(2))
        if 1 <= first <= 12 and 1 <= second <= 12:
            return None, ["ambiguous_date_format"]

    formats = [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%d/%m/%Y %H:%M:%S",
        "%d/%m/%Y %H:%M",
        "%m/%d/%Y %H:%M",
        "%m/%d/%Y %H:%M:%S",
    ]

    for fmt in formats:
        try:
            dt = datetime.strptime(value.strip(), fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
                warnings.append("assumed_utc")
            return dt, warnings
        except ValueError:
            continue

    # Try ISO format as fallback
    try:
        dt = datetime.fromisoformat(value.strip())
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
            warnings.append("assumed_utc")
        return dt, warnings
    except ValueError:
        return None, ["unparseable_timestamp"]


def _validate_ip(value: Optional[str]) -> tuple[Optional[str], list[str]]:
    """Validate an IP address string."""
    if not value:
        return None, []
    try:
        ip = ipaddress.ip_address(value.strip())
        return str(ip), []
    except ValueError:
        return None, [f"invalid_ip:{value}"]


def _safe_int(value: Optional[str]) -> Optional[int]:
    """Safely convert to int, returning None on failure."""
    if value is None:
        return None
    try:
        return int(float(value.strip()))
    except (ValueError, TypeError):
        return None


def _safe_float(value: Optional[str]) -> Optional[float]:
    """
    Convert to a non-negative float, or None.

    Returns None for missing, malformed, non-finite and negative input
    alike. Callers that need to tell those apart should use
    ``_safe_float_detailed``; this wrapper is kept for existing callers.
    """
    parsed, _ = _safe_float_detailed(value)
    return parsed


def _safe_float_detailed(value: Optional[str]) -> tuple[Optional[float], Optional[str]]:
    """
    Convert to a non-negative float, reporting WHY when it fails.

    "Absent", "unparseable", "not finite" and "negative where a count is
    required" are four different facts about the data. Collapsing them into
    a bare None loses the only signal that would tell an operator their file
    is malformed rather than merely sparse.
    """
    if value is None:
        return None, None
    text = str(value).strip()
    if not text:
        return None, None
    if text.lower() in ("nan", "inf", "+inf", "-inf", "infinity", "+infinity", "-infinity"):
        return None, "non_finite_value"
    try:
        number = float(text)
    except (ValueError, TypeError):
        return None, "malformed_number"
    if not math.isfinite(number):
        return None, "non_finite_value"
    if number < 0:
        return None, "invalid_negative_value"
    return number, None


def validate_and_normalize_row(
    row: dict,
    row_index: int,
    source_id: str,
    data_category: DataCategory = DataCategory.HISTORICAL_IMPORT,
) -> ValidationResult:
    """
    Validate a single CSV row and normalize it into a NormalizedEvent.

    Returns a ValidationResult containing either a valid event or
    a list of errors explaining why the row was rejected.
    """
    errors: list[str] = []
    warnings: list[str] = []
    quality_flags: list[QualityFlag] = []
    raw_ref = f"csv:row:{row_index}"

    # --- Timestamp (required) ---
    ts_raw = _find_field(row, CIC_FIELD_MAP["timestamp"])
    observed_at, ts_warnings = _parse_timestamp(ts_raw)
    warnings.extend(ts_warnings)

    if observed_at is None:
        errors.append(f"Row {row_index}: invalid or missing timestamp: '{ts_raw}'")
        return ValidationResult(is_valid=False, errors=errors, raw_reference=raw_ref)

    if "assumed_utc" in ts_warnings:
        quality_flags.append(QualityFlag.TIMESTAMP_UNCERTAINTY)

    # --- IP addresses (both required for network flow) ---
    src_ip_raw = _find_field(row, CIC_FIELD_MAP["src_ip"])
    src_ip, src_ip_warns = _validate_ip(src_ip_raw)
    if not src_ip:
        errors.append(f"Row {row_index}: missing or invalid src_ip: '{src_ip_raw or ''}'")

    dst_ip_raw = _find_field(row, CIC_FIELD_MAP["dst_ip"])
    dst_ip, dst_ip_warns = _validate_ip(dst_ip_raw)
    if not dst_ip:
        errors.append(f"Row {row_index}: missing or invalid dst_ip: '{dst_ip_raw or ''}'")


    # --- Ports ---
    src_port_raw = _find_field(row, CIC_FIELD_MAP["src_port"])
    src_port = None
    if src_port_raw is not None and src_port_raw != "":
        src_port = _safe_int(src_port_raw)
        if src_port is None or src_port < 0 or src_port > 65535:
            errors.append(f"Row {row_index}: invalid src_port: '{src_port_raw}'")

    dst_port_raw = _find_field(row, CIC_FIELD_MAP["dst_port"])
    dst_port = None
    if dst_port_raw is not None and dst_port_raw != "":
        dst_port = _safe_int(dst_port_raw)
        if dst_port is None or dst_port < 0 or dst_port > 65535:
            errors.append(f"Row {row_index}: invalid dst_port: '{dst_port_raw}'")

    # --- Protocol ---
    protocol_raw = _find_field(row, CIC_FIELD_MAP["protocol"])
    protocol = None
    if protocol_raw:
        clean_proto = protocol_raw.strip().lower()
        if clean_proto in PROTOCOL_MAP:
            protocol = PROTOCOL_MAP[clean_proto]
        elif clean_proto.isdigit() and int(clean_proto) > 255:
            errors.append(f"Row {row_index}: invalid protocol number: '{protocol_raw}'")
        else:
            protocol = protocol_raw.strip().upper()

    if errors:
        return ValidationResult(
            is_valid=False,
            errors=errors,
            warnings=warnings,
            raw_reference=raw_ref,
        )


    # --- Flow metrics ---
    duration, duration_issue = _safe_float_detailed(
        _find_field(row, CIC_FIELD_MAP["duration"])
    )
    if duration_issue:
        warnings.append(f"duration:{duration_issue}")
        quality_flags.append(QualityFlag.INVALID_VALUE)
    packets = _safe_int(_find_field(row, CIC_FIELD_MAP["packets"]))
    bytes_total = _safe_int(_find_field(row, CIC_FIELD_MAP["bytes"]))

    # --- Label ---
    label_raw = _find_field(row, CIC_FIELD_MAP["label"])
    label = label_raw.strip() if label_raw else None
    label_provenance = LabelProvenance.DATASET_GROUND_TRUTH if label else LabelProvenance.UNLABELED

    # --- Track missing optional fields ---
    missing = []
    if not src_ip:
        missing.append("src_ip")
    if not dst_ip:
        missing.append("dst_ip")
    if protocol is None:
        missing.append("protocol")
    if duration is None:
        missing.append("duration")
    if packets is None:
        missing.append("packets")
    if bytes_total is None:
        missing.append("bytes_total")

    if missing:
        quality_flags.append(QualityFlag.MISSING_FIELD)

    # --- Build normalized event ---
    event = NormalizedEvent(
        event_id=str(uuid.uuid4()),
        schema_version=SCHEMA_VERSION,
        source_id=source_id,
        data_category=data_category,
        observed_at=observed_at,
        event_type=EventType.NETWORK_FLOW,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        duration=duration,
        packets=packets,
        bytes_total=bytes_total,
        label=label,
        label_provenance=label_provenance,
        quality_flags=quality_flags,
        raw_reference=raw_ref,
    )

    return ValidationResult(
        is_valid=True,
        event=event,
        warnings=warnings,
        raw_reference=raw_ref,
    )


def import_csv_file(
    file_path: Path,
    source_id: str,
    data_category: DataCategory = DataCategory.HISTORICAL_IMPORT,
    max_records: int = 100_000,
) -> tuple[list[NormalizedEvent], ImportSummary]:
    """
    Import and validate a CSV file, returning normalized events and
    an import summary.

    Does NOT persist results — that is the caller's responsibility.
    """
    events: list[NormalizedEvent] = []
    rejection_reasons: dict[str, int] = {}
    warnings_count = 0
    total = 0

    summary = ImportSummary(
        source_id=source_id,
        source_file=str(file_path),
        data_category=data_category,
    )

    if not file_path.exists():
        summary.rejection_reasons = {"file_not_found": 1}
        summary.completed_at = datetime.now(timezone.utc)
        return events, summary

    try:
        with open(file_path, "r", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            for row_idx, row in enumerate(reader, start=1):
                if row_idx > max_records:
                    logger.warning("Max records (%d) reached at row %d", max_records, row_idx)
                    break

                total += 1
                result = validate_and_normalize_row(
                    row=row,
                    row_index=row_idx,
                    source_id=source_id,
                    data_category=data_category,
                )

                if result.is_valid and result.event:
                    events.append(result.event)
                    if result.warnings:
                        warnings_count += 1
                else:
                    for err in result.errors:
                        # Extract error reason (skip 'Row X: ' prefix if present)
                        parts = err.split(":", 1)
                        if len(parts) > 1:
                            key = parts[1].strip().split(":")[0].strip()
                        else:
                            key = err[:50].strip()
                        rejection_reasons[key] = rejection_reasons.get(key, 0) + 1

    except Exception as e:
        logger.error("CSV import error: %s", e)
        rejection_reasons["import_error"] = 1

    summary.total_records = total
    summary.accepted_records = len(events)
    summary.rejected_records = total - len(events)
    summary.warnings_count = warnings_count
    summary.rejection_reasons = rejection_reasons
    summary.completed_at = datetime.now(timezone.utc)

    return events, summary


def import_csv_string(
    csv_content: str,
    source_id: str,
    data_category: DataCategory = DataCategory.HISTORICAL_IMPORT,
    max_records: int = 100_000,
) -> tuple[list[NormalizedEvent], ImportSummary]:
    """
    Import CSV from a string (e.g., uploaded content).
    Same validation as file import.
    """
    events: list[NormalizedEvent] = []
    rejection_reasons: dict[str, int] = {}
    warnings_count = 0
    total = 0

    summary = ImportSummary(
        source_id=source_id,
        source_file="<uploaded>",
        data_category=data_category,
    )

    try:
        reader = csv.DictReader(StringIO(csv_content))
        for row_idx, row in enumerate(reader, start=1):
            if row_idx > max_records:
                break
            total += 1
            result = validate_and_normalize_row(
                row=row,
                row_index=row_idx,
                source_id=source_id,
                data_category=data_category,
            )
            if result.is_valid and result.event:
                events.append(result.event)
                if result.warnings:
                    warnings_count += 1
            else:
                for err in result.errors:
                    parts = err.split(":", 1)
                    if len(parts) > 1:
                        key = parts[1].strip().split(":")[0].strip()
                    else:
                        key = err[:50].strip()
                    rejection_reasons[key] = rejection_reasons.get(key, 0) + 1

    except Exception as e:
        logger.error("CSV string import error: %s", e)
        rejection_reasons["import_error"] = 1

    summary.total_records = total
    summary.accepted_records = len(events)
    summary.rejected_records = total - len(events)
    summary.warnings_count = warnings_count
    summary.rejection_reasons = rejection_reasons
    summary.completed_at = datetime.now(timezone.utc)

    return events, summary


class CsvImportAdapter:
    """
    Object-oriented adapter for CSV ingestion and normalization.
    """

    def __init__(self, default_max_records: int = 100_000):
        self.default_max_records = default_max_records

    def import_file(
        self,
        file_path: Path,
        source_id: str,
        data_category: DataCategory = DataCategory.HISTORICAL_IMPORT,
        max_records: Optional[int] = None,
    ) -> tuple[list[NormalizedEvent], ImportSummary]:
        return import_csv_file(
            file_path=file_path,
            source_id=source_id,
            data_category=data_category,
            max_records=max_records or self.default_max_records,
        )

    def import_string(
        self,
        csv_content: str,
        source_id: str,
        data_category: DataCategory = DataCategory.HISTORICAL_IMPORT,
        max_records: Optional[int] = None,
    ) -> tuple[list[NormalizedEvent], ImportSummary]:
        return import_csv_string(
            csv_content=csv_content,
            source_id=source_id,
            data_category=data_category,
            max_records=max_records or self.default_max_records,
        )

