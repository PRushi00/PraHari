"""
PraHari — JSON Stream & Log Ingestion Adapter

Parses and normalizes streaming JSON events such as:
- Zeek conn.log JSON formats
- Suricata EVE JSON events
- Generic syslog / structured JSON telemetry
"""

from __future__ import annotations

import json
import logging
import uuid
import ipaddress
from datetime import datetime, timezone
from typing import Any, Optional

from app.adapters.base import BaseTelemetryAdapter
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

PROTO_INT_MAP = {
    6: "TCP",
    17: "UDP",
    1: "ICMP",
}


class JsonStreamAdapter(BaseTelemetryAdapter):
    """
    Adapter for JSON telemetry events (Zeek, Suricata, Syslog).
    """

    def __init__(self, adapter_id: str = "json_stream_default"):
        super().__init__(adapter_id=adapter_id, adapter_type="json_stream")

    def validate_and_normalize(
        self,
        raw_record: dict[str, Any],
        record_index: int,
        data_category: DataCategory = DataCategory.HISTORICAL_IMPORT,
    ) -> ValidationResult:
        errors: list[str] = []
        warnings: list[str] = []
        quality_flags: list[QualityFlag] = []
        raw_ref = f"json:record:{record_index}"

        # 1. Timestamp extraction
        ts_candidates = ["timestamp", "@timestamp", "ts", "time", "observed_at", "flow_start"]
        observed_at: Optional[datetime] = None
        for k in ts_candidates:
            if k in raw_record and raw_record[k] is not None:
                val = raw_record[k]
                if isinstance(val, (int, float)):
                    # Unix timestamp (seconds or milliseconds)
                    if val > 1e11:  # milliseconds
                        val = val / 1000.0
                    try:
                        observed_at = datetime.fromtimestamp(val, tz=timezone.utc)
                    except Exception:
                        pass
                elif isinstance(val, str):
                    try:
                        clean_str = val.replace("Z", "+00:00")
                        observed_at = datetime.fromisoformat(clean_str)
                        if observed_at.tzinfo is None:
                            observed_at = observed_at.replace(tzinfo=timezone.utc)
                            warnings.append("assumed_utc")
                            quality_flags.append(QualityFlag.TIMESTAMP_UNCERTAINTY)
                    except Exception:
                        pass
                if observed_at:
                    break

        if not observed_at:
            errors.append(f"Record {record_index}: missing or unparseable timestamp")

        # 2. Extract Endpoints (IP & Port)
        # Supports Zeek format (id.orig_h / id.resp_h), Suricata (src_ip / dest_ip), and flat keys.
        # A malformed record where "id" is a scalar rather than an object must be
        # rejected as invalid data, not crash the whole batch import.
        id_obj = raw_record.get("id")
        if not isinstance(id_obj, dict):
            if id_obj is not None:
                warnings.append("id_field_not_an_object")
                quality_flags.append(QualityFlag.SCHEMA_WARNING)
            id_obj = {}

        src_ip_val = (
            raw_record.get("src_ip")
            or raw_record.get("source_ip")
            or id_obj.get("orig_h")
            or raw_record.get("id.orig_h")
        )
        dst_ip_val = (
            raw_record.get("dst_ip")
            or raw_record.get("dest_ip")
            or raw_record.get("destination_ip")
            or id_obj.get("resp_h")
            or raw_record.get("id.resp_h")
        )

        src_ip: Optional[str] = None
        dst_ip: Optional[str] = None

        if src_ip_val:
            try:
                ipaddress.ip_address(str(src_ip_val).strip())
                src_ip = str(src_ip_val).strip()
            except ValueError:
                errors.append(f"Record {record_index}: invalid src_ip: '{src_ip_val}'")
        else:
            errors.append(f"Record {record_index}: missing src_ip")

        if dst_ip_val:
            try:
                ipaddress.ip_address(str(dst_ip_val).strip())
                dst_ip = str(dst_ip_val).strip()
            except ValueError:
                errors.append(f"Record {record_index}: invalid dst_ip: '{dst_ip_val}'")
        else:
            errors.append(f"Record {record_index}: missing dst_ip")

        # Ports
        src_port_val = (
            raw_record.get("src_port")
            or raw_record.get("source_port")
            or id_obj.get("orig_p")
            or raw_record.get("id.orig_p")
        )
        dst_port_val = (
            raw_record.get("dst_port")
            or raw_record.get("dest_port")
            or raw_record.get("destination_port")
            or id_obj.get("resp_p")
            or raw_record.get("id.resp_p")
        )

        src_port: Optional[int] = None
        dst_port: Optional[int] = None

        if src_port_val is not None and src_port_val != "":
            try:
                p = int(src_port_val)
                if 0 <= p <= 65535:
                    src_port = p
                else:
                    errors.append(f"Record {record_index}: src_port out of range: {p}")
            except (ValueError, TypeError):
                errors.append(f"Record {record_index}: invalid src_port: '{src_port_val}'")

        if dst_port_val is not None and dst_port_val != "":
            try:
                p = int(dst_port_val)
                if 0 <= p <= 65535:
                    dst_port = p
                else:
                    errors.append(f"Record {record_index}: dst_port out of range: {p}")
            except (ValueError, TypeError):
                errors.append(f"Record {record_index}: invalid dst_port: '{dst_port_val}'")

        # Protocol
        proto_val = raw_record.get("proto") or raw_record.get("protocol")
        protocol: Optional[str] = None
        if proto_val:
            if isinstance(proto_val, int):
                protocol = PROTO_INT_MAP.get(proto_val, f"PROTO_{proto_val}")
            else:
                p_str = str(proto_val).strip().upper()
                protocol = p_str if p_str in ("TCP", "UDP", "ICMP") else p_str

        # Metrics (Duration, Packets, Bytes)
        duration = None
        dur_val = (
            raw_record.get("duration")
            or raw_record.get("flow_duration")
            or (raw_record.get("flow", {}).get("age") if isinstance(raw_record.get("flow"), dict) else None)
        )
        if dur_val is not None:
            try:
                duration = float(dur_val)
            except (ValueError, TypeError):
                quality_flags.append(QualityFlag.INVALID_VALUE)

        packets = None
        pkts_val = raw_record.get("packets") or raw_record.get("tot_pkts")
        if pkts_val is not None:
            try:
                packets = int(pkts_val)
            except (ValueError, TypeError):
                quality_flags.append(QualityFlag.INVALID_VALUE)
        elif isinstance(raw_record.get("flow"), dict):
            p1 = raw_record["flow"].get("pkts_toserver") or 0
            p2 = raw_record["flow"].get("pkts_toclient") or 0
            if p1 or p2:
                packets = int(p1) + int(p2)

        bytes_total = None
        bytes_val = raw_record.get("bytes_total") or raw_record.get("bytes")
        if bytes_val is not None:
            try:
                bytes_total = int(bytes_val)
            except (ValueError, TypeError):
                quality_flags.append(QualityFlag.INVALID_VALUE)
        elif "orig_bytes" in raw_record or "resp_bytes" in raw_record:
            b1 = raw_record.get("orig_bytes") or 0
            b2 = raw_record.get("resp_bytes") or 0
            try:
                bytes_total = int(b1) + int(b2)
            except (ValueError, TypeError):
                quality_flags.append(QualityFlag.INVALID_VALUE)
        elif isinstance(raw_record.get("flow"), dict):
            b1 = raw_record["flow"].get("bytes_toserver") or 0
            b2 = raw_record["flow"].get("bytes_toclient") or 0
            if b1 or b2:
                bytes_total = int(b1) + int(b2)

        # Label
        alert_obj = raw_record.get("alert")
        if not isinstance(alert_obj, dict):
            alert_obj = {}
        label = (
            raw_record.get("label")
            or alert_obj.get("signature")
            or raw_record.get("classification")
        )
        if label:
            label = str(label).strip()

        event_type = EventType.NETWORK_FLOW
        raw_type = str(raw_record.get("event_type", "")).lower()
        if "dns" in raw_type:
            event_type = EventType.DNS_QUERY
        elif "http" in raw_type:
            event_type = EventType.HTTP_REQUEST
        elif "alert" in raw_type or (label and label.lower() != "benign"):
            event_type = EventType.ALERT

        if errors:
            self.record_failure(errors[0])
            return ValidationResult(
                is_valid=False,
                errors=errors,
                warnings=warnings,
                raw_reference=raw_ref,
            )

        event = NormalizedEvent(
            event_id=str(uuid.uuid4()),
            schema_version=SCHEMA_VERSION,
            source_id=self.adapter_id,
            data_category=data_category,
            observed_at=observed_at,
            event_type=event_type,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            duration=duration,
            packets=packets,
            bytes_total=bytes_total,
            label=label,
            label_provenance=LabelProvenance.DATASET_GROUND_TRUTH if label else LabelProvenance.UNLABELED,
            quality_flags=quality_flags,
            raw_reference=raw_ref,
        )

        self.record_success()
        return ValidationResult(
            is_valid=True,
            event=event,
            warnings=warnings,
            raw_reference=raw_ref,
        )

    def import_ndjson_string(
        self,
        ndjson_content: str,
        data_category: DataCategory = DataCategory.HISTORICAL_IMPORT,
        max_records: int = 50_000,
    ) -> tuple[list[NormalizedEvent], ImportSummary]:
        """Ingest newline-delimited JSON string."""
        events: list[NormalizedEvent] = []
        rejection_reasons: dict[str, int] = {}
        warnings_count = 0
        total = 0

        summary = ImportSummary(
            source_id=self.adapter_id,
            source_file="<ndjson_stream>",
            data_category=data_category,
        )

        lines = [line.strip() for line in ndjson_content.splitlines() if line.strip()]
        for idx, line in enumerate(lines, start=1):
            if idx > max_records:
                break
            total += 1
            try:
                record = json.loads(line)
                res = self.validate_and_normalize(record, idx, data_category)
                if res.is_valid and res.event:
                    events.append(res.event)
                    if res.warnings:
                        warnings_count += 1
                else:
                    for err in res.errors:
                        parts = err.split(":", 1)
                        key = parts[1].strip().split(":")[0].strip() if len(parts) > 1 else err[:50]
                        rejection_reasons[key] = rejection_reasons.get(key, 0) + 1
            except json.JSONDecodeError:
                rejection_reasons["invalid_json_syntax"] = rejection_reasons.get("invalid_json_syntax", 0) + 1

        summary.total_records = total
        summary.accepted_records = len(events)
        summary.rejected_records = total - len(events)
        summary.warnings_count = warnings_count
        summary.rejection_reasons = rejection_reasons
        summary.completed_at = datetime.now(timezone.utc)
        return events, summary
