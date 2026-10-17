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

# Zeek writes "-" for a field that exists but has no value.
ZEEK_UNSET = {"-", "(empty)"}


def _first_present(record: dict[str, Any], *keys: str) -> Any:
    """
    Return the first key that is actually present with a non-null value.

    Deliberately not an ``or`` chain: ``0`` bytes, ``0.0`` seconds and port
    ``0`` are real measurements, and falling through them would turn a
    recorded zero into "no data". Those two mean different things here —
    the whole provenance model depends on not confusing them.
    """
    for key in keys:
        if key in record:
            value = record[key]
            if value is not None:
                return value
    return None


def _extract_sender_event_id(raw_record: dict[str, Any]) -> Optional[str]:
    """
    Extract an explicit sender-provided event identifier if present.

    Supports:
    - standard 'event_id'
    - Zeek 'uid' (unique connection identifier)
    - standard 'uuid'
    - 'record_id'
    - scalar 'id' (when 'id' is a string or int, not a nested dict like Zeek's endpoint object)
    """
    for key in ("event_id", "uid", "uuid", "record_id"):
        val = raw_record.get(key)
        if val is not None and not isinstance(val, (dict, list)):
            s = str(val).strip()
            if s:
                return s

    val = raw_record.get("id")
    if val is not None and isinstance(val, (str, int)):
        s = str(val).strip()
        if s:
            return s
    return None


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
        idempotency_key: Optional[str] = None,
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
        src_port_val = _first_present(raw_record, "src_port", "source_port")
        if src_port_val is None:
            src_port_val = _first_present(id_obj, "orig_p")
        if src_port_val is None:
            src_port_val = _first_present(raw_record, "id.orig_p")

        dst_port_val = _first_present(
            raw_record, "dst_port", "dest_port", "destination_port"
        )
        if dst_port_val is None:
            dst_port_val = _first_present(id_obj, "resp_p")
        if dst_port_val is None:
            dst_port_val = _first_present(raw_record, "id.resp_p")

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
                # Pass unrecognised protocol names through unchanged rather
                # than coercing them to a known one. An unexpected protocol
                # is information; a silently rewritten one is not.
                protocol = str(proto_val).strip().upper()

        # Metrics (Duration, Packets, Bytes)
        flow_obj = raw_record.get("flow")
        if not isinstance(flow_obj, dict):
            flow_obj = {}

        duration = None
        dur_val = _first_present(raw_record, "duration", "flow_duration")
        if dur_val is None:
            dur_val = _first_present(flow_obj, "age")
        if isinstance(dur_val, str) and dur_val.strip() in ZEEK_UNSET:
            dur_val = None
        if dur_val is not None:
            try:
                duration = float(dur_val)
            except (ValueError, TypeError):
                quality_flags.append(QualityFlag.INVALID_VALUE)

        packets = None
        pkts_val = _first_present(raw_record, "packets", "tot_pkts")
        if isinstance(pkts_val, str) and pkts_val.strip() in ZEEK_UNSET:
            pkts_val = None
        if pkts_val is not None:
            try:
                packets = int(pkts_val)
            except (ValueError, TypeError):
                quality_flags.append(QualityFlag.INVALID_VALUE)
        elif "pkts_toserver" in flow_obj or "pkts_toclient" in flow_obj:
            try:
                packets = int(flow_obj.get("pkts_toserver") or 0) + int(
                    flow_obj.get("pkts_toclient") or 0
                )
            except (ValueError, TypeError):
                quality_flags.append(QualityFlag.INVALID_VALUE)

        bytes_total = None
        bytes_val = _first_present(raw_record, "bytes_total", "bytes")
        if isinstance(bytes_val, str) and bytes_val.strip() in ZEEK_UNSET:
            bytes_val = None
        if bytes_val is not None:
            try:
                bytes_total = int(bytes_val)
            except (ValueError, TypeError):
                quality_flags.append(QualityFlag.INVALID_VALUE)
        elif "orig_bytes" in raw_record or "resp_bytes" in raw_record:
            try:
                bytes_total = int(raw_record.get("orig_bytes") or 0) + int(
                    raw_record.get("resp_bytes") or 0
                )
            except (ValueError, TypeError):
                quality_flags.append(QualityFlag.INVALID_VALUE)
        elif "bytes_toserver" in flow_obj or "bytes_toclient" in flow_obj:
            try:
                bytes_total = int(flow_obj.get("bytes_toserver") or 0) + int(
                    flow_obj.get("bytes_toclient") or 0
                )
            except (ValueError, TypeError):
                quality_flags.append(QualityFlag.INVALID_VALUE)

        # ── Label and its provenance ──
        #
        # Where a label came from decides whether it may be used as a
        # training target, so the two are resolved together and never
        # defaulted to the strongest option.
        #
        #   label / classification  -> the corpus states what this was
        #   alert.signature         -> a DETECTOR said so
        #
        # A Suricata signature is the IDS's opinion. Recording it as ground
        # truth would let a forecaster be trained to predict one detector's
        # alerts while the metrics claim it predicts attacks.
        alert_obj = raw_record.get("alert")
        if not isinstance(alert_obj, dict):
            alert_obj = {}

        label: Optional[str] = None
        label_provenance = LabelProvenance.UNLABELED

        corpus_label = _first_present(raw_record, "label", "classification")
        if corpus_label is not None and str(corpus_label).strip():
            label = str(corpus_label).strip()
            label_provenance = LabelProvenance.DATASET_GROUND_TRUTH
        else:
            signature = alert_obj.get("signature")
            if signature is not None and str(signature).strip():
                label = str(signature).strip()
                label_provenance = LabelProvenance.DETECTOR_OUTPUT
                warnings.append("label_is_detector_output_not_ground_truth")

        # ── Event type ──
        #
        # The event type describes WHAT WAS OBSERVED; the label describes how
        # it was annotated. They are kept separate: a labelled flow from a
        # historical corpus is still a flow. Collapsing every labelled record
        # into ALERT would make an imported dataset report as nothing but
        # alerts, and would misstate what the sensor actually saw.
        event_type = EventType.NETWORK_FLOW
        raw_type = str(raw_record.get("event_type", "")).lower()
        if "dns" in raw_type:
            event_type = EventType.DNS_QUERY
        elif "http" in raw_type:
            event_type = EventType.HTTP_REQUEST
        elif "alert" in raw_type or alert_obj:
            event_type = EventType.ALERT

        if errors:
            self.record_failure(errors[0])
            return ValidationResult(
                is_valid=False,
                errors=errors,
                warnings=warnings,
                raw_reference=raw_ref,
            )

        # Determine event identity:
        # 1. Explicit sender-provided event ID (Zeek uid, event_id, uuid, etc.)
        #    Scoped to source_id using UUIDv5 so cross-source collisions cannot occur.
        # 2. Batch idempotency key + record index, allowing safe retries of batches
        #    without collapsing distinct records in the same batch.
        # 3. Fresh random UUID4 for legacy clients without identity metadata, preserving
        #    documented legacy behavior.
        sender_event_id = _extract_sender_event_id(raw_record)
        if sender_event_id:
            event_id = str(
                uuid.uuid5(
                    uuid.NAMESPACE_URL,
                    f"urn:prahari:source:{self.adapter_id}:event:{sender_event_id}",
                )
            )
        elif idempotency_key:
            event_id = str(
                uuid.uuid5(
                    uuid.NAMESPACE_URL,
                    f"urn:prahari:source:{self.adapter_id}:batch:{idempotency_key}:record:{record_index}",
                )
            )
        else:
            event_id = str(uuid.uuid4())

        event = NormalizedEvent(
            event_id=event_id,
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
            label_provenance=label_provenance,
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
        idempotency_key: Optional[str] = None,
    ) -> tuple[list[NormalizedEvent], ImportSummary]:
        """Ingest newline-delimited JSON string."""
        events: list[NormalizedEvent] = []
        rejection_reasons: dict[str, int] = {}
        warnings_count = 0
        total = 0
        seen_batch_identities: dict[str, tuple] = {}

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
                if not isinstance(record, dict):
                    # Valid JSON that is not an object - an array, a number,
                    # a string, null. It used to reach the validator, which
                    # called .get() on it and raised AttributeError: one such
                    # line turned the whole batch into a 500 and cost every
                    # good record beside it (ADR-068). It is one bad record.
                    rejection_reasons["record_not_an_object"] = (
                        rejection_reasons.get("record_not_an_object", 0) + 1
                    )
                    continue
                res = self.validate_and_normalize(
                    record,
                    idx,
                    data_category,
                    idempotency_key=idempotency_key,
                )
                if res.is_valid and res.event:
                    eid = res.event.event_id
                    canonical = (
                        res.event.observed_at.isoformat(),
                        res.event.src_ip,
                        res.event.dst_ip,
                        res.event.src_port,
                        res.event.dst_port,
                        res.event.protocol,
                    )
                    if eid in seen_batch_identities:
                        if seen_batch_identities[eid] == canonical:
                            rejection_reasons["duplicate_event_in_batch"] = (
                                rejection_reasons.get("duplicate_event_in_batch", 0) + 1
                            )
                        else:
                            rejection_reasons["conflicting_event_id"] = (
                                rejection_reasons.get("conflicting_event_id", 0) + 1
                            )
                    else:
                        seen_batch_identities[eid] = canonical
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
