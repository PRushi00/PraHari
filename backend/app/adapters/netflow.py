"""
PraHari — NetFlow / IPFIX Flow-Record Adapter (blueprint §5)

§5 lists "Network flows — NetFlow/IPFIX or equivalent exporter records"
as an adapter category, with the boundary "requires an authorized
exporter and consistent field/timestamp semantics".

What this adapter is, precisely
-------------------------------
It parses the **text export** that flow tools emit — `nfdump -o csv`,
`silk rwcut`, YAF/`yafscii`, and the CSV a collector writes — into
canonical events. It does **not** speak the binary NetFlow v5/v9/IPFIX
wire protocol and does not open a UDP collector port, because that would
mean listening on the network, which the project's safety boundary
forbids without explicit authorization.

So the honest capability statement is: *PraHari can ingest flow records
exported by an authorized collector; it is not itself a flow collector.*
`capabilities.py` says the same thing, and the capability report is where
an operator should read it rather than inferring from the adapter's name.

Field semantics, which differ between exporters
-----------------------------------------------
There is no single NetFlow CSV format. Field names vary by tool and
version, so the adapter maps a documented set of aliases and **refuses a
record whose required fields are absent** rather than guessing. §5.3
requires exactly that: "Reject incompatible required fields with a useful
error rather than silently mis-mapping them."

Two semantics are routinely got wrong and are handled explicitly:

* **Byte and packet counts are directional.** `nfdump` reports `ibyt`
  (ingress) and `obyt` (egress) separately. Summing them is correct for a
  bidirectional record and wrong for a unidirectional one, so the record
  is flagged when only one direction is present.
* **A flow has a start and an end.** `observed_at` is the flow START,
  because that is the moment the evidence describes; using the end would
  date the flow to when it finished, which for a long-lived connection is
  materially later and would corrupt every temporal window.
"""

from __future__ import annotations

import csv
import hashlib
import io
import ipaddress
import logging
from datetime import datetime, timezone
from typing import Any, Iterable, Optional

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

# Field aliases, by tool. Longest-standing names first so a file that
# carries several resolve predictably.
START_FIELDS = ("ts", "first", "firstseen", "flowstartseconds", "start",
                "stime", "flow_start", "timestamp")
END_FIELDS = ("te", "last", "lastseen", "flowendseconds", "end", "etime",
              "flow_end")
SRC_IP_FIELDS = ("sa", "srcaddr", "src_ip", "sourceipv4address", "sip",
                 "source_address")
DST_IP_FIELDS = ("da", "dstaddr", "dst_ip", "destinationipv4address", "dip",
                 "destination_address")
SRC_PORT_FIELDS = ("sp", "srcport", "src_port", "sourcetransportport", "sport")
DST_PORT_FIELDS = ("dp", "dstport", "dst_port", "destinationtransportport",
                   "dport")
PROTO_FIELDS = ("pr", "prot", "proto", "protocol", "protocolidentifier")
PACKET_FIELDS = ("ipkt", "pkts", "packets", "packetdeltacount", "in_pkts")
PACKET_OUT_FIELDS = ("opkt", "out_pkts", "outpackets")
BYTE_FIELDS = ("ibyt", "byt", "bytes", "octetdeltacount", "in_bytes", "doctets")
BYTE_OUT_FIELDS = ("obyt", "out_bytes", "outbytes")
DURATION_FIELDS = ("td", "dur", "duration", "flowduration")

PROTO_NUMBERS = {1: "ICMP", 6: "TCP", 17: "UDP", 47: "GRE", 50: "ESP", 58: "ICMPv6"}

MAX_RECORDS_DEFAULT = 100_000


class NetFlowParseError(ValueError):
    """A flow record could not be understood."""


def _norm_key(key: str) -> str:
    return key.strip().lower().replace(" ", "").replace("-", "").replace("_", "")


def _pick(row: dict[str, Any], names: Iterable[str]) -> Optional[Any]:
    """First alias actually present with a non-empty value."""
    for name in names:
        if name in row:
            value = row[name]
            if value is not None and str(value).strip() not in ("", "-", "N/A"):
                return value
    return None


def _parse_timestamp(value: Any) -> Optional[datetime]:
    """
    Flow exports date-stamp in several ways. Each is tried explicitly;
    an unrecognised value returns None rather than `now`, because
    defaulting to the present would silently re-date the flow.
    """
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None

    # Epoch seconds, or milliseconds for larger magnitudes.
    try:
        number = float(text)
        if number > 1e11:
            number /= 1000.0
        if number > 0:
            return datetime.fromtimestamp(number, tz=timezone.utc)
    except (ValueError, OverflowError, OSError):
        pass

    candidate = text.replace("Z", "+00:00")
    for fmt in (None, "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S",
                "%Y/%m/%d %H:%M:%S"):
        try:
            parsed = (
                datetime.fromisoformat(candidate) if fmt is None
                else datetime.strptime(text, fmt)
            )
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _parse_protocol(value: Any) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        return PROTO_NUMBERS.get(int(text), f"PROTO_{int(text)}")
    except ValueError:
        return text.upper()


def _parse_ip(value: Any) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    # nfdump may render "10.0.0.1:443" when ports are folded in.
    if text.count(":") == 1 and "." in text:
        text = text.split(":")[0]
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return None


def _parse_int(value: Any) -> Optional[int]:
    if value is None:
        return None
    try:
        return int(float(str(value).strip()))
    except (ValueError, TypeError):
        return None


def _parse_float(value: Any) -> Optional[float]:
    if value is None:
        return None
    try:
        return float(str(value).strip())
    except (ValueError, TypeError):
        return None


class NetFlowAdapter(BaseTelemetryAdapter):
    """
    Canonical events from exported NetFlow / IPFIX records.

    Event identity is **deterministic**, derived from the source, the
    flow five-tuple and the flow start. Re-importing the same export is
    therefore idempotent at the storage layer (ADR-050) — important
    because flow collectors routinely emit overlapping files.
    """

    def __init__(self, adapter_id: str = "netflow_exporter"):
        super().__init__(adapter_id=adapter_id, adapter_type="netflow_ipfix")

    # ──────────────── identity ────────────────

    def event_id_for(self, raw_record: dict[str, Any]) -> str:
        parts = "|".join(
            str(raw_record.get(k) or "")
            for k in ("_src_ip", "_dst_ip", "_src_port", "_dst_port",
                      "_protocol", "_start_iso")
        )
        digest = hashlib.sha256(
            f"{self.adapter_id}|{parts}".encode("utf-8")
        ).hexdigest()
        return f"nf-{digest[:32]}"

    # ──────────────── normalization ────────────────

    def validate_and_normalize(
        self,
        raw_record: dict[str, Any],
        record_index: int,
        data_category: DataCategory = DataCategory.HISTORICAL_IMPORT,
    ) -> ValidationResult:
        errors: list[str] = []
        warnings: list[str] = []
        flags: list[QualityFlag] = []
        raw_ref = f"netflow:record:{record_index}"

        row = {_norm_key(k): v for k, v in raw_record.items() if k is not None}

        start = _parse_timestamp(_pick(row, START_FIELDS))
        if start is None:
            errors.append("missing_or_unparseable_flow_start")

        src_ip = _parse_ip(_pick(row, SRC_IP_FIELDS))
        dst_ip = _parse_ip(_pick(row, DST_IP_FIELDS))
        if src_ip is None or dst_ip is None:
            errors.append("missing_or_invalid_endpoint_address")

        protocol = _parse_protocol(_pick(row, PROTO_FIELDS))
        if protocol is None:
            errors.append("missing_protocol")

        if errors:
            self.record_failure(errors[0])
            return ValidationResult(
                is_valid=False, errors=errors, warnings=warnings,
                raw_reference=raw_ref,
            )

        src_port = _parse_int(_pick(row, SRC_PORT_FIELDS))
        dst_port = _parse_int(_pick(row, DST_PORT_FIELDS))

        # Directional counts. Summing is right for a bidirectional record
        # and wrong for a unidirectional one, so which happened is flagged.
        bytes_in = _parse_int(_pick(row, BYTE_FIELDS))
        bytes_out = _parse_int(_pick(row, BYTE_OUT_FIELDS))
        packets_in = _parse_int(_pick(row, PACKET_FIELDS))
        packets_out = _parse_int(_pick(row, PACKET_OUT_FIELDS))

        if bytes_in is not None and bytes_out is not None:
            bytes_total = bytes_in + bytes_out
        else:
            bytes_total = bytes_in if bytes_in is not None else bytes_out
            if bytes_total is not None:
                warnings.append("unidirectional_byte_count")
                flags.append(QualityFlag.MISSING_FIELD)

        if packets_in is not None and packets_out is not None:
            packets = packets_in + packets_out
        else:
            packets = packets_in if packets_in is not None else packets_out

        duration = _parse_float(_pick(row, DURATION_FIELDS))
        if duration is None:
            end = _parse_timestamp(_pick(row, END_FIELDS))
            if end is not None:
                duration = max(0.0, (end - start).total_seconds())

        if bytes_total is None and packets is None:
            # A flow with neither counter is a connection record, not a
            # volume measurement. Kept, but the gap is recorded.
            warnings.append("no_volume_counters_present")
            flags.append(QualityFlag.MISSING_FIELD)

        identity_input = {
            "_src_ip": src_ip, "_dst_ip": dst_ip,
            "_src_port": src_port, "_dst_port": dst_port,
            "_protocol": protocol, "_start_iso": start.isoformat(),
        }

        event = NormalizedEvent(
            event_id=self.event_id_for(identity_input),
            schema_version=SCHEMA_VERSION,
            source_id=self.adapter_id,
            data_category=data_category,
            # The flow START. Using the end would date a long-lived flow
            # to when it finished and corrupt every temporal window.
            observed_at=start,
            event_type=EventType.NETWORK_FLOW,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            duration=duration,
            packets=packets,
            bytes_total=bytes_total,
            # An exporter reports traffic, not ground truth. Any label
            # would have to come from elsewhere.
            label=None,
            label_provenance=LabelProvenance.UNLABELED,
            quality_flags=flags,
            raw_reference=raw_ref,
        )
        self.record_success()
        return ValidationResult(
            is_valid=True, event=event, warnings=warnings, raw_reference=raw_ref
        )

    # ──────────────── bulk import ────────────────

    def import_csv_string(
        self,
        csv_content: str,
        data_category: DataCategory = DataCategory.HISTORICAL_IMPORT,
        max_records: int = MAX_RECORDS_DEFAULT,
    ) -> tuple[list[NormalizedEvent], ImportSummary]:
        """
        Parse an exported flow CSV.

        Bounded by `max_records` (§5.1 "bounded parsing"): the reader
        stops rather than loading an arbitrarily large export into
        memory, and the summary says it was truncated.
        """
        started_at = datetime.now(timezone.utc)
        events: list[NormalizedEvent] = []
        reasons: dict[str, int] = {}
        total = 0
        warnings_count = 0
        truncated = False

        # nfdump appends a summary block after a blank line; everything
        # from there on is not flow data.
        text = csv_content.split("\n\n", 1)[0]
        reader = csv.DictReader(io.StringIO(text))

        for index, row in enumerate(reader):
            if total >= max_records:
                truncated = True
                break
            total += 1
            result = self.validate_and_normalize(row, index, data_category)
            warnings_count += len(result.warnings)
            if result.is_valid and result.event is not None:
                events.append(result.event)
            else:
                for err in result.errors or ["unknown_error"]:
                    reasons[err] = reasons.get(err, 0) + 1

        if truncated:
            reasons["truncated_at_max_records"] = 1

        summary = ImportSummary(
            source_id=self.adapter_id,
            source_file="<netflow_csv>",
            data_category=data_category,
            started_at=started_at,
            completed_at=datetime.now(timezone.utc),
            total_records=total,
            accepted_records=len(events),
            rejected_records=total - len(events),
            warnings_count=warnings_count,
            rejection_reasons=reasons,
        )
        return events, summary
