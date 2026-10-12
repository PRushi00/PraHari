"""
PraHari — Descriptive Analysis Service

Computes descriptive statistics from persisted normalized events.

This is NOT forecasting and NOT detection. It summarizes what was observed.
Frequency is not evidence of maliciousness: a destination contacted often, or
a connection to port 443, is ordinary. Nothing here classifies activity as an
attack.

Two properties are enforced throughout:

  * **Provenance is derived, never declared.** The category and source
    breakdown come from the analyzed events themselves. A caller may choose
    which events to analyze; it may not assert what they are.
  * **Absence is explained.** A field the contributing source cannot provide
    is reported separately from a field that is genuinely missing.
"""

from __future__ import annotations

import logging
from collections import Counter
from datetime import datetime, timezone
from typing import Iterable, Optional

from app.adapters.capabilities import get_capability
from app.schemas.events import (
    DataCategory,
    DescriptiveAnalysis,
    NormalizedEvent,
    QualityFlag,
    is_quality_defect,
)

logger = logging.getLogger(__name__)

# Canonical fields whose presence is worth accounting for in an analysis.
_TRACKED_FIELDS = (
    "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
    "duration", "packets", "bytes_total",
)


def _parse_raw_reference(raw_reference: Optional[str]) -> dict[str, str]:
    """
    Parse the adapter provenance string, e.g.
    ``windows:tcp;state=Established;pid=1234`` -> {'state': ..., 'pid': ...}.
    """
    out: dict[str, str] = {}
    if not raw_reference:
        return out
    for part in raw_reference.split(";"):
        if "=" in part:
            k, _, v = part.partition("=")
            out[k.strip()] = v.strip()
    return out


def compute_descriptive_analysis(
    events: list[NormalizedEvent],
    source_id: str,
    source_types: Optional[dict[str, str]] = None,
    hostname_resolver=None,
) -> DescriptiveAnalysis:
    """
    Compute descriptive statistics from a list of normalized events.

    Args:
        events: the events to summarize.
        source_id: label for the analyzed scope (e.g. a source id or
            ``all_sources``). This names the scope; it does not declare what
            the data is.
        source_types: optional ``{source_id: source_type}`` map used to look
            up capability profiles, so unsupported fields can be separated
            from genuinely missing ones.
        hostname_resolver: optional callable ``(event) -> hostname | None``
            used to aggregate destination hostnames. Attribution is an
            inference and is reported as such; it never mutates events.

    The returned ``data_category`` is derived from the events: the single
    category present, or ``MIXED`` when several are.
    """
    source_types = source_types or {}

    if not events:
        # No events: provenance cannot be derived, and naming any category
        # would be an invention.
        return DescriptiveAnalysis(
            source_id=source_id,
            data_category=DataCategory.UNDETERMINED,
            total_events=0,
            data_categories={},
            source_breakdown={},
            is_mixed_provenance=False,
        )

    # Counters
    type_counter: Counter = Counter()
    label_counter: Counter = Counter()
    protocol_counter: Counter = Counter()
    src_ip_counter: Counter = Counter()
    dst_ip_counter: Counter = Counter()
    dst_port_counter: Counter = Counter()
    category_counter: Counter = Counter()
    source_counter: Counter = Counter()
    state_counter: Counter = Counter()
    process_counter: Counter = Counter()
    hostname_counter: Counter = Counter()
    hour_counter: Counter = Counter()
    quality_counter: Counter = Counter()

    # Field accounting, split by *why* a value is absent.
    missing_counter: Counter = Counter()      # source supports it, value absent
    unsupported_counter: Counter = Counter()  # source cannot provide it

    timestamps: list[datetime] = []
    durations: list[float] = []
    packets_list: list[int] = []
    bytes_list: list[int] = []
    records_with_warnings = 0
    total_bytes = 0
    hostname_attributed = 0
    limitations: list[str] = []
    seen_source_types: set[str] = set()

    for event in events:
        category_counter[event.data_category.value] += 1
        source_counter[event.source_id] += 1
        type_counter[event.event_type.value] += 1
        label_counter[event.label or "unlabeled"] += 1

        capability = get_capability(source_types.get(event.source_id))
        seen_source_types.add(capability.source_type)

        # ── Field presence, attributed to a cause ──
        for field in _TRACKED_FIELDS:
            value = getattr(event, field, None)
            if value is not None:
                continue
            if capability.supports(field):
                missing_counter[field] += 1
            else:
                unsupported_counter[field] += 1

        if event.protocol:
            protocol_counter[event.protocol] += 1
        if event.src_ip:
            src_ip_counter[event.src_ip] += 1
        if event.dst_ip:
            dst_ip_counter[event.dst_ip] += 1
        if event.dst_port is not None:
            dst_port_counter[event.dst_port] += 1

        timestamps.append(event.observed_at)
        hour_counter[event.observed_at.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:00Z")] += 1

        if event.duration is not None:
            durations.append(event.duration)
        if event.packets is not None:
            packets_list.append(event.packets)
        if event.bytes_total is not None:
            bytes_list.append(event.bytes_total)
            total_bytes += event.bytes_total

        # ── Connection intelligence from adapter provenance ──
        meta = _parse_raw_reference(event.raw_reference)
        if meta.get("state"):
            state_counter[meta["state"]] += 1
        if meta.get("process"):
            process_counter[meta["process"]] += 1
        elif meta.get("pid"):
            process_counter[f"pid:{meta['pid']}"] += 1

        # ── Hostname aggregation (inference, clearly separate from the record) ──
        hostname = event.dst_hostname
        if hostname is None and hostname_resolver is not None:
            try:
                hostname = hostname_resolver(event)
            except Exception:  # noqa: BLE001
                hostname = None
        if hostname:
            hostname_counter[hostname] += 1
            hostname_attributed += 1

        # ── Quality flags ──
        # SOURCE_LIMITED and SYNTHETIC_SAMPLE describe a sensor limit and a
        # record's provenance respectively — neither is a defect. Counting
        # them would mark every synthetic fixture and every record from a
        # limited source as faulty, hiding the genuine problems.
        if event.quality_flags:
            if any(is_quality_defect(f) for f in event.quality_flags):
                records_with_warnings += 1
            for flag in event.quality_flags:
                quality_counter[flag.value] += 1

    for stype in sorted(seen_source_types):
        for lim in get_capability(stype).limitations:
            entry = f"[{stype}] {lim}"
            if entry not in limitations:
                limitations.append(entry)

    # ── Derived provenance ──
    categories = dict(category_counter)
    is_mixed = len(categories) > 1
    if is_mixed:
        derived_category = DataCategory.MIXED
    else:
        derived_category = DataCategory(next(iter(categories)))

    avg_duration = sum(durations) / len(durations) if durations else None
    avg_packets = sum(packets_list) / len(packets_list) if packets_list else None
    avg_bytes = sum(bytes_list) / len(bytes_list) if bytes_list else None

    top_n = 10
    return DescriptiveAnalysis(
        source_id=source_id,
        data_category=derived_category,
        data_categories=categories,
        source_breakdown=dict(source_counter),
        is_mixed_provenance=is_mixed,
        total_events=len(events),
        events_by_type=dict(type_counter),
        events_by_label=dict(label_counter),
        events_by_protocol=dict(protocol_counter),
        time_range_start=min(timestamps) if timestamps else None,
        time_range_end=max(timestamps) if timestamps else None,
        missing_field_counts=dict(missing_counter),
        unsupported_field_counts=dict(unsupported_counter),
        source_limitations=limitations,
        quality_flag_counts=dict(quality_counter),
        records_with_warnings=records_with_warnings,
        unique_src_ips=len(src_ip_counter),
        unique_dst_ips=len(dst_ip_counter),
        unique_src_ports=len({e.src_port for e in events if e.src_port is not None}),
        unique_dst_ports=len(dst_port_counter),
        top_src_ips=[{"ip": ip, "count": c} for ip, c in src_ip_counter.most_common(top_n)],
        top_dst_ips=[{"ip": ip, "count": c} for ip, c in dst_ip_counter.most_common(top_n)],
        top_dst_ports=[{"port": p, "count": c} for p, c in dst_port_counter.most_common(top_n)],
        events_by_connection_state=dict(state_counter),
        events_by_process=dict(process_counter.most_common(top_n)),
        top_dst_hostnames=[{"hostname": h, "count": c} for h, c in hostname_counter.most_common(top_n)],
        hostname_attributed_count=hostname_attributed,
        events_per_hour=dict(sorted(hour_counter.items())),
        avg_duration=round(avg_duration, 4) if avg_duration is not None else None,
        avg_packets=round(avg_packets, 2) if avg_packets is not None else None,
        avg_bytes=round(avg_bytes, 2) if avg_bytes is not None else None,
        total_bytes=total_bytes if bytes_list else None,
    )
