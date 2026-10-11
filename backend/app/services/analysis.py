"""
PraHari — Descriptive Analysis Service

Computes descriptive historical analysis from persisted normalized events.
This is NOT forecasting. It summarizes observed data to help understand
the dataset before any predictive modeling.

Analysis results are persisted and served through the API.
"""

from __future__ import annotations

import logging
from collections import Counter
from datetime import datetime, timezone
from typing import Optional

from app.schemas.events import (
    DataCategory,
    DescriptiveAnalysis,
    NormalizedEvent,
    QualityFlag,
)

logger = logging.getLogger(__name__)


def compute_descriptive_analysis(
    events: list[NormalizedEvent],
    source_id: str,
    data_category: DataCategory = DataCategory.HISTORICAL_IMPORT,
) -> DescriptiveAnalysis:
    """
    Compute descriptive statistics from a list of normalized events.

    This produces a factual summary of what the data contains.
    It does not make predictions or forecasts.
    """

    if not events:
        return DescriptiveAnalysis(
            source_id=source_id,
            data_category=data_category,
            total_events=0,
        )

    # Counters
    type_counter: Counter = Counter()
    label_counter: Counter = Counter()
    protocol_counter: Counter = Counter()
    src_ip_counter: Counter = Counter()
    dst_ip_counter: Counter = Counter()
    dst_port_counter: Counter = Counter()
    missing_counter: Counter = Counter()
    quality_counter: Counter = Counter()

    timestamps = []
    durations = []
    packets_list = []
    bytes_list = []
    records_with_warnings = 0
    total_bytes = 0

    for event in events:
        # Event type
        type_counter[event.event_type.value] += 1

        # Label
        label_counter[event.label or "unlabeled"] += 1

        # Protocol
        if event.protocol:
            protocol_counter[event.protocol] += 1
        else:
            missing_counter["protocol"] += 1

        # IPs
        if event.src_ip:
            src_ip_counter[event.src_ip] += 1
        else:
            missing_counter["src_ip"] += 1

        if event.dst_ip:
            dst_ip_counter[event.dst_ip] += 1
        else:
            missing_counter["dst_ip"] += 1

        # Ports
        if event.dst_port is not None:
            dst_port_counter[event.dst_port] += 1
        else:
            missing_counter["dst_port"] += 1

        # Timestamps
        timestamps.append(event.observed_at)

        # Flow metrics
        if event.duration is not None:
            durations.append(event.duration)
        else:
            missing_counter["duration"] += 1

        if event.packets is not None:
            packets_list.append(event.packets)
        else:
            missing_counter["packets"] += 1

        if event.bytes_total is not None:
            bytes_list.append(event.bytes_total)
            total_bytes += event.bytes_total
        else:
            missing_counter["bytes_total"] += 1

        # Quality flags
        if event.quality_flags:
            records_with_warnings += 1
            for flag in event.quality_flags:
                quality_counter[flag.value] += 1

    # Compute aggregates
    time_range_start = min(timestamps) if timestamps else None
    time_range_end = max(timestamps) if timestamps else None
    avg_duration = sum(durations) / len(durations) if durations else None
    avg_packets = sum(packets_list) / len(packets_list) if packets_list else None
    avg_bytes = sum(bytes_list) / len(bytes_list) if bytes_list else None

    # Top-N lists
    top_n = 10
    top_src_ips = [
        {"ip": ip, "count": cnt}
        for ip, cnt in src_ip_counter.most_common(top_n)
    ]
    top_dst_ips = [
        {"ip": ip, "count": cnt}
        for ip, cnt in dst_ip_counter.most_common(top_n)
    ]
    top_dst_ports = [
        {"port": port, "count": cnt}
        for port, cnt in dst_port_counter.most_common(top_n)
    ]

    return DescriptiveAnalysis(
        source_id=source_id,
        data_category=data_category,
        total_events=len(events),
        events_by_type=dict(type_counter),
        events_by_label=dict(label_counter),
        events_by_protocol=dict(protocol_counter),
        time_range_start=time_range_start,
        time_range_end=time_range_end,
        missing_field_counts=dict(missing_counter),
        quality_flag_counts=dict(quality_counter),
        records_with_warnings=records_with_warnings,
        unique_src_ips=len(src_ip_counter),
        unique_dst_ips=len(dst_ip_counter),
        unique_src_ports=len(set(e.src_port for e in events if e.src_port is not None)),
        unique_dst_ports=len(dst_port_counter),
        top_src_ips=top_src_ips,
        top_dst_ips=top_dst_ips,
        top_dst_ports=top_dst_ports,
        avg_duration=round(avg_duration, 4) if avg_duration is not None else None,
        avg_packets=round(avg_packets, 2) if avg_packets is not None else None,
        avg_bytes=round(avg_bytes, 2) if avg_bytes is not None else None,
        total_bytes=total_bytes if total_bytes > 0 else None,
    )
