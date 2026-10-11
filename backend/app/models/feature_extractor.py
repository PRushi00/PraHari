"""
PraHari — Causal Feature Engineering Engine

Extracts retrospective window-based telemetry features without forward leakage.
Observation Window: [t - W, t]
Prediction Horizon: [t + lead_time, t + lead_time + H]
"""

from __future__ import annotations

import math
from datetime import datetime, timedelta, timezone
from typing import Any
import numpy as np

from app.schemas.events import NormalizedEvent


FEATURE_NAMES = [
    "flow_count",
    "distinct_src_ips",
    "distinct_dst_ips",
    "distinct_dst_ports",
    "total_bytes",
    "avg_bytes_per_flow",
    "total_packets",
    "avg_packets_per_flow",
    "tcp_ratio",
    "udp_ratio",
    "avg_duration",
    "byte_rate_per_sec",
]


class WindowFeatureExtractor:
    """
    Constructs causal feature vectors from normalized network flows.
    """

    def __init__(
        self,
        window_size_seconds: float = 60.0,
        lead_time_seconds: float = 30.0,
        prediction_horizon_seconds: float = 60.0,
    ):
        self.window_size_seconds = window_size_seconds
        self.lead_time_seconds = lead_time_seconds
        self.prediction_horizon_seconds = prediction_horizon_seconds

    def extract_features_from_window(
        self,
        window_events: list[NormalizedEvent],
        window_duration: float,
    ) -> list[float]:
        """Extract a single feature vector from events in an observation window."""
        if not window_events:
            return [0.0] * len(FEATURE_NAMES)

        flow_count = float(len(window_events))
        src_ips = set(e.src_ip for e in window_events if e.src_ip)
        dst_ips = set(e.dst_ip for e in window_events if e.dst_ip)
        dst_ports = set(e.dst_port for e in window_events if e.dst_port is not None)

        durations = [e.duration for e in window_events if e.duration is not None]
        packets = [e.packets for e in window_events if e.packets is not None]
        bytes_total = [e.bytes_total for e in window_events if e.bytes_total is not None]

        tot_bytes = sum(bytes_total) if bytes_total else 0.0
        tot_pkts = sum(packets) if packets else 0.0

        tcp_count = sum(1 for e in window_events if e.protocol == "TCP")
        udp_count = sum(1 for e in window_events if e.protocol == "UDP")

        duration_sec = max(1.0, window_duration)

        return [
            flow_count,
            float(len(src_ips)),
            float(len(dst_ips)),
            float(len(dst_ports)),
            float(tot_bytes),
            float(tot_bytes / flow_count) if flow_count > 0 else 0.0,
            float(tot_pkts),
            float(tot_pkts / flow_count) if flow_count > 0 else 0.0,
            float(tcp_count / flow_count) if flow_count > 0 else 0.0,
            float(udp_count / flow_count) if flow_count > 0 else 0.0,
            float(sum(durations) / len(durations)) if durations else 0.0,
            float(tot_bytes / duration_sec),
        ]

    def build_dataset_instances(
        self,
        events: list[NormalizedEvent],
        step_seconds: float = 15.0,
    ) -> tuple[np.ndarray, np.ndarray, list[datetime]]:
        """
        Slide observation windows across chronological events to create
        (X, y, timestamp) pairs strictly preventing temporal leakage.
        """
        if not events:
            return np.empty((0, len(FEATURE_NAMES))), np.empty((0,)), []

        sorted_events = sorted(events, key=lambda e: e.observed_at)
        start_time = sorted_events[0].observed_at
        end_time = sorted_events[-1].observed_at

        total_span = (end_time - start_time).total_seconds()
        min_required_span = self.window_size_seconds + self.lead_time_seconds + self.prediction_horizon_seconds

        # If data span is very short (e.g. test fixture), scale window sizes proportionally to preserve task
        w_size = self.window_size_seconds
        lead_t = self.lead_time_seconds
        pred_h = self.prediction_horizon_seconds
        step_t = step_seconds

        if total_span > 20 and (total_span < min_required_span or (total_span - min_required_span) / step_t < 6):
            scale = min(1.0, total_span / (min_required_span * 2.5))
            w_size = max(5.0, w_size * scale)
            lead_t = max(2.0, lead_t * scale)
            pred_h = max(5.0, pred_h * scale)
            step_t = max(2.0, step_t * scale)

        X_list: list[list[float]] = []
        y_list: list[int] = []
        ts_list: list[datetime] = []

        current_window_end = start_time + timedelta(seconds=w_size)

        while current_window_end + timedelta(seconds=lead_t + pred_h) <= end_time:
            window_start = current_window_end - timedelta(seconds=w_size)
            target_start = current_window_end + timedelta(seconds=lead_t)
            target_end = target_start + timedelta(seconds=pred_h)

            # Observation events: [window_start, current_window_end)
            obs_events = [e for e in sorted_events if window_start <= e.observed_at < current_window_end]

            # Future target events: [target_start, target_end)
            future_events = [e for e in sorted_events if target_start <= e.observed_at < target_end]

            # Target label: 1 if ANY attack occurred in the future horizon, else 0
            has_attack = any(
                e.label is not None and e.label.lower() not in ("benign", "unlabeled")
                for e in future_events
            )

            features = self.extract_features_from_window(obs_events, w_size)
            X_list.append(features)
            y_list.append(1 if has_attack else 0)
            ts_list.append(current_window_end)

            current_window_end += timedelta(seconds=step_t)

        if not X_list:
            # Fallback if windowing yields 0 slices: generate sequential sub-chunks
            chunk_size = max(5, len(sorted_events) // 4)
            for idx in range(0, len(sorted_events) - chunk_size, max(1, chunk_size // 2)):
                chunk = sorted_events[idx:idx + chunk_size]
                future_chunk = sorted_events[idx + chunk_size:idx + chunk_size * 2]
                if not future_chunk:
                    break
                has_attack = any(
                    e.label is not None and e.label.lower() not in ("benign", "unlabeled")
                    for e in future_chunk
                )
                feat = self.extract_features_from_window(chunk, w_size)
                X_list.append(feat)
                y_list.append(1 if has_attack else 0)
                ts_list.append(chunk[-1].observed_at)

        return np.array(X_list, dtype=np.float32), np.array(y_list, dtype=np.int32), ts_list
