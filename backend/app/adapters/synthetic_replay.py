"""
PraHari — Synthetic Generator & Flow Replay Engine

Generates controlled, deterministic telemetry streams for offline evaluation,
load testing, and demonstration without requiring live packet sniffing.
All generated records are explicitly tagged as DataCategory.SYNTHETIC.
"""

from __future__ import annotations

import random
import uuid
from datetime import datetime, timezone, timedelta
from typing import Generator

from app.schemas.events import (
    SCHEMA_VERSION,
    DataCategory,
    EventType,
    LabelProvenance,
    NormalizedEvent,
    QualityFlag,
)


class SyntheticFlowGenerator:
    """
    Deterministic flow generator simulating multi-stage attack scenarios
    interleaved with normal enterprise background network activity.
    """

    def __init__(self, seed: int = 42, source_id: str = "synthetic_replay_engine"):
        self.rng = random.Random(seed)
        self.source_id = source_id

        # Simulated internal subnet
        self.internal_ips = [f"192.168.1.{i}" for i in range(10, 50)]
        self.dmz_servers = {
            "10.0.0.1": 443,   # Web Portal (HTTPS)
            "10.0.0.2": 80,    # Static Site (HTTP)
            "10.0.0.5": 22,    # Bastion Host (SSH)
            "10.0.0.10": 53,   # Internal DNS
            "10.0.0.20": 21,   # Legacy FTP Server
        }
        self.external_benign_ips = ["8.8.8.8", "1.1.1.1", "93.184.216.34", "151.101.1.140"]
        self.attacker_ips = ["198.51.100.22", "198.51.100.35", "203.0.113.88"]

    def generate_scenario_batch(
        self,
        count: int = 100,
        start_time: datetime | None = None,
        attack_ratio: float = 0.2,
    ) -> list[NormalizedEvent]:
        """
        Generate a chronological batch of synthetic network flow events.
        """
        current_time = start_time or datetime.now(timezone.utc) - timedelta(minutes=count)
        events: list[NormalizedEvent] = []

        for i in range(count):
            current_time += timedelta(seconds=self.rng.randint(1, 5))
            is_attack = self.rng.random() < attack_ratio

            if is_attack:
                attack_type = self.rng.choice(["SSH-BruteForce", "PortScan", "DoS-Hulk", "FTP-BruteForce"])
                event = self._generate_attack_event(current_time, attack_type, i)
            else:
                event = self._generate_benign_event(current_time, i)

            events.append(event)

        return events

    def _generate_benign_event(self, observed_at: datetime, index: int) -> NormalizedEvent:
        src = self.rng.choice(self.internal_ips)
        dst_ip, dst_port = self.rng.choice(list(self.dmz_servers.items()))
        src_port = self.rng.randint(32768, 61000)
        proto = "TCP" if dst_port != 53 else "UDP"
        duration = round(self.rng.uniform(10_000, 2_000_000), 2)  # microseconds
        packets = self.rng.randint(4, 40)
        bytes_total = packets * self.rng.randint(64, 1400)

        return NormalizedEvent(
            event_id=str(uuid.uuid4()),
            schema_version=SCHEMA_VERSION,
            source_id=self.source_id,
            data_category=DataCategory.SYNTHETIC,
            observed_at=observed_at,
            event_type=EventType.NETWORK_FLOW,
            src_ip=src,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=proto,
            duration=duration,
            packets=packets,
            bytes_total=bytes_total,
            label="Benign",
            label_provenance=LabelProvenance.SYNTHETIC_RULE,
            quality_flags=[QualityFlag.SYNTHETIC_SAMPLE],
            raw_reference=f"synthetic:benign:{index}",
        )

    def _generate_attack_event(self, observed_at: datetime, attack_type: str, index: int) -> NormalizedEvent:
        attacker = self.rng.choice(self.attacker_ips)

        if attack_type == "SSH-BruteForce":
            dst_ip = "10.0.0.5"
            dst_port = 22
            src_port = self.rng.randint(40000, 60000)
            duration = round(self.rng.uniform(300_000, 800_000), 2)
            packets = 6
            bytes_total = 1200
        elif attack_type == "PortScan":
            dst_ip = "10.0.0.1"
            dst_port = self.rng.choice([21, 22, 23, 25, 80, 443, 8080, 8443, 3389])
            src_port = self.rng.randint(50000, 65000)
            duration = round(self.rng.uniform(1000, 20_000), 2)
            packets = 2
            bytes_total = 128
        elif attack_type == "DoS-Hulk":
            dst_ip = "10.0.0.1"
            dst_port = 443
            src_port = self.rng.randint(1024, 65535)
            duration = round(self.rng.uniform(10_000, 50_000), 2)
            packets = self.rng.randint(1, 3)
            bytes_total = 64 * packets
        else:  # FTP-BruteForce
            dst_ip = "10.0.0.20"
            dst_port = 21
            src_port = self.rng.randint(40000, 60000)
            duration = round(self.rng.uniform(200_000, 400_000), 2)
            packets = 5
            bytes_total = 800

        return NormalizedEvent(
            event_id=str(uuid.uuid4()),
            schema_version=SCHEMA_VERSION,
            source_id=self.source_id,
            data_category=DataCategory.SYNTHETIC,
            observed_at=observed_at,
            event_type=EventType.NETWORK_FLOW,
            src_ip=attacker,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol="TCP",
            duration=duration,
            packets=packets,
            bytes_total=bytes_total,
            label=attack_type,
            label_provenance=LabelProvenance.SYNTHETIC_RULE,
            quality_flags=[QualityFlag.SYNTHETIC_SAMPLE],
            raw_reference=f"synthetic:{attack_type.lower()}:{index}",
        )
