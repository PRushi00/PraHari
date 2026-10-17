#!/usr/bin/env python3
"""
PraHari — SYNTHETIC Telemetry Stream Simulator  (NOT live telemetry)

Feeds hand-written, fabricated Zeek-style flow records into PraHari's NDJSON
ingestion endpoint. Its purpose is to exercise the ingestion, validation and
accounting path without needing a network sensor.

================================================================
  THIS SCRIPT DOES NOT OBSERVE ANY REAL NETWORK ACTIVITY.
  Records are invented by this file. They are ingested under the
  'synthetic_demo' data category and a source id that identifies
  them as simulated, so they can never be mistaken for, or mixed
  into, genuine telemetry.

  For GENUINE network telemetry from this Windows host, use the
  live collector instead:
      POST /api/v1/collector/start
      python scripts/verify_live_windows_telemetry.py
================================================================

Usage (with PraHari running):
    python scripts/simulate_synthetic_stream.py --count 8
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

BASE_URL = "http://127.0.0.1:8000/api/v1"

# Source id and name both state plainly what this is.
DEFAULT_SOURCE_ID = "synthetic_stream_simulator"
DEFAULT_SOURCE_NAME = "Synthetic Stream Simulator (fabricated records)"


def post_json(endpoint: str, payload: dict) -> dict:
    url = f"{BASE_URL}{endpoint}"
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8")
        print(f"[ERROR] HTTP {e.code}: {body[:400]}", file=sys.stderr)
        raise
    except urllib.error.URLError as e:
        print(
            f"[ERROR] Connection failed: {e.reason}. Is PraHari running at {BASE_URL}?",
            file=sys.stderr,
        )
        raise
        sys.exit(1)


# Fabricated scenarios. These are authored examples, not observations.
SCENARIOS = [
    {"desc": "HTTPS session (fabricated)", "proto": "tcp", "src": "192.168.1.55", "dst": "142.250.190.46", "sport": 51234, "dport": 443, "dur": 0.25, "bytes": 4500},
    {"desc": "DNS query (fabricated)", "proto": "udp", "src": "192.168.1.55", "dst": "10.0.0.10", "sport": 54321, "dport": 53, "dur": 0.01, "bytes": 128},
    {"desc": "SSH session (fabricated)", "proto": "tcp", "src": "192.168.1.10", "dst": "10.0.0.5", "sport": 49000, "dport": 22, "dur": 1.5, "bytes": 8200},
    {"desc": "Port-scan-shaped probe (fabricated)", "proto": "tcp", "src": "198.51.100.22", "dst": "10.0.0.1", "sport": 60001, "dport": 8080, "dur": 0.001, "bytes": 64},
    {"desc": "Repeated-auth-shaped flow (fabricated)", "proto": "tcp", "src": "198.51.100.22", "dst": "10.0.0.5", "sport": 60002, "dport": 22, "dur": 0.05, "bytes": 520},
    {"desc": "Bulk download (fabricated)", "proto": "tcp", "src": "192.168.1.72", "dst": "10.0.0.1", "sport": 52100, "dport": 443, "dur": 0.8, "bytes": 65000},
]


def run_simulation(source_id: str, interval: float, count: int, with_forecast: bool) -> int:
    print("=" * 70)
    print("  PraHari — SYNTHETIC Telemetry Stream Simulator")
    print("=" * 70)
    print("  WARNING: These records are FABRICATED by this script.")
    print("           They are NOT observations of real network activity.")
    print("           They are ingested as data_category='synthetic_demo'.")
    print(f"  Target:    {BASE_URL}")
    print(f"  Source id: {source_id}")
    print("=" * 70)
    print()

    total_accepted = 0
    total_rejected = 0

    for i in range(count):
        item = SCENARIOS[i % len(SCENARIOS)]
        flow_line = json.dumps(
            {
                "ts": time.time(),
                "uid": f"SYNTHETIC_{int(time.time() * 1000)}_{i}",
                "id.orig_h": item["src"],
                "id.orig_p": item["sport"],
                "id.resp_h": item["dst"],
                "id.resp_p": item["dport"],
                "proto": item["proto"],
                "duration": item["dur"],
                "orig_bytes": item["bytes"] // 2,
                "resp_bytes": item["bytes"] // 2,
                "conn_state": "SF" if "probe" not in item["desc"] else "REJ",
            }
        )

        ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
        print(f"[{ts}] Record #{i + 1}: {item['desc']}")
        print(f"         {item['src']} -> {item['dst']}:{item['dport']}")

        result = post_json(
            "/stream/ingest/ndjson",
            {
                "source_id": source_id,
                "source_name": DEFAULT_SOURCE_NAME,
                "ndjson_content": flow_line,
                # Explicitly categorised as synthetic so analytics and the
                # dashboard keep it separate from live telemetry.
                "data_category": "synthetic_demo",
            },
        )

        accepted = result.get("accepted_records", 0)
        rejected = result.get("rejected_records", 0)
        total_accepted += accepted
        total_rejected += rejected
        print(f"         Validation: {accepted} accepted, {rejected} rejected")

        if with_forecast:
            _print_forecast(source_id)

        print()
        if i + 1 < count:
            time.sleep(interval)

    print("-" * 70)
    print(f"Simulation complete: {total_accepted} accepted, {total_rejected} rejected.")
    print("These records are synthetic and are labelled as such in the database.")
    print("For genuine host telemetry, start the live collector:")
    print("    curl -X POST http://127.0.0.1:8000/api/v1/collector/start \\")
    print('         -H "Content-Type: application/json" -d \'{"interval_seconds":15}\'')
    return 0


def _print_forecast(source_id: str) -> None:
    """
    Show the model's output together with its validation status.

    A propensity score is never announced as an imminent incident: unless the
    model was evaluated on a leakage-free holdout containing positive
    examples, the number carries no demonstrated predictive meaning.
    """
    try:
        pred = post_json(
            "/forecast/predict",
            {
                "source_id": source_id,
                "model_id": "random_forest_forecaster",
                "threshold": 0.5,
            },
        )
    except Exception:
        print("         Forecast: unavailable (no model trained).")
        return

    score = pred.get("propensity_score", 0.0)
    validated = pred.get("is_validated_model", False)
    status = pred.get("validation_status", "unknown")

    print(f"         Propensity score: {score * 100:.1f}%  (model status: {status})")
    if not validated:
        print("         NOTE: UNVALIDATED output — this is not a forecast and does")
        print("               not indicate that an attack will occur.")
        for caveat in pred.get("evaluation_caveats", [])[:2]:
            print(f"               - {caveat}")
    else:
        print("         Model evaluated on a purged chronological holdout.")
        print("         Treat as a triage indicator, not a confirmed attack.")

    for feat in pred.get("top_contributing_features", [])[:2]:
        # The API field is 'impact'; a previous version read a non-existent
        # 'contribution' key and raised KeyError here.
        print(
            f"         Signal: {feat['feature']}={feat['value']} "
            f"(impact {feat['impact']})"
        )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Ingest SYNTHETIC (fabricated) telemetry into PraHari. "
                    "This does not observe real network activity."
    )
    parser.add_argument(
        "--base-url",
        default="http://127.0.0.1:8000",
        help="PraHari server to send to (default: http://127.0.0.1:8000)",
    )
    parser.add_argument("--source", default=DEFAULT_SOURCE_ID, help="Synthetic source id")
    parser.add_argument("--interval", type=float, default=1.5, help="Seconds between records")
    parser.add_argument("--count", type=int, default=8, help="Number of records to send")
    parser.add_argument(
        "--with-forecast",
        action="store_true",
        help="Also query the forecaster and print its validation status",
    )
    args = parser.parse_args()
    global BASE_URL
    BASE_URL = args.base_url.rstrip("/") + "/api/v1"

    if not args.source.startswith(("synthetic", "test", "sim")):
        print(
            f"[ERROR] Refusing source id '{args.source}': synthetic records must use a "
            "source id beginning with 'synthetic', 'sim' or 'test' so they cannot be "
            "mistaken for a live telemetry source.",
            file=sys.stderr,
        )
        return 2

    try:
        return run_simulation(args.source, args.interval, args.count, args.with_forecast)
    except urllib.error.URLError:
        return 1  # the reason was printed where it happened


if __name__ == "__main__":
    sys.exit(main())
