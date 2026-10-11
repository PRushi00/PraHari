#!/usr/bin/env python3
"""
PraHari — Live Data Streamer & Threat Checker

Demonstrates how live network telemetry (Zeek logs, Suricata events, or raw flows)
can be fed into PraHari in real time, and immediately checked for:
  1. Canonical schema validation and rejection accounting
  2. Data quality warnings (anomalous ports, missing fields, timestamp uncertainty)
  3. Real-time incident propensity forecasting using trained ML models
"""

import argparse
import json
import sys
import time
from datetime import datetime, timezone
import urllib.request
import urllib.error

BASE_URL = "http://127.0.0.1:8000/api/v1"


def post_json(endpoint: str, payload: dict) -> dict:
    url = f"{BASE_URL}{endpoint}"
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8")
        print(f"[ERROR] HTTP {e.code}: {err_body}", file=sys.stderr)
        raise
    except urllib.error.URLError as e:
        print(f"[ERROR] Connection failed: {e.reason}. Is PraHari server running on {BASE_URL}?", file=sys.stderr)
        sys.exit(1)


def simulate_live_stream(source_id: str = "live_network_probe", interval: float = 1.0, count: int = 10):
    print(f"\n==================================================================")
    print(f"  PraHari Live Telemetry Streamer & Real-Time Threat Evaluator")
    print(f"  Streaming to: {BASE_URL}")
    print(f"  Sensor ID:    {source_id}")
    print(f"==================================================================\n")

    # Sample benign and attack flow patterns (Zeek format)
    scenarios = [
        {"desc": "Normal HTTPS browsing", "proto": "tcp", "src": "192.168.1.55", "dst": "142.250.190.46", "sport": 51234, "dport": 443, "dur": 0.25, "bytes": 4500},
        {"desc": "Internal DNS query", "proto": "udp", "src": "192.168.1.55", "dst": "10.0.0.10", "sport": 54321, "dport": 53, "dur": 0.01, "bytes": 128},
        {"desc": "SSH Bastion access", "proto": "tcp", "src": "192.168.1.10", "dst": "10.0.0.5", "sport": 49000, "dport": 22, "dur": 1.5, "bytes": 8200},
        {"desc": "Suspicious Port Scan probe", "proto": "tcp", "src": "198.51.100.22", "dst": "10.0.0.1", "sport": 60001, "dport": 8080, "dur": 0.001, "bytes": 64},
        {"desc": "Brute Force SSH attempt", "proto": "tcp", "src": "198.51.100.22", "dst": "10.0.0.5", "sport": 60002, "dport": 22, "dur": 0.05, "bytes": 520},
        {"desc": "Heavy Web API download", "proto": "tcp", "src": "192.168.1.72", "dst": "10.0.0.1", "sport": 52100, "dport": 443, "dur": 0.8, "bytes": 65000},
    ]

    for i in range(count):
        item = scenarios[i % len(scenarios)]
        flow_line = json.dumps({
            "ts": time.time(),
            "uid": f"C_stream_{int(time.time()*1000)}_{i}",
            "id.orig_h": item["src"],
            "id.orig_p": item["sport"],
            "id.resp_h": item["dst"],
            "id.resp_p": item["dport"],
            "proto": item["proto"],
            "duration": item["dur"],
            "orig_bytes": item["bytes"] // 2,
            "resp_bytes": item["bytes"] // 2,
            "conn_state": "SF" if "probe" not in item["desc"] else "REJ",
        })

        print(f"[{datetime.now().strftime('%H:%M:%S')}] Ingesting Flow #{i+1}: {item['desc']} ({item['src']} -> {item['dst']}:{item['dport']})")

        # Step 1: Ingest live NDJSON line
        ingest_res = post_json("/stream/ingest/ndjson", {
            "source_id": source_id,
            "source_name": "Live Network Ingest Probe",
            "format": "zeek",
            "ndjson_content": flow_line,
        })

        accepted = ingest_res.get("accepted_records", 0)
        rejected = ingest_res.get("rejected_records", 0)
        print(f"   └─ Validation Check: {accepted} Accepted, {rejected} Rejected.")

        # Step 2: Instant Retrospective Forecast Check
        try:
            pred_res = post_json("/forecast/predict", {
                "source_id": source_id,
                "model_id": "random_forest_forecaster",
                "threshold": 0.5,
            })
            score = pred_res.get("propensity_score", 0.0)
            is_incident = pred_res.get("predicted_incident", False)
            status_tag = "[ALERT: INCIDENT IMMINENT]" if is_incident else "[BENIGN NORMAL]"
            color = "\033[91m" if is_incident else "\033[92m"
            reset = "\033[0m"

            print(f"   └─ Causal ML Propensity Check: {color}{status_tag} Score: {score*100:.1f}%\n"
                  f"      Model: {pred_res.get('model_name')}, Horizon: {pred_res.get('horizon_seconds', 60)}s{reset}")

            top_features = pred_res.get("top_contributing_features", [])[:2]
            if top_features:
                feat_strs = [f"{f['feature']}={f['value']:.1f} (impact {f['contribution']:.3f})" for f in top_features]
                print(f"      Top Signals: {', '.join(feat_strs)}")

        except Exception:
            print("   └─ ML Forecaster Note: Train benchmark in dashboard to enable live propensity scoring.")

        print()
        time.sleep(interval)

    print("Live stream session completed. Check PraHari SOC Dashboard at http://127.0.0.1:8000/ to view full analytics.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Stream live telemetry into PraHari Sentinel")
    parser.add_argument("--source", default="live_soc_stream", help="Sensor Source ID")
    parser.add_argument("--interval", type=float, default=1.5, help="Seconds between live flows")
    parser.add_argument("--count", type=int, default=8, help="Number of flows to send")
    args = parser.parse_args()

    simulate_live_stream(source_id=args.source, interval=args.interval, count=args.count)
