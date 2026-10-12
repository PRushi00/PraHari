#!/usr/bin/env python3
"""
PraHari — Application-Layer Contract Verifier (SIMULATED producer)

Posts the exact payload shape that `extension/background.js` builds, so the
application-layer path can be exercised end to end without installing a
browser extension.

================================================================
  THIS IS NOT A BROWSER. The records are synthesised by this
  script to match the extension's envelope byte-for-byte.

  Passing this script verifies the INTEGRATION CONTRACT:
  ingestion, validation, privacy stripping, persistence, and
  retrieval through the events API.

  It does NOT verify that a real browser produces this data.
  That requires installing the extension (see extension/README.md),
  which is an explicit user action.
================================================================

Usage (with PraHari running and app-layer ingest enabled):
    python scripts/simulate_browser_producer.py
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

DEFAULT_BASE = "http://127.0.0.1:8000"
SOURCE_ID = "browser_probe_simulated"

PASS, FAIL, INFO = "[PASS]", "[FAIL]", "[INFO]"
_failures: list[str] = []


def _request(base: str, path: str, method: str = "GET", payload: dict | None = None):
    url = f"{base}/api/v1{path}"
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(
        url, data=data, method=method,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = resp.read().decode()
            return resp.status, (json.loads(body) if body else None)
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        try:
            return e.code, json.loads(body)
        except json.JSONDecodeError:
            return e.code, {"raw": body[:400]}
    except urllib.error.URLError as e:
        print(f"{FAIL} Cannot reach PraHari at {url}: {e.reason}")
        sys.exit(2)


def check(label: str, ok: bool, detail: str = "") -> bool:
    print(f"{PASS if ok else FAIL} {label}" + (f" — {detail}" if detail else ""))
    if not ok:
        _failures.append(label)
    return ok


def section(title: str) -> None:
    print(f"\n{'=' * 72}\n  {title}\n{'=' * 72}")


# Records shaped exactly as extension/background.js emits them.
def _records(now: datetime) -> list[dict]:
    return [
        {
            "observed_at": (now - timedelta(seconds=30)).isoformat(),
            "method": "GET",
            "url": "https://docs.example.com/guide/getting-started",
            "status_code": 200,
            "duration_ms": 142,
            "dst_ip": "93.184.216.34",
            "dst_port": 443,
        },
        {
            "observed_at": (now - timedelta(seconds=20)).isoformat(),
            "method": "POST",
            "url": "https://api.example.com/v1/items",
            "status_code": 201,
            "duration_ms": 88,
            "dst_ip": "93.184.216.35",
            "dst_port": 443,
        },
        {
            "observed_at": (now - timedelta(seconds=10)).isoformat(),
            "method": "GET",
            "url": "https://cdn.example.net/assets/app.js",
            "status_code": 404,
            "duration_ms": 31,
            "dst_ip": "93.184.216.36",
            "dst_port": 443,
        },
        {
            # onErrorOccurred: the browser reports NO status.
            "observed_at": (now - timedelta(seconds=5)).isoformat(),
            "method": "GET",
            "url": "https://unreachable.example.org/ping",
            "status_code": None,
            "duration_ms": None,
            "dst_ip": None,
            "dst_port": 443,
        },
    ]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url", default=DEFAULT_BASE)
    args = ap.parse_args()
    base = args.base_url.rstrip("/")

    print("PraHari — Application-Layer Contract Verifier (SIMULATED producer)")
    print("NOTE: records are synthesised to match the extension envelope.")
    print("      This verifies the contract, NOT real browser collection.")
    print(f"Target: {base}")

    section("1. Ingestion state")
    status, al = _request(base, "/applayer/status")
    check("Application-layer status responds 200", status == 200)
    if status != 200:
        return 1
    if not al.get("enabled"):
        print(f"{FAIL} Ingestion is disabled.")
        print(f"{INFO} Enable it and restart PraHari:")
        print(f"{INFO}   set PRAHARI_ENABLE_APPLICATION_LAYER_INGEST=true")
        return 1
    check("Ingestion enabled", True)
    check(
        "Sensitive fields are declared never-accepted",
        "body" in al["never_accepted"] and "cookies" in al["never_accepted"],
    )

    section("2. Posting the extension's exact payload")
    now = datetime.now(timezone.utc)
    records = _records(now)
    status, summary = _request(
        base, "/applayer/ingest", method="POST",
        payload={
            "source_id": SOURCE_ID,
            "source_name": "Browser Telemetry Probe (SIMULATED)",
            "producer": "browser-extension-simulated",
            "records": records,
        },
    )
    if not check("Ingest accepted", status == 200, f"HTTP {status}"):
        print(json.dumps(summary, indent=2)[:600])
        return 1
    check(
        "All records accepted",
        summary["accepted_records"] == len(records),
        f"{summary['accepted_records']}/{len(records)}",
    )
    check("Categorised as live telemetry", summary["data_category"] == "live_telemetry")

    section("3. Privacy enforcement")
    status, qs = _request(
        base, "/applayer/ingest", method="POST",
        payload={
            "source_id": SOURCE_ID,
            "producer": "browser-extension-simulated",
            "records": [{
                "observed_at": now.isoformat(),
                "method": "GET",
                "url": "https://search.example.com/results?q=private+terms&token=secret123",
                "status_code": 200,
            }],
        },
    )
    check("Query-string record accepted", status == 200)

    status, page = _request(base, f"/events?source_id={SOURCE_ID}&limit=100")
    stored = page["events"] if status == 200 else []
    paths = [e.get("http_path") or "" for e in stored]
    check(
        "Query strings stripped before storage",
        all("q=" not in p and "secret123" not in p for p in paths),
    )

    for forbidden in ("cookies", "authorization", "request_body", "headers"):
        status_f, _ = _request(
            base, "/applayer/ingest", method="POST",
            payload={
                "source_id": SOURCE_ID,
                "producer": "browser-extension-simulated",
                "records": [{
                    "observed_at": now.isoformat(), "method": "POST",
                    "url": "https://example.com/login", forbidden: "sensitive",
                }],
            },
        )
        check(f"Producer sending '{forbidden}' is rejected", status_f == 422, f"HTTP {status_f}")

    section("4. Persistence and provenance")
    check("HTTP events retrievable", len(stored) > 0, f"{len(stored)} stored")
    if stored:
        check(
            "Typed as http_request",
            all(e["event_type"] == "http_request" for e in stored),
        )
        check(
            "Hostname reported by the producer",
            all(e.get("dst_hostname") for e in stored),
        )
        statuses = [e.get("http_status_code") for e in stored]
        check("Observed status codes preserved", 200 in statuses and 404 in statuses)
        check(
            "Failed request stored with NO fabricated status",
            any(s is None for s in statuses),
        )

    section("5. Separation from connection telemetry")
    status, http_page = _request(base, "/events?event_type=http_request&limit=1")
    status2, conn_page = _request(base, "/events?event_type=connection&limit=1")
    if status == 200 and status2 == 200:
        check(
            "HTTP and connection events counted separately",
            http_page["total"] > 0 and http_page["total"] != conn_page["total"],
            f"http={http_page['total']} connection={conn_page['total']}",
        )
    status, caps = _request(base, "/events/capabilities")
    if status == 200:
        by_type = {c["source_type"]: c for c in caps}
        if "windows_connection_table" in by_type:
            check(
                "Connection table still declares HTTP unsupported",
                by_type["windows_connection_table"]["fields"]["http_status_code"]
                == "unsupported_by_source",
            )

    section("Summary")
    if _failures:
        print(f"{FAIL} {len(_failures)} check(s) failed:")
        for f in _failures:
            print(f"        - {f}")
        return 1
    print(f"{PASS} All contract checks passed.")
    print()
    print(f"{INFO} VERIFIED: the application-layer ingestion contract, privacy")
    print(f"{INFO}   enforcement, persistence and provenance separation.")
    print(f"{INFO} NOT VERIFIED: that a real browser produces this data. That")
    print(f"{INFO}   requires installing extension/ — see extension/README.md.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
