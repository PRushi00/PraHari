"""
PraHari — Operational acceptance for ingestion (blueprint §16, ADR-110).

§16 requires that, **before claiming a supported live integration**, an
operator record: measured event rate, ingestion delay distribution,
processing delay, queue behaviour, dropped or rejected records, reconnect
behaviour, resource consumption, and the duration and environment of the
test. None of that had ever been measured, so `BLUEPRINT_COVERAGE.md`
carried §16 as `PARTIAL — no ingestion benchmark`.

This drives the real ingestion API over loopback with synthetic NDJSON
and records exactly those figures.

What this is, stated plainly
----------------------------
A **load measurement of this machine**, not a service target. §16 is
explicit that numerical targets are agreed only *after* measurement, and
nothing here is published as a promise. A figure from a development
container with a loopback socket and a local SQLite file says nothing
about a deployment on other hardware, over a network, against
PostgreSQL.

It is also synthetic load: records are generated here, so this measures
PraHari's ingestion path and not any real sensor's behaviour. The
`reconnect` probe is a deliberate connection failure against a closed
port, which exercises the client's retry, not a sensor's.

Honesty rules it follows
------------------------
* Every number is measured in this run. Nothing is extrapolated — a rate
  is events divided by the wall clock it actually took.
* Server-side counters are read from `/system/health` BEFORE and AFTER,
  and the delta is reported beside the client's own count. If the two
  disagree, that disagreement is the finding, and it is printed rather
  than reconciled away.
* Latency percentiles use the same nearest-rank definition as
  `services/admission.py`, so the client's view and the server's are
  comparable.
* Rejected and duplicate records are reported separately from accepted
  ones: deduplication is not a failure and must not be counted as one.

Usage:
    python scripts/benchmark_ingestion.py --url http://127.0.0.1:8099 \
        --batches 40 --batch-size 250 --concurrency 4
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import socket
import statistics
import sys
import threading
from typing import Optional
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

# Resource sampling needs psutil, which is NOT a runtime dependency of
# PraHari and is not added as one: §9.2 prefers small dependencies until
# a measured need justifies more, and this need is a verification tool's,
# not the application's. Absent, resource use is reported as UNMEASURED
# with the reason — never estimated, and never silently omitted.
try:
    import psutil  # type: ignore
except ImportError:  # pragma: no cover - depends on the environment
    psutil = None  # type: ignore

BENCH_SOURCE = "benchmark_ingestion_synthetic"


def _percentiles(samples_ms: list[float]) -> dict:
    if not samples_ms:
        return {"samples": 0, "p50_ms": None, "p95_ms": None, "p99_ms": None,
                "max_ms": None, "min_ms": None}
    ordered = sorted(samples_ms)

    def pct(p: float) -> float:
        idx = min(len(ordered) - 1, int(round((len(ordered) - 1) * p)))
        return round(ordered[idx], 3)

    return {
        "samples": len(ordered),
        "min_ms": round(ordered[0], 3),
        "p50_ms": pct(0.50),
        "p95_ms": pct(0.95),
        "p99_ms": pct(0.99),
        "max_ms": round(ordered[-1], 3),
    }


def _server_pid_on(port: int) -> Optional[int]:
    """The PID listening on `port`, or None. Resource use must describe
    the SERVER, not this benchmark process."""
    if psutil is None:
        return None
    try:
        for conn in psutil.net_connections(kind="inet"):
            if conn.laddr and conn.laddr.port == port and conn.pid:
                return conn.pid
    except (psutil.AccessDenied, PermissionError):
        return None
    return None


class _ResourceSampler(threading.Thread):
    """Samples the server process while the load runs."""

    def __init__(self, pid: Optional[int], interval: float = 0.05):
        super().__init__(daemon=True)
        self.pid = pid
        self.interval = interval
        self.rss_mb: list[float] = []
        self.cpu_pct: list[float] = []
        self._stop = threading.Event()
        self.reason: Optional[str] = None

    def run(self) -> None:
        if psutil is None:
            self.reason = (
                "psutil is not installed, so resource use was not sampled. "
                "Install it (pip install psutil) and re-run to measure it."
            )
            return
        if self.pid is None:
            self.reason = (
                "The server process could not be identified from its port "
                "(it may be in another container or namespace), so resource "
                "use was not sampled."
            )
            return
        try:
            proc = psutil.Process(self.pid)
            proc.cpu_percent(None)  # prime the interval
            while not self._stop.is_set():
                self.rss_mb.append(proc.memory_info().rss / (1024 * 1024))
                self.cpu_pct.append(proc.cpu_percent(None))
                self._stop.wait(self.interval)
        except Exception as exc:  # noqa: BLE001
            self.reason = f"sampling stopped: {type(exc).__name__}: {exc}"

    def stop(self) -> None:
        self._stop.set()

    def summary(self) -> dict:
        if not self.rss_mb:
            return {"available": False, "reason": self.reason or "no samples taken"}
        busy = [c for c in self.cpu_pct if c > 0]
        return {
            "available": True,
            "pid": self.pid,
            "samples": len(self.rss_mb),
            "sample_interval_seconds": self.interval,
            "rss_mb_start": round(self.rss_mb[0], 1),
            "rss_mb_peak": round(max(self.rss_mb), 1),
            "rss_mb_end": round(self.rss_mb[-1], 1),
            "rss_mb_growth": round(self.rss_mb[-1] - self.rss_mb[0], 1),
            "cpu_percent_peak": round(max(self.cpu_pct), 1),
            "cpu_percent_mean_while_busy": (
                round(sum(busy) / len(busy), 1) if busy else None
            ),
            "note": (
                "Of the SERVER process only, sampled during the load. "
                "cpu_percent can exceed 100 on a multi-core host. Growth is "
                "end minus start over one short run and is not evidence "
                "about a leak."
            ),
        }


def _post(url: str, payload: dict, timeout: float = 60.0) -> tuple[int, dict, float]:
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url, data=body, headers={"Content-Type": "application/json"}, method="POST"
    )
    started = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            elapsed = (time.perf_counter() - started) * 1000.0
            return resp.status, json.loads(resp.read() or b"{}"), elapsed
    except urllib.error.HTTPError as exc:
        elapsed = (time.perf_counter() - started) * 1000.0
        try:
            detail = json.loads(exc.read() or b"{}")
        except Exception:  # noqa: BLE001
            detail = {}
        return exc.code, detail, elapsed


def _get(url: str, timeout: float = 30.0) -> dict:
    with urllib.request.urlopen(url, timeout=timeout) as resp:
        return json.loads(resp.read() or b"{}")


def _batch(seq: int, size: int, base: datetime, nonce: str) -> dict:
    """
    One NDJSON batch of Zeek-shaped records with distinct identities.

    `nonce` makes identities unique PER RUN. Without it a second run
    re-offers the first run's records, they deduplicate correctly, and
    the report shows "0 stored" — which looks identical to a run that
    failed. Deduplication working is not a failure, and the two causes
    must not be confusable.
    """
    lines = []
    for i in range(size):
        n = seq * size + i
        ts = base + timedelta(milliseconds=n * 7)
        lines.append(json.dumps({
            "ts": ts.timestamp(),
            "uid": f"bench-{nonce}-{seq}-{i}",
            "id.orig_h": f"10.1.{(n // 254) % 254}.{n % 254 + 1}",
            "id.orig_p": 40000 + (n % 20000),
            "id.resp_h": f"93.184.{(n // 254) % 254}.{n % 254 + 1}",
            "id.resp_p": 443,
            "proto": "tcp",
            "duration": 0.25,
            "orig_bytes": 512,
            "resp_bytes": 1024,
        }))
    return {
        "source_id": BENCH_SOURCE,
        "data_category": "synthetic_demo",
        "ndjson_content": "\n".join(lines),
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://127.0.0.1:8099")
    ap.add_argument("--batches", type=int, default=40)
    ap.add_argument("--batch-size", type=int, default=250)
    ap.add_argument("--concurrency", type=int, default=4)
    ap.add_argument("--out", default="")
    args = ap.parse_args()

    base = args.url.rstrip("/")
    ingest_url = f"{base}/api/v1/stream/ingest/ndjson"
    health_url = f"{base}/api/v1/system/health"

    try:
        before = _get(health_url)
    except Exception as exc:  # noqa: BLE001
        print(f"Cannot reach {health_url}: {exc}", file=sys.stderr)
        return 2

    nonce = f"{int(time.time())%100000:05d}"
    t0 = datetime(2026, 1, 1, tzinfo=timezone.utc)
    total_records = args.batches * args.batch_size

    latencies: list[float] = []
    statuses: dict[int, int] = {}
    accepted = stored = rejected = duplicates = 0

    print(
        f"Ingesting {total_records} records in {args.batches} batches of "
        f"{args.batch_size}, concurrency {args.concurrency}…"
    )
    port = int(base.rsplit(":", 1)[-1].split("/")[0]) if ":" in base else 80
    sampler = _ResourceSampler(_server_pid_on(port))
    sampler.start()
    run_started = time.perf_counter()
    with ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        futures = [
            pool.submit(_post, ingest_url, _batch(i, args.batch_size, t0, nonce))
            for i in range(args.batches)
        ]
        for fut in futures:
            status, body, ms = fut.result()
            latencies.append(ms)
            statuses[status] = statuses.get(status, 0) + 1
            if status == 200:
                accepted += int(body.get("accepted_records", 0) or 0)
                stored += int(body.get("stored_records", body.get("accepted_records", 0)) or 0)
                rejected += int(body.get("rejected_records", 0) or 0)
                duplicates += int(body.get("duplicate_records", 0) or 0)
    wall_seconds = time.perf_counter() - run_started
    sampler.stop()
    sampler.join(timeout=2.0)

    after = _get(health_url)

    # Reconnect behaviour: a deliberate failure against a closed port.
    # This exercises the CLIENT's failure handling, not a sensor's.
    closed = socket.socket()
    closed.bind(("127.0.0.1", 0))
    dead_port = closed.getsockname()[1]
    closed.close()
    reconnect_ok = False
    reconnect_detail = ""
    try:
        _post(f"http://127.0.0.1:{dead_port}/api/v1/stream/ingest/ndjson",
              _batch(0, 1, t0, nonce), timeout=5.0)
        reconnect_detail = "the closed port accepted a request, which should not happen"
    except Exception as exc:  # noqa: BLE001
        reconnect_ok = True
        reconnect_detail = f"refused as expected ({type(exc).__name__})"
    # And the live endpoint still works afterwards.
    status_after, _, _ = _post(ingest_url, _batch(args.batches, 10, t0, nonce))
    recovered = status_after == 200

    ing_before = (before.get("ingestion") or {}).get("data") or {}
    ing_after = (after.get("ingestion") or {}).get("data") or {}

    def delta(key: str):
        a, b = ing_after.get(key), ing_before.get(key)
        if a is None or b is None:
            return None
        return a - b

    report = {
        "measured_at": datetime.now(timezone.utc).isoformat(),
        "what_this_is": (
            "A load measurement of THIS machine over loopback with synthetic "
            "records. Not a service target, and not a measurement of any real "
            "sensor. §16 agrees numerical targets only after measurement."
        ),
        "environment": {
            "platform": platform.platform(),
            "python": platform.python_version(),
            "cpu_count": os.cpu_count(),
            "url": base,
            "storage_backend": ((after.get("storage") or {}).get("data") or {}).get("backend"),
        },
        "load": {
            "batches": args.batches,
            "batch_size": args.batch_size,
            "concurrency": args.concurrency,
            "records_offered": total_records,
        },
        "duration_seconds": round(wall_seconds, 3),
        "event_rate": {
            "records_per_second": round(total_records / wall_seconds, 1) if wall_seconds else None,
            "stored_per_second": round(stored / wall_seconds, 1) if wall_seconds else None,
            "batches_per_second": round(args.batches / wall_seconds, 2) if wall_seconds else None,
        },
        "client_observed": {
            "accepted_records": accepted,
            "stored_records": stored,
            "rejected_records": rejected,
            "duplicate_records": duplicates,
            "http_status_counts": statuses,
            "request_latency": _percentiles(latencies),
        },
        "server_counters_delta": {
            "requests_admitted": delta("requests_admitted"),
            "requests_rejected_overloaded": delta("requests_rejected_overloaded"),
            "batches_completed": delta("batches_completed"),
            "batches_failed": delta("batches_failed"),
            "events_stored": delta("events_stored"),
            "events_duplicate": delta("events_duplicate"),
            "events_rejected": delta("events_rejected"),
            # NOT a delta: these are absolute, process-lifetime values.
            # peak_in_flight is a high-water mark since the server started,
            # so an earlier run's saturation still shows here. Labelled so
            # it is not read as this run's peak.
            "peak_in_flight_process_lifetime": ing_after.get("peak_in_flight"),
            "capacity": ing_after.get("capacity"),
            "queue_depth": ing_after.get("queue_depth"),
            "queue_depth_note": ing_after.get("queue_depth_note"),
            "processing_latency": ing_after.get("processing_latency"),
        },
        "resource_consumption": sampler.summary(),
        "reconnect": {
            "closed_port_refused": reconnect_ok,
            "detail": reconnect_detail,
            "live_endpoint_recovered": recovered,
        },
    }

    # The reconciliation is the point: if the client and the server
    # disagree about what was stored, that disagreement is the finding.
    server_stored = report["server_counters_delta"]["events_stored"]
    report["reconciles"] = (
        server_stored is not None and server_stored == stored
    )
    if not report["reconciles"]:
        report["reconciliation_note"] = (
            f"Client counted {stored} stored; the server's counter moved by "
            f"{server_stored}. Investigate before trusting either figure."
        )

    # A run that stored NOTHING still reconciles trivially (0 == 0) and
    # would print a throughput figure for work that never happened. That
    # is the fabricated measurement this project refuses, so it is a
    # failure with its own name rather than a quiet pass.
    # Overload rejection (503) is admission control working, and is one of
    # the things §16 asks to be measured — not a broken run. What IS broken
    # is a run where nothing was accepted and nothing was deliberately
    # refused, because then the rate figures describe errors.
    overloaded = statuses.get(503, 0)
    report["ingested_anything"] = stored > 0
    report["overload_measured"] = overloaded > 0
    report["usable"] = report["ingested_anything"] or report["overload_measured"]
    if not report["usable"]:
        report["failure"] = (
            f"No record was stored and nothing was refused for overload. "
            f"{total_records} offered, HTTP statuses {statuses}. The rate "
            "figures above describe failed requests and mean nothing."
        )
    elif not report["ingested_anything"]:
        report["note"] = (
            f"Nothing was stored because {overloaded} of {args.batches} "
            "requests were refused for overload. That is admission control "
            "working; the throughput figures describe offered load, not "
            "accepted work."
        )

    text = json.dumps(report, indent=2)
    print(text)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
        print(f"\nWritten to {args.out}")
    return 0 if (report["reconciles"] and report["usable"]) else 1


if __name__ == "__main__":
    sys.exit(main())
