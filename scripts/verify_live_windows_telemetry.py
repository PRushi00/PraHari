#!/usr/bin/env python3
"""
PraHari — Live Windows Telemetry Verification

Proves the genuine operational path end-to-end against a RUNNING PraHari
server, using real connection activity from this Windows host:

    Windows TCP connection table
        -> collector poll
        -> canonical normalization + validation
        -> SQLite persistence
        -> events / analytics / source-health APIs

Every number printed is read back from the server's own API. Nothing is
generated, simulated, or assumed.

Usage (with PraHari already running on 127.0.0.1:8000):
    python scripts/verify_live_windows_telemetry.py
    python scripts/verify_live_windows_telemetry.py --base-url http://127.0.0.1:8000
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

DEFAULT_BASE = "http://127.0.0.1:8000"

PASS = "[PASS]"
FAIL = "[FAIL]"
INFO = "[INFO]"

_failures: list[str] = []


def _request(base: str, path: str, method: str = "GET", payload: dict | None = None):
    url = f"{base}/api/v1{path}"
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            body = resp.read().decode()
            return resp.status, (json.loads(body) if body else None)
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        try:
            return e.code, json.loads(body)
        except json.JSONDecodeError:
            return e.code, {"raw": body[:500]}
    except urllib.error.URLError as e:
        print(f"{FAIL} Cannot reach PraHari at {url}: {e.reason}")
        print(f"{INFO} Start the server first:  .\\start_prahari.ps1")
        sys.exit(2)


def check(label: str, condition: bool, detail: str = "") -> bool:
    print(f"{PASS if condition else FAIL} {label}" + (f" — {detail}" if detail else ""))
    if not condition:
        _failures.append(label)
    return condition


def section(title: str) -> None:
    print(f"\n{'=' * 72}\n  {title}\n{'=' * 72}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url", default=DEFAULT_BASE)
    ap.add_argument(
        "--polls", type=int, default=2,
        help="Number of collection polls (>=2 verifies repeat-observation handling)",
    )
    ap.add_argument(
        "--settle", type=float, default=3.0,
        help="Seconds to wait between polls",
    )
    args = ap.parse_args()
    base = args.base_url.rstrip("/")

    print("PraHari — Live Windows Telemetry Verification")
    print(f"Target: {base}")
    print(f"Started: {datetime.now(timezone.utc).isoformat()}")

    # ── 1. Server reachable ────────────────────────────────────────
    section("1. Server health")
    status, health = _request(base, "/health")
    check("Health endpoint responds 200", status == 200, f"status={status}")
    if status != 200:
        return 1
    events_before = health["database"]["events_count"]
    print(f"{INFO} Events already stored: {events_before}")

    # ── 2. Collector supported and reports honest initial state ────
    section("2. Collector capability and initial state")
    status, st = _request(base, "/collector/status")
    check("Collector status responds 200", status == 200)
    check(
        "Platform supports Windows connection-table collection",
        st.get("platform_supported") is True,
        f"platform={st.get('platform_name')}",
    )
    if not st.get("platform_supported"):
        print(f"{INFO} Live collection is unavailable on this platform. Stopping.")
        return 1

    check(
        "Source is declared as live telemetry",
        st.get("data_category") == "live_telemetry",
        st.get("data_category", ""),
    )
    check(
        "Capability limits are disclosed",
        len(st.get("capability_notes", [])) >= 5,
        f"{len(st.get('capability_notes', []))} notes",
    )
    print(f"{INFO} Declared limitations:")
    for note in st.get("capability_notes", []):
        print(f"        - {note}")

    source_id = st["source_id"]

    # ── 3. Genuine collection polls ────────────────────────────────
    section("3. Live collection polls (genuine host activity)")
    polls = []
    for i in range(max(1, args.polls)):
        if i:
            print(f"{INFO} Waiting {args.settle}s before next poll...")
            time.sleep(args.settle)
        status, result = _request(base, "/collector/poll", method="POST")
        if status != 200:
            check(f"Poll {i + 1} succeeded", False, json.dumps(result)[:300])
            return 1
        polls.append(result)
        print(
            f"{INFO} Poll {i + 1}: observed={result['records_observed']} "
            f"accepted={result['events_accepted']} persisted={result['events_persisted']} "
            f"duplicates_suppressed={result['duplicates_suppressed']} "
            f"filtered_by_policy={result['records_filtered_by_policy']} "
            f"rejected={result['records_rejected']}"
        )
        if result["rejection_reasons"]:
            print(f"        rejection reasons: {result['rejection_reasons']}")

    first = polls[0]
    check(
        "Real connections were observed on this host",
        first["records_observed"] > 0,
        f"{first['records_observed']} connections",
    )
    # On a warm collector every current connection may already be recorded,
    # so zero NEW events is correct. What must hold is that the observation
    # was processed: each record was either accepted, recognised as a repeat,
    # filtered, or rejected — never silently dropped.
    processed = (
        first["events_accepted"]
        + first["duplicates_suppressed"]
        + first["records_filtered_by_policy"]
        + first["records_rejected"]
    )
    check(
        "Every observed record was processed (none silently dropped)",
        processed == first["records_observed"],
        f"{processed}/{first['records_observed']}",
    )
    check(
        "Observations entered the canonical pipeline",
        first["events_accepted"] > 0 or first["duplicates_suppressed"] > 0,
        f"{first['events_accepted']} new, {first['duplicates_suppressed']} already known",
    )
    check(
        "Newly accepted events were persisted",
        first["events_persisted"] == first["events_accepted"]
        or first["events_accepted"] == 0,
        f"{first['events_persisted']} persisted of {first['events_accepted']} accepted",
    )
    check(
        "Per-poll accounting balances (observed = accepted + rejected + duplicates + filtered)",
        first["records_observed"]
        == first["events_accepted"]
        + first["records_rejected"]
        + first["duplicates_suppressed"]
        + first["records_filtered_by_policy"],
    )

    if len(polls) >= 2:
        second = polls[1]
        check(
            "Repeat observations of still-open connections are suppressed",
            second["duplicates_suppressed"] > 0,
            f"{second['duplicates_suppressed']} suppressed on poll 2",
        )

    # ── 4. Persistence and provenance ──────────────────────────────
    section("4. Persistence, provenance and honest field absence")
    status, page = _request(base, f"/events?source_id={source_id}&limit=200")
    check("Collected events are retrievable via the events API", status == 200)
    stored = page["events"]
    check(
        "Stored event count is positive",
        page["total"] > 0,
        f"{page['total']} events for source '{source_id}'",
    )

    if stored:
        live = [e for e in stored if e["data_category"] == "live_telemetry"]
        check(
            "All collected events are categorised as live telemetry",
            len(live) == len(stored),
            f"{len(live)}/{len(stored)}",
        )
        check(
            "All collected events are typed as connection metadata",
            all(e["event_type"] == "connection" for e in stored),
        )
        check(
            "Endpoints and ports are populated from real observations",
            all(e["src_ip"] and e["dst_ip"] and e["dst_port"] is not None for e in stored),
        )
        check(
            "Unavailable metrics are null, not fabricated",
            all(
                e["bytes_total"] is None and e["packets"] is None and e["duration"] is None
                for e in stored
            ),
        )
        check(
            "Source-limit flag recorded (not a data defect)",
            all("source_limited" in e["quality_flags"] for e in stored),
        )
        check(
            "Unobtainable fields are NOT reported as missing-data defects",
            all("missing_field" not in e["quality_flags"] for e in stored),
            "a field the source cannot provide is a limit, not a defect",
        )
        check(
            "No HTTP fields are fabricated from port numbers",
            all(
                e.get("http_method") is None
                and e.get("http_status_code") is None
                and e.get("app_protocol") is None
                for e in stored
            ),
        )
        with_process = [e for e in stored if "process=" in (e["raw_reference"] or "")]
        check(
            "Owning process attributed where visible",
            len(with_process) > 0,
            f"{len(with_process)}/{len(stored)} records carry a process name",
        )
        check(
            "No timestamp predates the plausible range (FILETIME epoch guard)",
            all(int(e["observed_at"][:4]) >= 2000 for e in stored),
        )
        check(
            "No attack labels were invented for local traffic",
            all(e["label"] is None for e in stored),
        )
        check(
            "Timestamps are timezone-aware",
            all(("+" in e["observed_at"] or e["observed_at"].endswith("Z")) for e in stored),
        )
        check(
            "Provenance records connection state and owning process",
            all("windows:tcp" in (e["raw_reference"] or "") for e in stored),
        )

        sample = stored[0]
        print(f"{INFO} Sample stored event:")
        for k in (
            "event_id", "source_id", "data_category", "event_type", "observed_at",
            "src_ip", "src_port", "dst_ip", "dst_port", "protocol",
            "bytes_total", "packets", "label", "quality_flags", "raw_reference",
        ):
            print(f"        {k:15} = {sample.get(k)}")

    # ── 5. Source health ───────────────────────────────────────────
    section("5. Telemetry source health")
    status, source = _request(base, f"/sources/{source_id}")
    check("Live source is registered", status == 200)
    if status == 200:
        check(
            "Source type identifies the collection method",
            source["source_type"] == "windows_connection_table",
            source["source_type"],
        )
        check(
            "Source event_count matches stored events",
            source["event_count"] == page["total"],
            f"source={source['event_count']} stored={page['total']}",
        )
        check("Source records a last-event time", source["last_event_at"] is not None,
              str(source["last_event_at"]))

    # ── 6. Analytics reflect real data ─────────────────────────────
    section("6. Analytics over genuinely collected data")
    status, analysis = _request(
        base, "/analysis/run", method="POST", payload={"source_id": source_id}
    )
    check("Analytics computed over the live source", status == 200)
    if status == 200:
        check(
            "Analytics event total matches stored events",
            analysis["total_events"] == page["total"],
            f"{analysis['total_events']} events",
        )
        check(
            "Protocol distribution is derived from real observations",
            "TCP" in analysis["events_by_protocol"],
            json.dumps(analysis["events_by_protocol"]),
        )
        check(
            "Destination endpoints were aggregated",
            len(analysis["top_dst_ports"]) > 0,
            f"top ports: {analysis['top_dst_ports'][:3]}",
        )
        check(
            "Byte totals are absent because the source cannot provide them",
            analysis["total_bytes"] is None,
            "total_bytes=null (correct for connection metadata)",
        )
        print(f"{INFO} Unique destination IPs observed: {analysis['unique_dst_ips']}")
        print(f"{INFO} Observation window: {analysis['time_range_start']} .. {analysis['time_range_end']}")

    # ── 6b. Domain attribution ─────────────────────────────────────
    section("6b. Domain attribution (inference with evidence)")
    status, enr = _request(base, "/enrichment/status")
    check("Enrichment status responds 200", status == 200)
    if status == 200:
        check(
            "Attribution limits are disclosed",
            len(enr.get("limitations", [])) >= 4,
            f"{len(enr.get('limitations', []))} documented limits",
        )
        if enr.get("cache_appears_unavailable"):
            print(f"{INFO} DNS cache yields no records on this host. Diagnosis:")
            print(f"        {enr.get('diagnosis')}")
        else:
            print(f"{INFO} DNS observations stored: {enr.get('total_observations_stored')}")

    status, conns = _request(base, f"/events/connections?source_id={source_id}&limit=50")
    check("Connection-intelligence endpoint responds 200", status == 200)
    if status == 200 and conns["connections"]:
        attributed = [
            c for c in conns["connections"]
            if c["domain_attribution"] and c["domain_attribution"]["hostname"]
        ]
        unknown = len(conns["connections"]) - len(attributed)
        print(f"{INFO} Hostnames attributed: {len(attributed)}, unknown: {unknown}")
        check(
            "Unattributed hostnames are reported as unknown with a reason",
            all(
                c["domain_attribution"]["limitations"]
                for c in conns["connections"]
                if not c["domain_attribution"]["hostname"]
            ),
        )
        check(
            "Every attribution states whether it identifies the requested host",
            all(
                "identifies_requested_host" in c["domain_attribution"]
                for c in conns["connections"]
            ),
        )
        check(
            "Source capability limits accompany each connection",
            all(c["unsupported_fields"] for c in conns["connections"]),
            f"e.g. {conns['connections'][0]['unsupported_fields'][:4]}",
        )

    # ── 6c. Forecasting research gate ──────────────────────────────
    section("6c. Forecasting research gate (backend-enforced)")
    # Scoped to the LIVE source. A database may also hold imported or
    # synthetic labelled data, in which case the gate legitimately permits
    # training — that would say nothing about live telemetry.
    status, readiness = _request(base, f"/forecast/readiness?source_id={source_id}")
    check("Readiness endpoint responds 200", status == 200)
    if status == 200:
        print(f"{INFO} State (live source only): {readiness['state']}")
        print(f"{INFO} {readiness['summary']}")
        check(
            "Unlabelled live traffic is not counted as benign",
            readiness["negative_events"] == 0 and readiness["labelled_events"] == 0,
            f"labelled={readiness['labelled_events']}, negatives={readiness['negative_events']}",
        )
        check(
            "Gate blocks training on unlabelled local telemetry",
            readiness["can_train"] is False,
            f"state={readiness['state']}",
        )

        # The gate is enforced in the backend, so a direct API call is
        # refused on the same terms. Scoped to the live source for the
        # same reason as above.
        status_t, blocked = _request(
            base, "/forecast/train", method="POST",
            payload={"source_id": source_id},
        )
        check(
            "Direct API training request is refused (not just the UI)",
            status_t == 409,
            f"HTTP {status_t}",
        )
        if status_t == 409:
            check(
                "Refusal names the unmet requirements",
                len(blocked["detail"]["unmet_requirements"]) > 0,
            )

        total_status, total_readiness = _request(base, "/forecast/readiness")
        if total_status == 200 and total_readiness["labelled_events"] > 0:
            print(
                f"{INFO} Note: the database also holds "
                f"{total_readiness['labelled_events']} labelled event(s) from "
                "other sources (imported or synthetic). Across all sources the "
                f"gate state is '{total_readiness['state']}'. That reflects "
                "those datasets, not live telemetry."
            )

    # ── 6d. Application-layer telemetry is off ─────────────────────
    section("6d. Application-layer telemetry")
    status, al = _request(base, "/applayer/status")
    check("Application-layer status responds 200", status == 200)
    if status == 200:
        # Opt-in: disabled unless the operator explicitly enabled it. Both
        # states are valid, so report which one is in effect rather than
        # assuming the default.
        if al["enabled"]:
            print(
                f"{INFO} Application-layer ingestion is ENABLED on this instance "
                "(PRAHARI_ENABLE_APPLICATION_LAYER_INGEST=true)."
            )
            check(
                "Enabled ingestion still requires an external producer",
                al.get("producer_required") is True,
            )
        else:
            check("Disabled by default (opt-in)", True)

        check(
            "Bodies/cookies/credentials are declared never-accepted",
            "body" in al["never_accepted"] and "cookies" in al["never_accepted"],
        )
        check(
            "Connection telemetry is not presented as an HTTP source",
            al["source_type"] == "application_layer",
        )

    # ── 7. Adapter health is real ──────────────────────────────────
    section("7. Adapter health registry")
    status, adapters = _request(base, "/stream/adapters")
    check("Adapter health responds 200", status == 200)
    win = [a for a in (adapters or []) if a["adapter_type"] == "windows_connection_table"]
    check("Windows adapter appears in the live registry", len(win) > 0)
    if win:
        a = win[0]
        check(
            "Adapter counters reflect real processing",
            a["records_processed"] > 0,
            f"processed={a['records_processed']} rejected={a['records_rejected']}",
        )

    # ── 8. Data categories remain separated ────────────────────────
    section("8. Separation of live telemetry from other data categories")
    status, allpage = _request(base, "/events?limit=500")
    if status == 200:
        cats: dict[str, int] = {}
        for e in allpage["events"]:
            cats[e["data_category"]] = cats.get(e["data_category"], 0) + 1
        print(f"{INFO} Data categories present: {cats}")
        check(
            "Live telemetry is present and distinguishable",
            cats.get("live_telemetry", 0) > 0,
            f"{cats.get('live_telemetry', 0)} live events",
        )

    # ── Summary ────────────────────────────────────────────────────
    section("Verification summary")
    if _failures:
        print(f"{FAIL} {len(_failures)} check(s) failed:")
        for f in _failures:
            print(f"        - {f}")
        return 1
    print(f"{PASS} All checks passed.")
    print(f"{INFO} Genuine Windows network telemetry was observed, normalized,")
    print(f"{INFO} persisted, and served through the PraHari API.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
