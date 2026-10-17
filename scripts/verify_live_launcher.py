"""
Verify a PraHari server's lifecycle end to end: loopback binding, health and
request ids, SPA routing (or the no-build behaviour), REST and ingestion
workflows, the forecasting gate, and clean shutdown with the port released.

Runs on Windows and Linux. It starts its OWN server, isolated from the
operator's data:

  * a throwaway directory is the working directory (so no stray `.env` is
    read) and holds the database and experiment manifests;
  * every inherited PRAHARI_* variable is removed, then the database and
    experiment directory are pointed into that throwaway directory;
  * the server binds 127.0.0.1 only, on a free port unless --port is given;
  * the server is stopped, and the port checked closed, however the checks
    end; the throwaway directory is then removed.

Before this, the script started uvicorn against the default (operational)
database and posted a fabricated flow labelled `live_telemetry` into it,
and its checks were `assert` statements that `python -O` removes.

Usage:
    python scripts/verify_live_launcher.py [--port N] [--python PATH]

Exit status is 0 only if every check passed.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
BACKEND = REPO / "backend"
HOST = "127.0.0.1"


class Checks:
    def __init__(self) -> None:
        self.failed = 0

    def check(self, ok: bool, label: str, detail: str = "") -> bool:
        print(f"  [{'PASS' if ok else 'FAIL'}] {label}" + (f" - {detail}" if detail else ""))
        if not ok:
            self.failed += 1
        return ok

    def skip(self, label: str, reason: str) -> None:
        print(f"  [SKIP] {label} - {reason}")


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, 0))
        return s.getsockname()[1]


def _listening(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        return s.connect_ex((HOST, port)) == 0


def _request(base: str, method: str, path: str, body: dict | None = None):
    """(status, headers, parsed-or-raw body). HTTP errors are answers too."""
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(
        base + path, data=data, method=method,
        headers={"Content-Type": "application/json"} if data else {},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            status, headers, raw = resp.status, resp.headers, resp.read()
    except urllib.error.HTTPError as exc:
        status, headers, raw = exc.code, exc.headers, exc.read()
    text = raw.decode("utf-8", errors="replace")
    try:
        return status, headers, json.loads(text)
    except json.JSONDecodeError:
        return status, headers, text


def _stop(proc: subprocess.Popen) -> None:
    if proc.poll() is not None:
        return
    if os.name == "nt":
        # A venv python.exe may be a launcher with the real interpreter as
        # a child; stop the whole tree.
        subprocess.run(["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                       capture_output=True, timeout=30)
    else:
        proc.terminate()
    try:
        proc.wait(timeout=15)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=15)


def run(python: str, port: int) -> int:
    c = Checks()
    work = Path(tempfile.mkdtemp(prefix="prahari-launcher-verify-"))
    base = f"http://{HOST}:{port}"
    spa_built = (REPO / "frontend" / "dist" / "index.html").is_file()

    env = {k: v for k, v in os.environ.items() if not k.startswith("PRAHARI_")}
    env["PRAHARI_DATABASE_URL"] = f"sqlite:///{(work / 'verify.db').as_posix()}"
    env["PRAHARI_EXPERIMENTS_DIR"] = str(work / "experiments")

    print("=== PraHari Launcher Lifecycle Verification ===")
    print(f"Python:    {python}")
    print(f"Server:    {base} (loopback only)")
    print(f"Scratch:   {work} (database, manifests; removed afterwards)")
    print(f"Frontend:  {'built' if spa_built else 'NOT built - SPA checks verify the no-build behaviour'}")

    if _listening(port):
        print(f"[ERROR] Port {port} already has a listener; choose another with --port.")
        shutil.rmtree(work, ignore_errors=True)
        return 2

    log = open(work / "server.log", "w", encoding="utf-8")
    proc = subprocess.Popen(
        [python, "-m", "uvicorn", "app.main:app", "--app-dir", str(BACKEND),
         "--host", HOST, "--port", str(port), "--log-level", "info"],
        cwd=str(work), env=env, stdout=log, stderr=subprocess.STDOUT,
    )
    try:
        deadline = time.monotonic() + 60
        status = None
        while time.monotonic() < deadline and proc.poll() is None:
            try:
                status, headers, health = _request(base, "GET", "/api/v1/health")
                if status == 200:
                    break
            except OSError:
                time.sleep(0.25)
        print("\n[1] Startup and health")
        if not c.check(status == 200, "server became healthy"):
            log.flush()
            print((work / "server.log").read_text(encoding="utf-8", errors="replace")[-3000:])
            return 1
        c.check(health.get("status") == "healthy", "status=healthy", str(health.get("status")))
        c.check(bool(headers.get("x-request-id")), "x-request-id header present (current code loaded)")
        db_path = (health.get("database") or {}).get("path", "")
        c.check(Path(db_path).resolve().parent == work.resolve(),
                "database is the throwaway one", db_path)

        print("\n[2] SPA routing")
        status, headers, body = _request(base, "GET", "/")
        if spa_built:
            c.check(status == 200 and "text/html" in headers.get("content-type", "")
                    and "PraHari" in str(body), "GET / serves the SPA shell")
            for route in ["/events", "/forecast", "/analytics", "/stream"]:
                s, h, _ = _request(base, "GET", route)
                c.check(s == 200 and "text/html" in h.get("content-type", ""),
                        f"deep link {route} falls back to the shell")
        else:
            c.check(status == 200 and isinstance(body, dict) and body.get("health") == "/api/v1/health",
                    "GET / answers with the API root (no build)")
            s, _, _ = _request(base, "GET", "/events")
            c.check(s == 404, "deep link /events is 404 without a build", str(s))
            c.skip("SPA shell and deep-link fallback", "frontend/dist not built")
        s, _, _ = _request(base, "GET", "/assets/missing.js")
        c.check(s == 404, "missing asset is 404", str(s))
        s, h, _ = _request(base, "GET", "/api/v1/definitely-not-an-endpoint")
        c.check(s == 404 and "application/json" in h.get("content-type", ""),
                "unknown API path is a JSON 404, not the shell", str(s))

        print("\n[3] REST and ingestion")
        s, _, sources = _request(base, "GET", "/api/v1/sources")
        c.check(s == 200 and isinstance(sources, list), "GET /api/v1/sources", f"{s}")
        flow = {
            "ts": time.time(), "id.orig_h": "192.0.2.100", "id.resp_h": "198.51.100.1",
            "id.orig_p": 45000, "id.resp_p": 443, "proto": "tcp", "duration": 0.1,
            "orig_bytes": 1024, "resp_bytes": 4096, "uid": "launcher-verify-1",
        }
        ingest = {
            # Fabricated by this script, so filed as synthetic - never as
            # live telemetry.
            "source_id": "launcher_verify_probe",
            "ndjson_content": json.dumps(flow),
            "data_category": "synthetic_demo",
        }
        s, _, res = _request(base, "POST", "/api/v1/stream/ingest/ndjson", ingest)
        c.check(s == 200 and res.get("accepted_records") == 1 and res.get("stored_records") == 1,
                "NDJSON ingest stores the record", f"{s} {res if s != 200 else ''}")
        s, _, res = _request(base, "POST", "/api/v1/stream/ingest/ndjson", ingest)
        c.check(s == 200 and res.get("stored_records") == 0 and res.get("duplicate_records") == 1,
                "a resend is deduplicated, not stored twice")
        s, _, page = _request(base, "GET", "/api/v1/events?source_id=launcher_verify_probe")
        c.check(s == 200 and page.get("total") == 1, "the event reads back exactly once",
                f"total={page.get('total') if isinstance(page, dict) else page}")

        print("\n[4] Forecasting and collector")
        s, _, res = _request(base, "POST", "/api/v1/forecast/predict", {"threshold": 0.5})
        gated = s == 409 and isinstance(res, dict) and \
            (res.get("detail") or {}).get("error") == "forecasting_blocked_by_research_gate"
        c.check(s == 200 or gated,
                "predict answers, or refuses through the research gate (never a 5xx)", str(s))
        s, _, col = _request(base, "GET", "/api/v1/collector/status")
        c.check(s == 200 and col.get("state") in ("stopped", "unsupported")
                and col.get("polls_attempted") == 0,
                "collector reports itself not started", f"state={col.get('state')}")
    finally:
        print("\n[5] Shutdown")
        _stop(proc)
        log.close()
        c.check(proc.returncode is not None, "server process exited", f"code={proc.returncode}")
        time.sleep(0.5)
        c.check(not _listening(port), f"port {port} released")
        shutil.rmtree(work, ignore_errors=True)

    print(f"\n{'ALL CHECKS PASSED' if not c.failed else f'{c.failed} CHECK(S) FAILED'}")
    return 0 if not c.failed else 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--port", type=int, default=0, help="loopback port (default: a free one)")
    ap.add_argument("--python", default=sys.executable,
                    help="interpreter with PraHari's dependencies (default: this one)")
    args = ap.parse_args()
    return run(args.python, args.port or _free_port())


if __name__ == "__main__":
    sys.exit(main())
