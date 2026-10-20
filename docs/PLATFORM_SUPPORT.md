# Platform Support and Network Sensor Deployment

What has actually been executed on which platform, and what a real network
sensor deployment would require. Blueprint items 1 and 3.

Nothing here is a projection presented as a result.

---

## 1. Platform status

| Platform | Status | Basis |
|---|---|---|
| **Windows 11** | **Verified — runtime, earlier revisions** | 394 backend tests, 36 frontend tests, live collection, all nine pages driven in a browser, loopback central-mode run. Not re-run for the revision validated on Arch below |
| **Linux (Arch, kernel 7.2.9, Python 3.14.8)** | **Verified — current revision: backend suite, frontend, loopback runtime** | 1,284 backend tests passed, 3 skipped (all platform skips, explained in section 6); frontend `tsc`, 67 vitest tests and production build pass (Node 26, npm 12); application started on loopback against a disposable database and shut down cleanly; the backend served the real frontend build. Section 6 records the runs. The collector was not started |
| Linux (Ubuntu 26.04, Python 3.14.4, WSL2) | Verified for an earlier revision only | 392 backend tests passed, 2 skipped, on the codebase as it was then (below) |
| macOS | **Not assessed** | No macOS machine available |
| Docker | **Not verified** | Docker is not installed on this host and installing it is outside the agreed boundary |

### Linux: what was actually run (earlier revision, Ubuntu)

Historical record. The current revision's Arch run is in section 6; where
the two disagree, section 6 describes the code as it is now.

A pre-existing Ubuntu 26.04 WSL2 environment was used. Dependencies were
installed into a **virtual environment under the user's home directory** —
no system packages, no `apt`, no root.

```
python: Python 3.14.4   platform: linux
392 passed, 2 skipped in 13.29s
```

The two skips are the `live_windows` tests, which require a real Windows
connection table and are correctly skipped elsewhere.

Application startup was then verified directly:

```
GET /health               -> 200  status=healthy mode=local
GET /collector/status     -> 200  state=unsupported platform=Linux 6.18.33.2-microsoft-standard-WSL2
GET /events               -> 200  total=0
GET /hostobs/capabilities -> 200  profiles=['windows_udp_endpoint', 'windows_interface_counters']
POST /hostobs/udp/poll    -> 501  unsupported_platform
GET /hostobs/interfaces   -> 501  unsupported_platform
```

The Windows-only sources refuse cleanly with 501 and a named reason; they
do not crash, and they do not pretend to work.

### Two portability defects this found

Running the suite on Linux is what exposed them. Static analysis had said
the code was portable; it was wrong.

**1. The platform gate refused injected sources.** `collector.py` gated on
`sys.platform == "win32"` before checking whether the caller had supplied
its own query function. Twelve collector tests that inject a fake query
failed on Linux with *"unavailable on platform 'linux'"*, and a genuine
alternative producer would have been refused for the same wrong reason.
The gate exists to stop the **PowerShell probe** running where there is no
Windows connection table — not to stop collection as such. It now applies
only when no source is injected, which also gave the collector API its
first Linux coverage. The real OS path is still refused off Windows, and
there is a test for that.

> *Superseded by ADR-053 and ADR-075:* Linux now has its own genuine
> source (`/proc/net/tcp`), so the real OS path runs on Linux too. It is
> refused - 501 - only on a platform that is neither Windows nor Linux,
> and the PowerShell query is never called there.

**2. The operational-database guards tested a substring, not the
property.** Two tests asserted the database URL contained `tmp` or `temp`.
On Linux a throwaway database under `$HOME` is isolated by any reasonable
reading, and they failed. They now assert what actually matters: the
resolved path is **not** the repository's `prahari.db`.

### What remains Windows-specific

| Component | Portable? |
|---|---|
| API, ingestion, analytics, forecasting, research gate, retention, experiments, central security | **Yes** — all verified running on Linux |
| Frontend / SPA serving | **Yes** |
| TCP connection-table collection | **Windows and Linux.** Windows reads `Get-NetTCPConnection`; Linux reads `/proc/net/tcp` and `/proc/net/tcp6` (ADR-053). Any other platform reports `unsupported`, and `POST /collector/poll` and `/collector/start` return **501** |
| UDP endpoint table (`Get-NetUDPEndpoint`) | **No** — Windows only; 501 elsewhere |
| Interface counters (`Get-NetAdapterStatistics`) | **No** — Windows only; 501 elsewhere |
| DNS cache enrichment | **No** — Windows DNS client only. Since ADR-075 the collector does not attempt it on Linux, and since ADR-076 neither do `POST /enrichment/dns/refresh` (200, `succeeded: false`, reason given) or `GET /enrichment/dns/diagnose` - nothing is spawned |

What Linux TCP collection does **not** provide, and reports in
`/collector/status` `capability_notes`: no socket creation time (every
event is stamped with the poll time and flagged `timestamp_uncertainty`);
process name (`comm`, never the command line) only for processes the
running user may inspect; no hostname evidence; no bytes, packets or
duration. Linux records still carry the Windows-named identifiers
`windows_local_host`, `windows_connection_table` and a `windows:tcp`
reference prefix (ADR-075).

A Linux deployment therefore runs everything, including local TCP
collection, except the Windows-only UDP, interface and DNS sources, and it
refuses those with a named reason rather than failing.

---

## 2. There is no packet-capture sensor, by design

PraHari does not capture packets, and will not. No promiscuous mode, no
capture driver, no span port, no TLS interception, no privilege elevation.

Local sources read OS tables — the same information `netstat` shows.

Consequences, stated plainly:

- No payloads, so no content inspection.
- No visibility into other hosts. A machine on a switched network sees its
  own sockets, not its neighbours'.
- Connections shorter than the poll interval can be missed entirely; gaps
  are detected and recorded rather than interpolated.
- No application-layer fields unless the optional browser producer is
  enabled, and that sees one browser, not the host.

---

## 3. What each local source can and cannot measure

| Source | Provides | Does **not** provide |
|---|---|---|
| TCP connection table | 5-tuple, TCP state, owning process, creation time | bytes, packets, flow duration, payload, app layer |
| UDP endpoint table | local address/port, owning process, creation time | **any remote peer** (UDP is connectionless), bytes, packets, duration |
| Interface counters | **real** cumulative bytes and packets, per interface | attribution to any connection, process or destination |

### Volume measurement, honestly

Interface counters are the only genuine byte and packet measurement
available on this host without packet capture. They are **interface-level
and cumulative since the adapter last reset**, so they are reported through
their own endpoint and are **never written into `normalized_events`**.

```
GET /api/v1/hostobs/interfaces
```

The payload states its own scope — `measurement_scope:
"interface_cumulative"`, `attributable_to_flow: false`,
`attributable_to_process: false` — so a consumer cannot mistake it for flow
accounting. Summing it alongside the byte counts of an imported flow
dataset would produce a number that means nothing, and the capability
profile says so.

A delta between two readings is offered where one exists. Across an adapter
reset (a decreasing counter) **no delta is derived**, because neither a
negative nor a wrapped-around positive describes anything that happened on
the wire.

### UDP endpoints are not connections

```
POST /api/v1/hostobs/udp/poll
```

Emitted as `EventType.UDP_ENDPOINT` with `dst_ip` and `dst_port` declared
**not applicable** — not missing. Windows records no peer for an
unconnected socket, so inventing one would manufacture destinations that
were never observed and corrupt every destination-based aggregation.

Verified live on this host: 41 endpoints observed, 41 normalized, 0
rejected; a second poll persisted 1 new socket and suppressed 40 repeats,
confirming deterministic identity.

---

## 4. Deploying a real network sensor

The supported route for genuine network-wide telemetry is an **existing
sensor** writing JSON, which PraHari normalizes. PraHari is the analysis
and research layer; it is not the sensor.

### Requirements the operator must satisfy first

| Requirement | Why |
|---|---|
| **Written authorization** for the network segment | Monitoring a network you do not own or administer is not a technical question. A shared or institutional network needs the owner's permission in writing |
| A **tap or mirror port**, or host-based agents | A switched network gives a sensor nothing by default |
| A host to run the sensor, with elevated privileges **there** | Capture needs them; PraHari still does not |
| A retention and access decision | Captured metadata about other people's traffic is personal data in most jurisdictions |

PraHari provides none of this automatically, and no part of it will
configure a tap, change an interface, or enable capture.

### Wiring a sensor in

**Suricata** — `suricata.yaml`, EVE output:

```yaml
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - flow
        - dns
        - http
        - alert
```

**Zeek** — load the JSON writer so `conn.log` is newline-delimited JSON:

```
redef LogAscii::use_json = T;
```

The endpoint takes a JSON body carrying the NDJSON payload as a string, so
sensor output is wrapped rather than streamed raw:

```bash
python -c "import json; print(json.dumps({'source_id':'suricata-01','ndjson_content':open('eve.json',encoding='utf-8').read(),'data_category':'historical_import'}))" > payload.json
```

```bash
curl -X POST http://127.0.0.1:8000/api/v1/stream/ingest/ndjson -H "Content-Type: application/json" --data-binary @payload.json
```

The response is an `ImportSummary` in which `accepted + rejected = total`,
with a reason recorded for every rejection. A batch is capped at 50,000
records, so a long-running sensor should be shipped in chunks.

### What the adapter guarantees

Pinned by `tests/unit/test_network_sensor_adapters.py` (21) and
`tests/integration/test_sensor_ingest_roundtrip.py` (5):

| Behaviour | Guarantee |
|---|---|
| Zeek id form | Flattened `id.orig_h` and nested `id` normalize identically |
| Zeek unset `"-"` | Stays absent. **Never** read as `0` |
| Zero measurements | `0` bytes, `0.0` seconds and port `0` are preserved as recorded values, not collapsed to "no data" |
| Timestamps | Seconds and milliseconds distinguished; non-UTC offsets converted, not truncated |
| IPv6 | Accepted |
| Suricata `dns` / `http` / `alert` | Mapped to `dns_query` / `http_request` / `alert` |
| Unknown fields | Ignored, not fatal |
| Unrecognised protocol | Passed through unchanged, not rewritten to a known one |
| Malformed record | Rejected with a reason; the rest of the batch still imports, and accepted + rejected reconciles to total |

### The label rule that matters most

**A Suricata signature is recorded as `detector_output`, never as ground
truth.**

An IDS signature is that detector's opinion. If it were stored as
`dataset_ground_truth`, a forecaster trained on it would learn to predict
*one detector's alerts* while every metric claimed it predicted attacks —
and the claim would look fully evidenced.

| Label source | Provenance recorded |
|---|---|
| `label` / `classification` (corpus states it) | `dataset_ground_truth` |
| `alert.signature` (a detector decided it) | `detector_output` + an explicit warning |
| Neither | `unlabeled` — never inferred as benign |

A corpus label takes precedence over a detector signature on the same
record. The readiness report counts detector labels — they are labels — but
reports them under `non_ground_truth_labelled_events` with a caveat shown
on the dashboard, so a verdict built on them cannot read as a verdict built
on ground truth.

The event type is kept separate from the label: a labelled flow is still a
`network_flow`.

---

## 5. Summary

| Claim | Status |
|---|---|
| Runs on Windows | **Verified at runtime** |
| Runs on Linux | **Verified on Arch for the current revision** — backend suite, frontend type-check/tests/build, and loopback runtime. Local TCP collection reads `/proc`; the live table read is tested, but the collector was not started as part of validation |
| Runs on macOS | **Unknown** |
| Runs in Docker | **Unverified** — Docker not installed on this host |
| Ingests Zeek JSON | **Verified against fixtures and over HTTP**, not against a live Zeek instance |
| Ingests Suricata EVE | **Verified against fixtures and over HTTP**, not against a live Suricata instance |
| Measures bytes/packets per flow | **No** — not available from any local source. Interface-level counters only |
| Captures packets | **No, and will not** |
| Has been run against a real network sensor | **No** |

---

## 6. Re-verifying on Linux (Arch)

**Status: executed on 17 Oct 2026** against revision `a128bfd` plus the
uncommitted fixes recorded in ADR-073 to ADR-075. Host: Arch Linux, kernel
7.2.9-arch1-1, x86_64, Python 3.14.8, pytest 9.1.1, existing
`backend/.venv-linux`.

| Step | Result |
|---|---|
| `pytest tests/unit/test_linux_telemetry.py -v -rs` | **30 passed, 1 skipped** |
| `pytest -q -rs` (first run, before fixes) | 3 failed, 1243 passed, 3 skipped |
| `pytest -q -rs` (after ADR-075) | 1278 passed, 3 skipped, 0 failed |
| `pytest -q -rs` (after ADR-076) | 1284 passed, 3 skipped, 0 failed |
| `pytest -q -rs` (current, after ADR-077) | **1292 passed, 3 skipped, 0 failed**, 3 deprecation warnings from FastAPI/Starlette |
| `scripts/simulate_synthetic_stream.py --base-url <throwaway server>` | 4 synthetic records accepted; exits 1 on an unreachable server |
| Frontend: `npm ci`, `tsc -p .`, `vitest run`, `vite build` | 239 locked packages installed; `tsc` 0 errors; **67 passed** in 8 files; build succeeded (one advisory: the main chunk is 1.36 MB, over Vite's 500 kB guideline). Built to a scratch directory, not `frontend/dist` |
| Backend serving that build (in process) | shell for client routes, assets served as JS, 404 for missing files and unknown API paths, raw `..` paths refused (ADR-076) |
| `scripts/verify_live_launcher.py` | 16 checks passed, 1 skip (no `frontend/dist`); also passes under `python -O` |
| `scripts/simulate_browser_producer.py` against a throwaway loopback server | all contract checks passed |
| `pytest tests/integration/test_central_https_e2e.py` | 28 passed; separate uvicorn process on 127.0.0.1, port verified closed |
| Loopback startup, disposable DB | `/health` 200 with `x-request-id`; `/collector/status` `state=stopped`, `platform_supported=true`, 0 polls; port 8765 closed after stop |

**The skips.** Three, all expected on Linux, none a pass:

- two `live_windows` tests - they need a real Windows connection table;
- `test_the_collector_selects_the_windows_query_off_linux` - it asserts
  the *non-Linux* branch of `default_host_query_fn()`, so it cannot run on
  Linux. Its Linux counterpart runs and passes.

The procedure below originally said "expect zero skips here"; one skip in
the Linux module is by design, and the procedure has been corrected.

**What the run found** - three test failures and two collector defects,
all explained in ADR-073 to ADR-075. In short: a stale Windows-only test, a
traversal test that the HTTP client defeated by normalising `..` and that
depended on a built frontend, and an agent test that assumed the 413 is
never seen. Plus a Linux collector that tried to spawn PowerShell for DNS
enrichment, and that described itself as `Get-NetTCPConnection`.

**Not run on Linux:** `verify_live_windows_telemetry.py` (polls the real
collector of a running server), the PowerShell and batch launchers, and a
real-browser session.

**SPA tests and the frontend build.** The deep-link and missing-asset
tests in `test_deployment_and_spa.py` check the checkout's own
`frontend/dist` only if it exists; this checkout had not run `npm run
build`, so those two passed **without asserting anything**. The fallback
itself - shell for client routes, 404 for missing files and unknown API
paths - and its traversal guards are tested against a throwaway build
created per test, and the no-build behaviour (no fallback route, 404) by
its own test, so both run either way.

The procedure as originally written follows.

It installs nothing system-wide and changes no networking. It needs only
`git`, `python` (3.12 or later) and `openssl`, which an Arch base system
normally has. **If `python` is missing, stop**: installing it with pacman
is a system change to authorize separately.

```bash
cd ~/src/PraHari
git fetch origin
git status --short
git merge --ff-only origin/main
git rev-parse HEAD
```

Compare `git rev-parse HEAD` with the published `origin/main` commit.

```bash
cd backend
python -m venv .venv-linux
. .venv-linux/bin/activate
python -m pip install -r requirements.txt
```

The venv lives inside the checkout and is removed with `rm -rf .venv-linux`.

```bash
python -m pytest tests/unit/test_linux_telemetry.py -v -rs
```

On Linux the four tests that skip on Windows must **run**. Two read a
live `/proc`; two create symlinks under a fake `/proc/<pid>/fd`. Expect
exactly one skip here - `test_the_collector_selects_the_windows_query_off_linux`,
which asserts the non-Linux branch. Any other skip means that check did
not execute.

```bash
python -m pytest -q -rs
```

On Linux, expect the two `live_windows` tests and the non-Linux
selection test to skip, and nothing else. Record passed, failed and skipped counts
exactly; a skip is not a pass.

```bash
python -m pytest tests/integration/test_central_https_e2e.py -v
```

This starts PraHari as a separate process serving HTTPS on 127.0.0.1 with
a throwaway test PKI and a temporary database, then stops it and checks the
port closed.

Startup and shutdown against a disposable database, loopback only:

```bash
mkdir -p /tmp/prahari-linux-verify
PRAHARI_DATABASE_URL=sqlite:////tmp/prahari-linux-verify/verify.db python -m uvicorn app.main:app --host 127.0.0.1 --port 8765 &
sleep 3
curl -s -D - http://127.0.0.1:8765/api/v1/health
curl -s http://127.0.0.1:8765/api/v1/collector/status
kill %1
sleep 1
ss -ltn | grep 8765 || echo "port 8765 closed"
```

Expect `/health` 200 with an `x-request-id` header, and the collector
status to name the Linux platform without starting anything. No collector
is enabled by any step here.

When this was executed it was run from inside the empty
`/tmp/prahari-linux-verify` directory with `--app-dir <repo>/backend`, so
no `.env` in the checkout could be picked up, with every inherited
`PRAHARI_*` variable unset, and with an exit trap that stops the server
even if a request fails.

Clean up:

```bash
rm -rf /tmp/prahari-linux-verify
deactivate
```

Linux integration can be claimed only once these have run and their
output has been recorded - not because the Linux modules import, and not
because their tests were skipped elsewhere.

---

## 7. Re-verifying on Windows (current revision)

**Status: executed on 17 Oct 2026** for `4360ca3` - results in §7.1, after
the procedure. Steps 1-5 and 7-10 ran; step 6 (collector lifecycle against
the operational database) is blocked pending explicit authorization.

The note below is from the Linux side and is kept as written. The Arch
host cannot reach the Windows checkout:
the Windows partition is BitLocker-encrypted and unmounted, and the
machine dual-boots, so Windows cannot run alongside Linux.

**Getting the changes.** They are committed on `main` in
`origin` (`https://github.com/PRushi00/PraHari`). On Windows, first check
the checkout - `git status --short --branch` must show no modified files
and `git log -1` the commit you expect to build on - then:

```powershell
git fetch origin
git merge --ff-only origin/main
```

`--ff-only` refuses rather than merging if the Windows branch has local
commits; stop and inspect them if it does. A patch with a manifest was also
prepared before the commit (`IMPLEMENTATION_STATUS.md`, Session 30) for a
checkout that cannot pull.

Then run the steps below in PowerShell from the repository root. Preserve
first: copy `prahari.db` (and any `-wal`/`-shm`) somewhere safe, with
PraHari stopped. Nothing below touches the operational database except
steps 6 to 8, which use the running instance deliberately.

| # | Command | Expect |
|---|---|---|
| 1 | `cd backend; .\.venv\Scripts\python.exe -m pytest -q -rs` | All pass; the skips are the Linux-only tests (`/proc` reads, POSIX symlinks, Linux selection, the non-Windows gates) - none of the `live_windows` tests skip |
| 2 | `.\.venv\Scripts\python.exe -m pytest -m live_windows -v -rs` | 2 passed, against the real connection table |
| 3 | `.\.venv\Scripts\python.exe ..\scripts\verify_live_launcher.py` | All checks pass; database path under a `prahari-launcher-verify-*` temp directory; port released. Since ADR-080 the server is stopped with `CTRL_BREAK`, gracefully, and a forced `taskkill` is a failed check |
| 4 | `cd ..\frontend; npm ci; npx tsc -p .; npx vitest run` | `tsc` 0 errors; 67 passed |
| 5 | `npx vite build --outDir $env:TEMP\prahari-spa-check --emptyOutDir` | Build succeeds without touching `frontend\dist` |
| 6 | **Operator decision:** start PraHari normally, then from the dashboard (or `POST /api/v1/collector/start`), collect for a few polls and stop | `capability_notes` name `Get-NetTCPConnection`; `refresh_dns` on; events persisted; stopping leaves no extra process |
| 7 | With PraHari running: `POST /api/v1/enrichment/dns/refresh`, `GET /api/v1/enrichment/dns/diagnose` | Real DNS-cache data and a resolver diagnosis - not the "Windows-only" message the Linux gate returns |
| 8 | `GET /api/v1/hostobs/interfaces`, `POST /api/v1/hostobs/udp/poll` | 200 with data |
| 9 | `powershell -ExecutionPolicy Bypass -File .\start_prahari.ps1 -CheckOnly` | Preflight passes |
| 10 | A real browser on `http://127.0.0.1:8000/` | Every tab renders; no console errors; no unexpected 4xx/5xx in the network panel |

Steps 6 to 8 read and write the **operational** database, because that is
what the running instance uses: that is collection, not a test. Run them
only when that is intended.

### 7.1 Windows results (17 Oct 2026, revision `4360ca3` plus ADR-078..081)

Windows 11 Home Single Language 10.0.26300 · Python 3.12.0 (project venv) ·
Node 24.19.0 · npm 12.0.2. Every check used temporary storage; neither
operational database was opened. `npm ci` was not run: the installed
dependencies already matched the lockfile (`npm ls` clean), and `npm ci`
deletes `node_modules`.

| # | Result |
|---|---|
| 1 | **1334 passed, 8 skipped, 0 failed**, 3 warnings (Starlette/httpx deprecations). Baseline before this work: 1287 passed, 8 skipped. Skips: 4 Linux `/proc`, 2 non-Windows gates, 1 Linux host-source selection, and the POSIX symlink escape (WinError 1314), whose Windows equivalent now runs as a junction test |
| 2 | `live_windows`: **8 passed**: the two connection-table tests plus six new endpoint tests |
| 3 | **21 checks passed, 0 skipped**, under `python` and `python -O`; stopped gracefully, shutdown hook ran, port released. Linux reported 16 + 1 designed skip; the difference is that Windows has a built frontend |
| 4 | `tsc` 0 errors; Vitest **77 passed** (67 before; +10 for ADR-078/079) |
| 5 | Build to a temp directory succeeds; `frontend\dist` untouched (hash unchanged). Same 500 kB chunk advisory as Linux |
| 6 | **Blocked - authorization required.** The single-poll endpoint was not used as a substitute |
| 7 | Ran against temporary storage, not the running instance. DNS diagnose and refresh executed the **Windows** path, not the platform gate, but the DNS client cache was **empty**: refresh succeeded with 0 entries. Live DNS parsing is therefore unproven on this host (ADR-082) |
| 8 | Temporary storage: 38 real UDP sockets read; 2 adapters with counters, scope declared |
| 9 | `-CheckOnly` passes and creates nothing (fingerprint of `dist`, venv and `node_modules` unchanged). It no longer installs or builds (ADR-080) |
| 10 | Real browser, two isolated servers, every page. Found and fixed: the loopback claim (ADR-078) and local time under UTC headers (ADR-079). Expected 404s: `/sources/windows_local_host` before first collection (handled), `/favicon.ico` on non-HTML responses. No server errors |

Windows-only evidence, separated from mocks:
- **Real OS:** `Get-NetTCPConnection` (live tests), `Get-NetUDPEndpoint`,
  `Get-NetAdapterStatistics`, the DNS client cache and resolver diagnosis,
  a directory junction against both static paths, real PowerShell running
  the launcher, `CTRL_BREAK` shutdown, and a missing PowerShell executable.
- **Stand-ins:** PowerShell timeout, nonzero exit and output shapes
  (`test_windows_query_subprocess.py`), stated as such in that file.

### 7.2 Windows closure, second pass (17 Oct 2026, ADR-083..086)

| Check | Result |
|---|---|
| Backend `pytest -q -rs` | 1334 passed, 8 skipped, 0 failed, 3 warnings |
| `pytest -m live_windows -v` | **15 passed**: connection table (2), collector lifecycle into a temporary database (2), DNS-cache pipeline through real PowerShell (5), host-observation and DNS endpoints (6) |
| `verify_live_launcher.py` (`python`, `python -O`) | 21/21 each, graceful stop |
| Frontend | `tsc` 0; Vitest 90 passed; build to a temporary directory OK |
| Real browser | Deep links, refresh, back/forward, aliases, unknown routes; System Health and Administration now reachable |

Fixed: a new collector inherited the previous one's deduplication cache and
configuration (ADR-083); the dashboard had no URLs and two unreachable
pages (ADR-084); four defects in the first pass's own changes (ADR-085).

Still open: `Get-DnsClientCache` returning populated objects (the cache on
this host is empty); a shutdown hang seen twice with a real browser and not
reproduced (ADR-086); a Linux re-run of ADR-080 and ADR-083;
`frontend/dist` to be rebuilt by the operator.

### 7.3 Re-validation on Python 3.12.10 (17 Oct 2026, ADR-087, ADR-088)

Python 3.12.10 was installed on this host after §7.1-7.2 were measured on
3.12.0, so every check was repeated rather than inherited.

| Check | Result on 3.12.10 |
|---|---|
| Backend `pytest -q -rs` | 1334 passed, 8 skipped, 0 failed, 3 warnings |
| `pytest -m live_windows` | 15 passed |
| `verify_live_launcher.py` (`python`, `-O`) | 23/23 each (now including `/system-health` and `/admin`), graceful |
| Real `start_prahari.ps1` on a temporary database | Served the rebuilt `frontend/dist`; every client route; binding `CONFIGURED`; real browser opened deep links and showed `LOOPBACK CONFIGURED`; stopped gracefully with the browser open |
| Frontend | `tsc` 0; 90 passed; `frontend/dist` rebuilt (byte-identical to the build already present) |
| Static | 144 Python files parse with warnings as errors; `start_prahari.ps1` 0 parse errors |

The DNS client cache on this host is still empty (0 entries), so the one
unproven DNS step remains unproven.

### 7.4 Final run before the Windows commit (ADR-089)

After the independent review's fixes: backend 1336 passed, 8 skipped, 0
failed; `live_windows` 15 passed; verifier 23/23 under `python` and `-O`;
frontend `tsc` 0 and 91 passed; static 144 files, 0 problems. The real
launcher on a temporary database served the rebuilt `frontend/dist` and
stopped gracefully. Python 3.12.10, Node 24.20.0.
