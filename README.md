# PraHari — The Digital Sentinel

> Unified Cybersecurity Telemetry Ingestion, Canonical Normalization, SQLite Persistence, Descriptive Analytics, Research Feasibility Gating, and Causal Future Threat Forecasting.

---

## 1. System Overview

PraHari is a production-grade, local-first cybersecurity intelligence platform designed for dependable telemetry processing, auditability, and honest predictive threat modeling. It unifies high-throughput telemetry ingestion, schema validation, transactional SQLite persistence, factual descriptive profiling, and a causal machine-learning forecasting engine into a single executable application served on loopback (`127.0.0.1:8000`).

```
[ Telemetry Sources ] ──► [ Ingestion & Normalizer ] ──► [ SQLite (WAL) ] ──► [ Analytics & Forecasting ] ──► [ Unified SPA Dashboard ]
 • WINDOWS LIVE HOST      • IP/Port/Time Validation      • Events               • Descriptive Profiling        • Live Telemetry
   (connection table)     • UTC Normalization            • Sources              • Feasibility Gating           • Overview & Explorer
 • CSV (CIC-IDS)          • Quality Flags & Rejection    • Analyses             • Causal ML Pipeline           • Threat Forecaster
 • Zeek (conn.log)        • Deterministic event ids      • Audit Log            • Split-integrity reporting    • Audit Log Viewer
 • Suricata (EVE Flow)    • Canonical Schema 1.0.0
 • Synthetic Replay/Sim
```

**Data categories are kept strictly separate.** Live host telemetry
(`live_telemetry`), historical imports (`historical_import`), replays
(`historical_replay`), synthetic demonstrations (`synthetic_demo`) and test
fixtures (`test_fixture`) are distinct values on every stored record, and the
dashboard shows which one it is displaying. Synthetic records are never
presented as live observations.

---

## 2. Key Architecture Pillars

- **Unified Single-Port Deployment**: FastAPI backend serves the production React SPA directly on `http://127.0.0.1:8000/`. Client-side deep links (`/events`, `/forecast`, `/analytics`) fall back gracefully to `index.html` with strict path-traversal prevention.
- **Multi-Format Ingestion**: Native adapters for multi-column CSVs, Zeek `conn.log` NDJSON, Suricata EVE logs, and synthetic flow streams.
- **Factual Descriptive Analysis vs. Forecasting**: Factual empirical summaries are strictly segregated from predictive modeling to prevent operator confusion.
- **Live Windows Telemetry**: Polls this host's TCP connection table
  (`Get-NetTCPConnection`) for genuine connection metadata. No administrator
  rights, no driver, no packet capture, no third-party dependency. Repeat
  sightings of a still-open connection are suppressed by deterministic event
  ids, so polling never inflates counts. See section 5.
- **Backend-Enforced Research Gate**: Forecasting readiness is enforced at
  the API, not by hiding dashboard controls. Every entry point refuses with
  HTTP 409, the unmet requirements and observed-versus-required values.
  Unlabelled traffic is never counted as benign.
- **Causal Threat Forecasting**: Nominal observation window ($W=60s$), lead
  time buffer ($30s$), prediction horizon ($H=60s$), stride ($15s$). Training
  windows whose label horizon reaches into the evaluation period are
  **purged**, and the configuration actually used is reported alongside every
  metric. When the data cannot support a leakage-free holdout, evaluation is
  **refused** rather than reported.
- **Research Feasibility Engine**: Advisory audit requiring $\ge 25$ events,
  $\ge 99\%$ temporal monotonicity, and label balance. It reports feasibility;
  it does not silently disable endpoints.
- **Zero-Dependency SQLite Persistence**: Embedded SQLite with WAL mode (`PRAGMA journal_mode=WAL`) and foreign keys (`PRAGMA foreign_keys=ON`).

---

## 3. Directory Layout

```
Implementation/
├── backend/
│   ├── app/
│   │   ├── adapters/          # csv_import.py, json_stream.py, synthetic_replay.py,
│   │   │                      #   windows_telemetry.py (live Windows connection table)
│   │   ├── api/v1/            # health, events, sources, import, stream, analysis,
│   │   │                      #   research, forecast, audit, collector (live telemetry)
│   │   ├── core/              # Config, profile settings, and loopback defaults
│   │   ├── models/            # Feature extractor, forecaster pipeline, model registry
│   │   ├── research/          # Feasibility audit engine and scientific gating
│   │   ├── schemas/           # Pydantic canonical models (events.py)
│   │   ├── services/          # analysis.py (descriptive engine),
│   │   │                      #   collector.py (live telemetry polling service)
│   │   ├── storage/           # SQLite database layer with WAL mode,
│   │   │                      #   protected-database guard
│   │   ├── agents/            # sensor_agent.py (optional forwarding agent)
│   │   └── main.py            # FastAPI application & SPA static server
│   ├── tests/
│   │   ├── fixtures/          # sample_flows.csv (45-row fixture with valid & malformed rows)
│   │   ├── integration/       # API, deployment/SPA, and end-to-end pipeline tests
│   │   └── unit/              # Adapters, database, analysis, forecaster, research tests
│   └── prahari.db             # Local SQLite database (gitignored - holds real telemetry)
├── frontend/
│   ├── src/                   # React + TypeScript SOC interface
│   ├── dist/                  # Pre-compiled production bundle served by FastAPI
│   └── package.json
├── scripts/
│   ├── verify_live_windows_telemetry.py # Live Windows telemetry end-to-end verification
│   ├── simulate_synthetic_stream.py     # SYNTHETIC record simulator (not live telemetry)
│   ├── verify_live_launcher.py          # Server launch & API workflow verification
│   └── verify_forecasting_pipeline.py   # Empirical forecasting evaluation audit
├── start_prahari.ps1          # PowerShell turnkey launcher (port conflict preflight, venv check)
├── start_prahari.bat          # Windows batch launcher
├── Dockerfile                 # Multi-stage container definition
├── docker-compose.yml         # Container compose config with persistent volume
├── ARCHITECTURE.md            # Detailed system architecture specification
├── DECISIONS.md               # Architecture Decision Records (ADRs)
└── IMPLEMENTATION_STATUS.md   # Complete verification matrix & test results
```

---

## 4. Quickstart & Deployment

> **If a PraHari instance is already running, check which code it is
> running before you trust it.** `uvicorn` is launched without
> `--reload`, so a process started before a fix was applied keeps serving
> the old code indefinitely — the source on disk says nothing about what
> is in memory. A running instance that predates the ADR-062 fix still
> writes a `descriptive_analyses` row on a dashboard page load.
>
> One read-only check tells you which it is:
>
> ```bash
> curl -s -D - -o /dev/null http://127.0.0.1:8000/api/v1/health
> ```
>
> An `x-request-id` response header means the current code is loaded. Its
> absence means the instance predates ADR-063, and therefore ADR-062 too.
>
> Note before restarting: the current code adds an `audit_events`
> `request_id` column, so the first start against an older database
> performs an additive `ALTER TABLE` on it. That is a schema change to an
> operational database — make it deliberately, and back the file up first.


### Option A: PowerShell Turnkey Launcher (Recommended)
1. Run preflight conflict verification:
   ```powershell
   powershell -ExecutionPolicy Bypass -File .\start_prahari.ps1 -CheckOnly
   ```
2. Launch PraHari on `127.0.0.1:8000`:
   ```powershell
   powershell -ExecutionPolicy Bypass -File .\start_prahari.ps1
   ```
3. Open your browser:
   - **Unified SOC Dashboard**: [http://127.0.0.1:8000/](http://127.0.0.1:8000/)
   - **Interactive API Documentation**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

### Option B: Windows Batch Launcher
Double-click or run:
```cmd
start_prahari.bat
```

### Option C: Manual Backend Launch
```powershell
.\backend\.venv\Scripts\python.exe -m uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 8000
```

---

## 5. Live Windows Telemetry (Genuine Host Data)

PraHari's primary operational data source is the **Windows TCP connection
table** on the machine it runs on. It is read with `Get-NetTCPConnection`,
which needs no administrator rights, installs nothing, captures no packets,
and changes no network settings.

### Start and stop collection

From the dashboard: open the **Live Telemetry** tab and press
**Start collection** (or **Poll once** for a single sample).

From the API:

```bash
curl -X POST http://127.0.0.1:8000/api/v1/collector/start -H "Content-Type: application/json" -d "{\"interval_seconds\":15}"
```

```bash
curl http://127.0.0.1:8000/api/v1/collector/status
```

```bash
curl -X POST http://127.0.0.1:8000/api/v1/collector/stop
```

Collection never starts by itself, and the database is never seeded with
sample data on startup. Stopping the server also stops the collector cleanly.

### What this source can and cannot see

| Attribute | Available | Notes |
|---|---|---|
| Source/destination IP and port | **Yes** | Real 5-tuple from the OS |
| Protocol | **Yes** | TCP (transport only) |
| TCP connection state | **Yes** | Established, CloseWait, … |
| Owning process id **and name** | **Yes** | Name resolved unprivileged; command line never collected |
| Connection start time | **Yes** | OS `CreationTime` becomes `observed_at` |
| Destination hostname | **Inferred** | Not reported by this source — see §5c |
| Byte counts | **No** | Stored as `null`, flagged `missing_field` |
| Packet counts | **No** | Stored as `null`, flagged `missing_field` |
| Completed-flow duration | **No** | Stored as `null`, flagged `missing_field` |
| Application-layer protocol | **No** | Not exposed by this source |
| Attack labels | **No** | No ground truth exists for local traffic; none is invented |

Further limits, reported by `/api/v1/collector/status` itself:

- **Snapshot polling.** Connections that open *and* close between two polls
  are never observed. Gaps in collection are recorded and shown in the UI.
- **UDP is not collected.** Windows exposes only local UDP endpoint binds,
  with no remote peer, so no source-to-destination record can be built.
- **Loopback-only connections are out of scope by default.** They are counted
  as *filtered*, not as rejections.
- This is **connection metadata, not packet-level monitoring.**
- **A destination port is not an application protocol.** Port 443 is
  conventionally HTTPS, but this source observes no application-layer
  traffic. HTTP status codes are application-layer values and have no TCP
  equivalent; they appear only via §5c.
- **Implausible timestamps are rejected.** Windows reports an unset
  connection start as the FILETIME epoch (1601-01-01); such values are
  discarded in favour of the poll time and flagged.

### Ingestion accounting

Every observed record falls into exactly one outcome: *accepted*, *rejected*
(unusable data), *duplicate* (a repeat sighting of a connection already
recorded), or *filtered* (out of collection scope). Repeat sightings and
filtered records are tracked separately so the rejection count keeps meaning
"something was wrong with the data".

### Verify the whole live path

With the server running:

```bash
backend/.venv/Scripts/python.exe scripts/verify_live_windows_telemetry.py
```

This polls genuine host activity and checks every step (collection,
normalization, persistence, source health, analytics and provenance),
reading each figure back from the API.

### Privacy

The collected data describes **this machine's** network activity: its local
address, the remote addresses it connects to, ports, connection times and
owning process ids. It is stored only in the local SQLite database, is never
transmitted anywhere, and `*.db` is gitignored so it cannot be committed. No
payload contents are captured. Only this host is observed; there is no
network-wide or other-device collection.

### Data-quality semantics

A null is not self-explanatory, so PraHari distinguishes:

| Reported as | Meaning |
|---|---|
| `unsupported_field_counts` | The source **cannot** measure it (e.g. bytes from a connection table). Not a defect |
| `missing_field_counts` | The source **does** support it but did not provide it. A real gap |

Metrics that cannot be computed stay `N/A`; zero is never substituted. A
record is only counted as "warned" for a genuine defect, so a structurally
limited source no longer reports every record as faulty.

---

## 5c. Domain Attribution (inference, with evidence)

Destination hostnames are inferred from **locally observed DNS
resolutions** read from the Windows DNS client cache. No DNS query is sent
for this and no external service is contacted.

Every attribution carries its method, confidence, evidence timestamp,
competing candidate hostnames and limitations:

| Confidence | When |
|---|---|
| HIGH | One recent local resolution for this exact address, or a hostname reported by an app-layer source |
| MEDIUM | Recent resolution, but several hostnames share the address (CDN / shared hosting) |
| LOW | Evidence older than 30 minutes, or reverse DNS |
| NONE | No defensible association — shown as `unknown` |

**Reverse DNS is different and is labelled as such.** A PTR record names the
*owner of the address* — usually a CDN edge such as
`server-….cloudfront.net` — not the site that was requested. It is off by
default, sends DNS queries when enabled, is rendered as `IP OWNER` rather
than as a domain, and is excluded from "top domains" aggregation.

```bash
curl -X POST http://127.0.0.1:8000/api/v1/enrichment/dns/refresh
```

```bash
curl http://127.0.0.1:8000/api/v1/enrichment/status
```

> **Known limit on hosts using encrypted DNS.** If the browser or system
> uses DoH/DoT, the Windows resolver cache stays empty and hostnames cannot
> be inferred. The API reports this as an explicit `diagnosis` rather than
> as "no domains observed". An authorized external resolver log can be
> supplied via `POST /api/v1/enrichment/dns/observations`.

---

## 5d. Application-Layer Telemetry (optional, disabled by default)

HTTP method, path, status and timing are **not observable** from the
connection table. They appear only when an authorized producer the operator
runs themselves reports them.

PraHari implements the receiving half only. It never configures a proxy,
installs a certificate, decrypts TLS, changes browser settings, installs
capture drivers, or requests elevation.

```bash
PRAHARI_ENABLE_APPLICATION_LAYER_INGEST=true
```

Enabling the endpoint captures nothing by itself. Bodies, cookies,
authorization headers and credentials have no field in the accepted payload
and are rejected outright; query strings are stripped by default.

Full option analysis (browser extension vs. inspection proxy vs. ETW vs.
packet capture), privacy controls and a producer sketch:
[docs/APPLICATION_LAYER_VISIBILITY.md](docs/APPLICATION_LAYER_VISIBILITY.md).

---

## 5b. Synthetic Stream Simulator (NOT live telemetry)

For exercising the ingestion path without a sensor, a simulator is provided.
It fabricates records; it observes nothing:

```bash
backend/.venv/Scripts/python.exe scripts/simulate_synthetic_stream.py --count 10
```

Records enter under `data_category='synthetic_demo'` with a source id that
identifies them as simulated. The script refuses source ids that do not begin
with `synthetic`, `sim` or `test`.

---

## 6. Verification & Automated Test Suites

### Run the automated test suite (1070 backend tests, 4 skipped)

```bash
cd backend && .venv/Scripts/python.exe -m pytest tests/ -v
```

Two of those tests are marked `live_windows`: they query the real Windows
connection table and are skipped automatically on other platforms. Run only
them with:

```bash
cd backend && .venv/Scripts/python.exe -m pytest -m live_windows -v
```

A mocked collector test proves the pipeline wiring; only the `live_windows`
tests demonstrate that genuine host telemetry is observed.

### Verify live Windows telemetry end-to-end (server must be running)

```bash
backend/.venv/Scripts/python.exe scripts/verify_live_windows_telemetry.py
```

### Run Live Server & Lifecycle Verification
```powershell
.\backend\.venv\Scripts\python.exe scripts\verify_live_launcher.py
```

### Run Empirical Forecasting Audit
```powershell
.\backend\.venv\Scripts\python.exe scripts\verify_forecasting_pipeline.py
```

### Recompile Frontend Production Bundle
```powershell
cd frontend
npm run build
```

---

## 7. Documentation Index

- [ARCHITECTURE.md](ARCHITECTURE.md): Full technical architecture, data model, causal window formulation, and security model.
- [DECISIONS.md](DECISIONS.md): Architecture Decision Records (ADR-001 through ADR-008).
- [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md): Empirical test verification matrix, forecasting findings, and environmental limitations.

---

## 8. Frontend Tests

```bash
cd frontend && npm test
```

36 tests covering the error boundary, the Feasibility and Stream & Replay
page contracts and states, numeric-formatting safety, and navigation across
every tab (including with all API calls failing).

A render error in one page can no longer blank the application: page
content is wrapped in an `ErrorBoundary` that contains the failure, keeps
navigation usable, and resets when you switch tabs.

Backend contract tests (`backend/tests/integration/test_frontend_api_contract.py`)
compare every TypeScript interface against the live OpenAPI schema, so a
field the dashboard reads but the API does not return fails the suite
instead of crashing the browser.

---

## 9. Ingestion Counter Definitions

The Live Telemetry page shows two groups of counters with **different
scopes**, which is why they do not match each other:

| Counter | Scope | Meaning |
|---|---|---|
| Observed | collector process (resets on restart) | Rows read from the Windows connection table across all polls |
| Accepted | collector process | Normalized into canonical events by this process |
| Repeats suppressed | collector process | Same still-open connection seen again; not a new event |
| Filtered (out of scope) | collector process | Excluded by policy (loopback-only). Not a defect |
| Rejected (unusable) | collector process | Failed validation |
| Events persisted | collector process | **New database rows** written this run |
| Events stored | database, all time | Rows in SQLite for that source |

Invariant (tested): `observed = accepted + repeats + filtered + rejected`.

`accepted` can exceed `events persisted`: after a restart the adapter's
in-memory dedup cache is empty, so connections are re-normalized, but
deterministic event ids mean storage recognises them and inserts nothing.

---

## 10. Why Domain Attribution May Show Nothing

`GET /api/v1/enrichment/dns/diagnose` inspects this host's resolver
configuration **read-only** — it changes no setting, flushes no cache and
sends no query — and reports why local DNS evidence is or is not available.

On the development machine the cache is empty. The diagnosis reports the
measured evidence and **explicitly declines to name a single cause**:
several explanations are consistent with it (an application using its own
encrypted DNS, the cache being unreadable without elevation, expired
entries, or connections made directly by IP).

Note in particular that the configured resolvers appear in Windows'
built-in table of *well-known DoH servers* but have **auto-upgrade off**.
That table records which servers **offer** DoH; it is **not** evidence that
this machine used DoH for any connection. Hostnames correctly remain
`unknown`.

---

## 11. Optional Browser Telemetry Probe (application-layer HTTP)

The Windows TCP connection table cannot observe HTTP. For request method,
path, status and timing, an optional WebExtension is provided in
[`extension/`](extension/README.md).

It is **off by default**, PraHari does not install it, and the application
works fully without it. It collects metadata only — never bodies, cookies,
headers, credentials, query strings or page content — needs no
administrator rights, no certificate, no proxy and no network change, and
sends only to your local PraHari endpoint.

```bash
set PRAHARI_ENABLE_APPLICATION_LAYER_INGEST=true
```

Then load `extension/` via `chrome://extensions` → Developer mode → **Load
unpacked**, and press **Start collection** in its popup. Full instructions
and limits: [extension/README.md](extension/README.md).

Verify the contract without installing anything:

```bash
python scripts/simulate_browser_producer.py
```

That uses a **simulated** producer (source id `browser_probe_simulated`).
It proves the ingestion contract; it does **not** prove a real browser
produces the data.

---

## 12. Alignment With the Architecture Blueprint

The governing specification is the *Complete Cross-Platform Architecture
Blueprint* (`../Implementation.docx` / `.pdf`). Section 18 defines the
acceptance criteria.

**[docs/REQUIREMENTS_MATRIX.md](docs/REQUIREMENTS_MATRIX.md)** maps every
criterion to its code, tests and evidence, with an explicit status.

Current position, stated plainly:

- **MET**: canonical contracts shared by live and replay ingestion; adapter
  capability and health reporting; target and negative-label semantics;
  dashboard fidelity; the full test matrix including security tests; no
  disruptive response; documented limitations and negative results.
- **PARTIAL**: Windows verified / Linux not; host sensor tested / network
  sensor not; manifest covers the local store but no external dataset;
  no sequence model (deliberately — see the blueprint's advanced-feature
  rule); lead time and generalization not measured; retention reported but
  not enforced.
- **NOT MET**: central deployment with authenticated multi-source identities.

**No forecasting effectiveness is claimed.** Every metric produced so far
comes from synthetic data; locally collected telemetry has no incident
labels and the research gate refuses it.

---

## 13. Reproducible Experiments

Capture a manifest of an evaluation, then verify it still reproduces:

```bash
curl -X POST http://127.0.0.1:8000/api/v1/experiments/capture -H "Content-Type: application/json" -d "{\"experiment_id\":\"baseline-1\"}"
```

```bash
curl -X POST http://127.0.0.1:8000/api/v1/experiments/baseline-1/replay
```

The manifest records the dataset fingerprint, provenance, target
definition, window and split parameters, seed, feature set and results —
and **no telemetry**, so it is safe to share. Replay **fails closed** if
the dataset, schema or feature set has changed, rather than reporting a
number computed from different inputs as a reproduction.

Timings and timestamps are declared non-deterministic; instance counts,
split sizes and confusion matrices are expected to match exactly.

---

## 14. Retention

Retention is **enforced manually and never automatically** — there is no
scheduler and no startup hook.

```bash
curl -X POST http://127.0.0.1:8000/api/v1/retention/preview -H "Content-Type: application/json" -d "{}"
```

Preview changes nothing. To actually delete:

```bash
curl -X POST http://127.0.0.1:8000/api/v1/retention/enforce -H "Content-Type: application/json" -d "{\"confirm\":\"DELETE-EXPIRED-TELEMETRY\"}"
```

Age is measured from `observed_at` in UTC. Telemetry sources, import
summaries, analyses and audit records are never pruned, and test fixtures
are outside the default policy.

---

## 15. Central Deployment (optional, disabled by default)

Local deployment is loopback-only and unauthenticated by design. **Central
mode requires credentials and refuses to start without them.**

```bash
python scripts/manage_credentials.py init --file secrets/credentials.json
```

```bash
python scripts/manage_credentials.py add --file secrets/credentials.json --source-id sensor-01 --role ingest
```

The token is displayed once and cannot be recovered; the file stores
hashes only and `secrets/` is gitignored. Then:

```bash
set PRAHARI_DEPLOYMENT_MODE=central
```

```bash
set PRAHARI_CREDENTIALS_FILE=secrets/credentials.json
```

Clients send `Authorization: Bearer <token>`. A credential is scoped to one
source: an unscoped query returns only that source's data, and requesting
another source returns **403**. The `admin` role may read all sources and
the audit log.

> Central mode has been verified **over loopback only**. Exposing a
> listener beyond 127.0.0.1 is outside this project's safety boundary and
> has not been done or tested.

---

## 16. Platform Support and Network Sensors

PraHari runs on **Windows 11** (fully verified) and on **Linux** (the
application starts, serves and shuts down cleanly; verified on Ubuntu
26.04 / Python 3.14.4 in an earlier run).

**Linux host telemetry is implemented but not yet executed on Linux.**
`app/adapters/linux_telemetry.py` reads `/proc/net/tcp` and
`/proc/net/tcp6` and emits the same raw record shape as the Windows
adapter, so the collector, normalization and deterministic event identity
are the same code on both. It is tested against real `/proc` text and
synthetic `/proc` trees, and four tests that need a live Linux host or
POSIX symlinks are **declared skips** on Windows. Until those run on
Linux, this README does not call Linux host collection verified.

To verify on an authorized Linux host:

```bash
cd backend && python -m pytest tests/unit/test_linux_telemetry.py -v
```

macOS is unassessed and Docker is unverified. See
[docs/PLATFORM_SUPPORT.md](docs/PLATFORM_SUPPORT.md) for what was checked.

PraHari **does not capture packets** and will not. For network-wide
telemetry it ingests JSON from an existing sensor:

- **Suricata** — enable `eve-log` with `flow`, `dns`, `http`, `alert`.
- **Zeek** — `redef LogAscii::use_json = T;`

POST the records to `/api/v1/stream/ingest/ndjson`. The adapter contract is
pinned by 26 tests.

> A Suricata signature is stored as `detector_output`, never as ground
> truth. It is the detector's opinion. Training on detector labels produces
> a model that predicts that detector's alerts, and PraHari says so in the
> readiness report rather than letting the metrics imply otherwise.

Monitoring a network you do not own or administer requires the owner's
written authorization. That is a prerequisite, not a configuration step.

---

## 17. Additional Host Observations (Windows)

Two further unprivileged, read-only sources. Neither captures packets.

### UDP endpoints

```bash
curl -X POST http://127.0.0.1:8000/api/v1/hostobs/udp/poll
```

Locally **bound UDP sockets** — which process holds which local port. UDP
is connectionless and Windows records no peer, so these events carry no
destination at all, and the capability profile declares `dst_ip` /
`dst_port` *not applicable* rather than missing. Pass `?persist=false` to
inspect the source without adding to the dataset.

### Interface counters

```bash
curl http://127.0.0.1:8000/api/v1/hostobs/interfaces
```

Real cumulative bytes and packets **per network interface** — the only
genuine volume measurement available without packet capture.

> These are **not flow metrics**. They cannot be attributed to a
> connection, a process or a destination, and they must never be summed
> alongside per-flow byte counts from an imported dataset. The payload
> carries `measurement_scope: "interface_cumulative"` and
> `attributable_to_flow: false` so this cannot be lost in transit. They are
> never written into `normalized_events`.

A delta against the previous reading is included when one exists. Across an
adapter reset no delta is derived.

Both endpoints return `501 unsupported_platform` off Windows.

---

## 18. Lead Time and Uncertainty

**How far ahead can it warn?**

```bash
curl -X POST http://127.0.0.1:8000/api/v1/forecast/lead-time-curve -H "Content-Type: application/json" -d "{\"lead_times_seconds\":[0,30,60,120]}"
```

Re-runs the complete protocol once per lead time with everything else held
constant. A lead time whose split cannot support an honest evaluation comes
back as a **refusal with its reason**, never silently omitted — omitting it
would imply the curve was measured and flat there.

**How much of the number is noise?**

```bash
curl http://127.0.0.1:8000/api/v1/forecast/uncertainty
```

Percentile bootstrap intervals over the held-out instances. Refused, with a
stated reason, when the holdout has fewer than 20 instances or 5 positives,
or only one class.

Both are subject to the same research gate as training.

---

## 19. Models

| Model | Kind |
|---|---|
| `baseline_constant` | Majority class |
| `baseline_threshold` | Interpretable rate heuristic |
| `logistic_regression` | Interpretable linear |
| `random_forest_forecaster` | Nonlinear ensemble |
| `temporal_window_stack` | **Temporal** — the previous N windows concatenated, so order matters |
| `lstm_forecaster` | **LSTM** — single layer, BPTT with Adam, implemented in NumPy |

All five are evaluated on the same target, dataset and purged chronological
split. Lag stacking for the temporal model is applied **after** the split,
separately per side, so a test instance can never carry a training-period
window in its lags.

The LSTM is hand-written, so its correctness is **demonstrated**: analytic
gradients match central finite differences to a worst relative error of
1.3e-07, and it reaches 100% holdout accuracy on a task whose answer is
visible only in the first timestep (a memoryless model scores below 0.70
on the same task).

> **It is the worst non-baseline model on the data available here** —
> PR-AUC 0.751 against 0.886 for the window-stack model. That is reported,
> not buried. There is no Transformer.

Add generalization to the picture:

```bash
curl -X POST http://127.0.0.1:8000/api/v1/forecast/generalization -H "Content-Type: application/json" -d "{\"group_by\":\"source_id\"}"
```

Leave-one-group-out transfer, with the within-group score beside it so the
**gap** is readable. The report states whether the groups are genuinely
independent environments — several synthetic groups from one generator are
not, and it says so.

---

## 20. Research Data Isolation

Benchmark corpora and operational telemetry do not share a database.

The operational store is the only copy of genuine observations from this
host. A benchmark corpus is a third-party artefact with its own labels,
provenance and licence. PraHari keeps them apart and **fails closed**.

```bash
export PRAHARI_RESEARCH_DATABASE_URL=sqlite:///./research/benchmark.db
```

```bash
curl http://127.0.0.1:8000/api/v1/research/import/status
```

A research import is refused **before any row is read** when the setting is
missing, invalid, or resolves to the operational database — including
through `..` or the legacy `backend/prahari.db`. There is no fallback. The
general CSV endpoints also refuse `data_category=historical_import` aimed at
the operational store.

See [.env.research.example](.env.research.example) for the full setup and
[docs/DATASET_ACQUISITION.md](docs/DATASET_ACQUISITION.md) for the import
policy, manifest fields and outstanding prerequisites.

> No dataset has been acquired, licensed, inspected, imported or validated.
> The workflow is built and tested against synthetic fixtures only.

---

## 21. Bounded Ingestion and System Health

Ingestion is **synchronous**: a request is parsed, stored and answered in
the handler, and the response reports what was actually written
(`stored_records` / `duplicate_records`). There is therefore **no queue**,
and the API says so rather than reporting a queue depth of zero — a zero
would assert an empty queue, and `null` says there is none.

Bounding is applied at admission instead. `AdmissionController` caps
concurrent in-flight ingestion; a request that cannot be admitted is
refused with **503 and `Retry-After`**, carrying `stored_records: 0`. The
slot is reserved before parsing, so a flood of large bodies cannot all be
normalized into memory at once.

`GET /api/v1/system/health` returns everything the dashboard's **System
Health** view needs, in one response:

| Block | Contents |
|---|---|
| `ingestion` | admitted / refused, stored / duplicate / rejected, conflicts, processing-latency percentiles |
| `sources` | per-source state with the freshness basis and whether it depends on the source's clock |
| `storage` | `integrity_check`, size, journal mode, migration state |
| `models` | trained models, whether inference is available |
| `adapters` | per-adapter processed / rejected counters |
| `limits` | each configured limit **with whether it is enforced** |

Every field obeys one rule: a value that was not measured is `null`,
never `0`. The UI renders those as "not measured".

```bash
curl http://127.0.0.1:8000/api/v1/system/health
```

## 22. Request Limits

| Control | Default | Enforced by |
|---|---|---|
| Max request body | 50 MB | `RequestSizeLimitMiddleware` → 413 |
| Max import records | 100,000 | lower of the request's and the configured ceiling |
| Rate limit | 600 / 60s per caller | `RateLimitMiddleware` → 429 + `Retry-After` |
| Ingestion concurrency | 8 | `AdmissionController` → 503 + `Retry-After` |

Rate limiting is keyed by **authenticated credential** where there is one,
and by client address otherwise, so one sensor cannot spend another's
allowance. `/health` is exempt so an operator can still diagnose a
deployment that is refusing them.

**Both limiters are per process.** Running several workers multiplies the
effective allowance by the worker count. No throughput figure is claimed:
none has been benchmarked.

## 23. Sensor Forwarding Agent (optional)

`backend/app/agents/sensor_agent.py` forwards locally collected events to
a central PraHari over the **existing** ingestion contract — no second
event schema and no second identity mechanism. The transport is the
standard library, so it adds no dependency on a sensor host.

```python
from app.agents.sensor_agent import AgentConfig, SensorAgent

agent = SensorAgent(AgentConfig(
    endpoint="https://prahari.example/api/v1/stream/ingest/ndjson",
    source_id="sensor-a",
    token=os.environ["PRAHARI_SENSOR_TOKEN"],   # never hard-code this
    buffer_capacity=10_000,
    batch_size=100,
))
agent.offer(event_dict)
agent.flush_once()
print(agent.health())      # statistics; never contains the token
agent.shutdown(drain=True)
```

**Delivery is at-least-once with server-side deduplication — not
exactly-once.** The agent retries until acknowledged and the server stores
at most one copy because event identity is deterministic, but a response
lost in transit causes a resend and the duplicate is absorbed at the
database, not prevented on the wire.

The buffer is **bounded and in memory**: unacknowledged events are lost if
the process is killed. Other deliberate behaviours:

- 400 / 401 / 403 / 409 / 413 are **not retried** — resending the same
  bytes is a loop. The batch is dropped with a counted, logged reason.
- Transient failures retry with bounded exponential backoff and jitter; a
  server-supplied `Retry-After` wins.
- Plaintext HTTP to a non-loopback host is **refused at configuration
  time**: a bearer credential over plaintext is compromised on first use.
- The agent registers no service, opens no port and changes no firewall
  rule. Starting it is the operator's explicit act.

## 24. Administration

The **Administration** view is wired to real endpoints; it is not a mockup.

| Operation | Endpoint | Authorization |
|---|---|---|
| Enable / disable a source | `PATCH /api/v1/sources/{id}/enabled` | admin in central mode |
| Set or clear retention | `PUT /api/v1/retention/policy` | admin in central mode |

**Changing the retention policy deletes nothing.** It sets a number;
pruning still requires `POST /api/v1/retention/enforce` with its
confirmation token. The UI says so before you submit.

Retention is reported as three values together — the period in force, its
`origin` (configured default or operator override), and the configured
default — so it is never ambiguous which one won. An unreadable stored
override falls back to the default rather than to zero, because guessing
could shorten retention, which is the direction that destroys data.

Credentials are **not** managed from the UI. They are issued, rotated and
revoked offline with `scripts/manage_credentials.py`:

```bash
python scripts/manage_credentials.py add    --file creds.json --source-id sensor-a --role ingest --expires-in-days 90
python scripts/manage_credentials.py rotate --file creds.json --credential-id <id> --overlap-days 7
python scripts/manage_credentials.py revoke --file creds.json --credential-id <id> --reason "host decommissioned"
```

A rotation keeps the `source_id`, so a rotated secret stays in the same
idempotency namespace. A revocation takes effect **on the next request**,
without restarting the backend. A remote credential-minting route was
deliberately not built: it would require the server to write the
credential store, turning a stolen admin token into the power to issue
credentials.

## 25. Telemetry Adapters: What Each One Actually Does

| Adapter | Status | Boundary |
|---|---|---|
| Windows host (`windows_telemetry.py`) | Live-verified | Connection-table polling; metadata only, no packet capture |
| Linux host (`linux_telemetry.py`) | Implemented, **not run on Linux** | `/proc/net/tcp`; process attribution is partial without elevation |
| CSV / NDJSON / Zeek / Suricata | Verified against fixtures | Parses exports; no live sensor has fed PraHari |
| NetFlow / IPFIX (`netflow.py`) | Implemented | Parses **exported** flow text (nfdump, SiLK, YAF). **Not a collector**: it does not speak the binary protocol or open a UDP port |
| Synthetic replay | Verified | Test fixtures; never evidence of real-world performance |

The NetFlow distinction matters: PraHari ingests what an authorized
collector exported. Opening a listener would mean collecting from the
network, which is out of scope without explicit authorization.

## 26. Protected Databases and Test Isolation

`prahari.db` holds genuine telemetry from the operator's host. It is
gitignored and must never be used by tests.

`app/storage/guard.py` enforces that: under pytest, `Database.initialize()`
**refuses** any database outside a temporary directory, because
`initialize()` creates tables and applies migrations. Outside pytest it is
a no-op, so a real deployment upgrades exactly as before.

This exists because of a real incident, recorded in ADR-054: an ad-hoc
diagnostic imported the app without overriding the database dependency,
the FastAPI lifespan ran `initialize()`, and a pending additive migration
was applied to the live database. The data survived intact, but the guard
and a WARNING-level log on any migration against a populated table were
added so it cannot happen silently again.

## 27. What PraHari Does Not Establish

Read this before drawing conclusions from anything above.

- **No real-data predictive performance.** No labelled corpus has been
  acquired. Every metric in this repository comes from synthetic fixtures
  and is labelled as such. The scientific acceptance criteria are
  **BLOCKED**, not met.
- **No live network-sensor integration.** The Zeek/Suricata adapters are
  verified against fixtures; no real sensor has fed this system.
- **No Linux host-collection run.** The adapter exists and is tested on
  fixtures; the Linux-only tests are declared skips on Windows.
- **No cryptographic source authenticity.** Credentials are bearer tokens.
  PraHari does not terminate TLS, so central mode must sit behind HTTPS —
  a deployment prerequisite, not a property of this code.
- **No exactly-once delivery** anywhere, and no automatic blocking,
  isolation or remediation. PraHari is advisory.

A passing test suite shows the software behaves as specified. It is not
evidence that PraHari can forecast attacks.
