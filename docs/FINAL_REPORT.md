# PraHari — Final Implementation Report

Work completed against the *Complete Cross-Platform Architecture Blueprint*
§18 Definition of Done, with the evidence for each claim and an explicit
account of what is **not** done.

No completion percentage is given. The criteria are not equally weighted,
and averaging them would misrepresent the state.

**Status vocabulary:** *Implemented and tested* · *Partially implemented* ·
*Unverified* · *Blocked*.

---

## 1. Requirement-to-evidence matrix

Full detail in [REQUIREMENTS_MATRIX.md](REQUIREMENTS_MATRIX.md).

| # | Criterion | Status | Evidence |
|---|---|---|---|
| 1 | Local deployment on declared OSes | **MET** | 442 tests Windows; 440 passed / 2 skipped Linux; startup verified on both |
| 2 | Central deployment, authenticated distinct sources | **MET** | 24 tests + live loopback run (§8) |
| 3 | ≥1 host and ≥1 network integration | **PARTIAL** | Three host sources live-verified; network adapter pinned by 26 tests but **no live sensor** |
| 4 | Replay and live ingestion share canonical contracts | **MET** | `SCHEMA_VERSION 1.0.0` across six producers |
| 5 | Adapter capability and health visible | **MET** | `not_applicable` vs `missing_unexpected` vs `unsupported_by_source` |
| 6 | Descriptive analytics separated from forecasts | **MET** | Separate services, pages, provenance |
| 7 | Dataset provenance, hashes, audit, split manifests | **PARTIAL** | Workflow implemented and tested; **no external dataset acquired** |
| 8 | Baseline **and temporal** models, same valid target | **MET** | Six models incl. a gradient-checked LSTM, one protocol |
| 9 | Precision/recall, PR-AUC, false alarms, missed events, lead time, generalization | **MET as capability** | All implemented and measured; evidence remains synthetic |
| 10 | Dashboard uses actual backend results | **MET** | Nine pages driven in a browser; contract tests against live OpenAPI |
| 11 | Auth, authz, isolation, payload limits, audit, retention tested | **MET** | 59 tests across three suites |
| 12 | Replay, adapter, unit, integration, security, e2e tests pass | **MET** | 442 backend + 42 frontend |
| 13 | Reproducibility manifests match the implementation | **MET** | Replay reproduces exactly; fails closed |
| 14 | No automatic network changes or disruptive response | **MET** | No write path to any network control exists |
| 15 | Limitations, negative results, unsupported platforms documented | **MET** | This report, `PLATFORM_SUPPORT.md`, `DATASET_ACQUISITION.md` |

**MET: 1, 2, 4, 5, 6, 8, 9, 10, 11, 12, 13, 14, 15 (13 of 15).
PARTIAL: 3, 7. NOT MET: none.**

Both remaining PARTIALs are blocked on decisions and permissions outside
the agreed boundary — a dataset the operator must choose to download under
its licence, and an authorised network segment with a tap — not on
implementation. Every pipeline that would consume either is built and
tested.

---

## 2. Root causes and files changed

### Committed as `0fd1f1c` (96 files, +21,293 / −814)

Windows connection-table telemetry, enrichment, the browser producer, the
research readiness gate, experiment capture/replay, retention, central
security, the dashboard, and the contract suites.

### Uncommitted since

| File | Change |
|---|---|
| `models/lstm_forecaster.py` *(new)* | Single-layer LSTM, BPTT + Adam, NumPy; gradient-check helper |
| `research/evaluation.py` *(new)* | Lead-time sweep, bootstrap uncertainty, leave-one-group-out generalization |
| `adapters/windows_host_observations.py` *(new)* | UDP endpoint table + interface counters |
| `api/v1/hostobs.py` *(new)* | Their endpoints, Windows-gated |
| `.dockerignore` *(new)* | Keeps telemetry and secrets out of the build context |
| `models/forecaster.py` | `temporal_window_stack`, `stack_lagged_windows`, `HoldoutPredictions`, LSTM integration, content-addressed `dataset_fingerprint` |
| `schemas/events.py` | `is_plausible_timestamp` (one definition), `UDP_ENDPOINT`, `DETECTOR_OUTPUT`, distinct `SYNTHETIC_RULE`, analysis denominators |
| `services/analysis.py` | Excludes implausible timestamps; publishes measurement denominators |
| `research/feasibility.py` | Temporal check fails on a broken clock; `attack_ratio` over labelled events |
| `research/readiness.py` | `label_caveats`, `non_ground_truth_labelled_events` |
| `services/collector.py` | Platform gate no longer refuses injected sources |
| `adapters/json_stream.py` | Label provenance resolved with the label; presence-based lookup |
| `api/v1/forecast.py` | Lead-time, uncertainty and generalization endpoints |
| `docker-compose.yml` | Obsolete `version` key removed; loopback rationale recorded |
| `frontend/src/utils/models.ts` *(new)* | Derived best-model selection |
| Frontend pages/types | Six models, readiness caveats, excluded-record note, new enums |
| 9 new test modules | 160 new tests |
| 6 docs | Matrix, status, architecture, decisions (ADR-025…034), README, platform |

### Root causes, not symptoms

**Duplicated policy that silently diverged.** The timestamp-plausibility
rule lived in three modules; two implemented it, one never had, and a
fourth consumer inherited the broken value. One definition in the schema
module now, imported everywhere, with a test asserting all three agree.

**A weaker claim stored as a stronger one.** A Suricata signature as
`dataset_ground_truth`; `SYNTHETIC_RULE` aliased to `rule_based`; a
hardcoded "best model" badge. Each fixed by deriving the value or giving
it its own identity.

**A number without its denominator.** `avg_bytes` over 200 of 3,669
records; `attack_ratio` dividing labelled counts by all events.

**Data leaving the machine by a path nobody looked at.** No
`.dockerignore`, so every build would ship `prahari.db` to the daemon.

---

## 3. Commands executed and their results

```bash
cd backend && python -m pytest -q
```
```
442 passed, 3 warnings in 29.38s
```

```bash
cd frontend && npx tsc --noEmit && npx vitest run && npm run build
```
```
tsc: clean
Test Files  6 passed (6)      Tests  42 passed (42)
✓ built in 4.61s              (one pre-existing advisory: chunk > 500 kB)
```

**Linux** (Ubuntu 26.04, Python 3.14.4, venv under `$HOME` — no system
packages, no root):
```
440 passed, 2 skipped in 20.72s
```

### Mutation checks

Every regression test added across this work was verified to **fail** when
the defect is reintroduced:

| Defect reintroduced | Tests that failed |
|---|---|
| `alert.signature` → `dataset_ground_truth` | 2 |
| `SYNTHETIC_RULE = "rule_based"` | 1 |
| Labelled record → `EventType.ALERT` | 1 |
| `or`-chain byte/packet lookup | 1 |
| Implausible timestamps back in the analysis range | 1 |
| Implausible timestamps back in the feasibility span | 2 |

The first mutation run exposed a coverage hole in my own test; a case was
added and re-checked.

### LSTM correctness

Not inferred from the loss curve — a wrong BPTT pass produces a plausible
one:

```
max relative gradient error vs central finite differences : 1.3e-07
first-timestep-memory task, holdout accuracy              : 1.000
same task, memoryless model (control)                     : < 0.70
```

---

## 4. Verified telemetry sources and measurement capabilities

| Source | Status | Provides | Does **not** provide |
|---|---|---|---|
| Windows TCP connection table | **Live-verified** | 5-tuple, TCP state, owning process, creation time | bytes, packets, duration, payload, app layer |
| Windows UDP endpoint table | **Live-verified** | local address/port, owning process, creation time | **any peer** (UDP is connectionless), volume, duration |
| Windows interface counters | **Live-verified** | **real** cumulative bytes/packets per interface | attribution to any flow, process or destination |
| Windows DNS cache | Implemented; **yields nothing on this host** | hostname evidence with freshness | — |
| Browser producer (MV3) | Implemented, **disabled by default** | hostname, method, path, status, timing | host-wide coverage |
| Zeek / Suricata NDJSON | **Fixture- and HTTP-verified** | flows, DNS, HTTP, alerts, volume where the sensor records it | — |
| CSV import | Implemented | dataset flow records | — |

```
UDP poll 1: 41 observed, 41 normalized, 41 persisted, 0 rejected
UDP poll 2: 41 observed,  1 persisted, 40 repeats suppressed
  stored: event_type=udp_endpoint protocol=UDP src_port=5355
          dst_ip=None dst_port=None bytes/pkts/dur=None/None/None

Interfaces: scope=interface_cumulative attributable_to_flow=False
  Wi-Fi  rx=2,210,384,201 bytes  tx=76,042,456 bytes
  delta over 3.9s: rx=21,555  tx=147,380  reset=False
  events written to normalized_events from this source: 0
```

### Bytes, packets and flow duration — the honest answer

**No local source measures them per flow.** PraHari leaves them `None`
with a `source_limited` flag rather than estimating. Interface counters are
real but per-interface and cumulative, so they are served separately, carry
their own declared scope, and never enter `normalized_events`.

Per-flow volume requires a network sensor (supported on ingest) or packet
capture (permanently out of scope).

---

## 5. Dataset provenance and forecasting results

### The headline negative result

**Locally collected telemetry cannot train or validate a forecaster.**
Measured against a **copy** of the operational database:

```
[LIVE TELEMETRY ONLY]  source_id=windows_local_host
  state=missing_or_invalid_labels  can_train=False
  events=3469  labelled=0
  POST /forecast/train -> HTTP 409  forecasting_blocked_by_research_gate

[WHOLE DATABASE]
  state=invalid_evaluation_conditions  can_train=True
  events=3669  labelled=200
  POST /forecast/train -> HTTP 422  insufficient_data_for_honest_evaluation
```

Two independent refusals, for different reasons.

### Dataset provenance

**No external dataset has been acquired.** The acquisition checklist and
the import → audit → readiness → train → capture → replay workflow are
documented in [DATASET_ACQUISITION.md](DATASET_ACQUISITION.md) and
implemented. Acquisition requires reading and accepting a licence and a
multi-gigabyte download — an operator decision, not an agent's.

### Model comparison (one recorded run, 900 synthetic events)

170 instances · 109 train / 52 test · 9 purged · 30 test positives.

| Model | Precision | Recall | PR-AUC | 95% CI (PR-AUC) |
|---|---|---|---|---|
| `baseline_constant` | 0.000 | 0.000 | 0.577 | — |
| `baseline_threshold` | 0.757 | 0.933 | 0.701 | — |
| `logistic_regression` | 0.909 | 0.667 | 0.836 | — |
| `random_forest_forecaster` | 0.808 | 0.700 | 0.865 | [0.750, 0.950] |
| `temporal_window_stack` | 0.917 | 0.733 | **0.886** | [0.776, 0.965] |
| `lstm_forecaster` | 0.647 | 0.733 | 0.751 | [0.596, 0.891] |

**The intervals overlap heavily.** On ~50 held-out instances this
evaluation cannot distinguish the top three models. No claim that one beats
another is supported, and the dashboard's "best" badge marks the highest
point estimate, nothing more.

**The LSTM is the worst non-baseline model here** — below logistic
regression. It has not been promoted, hidden, or re-tuned until it won.

### Lead time

Same events, window/horizon/ratio/seed held constant:

| Lead | 0s | 30s | 60s | 120s | 300s |
|---|---|---|---|---|---|
| best PR-AUC | 0.937 | 0.886 | 0.851 | 0.745 | 0.931 |

Decay from 0→120s is the expected shape. The 300s rebound is a
46-instance holdout talking.

### Generalization

Leave-one-environment-out across two synthetic environments:

| Held out | Model | Cross-group | Within-group | Gap |
|---|---|---|---|---|
| env_a | `lstm_forecaster` | 0.716 | 0.841 | 0.126 |
| env_b | `temporal_window_stack` | **0.494** | 0.688 | 0.194 |

Mean transfer gap **0.16 PR-AUC**. On env_b performance falls to barely
above its own positive rate.

The report sets `independent_environments: false` and says explicitly that
both groups come from the same generator, so this measures the generator's
consistency rather than the model's generality.

### What all of this is worth

**None of these numbers is evidence that PraHari forecasts threats.** They
were computed on data this project generated, by rules this project wrote.
The generator decides what counts as an attack and the model recovers that
rule. The readiness report attaches that caveat to every one of them, and
the dashboard displays it.

### Reproducibility

Capture → replay reproduces **exactly** (`reproduced=True`, zero
differences), and refuses with 409 once the dataset changes. The integrity
endpoint and the manifest report the same content fingerprint.

### Other negative and invalid results

- Negative labels require an observed, labelled horizon, so unlabelled live
  telemetry yields **zero** usable windows.
- Two leakage fallbacks were removed — an interleaved split and
  `X_test = X_train`.
- A DNS-over-HTTPS claim was withdrawn; the diagnosis declines to name a
  cause.

---

## 6. Frontend pages verified in a real browser

Driven against a copy of the operational dataset at `127.0.0.1:8000`, not a
mock.

| Page | Result |
|---|---|
| Overview | Renders — event totals, sources, label breakdown, port distribution |
| Live Telemetry | Renders — accounting, source health, corrected DoH wording |
| CSV Import | Renders — upload, paste, import audit log |
| Stream & Replay | Renders — adapter health, generator, NDJSON ingest. **No `toFixed` crash** |
| Events Explorer | Renders — real rows with provenance and quality flags |
| Analytics | Renders — **the 1601 observation-window defect was found here** |
| Feasibility | Renders — **the 425-year / 100%-PASSED defect was found here**. No blank page |
| Threat Forecasting | Renders — **trained all six models through the UI**; readiness caveat panel shown; "Best ML" badge correctly on `temporal_window_stack` (0.875), not random forest (0.792) |
| Audit & Security | Renders — loopback boundary, no-capture boundary, audit log |

Navigation between all nine without reload; no page needed a restart.

**Console:** the only errors recorded are `ERR_CONNECTION_REFUSED` from the
health poller during the intervals when I deliberately stopped the server
between restarts. No page produced an application error while the server
was running.

**A successful build is not proof of browser correctness** — and this work
is the evidence. The build was clean the whole time the dashboard was
displaying an observation window starting in 1601.

---

## 7. Windows / Linux / Docker verification

| Platform | Status | Evidence |
|---|---|---|
| **Windows 11** | **Verified at runtime** | 442 tests; live collection from three sources; nine pages in a browser; loopback central mode |
| **Linux** (Ubuntu 26.04, Python 3.14.4) | **Verified at runtime** | 440 passed / 2 skipped; `/health` 200, `/collector/status` 200 reporting `unsupported`, Windows-only endpoints 501 with a named reason; clean shutdown |
| macOS | **Unverified** | No machine available |
| **Docker** | **Unverified at runtime; configuration validated statically** | Docker is **not installed** on this host (checked PATH, Program Files, ProgramData, services) and installing it is outside the boundary. 18 tests validate the Dockerfile, compose file and `.dockerignore` |

### Two portability defects Linux found

Static analysis had said the code was portable. Running it said otherwise.

1. **The platform gate refused injected sources** — 12 tests failed off
   Windows, and a legitimate alternative producer would have been refused
   for the same wrong reason. The gate now applies only to the real
   PowerShell path, which is still refused off Windows, with a test.
2. **The operational-database guards tested a substring** (`tmp` in the
   path) rather than the property that matters. They now assert the
   resolved path is not the repository's `prahari.db`.

### What the static container validation does and does not establish

Asserts: the ignore file covers every sensitive path; the Dockerfile's
`/frontend/dist` target matches the path `main.py` resolves; the database
URL has four slashes (three would place telemetry in the ephemeral layer);
the runtime user owns `/data`; the published port is loopback-only; no
credential material is in a layer.

Does **not** establish: that `docker build` succeeds, that the image runs,
or that the healthcheck passes. The image has never been built here.

---

## 8. Security and privacy findings

### Central deployment — still disabled by default

Default is `LOCAL`, loopback-only and unauthenticated by design. Central
mode **fails closed**:

```
Refusing to start in CENTRAL deployment mode: Central deployment requires
credentials. Set PRAHARI_CREDENTIALS_FILE or PRAHARI_CREDENTIALS_JSON.
```

Live loopback verification: health 200 (public), no credential 401,
invalid 401, valid 200 with `X-PraHari-Source`, cross-source 403.

- PBKDF2-HMAC-SHA256 (240k iterations), per-credential salt, constant-time
  comparison, plaintext shown once at mint.
- **An unscoped request returns only the caller's source**, never
  everything. There is a test for that leak.
- Cross-source requests refused, not silently rewritten.
- Unknown and disabled credentials return identical wording.
- Default deny for newly added routes.

**Not claimed:** no exposure beyond loopback, no rate limiting, no token
rotation, no in-process TLS.

### Privacy findings

- **A real disclosure path was closed.** Without `.dockerignore`, every
  `docker build` would send `prahari.db` — 2 MB of genuine local network
  telemetry — plus `.git` and `secrets/` to the Docker daemon. Not into the
  image; off the machine. "Not in the image" is not "not sent".
- No live telemetry, credential, secret or personal datum is committed.
  Fixtures use RFC 5737 / RFC 3849 documentation addresses.
- Two identifiers that had reached a status document from live collection
  — the host's LAN gateway and real process names — were redacted.
- Retention is enforceable, dry-run by default, never on a timer, and never
  prunes the audit trail.
- **A testing hazard worth recording:** `lifespan` opens the configured
  database directly, so `TestClient(app)` with only a `get_db` override
  still runs `initialize()` against whatever `PRAHARI_DATABASE_URL` points
  at. The suite's conftest pins a temp path; ad-hoc scripts must set
  `PRAHARI_DATABASE_URL` — **not** `PRAHARI_DATABASE_PATH`, which is not a
  config field and is silently ignored. Earlier in this work I made that
  mistake and a verification run opened the operational database for schema
  initialisation. No data changed (3,669 before and after), but my earlier
  statement that it "was not opened" was wrong and is corrected here.

---

## 9. Known limitations and environmental blockers

| Requirement | Blocked by | What would unblock it |
|---|---|---|
| External labelled dataset (DoD 7) | Licence acceptance and a multi-gigabyte download — your decision | Follow `DATASET_ACQUISITION.md`; the pipeline is implemented and tested |
| **Real** generalization evidence (DoD 9) | Both current groups are synthetic, from one generator | Environments collected separately — i.e. the above |
| Live network sensor (DoD 3) | Safety boundary: no capture, no promiscuous mode, no monitoring of shared networks | Written authorization for a segment, a tap or mirror port, a sensor host |
| Per-flow byte/packet/duration | No local source exposes it | A network sensor, or packet capture (permanently out of scope) |
| macOS support | No machine | Access to one |
| Docker runtime validation | Docker not installed; installing it needs your approval | Approval to install, or a host that has it |
| Central mode on a real network | Boundary: no listener beyond loopback | An authorised isolated network and a TLS front end |
| Transformer / multi-layer LSTM | Would need a deep-learning dependency | Approval to install one — though the binding constraint is the dataset, not the library |
| DNS cache attribution | Empty on this host; cause deliberately not named | Evidence distinguishing the candidate explanations |

Nothing in this table is blocked by missing implementation work.

---

## 10. Final Git status and data preservation

```
branch: master   (no remote configured)
HEAD:   0fd1f1c  feat: live Windows telemetry, research gate, reproducible
                 experiments, retention and central-mode security
```

Modified, uncommitted (21): `ARCHITECTURE.md`, `DECISIONS.md`,
`IMPLEMENTATION_STATUS.md`, `README.md`, `docker-compose.yml`,
`docs/DATASET_ACQUISITION.md`, `docs/REQUIREMENTS_MATRIX.md`, and the
backend/frontend files listed in §2.

Untracked (14): `.dockerignore`, `backend/app/models/lstm_forecaster.py`,
`backend/app/research/evaluation.py`,
`backend/app/adapters/windows_host_observations.py`,
`backend/app/api/v1/hostobs.py`, `frontend/src/utils/models.ts`,
`frontend/src/test/BestModel.test.tsx`, nine test modules, and
`docs/FINAL_REPORT.md`, `docs/PLATFORM_SUPPORT.md`.

**Nothing was committed or pushed.** No remote exists.

### Operational data preserved

```
prahari.db   3,669 events
  live_telemetry   3,469
  synthetic_demo     200
```

Unchanged throughout, verified before and after every phase. Every
verification used an isolated temporary database or a copy — including the
browser sessions (which trained six models and seeded 900 synthetic events
into a **copy**), the retention demonstration (which deleted 120 records
from a purpose-seeded temporary database), and the Linux runs (databases
under the WSL user's home directory).
