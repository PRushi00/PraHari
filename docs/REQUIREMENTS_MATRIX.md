# PraHari — Requirement-to-Evidence Matrix

Maps each acceptance criterion in **§18 Definition of Done** of the
*Complete Cross-Platform Architecture Blueprint* to its actual code, tests
and evidence.

**Status vocabulary**

| Status | Meaning |
|---|---|
| **MET** | Implemented and backed by executed tests or recorded runs |
| **PARTIAL** | Implemented for some declared scope; remaining scope named |
| **NOT MET** | Not implemented |
| **BLOCKED** | Cannot be completed within the authorised safety boundary or available data |

No completion percentage is given: the criteria are not equally weighted and
averaging them would misrepresent the state.

Evidence commands (all executed, results in the final report):

```bash
cd backend && python -m pytest -q
```

```bash
cd frontend && npx tsc --noEmit && npx vitest run && npm run build
```

---

## §18 Definition of Done

### 1. Local deployment runs end-to-end on declared supported operating systems

**MET for Windows and Linux. macOS and Docker unverified.**

| | |
|---|---|
| Code | `start_prahari.ps1`, `start_prahari.bat`, `backend/app/main.py` (unified SPA + API) |
| Tests | `tests/integration/test_deployment_and_spa.py` (5) |
| Evidence | Repeatedly launched on Windows 11; all nine pages verified in-browser; `scripts/verify_live_windows_telemetry.py` passes |
| Linux | **Runtime verified.** Ubuntu 26.04 / Python 3.14.4 (WSL2), dependencies in a home-directory venv — no system packages, no root. `392 passed, 2 skipped`. The application starts, serves and shuts down: `/health` 200, `/events` 200, `/collector/status` 200 reporting `unsupported` with the platform name, and the Windows-only sources returning a clean `501 unsupported_platform` |
| Defects this found | (a) the collector's platform gate refused **injected** sources, so 12 tests failed off Windows and a legitimate alternative producer would have been refused for the wrong reason; (b) two operational-database guards tested for `tmp` in the path rather than the property that matters. Both fixed — see ADR-029's sibling discussion in `PLATFORM_SUPPORT.md` §1 |
| Gap | macOS unassessed (no machine). Docker **not verified** — not installed on this host, and installing it is outside the boundary. Local host collection remains Windows-only by construction and reports `unsupported` elsewhere |

### 2. Central deployment accepts authenticated telemetry from distinct, authorized source identities

**MET (implemented, verified over loopback) — but central mode remains disabled by default.**

| | |
|---|---|
| Code | `core/security.py` (credentials, roles, principals), `api/auth.py` (middleware, scoping), `main.py` fail-closed startup, `scripts/manage_credentials.py` |
| Tests | `test_central_security.py` (24) |
| Evidence | Live loopback run: health public `200`; no credential `401`; invalid credential `401`; valid credential `200`; cross-source request `403`; `X-PraHari-Source` attached. Startup without credentials **refuses**: *"Refusing to start in CENTRAL deployment mode"* |
| Design | Tokens are PBKDF2-HMAC-SHA256 hashed with per-credential salts and compared in constant time; plaintext is shown once at mint and never stored. Roles separate `ingest` / `read_only` / `admin`. An unscoped query returns **only the caller's source**, never everything. Cross-source access is **refused**, not silently rewritten. Unknown and disabled credentials return identical text so source ids cannot be enumerated. |
| Remaining | Not exercised over a real network (loopback only, by the safety boundary). No rate limiting. Default deployment is still `local`. |

### 3. ≥1 host telemetry integration and ≥1 network-level sensor/flow integration tested on declared environments

**PARTIAL — host MET, network-level NOT tested against a real sensor.**

| | |
|---|---|
| Host | `adapters/windows_telemetry.py` — **MET**. 27 unit + 21 integration tests, including 2 `live_windows` tests against the real connection table |
| Network-level | `adapters/json_stream.py` (Zeek conn.log / Suricata EVE). Contract now pinned by `tests/unit/test_network_sensor_adapters.py` (21) and `tests/integration/test_sensor_ingest_roundtrip.py` (5): both Zeek id forms, the `"-"` unset marker, zero-valued counters, second/millisecond timestamps, non-UTC offsets, IPv6, EVE `dns`/`http`/`alert` mapping, unknown fields, and batch reconciliation with per-record rejection reasons |
| Deployment guide | [docs/PLATFORM_SUPPORT.md](PLATFORM_SUPPORT.md) §3 — sensor configuration, the ingest endpoint and payload shape, and the authorisation the operator must obtain first |
| Label integrity | A Suricata signature is stored as `detector_output`, **never** `dataset_ground_truth`. The readiness report counts it but reports it under `non_ground_truth_labelled_events` with a caveat rendered on the dashboard |
| Gap | No real Zeek/Suricata sensor has produced data into PraHari. The adapter is verified against fixtures and over the HTTP boundary, not against a live sensor. Deploying one needs an authorised, isolated observation environment — **BLOCKED** by the §6 safety boundary (no packet capture, no promiscuous mode, no monitoring of shared networks). Documented, not claimed. |

### 4. Historical file replay and live ingestion use the same canonical contracts

**MET.**

| | |
|---|---|
| Code | `schemas/events.py` (`NormalizedEvent`, `SCHEMA_VERSION = 1.0.0`); CSV, NDJSON, synthetic replay, Windows collector and app-layer ingest all emit it |
| Tests | `test_comprehensive_ingestion.py`, `test_csv_import.py`, `test_stream.py`, `test_windows_collector.py`, `test_applayer_and_connections.py` |
| Evidence | Mixed-provenance analysis reconciles across sources; `data_category` distinguishes live / import / replay / synthetic / test |

### 5. Adapters expose capability and health status; failures visible, not silently ignored

**MET.**

| | |
|---|---|
| Code | `adapters/capabilities.py` (per-source `FieldAvailability`), `adapters/base.py` (`AdapterRegistry`), `GET /events/capabilities`, `GET /stream/adapters` |
| Tests | `test_provenance_and_quality.py` (20), adapter-health assertions in `test_applayer_and_connections.py` |
| Evidence | Fabricated adapter-health constants were removed; counters now come from live adapter instances. Collector failures surface via `last_error`, `consecutive_failures`, `collection_gaps` |

### 6. Target event, horizon, label rules and negative-label rules documented and tested

**MET** (this session closed the gap).

| | |
|---|---|
| Code | `models/feature_extractor.py` — `require_labelled_horizon`, `min_horizon_events`; target string in `SplitIntegrityReport.target_definition` |
| Tests | `test_forecaster.py` — 5 dedicated negative-label validity tests |
| Evidence | Blueprint §7 requires `y=0` **only** when the horizon supports it. Previously `y=0` was assigned for empty horizons (capture gaps) and for horizons containing only *unlabelled* traffic. Both now **exclude** the window and are counted in `windows_excluded_empty_horizon` / `windows_excluded_unlabelled_horizon` |

### 7. Dataset provenance, hashes, schemas, audit report, feature definitions, split manifests available

**PARTIAL.**

| | |
|---|---|
| Present | `SplitIntegrityReport` now carries `dataset_fingerprint`, `event_count`, `event_time_range`, `source_breakdown`, `label_provenance_breakdown`, `data_category_breakdown`, `random_seed`, `target_definition`, plus full windowing/purge parameters. Exposed at `GET /forecast/integrity`. Feature definitions in `FEATURE_NAMES`. Dataset audit at `POST /research/audit` |
| Tests | `test_research_gate.py` — manifest content, fingerprint stability, telemetry-free assertion |
| Workflow | [docs/DATASET_ACQUISITION.md](DATASET_ACQUISITION.md) — operator acquisition checklist (source URL/version, licence + acceptance date, SHA-256 per file, row semantics, timestamp timezone, label scope), the implemented import -> audit -> readiness -> train -> capture -> replay path, and which leakage controls are automatic versus the operator's responsibility |
| Gap | **No external dataset has been acquired**, so there are no file hashes, licence records or acquisition dates for CSE-CIC-IDS2018 / CTU-13. The manifest covers what is in the database; it does not cover an external corpus that does not exist here. Acquisition is left to the operator deliberately: it requires reading and accepting a licence and a multi-gigabyte download |

### 8. Baseline and temporal models evaluated using the same valid target and leakage-resistant protocol

**MET.** Six models including the blueprint's LSTM, all on one protocol.

| | |
|---|---|
| Code | `models/forecaster.py` — `BaselineConstantModel` (majority class), `BaselineThresholdModel` (interpretable rate heuristic), `LogisticRegression` (interpretable linear), `RandomForestClassifier` (nonlinear), and `temporal_window_stack` (**temporal**: concatenates the previous `TEMPORAL_LAGS` windows, so order matters). All five evaluated on the same target, dataset and split |
| Temporal leakage control | Lag stacking is applied **separately to the train and test matrices**, never before the split. Applied before, a test instance near the boundary would carry training-period windows in its lags, re-importing exactly the contamination the purge removes. The first `TEMPORAL_LAGS` instances of each side are dropped |
| Leakage controls | Chronological split with **train-side purge** of `ceil((W+L+H)/S)` windows; no instance reassignment; evaluation refused when no honest split exists |
| Tests | `test_forecaster.py` (17) incl. purge geometry, refusal on short span, refusal on single-class training period |
| Tests (temporal) | `test_lead_time_and_uncertainty.py` — sequence ordering is not order-invariant, holdout length accounts for the dropped lag prefix, per-model truth stored separately |
| **LSTM** | **Implemented** — `models/lstm_forecaster.py`, single-layer LSTM + sigmoid read-out, BPTT with Adam, in NumPy (no new dependency). Correctness **demonstrated**: worst relative gradient error vs central finite differences **1.3e-07**, and 100% holdout accuracy on a task solvable only with memory, where a memoryless model is verified to score below 0.70 |
| Tests | `test_lstm_forecaster.py` (17), `test_lead_time_and_uncertainty.py` (23) |
| **Result (negative, reported)** | On 900 synthetic events the LSTM scores PR-AUC **0.751** — the **worst** of the four non-baseline models, below logistic regression. Not promoted, not hidden, not re-tuned until it wins |
| Gap | One layer, fixed epoch budget, no dropout or early stopping; no Transformer. And the headline caveat is unchanged: trained on generated data, the score measures recovery of the generator's rule |

### 9. Metrics include precision/recall, PR-AUC, false alarms, missed events, lead time, generalization

**MET as capability.** Every metric is implemented and measured; the
*evidence* remains synthetic until a real corpus exists.

| | |
|---|---|
| Present | precision, recall, F1, PR-AUC, ROC-AUC, Brier, FPR, confusion matrix, and (added this session) `detected_events`, `missed_events`, `false_alarms`, `correct_quiet_windows`, `false_alarms_per_100_windows`, `missed_event_rate` |
| Validity guards | `metrics_interpretable` + `interpretation_warnings`; undefined metrics are flagged rather than printed as numbers |
| Tests | `test_research_gate.py` — burden metrics reconcile with the confusion matrix |
| **Lead time** | **Implemented.** `research/evaluation.py` re-runs the full protocol once per lead time with everything else held constant; `POST /forecast/lead-time-curve`. A lead with no honest split is reported as a **refusal with its reason**, not omitted. Measured decay on synthetic data: PR-AUC 0.937 (0s) -> 0.886 (30s) -> 0.851 (60s) -> 0.745 (120s) |
| **Uncertainty** | **Implemented.** Percentile bootstrap over held-out instances; `GET /forecast/uncertainty`. Refused, with a reason, below 20 instances or 5 positives, or on a single class. Held-out truth is stored per model because the temporal model's holdout is shorter |
| Tests | `test_lead_time_and_uncertainty.py` (23) |
| **Generalization** | **Implemented.** `POST /forecast/generalization` — leave-one-group-out transfer with the within-group score beside it, so `transfer_gap = within − cross` is readable. Groups that cannot support a score are reported with their reason. Measured: mean transfer gap **0.16 PR-AUC**; on one held-out environment cross-group PR-AUC falls to **0.494** against a within-group 0.688 |
| Tests (generalization) | `test_generalization.py` (13) |
| Gap | Both groups are `synthetic_demo` from one generator, and the report says so (`independent_environments: false`). A defensible generalization claim needs environments **collected separately** — the external dataset that has not been acquired. Everything above is evidence that the measurements work, not that the forecasting does |

### 10. Dashboard uses actual backend results; distinguishes observed events, forecasts, confirmed facts

**MET.**

| | |
|---|---|
| Code | `frontend/src/pages/*`, `components/ConnectionTable.tsx`, `components/AppLayerPanel.tsx` |
| Tests | 36 frontend tests; `test_frontend_api_contract.py` (32) pins every interface, enum and field against the live OpenAPI schema |
| Evidence | Three render-crash outages (Feasibility, Stream & Replay, and latent ones in Forecast/Audit/Stream) traced to contract drift and fixed. Predictions carry `is_validated_model` / `validation_status` / `is_actionable_forecast`; unvalidated output is labelled UNVALIDATED. HTTP status shown only when an app-layer source reported it |

### 11. Central authentication, authorization, source isolation, payload limits, audit logging, retention tested

**MET.**

| | |
|---|---|
| Authentication / authorization / isolation | `core/security.py`, `api/auth.py` — see item 2. 24 tests |
| Payload limits | Pagination bounds, 5000-record batch cap, confirmation token for destructive operations |
| Audit logging | `audit_events` table; retention runs, blocked forecasts, refused replays and credential use are all recorded |
| **Retention enforcement** | `services/retention.py` + `api/v1/retention.py` — **now enforced**, not merely reported |
| Tests | `test_security_boundaries.py` (15), `test_retention.py` (20), `test_central_security.py` (24) |
| Retention design | Dry-run by default; `confirm="DELETE-EXPIRED-TELEMETRY"` required to delete; **never automatic** (no scheduler, no startup hook — tested); age from `observed_at` in UTC; batched in independent transactions so an interruption leaves whole batches committed; sources, import summaries, analyses and audit records are never pruned; source counters refreshed afterwards |

### 12. Data replay, adapter contract, unit, integration, security, end-to-end tests pass

**MET.**

| Category | File(s) | Count |
|---|---|---|
| Replay | `test_stream.py` | 4 |
| Adapter contract | `test_windows_telemetry.py`, `test_comprehensive_ingestion.py`, `test_csv_import.py` | 38 |
| Unit | `test_provenance_and_quality.py`, `test_enrichment.py`, `test_analysis.py`, `test_forecaster.py`, `test_research.py`, `test_database.py` | 69 |
| Integration | `test_windows_collector.py`, `test_applayer_and_connections.py`, `test_research_gate.py`, `test_advanced_api.py`, `test_api.py` | 70 |
| **Security** | `test_security_boundaries.py` | **15** (added this session) |
| Contract | `test_frontend_api_contract.py`, `test_browser_producer_contract.py` | 44 |
| End-to-end | `test_end_to_end_workflow.py`, `test_deployment_and_spa.py` | 6 |
| | **Total backend** | **248 passed** |

### 13. Reproducibility manifests and troubleshooting documentation match the implementation

**MET.**

| | |
|---|---|
| Code | `research/experiment.py` (versioned manifest + replay runner), `api/v1/experiments.py` |
| Tests | `test_experiment_replay.py` (25) |
| Evidence | Capture → save → load → replay reproduces **exactly**: `reproduced=True`, zero differences, including every model's confusion matrix |
| Fails closed on | changed dataset fingerprint · missing dataset · schema-version change · feature-set change · a configuration that no longer yields a valid evaluation. All mismatches are reported together |
| Safety | Replay is read-only against telemetry (asserted by test); manifests contain **no telemetry** — no IP literals, no record fields (asserted by test); experiment ids are path-traversal checked |
| Honesty | `DETERMINISTIC_OUTPUTS` vs `NON_DETERMINISTIC_OUTPUTS` are declared, so timings and timestamps are not claimed to be reproducible |
| **Defect this found** | The manifest initially stored a *derived* train ratio (`train_instances/total`), which differs from the configured value because purging removes windows between the splits. Replaying with it produced a different split. `SplitIntegrityReport.configured_train_ratio` now records the parameter actually passed |

### 14. No automatic network changes or disruptive response occur

**MET.**

| | |
|---|---|
| Tests | `test_security_boundaries.py::test_no_blocking_or_response_endpoints_exist` scans every OpenAPI route for block/quarantine/isolate/remediate/firewall verbs |
| Evidence | Across five working sessions: no firewall, routing, DNS, proxy, certificate, driver, interface, VM, router or cloud change. Collector is unprivileged `Get-NetTCPConnection`; DNS diagnosis is read-only |

### 15. Known limitations, negative results, unsupported platforms, failed experiments documented

**MET.**

| | |
|---|---|
| Docs | `IMPLEMENTATION_STATUS.md` (sessions 1–5 defect tables, withdrawn metrics, negative results), `DECISIONS.md` (ADR-001…ADR-020), `README.md`, `docs/APPLICATION_LAYER_VISIBILITY.md`, this matrix |
| Notable negative results preserved | Earlier fixture metrics **withdrawn** as contaminated; live telemetry **cannot** support supervised forecasting (no labels); domain attribution yields **nothing** on this host and the cause is **not established**; real-browser HTTP **unverified** |

---

## Summary by status

| Status | Items |
|---|---|
| **MET** | 1, 2, 4, 5, 6, 8, 9, 10, 11, 12, 13, 14, 15 |
| **PARTIAL** | 3 (no live network sensor), 7 (no external dataset acquired) |
| **NOT MET** | — |
| **BLOCKED by safety boundary** | Real network-sensor integration (item 3) — requires an authorised isolated observation environment |
| **BLOCKED by data availability** | Generalization and lead-time evidence (item 9), external dataset provenance (item 7) — require a labelled incident corpus that is not present |

## Evidence the project cannot currently produce

These are stated plainly because the blueprint forbids claiming them:

1. **No demonstrated forecasting effectiveness on real traffic.** Every metric produced to date comes from **synthetic** data with deterministic attack bursts. It demonstrates the pipeline functions; it is not evidence of predictive skill.
2. **Locally collected telemetry carries no incident labels** and therefore cannot train or validate a forecaster. The gate refuses it, correctly.
3. **No generalization result** exists — a second independent dataset or scenario is required.
4. **No lead-time measurement** — the current target records horizon membership, not event offset.

---

## Session 6 changes to this matrix

| Item | Before | After | Why |
|---|---|---|---|
| 2 — Central deployment | NOT MET | **MET** (loopback-verified, disabled by default) | Authentication, per-source identity, roles and source isolation implemented and tested; startup fails closed without credentials |
| 11 — Retention | PARTIAL | **MET** | `retention_days` is now enforced by a manual, dry-run-by-default, batched pruning service — previously it was reported but never applied |
| 13 — Reproducibility | PARTIAL | **MET** | Versioned manifest plus a replay runner that reproduces exactly and fails closed on any input change |
| 7 — Dataset provenance | PARTIAL | PARTIAL (workflow documented) | Import/audit workflow and acquisition checklist written up in `docs/DATASET_ACQUISITION.md`; **acquisition itself remains outstanding** and is a user decision |

Still open, unchanged: Linux execution, a real network sensor, an external
labelled dataset, a sequence model (deliberately withheld), and lead-time /
generalization evidence.

---

## Session 7 changes to this matrix

| Item | Change |
|---|---|
| 1 — Platform | Linux **assessed statically** (48 modules parse under Python 3.14 on Ubuntu 26.04, no Windows-only imports, collector gates cleanly). Still **not executed**; status unchanged at PARTIAL |
| 3 — Network sensor | Adapter contract pinned by 26 new tests covering the shapes Zeek and Suricata actually emit, plus the ingest round trip. Deployment documented. Still PARTIAL: no live sensor has run |

### Defects found and fixed while writing those tests

| Defect | Effect | Fix |
|---|---|---|
| `SYNTHETIC_RULE = "rule_based"` | A duplicate enum **value** made it a silent alias, so synthetic labels were indistinguishable from locally derived ones in every provenance breakdown — including the experiment manifest, whose purpose is to record what a result was computed on | Distinct value `synthetic_rule`; a test now asserts no provenance value is aliased |
| Suricata `alert.signature` stored as `dataset_ground_truth` | A detector's opinion presented as confirmed fact. A forecaster trained on it would learn to predict one detector's alerts while every metric claimed it predicted attacks | New `detector_output` provenance, an explicit warning, and a readiness caveat surfaced on the dashboard |
| Any labelled record rewritten to `EventType.ALERT` | An imported labelled corpus would report as nothing but alerts, misstating what the sensor observed | Event type now reflects the observation; the label is separate |
| `or`-chain field lookups | `0` bytes, `0.0` seconds and port `0` fell through and became `None` — a recorded zero turned into "no measurement" | Presence-based lookup; Zeek's `"-"` unset marker stays absent rather than becoming `0` |

Each was mutation-checked: the behaviour was reintroduced and the
corresponding test observed to fail.

### Addendum — fingerprint semantics corrected

`SplitIntegrityReport` and `ExperimentManifest` both exposed
`dataset_fingerprint` computed by different algorithms, so the two could
never agree. The split report now carries the **content** fingerprint
(identical function to the manifest) plus a separately named
`split_configuration_fingerprint` for the protocol hash. Verified live: the
integrity endpoint and the captured manifest report the same value
(`5decfa963e242d13…`). See ADR-026.

---

## Session 8 changes to this matrix

| Item | Before | After | Why |
|---|---|---|---|
| 1 — Platform | PARTIAL (Linux parsed only) | **MET for Windows and Linux** | 392 passed / 2 skipped on Ubuntu 26.04 + Python 3.14.4; application startup, serving and clean shutdown verified. macOS and Docker remain unverified |
| 8 — Temporal model | PARTIAL (none) | PARTIAL (`temporal_window_stack`) | A genuine sequence model now runs under the same target, dataset and split, with lag stacking applied after the split so it cannot reach across the boundary. Still no recurrent model, and it is not described as one |
| 9 — Lead time / uncertainty | PARTIAL (neither) | PARTIAL (both implemented) | Lead-time sweep and bootstrap intervals, each refusing with a reason where the data cannot support them. Generalization still blocked |
| 3 — Telemetry breadth | PARTIAL | PARTIAL (two sources added) | UDP endpoint table and interface counters, both unprivileged and read-only, both verified live |
| 10 — Dashboard | MET | MET (re-verified in a browser) | All nine pages driven against real data; zero console errors |

### Telemetry coverage added

| Source | Status |
|---|---|
| `windows_udp_endpoint` | **Live-verified.** 41 endpoints observed, 0 rejected; second poll suppressed 40 repeats and persisted 1 new socket. `dst_ip`/`dst_port` declared **not applicable** — UDP has no peer here |
| `windows_interface_counters` | **Live-verified.** Real cumulative bytes/packets per interface, with inter-reading deltas and reset detection. Served from its own endpoint; **never** written into `normalized_events` |

### Measurement integrity defects found and fixed

Found by driving the dashboard in a browser against the real dataset, not
by a test.

| Defect | Effect | Fix |
|---|---|---|
| FILETIME-epoch timestamps included in the analysis range and the feasibility span | Analytics showed an observation window starting **1/1/1601**; Feasibility scored temporal integrity **100% PASSED** over **425 years**, while the readiness gate reported 18 hours for the same data | One `is_plausible_timestamp()` in `schemas/events.py`, imported by all three. 65 such records exist in the operational database; they are now excluded, counted and surfaced, and the temporal check **fails** |
| Averages published without a denominator | `avg_bytes` over 200 of 3,669 records read as a property of the dataset in any API response | `duration_measured_count`, `packets_measured_count`, `bytes_measured_count` |
| `attack_ratio` divided labelled counts by all events | "1.4% attack" for a dataset whose labelled part is 25% attacks | Computed over labelled events; `labelled_events` and `unlabelled_events` reported |
| Feasibility temporal score showed 100% beside a failed check | Reads as a display bug and invites dismissing the failure | Score folds in the usable fraction of the time axis |

Each was mutation-checked: the behaviour was reintroduced and the
corresponding test observed to fail.

---

## Session 9 changes to this matrix

| Item | Before | After | Why |
|---|---|---|---|
| 8 — Models | PARTIAL (no recurrent model) | **MET** | The blueprint's LSTM is implemented in NumPy, gradient-checked to 1.3e-07 and verified to carry memory, and evaluated on the same protocol as the other five |
| 9 — Metrics | PARTIAL (no generalization) | **MET as capability** | Leave-one-group-out transfer with the within-group score beside it. Evidence remains synthetic |
| 1 — Platform / Docker | Docker unverified, unvalidated | Docker still unverified, **configuration validated statically** | 18 tests over the Dockerfile, compose file and a new `.dockerignore` |

### Status summary

| Status | Items |
|---|---|
| **MET** | 1, 2, 4, 5, 6, 8, 9, 10, 11, 12, 13, 14, 15 |
| **PARTIAL** | 3 (no live network sensor), 7 (no external dataset acquired) |
| **NOT MET** | — |

The two remaining PARTIALs are both blocked on things outside the agreed
boundary rather than on implementation: a dataset the operator must choose
to download under its licence, and an authorised network segment with a
tap. Every pipeline that would consume either is implemented and tested.

### Defects found and fixed this session

| Defect | Effect | Fix |
|---|---|---|
| No `.dockerignore` | Every `docker build` would send `prahari.db` — 2 MB of genuine local telemetry — plus `.git` and `secrets/` to the Docker daemon. Not in the image, but off the machine | `.dockerignore` + 18 static validation tests |
| Dashboard hardcoded `random_forest_forecaster` as "best" | With six models the badge frequently marked a model the evaluation had not chosen. An operator reads it as a result | `bestModelId()` derives it from measured PR-AUC, excluding baselines; 6 frontend tests |
| Obsolete Compose `version` key | Warning on every `docker compose` invocation | Removed |

### Measured results (one recorded run, 900 synthetic events)

| Model | Precision | Recall | PR-AUC | 95% CI (PR-AUC) |
|---|---|---|---|---|
| `baseline_constant` | 0.000 | 0.000 | 0.577 | — |
| `baseline_threshold` | 0.757 | 0.933 | 0.701 | — |
| `logistic_regression` | 0.909 | 0.667 | 0.836 | — |
| `random_forest_forecaster` | 0.808 | 0.700 | 0.865 | [0.750, 0.950] |
| `temporal_window_stack` | 0.917 | 0.733 | **0.886** | [0.776, 0.965] |
| `lstm_forecaster` | 0.647 | 0.733 | 0.751 | [0.596, 0.891] |

Split: 170 instances, 109 train / 52 test, 9 purged, 30 test positives.

**The intervals overlap heavily.** On 49–52 held-out instances this
evaluation cannot distinguish the top three models, and no claim that one
is better is supported. That is what the intervals are for.

---

# Full-Blueprint Compliance Audit (Session 19)

Audited against the 18-page PDF, section by section, with every status
checked against code or test output rather than against an earlier report.
Evidence: **889 backend passed / 4 skipped**, 46 frontend, on Windows.

## §4 Deployment models

| Requirement | Status | Evidence |
|---|---|---|
| Local mode: backend, adapters, pipeline, storage on one host | **Implemented** | `main.py` LOCAL mode; loopback default |
| Loopback default bind | **Implemented** | `config.host`; `/audit/config.loopback_enforced` |
| Central mode: authenticated remote ingestion | **Implemented** | `CentralAuthMiddleware`; ADR-051 |
| Central validates identity, schema, timestamps, **payload size, rate** | **Implemented (this session)** | ADR-052; `test_request_limits.py` (18 tests) |
| Central preserves source identity + ingestion provenance | **Implemented** | ADR-048 `received_at`; ADR-051 |
| Access scoped to permitted sources | **Implemented** | `scope_source`, `resolve_ingest_source` |
| Agent buffering during disconnection | **Not implemented** | No forwarding agent exists |
| Expose health, lag, **queue depth**, rejected records, last ingestion | **Partial** | health / lag / last-ingestion yes; **queue depth has no referent — ingestion is synchronous, there is no queue** |
| Enrollment authenticated, audited, revocable | **Partial** | Offline CLI by decision (ADR-051); `enabled:false` works; no expiry or rotation |
| §4.4 Windows **and Linux** host support | **Implemented; not yet run on Linux** | ADR-053; 27 passed / 4 skipped, the 4 needing a live Linux or POSIX symlinks |

## §5 Adapter categories

| Category | Status | Evidence |
|---|---|---|
| Host telemetry, Windows | **Implemented, live-verified** | `windows_telemetry.py`; 2 live-OS tests |
| Host telemetry, Linux | **Implemented, fixture-verified only** | `linux_telemetry.py`; ADR-053 |
| Network sensor (Zeek / Suricata) | **Fixtures only; BLOCKED live** | `json_stream.py`; no authorised observation point |
| File / replay (CSV, JSON, NDJSON) | **Implemented** | `csv_import.py`, `research_csv.py`, `json_stream.py` |
| Network flows (NetFlow / IPFIX) | **Not implemented** | No exporter adapter exists |
| Security platforms (IDS / EDR / SIEM) | **Not implemented** | Provider-specific; none authorised |
| Synthetic fixtures | **Implemented** | `synthetic_replay.py` |
| PCAP | **Not implemented** | Needs Scapy or PyShark; installing is not authorised |
| §5.1 lifecycle: health, bounded retries, dedup, versioning | **Implemented** | `base.py`, ADR-050, `capabilities.py` |
| §5.2 canonical envelope, all ten field groups | **Implemented** | `schemas/events.py`, SCHEMA_VERSION 1.0.0 |

## §6 Ingestion and data quality

| Requirement | Status |
|---|---|
| Validate schema, size, timestamps, ranges, identity at the boundary | **Implemented** — size added this session |
| Explicit duplicate / late / skew / incomplete-window policy | **Implemented** — ADR-045, 046, 048, 050 |
| Source identity attached throughout | **Implemented** — ADR-051 |
| **Bounded queues and backpressure** | **Not implemented** — ingestion is synchronous |
| Separate parser / auth / schema / transient / model failures | **Implemented** — distinct error classes |
| Sensitive payloads kept out of logs | **Implemented** — `redact()`, `comm`-only attribution |
| Freshness measured; a stale source is not called healthy | **Implemented** — ADR-047, ADR-049 |

## §7 to §10 Forecasting, data, models, evaluation

| Requirement | Status |
|---|---|
| Formal target, horizon, negative-label validity | **Implemented** — ADR-039, window extractor |
| Leakage controls: chronological split, train-side purge, training-only fitting | **Implemented** — ADR-041, ADR-042 |
| Logistic Regression, tree baseline, temporal model | **Implemented** — six models including a gradient-checked NumPy LSTM |
| PyTorch specifically | **Documented deviation** — pure NumPy instead; installing PyTorch is not authorised |
| Precision, recall, PR-AUC, false alarms, missed events, lead time, calibration | **Implemented** — `research/evaluation.py` |
| Metrics **on real benchmark data** | **BLOCKED** — CSE-CIC-IDS2018 cannot be downloaded under the standing constraints. Every number to date comes from synthetic fixtures and is labelled as such |
| Cross-dataset generalization results | **BLOCKED** — same reason |

## §11 Dashboard and API

| Blueprint route family | Status |
|---|---|
| `GET /api/health` | **Implemented** |
| `/api/sources` | **Implemented**, plus `/health` and `/clock-integrity` |
| `/api/events` | **Implemented**, paginated and source-scoped |
| `/api/forecasts` | **Implemented** as `/forecast/*` |
| `/api/models` | **Implemented** as `/forecast/models` |
| `/api/evaluations` | **Implemented** as `/experiments/*` |
| `/api/config` | **Implemented** as `/audit/config` |
| `/api/audit` | **Implemented**, admin-only since ADR-051 |
| Authenticated ingestion endpoint | **Implemented** |

Three families are served under different names. Duplicating them purely to
match the blueprint's spelling would add surface without capability, so the
mapping is recorded here instead.

| Blueprint view | Status |
|---|---|
| Overview | **Implemented** — `OverviewPage` |
| Sources | **Implemented** — `LiveTelemetryPage` |
| Forecast timeline | **Implemented** — `ForecastPage` |
| Investigation | **Implemented** — `EventsPage` with `AnalysisPage` |
| Evaluation | **Implemented** — `ResearchPage` |
| **System health** | **Not implemented** — the data is reachable by API but no single view presents it |
| Administration | **Partial** — `AuditPage` covers audit and config; no source-configuration or retention UI |

## §12 Security

| Control | Status |
|---|---|
| Authenticated sensor identity, revocation, audit, **rate limiting** | **Implemented** — ADR-051, ADR-052 |
| Least privilege, scoped source identity | **Implemented** |
| Credential **rotation and expiry** | **Not implemented** |
| Bounded parsers, **payload-size limits**, safe paths | **Implemented** — ADR-052 |
| Cross-source isolation, tested | **Implemented** — `test_source_identity_boundary.py` |
| Retention and deletion | **Implemented** — `retention.py` |
| Secrets outside source control, redacted logs | **Implemented** |
| No automatic blocking or network change | **Implemented** — no such code path exists |

## §16 to §18 Testing and definition of done

| DoD item | Status |
|---|---|
| Local deployment runs end-to-end on declared operating systems | **Windows verified; Linux implemented, not run this session** |
| Central deployment accepts authenticated telemetry from distinct identities | **Implemented and tested** |
| One host and one network integration tested on declared environments | **Host (Windows) yes; network sensor BLOCKED, fixtures only** |
| Replay and live share canonical contracts | **Implemented** |
| Adapters expose capability and health; failures visible | **Implemented** |
| Target, horizon, label and negative-label rules documented and tested | **Implemented** |
| Dataset provenance, hashes, audit report, split manifests | **Mechanism implemented; BLOCKED for a real corpus** |
| Baselines and temporal model on one protocol | **Implemented** |
| Metrics including lead time and generalization | **On fixtures only; BLOCKED on real data** |
| Dashboard uses real backend results | **Implemented** |
| Central authn / authz, isolation, **payload limits**, audit, retention tested | **Implemented** |
| Replay, adapter, unit, integration, security and e2e tests pass | **Implemented** — 889 passed, 4 skipped |
| Reproducibility manifests match the implementation | **Implemented** |
| No automatic network changes | **Implemented** |
| Known limitations and negative results documented | **Implemented** |

## Summary

**Blocked by the standing safety boundary, not by engineering**: real
benchmark metrics, cross-dataset generalization, live network-sensor
integration, PCAP parsing, PyTorch, PostgreSQL and Parquet backends.

**Not implemented and feasible later**: bounded queue and backpressure with
real queue-depth reporting, a sensor forwarding agent, NetFlow/IPFIX and
security-platform adapters, credential expiry and rotation, a System Health
dashboard view, and source/retention administration UI.

**The honest headline**: the engineering contract is largely met; the
*scientific* contract is not, and cannot be until a labelled corpus is
acquired. No metric in this repository is evidence of predictive
performance on real traffic.

---

## Session 20 delta — statuses that changed

Using the required vocabulary: PASS / PARTIAL / BLOCKED / FAIL.

| PDF requirement | Was | Now | Evidence |
|---|---|---|---|
| §12 credential rotation and expiry | FAIL (not implemented) | **PASS** | ADR-055; `test_credential_lifecycle.py`, 24 passed |
| §4.2 enrollment "authenticated, audited, **revocable**" | PARTIAL | **PASS** for revocation; PARTIAL overall — issuance is still offline CLI by decision | ADR-055; revocation takes effect without a restart |
| §12 payload limits | PASS (Session 19) | **PASS** | `test_request_limits.py`, 19 passed |
| §13 "validate all configuration"; config fails closed | PARTIAL | **PASS** for the three limits audited | `max_import_records` wired this session |
| §16 "tests use isolated fixtures" | PARTIAL (convention only) | **PASS** | `app/storage/guard.py`; `test_protected_database_guard.py`, 13 passed |
| §4.4 Linux host telemetry | PARTIAL | **PARTIAL** — unchanged; still not executed on a live Linux host | 4 tests skip on Windows and report as skipped |

Unchanged and still **BLOCKED**: real-data metrics, cross-dataset
generalization, live network-sensor integration, PCAP, PyTorch,
PostgreSQL/Parquet. Unchanged and still **FAIL**: bounded queue and
backpressure, sensor forwarding agent, NetFlow/IPFIX and security-platform
adapters, System Health dashboard view, source/retention admin UI.

---

## Session 21 delta — statuses that changed

| PDF requirement | Was | Now | Evidence |
|---|---|---|---|
| §6 bounded resources, visible backpressure | FAIL | **PASS** | ADR-056; `test_system_health.py` 24 passed; 503 on saturation, nothing stored |
| §4.2 expose queue depth, rejected records, last ingestion | FAIL | **PASS** | `GET /system/health`; queue_depth null **by design** with a stated reason |
| §11 System Health dashboard view | FAIL | **PASS** | `SystemHealthPage.tsx`; 8 frontend tests incl. unmeasured-is-not-zero |
| §5 Network flows (NetFlow/IPFIX) adapter | FAIL | **PARTIAL** | ADR-057; 30 tests. Parses authorized **exports**; does NOT open a collector port — that needs network authorization |
| §11 Administration view | PARTIAL | **PARTIAL** | unchanged: audit + config only, no source/retention UI |
| §5 Sensor forwarding agent | FAIL | **FAIL** | unchanged — not attempted this session |

Still **BLOCKED** (authorization or environment, not code): real-data
metrics, cross-dataset generalization, live network-sensor integration,
PCAP, PyTorch, PostgreSQL/Parquet, Linux execution.

---

## Session 22 delta — statuses that changed

| PDF requirement | Location | Was | Now | Evidence |
|---|---|---|---|---|
| §4.2 / §13 sensor forwarding agent | `app/agents/sensor_agent.py` | FAIL | **PASS** | ADR-058; 52 tests, 5 end-to-end against an in-process PraHari |
| §4.2 agent bounded buffering + safe retry | same | FAIL | **PASS** | bounded deque, jittered backoff, `Retry-After` honoured |
| §11 Administration view | `AdministrationPage.tsx` | PARTIAL | **PASS** | 13 frontend tests; wired to real endpoints |
| §11 authorized source enable/disable | `PATCH /sources/{id}/enabled` | FAIL | **PASS** | ADR-059; admin-gated, audited, 404 on unknown |
| §11 retention settings administration | `PUT /retention/policy` | FAIL | **PASS** | ADR-059; override with reported origin; change deletes nothing |
| §12 auditable configuration changes | `audit_events` | PARTIAL | **PASS** | both new mutations audited |

Credential rotation/revocation in the UI remains **deliberately absent**
(ADR-051/055): a remote route would require the server to write the
credential store. Operator CLI only.

Still **BLOCKED** (authorization or environment, not code): real-data
metrics, cross-dataset generalization, live network-sensor integration,
binary NetFlow collection, PCAP, PyTorch, PostgreSQL/Parquet, Linux
execution.
