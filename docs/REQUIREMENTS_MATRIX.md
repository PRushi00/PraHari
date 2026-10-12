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

**PARTIAL — Windows verified, Linux not verified.**

| | |
|---|---|
| Code | `start_prahari.ps1`, `start_prahari.bat`, `backend/app/main.py` (unified SPA + API) |
| Tests | `tests/integration/test_deployment_and_spa.py` (5) |
| Evidence | Repeatedly launched on Windows 11; all nine pages verified in-browser; `scripts/verify_live_windows_telemetry.py` passes |
| Gap | Linux has never been executed. The collector is Windows-only by construction; a Linux deployment would run with file/replay adapters only. **No Linux claim is made.** |

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
| Network-level | `adapters/json_stream.py` (Zeek conn.log / Suricata EVE) — parses both formats, tested with fixtures only |
| Gap | No real Zeek/Suricata sensor has produced data into PraHari. Deploying one needs an authorised, isolated observation environment — **BLOCKED** by §6 safety boundary (no packet capture, no promiscuous mode, no monitoring of shared networks). Documented, not claimed. |

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

**PARTIAL.**

| | |
|---|---|
| Code | `models/forecaster.py` — `BaselineConstantModel` (majority class), `BaselineThresholdModel` (interpretable rate heuristic), `LogisticRegression` (interpretable linear), `RandomForestClassifier` (nonlinear). All evaluated on one split |
| Leakage controls | Chronological split with **train-side purge** of `ceil((W+L+H)/S)` windows; no instance reassignment; evaluation refused when no honest split exists |
| Tests | `test_forecaster.py` (17) incl. purge geometry, refusal on short span, refusal on single-class training period |
| Gap | No sequence model (LSTM/Transformer). Per blueprint §18 *advanced-feature decision rule*, one is **deliberately not added**: the available data cannot demonstrate it adds value, and adding it for appearance is explicitly forbidden. Recorded as a research extension |

### 9. Metrics include precision/recall, PR-AUC, false alarms, missed events, lead time, generalization

**PARTIAL.**

| | |
|---|---|
| Present | precision, recall, F1, PR-AUC, ROC-AUC, Brier, FPR, confusion matrix, and (added this session) `detected_events`, `missed_events`, `false_alarms`, `correct_quiet_windows`, `false_alarms_per_100_windows`, `missed_event_rate` |
| Validity guards | `metrics_interpretable` + `interpretation_warnings`; undefined metrics are flagged rather than printed as numbers |
| Tests | `test_research_gate.py` — burden metrics reconcile with the confusion matrix |
| Gap | **Lead time** not computed (requires event-level timestamps the current target does not retain). **Generalization** not measured — needs a second independent dataset/scenario, which does not exist here |

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
| **MET** | 2, 4, 5, 6, 10, 11, 12, 13, 14, 15 |
| **PARTIAL** | 1 (Linux), 3 (network sensor), 7 (external dataset), 8 (sequence model), 9 (lead time, generalization) |
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
