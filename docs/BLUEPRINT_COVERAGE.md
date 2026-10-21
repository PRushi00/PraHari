# PraHari — Coverage of the Whole Blueprint

`ACCEPTANCE_MATRIX.md` tracks **§18 Definition of done** — fifteen criteria.
This document audits the **other eighteen sections**, which carry roughly
230 further discrete requirements that §18 never mentions.

**Assessed 21 Oct 2026** against commit on `ccr-58caddbd-1gv7jn`, by
reading each section's requirement lists and checking them in the code.

| Status | Meaning |
|---|---|
| `MET` | Implemented and exercised |
| `PARTIAL` | Implemented for part of the scope; the remainder is named |
| `DEVIATES` | Implemented differently from the blueprint, deliberately, with the reason recorded |
| `ABSENT` | Not implemented |

> **On the percentage.** A count is given below because it was asked for,
> but it weights a dashboard panel the same as "can it forecast". The
> blueprint's own §18 declines to give one, for that reason. Read the
> section table, not the number.

---

## Summary

| § | Section | Requirements | Verdict |
|---|---|---|---|
| 1 | Executive summary / what the blueprint changes | 6 | `MET` |
| 2 | Goals and non-goals | 15 | `MET` |
| 3 | Architecture and invariants | 6 | `MET` |
| 4 | Local and central deployment | 20 | `MET` (central loopback-only) |
| 5 | Pluggable adapter architecture | 27 | `PARTIAL` — no security-platform adapter |
| 6 | Ingestion and data quality | 7 | `MET` |
| 7 | Forecasting task and label semantics | 7 | `MET` |
| 8 | Dataset strategy and leakage controls | 13 | `MET` |
| 9 | Models, technology stack, lifecycle | 27 | `PARTIAL` / 3 `DEVIATES` |
| 10 | Evaluation methodology | 16 | `PARTIAL` — 2 metrics, 2 rules short |
| 11 | Dashboard and API contracts | 31 | `PARTIAL` — 1 view absent, 1 partial |
| 12 | Security, privacy, threat model | 16 | `MET` |
| 13 | Repository structure and configuration | 7 | `DEVIATES` (layout, keys) |
| 14 | Installation and operating guide | 2 | `MET` |
| 15 | Troubleshooting and failure handling | 15 | `ABSENT` as a guide |
| 16 | Reproducibility, testing, release readiness | 17 | `PARTIAL` — no ingestion benchmark |
| 17 | Research positioning and claims | 6 | `MET` |
| 18 | Definition of done | 15 | 13 `MET`, 2 `PARTIAL` |
| 19 | References and decision register | 2 | `MET` |

**≈ 222 of ≈ 249 discrete requirements — about 89 %.**

The missing ~11 % is not evenly trivial. It contains one thing the
project exists for (live network-level collection) and one guide a user
would actually reach for (§15).

---

## Where it is genuinely complete

**§2, §3, §6, §7, §8, §12, §17** — every requirement met.

§3's six architectural invariants were each checked in the code, not
assumed: no adapter imports a model (the only matches are the words
"model" and "provenance model" inside comments); nothing under
`app/models/` spawns a subprocess or starts a collector; no dashboard
page reaches past `services/api.ts`; forecasts carry model version,
target, horizon, window and timestamp; ingestion errors surface as errors;
replay and live share one canonical contract.

§8 moved from "tooling complete, nothing audited" to fully met when a
real corpus was acquired, hashed, audited and imported (ADR-095/096),
and the audit surfaced four source defects the pipeline would otherwise
have absorbed silently.

§12's nine threats each have a control and a test — central HTTPS,
credential lifecycle, cross-source isolation, payload limits, reserved
source ids, protected-database guard, request limits.

---

## Where it deviates, deliberately

### §9 — three technology deviations

| Blueprint | Built | Why |
|---|---|---|
| **PyTorch LSTM** | **NumPy LSTM** | A single-layer LSTM with BPTT and Adam, written out in NumPy. Removes a ~2 GB dependency from a project whose §9.2 rule is "prefer small, maintainable dependencies until measured needs justify more". Same architecture, same target, same split; gradient-checked. |
| **Parquet** (analytical intermediates) | **ABSENT** | §9's own decision rule says "use for larger tables where suitable". No table has been large enough to justify a second storage format. |
| **Scapy / PyShark** (optional) | **ABSENT** | Marked optional in the blueprint, with the rule "do not make raw packet parsing a requirement for all adapters". No PCAP path exists, so nothing needs it. |

Everything else in §9's table is adopted as specified: Python, pandas/NumPy,
scikit-learn logistic regression, random forest, React + TypeScript,
**Apache ECharts** (used on the Overview page), FastAPI, SQLite **and**
PostgreSQL, Zeek-shaped sensor parsing, feature attribution, and
Transformers/GNNs correctly deferred under the §18 advanced-feature rule.

### §13 — layout and configuration keys

The blueprint proposes a monorepo of `apps/`, `core/`, `adapters/`,
`agents/`, `storage/`, `configs/`. The repository is `backend/app/{adapters,
api,core,models,research,schemas,services,storage,agents}` plus
`frontend/`. The same separations exist under different names, and the
adapter/core/storage boundary the blueprint cares about is enforced by a
test (`KNOWN_ABSTRACTION_LEAKS` is empty).

Configuration keys differ from the blueprint's YAML sketch — which says
of itself, *"a conceptual example only; exact keys will be finalized with
the implementation."* Storage backend is chosen by the `database_url`
scheme rather than a `metadata_backend` key, which is strictly better: one
setting cannot contradict another.

**All five §13 configuration rules are met**, including the one that
matters most — fail closed. A non-SQLite URL used to silently read the
local SQLite file; it now refuses (ADR-094), and PostgreSQL is properly
selectable (ADR-097).

---

## Where it is short

### §5 — no security-platform adapter · `PARTIAL`

Five of six adapter categories exist: host telemetry, network flows
(parsing), network sensor (Zeek-shaped), file/replay, synthetic. The
sixth — **IDS/IPS, firewall, EDR, SIEM exports or APIs** — has no adapter.

The §5.1 lifecycle contract, the §5.2 canonical envelope (all nine fields)
and the §5.3 compatibility rules are fully met for the five that exist.

### §10 — two metrics and two rules short · `PARTIAL`

| Requirement | State |
|---|---|
| Precision/recall, PR-AUC, FPR, missed-event, **event-level lead time**, data freshness, uncertainty | `MET` |
| **Calibration** | `PARTIAL` — Brier score is computed; no reliability curve or calibration-vs-frequency plot |
| **Scenario-level performance** | `PARTIAL` — leave-one-group-out generalization exists; no scenario identifiers in the schema, so it groups by source/category |
| **Inference latency / throughput** | `ABSENT` — never measured |
| Rule: *select thresholds on validation data* | `DEVIATES` — the threshold is fixed at 0.5 and never tuned, so no test data can influence it. Documented as a limitation in the target spec: the operating point may not suit a deployment |
| Rule: *evaluate cross-dataset generalization* | `ABSENT` — one corpus only |

### §11 — one view absent, one partial · `PARTIAL`

| Blueprint view | State |
|---|---|
| Overview, Forecast timeline, Evaluation, System health, Administration | `MET` |
| **Sources** | `PARTIAL` — source identity, capability, last event and adapter errors appear across Administration and Live Telemetry; there is no single Sources view |
| **Investigation** | `ABSENT` — no drill-down from a warning to its input window, contributing features, source references and related events. Feature contributions exist on the Forecast page; the drill-down does not |

The forecast record contract (all 8 fields), the API surface (every route
family), the streaming decision (polling, explicitly permitted) and all
six UI honesty rules are met.

### §15 — the troubleshooting guide · `ABSENT`

The blueprint gives a fifteen-row table of symptom → investigate first →
safe response ("no live events", "queue grows continuously", "model
predicts nearly all negatives", "suspiciously perfect metrics",
"implausibly long lead time", …).

Most of the *behaviour* exists — the gate refuses, the report states
limitations, counters reconcile. What does not exist is **the guide**. A
user hitting "suspiciously perfect metrics" has nowhere to look, even
though this project has twice produced exactly that and diagnosed it
(window recall 1.000 on a single-class holdout; PR-AUC 0.9925 measuring
continuation). Those diagnoses live in ADRs, not in a troubleshooting
page.

This is the single most user-visible gap, and the cheapest to close.

### §16 — operational acceptance for real-time ingestion · `PARTIAL`

All eight required test layers exist (unit, adapter contract, integration,
leakage, deterministic replay, security, cross-platform, end-to-end), and
the experiment manifest carries all eight required items.

What is missing is §16's **operational acceptance**: before claiming a
supported live integration, record measured event rate, ingestion delay
distribution, processing delay, queue behaviour, dropped/rejected records,
reconnect behaviour, resource consumption, and the duration and
environment of the test. None of that has been measured. The blueprint is
explicit that numerical service targets are agreed only *after* these
measurements — and no such claim is made anywhere, so the project is at
least consistent.

---

## §18 — the two remaining criteria

| # | Criterion | State |
|---|---|---|
| 1 | Local deployment on declared OSes | `PARTIAL` — Linux verified including a real-browser session (27/27); Windows has not run Sessions 34–36 |
| 3 | ≥1 host **and** ≥1 network-level integration | `PARTIAL` — host verified; flow *parsing* tested against fixtures, but no live collector exists (ADR-072, deliberately not built without an exporter and an authorized observation point) |

Rows 8 and 9 are met **and the measurement is negative**: on
CSE-CIC-IDS2018 the learned models do not forecast attack onsets. See
`DATASET_PROVENANCE_IDS2018.md` §6.

---

## What would close the rest

| Gap | Needs | Size |
|---|---|---|
| §15 troubleshooting guide | nothing — writing | small |
| §11 Investigation view | nothing — frontend work | medium |
| §11 dedicated Sources view | nothing — frontend work | small |
| §10 calibration curve | nothing — the holdout is already kept | small |
| §10 inference latency | nothing — instrument the predict path | small |
| §5 security-platform adapter | an export format to target | medium |
| §16 ingestion benchmark | a load generator and a declared environment | medium |
| §10 cross-dataset generalization | a second corpus (CIC-IDS2017) | medium |
| §18-1 Windows | the operator's Windows machine | — |
| §18-3 live network collection | an authorized exporter and observation point | — |

Six of the ten need nothing but work in this repository.
