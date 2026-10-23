# PraHari — Coverage of the Whole Blueprint

`ACCEPTANCE_MATRIX.md` tracks **§18 Definition of done** — fifteen criteria.
This document audits the **other eighteen sections**, which carry roughly
230 further discrete requirements that §18 never mentions.

**Assessed 21 Oct 2026** against commit on `ccr-58caddbd-1gv7jn`, by
reading each section's requirement lists and checking them in the code.
**§15 re-assessed 21 Oct 2026** on Windows 11, after
`docs/TROUBLESHOOTING.md` was written and its claims checked in the
source and against a running instance.

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
| 5 | Pluggable adapter architecture | 27 | `PARTIAL` — no security-platform adapter, by decision (ADR-105) |
| 6 | Ingestion and data quality | 7 | `MET` — the persisted poll summary reconciles (ADR-123); DNS evidence is collected continuously against a durable event-log bookmark, on by default, with a proven fallback when the filtered query fails (ADR-127, ADR-128) |
| 7 | Forecasting task and label semantics | 7 | `MET` |
| 8 | Dataset strategy and leakage controls | 13 | `MET` |
| 9 | Models, technology stack, lifecycle | 27 | `PARTIAL` / 3 `DEVIATES` |
| 10 | Evaluation methodology | 16 | `PARTIAL` — cross-*dataset* alone is outstanding; cross-*period* measured and negative (ADR-111) |
| 11 | Dashboard and API contracts | 31 | `MET` (ADR-108, ADR-109, ADR-114, ADR-115, ADR-118, ADR-122, ADR-124, ADR-125) |
| 12 | Security, privacy, threat model | 16 | `MET` — source registration, retention enforcement and collector control all under the central-mode admin guard (ADR-118, ADR-126) |
| 13 | Repository structure and configuration | 7 | `DEVIATES` (layout, keys) |
| 14 | Installation and operating guide | 2 | `MET` |
| 15 | Troubleshooting and failure handling | 15 | `MET` — `docs/TROUBLESHOOTING.md` |
| 16 | Reproducibility, testing, release readiness | 17 | `MET` — all eight operational-acceptance items measured, on both storage backends (ADR-110, ADR-113, ADR-116) |
| 17 | Research positioning and claims | 6 | `MET` |
| 18 | Definition of done | 15 | 13 `MET`, 2 `PARTIAL` |
| 19 | References and decision register | 2 | `MET` |

**251 of 255 discrete requirements — about 98 %.**
(Was ≈ 222 / 89 % before §15's fifteen rows were written on 21 Oct 2026.)

255 is the sum of the Requirements column above, §18's fifteen included.
It is stated exactly rather than as "≈ 249", which was the figure here
until 22 Oct 2026 and understated the table it claimed to summarise by
six.

**Four requirements remain, and each needs an input rather than work in
this repository:**

| | Gap | Needs |
|---|---|---|
| §5 | No security-platform adapter | One real export file to target (ADR-105) |
| §10 | No cross-**dataset** generalization | CIC-IDS2017, behind a form asking for the operator's name, organisation and email (ADR-111) |
| §18-1 | Windows not run for this revision | The operator's Windows machine |
| §18-3 | No live network-level collection | An authorized exporter and observation point |

**This paragraph said "two" until 22 Oct 2026**, naming only §5 and §10
and omitting §18's two criteria — which the §18 section and the
closing-gaps table at the bottom of this same document both listed as
outstanding at the time. Three parts of one file, two answers. Found
while answering the question "how much is left", which is the question
the paragraph exists to answer, and corrected in ADR-117.

The deviations in §9 and §13 are **not** counted as gaps. `DEVIATES`
means implemented differently on purpose with the reason recorded, which
the legend above states and both sections do.

Two items listed here as blocked were not. Resource-consumption sampling
and scenario-level performance each needed only work, and both are done
(ADR-113).

**Two sections of this document were stale on 22 Oct 2026**, and both
were corrected by re-deriving them from the code rather than by editing
the words: §11 listed `Sources` as partial and `Investigation` as
absent, three revisions after both shipped; §16 read "None of that has
been measured", two revisions after ADR-110 measured six of its eight
items. In both cases the summary table above was right and the prose
below was wrong — which is the worse failure, because each half reads as
authoritative on its own. See ADR-116.

**Live network-level collection has been demonstrated but is not yet
recorded here**: real Zeek 8 into the wired JSON path, 989/989 accepted
across two distinct sources. That evidence lives on the operator's
machine and is uncommitted, so §18 row 3 still reads `PARTIAL` on
`main`. Pushing it is what closes it, not further work in this
repository.

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

### §5 — no security-platform adapter · `PARTIAL` by decision (ADR-105)

Five of six adapter categories exist: host telemetry, network flows
(parsing), network sensor (Zeek-shaped), file/replay, synthetic. The
sixth — **IDS/IPS, firewall, EDR, SIEM exports or APIs** — has no adapter.

The §5.1 lifecycle contract, the §5.2 canonical envelope (all nine fields)
and the §5.3 compatibility rules are fully met for the five that exist.

**This is now a recorded decision rather than an open task (ADR-105).**
Asked which export format was available to target, the answer was that
none is. An adapter written against an imagined export would encode a
guess at a schema and pass tests built from the same guess — ADR-072's
reasoning, applied to a second category. §5.3 requires refusing
incompatible required fields with a useful error, which a mapping
invented without a real export cannot honour. One real export file
changes this; `json_stream.py` already handles Zeek/Suricata-shaped
JSON, so a JSON-lines security export may need field aliases rather
than a new adapter.

### §10 — two metrics and two rules short · `PARTIAL`

| Requirement | State |
|---|---|
| Precision/recall, PR-AUC, FPR, missed-event, **event-level lead time**, data freshness, uncertainty | `MET` |
| **Calibration** | `MET` — reliability curve with per-bin counts (ADR-107) |
| **Scenario-level performance** | `MET` — the event-level report breaks every documented event down by attack label (ADR-113) |
| **Inference latency / throughput** | `MET` — measured at the `predict_recent_window` boundary (ADR-106); throughput under load in ADR-110 |
| Rule: *select thresholds on validation data* | `DEVIATES` — the threshold is fixed at 0.5 and never tuned, so no test data can influence it. Documented as a limitation in the target spec: the operating point may not suit a deployment |
| Rule: *evaluate cross-dataset generalization* | `PARTIAL` — **cross-period** measured and negative, mean transfer gap 0.4472 (ADR-111). Cross-*dataset* still absent: CIC-IDS2017 needs an operator-submitted registration form |

### §11 — all seven views present · `MET`

| Blueprint view | State |
|---|---|
| Overview, Forecast timeline, Evaluation, System health, Administration | `MET` |
| **Sources** | `MET` — `SourcesPage`, routed at `/sources` (ADR-108) |
| **Investigation** | `MET` — `InvestigationPage` at `/investigate`: a warning drills to the window scored, the records inside it, the sources that contributed, and activity either side (ADR-109) |

**This section said `PARTIAL` until 22 Oct 2026, three revisions after
both views shipped.** The closing-gaps table below had been struck
through at the time; this one was not. A coverage document that
contradicts itself is worse than one that is merely out of date, because
each half looks authoritative on its own. Both views were re-checked
against `routing.ts`, the two page components and the real-browser
session verifier before this row was changed.

The forecast record contract (all 8 fields), the API surface (every route
family), the streaming decision (polling, explicitly permitted) and all
six UI honesty rules are met. Guided mode (ADR-115) adds a plain-language
layer over the same data without weakening any honesty rule, enforced by
`AdvancedNeverHidesCaveats.test.ts`.

### §15 — the troubleshooting guide · `MET`

The blueprint gives a fifteen-row table of symptom → investigate first →
safe response ("no live events", "queue grows continuously", "model
predicts nearly all negatives", "suspiciously perfect metrics",
"implausibly long lead time", …).

**Written 21 Oct 2026: `docs/TROUBLESHOOTING.md`.** Fifteen rows, each
grounded in a diagnosis this repository actually made and citing its ADR
— eleven distinct ADRs across the fifteen rows — with every behavioural
claim read in the source or exercised against a running instance rather
than assumed. The two diagnoses that motivated this row are rows 5 and 4
of the guide (window recall 1.000 while warning 0 of 3 events, ADR-091;
PR-AUC 0.9925 measuring attack continuation, ADR-096), so they are now
where an operator will find them rather than only in `DECISIONS.md`.

Rows 7 and 13 cover this revision's own two fixes (ADR-100, ADR-099),
each with a measured before and after from Windows, because an operator
on an older build still meets them and the ADR-099 case leaves data that
cannot be repaired afterwards.

It also records what *cannot* occur — there is no queue, no live NetFlow
listener, and no code path that changes a route or firewall rule — so
time is not spent looking for those.

### §16 — operational acceptance for real-time ingestion · `MET`

All eight required test layers exist (unit, adapter contract, integration,
leakage, deterministic replay, security, cross-platform, end-to-end), and
the experiment manifest carries all eight required items.

§16's **operational acceptance** requires, before claiming a supported
live integration, measured event rate, ingestion delay distribution,
processing delay, queue behaviour, dropped/rejected records, reconnect
behaviour, resource consumption, and the duration and environment of the
test.

**All eight are measured** — `docs/INGESTION_BENCHMARK.md`, reproducible
with `scripts/benchmark_ingestion.py`:

| §16 item | Where |
|---|---|
| Event rate | 7105.7 rec/s SQLite, 2460.4 rec/s PostgreSQL (ADR-110, ADR-116) |
| Ingestion delay distribution | client p50/p95/p99/max per scenario |
| Processing delay | server-side p50/p95/max |
| Queue behaviour | `null` — there is no queue; bounding is by admission, and the hard 503 edge is measured |
| Dropped / rejected records | 0 dropped; rejected, duplicate and refused-for-overload kept distinct |
| Reconnect behaviour | closed-port refusal, then recovery on the live endpoint |
| Resource consumption | server-process RSS and CPU, sampled at 50 ms (ADR-113) |
| Duration and environment | recorded per run, both storage backends |

**This section read "None of that has been measured" until 22 Oct 2026**,
two revisions after ADR-110 measured six of the eight and one after
ADR-113 added the seventh. The summary table at the top of this document
had been updated to `MET`; this prose had not.

What this does **not** establish is unchanged and is stated in the
benchmark itself: one machine, loopback only, synthetic records, runs
lasting seconds rather than hours, and neither backend tuned. The
blueprint is explicit that numerical service targets are agreed only
*after* these measurements, and no figure here is published as a
promise.

---

## §18 — the two remaining criteria

| # | Criterion | State |
|---|---|---|
| 1 | Local deployment on declared OSes | `PARTIAL` — Linux verified including a real-browser session (**35/35**, grown from 27 as routes were added); Windows has not run Sessions 34–36 |
| 3 | ≥1 host **and** ≥1 network-level integration | `PARTIAL` — host verified; flow *parsing* tested against fixtures, but no live collector exists (ADR-072, deliberately not built without an exporter and an authorized observation point) |

Rows 8 and 9 are met **and the measurement is negative**: on
CSE-CIC-IDS2018 the learned models do not forecast attack onsets. See
`DATASET_PROVENANCE_IDS2018.md` §6.

---

## What would close the rest

| Gap | Needs | Size |
|---|---|---|
| ~~§11 Investigation view~~ | **done** (ADR-109) | — |
| ~~§11 dedicated Sources view~~ | **done** (ADR-108) | — |
| ~~§10 calibration curve~~ | **done** (ADR-107) | — |
| ~~§10 inference latency~~ | **done** (ADR-106) | — |
| §5 security-platform adapter | an export format to target — none available (ADR-105) | blocked |
| ~~§16 ingestion benchmark~~ | **done** (ADR-110); re-run on PostgreSQL (ADR-116) | — |
| §10 cross-**dataset** generalization | CIC-IDS2017 — an operator-submitted registration form. Cross-**period** is done (ADR-111) | blocked |
| §18-1 Windows | the operator's Windows machine | — |
| §18-3 live network collection | an authorized exporter and observation point | — |

Six of the ten need nothing but work in this repository.
