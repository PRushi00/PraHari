# PraHari — Implementation Status & Verification Audit Report

**Date**: October 11, 2026
**Canonical Repository**: `C:\Users\nanda\OneDrive\Desktop\Studies\CyberSecurity\Projects\PraHari\Implementation`
**Git Branch**: `master`
**Baseline reviewed**: commit `d0a2839`

This report distinguishes **verified** (executed and observed in this
environment), **implemented but unverified** (code complete, execution not
possible here), and **not implemented**. Claims not demonstrated by a test or
a recorded run are not marked verified.

---

## 0.-2 Session 5 — Browser Producer, Counter Correctness, Test Isolation, DNS Claim Correction

**317 backend tests + 36 frontend tests pass** (backend suite: 20.95s).
Typecheck and production build clean. Live telemetry and application-layer
contract verified against running instances.

### A claim I previously got wrong

Session 4 concluded that DoH explained the empty DNS cache. **That
overclaimed.** Re-measured this session:

```
AutoUpgrade          : False  (every entry)
DoH interface settings for the active adapter : none
```

The resolvers merely appear in Windows' built-in table of **well-known DoH
servers**. That table records which servers *offer* DoH; it is **not**
evidence this machine used DoH for any connection. The diagnosis now
reports the measured evidence and **explicitly declines to name a cause**,
listing all explanations consistent with it. Corrected in
`enrichment.py`, the UI, README and above.

### Defects found and fixed

| # | Severity | Defect | Fix |
| :-- | :-- | :--- | :--- |
| 43 | **High** | `count_events` ignored `event_type`, so a filtered query returned the **unfiltered** total. Observed live: `/events?event_type=http_request` reported **"3,252 total" beside zero rows**. | `count_events` accepts every filter `list_events` does; the endpoint forwards it. 3 regression tests cover all filter combinations. |
| 44 | **High (test integrity)** | Tests that *mocked* the connection table still shelled out to PowerShell for DNS refresh — one subprocess per poll. Inconsistent (fake connections, real DNS) and slow; the suite had ballooned to **3h 55m** under load. | Enrichment now defaults OFF when a `query_fn` is injected, ON for genuine collection; an explicit value always wins. **Suite: 8.85s.** Two tests assert no subprocess is spawned. |
| 45 | **Medium** | The live verification script assumed a cold collector and default config, so it failed on a warm instance (`accepted=0` is correct when everything is already recorded) and on an ingest-enabled instance. | Asserts the real invariant — every observed record is accepted, deduplicated, filtered or rejected, never silently dropped — and reports the ingestion mode rather than assuming it. Verified in cold, warm, default and enabled configurations. |

### Application-layer telemetry — now implemented, partially verified

| Component | Status |
| :--- | :--- |
| `extension/` WebExtension (MV3) | **Implemented** — `manifest.json`, `background.js`, `popup.html`, `popup.js`, `README.md` |
| Backend ingestion contract | **Verified** — 12 automated tests |
| End-to-end with **simulated** producer | **Verified** — `scripts/simulate_browser_producer.py`, all checks pass |
| End-to-end from a **real browser** | **NOT VERIFIED** — installing the extension is an explicit user action |
| UI panel | **Verified in browser** — `AppLayerPanel` on Live Telemetry |

Design points that matter:

* **Off by default**, with explicit start/stop in the popup. Stopping
  discards anything queued.
* **Query strings are discarded in the browser**, before transmission, and
  stripped again server-side. Defence in depth.
* Permissions are minimal: `webRequest`, `storage`, `alarms`. No
  `webRequestBlocking`, no `cookies`, no default `<all_urls>` — observing
  sites is an **optional** permission the user grants and can revoke.
* A failed request carries **no status**; it is stored null and rendered
  *"no response"*. A status code is never fabricated, and never inferred
  from a TCP connection succeeding.
* The simulator uses source id `browser_probe_simulated`, distinct from the
  extension's `browser_probe`, so simulated and genuine data can never be
  confused.
* Automated tests parse the extension source and fail if it references
  headers, cookies, bodies or query strings, or contacts any non-local host.

**HTTP visibility is therefore NOT claimed as operational.** Until the user
installs the extension, the dashboard shows "No HTTP transactions have been
observed" and explains why.

## 0.-1 Session 4 — Stream & Replay Crash, Numeric Safety, Counter Scopes, DNS Diagnosis

**224 backend tests + 36 frontend tests pass.** Typecheck and production
build clean. All nine pages verified in a browser against live telemetry
with zero console errors.

### Confirmed defect: Stream & Replay crash

`TypeError: Cannot read properties of undefined (reading 'toFixed')`.

**Root cause — a third instance of frontend/backend contract drift.**
`POST /stream/replay/synthetic` returns an **`ImportSummary`**. The page
declared a `SyntheticReplayResponse` interface that does not exist:

| Frontend read | Reality |
| :--- | :--- |
| `duration_seconds` | absent → `.toFixed(2)` **threw** |
| `simulated_attack_ratio` | absent |
| `generated_records` | actually `total_records` |
| `status` | absent |

The error boundary added in session 3 contained it — the rest of the app
stayed usable, which is how the user was able to report it precisely.

**Why the session-3 contract test did not catch it:** the comparison
silently skipped any interface with no same-named backend schema. No schema
is called `SyntheticReplayResponse`, so it was never checked. That hole is
now closed by `test_every_interface_is_accounted_for`, which fails unless
every exported interface is either paired with a schema or explicitly
declared local-only.

### Fixes

| # | Fix |
| :-- | :--- |
| 34 | `SyntheticReplayResponse` is now an alias of `ImportSummary`; the panel renders `total_records`, `accepted_records`, `rejected_records`, `data_category`, and an elapsed time **derived** from the summary's own `started_at`/`completed_at`. |
| 35 | **Backend gap**: the synthetic replay endpoint never set `completed_at`, unlike every other ingestion path — so elapsed duration was genuinely unavailable. Both timestamps are now recorded. |
| 36 | **`src/utils/format.ts`** — shared safe formatters (`fmtFixed`, `fmtInt`, `fmtPercent`, `fmtTime`, `fmtRelative`, `fmtElapsed`, `safeSeries`). They never throw and **preserve the difference between 0 and unavailable**. |
| 37 | Applied across Analysis, Overview, Forecast, LiveTelemetry, Audit, Events, Import and StreamReplay. Several truthiness guards (`value ? … : "N/A"`) were wrongly rendering a real **0** as unavailable; those now use `isNum`. |
| 38 | **Contract test hole closed** (see above), plus coverage extended to `EventSummaryStats`, `ConnectionDetail`, `CollectionGap`, `ReadinessRequirement`. |
| 39 | **Enum unions corrected.** `DataCategory` omitted `live_telemetry` and `EventType` omitted `connection` — the two values the live collector actually emits. A new by-value enum contract test guards them. |
| 40 | **`SYNTHETIC_SAMPLE` was counted as a data-quality defect.** With synthetic fixtures present this reported **477 of 552** records as defective. Provenance markers are now classified via `NON_DEFECT_QUALITY_FLAGS`; genuine defects dropped to **27** (the implausible-timestamp records). |
| 41 | Analytics showed *"Not measurable by the contributing source"* **beside a displayed value** under mixed provenance. It now reads e.g. *"Mean connection length — excludes 102 of 552 records whose source cannot measure it"*. |
| 42 | **Counter scopes made explicit** (see below). |

### Counter definitions (Phase C)

The user asked why "285 accepted" sat beside "993 stored". They are
different scopes, and the UI now says so:

| Counter | Scope | Meaning |
| :--- | :--- | :--- |
| Observed | collector process | Connection rows read from the Windows connection table across all polls |
| Accepted | collector process | Normalized into canonical events by this process |
| Repeats suppressed | collector process | Same still-open connection seen again; not a new event |
| Filtered (out of scope) | collector process | Excluded by policy (loopback-only). **Not** a defect |
| Rejected (unusable) | collector process | Failed validation — genuinely unusable |
| Events persisted | collector process | **New database rows** inserted this run |
| Events stored / source `event_count` | database, all time | Rows in SQLite, derived from storage |

**Invariant, now tested:** `observed = accepted + repeats + filtered + rejected`.

`accepted` can exceed `events persisted` because a restart clears the
adapter's in-memory dedup cache; connections are re-normalized but
deterministic event ids mean storage recognises them and inserts nothing.
Verified live: `observed=95 = accepted 50 + repeats 0 + filtered 45 + rejected 0`.

### DNS attribution — evidence-based diagnosis (Phase D)

Rather than guessing why the cache is empty, a **read-only** diagnostic
(`GET /api/v1/enrichment/dns/diagnose`) inspects resolver configuration.
Measured on this host:

```
Cached DNS records visible : 0
DNS client service         : Running
Configured resolvers       : 1.1.1.1, <LAN gateway, redacted>, 8.8.8.8
With DoH templates         : 1.1.1.1, 8.8.8.8
```

Additional measured facts: `Resolve-DnsName -CacheOnly` reports "record
does not exist" immediately after a *successful* resolution, and
`Get-DnsClientCache` returns an empty set **without error** as a non-admin,
while `ipconfig /displaydns` requires elevation.

**Conclusion (corrected in session 5 — the session-4 wording overclaimed):**
the diagnosis now **declines to name a single cause**. Measured on this
host, `AutoUpgrade` is **False** for every entry and the active adapter has
no DoH interface settings, so the resolvers merely appear in Windows'
built-in table of *well-known DoH servers*. That table records which
servers **offer** DoH; it is **not** evidence that this machine used DoH
for any connection. Several explanations remain consistent with the empty
cache — an application resolving over its own encrypted DNS, the cache
being unreadable without elevation, expired entries, or connections made
directly by IP. Hostnames therefore remain `unknown`, which is the correct
result.

It changes no DNS setting, flushes nothing, and sends no query.

## 0.0 Session 3 — Blank-Page Failure and Frontend/Backend Contracts

**206 backend tests + 36 frontend tests pass.** Typecheck and production
build clean. All nine pages verified in a real browser with zero console
errors.

### The reported failure, and why it happened

Opening **Feasibility** blanked the entire application; only a page reload
recovered it.

**Root cause — a frontend/backend contract mismatch with no containment.**
`ResearchPage` rendered a schema the backend has never produced:

| Frontend expected | Backend actually returns |
| :--- | :--- |
| `overall_feasibility_score` | `overall_score` (0–1, not 0–100) |
| `audit_id`, `audited_at`, `total_events` | `dataset_id`, `evaluated_at`, `metrics` |
| `temporal_monotonicity`, `class_balance`, `label_provenance`, `source_diversity`, `causal_leakage_risk` (objects) | `checks[]` (a list of `FeasibilityCheckResult`) |
| `advisory_warnings` | — |

`report.overall_feasibility_score` was therefore `undefined`, and
`.toFixed(1)` threw `TypeError: Cannot read properties of undefined`.
Reproduced in-browser: the page body was empty and the console showed that
exact error.

Two things made it fatal rather than cosmetic:

1. **The TypeScript interface was itself wrong.** It was internally
   consistent, so `tsc` passed — type-checking could not catch it, because
   the types were the thing that had drifted.
2. **No error boundary existed anywhere.** React 18 unmounts the whole tree
   when a render error reaches the root, so one bad field reference took
   down the entire application.

"Sometimes blank" is explained by the data: with an empty database the page
renders its empty state fine. Once events exist, `GET /research/audit`
auto-computes a report, the report becomes non-null, and the page crashes
every time.

### The same class of bug found elsewhere

An automated comparison of every TypeScript interface against the live
OpenAPI schema found four more mismatches that no test would have caught:

| Location | Phantom field | Consequence |
| :--- | :--- | :--- |
| `ForecastPage` | `feat.contribution` (backend emits `impact`) | `undefined.toFixed(3)` — would blank Threat Forecasting after a prediction |
| `AuditPage` | `log.created_at`, `log.log_id` (backend: `timestamp`, `id`) | Audit log rendered "Invalid Date" |
| `AuditPage` | `config.host` (backend: `host_binding`) | Displayed "Binding: undefined:8000" |
| `StreamReplayPage` | `adapter_name`, `format`, `is_running`, `records_accepted` | Adapter health cards rendered blank/undefined values |

### Fixes

| # | Fix |
| :-- | :--- |
| 26 | **`ErrorBoundary`** around the page area, keyed on the active tab. A render failure is contained, navigation stays usable, and moving away and back resets it. The shell can no longer be unmounted by a page. |
| 27 | **`ResearchPage` rewritten** against the real contract. The checklist is driven by the `checks[]` array rather than hard-coded criterion names, so a backend change cannot leave it referencing a field that no longer exists. Explicit loading / empty / error / success states, with a recoverable Retry. |
| 28 | **All five contract mismatches corrected** in both the TypeScript types and their call sites. |
| 29 | **Contract regression tests** (`test_frontend_api_contract.py`, 21 tests) compare every TypeScript interface against the live OpenAPI schema. Verified to fail when the original phantom field is reintroduced, and to pass once removed. |
| 30 | **Feasibility audit quality semantics** — the engine still counted `SOURCE_LIMITED` as a defect, so it reported 210/210 records "with warnings", scoring data quality 0.0% and pushing the verdict to REJECT. Structural source limits are now excluded: quality rose to 92.9% with 4 genuine defects (the implausible-timestamp records), and the verdict became CONDITIONAL_REVIEW. |
| 31 | **Honest label wording** — the audit said "Ground truth verified" while reporting 0 benign and 0 attack. It now states plainly that no labels are present and that unlabelled traffic is not treated as benign. |
| 32 | **Overview** reported "1 attack categories detected" for 56 entirely unlabelled events, because `unlabeled` was counted as a label class. It now reports 0 classifications and states how many events carry no ground truth. |
| 33 | **Audit page security boundaries** were hardcoded strings ("PROMISCUOUS SNIFFING DISABLED", "Adapters: CSV, Zeek JSON, Suricata, Synthetic Replay" — a list that omitted the live Windows source entirely). They are now read from the backend's live-derived `security_boundaries`. |

### Frontend test suite (new)

`vitest` + Testing Library, 18 tests:

* `ErrorBoundary.test.tsx` (6) — containment, page naming, retry, reset on navigation.
* `ResearchPage.test.tsx` (8) — the real contract, null report, API failure, partial source failure, missing `checks`, **non-numeric `overall_score`** (the exact crash), contract break contained by the boundary, run-audit flow.
* `Navigation.test.tsx` (4) — every tab renders; every tab survives **all API calls failing**; returning from Feasibility works without reload; navigation stays usable when a page throws.

```bash
cd frontend && npm test
```

### Verified in a real browser

All nine pages opened against a live backend with real collected telemetry:
Overview, Live Telemetry, CSV Import, Stream & Replay, Events Explorer,
Analytics, Feasibility, Threat Forecasting, Audit & Security — **zero
console errors**, no blank views, no reload required.

---

## 0. Session 2 Additions (Connection Intelligence, Provenance, Research Gate)

**189 backend tests + 18 frontend tests pass.** Frontend typecheck and production
build clean. Verified live against genuine host traffic.

### Defects found and fixed in this pass

| # | Severity | Defect | Fix |
| :-- | :-- | :--- | :--- |
| 19 | **High (DoS)** | A single Windows FILETIME-epoch timestamp (1601-01-01, emitted for PID 0 TimeWait sockets) implied a ~425-year span, so window generation attempted ~895 million iterations and **hung the request thread indefinitely**. Reproduced: `POST /forecast/train` never returned | Three guards: the adapter rejects implausible timestamps and falls back to poll time (flagged `invalid_value`); windowing excludes them from the observation range; `MAX_WINDOWS` caps generation regardless of input |
| 20 | **High (user-reported)** | Analytics showed `historical_import` while displaying live telemetry. Root cause: `data_category` came from a **request default**, never from the data, and was persisted that way | Provenance is now derived from the analyzed events (`data_category`, `data_categories`, `source_breakdown`, `is_mixed_provenance`). The request field is a filter only |
| 21 | **High** | The research gate was advisory. `POST /forecast/train` and `/predict` were callable directly, and prediction fell back to an uncalibrated heuristic | Backend enforcement at every entry point, HTTP 409 with unmet requirements, observed-vs-required values and next steps. Audited |
| 22 | **Medium** | `sqlite:///./prahari.db` resolved against the **working directory**, so the launcher and backend-directory runs created different databases. The user's 318 live events were in one; tests used the other | Paths resolve against the project root, derived from package location. Tests forced to a temp database so they can never touch live telemetry |
| 23 | **Medium** | Every live record was flagged `MISSING_FIELD` for bytes/packets/duration, so all 195 profiled records appeared defective and genuine gaps were invisible | `SOURCE_LIMITED` for structural limits; analytics splits `unsupported_field_counts` from `missing_field_counts`; `records_with_warnings` now counts real defects only (0, was all) |
| 24 | **Medium** | A saved analysis was served as current even after new events arrived | `/analysis/latest` recomputes when stored events have changed |
| 25 | **Low** | Attribution reported `dns_cache_observation` even when the evidence came from a submitted resolver log | The winning observation's actual method is reported |

### Capabilities added

| Capability | Status | Evidence |
| :--- | :--- | :--- |
| **Process-name attribution** | **VERIFIED (live)** | All 77 observed connections resolved a process name unprivileged (a browser, a cloud-sync client, system services). Specific names are withheld: they describe what the operator runs. Command line never collected |
| **Domain attribution with evidence** | **IMPLEMENTED; no evidence available on this host** | Confidence grading verified end-to-end: single recent resolution → HIGH; second hostname on same IP → MEDIUM with CDN limitation; stale → LOW. See §0.1 |
| **Reverse DNS (opt-in)** | **VERIFIED (live)** | Returns `ec2-…compute-1.amazonaws.com`, `…cloudfront.net` marked `confidence=low`, `attribution_kind=infrastructure_owner`, `identifies_requested_host=false` |
| **Connection-intelligence API + UI** | **VERIFIED (browser)** | Sortable/filterable table with expandable per-connection evidence |
| **Source capability model** | **VERIFIED** | `GET /events/capabilities`; `http_status_code` is `unsupported_by_source` for every source except `application_layer` |
| **Application-layer ingestion** | **IMPLEMENTED, disabled by default; no producer configured** | 18 tests. Bodies/cookies/credentials rejected (422). Query strings stripped |
| **Forecasting readiness states** | **VERIFIED** | 7 states; `GET /forecast/readiness` |

### 0.1 Domain attribution — honest status on this host

`Get-DnsClientCache` returns **zero records** on the development machine,
and `Resolve-DnsName -CacheOnly` reports "record does not exist" immediately
after a successful resolution — so entries are genuinely not cached. The
practical cause is encrypted DNS (DoH/DoT) bypassing the Windows resolver.

Consequently **0 of 48 live connections could be attributed a hostname** in
the final verification run. The API reports this as an explicit `diagnosis`
rather than as "no domains observed". Attribution logic itself is verified
by 23 unit tests and by live submission of resolver evidence.

### 0.2 Forecasting — what the numbers do and do not show

With 800 **synthetic** labelled events the gate permits training and the
pipeline produces a defensible evaluation:

```
split: chronological_train_side_purge | 154 windows | 98 train | 9 purged | 47 holdout
holdout class balance: 24 incident / 23 benign
Random Forest: accuracy 0.766  precision 0.842  recall 0.667  F1 0.744  PR-AUC 0.760  Brier 0.202
Majority-class baseline: accuracy 0.489
```

**These figures demonstrate that the pipeline works. They are not evidence
of real-world forecasting effectiveness.** The data is synthetic, generated
with deterministic attack bursts that are inherently learnable. No claim of
predictive skill on real traffic is made or supported.

On genuine local telemetry the gate **refuses**, correctly: locally
observed traffic carries no incident labels, and unlabelled traffic is not
counted as benign.

---

## 1. Requirements Verification Matrix

| Requirement Area | Requirement | Status | Source Files | Tests / Evidence |
| :--- | :--- | :--- | :--- | :--- |
| **Live Windows Telemetry** | Collect genuine network activity from this Windows host into the existing ingestion pipeline | **VERIFIED (live)** | `backend/app/adapters/windows_telemetry.py`<br>`backend/app/services/collector.py`<br>`backend/app/api/v1/collector.py` | `tests/unit/test_windows_telemetry.py` (22)<br>`tests/integration/test_windows_collector.py` (16, incl. 2 `live_windows`)<br>`scripts/verify_live_windows_telemetry.py` — executed, all checks passed |
| **Live Collector Lifecycle** | Start/stop cleanly, report health, failures and collection gaps | **VERIFIED (live)** | `backend/app/services/collector.py` | Background loop run live: 5 polls, 43 events persisted, 146 repeats suppressed, 1 gap detected, clean stop, source marked `disconnected` |
| **Live Dashboard Integration** | Dashboard shows collector state and real observations | **VERIFIED (browser)** | `frontend/src/pages/LiveTelemetryPage.tsx` | Started/stopped collection from the UI; 37 real connections rendered with genuine endpoints and provenance |
| **Data Category Separation** | Live telemetry distinguishable from imports, replays and fixtures | **VERIFIED** | `backend/app/schemas/events.py` | Verification script section 8; `test_windows_collector.py` |
| **Unified Deployment** | React SPA served by FastAPI on `127.0.0.1:8000` with deep links and traversal protection | **VERIFIED** | `backend/app/main.py`<br>`frontend/dist/` | `tests/integration/test_deployment_and_spa.py` (5) + live curl matrix |
| **API 404 Correctness** | Unknown `/api/*` paths return JSON 404, not the SPA shell | **VERIFIED (fixed)** | `backend/app/main.py` | Live: `/api/v1/does-not-exist` → 404 `application/json` |
| **Windows Launchers** | `.ps1` / `.bat` launchers, loopback binding, port preflight | **VERIFIED** | `start_prahari.ps1`, `start_prahari.bat` | `scripts/verify_live_launcher.py` |
| **Docker Configuration** | Multi-stage `Dockerfile` + compose with persistent volume | **IMPLEMENTED, RUNTIME UNVERIFIED** | `Dockerfile`, `docker-compose.yml` | Docker not installed on this host; not installed (requires approval). Reviewed statically only |
| **CSV Ingestion** | Flow ingestion with IP/port validation, UTC normalization, rejection categorization | **VERIFIED** | `backend/app/adapters/csv_import.py` | `tests/unit/test_csv_import.py` (5), `test_comprehensive_ingestion.py` |
| **NDJSON / Zeek / Suricata** | Zeek `conn.log` and Suricata EVE ingestion | **VERIFIED (defect fixed)** | `backend/app/adapters/json_stream.py` | `tests/unit/test_stream.py`, `test_comprehensive_ingestion.py` |
| **Database Persistence** | Transactional SQLite, WAL, foreign keys, idempotency | **VERIFIED (defect fixed)** | `backend/app/storage/database.py` | `tests/unit/test_database.py`, `test_windows_collector.py` |
| **Descriptive Analytics** | Factual summaries segregated from forecasting | **VERIFIED** | `backend/app/services/analysis.py` | `tests/unit/test_analysis.py`; live analytics over collected telemetry |
| **Research Feasibility** | Dataset audit before forecasting claims | **VERIFIED (advisory)** | `backend/app/research/feasibility.py` | `tests/unit/test_research.py` |
| **Forecasting Pipeline** | Causal windows, purged chronological split, baselines, calibration | **IMPLEMENTED — RESEARCH-GATED** | `backend/app/models/forecaster.py`<br>`backend/app/models/feature_extractor.py` | `tests/unit/test_forecaster.py` (10); `scripts/verify_forecasting_pipeline.py` |
| **Forecasting Effectiveness** | Demonstrated ability to predict future attacks | **NOT DEMONSTRATED** | — | No dataset available with defensible labels across independent periods. See §5 |
| **End-to-End Pipeline** | Ingestion → analytics → research gate → forecasting | **VERIFIED** | `tests/integration/test_end_to_end_workflow.py` | 1 test, asserts honest refusal path |

---

## 2. Test Execution Results

**189 backend tests, 189 passed, 0 failed, 0 skipped** (plus 18 frontend tests) (Python 3.12.0, pytest 9.1.1, win32).

```
cd backend && python -m pytest -q
189 passed, 1 warning in 40.06s
```

Breakdown of coverage added during this review:

| Test file | Tests | Covers |
| :--- | ---: | :--- |
| `tests/unit/test_windows_telemetry.py` | 22 | Field mapping, OS timestamp parsing (incl. 7-digit .NET fractions), honest null metrics, IPv6, rejection reasons, deterministic ids, repeat suppression, 4-way accounting, cache pruning |
| `tests/integration/test_windows_collector.py` | 16 | Persistence, source health, dedup across polls, restart safety, failure surfacing, empty-table success, gap detection, lifecycle idempotency, policy filtering, API endpoints, **2 genuine live-OS tests** |
| `tests/unit/test_forecaster.py` | 10 | Purged split geometry, refusal on short span, refusal on single-class training period, uninterpretable-metric flagging, unvalidated-prediction labelling, inference window bounding, configuration disclosure |

The two `live_windows`-marked tests query the real Windows connection table
and are skipped automatically on other platforms:

```
python -m pytest -m live_windows -v
tests/integration/test_windows_collector.py::test_live_query_returns_real_connections PASSED
tests/integration/test_windows_collector.py::test_live_collection_end_to_end_persists_real_telemetry PASSED
2 passed, 77 deselected
```

A mocked collector test demonstrates pipeline wiring only. Only the
`live_windows` tests demonstrate that genuine host telemetry is observed.

**Frontend production build**: `npm run build` succeeded (2518 modules,
`dist/assets/index-*.js` 1,307.70 kB / 419.33 kB gzip). `tsc --noEmit` clean.

---

## 3. Live Windows Telemetry — Observed Evidence

Executed `scripts/verify_live_windows_telemetry.py` against a running server
on an isolated database. **All checks passed.** Representative run:

```
Poll 1: observed=110 accepted=37 persisted=37 duplicates_suppressed=0  filtered_by_policy=73 rejected=0
Poll 2: observed=112 accepted=0  persisted=0  duplicates_suppressed=37 filtered_by_policy=75 rejected=0
```

Verified in that run:

- **Genuine activity**: 110 real TCP connections read from this host's
  connection table; external peers on port 443 and others.
- **Accounting balances**: observed = accepted + rejected + duplicates + filtered.
- **Repeat handling**: all 37 still-open connections suppressed on poll 2;
  stored row count unchanged.
- **Provenance**: every stored record `data_category=live_telemetry`,
  `event_type=connection`, `source_id=windows_local_host`,
  `raw_reference=windows:tcp;state=…;pid=…`.
- **Honest absence**: `bytes_total`, `packets`, `duration` all null with
  `missing_field` flagged; `label` null.
- **Timestamps**: OS connection creation time, timezone-aware.
- **Source health**: `event_count` matched stored events exactly (37 = 37).
- **Analytics**: protocol distribution `{"TCP": 37}`, 23 unique destination
  IPs, top destination ports aggregated; `total_bytes` correctly null.
- **Adapter registry**: genuine counters (`processed=37, rejected=0`).

Background loop verified separately: 5 polls, 43 events persisted (6 new
connections appeared during the window), 146 repeats suppressed, one
collection gap correctly recorded, clean stop, source `disconnected`.

Dashboard verified in a browser: collection started and stopped from the UI,
real endpoints rendered, empty state shown correctly before collection.

---

## 4. Defects Found and Corrected

| # | Severity | Defect | Correction |
| :-- | :-- | :--- | :--- |
| 1 | **High** | `EventType.DNS` does not exist — any Suricata/Zeek record with `event_type` containing `dns` raised `AttributeError`, failing the whole import | Mapped to `DNS_QUERY`; added `HTTP_REQUEST`; regression covered |
| 2 | **High** | Forecaster fell back to an interleaved `[::2]` split when the chronological training split was single-class — direct leakage with overlapping windows | Fallback removed; refuses with `InsufficientEvaluationDataError` |
| 3 | **High** | Forecaster set `X_test = X_train` when the test split was empty, reporting a fitted-data score as a holdout score | Removed; refuses instead |
| 4 | **High** | `/forecast/predict` returned a propensity score from an **unfitted** heuristic with nothing marking it unvalidated; auto-train failures silently swallowed | Added `is_validated_model`, `validation_status`, `is_actionable_forecast`, `interpretation`, `evaluation_caveats`; training failures surfaced |
| 5 | **High** | `/stream/adapters` returned hardcoded fabricated health metrics (`records_processed=35`…) | Replaced with a live `AdapterRegistry` reporting genuine counters |
| 6 | **High** | `insert_events` caught every `IntegrityError` as "duplicate" and continued. `INSERT OR IGNORE` does **not** suppress foreign-key violations, so events were silently dropped and reported as successful | FK failures now raise with a diagnostic message |
| 7 | **Medium** | Every unknown `/api/*` path returned HTTP **200 with HTML** (SPA shell), hiding missing routes and breaking clients | API paths now return JSON 404 |
| 8 | **Medium** | Frontend called `/research/report`, which does not exist — silently received HTML and failed to parse | Corrected to `/research/audit` |
| 9 | **Medium** | `source.event_count += len(events)` inflated counts whenever records were deduplicated on insert | Added `refresh_source_activity()`, deriving counts from storage; `last_event_at` only moves forward |
| 10 | **Medium** | `/audit/config` published hardcoded `research_gate_enforced: true` and `live_sniffing_disabled: true` — a security surface asserting guarantees the system did not provide | All boundaries now derived from live state; gate described accurately as advisory |
| 11 | **Medium** | `backend/prahari.db` was committed to git — now a privacy problem, since the operational DB holds real local/remote IPs, ports and process ids | Untracked; `*.db` gitignored |
| 12 | **Medium** | `scripts/live_data_streamer.py` fabricated records, stamped them with `time.time()`, ingested them under `live_*` source ids and printed "ALERT: INCIDENT IMMINENT" from an unvalidated score | Replaced by `scripts/simulate_synthetic_stream.py`: synthetic category, enforced `synthetic*` source ids, honest validation reporting |
| 13 | **Medium** | Inference used the N most recent events regardless of time span, making rate features incomparable with the W-second training windows | Inference now bounded to the observation window; window reported in the response |
| 14 | **Medium** | Window configuration was silently rescaled for short datasets, so documented W/L/H/S did not match what ran | `WindowingReport` publishes nominal vs effective configuration and flags fallback chunking |
| 15 | **Low** | `raw_record["id"]` / `["alert"]` assumed dict — a scalar crashed the batch | Guarded; flagged `schema_warning` |
| 16 | **Low** | `POST /research/audit` read `source_id` from the query string only, silently ignoring the dashboard's JSON body | Accepts either |
| 17 | **Low** | Collector could not persist without a prior `start()` (FK violation on unregistered source) — found by new tests | `poll_once` ensures source registration |
| 18 | **Low** | Policy-filtered (loopback) records were counted as rejections, overstating data-quality failures | Separate `filtered_by_policy` accounting |

---

## 5. Forecasting: Methodology and Honest Status

### Formulation (unchanged, as specified)

Observation window `W=60s`, lead time `L=30s`, horizon `H=60s`, stride `S=15s`.

### Leakage control (strengthened)

Sliding windows overlap, and a window's label describes a period that later
windows take as input. The pipeline now applies a **chronological split with
a train-side purge** of `ceil((W+L+H)/S)` windows, preserving the holdout.
Instances are never reassigned across the boundary.

Evaluation is **refused** when fewer than 4 training windows survive the
purge, when no holdout remains, or when the leakage-free training period is
single-class. The API returns HTTP 422 with the split report.

### Result on the repository fixture (`sample_flows.csv`, 35 accepted flows)

```
total windows          : 21
purged (contaminated)  : 9  (embargo 10 windows = 150.0s)
leakage-free training  : 5  (positives 5, negatives 0)
holdout                : 7  (positives 0, negatives 7)

EVALUATION REFUSED — the leakage-free training period contains only class 1.
```

**The previously reported metrics for this fixture (Random Forest accuracy
42.9%, Brier 0.365, etc.) are withdrawn.** They were produced on a boundary
split that is contaminated by overlapping windows, from a training period
that was single-class, against a holdout with zero positive examples. Under
those conditions accuracy measures nothing and precision/recall/PR-AUC are
undefined. No number is reported in their place, because this dataset cannot
support one.

### What is and is not claimed

- **Implemented and tested**: causal windowing, purged chronological
  splitting, four comparative models, PR-AUC / ROC-AUC / Brier / confusion
  matrix, feature attribution, calibration reporting, refusal semantics.
- **Not demonstrated**: any ability to predict future attacks. No evaluation
  in this repository shows predictive skill, and the pipeline is explicitly
  research-gated.
- **Required to progress**: labelled incident data spanning substantially
  more time, with attack and benign activity present in both earlier and
  later periods, ideally across independent scenarios so generalization can
  be tested. Locally collected Windows telemetry carries no attack ground
  truth and cannot supply this.

---

## 6. Security and Privacy Posture

- Server binds `127.0.0.1` by default; the ingestion API is not exposed to
  the LAN for the collector (it runs in-process).
- Collection is **unprivileged**: no packet capture, no promiscuous mode, no
  raw sockets, no driver, no elevated privileges, no network configuration
  change, no router change.
- Only the local host is observed. No other device or household traffic.
- No payload content is captured. Process **id** retained as provenance;
  process **name** not collected.
- Telemetry never leaves the machine. `*.db` is gitignored; the previously
  committed database has been untracked.
- `/audit/config` reports the live posture rather than fixed claims.

**Sensitive fields stored**: local IP, remote IP, ports, protocol, TCP state,
owning process id, connection timestamps. Retention is governed by
`retention_days` (default 365); no automatic pruning job is implemented yet —
see §7.

---

## 7. Remaining Limitations

1. **Docker runtime unverified.** Docker is not installed on this host and
   was not installed (that needs approval). Configuration reviewed statically.
2. **No demonstrated forecasting effectiveness.** See §5.
3. **No byte/packet/duration from the live source.** Inherent to the
   connection table. Volumetric forecasting features are therefore
   unavailable for live data; they remain available for CSV/NDJSON imports.
4. **Short-lived connections are missed** between polls. Reported as a
   capability limit and via collection gaps.
5. **UDP not collected** — Windows exposes no remote peer for UDP endpoints.
6. **Retention not enforced.** `retention_days` is configured and reported
   but no pruning job deletes aged telemetry.
7. **No authentication.** `require_authentication` defaults false, which is
   appropriate for loopback-only local use but means the API must not be
   exposed to a network as-is.
8. **SPA deep links are cosmetic.** The frontend uses tab state, not a
   router, so `/events` serves the shell and renders the Overview tab. Deep
   links return 200 but do not restore a specific view.
9. **Frontend bundle is large** (1.3 MB, 419 kB gzip) — no code splitting.
10. **No automated frontend tests.** UI verified manually in a browser.

---

## 8. How to Reproduce This Verification

```bash
cd backend && python -m pytest -q                      # 80 tests
cd backend && python -m pytest -m live_windows -v      # genuine OS collection
cd frontend && npm run build                           # production bundle
python scripts/verify_forecasting_pipeline.py          # forecasting audit (refusal)
```

With the server running (`.\start_prahari.ps1`):

```bash
python scripts/verify_live_windows_telemetry.py
```

---

## Session 6 — Reproducibility, Retention, Central-Mode Security

**317 backend + 36 frontend tests pass.** Three Definition-of-Done items
moved from PARTIAL/NOT MET to MET. See
[docs/REQUIREMENTS_MATRIX.md](docs/REQUIREMENTS_MATRIX.md).

### Experiment replay (DoD 13)

`research/experiment.py` adds a versioned manifest recording the dataset
fingerprint, provenance breakdowns, target definition, window and split
parameters, seed, feature set, environment and results — with **no
telemetry**. `replay_experiment()` re-selects the dataset, rebuilds the
windows and split, retrains, and compares the deterministic outputs.

Verified: capture → replay reproduces exactly (`reproduced=True`, zero
differences, confusion matrices identical). Fails closed on a changed
fingerprint, missing dataset, schema change, feature change, or a config
that no longer evaluates — reporting **all** mismatches at once.

**A real defect the runner exposed:** the manifest first stored a *derived*
train ratio (`train_instances / total_instances`). Because purging removes
windows between the splits, that value is smaller than the configured one,
so replaying with it produced a different split. The split report now
records `configured_train_ratio`, the parameter actually passed.

### Retention enforcement (DoD 11)

`retention_days` was reported but never applied. `services/retention.py`
enforces it:

- **Dry run by default**; `confirm="DELETE-EXPIRED-TELEMETRY"` to delete.
- **Never automatic** — no scheduler, no startup hook (explicitly tested).
- Age from `observed_at` in **UTC**, not ingestion time, so old telemetry
  imported recently is still eligible.
- Batched in independent transactions: an interruption leaves whole
  batches committed and the database consistent (tested).
- Sources, import summaries, analyses and **audit records are never
  pruned**. Test fixtures are outside the default policy.
- Source counters refreshed afterwards so they cannot report deleted rows.

### Central-mode security (DoD 2)

Central deployment now **fails closed**: it refuses to start without
credentials rather than serving open.

```
Refusing to start in CENTRAL deployment mode: Central deployment requires
credentials. Set PRAHARI_CREDENTIALS_FILE or PRAHARI_CREDENTIALS_JSON.
PraHari will not run centrally without authentication.
```

Live loopback verification:

| Request | Result |
|---|---|
| `GET /health` (public) | **200** |
| `GET /events` no credential | **401** |
| `GET /events` invalid credential | **401** |
| `GET /events` valid credential | **200**, `X-PraHari-Source: sensor-01` |
| `GET /events?source_id=other` | **403** cross-source denied |

Tokens are PBKDF2-HMAC-SHA256 hashed with per-credential salts, compared in
constant time, shown once at mint and never stored. An unscoped query
returns only the caller's source — not everything. Unknown and disabled
credentials return identical wording so source ids cannot be enumerated.

`scripts/manage_credentials.py` mints and manages credentials; the store
holds hashes only and `secrets/` is gitignored.

**Central mode remains disabled by default.** It was exercised only over
127.0.0.1; no listener was exposed beyond loopback.

### Dataset acquisition (DoD 7)

[docs/DATASET_ACQUISITION.md](docs/DATASET_ACQUISITION.md) documents the
acquisition checklist, the implemented import/audit workflow, the leakage
controls applied automatically and those that remain the operator's
responsibility. **No dataset was downloaded** — licence acceptance and a
multi-gigabyte transfer are a user decision.
