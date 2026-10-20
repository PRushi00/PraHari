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

**761 backend (Windows) + 759/2-skipped (Linux) + 46 frontend tests pass.**
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

---

## Session 7 — Sensor Contract, Label Provenance, Platform Assessment

**343 backend + 36 frontend tests pass.** Typecheck and production build
clean.

### Zeek / Suricata ingestion contract

26 new tests (`test_network_sensor_adapters.py` 21,
`test_sensor_ingest_roundtrip.py` 5) pin the adapter against the shapes
those tools actually emit: both Zeek connection-id forms, the `"-"` unset
marker, zero-valued counters, second vs millisecond timestamps, non-UTC
offsets, IPv6, EVE `dns`/`http`/`alert` mapping, unknown fields, protocol
passthrough, and batch reconciliation with per-record rejection reasons.

Writing them surfaced four real defects.

**1. A Suricata signature was stored as `dataset_ground_truth`.** An IDS
signature is the detector's opinion, not confirmation that an attack
occurred. A forecaster trained on it learns to predict *one detector's
alerts* while precision and recall are reported as attack prediction. Now
recorded as `detector_output` with a warning, and surfaced in the readiness
report as `non_ground_truth_labelled_events` with a caveat shown on the
forecast page.

**2. `SYNTHETIC_RULE` was a silent enum alias.** It shared the string value
`"rule_based"`, so synthetic labels were indistinguishable from locally
derived ones in every provenance breakdown — including the experiment
manifest, whose entire purpose is recording what a result was computed on.
Every metric this project has produced comes from synthetic data, so this
hid the most important caveat attached to all of them. Two existing tests
asserted `"rule_based" in ...` under a comment reading "Provenance makes
synthetic data obvious"; they were asserting the bug.

**3. Any labelled record was rewritten to `EventType.ALERT`.** An imported
labelled corpus would have reported as nothing but alerts. The event type
describes what was observed; the label describes how it was annotated.

**4. `or`-chain field lookups discarded recorded zeros.** `0` bytes, `0.0`
seconds and port `0` are falsy, so they fell through to the next key and
ended as `None` — "we measured zero" became "we measured nothing". Zeek's
`"-"` unset marker now stays absent rather than becoming `0`.

All four were **mutation-checked**: each old behaviour was reintroduced and
the corresponding test observed to fail (4/4, then the zero-counter case
separately after it revealed a coverage hole in the first attempt).

### Platform assessment

[docs/PLATFORM_SUPPORT.md](docs/PLATFORM_SUPPORT.md) records what has
actually been executed where, and what a real network sensor deployment
requires.

A pre-existing Ubuntu 26.04 / Python 3.14.4 WSL2 environment was inspected
**read-only** — nothing installed, nothing started:

```
python 3.14.4 on linux
compiled 48 modules from app/
syntax errors: 0
```

No Windows-only imports exist at module scope, and `collector.py` gates on
`sys.platform`, reporting state `unsupported` rather than raising. The
expected Linux behaviour is therefore: everything works except live local
collection, which says it is unavailable.

**That remains an expectation, not a result.** Nothing was imported or
executed there, because the dependencies are not installed and installing
software is outside the agreed boundary. Linux stays **not verified**.

---

## Session 8 — Telemetry Breadth, Lead Time, Measurement Integrity, Linux

**394 backend (Windows) · 392 passed / 2 skipped (Linux) · 36 frontend.**
Typecheck and production build clean. All nine pages driven in a browser.

### New telemetry sources

Two further unprivileged, read-only Windows sources. Neither captures
packets, elevates, installs anything or touches network configuration.

**UDP endpoint table** (`POST /hostobs/udp/poll`) — locally bound UDP
sockets as `EventType.UDP_ENDPOINT`. These are **not conversations**: UDP
is connectionless and Windows records no peer, so `dst_ip`/`dst_port` are
declared **not applicable** rather than missing. Inventing a destination
would corrupt every destination-based aggregation.

Live: 41 endpoints observed, 41 normalized, 0 rejected. A second poll
persisted 1 new socket and suppressed 40 repeats — deterministic ids work.

**Interface counters** (`GET /hostobs/interfaces`) — the only genuine byte
and packet measurement available here without packet capture. They are
**interface-level and cumulative**, so they are served from their own
endpoint and are never written into `normalized_events`. The payload states
its own scope (`attributable_to_flow: false`). Deltas are offered between
readings; across an adapter reset no delta is derived, because neither a
negative nor a wrapped-around positive describes anything real.

### Forecasting: lead time, uncertainty, a temporal model

`POST /forecast/lead-time-curve` re-runs the complete protocol once per
lead time, everything else held constant. Measured decay on synthetic
data:

| Lead | 0s | 30s | 60s | 120s | 300s |
|---|---|---|---|---|---|
| best PR-AUC | 0.937 | 0.886 | 0.851 | 0.745 | 0.931 |

A lead whose split cannot support an honest evaluation is reported as a
**refusal with its reason**, never omitted. The 300s rebound is a
46-instance holdout talking, which is exactly why intervals matter.

`GET /forecast/uncertainty` gives percentile bootstrap intervals, and
**refuses** below 20 instances or 5 positives, or on a single class,
rather than returning a narrow range computed from nothing.

`temporal_window_stack` concatenates the previous `TEMPORAL_LAGS` windows,
so order matters. Lag stacking happens **after** the split, separately per
side — applied before, a test instance near the boundary would carry
training-period windows in its lags and re-import the contamination the
purge removes. It is **not** an LSTM and is not described as one.

### Measurement integrity — found in a browser, not by a test

Driving the dashboard against the real dataset exposed a defect no test
had caught.

The **Analytics** page showed an observation window starting **1/1/1601**,
and **Feasibility** scored "Temporal Monotonicity & Ordering" at **100%,
PASSED**, over a span of **13,436,268,232 seconds — about 425 years**. The
readiness gate, over the very same dataset, correctly reported 65,260
seconds.

Three modules implemented the same timestamp rule independently. The
adapter had it, readiness had it, the descriptive analysis had never had
it, and feasibility inherited the broken span and awarded full marks for
temporal integrity on a dataset whose time axis was unusable. **65 records
in the operational database carry the FILETIME epoch.**

`is_plausible_timestamp()` now lives in one place and is imported
everywhere. The analysis excludes and counts them, the UI says so, and the
feasibility check fails with the count named.

Two related corrections:

- Averages now publish their denominator. `avg_bytes` was computed over
  200 of 3,669 records and reported beside `total_events: 3669`; the
  dashboard disclosed it, the API did not.
- `attack_ratio` divided 50 attack labels by 3,669 total events, giving
  "1.4% attack" for a dataset whose labelled portion is 25% attacks. It is
  now a fraction of the labelled population, with both counts reported.

### Linux: runtime verified, and it found two portability defects

Ubuntu 26.04, Python 3.14.4, dependencies in a home-directory venv — no
system packages, no root.

```
392 passed, 2 skipped in 13.29s
GET /health               -> 200  healthy, mode=local
GET /collector/status     -> 200  state=unsupported, platform=Linux 6.18.33.2
POST /hostobs/udp/poll    -> 501  unsupported_platform
```

Static analysis had said the code was portable. Running it said otherwise:

1. **The platform gate refused injected sources.** `collector.py` checked
   `sys.platform` before checking whether the caller had supplied its own
   query function, so 12 tests failed off Windows and a legitimate
   alternative producer would have been refused for the same wrong reason.
   The gate now applies only to the real PowerShell path — which is still
   refused off Windows, with a test for it.
2. **The operational-database guards tested a substring.** They asserted
   the database URL contained `tmp`. A throwaway database under `$HOME` is
   isolated by any reasonable reading, and they failed. They now assert the
   property that matters: the resolved path is not the repository's
   `prahari.db`.

### Browser verification

All nine pages loaded against a copy of the real dataset, with **zero
console errors**: Overview, Live Telemetry, CSV Import, Stream & Replay,
Events Explorer, Analytics, Feasibility, Threat Forecasting, Audit &
Security. No blank pages, no `toFixed` crash, navigation between all pages
without reload.

### Docker

**Not verified.** Docker is not installed on this host and installing it is
outside the agreed boundary.

---

## Session 9 — LSTM, Generalization, Container Hardening

**442 backend (Windows) · 440 passed / 2 skipped (Linux) · 42 frontend.**
Typecheck and production build clean.

Two Definition-of-Done items moved to MET. The only remaining PARTIALs
(3 and 7) are blocked on an external dataset and an authorised network
segment, not on implementation.

### The LSTM, built and verified

`models/lstm_forecaster.py` — single-layer LSTM with a sigmoid read-out,
backpropagation through time with Adam, in **NumPy**. No new dependency:
PyTorch would be a large install outside the agreed boundary for a model
operating on a few hundred sequences of four timesteps.

Because it is hand-written, correctness is demonstrated rather than
assumed. A subtly wrong BPTT pass still produces a plausible loss curve.

| Check | Result |
|---|---|
| Analytic gradients vs central finite differences | worst relative error **1.3e-07** |
| Memory: label visible only at timestep 0 | **100%** holdout accuracy |
| Same task, memoryless model | **below 0.70** — the task really does need memory |

**The result is negative and is reported as such.** On 900 synthetic
events the LSTM scores PR-AUC **0.751** — the worst of the four
non-baseline models, below logistic regression. It has not been promoted,
hidden, or re-tuned until it wins.

### Generalization

`POST /forecast/generalization` — leave-one-group-out transfer, with the
within-group score computed beside it so the gap is readable. A
cross-group number alone is not interpretable: 0.6 might be a collapse
from 0.95 or a rise from 0.5.

Measured across two synthetic environments:

| Held out | Model | Cross-group | Within-group | Gap |
|---|---|---|---|---|
| env_a | `lstm_forecaster` | 0.716 | 0.841 | 0.126 |
| env_b | `temporal_window_stack` | **0.494** | 0.688 | 0.194 |

Mean transfer gap **0.16 PR-AUC**. On env_b performance falls to barely
above its own positive rate.

The report sets `independent_environments: false` and warns explicitly:
both groups come from the same generator, so this measures the
generator's consistency, not the model's generality. A real claim needs
environments collected separately.

### Model comparison, with intervals

| Model | Precision | Recall | PR-AUC | 95% CI |
|---|---|---|---|---|
| `baseline_constant` | 0.000 | 0.000 | 0.577 | — |
| `baseline_threshold` | 0.757 | 0.933 | 0.701 | — |
| `logistic_regression` | 0.909 | 0.667 | 0.836 | — |
| `random_forest_forecaster` | 0.808 | 0.700 | 0.865 | [0.750, 0.950] |
| `temporal_window_stack` | 0.917 | 0.733 | **0.886** | [0.776, 0.965] |
| `lstm_forecaster` | 0.647 | 0.733 | 0.751 | [0.596, 0.891] |

170 instances · 109 train / 52 test · 9 purged · 30 test positives.

**The intervals overlap heavily.** On ~50 held-out instances this
evaluation cannot distinguish the top three models, and no claim that one
beats another is supported.

### Container configuration

**A real disclosure defect.** There was no `.dockerignore`, so every
`docker build` with `context: .` would send the **entire repository** to
the Docker daemon — including `prahari.db`, two megabytes of genuine local
network telemetry, plus `.git` and anything under `secrets/`. The `COPY`
instructions are narrow so none of it reaches the image, but a build
context is transferred in full, is recoverable from the daemon, and is
routinely captured in CI logs. "Not in the image" is not "not sent".

Docker is not installed here, so the configuration is validated
**statically**: 18 tests assert the ignore coverage, that the Dockerfile's
`/frontend/dist` target matches the path `main.py` actually resolves, that
the database URL has four slashes (three would put telemetry in the
container's ephemeral layer), that the runtime user owns `/data`, that the
published port is loopback-only, and that no credential material is baked
into a layer.

**This is not a runtime check.** The image has never been built here.

### Dashboard: a fabricated "best model" badge

The forecasting table marked `random_forest_forecaster` as best with a
hardcoded string comparison, whatever the evaluation returned. With six
models it frequently sat on the second-best. `bestModelId()` now derives
it from the measured PR-AUC, excludes baselines, and returns nothing
rather than falling back to a default.

---

## Session 11 — Closing the Rehearsal Findings

**554 backend (Windows) · 552 passed / 2 skipped (Linux) · 46 frontend.**

The synthetic rehearsal left two issues open. Both were results that were
arithmetically correct and misleading to read; neither is fixed by changing
a metric.

### Window truncation is now structured state

`WindowingReport` gains `windows_limit`, `windows_eligible`,
`windows_considered`, `windows_omitted` and `windows_truncated`.
`windows_eligible` is computed from the same bound the loop uses, so it is
derived rather than estimated.

| | Complete run | Truncated run |
|---|---|---|
| `windows_eligible` | 389 | 143,751 |
| `windows_considered` | 389 | 20,000 |
| `windows_generated` | 389 | 332 |
| `windows_omitted` | 0 | **123,751** |
| `windows_truncated` | `false` | **`true`** |

The three counts are genuinely distinct: in the truncated run only 332
instances were emitted from 20,000 examined windows, because the rest
failed the negative-label validity rules rather than the cap.

`require_complete_windowing=True` raises `WindowCoverageIncomplete` with
the partial report attached. Kept deliberately separate from
`SelectionCoverage.truncated`, which reports a **record**-count cap.

### Degeneracy is reported apart from computability and adequacy

`metrics_interpretable` asked one question and was read as answering three.
A constant predictor scored precision = base rate, recall = 1.0, and was
flagged interpretable.

| Field | Degenerate model | Discriminating model |
|---|---|---|
| `precision` / `recall` | 0.300 / 1.000 | 1.000 / 1.000 |
| `pr_auc` vs `no_skill_pr_auc` | 0.300 vs **0.300** | 1.000 vs 0.300 |
| `predicted_negative_count` | **0** | 28 |
| `distinct_score_count` | **1** | 40 |
| `predictions_degenerate` | **true** | false |
| `discrimination_demonstrated` | **false** | true |

Metrics are preserved, never blanked — a degenerate model's precision is a
real number about a real prediction. `no_skill_pr_auc` is the positive base
rate, the principled reference for PR-AUC rather than an arbitrary cutoff.
`discrimination_demonstrated=True` means "better than chance on this
sample", not "a useful model".

The dashboard shows `Degenerate`, `No skill` and `Inconclusive` badges, and
`bestModelId()` refuses to crown a model that demonstrated nothing.

### Rehearsal count correction

The previous report's headline, "45 of 46 checks passed", was wrong in both
numbers. The scripts printed `{'PASS': 37}` (phases 3–5) and
`{'PASS': 7, 'NOT VERIFIED': 1}` (phase 6). The correct total is
**44 of 45 passed, 1 NOT VERIFIED** — and that one NOT VERIFIED is the
window-truncation gap closed above.

---

## Session 12 — Time-Indexed Window Extraction

**569 backend (Windows) · 567 passed / 2 skipped (Linux) · 46 frontend.**

`build_dataset_instances` re-scanned every event twice per window. Replaced
with binary-search interval boundaries and label prefix sums. Pure
performance work: semantics are unchanged and were proved unchanged before
adoption.

### Measured (best of 3, synthetic fixtures)

| events | windows | reference | optimized | speedup |
|---|---|---|---|---|
| 500 | 989 | 37 ms | 4 ms | 8.9x |
| 1,000 | 1,989 | 133 ms | 9 ms | 14.8x |
| 2,000 | 3,989 | 499 ms | 17 ms | 30.3x |
| 4,000 | 7,989 | 2,157 ms | 37 ms | 57.7x |
| 8,000 | 15,989 | 10,541 ms | 75 ms | **140.8x** |

Growth from 500 to 2,000 events: **13.5x before, 4.0x after** — now
tracking the event count rather than compounding with window count.

Rejection-heavy corpus (20,000 windows examined, 332 emitted): 743 ms to
31 ms, 24x. That path gained most because the old code materialised both
intervals before discovering the horizon was empty.

Peak traced memory 4.68 to 4.96 MiB at 4,000 events — two integer prefix
arrays of length n+1.

### Equivalence evidence

A snapshot of the pre-edit module was imported alongside the new one and
both run in a single process against identical inputs: **88 fixture-by-
configuration pairs** across 11 fixtures (dense, sparse, multi-host,
boundary-aligned, missing labels, single-class, empty, one-event,
duplicate timestamps, implausible timestamps, rescaled) and 8
configurations. Features, labels, observation masks, timestamps, all 27
report counters and every note matched exactly. Separately verified below,
exactly at, and over the window cap, and that `require_complete_windowing`
still refuses with the partial report attached.

15 permanent regression tests cover the properties that could have broken:
half-open boundaries, tie ordering, prefix-sum label agreement with a
direct scan, counter ordering, and determinism under shuffled input.

### Deliberately unchanged

- Observation features are still computed exactly per window. Distinct
  IP/port counts cannot be maintained incrementally across a sliding
  window without a multiset, and with stride ≠ window size the windows do
  not nest. Correctness kept, cost accepted.
- `MAX_WINDOWS` unchanged — raising it would hide the limit, not fix it.
- `windows_with_attack_in_observation` still counts windows later rejected.

### Noted, not changed

With no generated windows the function returns shape `(0,)` while the
early-return paths return `(0, n_features)`. Pre-existing, harmless (the
pipeline refuses fewer than four instances before any model sees it), and
out of scope for a performance change. Recorded in the test rather than
quietly fixed.

---

## Session 13 — Research Readiness Audit

**649 passed / 6 skipped (Windows) · 647 passed / 8 skipped (Linux) · 46 frontend.**

Two correctness fixes, a permanent equivalence harness, and a capability
audit. No architecture changed.

### Empty-dataset shape (ADR-042)

`build_dataset_instances` returned `(0, n_features)` from its early exits
and `(0,)` when the loop ran but emitted nothing. `stack_lagged_windows`
reads `X.shape[1]` — an IndexError on the first form, unreachable only
because the pipeline refuses fewer than four instances first. All three
paths now return `(0, len(FEATURE_NAMES))` float32 via one helper.

### Coverage counters that could not add up (ADR-042)

Writing the regression test exposed a second defect: on a 400-event
unlabelled corpus the report showed **124 windows considered and 130
excluded**. The event-count fallback incremented rejection counters without
incrementing `windows_considered`, while `windows_generated` already
included fallback output. Both the identity
`considered == generated + rejected` and the ordering
`eligible >= considered >= generated` now hold on every path, with
`fallback_chunks_considered` / `fallback_chunks_excluded` keeping the two
populations distinguishable.

### `duplicate_rows_exact` was dead (ADR-043)

Identity is `sha256(file_sha | row_index | content)`, so two rows in one
file can never collide — the counter was permanently zero. It now counts
rows whose **raw text repeats**, a documented CICFlowMeter artefact.
`near_duplicate_flows` keeps the looser canonical-field meaning. Neither
filters: both rows are stored.

### Permanent equivalence harness

`tests/unit/test_window_equivalence.py` compares the index-based extractor
against a **naive linear-scan reference written inline in the test tree** —
not a copy of the production algorithm, and not a git snapshot. 8 fixtures
x 8 configurations; **63 passed, 6 skipped** (the skips take the rescaling
or fallback path, which the reference deliberately does not reimplement,
and are reported rather than hidden).

The earlier 88-pair snapshot comparison was re-run after these changes:
**exactly 14 differences, all intended** — 8 shape changes on the
`one_event` fixture, 6 fallback-counter changes on three fixtures. The
other 74 pairs are byte-identical.

### Capability audit

[docs/MULTI_SYSTEM_CAPABILITY.md](docs/MULTI_SYSTEM_CAPABILITY.md) traces
multi-system monitoring through code, tests and configuration. The
blocking findings: the collector is a **process-global singleton**
(`collector.py:558`), so one backend process collects for one source;
there is **no cross-source correlation** anywhere; **no Linux collector**;
and **no backpressure or rate limiting**. No live network sensor has ever
produced data into PraHari.

---

## Session 14 — Closeout Verification

**729 passed, 0 skipped (Windows) · 727 passed / 2 skipped (Linux) · 46 frontend.**

Verifying the previous session's changes found two further defects, both
inside the region the equivalence harness had been skipping.

### The skips were hiding the defects

The harness skipped any combination that took the rescaling or fallback
path — 6 of 64. Investigating them:

- **4 were rescaling-only** and perfectly testable; the skip was
  over-broad. Removing it exposed an off-by-one.
- **2 were fallback**, which the reference did not implement. Mirroring it
  exposed an inverted control.

The harness now runs **143 tests with zero skips**.

### Reported configuration did not describe the run (ADR-044)

`WindowingReport` stored effective W/L/H/S rounded to three decimals while
the loop used the unrounded floats. On a rescaled fixture, re-deriving the
window count from the report gave 40 where the run produced 39. Small
number, but it violates the project's central claim — that an evaluation
is reproducible from its recorded parameters. Rounding now happens once,
before the loop.

### An ongoing-attack control that produced its own opposite (ADR-045)

`exclude_ongoing_attack_windows=True` drops windows whose observation
period already contains an attack. On a dense-attack dataset it drops
*every* candidate, which empties the window list and triggers the
event-count fallback — which did not check the flag.

| run | rows | fallback | instances with attack in observation |
|---|---|---|---|
| `exclude=False` | 10 | no | 10 |
| `exclude=True` | 7 | **yes** | **7 — all of them** |

The caller asked for clean pre-attack instances and received a dataset
where every instance had an attack underway, while
`windows_excluded_ongoing_attack` reported the control as having worked.
Worse than the flag doing nothing, because the report corroborated the
wrong answer.

After the fix the same fixture yields **0 rows** with the mask summing to
zero — the honest answer for a dataset with no clean pre-attack window.

### Counter invariants now hold universally

Across all 64 fixture-by-configuration combinations, including rescaling
and fallback paths:

```
eligible >= considered >= generated
omitted  == eligible - considered
considered == generated + rejected
```

No exception is required. Asserted permanently in
`test_coverage_invariants_hold_on_every_path`.

### Snapshot comparison

17 differences across 88 pairs against the pre-change snapshot, **all
intended**: 13 empty-shape changes, 2 window counts from the rounding fix,
4 `windows_eligible` from the rounding fix, 3 emptied datasets from the
exclusion fix.

### Next phase

[docs/NEXT_PHASE_MULTI_SOURCE.md](docs/NEXT_PHASE_MULTI_SOURCE.md) — an
evidence-backed starting specification, not implemented. Top priority is
**clock-skew estimation**, because every window, split and purge depends
on timeline order and nothing currently detects a wrong clock.

---

## Session 15 — Clock Integrity and Source Health

**761 passed (Windows) · 759 passed / 2 skipped (Linux) · 46 frontend.**

### The plan's first priority could not be delivered as specified

Inspecting the schema before designing changed the answer. **PraHari has no
reference clock**, so clock skew cannot be measured. Two timestamps exist —
`observed_at` (source event time) and `ingested_at` (set at object
construction in the backend) — and no monotonic clock, sequence number or
round-trip measurement exists anywhere.

Their difference is the **ingest lag**: clock offset plus collection,
transport, queueing and processing delay, inseparably. Reporting it as skew
would attribute all of it to one cause the data cannot isolate.

`GET /sources/clock-integrity` therefore reports ingest lag, named as such.
One rigorous inference is drawn: delay cannot be negative, so a negative
lag of δ proves the source clock leads this host's by **at least** δ — a
bound, not an estimate. A positive lag supports no skew claim however
large, and the response states that.

Live-verified on a temporary database: a source with a −90s lag reports
`source_clock_ahead` with `bound=90.0`; a normal source reports
`no_anomaly_detected` with `bound=None`.

### Source health, and why it is the same problem

`GET /sources/health` classifies each source. The finding that shaped it:
`last_event_at` is max(`observed_at`) — **event time**. A source whose
clock runs fast looks fresher than it is and can appear healthy while
silent; a slow clock reads as stale while reporting normally.

`SILENT` never means disconnected, `NEVER_SEEN` is distinct from it, a
recorded error outranks apparent freshness, and a future `last_event_at`
yields `UNKNOWN`. No heartbeat was fabricated.

### A defect found by driving the endpoint, not by a test

The ordering check walked the supplied event order, but
`Database.list_events` returns `ORDER BY observed_at DESC` — so every
well-behaved source was reported as a continuous backward march. Ordering
is now assessed by arrival (`ingested_at`), with bulk-insert ties excluded.
Two regression tests pin it, one explicitly feeding the list in reverse.

### Not implemented, deliberately

Collector registry, enrollment, Linux adapter. The architecture question —
central supervision versus per-endpoint agents — is still unresolved and
gates the registry.

---

## Session 16 — Server-Receipt Timestamps

**782 passed (Windows) · 780 passed / 2 skipped (Linux) · 46 frontend.**
Typecheck and production build clean. Both operational databases byte-for-byte
unchanged (hashes recorded below).

### The Phase 1 blocker, closed

Phase 1 ended with one outstanding requirement: a receiver-side timestamp on
the ingest path, without which a consistently offset clock is undetectable.
`received_at` now provides it — but only where a receipt genuinely exists.

Tracing every caller of `insert_events` found six paths and two situations:

| Path | Receipt recorded |
|---|---|
| `POST /stream/ingest/ndjson` | **yes** — stamped at the API boundary |
| `POST /applayer/ingest` | **yes** — same |
| Windows collector poll, UDP endpoint poll | no — the backend produced the event |
| CSV import, research import | no — the *file* arrived now, the events did not |
| Synthetic replay | no — generated |

`NULL` means "not measured" and is never backfilled. The capture happens
**before** parsing, so a large batch cannot push the recorded arrival later
than the real one, and every event in one submission shares one receipt.

The client cannot supply it: no request model carries the field, and
`test_the_client_cannot_supply_or_influence_the_receipt` submits one in the
body and asserts it is discarded.

### What the diagnostics do with it

`GET /sources/clock-integrity` now reports which reference each lag was
measured against (`received_at` / `ingested_at` / `mixed` / `none`). The
lower bound and the `SOURCE_CLOCK_AHEAD` verdict are asserted **only** on a
measured receipt — an `ingested_at` lag no longer supports either.

`GET /sources/health` prefers a measured receipt over event time, and reports
`clock_dependent: false` when it does. The Phase 1 failure is pinned by
`test_health_prefers_a_measured_receipt_over_a_skewed_event_time`: a source
claiming an event five seconds ago, last actually heard from three days ago,
now reports `SILENT` rather than `REPORTING`.

### A finding recorded rather than fixed

`/stream/ingest/ndjson` is **not idempotent**. The adapter assigns
`uuid.uuid4()` per row (`adapters/json_stream.py:319`), so a sensor retrying
after a timeout double-counts its own telemetry. The research importer and
the Windows collector derive deterministic ids and are idempotent; this path
is the exception.

A retry test was originally written assuming idempotency and failed. The
behaviour was not quietly adjusted to match the test: the test was rewritten
to assert what the code actually does, and
`test_the_stream_path_is_not_idempotent_on_retry` now pins the defect with
its consequence stated. Changing event identity on a live ingestion route is
the recommended next phase.

### Migration

A nullable additive column via the existing `_ADDED_COLUMNS` mechanism.
Tested on a temporary database whose legacy schema is derived from the real
`TABLES_DDL` with the `received_at` lines removed — an earlier hand-written
minimal fixture passed while omitting the indexes, which hid the real
`ALTER TABLE` path. Neither project database was opened for writing;
`prahari.db` (2,129,920 bytes, sha256 `51d80b91…c69fa`) and
`backend/prahari.db` (184,320 bytes, sha256 `1c9c71f1…a3b6275`) are identical
to their pre-session hashes.

### What this does not establish

A measured receipt proves this backend received data at time T. It does not
prove the endpoint is connected, running or healthy, and it does not yield
exact clock skew — the common failure, a steadily offset clock producing a
steadily offset *positive* lag, is still undetectable. No heartbeat exists,
so a silent source remains indistinguishable from a healthy one with nothing
to report. Receipts exist only for events arriving after this change.

---

## Session 17 — Stream Event Identity, and an Audit of It

**815 passed (Windows) · 46 frontend.** Typecheck and production build clean.
Both operational databases byte-for-byte unchanged.

Phase 3 delivered the identity protocol; this session audited it against the
code rather than against its own report, and three things did not hold.

### Defect 1 — the conflict check ignored most of the event

`insert_events` compared `source_id`, `observed_at` and the five-tuple, and
nothing else. Measured directly against a temporary database before any fix:

| Mutation under a re-used `event_id` | Result |
|---|---|
| `bytes_total` 100 → 999999 | HTTP 200, `accepted_records=1`, stored row unchanged |
| `packets` 2 → 50000 | HTTP 200, `accepted_records=1`, stored row unchanged |
| `duration` 1.5 → 987.0 | HTTP 200, `accepted_records=1`, stored row unchanged |
| `event_type` flow → alert | HTTP 200, `accepted_records=1`, stored row unchanged |
| `label` none → "DDoS" | HTTP 200, `accepted_records=1`, stored row unchanged |

So the two things a forecaster actually consumes — the measurements and the
training target — could be replaced under an existing identity and the API
would report success while discarding them.

`CONFLICT_FIELDS` now compares all twenty fields that assert something about
the observation, and `CONFLICT_FIELDS_EXCLUDED` names the six that are not
compared with a reason for each. The same five mutations now return **409**
naming the differing field. Seven parametrized regression tests pin them.

### Defect 2 — the response could not distinguish stored from parsed

`insert_events` returns the number of rows written; the endpoint discarded
it. A complete retry reported `accepted_records=N` exactly as a first
delivery did. `ImportSummary` now also carries `stored_records` and
`duplicate_records` — optional, `None` on paths that do not report storage,
and not persisted, so no migration.

### Defect 3 — a 409 left no trace

The conflict path raised before any audit write, so a refused batch was
indistinguishable from a request that never arrived. It now logs
`ingest_ndjson_stream_conflict` before raising.

### Verified, not assumed

- **Batch rollback**: `get_connection` rolls back on any exception, so a
  conflict anywhere in a batch discards the whole batch. One good record
  plus one conflicting record stores nothing.
- **Batch-key boundaries**: the key binds `(key, index)`, not the batch.
  Reordering conflicts; a *shorter* retry is accepted and the missing tail
  is **not** detected. Both are tested and documented rather than claimed
  away — see ADR-050.
- **Legacy senders still double-count.** `test_the_stream_path_is_not_
  idempotent_on_retry` still passes, and its docstring was corrected: it had
  described the defect as unfixed generally, when Phase 3 fixed it for
  senders that supply identity and deliberately left it for those that do
  not. Closing it for them would require content equality, which would
  collapse genuinely distinct events.

### Not claimed

Not exactly-once delivery. A sender that invents a fresh identifier for an
event it already sent is undetectable, and nothing here makes a legacy
sensor retry-safe.

---

## Session 18 — The Ingestion Trust Boundary

**844 passed (Windows) · 46 frontend.** Typecheck and production build clean.
Both operational databases byte-for-byte unchanged.

### The gap

Central mode had credentials, hashing, roles, constant-time comparison and
default-deny middleware. None of it reached ingestion. One grep:

```
grep -rn "scope_source|require_principal|require_admin" app/api/v1/
  app/api/v1/events.py  ->  scope_source
```

One read path. Every write path trusted the request body's `source_id`.
`Principal.may_write()` and `require_admin` were both defined and called
nowhere.

Measured with enforcement removed under a monkeypatch: a credential for
`sensor-a` posting `{"source_id": "sensor-b"}` returns **HTTP 200** and one
event appears under `sensor-b`. Because ADR-050 scopes event identity by
source, the claimed id also selected another source's **idempotency
namespace**.

### Closed

`resolve_ingest_source` is now the single ingestion boundary, called before
parsing on all six write paths. Everything downstream — adapter id,
idempotency namespace, `event.source_id`, source registration, audit — comes
from its return value. Impersonation is refused with 403, not rewritten;
`read_only` cannot write; an admin must name the source it acts for; local
mode is unchanged.

### A second bypass, found by a bad test

The first admin test asked for `/audit/events`, which 404s, and passed
without reaching any authorization check. Pointed at the real `/audit/logs`,
an **ingest credential read the audit log** — contradicting `security.py`'s
own stated guarantee. Both audit routes now depend on
`require_admin_in_central`.

Two other tests in the new file were also passing vacuously (a 422 from a
malformed app-layer payload that never reached the boundary). Both were
rebuilt to reach the code under test.

### Not built, deliberately

No HTTP enrollment route: `CredentialStore` is never written at runtime, and
a minting endpoint would let a stolen admin token issue ingest credentials
remotely. Enrollment stays in the existing offline CLI. No schema change, no
migration, no credential fabricated for any existing source or event.

### Not claimed

Not cryptographic source authenticity — these are bearer tokens, and central
mode must sit behind HTTPS. No expiry or rotation exists; revocation means
editing the credential file and restarting. A stolen sensor credential still
writes freely as that sensor. `source_id` on a stored row means "filed
under", never "proved to originate from".

---

## Session 19 — Blueprint Audit, Enforced Limits, Linux Host Telemetry

**889 passed / 4 skipped (Windows) · 46 frontend.** Typecheck and build clean.

Audited all 19 blueprint sections against code rather than against earlier
reports. Full result in [REQUIREMENTS_MATRIX.md](docs/REQUIREMENTS_MATRIX.md).
Three things were worth implementing; the rest is either done, blocked by the
standing safety boundary, or recorded as not attempted.

### A database I should not have touched

While probing a URL-routing question I ran an ad-hoc script that imported
`app.main.app` **without overriding `get_db`**. Its lifespan opened the
operational `prahari.db` at the repository root and applied the pending
additive migration.

`prahari.db` sha256 changed `51d80b91…c69fa` → `bb0e74d5…aacf90`. Inspected
read-only afterwards: the change is exactly the ADR-048 `received_at` column
(26 columns now), **all values NULL**, 3,669 event rows intact, all 7 tables
present with their counts. No row was modified, no data lost, nothing
fabricated. `backend/prahari.db` is untouched.

Not reverted: undoing an `ALTER TABLE ADD COLUMN` in SQLite requires
rebuilding the table, which is far riskier than the additive column it would
remove. Reported rather than quietly restored.

### Two controls that were configuration, not behaviour

`max_request_size_mb` had existed since the first schema, was published by
`/audit/config` as a security boundary, and **was read by nothing** — a body
of any size was buffered before a validator ran. Rate limiting did not exist
at all, though §4.2 lists "rate" among what central ingestion must validate.

This is the third instance of one defect class: ADR-051 found `may_write`
and `require_admin` defined and never called. A control that exists as a
value while a diagnostic reports it as enforced.

`app/api/limits.py` adds both, failing closed at the boundary, ordered
`CORS → size limit → auth → rate limit → route` so an oversized body costs
no PBKDF2 and the limiter can still key on the credential. `/audit/config`
now reports *enforcement* separately from the configured numbers. See
ADR-052, including the limits: per-process counter, 2x burst at a window
boundary, and unauthenticated floods still reaching the credential check.

### Linux host telemetry

The blueprint names Windows and Linux as initial targets; only Windows had a
host adapter. The service turned out to be platform-neutral already — the
only Windows-specific parts were the default query function and one
`sys.platform` gate — so this was an adapter gap, not a rewrite.

`linux_telemetry.py` reads `/proc/net/tcp` and `/proc/net/tcp6` directly and
emits the **same raw record shape**, so the collector, normalization and the
deterministic event id are the same code on both platforms. Verified by
driving a Linux-produced record through `WindowsConnectionAdapter` and
asserting a stable identity across two polls.

**Not claimed**: it has not been run against a live Linux host this session.
The four tests that need one, or need POSIX symlinks, are skipped on Windows
and report as skipped rather than vanishing from the count.

### Still the honest headline

The engineering contract is largely met. The scientific one is not: no
labelled corpus can be acquired under the standing constraints, so no metric
in this repository is evidence of predictive performance on real traffic.

---

## Session 20 — Database Integrity, Credential Lifecycle, Limit Enforcement

**926 passed / 4 skipped (Windows) · 46 frontend.** Typecheck and build clean.

### Database incident: investigated, not reversed

Read-only forensics on the `prahari.db` change reported in Session 19.
`backend/prahari.db` turned out to be a decisive control — same codebase,
never started from the repository root, 7 tables, 9 indexes, and **exactly
one fewer column** (25 vs 26).

| Check | `prahari.db` | control |
|---|---|---|
| integrity_check / foreign_key_check | ok / 0 | ok / 0 |
| tables / indexes | 7 / 9 | 7 / 9 |
| `normalized_events` columns | 26 | 25 |
| `received_at` | present, **all NULL** | absent |
| event rows | 3,669 | 187 |
| newest `ingested_at` | 2026-10-12 | 2026-10-11 |

The newest event predates the 16 October incident by four days, so **no
rows were written**. **No backup exists** anywhere in the repository, so
restoration was never available. Not reversed: undoing
`ALTER TABLE ADD COLUMN` means rebuilding a 3,669-row table with no backup
to remove an empty nullable column the code already expects. See ADR-054.

Root cause was **not** the test suite — `conftest.py` has always redirected
`PRAHARI_DATABASE_URL` to a temp directory, and all 926 tests pass with the
new guard, which proves every one was already isolated. The hole was an
ad-hoc, non-pytest process: `database_url` is relative, so the working
directory silently decides which real database gets opened.

`app/storage/guard.py` now refuses, under pytest, to initialize any
database outside a temporary directory, and a migration against a
populated table logs at WARNING rather than INFO. 13 tests, including one
that drives the exact incident shape and asserts it is refused.

### Credential lifecycle

`enabled` was the only control, and a running process honoured a change to
it only after a restart. Added `not_after` expiry (None means "never", so
existing stores are unaffected; an unparseable value counts as expired),
rotation that **preserves `source_id`** so a rotated secret stays in the
same idempotency namespace, and revocation that takes effect on the next
request because the store re-reads its file when it changes.

A corrupt or emptied credential file is refused rather than applied — an
operator who breaks the file must not lock out the fleet. Unknown,
disabled, revoked and expired share one message, pinned by a test
asserting the set of four wordings has one element. 24 tests. ADR-055.

### A third unenforced config value

The regression sweep for "declared but not wired" found
`max_import_records`: the request model carried its own hard-coded ceiling,
so lowering the operator's policy did nothing. The effective limit is now
the lower of the two. This is the same class as `max_request_size_mb`
(Session 19) and `may_write` / `require_admin` (ADR-051) — the fourth
instance, and worth watching for as a pattern rather than a coincidence.

Also swept and found clean: no ingestion route lacks the identity boundary
(`hostobs` uses a server-side constant, not client input), and every auth
helper except `may_access_source` is called at an enforcement point.
`may_access_source` is a predicate superseded by `assert_source_access`.

### Unchanged

The scientific position. No labelled corpus can be acquired under the
standing constraints, so no metric here is evidence of predictive
performance on real traffic.

---

## Session 21 — Admission Control, System Health, NetFlow

**981 passed / 4 skipped (backend) · 54 passed (frontend).** Typecheck and
production build clean. Both protected databases unchanged.

Closed three of the five items that had stood at FAIL.

### Bounded ingestion (§4.2, §6) — admission control, not a queue

Ingestion is synchronous end to end, and the response reports what was
*stored*. A queue would answer the caller before the data is durable and
break `stored_records`, the 409 conflict and atomic rollback at once.

`AdmissionController` caps concurrent in-flight ingestion instead,
reserving a slot **before parsing** and refusing with 503 + `Retry-After`
when saturated. Released by a context manager, so a 409 cannot leak
capacity — pinned by a test.

`queue_depth` is reported as **null with a note**, never 0: zero would
assert an empty queue, null says there is none. 24 tests.

### System Health view (§11) — `GET /system/health` plus the React page

One response carrying ingestion counters and latency percentiles, source
freshness with its basis, storage integrity and migration state, model
availability, adapter health, and every limit **with its enforcement
state**. The page renders unmeasured values as "not measured", and drops
the previous reading when a refresh fails rather than leaving a stale
number under a fresh timestamp. 8 frontend tests.

### NetFlow / IPFIX adapter (§5)

Parses exported flow text — nfdump, SiLK rwcut, YAF, collector CSV — into
canonical events, with deterministic identity so re-importing overlapping
files does not duplicate. It does **not** open a collector port or speak
the binary protocol, and says so: it ingests what an authorized collector
exported, and is not itself a collector. 30 tests.

Three semantics handled explicitly because they are routinely got wrong:
directional counters are summed only when both directions are present and
flagged otherwise; `observed_at` is the flow START, not its end; an
unparseable timestamp returns None rather than `now`.

### Caught by existing tests, not by me

`test_frontend_api_contract.py` failed on the two new TypeScript
interfaces, exactly as designed — it refuses any interface that is neither
paired with a backend schema nor declared view-model-only. Both are now
paired, so the System Health contract cannot drift silently.

One System Health test also failed only in the full suite: it asserted an
empty model registry, which is a process-wide singleton another test had
populated. The assertion was wrong, not the code — it now checks the
invariant that actually matters, that `inference_available` tracks
`model_count`.

### Still open

Sensor forwarding agent and source/retention administration UI remain
FAIL. Real-data evaluation, live sensor integration and Linux execution
remain BLOCKED on authorization or an environment, not on code.

---

## Session 22 — Sensor Agent, Source and Retention Administration

**1070 backend passed / 4 skipped · 67 frontend passed.** Typecheck and
production build clean. Both protected databases unchanged.

The two items that had stood at FAIL are closed.

### Sensor forwarding agent (§4.2, §13)

`app/agents/sensor_agent.py` — bounded in-memory buffer, finite timeouts,
bounded exponential backoff with jitter, `Retry-After` honoured, and a
hard distinction between transient failures (retried) and permanent ones
(400/401/403/409/413 — dropped with a counted reason, because resending
the same bytes is a loop).

It reuses the existing contracts: the real ingestion endpoint, the bearer
credential model, and deterministic event identity plus a batch
idempotency key derived from the event ids so a resend presents the same
key. The transport is stdlib `urllib` — an agent is the component most
likely to run where nothing is installed — and is injectable so no test
opens a socket.

**52 tests**, including five end to end against a genuine in-process
PraHari on a temporary database. The resend case is the one that matters:
four events sent twice return `stored=0, duplicates=4` and the row count
stays at four.

Stated rather than implied: **at-least-once delivery with server-side
deduplication, not exactly-once**, and unacknowledged events are lost if
the process is killed. `health()` carries both sentences.

### Source and retention administration (§11)

Two operations that did not exist:

* `PATCH /sources/{id}/enabled` — admin-gated, audited, 404 on unknown.
  Writes only the `enabled` column, so counters and last-event time
  survive the toggle.
* `PUT /retention/policy` — admin-gated, audited, validated server side.

Retention was read-only from `AppConfig`. Rather than a second policy
store, a `system_settings` table holds an **override** of that default,
and every response reports `retention_days`, `origin` and
`configured_default` together so nobody has to guess which won. An
unreadable or out-of-range stored override falls back to the default, not
to zero — guessing could shorten retention, the direction that destroys
data.

**The rule the feature rests on: changing the policy deletes nothing.**
Pruning still needs the separate confirmed enforcement call. Asserted by a
test that sets retention to one day and checks the row count is unchanged.

`AdministrationPage.tsx` is wired to those endpoints, not a mockup. Every
mutation re-reads from the server rather than patching optimistically, so
the UI cannot report a success the backend never gave — pinned by a test
that rejects the call and asserts no success notice appears. 13 frontend
tests.

### Caught by an existing test again

`test_frontend_api_contract.py` rejected all three new TypeScript
interfaces until they were paired with their backend schemas. That is the
second session running in which it has caught drift before a human would
have, and it compares fields, not just names.

### Unchanged

The scientific position. No labelled corpus, so no metric here is evidence
of predictive performance on real traffic.

---

## Session 23 — Timestamp Investigation and Verification Audit

**1088 backend passed / 4 skipped · 67 frontend passed.** Typecheck and
build clean. No code defect was found; one evidence gap was closed.

### The 65 implausible timestamps: diagnosed, not a live defect

All 65 are `1601-01-01T00:00:00Z` — the Windows FILETIME epoch — from
`windows_local_host`, every one a `TimeWait` socket with `pid=0`.

The adapter guard that rejects this **already exists and works**. Proof
from the operational database, read-only: the 65 were ingested in a single
26-minute window on 2026-10-11, carry only `missing_field` (the current
code adds `invalid_value` + `timestamp_uncertainty`), 1,612 later rows
carry those flags, and of 3,263 Windows events ingested afterwards, zero
have a 1601 timestamp.

So they are **pre-fix residue in the protected database**, left untouched.
The feasibility gate's refusal is correct and stays. See ADR-060.

### What was actually missing

Coverage. The unit tests stopped at `validate_and_normalize` and the
research-gate test injected 1601 straight onto an event object — neither
proved a sentinel cannot survive persistence and serialization.
`test_timestamp_integrity_roundtrip.py` adds 18 tests across the whole
path, five sentinel shapes, and the gate's behaviour with and without bad
records.

### Verified by existing evidence, not re-asserted

| Area | Evidence |
|---|---|
| Live Windows telemetry | 49 passed — dedup across polls, port reuse, failure surfaced, gaps recorded, restart safety, unavailable metrics null not invented, no app-layer fields fabricated, four-way accounting balances |
| Provenance and the research gate | 58 passed |
| Security and authorization | 129 passed — central auth, identity boundary, credential lifecycle, administration, limits |

### Unchanged

No labelled corpus, so forecasting remains correctly gated and no metric
here is evidence of predictive performance.

---

## Session 24 — Dashboard Trace, Persistence Defect, Live Verification

**1102 backend passed / 4 skipped · 67 frontend passed.** Typecheck, build
and `git diff --check` clean.

### Counts reconcile exactly

Traced UI metrics to API to database:

| Source | Value |
|---|---|
| Database (read-only) | 5674 = 3774 live + 1900 synthetic |
| `/health` | 5674 |
| `/events` total | 5674 |
| `/events?data_category=live_telemetry` | 3774 |
| `/events?data_category=synthetic_demo` | 1900 |
| `/analysis/latest` | 5674 |
| `/research/audit` | 5674, 65 implausible |

The walkthrough's apparent mismatch (3,582 + 1,900 vs 5,479) was two
snapshots taken while the collector was running, not a defect.
`events_by_label` also reconciles: 3774 unlabeled + 1900 synthetic labels.

### Defect found and fixed

A stored analysis reported `avg_bytes 11474.63` beside
`bytes_measured_count 0`, and `implausible_timestamp_events 0` while 65
exist. Four computed fields had no column in `descriptive_analyses` and
were dropped on save, reading back as the default 0. Fixed with additive
columns and a `-1` → `None` sentinel so "not recorded" stays distinct
from "zero". See ADR-061. 14 tests.

### Live verification

Collection was stopped gracefully through the app's own API for the
maintenance window. Source health then correctly reported `silent` — the
honest state, not a stale "reporting".

An earlier bounded run over three polls reconciled exactly:
**327 observed = 12 accepted + 199 duplicates + 116 filtered + 0
rejected**, with accepted equal to persisted, nulls preserved for fields
the Windows table cannot supply, and no attack label invented.

### Not verified

Linux (Windows-only host), live NetFlow collection (the adapter parses
exports only), and any real-data forecasting claim. The research gate
remains closed and correctly so.

---

## Session 25 — GET /analysis/latest No Longer Writes

**1121 backend passed / 4 skipped · 67 frontend passed.** Typecheck, build
and `git diff --check` clean. Both operational databases unchanged.

### The defect

`GET /analysis/latest` called `db.save_analysis()` whenever the stored
analysis was stale. Each recomputation minted a fresh `uuid4`, so
`INSERT OR REPLACE` never replaced — the live database accumulated **30
rows with 30 distinct ids**, six inside one ten-minute window. The GET
path wrote no audit record, so the rows had nothing attributing them.

It was the only GET in the whole API that writes, and it was found when a
`curl` issued during an explicitly read-only investigation caused one.

### The fix

GET now computes a fresh result and returns it **unsaved**; `POST
/analysis/run` remains the only route that persists, keeping its audit
record. Two response-only fields distinguish the cases that one flag
cannot: `persisted` (is this stored?) and `is_current` (do its totals
still describe the database?).

### Evidence

19 tests asserting at the **storage layer** — row counts and an
intercepted `save_analysis` — not HTTP status codes, since a route can
return 200 while writing. Ten consecutive stale GETs leave the table at
its original size.

Teeth verified: with the pre-fix behaviour restored under a monkeypatch,
the same assertions catch it (rows 1 → 2).

### Left alone, deliberately

The 30 stored rows. Deleting them would modify operational data and they
legitimately record what was computed. A retention policy for POST-created
analyses, and request-ID attribution in the audit log, are recommended in
ADR-062 and not implemented here.

---

## Session 26 — Request Attribution and Analysis-History Retention

**1151 backend passed / 4 skipped · 67 frontend passed.** Typecheck, build
and `git diff --check` clean. Both operational databases byte-identical to
the session baseline.

Closes the two items ADR-062 recorded as recommended-but-not-done. They
were the last blueprint requirements implementable in this environment;
everything still open is externally blocked.

### Request correlation ids (ADR-063)

A correlation id per request, echoed in `X-Request-ID` and read by
`log_audit` through a ContextVar — so every existing audit call site
gained attribution with no edit. NULL outside a request, which is the
accurate answer for a collector poll, the CLI or a test.

A client-supplied id is accepted but capped at 64 characters and
character-restricted, and **rejected rather than truncated**: the value is
persisted, so an unbounded or newline-bearing id would be a log-injection
vector. Six hostile shapes are tested, including a null byte and a SQL
fragment. Only the id is stored — no address or user agent, verified by a
test that asserts a planted `User-Agent` does not reach the row.

### Analysis history retention (ADR-064)

Semantics decided and documented: an analysis is a **historical record**,
not a cache — it carries its own totals and provenance, and the events it
summarised may since have been pruned.

So nothing expires it automatically. `POST /analysis/prune` is dry-run by
default, needs the `DELETE_ANALYSIS_HISTORY` token, requires `keep >= 1`,
is admin-gated in central mode, is audited with its request id, and never
touches telemetry. `analysis_history_limit` defaults to 0 (keep
everything) and is only a suggestion — a test asserts a positive value
prunes nothing on its own.

The 30 rows in the operational database are left for the operator. 30
tests.

### Verified this session, not re-asserted

Both database hashes matched the historical reference values at baseline
and are unchanged at the end. The collector was already stopped and was
left stopped; no process was started.

---

## Session 27 — The Fix Is in the Source, Not in the Running Process

A verification check, not new engineering. Asked to confirm completion, I
probed the live deployment instead of re-asserting the previous report,
and found one thing the report had understated.

### Finding: the running instance predates its own fix

The listener on `127.0.0.1:8000` (PID 35192) was started at
**22:59 IST on 16 Oct 2026**, with no `--reload`. The two fixes that
matter were committed **after** it started — `773a2eb` (GET must not
write) at 23:34, `c87b15b` (correlation ids) at 00:06.

So the process in memory is **pre-fix code**. Evidence rather than
inference: the health response carries no `x-request-id` header, which
`RequestIdMiddleware` would add unconditionally. Its absence proves the
middleware is not loaded, and therefore that the ADR-062 fix in the same
working tree is not loaded either.

The consequence is concrete: against **this** process, a dashboard page
load still appends a `descriptive_analyses` row to the protected
database. The defect is fixed in the published source and pinned by 19
tests; it is not fixed in what is currently serving.

For that reason I did not call `GET /analysis/latest` during this check.
Only `/health` was called — twice — and `prahari.db` is byte-identical
afterwards (`58404fc5…5caa`), which also demonstrates that the health
route is genuinely read-only.

### Why a restart is the operator's call, not mine

Restarting on the current source runs the additive migration, and
`prahari.db`'s `audit_events` table has no `request_id` column yet
(verified on a scratchpad copy, never on the file itself). A restart
therefore performs an `ALTER TABLE` on a protected database — the exact
operation the standing instruction withholds without specific
authorization. Stopping the operator's own long-running process is
likewise not mine to do unprompted.

Both facts were reported and left for the operator to decide.

### State at the end of the check

Working tree clean. `origin/main` == local `HEAD` == `c87b15b`. Both
protected databases byte-identical to the session baseline. 30 stored
analyses and the 65 FILETIME rows still untouched. No process started,
stopped, or restarted; the collector remains stopped.

### Resolved — restarted with explicit authorization

The operator authorized the backup-then-restart option, so the finding
above is now closed by action rather than left open.

Sequence, in order, with the check that proved each step:

1. **Backed up first.** `prahari.db` and `backend/prahari.db` copied to
   `db_backups/`. Both copies hash-matched their originals.

   I first recorded here that the existing `*.db` rule already ignored
   them. That was wrong, and worth recording as the near-miss it was: I
   had tested the rule with a probe path ending in `.db`, but a real
   backup is named `prahari.db.prestop-20261017-090400`, which `*.db`
   does not match. `git status` listed both files as untracked, so a
   careless `git add -A` would have published 3.8 MB of genuine host
   telemetry to a public repository. `.gitignore` now ignores
   `db_backups/` by directory name, plus the backup suffixes, rather than
   trusting a suffix pattern to anticipate every naming scheme; both
   files verify as ignored.
2. **Stopped PID 35192**, then confirmed no `-wal` or `-shm` residue and
   that the hash still read `58404fc5…5caa`. A clean shutdown is what
   makes the pre-stop copy authoritative rather than merely recent.
3. **Restarted** through the documented `start_prahari.ps1`. Healthy in
   about two seconds.
4. **Confirmed the new code is loaded** — `x-request-id` is now present,
   and a supplied `X-Request-ID: operator-check-001` came back verbatim.
   The same probe that exposed the stale process now proves the fix.
5. **Proved ADR-062 live.** Five consecutive `GET /analysis/latest`
   requests against the operational database left
   `descriptive_analyses` at **30 rows**. On the previous process those
   five requests would have appended five rows. Until now the fix was
   evidenced only by tests against temporary databases.
6. **Checked integrity.** `PRAGMA integrity_check` = `ok`; 8 tables;
   5,674 normalized events, 2,271 DNS observations, 364 import
   summaries, 38 audit events, 3 sources, 30 analyses. Dashboard,
   `/docs` and `/system/health` all 200.

Authorized schema change, recorded in full: `prahari.db` moved from
`58404fc575db7729ca48d9e1886915655f2766a8bf77da479602e93c05955caa` to
`4f65601a51dc4d096f8471fead2309c890aab009b16a35daf87446b90b00d5f1`. The
file size is unchanged at 3,821,568 bytes, because `ALTER TABLE ADD
COLUMN` rewrites schema pages and no row data. The only difference is the
`audit_events.request_id` column. `backend/prahari.db` is untouched
(`1c9c71f1…a3b6275`) — the server does not use it.

The 65 FILETIME rows and the 30 stored analyses remain untouched. No
collector was started.

### Launcher defect found while verifying, and fixed

`start_prahari.ps1` called `Get-NetTCPConnection -LocalPort $Port` with
no state filter, so it matched a client socket in `TimeWait` as well as a
listener. My own health check left exactly such a socket, and the
preflight then warned that the port was "in use by PID 0" — a conflict
that did not exist, attributed to the kernel. Evidence: with zero
listeners, the unfiltered query returned one `TimeWait` row owned by
process 0.

This is the project's recurring defect class in miniature — a check
reporting a confident value that is not true. Fixed by filtering to
`-State Listen` and resolving the owning process name, so a real
conflict now reads `python (PID 37664)` instead of `PID 0`. The warning
also now says that an existing instance may predate the current source,
since PraHari runs without `--reload`; that is the one thing an operator
most needs to know at exactly that moment.

---

## Session 28 — Final Validation: Out-of-Process HTTPS, Research Integrity, Storage Contract

Baseline verified first, read-only: `HEAD` = `origin/main` = `3ab6d2d`,
tree clean, `prahari.db` `4f65601a…d5f1` (3,821,568 B, the post-migration
value) and `backend/prahari.db` `1c9c71f1…a3b6275` (184,320 B). Its `-wal`
is empty and its `-shm` predates the session, so the main file is its full
content.

### A correction to earlier reports

Earlier sessions said PostgreSQL was blocked only by the lack of a service
and that "repository abstractions already exist". There was no PostgreSQL
code and no abstraction. PostgreSQL is **MISSING**, now with a contract and
conformance suite (ADR-071). The Linux row of `PLATFORM_SUPPORT.md` also
called Linux "Verified — runtime" on the strength of a run against an
earlier revision; it now says so.

### Defects found and fixed

| ADR | Defect | How it was found |
|---|---|---|
| 066 | `verify_tls` read by nothing; no private-CA support | Reading the transport |
| 066 | Certificate failures retried as `connection_error` | Out-of-process HTTPS test |
| 066 | Redirects carried the bearer token to plaintext | Demonstrated with a real 302 to an HTTP listener |
| 066 | One oversized batch wedged the agent forever | Real server closes before reading the body |
| 067 | Every central-mode audit entry attributed to `local_operator` | Writing the HTTPS audit test |
| 068 | A wholly rejected batch reported `stored: null` and never reached health | A test expecting `0` received `None` |
| 068 | A non-object JSON line crashed the batch (500) | A test fixture used `[]` as a bad line |
| 069 | Late live events counted in earlier forecasts' features | Blueprint section 6 against `feature_extractor.py` |
| 070 | Training ignored label provenance; the provenance check always passed | Tracing what `target_definition` and the gate rely on |
| 070 | Manifest lacked git revision, config hash, packages, parameters, limitations | Comparing fields with the brief |

Each fix has regression tests at the layer where the defect lived, and the
availability tests were checked against the defect: reverting the rule
fails three of nine.

### Added, not fixed

- `tests/integration/test_central_https_e2e.py` (28): PraHari as its own
  `uvicorn` process serving HTTPS, test PKI per run, central mode, a
  temporary database. Health with request id; no plaintext; verified
  delivery and deduplication; actor and request id audited; untrusted CA,
  wrong hostname and rogue issuer refused with events kept; redirect hazard
  demonstrated and refused; 401, 403 cross-source and read-only, revocation
  without restart, 413 with server-log evidence, per-credential rate
  limiting, no token in the server log; batch splitting; an outage survived
  and delivered on reconnect. Every server is stopped and its port checked
  closed.
- `research/target.py`, `research/label_policy.py`, manifest 1.1.0.
- `storage/contract.py` and `test_storage_contract.py` (13).
- `docs/ACCEPTANCE_MATRIX.md`; publisher facts for CSE-CIC-IDS2018 and
  CTU-13 read from their pages, nothing downloaded or accepted; the Arch
  verification procedure.

### Decided against

No live NetFlow collector (ADR-072): exercised only by hand-built packets
it would prove nothing about a real exporter, and it is attack surface. No
untested PostgreSQL backend: it would look finished without being so. No
CTU-13 importer: its label strings have not been seen. Ubuntu-WSL was not
booted: the authorization named Arch, and starting a VM was not part of it.

### Results

Backend **1245 passed, 4 skipped, 0 failed** (from 1151); the 4 skips are
Linux-only and are not counted as passes. Frontend 67 passed, `tsc` 0,
build 0. Every command in the acceptance matrix was executed.

Both protected databases unchanged; the operational instance untouched on
`127.0.0.1:8000`; collector stopped; no test server left running.

---

## Session 29 — Linux (Arch) Validation and Closure Audit

Run on Arch Linux (kernel 7.2.9, Python 3.14.8, `backend/.venv-linux`,
Node 26, npm 12) from `a128bfd` with the changes below uncommitted.

### What the first Linux run of the current revision found (ADR-075)
`3 failed, 1243 passed, 3 skipped`. Two stale tests: Linux collection
refused, which ADR-053 had enabled; an agent test assuming the 413 is
never seen. One test the HTTP client defeated: httpx removes `..` before
sending, and the expected SPA shell needs a built frontend. Two collector
defects: a PowerShell DNS refresh attempted on every Linux poll, and
Linux status describing itself as `Get-NetTCPConnection`.

### Agent retry bound (ADR-073)
A clean 413 dropped every event in the batch; the dropped-connection
shape still wedged; `IncompleteRead` escaped with the batch out of the
buffer; a truncated 413 lost its status. Now a 413 splits the batch and
sets a byte ceiling; an all-drops round splits the batch (unconfirmed) and
recovers; a single event that keeps dropping while the next event is
delivered goes to an in-memory dead-letter store. Splitting is
duplicate-safe because identity is the sender's `event_id`, pinned end to
end.

### Test artefacts (ADR-074)
The experiment API tests rewrote `experiments/api-exp-*.json` in the
checkout through a fixture attribute nothing read.
`PRAHARI_EXPERIMENTS_DIR` now selects the directory (default unchanged);
the suite uses a temporary one. Both existing manifests are byte-identical
before and after every run since.

### Closure audit (ADR-076)
Six defects, each reproduced by a failing test first: events lost to a full
buffer undercounted; dead-letter requeue could lose events; a refused
probe livelocked the queue; one 413 capped batches at one event for good;
the DNS enrichment endpoints spawned PowerShell on Linux; the launcher
verification script ran against the operational database with `assert`
checks. Frontend installed from the lockfile and verified; the backend
served its real build.

### Results
Backend **1284 passed, 3 skipped, 0 failed** (two `live_windows`, one
non-Linux branch test). Linux telemetry module 30 passed, 1 skipped.
Frontend `tsc` 0, 67 passed, build succeeded. `verify_live_launcher.py`,
`simulate_browser_producer.py` (throwaway server),
`verify_forecasting_pipeline.py` and `manage_credentials.py` pass.

Not done here: Windows re-run, a sustained Linux collector run, a
real-browser session. No operational database existed on this host; none
was created. The collector was never started; every server was loopback
and stopped with its port checked.

---

## Session 30 — Linux Closure, Second Audit, and the Windows Handoff

Arch Linux (kernel 7.2.9, Python 3.14.8, Node 26.11.1, npm 12.2.1), still
`a128bfd` with every change uncommitted.

### Found and fixed (ADR-077)
- After any restart, every Linux connection still open became an identity
  conflict that failed the poll and lost the poll's new connections; the
  collector now does not re-insert ids storage already holds.
- Fingerprints were marked seen before storage succeeded, so a failed
  write lost that poll's events for good (both platforms).
- Agent: a non-JSON value (a `datetime`) took its whole batch with it;
  records rejected inside a 2xx were invisible; a wrong endpoint (404/405)
  dropped every batch instead of halting.
- `simulate_synthetic_stream.py` can target a throwaway server
  (`--base-url`) and exits 1 when unreachable.
- The SPA symlink test skips, with a reason, on a host that refuses to
  create symlinks (Windows without Developer Mode) instead of failing.

### Kept as limitations
Linux identity without creation time merges a reused 5-tuple+PID; 401/403
still drop batches (ADR-058); the buffer and dead-letter store are in
memory.

### Windows
Not reachable from this host: the Windows partition is BitLocker-encrypted
and unmounted, and the machine dual-boots. Nothing was mounted or
unlocked. The changes were handed over as a patch against `a128bfd`, with a
manifest and SHA-256 hashes, in a directory outside the repository; the
patch was applied to a fresh clone of `a128bfd` and the suite run there.
The Windows procedure is `PLATFORM_SUPPORT.md` §7.

### Results
Backend **1292 passed, 3 skipped, 0 failed**. Frontend and launcher
results in ADR-076 and `PLATFORM_SUPPORT.md` §6, re-run this session.

---

## Session 31 — Windows Validation of the Linux Revision

Started from `4360ca3` on `master`, equal to `origin/main`, with a clean
tree and nothing untracked. `master` has no upstream configured: it is
pushed as `master:main`. PraHari was not running. Nothing was committed or
pushed.

### Baseline and final

| | Baseline | Final |
|---|---|---|
| Backend `pytest -q -rs` | 1287 passed, 8 skipped, 3 warnings | **1322 passed, 8 skipped, 3 warnings, 0 failed** (110.7 s) |
| `pytest -m live_windows` | 2 passed | **8 passed** |
| Launcher verifier | 19 checks (forced stop) | **21 checks**, graceful, also under `-O` |
| Frontend | `tsc` 0, 67 passed, build OK | **`tsc` 0, 77 passed**, build OK |
| Static parse | - | 141 Python files and `start_prahari.ps1`, 0 errors |

Every count came from a run in this session. None is carried over from
Linux.

### Defects found and fixed (ADR-078..081)

| ADR | Defect | Found by |
|---|---|---|
| 078 | Audit card printed LOOPBACK ENFORCED unconditionally; `/audit/config` reported configured, not served, binding | Real browser: `:18765` displayed as `127.0.0.1:8000` |
| 079 | Events and Audit tables headed "(UTC)" showed local time, 5 h 30 m off | Real browser against the API's own timestamps |
| 080 | `-CheckOnly` installed and built, and passed with the port taken | Reading the script; port case reproduced on Windows |
| 080 | Verifier force-killed on Windows; shutdown hook never exercised | `code=1` in its own report; `CTRL_BREAK` proven to work |
| 081 | Latent PowerShell injection through `states` | Subprocess-boundary review |

Gaps closed with tests, no defect behind them: junction escape on both
static paths, and every subprocess branch of the connection-table query.

### Preservation

Both databases and their sidecars, `db_backups/`, `experiments/` and
`frontend/dist` are byte-identical before and after. Builds went to a
temporary directory. Every server this session started bound `127.0.0.1`
on its own port, used a temporary database, and was stopped with its port
checked closed; no Python process remained at the end.

### Not done

- Collector lifecycle against the operational database: blocked pending
  authorization.
- Live DNS parsing: the cache was empty on this host.
- The verifier's SIGTERM branch is shared code that cannot run here; re-run
  it on Linux.

---

## Session 32 — Windows Closure: Review, DNS and Lifecycle Proof, Deep Links

Continued from the uncommitted Session 31 work. Nothing was reset, stashed,
discarded, committed or pushed.

| Check | Session 31 | Now |
|---|---|---|
| Backend `pytest -q -rs` | 1322 passed, 8 skipped | **1334 passed, 8 skipped, 0 failed**, 3 warnings |
| `live_windows` | 8 passed | **15 passed** |
| Launcher verifier | 21/21 | 21/21 (`python` and `-O`), graceful |
| Frontend | `tsc` 0, 77 passed | **`tsc` 0, 90 passed**, build OK |

### Fixed

| ADR | Defect |
|---|---|
| 083 | A new collector reused the previous collector's adapter: its dedup cache (suppressing connections never stored) and its `include_loopback` |
| 084 | No URLs: deep links opened Overview, refresh lost the page, back left the app, unknown paths showed Overview; System Health and Administration unreachable |
| 085 | In Session 31's own changes: launcher leaked `PRAHARI_HOST`/`PORT` into the caller's session; verifier mislabelled a self-exit as forced; binding evidence claimed unmeasured facts; a loose UDP test; a `SyntaxWarning` |

### Proven, without the operational database (ADR-086)
- DNS: the unmodified script in real PowerShell over client-only instances
  of the real `MSFT_DNSClientCache` class; property names checked against
  the OS schema.
- Collector lifecycle: the real class and real query, started, polled,
  stopped and restarted into a temporary database.

### Documented
- `docs/FORECASTING_DATA_REQUIREMENTS.md`: target, CSV schema, declared
  policy, minimum quantities, features, split, and the fit of
  CSE-CIC-IDS2018 and CTU-13. Three claims in its first draft were checked
  against the code and corrected (model list, bidirectional-count
  behaviour, ambiguous-date handling).

### Open
- `Get-DnsClientCache` returning populated objects: empty cache here.
- A shutdown hang seen twice with a real browser; not reproduced.
- Linux re-run of ADR-080 and ADR-083.
- `frontend/dist` to be rebuilt by the operator (`npm run build`).

---

## Session 33 — Windows Closure on `windows-closure`, Python 3.12.10

On branch `windows-closure` at `4360ca3`. All Session 31-32 changes were
preserved; nothing was reset, stashed, discarded, staged, committed,
pushed or merged.

### Environment change found
Python 3.12.10 was installed today at 18:39, after Sessions 31-32, and
upgraded the venv's base interpreter (ADR-087). Every check was re-run:

| Check | Result |
|---|---|
| Backend | 1334 passed, 8 skipped, 0 failed, 3 warnings |
| `live_windows` | 15 passed |
| Launcher verifier | 23/23 (`python`, `-O`), graceful |
| Real launcher on a temporary database | serves rebuilt dist, all routes, binding `CONFIGURED`, graceful stop with a browser open |
| Frontend | `tsc` 0, 90 passed |
| Static | 144 files, 0 problems with warnings as errors; launcher 0 parse errors |

### Done
- Reviewed every source change and test; the verifier now also probes
  `/system-health` and `/admin`.
- `frontend/dist` rebuilt. It was already identical: it had been rebuilt
  after Session 32. The real launcher was verified to serve it.
- Shutdown hang investigated (ADR-087): no hang in any stop on 3.12.10; no
  deterministic reproduction of the suspected asyncio mechanism; **no fix
  applied**, as any fix would be speculative.
- Dataset compatibility measured (ADR-088): 1 of 10 CSE-CIC-IDS2018
  processed files is importable; CIC-IDS2017 is behind a registration form.
  Two documentation claims corrected (no AWS CLI needed; "importable as it
  stands").

### Remaining
- Live DNS cache entries: the cache on this host is empty.
- Shutdown hang: unreproduced; watch for recurrence.
- Dataset: a download decision, a CIC-IDS2017 registration, or a
  research-design decision about address-less flows.
- Running the application's own collector against `prahari.db`: operator
  authorization.

### Session 33, continued: independent review and commit preparation (ADR-089)

An independent read-only review of the diff found no blockers. Fixed: the
binding report's unverified loopback claim (now `true`/`false`/`null`),
IPv4-mapped arrivals, a contradictory README section, an overstated
acceptance-matrix row; plus a counter-isolation test. A pre-existing 500 on
stream ingest under the collector's source id was confirmed and raised as a
separate task. Final run: backend 1336 passed, 8 skipped, 0 failed;
`live_windows` 15; verifier 23/23 twice; frontend 91 passed; static clean.

### Follow-up: reserved local-producer sources (ADR-090)

The pre-existing 500 on stream ingest under the collector's source id is
fixed at the ingestion trust boundary. Synthetic replay and CSV import can
no longer write into the host collector's or UDP observer's sources either,
whether or not the collector has been created. All six external write
paths are guarded. 13 regression tests; with the guard neutralised the 10
defect tests fail. The sensor agent treats the refusal as permanent, without
counting it as an identity conflict.
