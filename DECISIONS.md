# PraHari — Architecture Decision Records (ADR)

This document records the architectural decisions made during the design, implementation, and verification of **PraHari — The Digital Sentinel**.

---

## ADR-001: Embedded SQLite with WAL Mode and Foreign Keys

### Context
PraHari requires durable persistence for telemetry sources, normalized events, import summaries, descriptive analyses, and audit trails. Running a separate database daemon (e.g., PostgreSQL) introduces deployment overhead, network failure modes, and dependency complexity on edge and local host machines.

### Decision
Use SQLite with Write-Ahead Logging (`PRAGMA journal_mode=WAL`) and Foreign Key enforcement (`PRAGMA foreign_keys=ON`).
- WAL mode allows non-blocking concurrent readers while a write transaction is executing.
- Schema versioning is explicitly enforced via DDL table creation.
- Connection lifetimes are managed with Python context managers that guarantee rollback on failure.

### Consequences
- **Positive**: Zero external services required. Instant startup on Windows, macOS, and Linux. Atomic ACID transactions.
- **Negative**: Write throughput is limited by single-writer lock; sufficient for edge/local SOC monitoring and batch imports up to 100,000 records.

---

## ADR-002: Strict Separation of Descriptive Factual Summaries and Forecasting

### Context
In cybersecurity tooling, dashboards frequently blur the distinction between observed empirical telemetry and speculative ML predictions, leading operators to confuse model inferences with confirmed incidents.

### Decision
Architecturally isolate **Descriptive Analytics** from **Threat Forecasting**:
1. Descriptive Analytics calculates factual aggregations (counts, protocol distributions, IP top-talkers, byte aggregates, data quality flags). It makes no predictions.
2. Threat Forecasting produces probabilistic propensity scores for a specified future horizon. Models are benchmarked against heuristics, evaluated with calibration metrics, and clearly demarcated in the UI.

### Consequences
- Operators clearly know when they are viewing ground truth versus statistical estimates.

---

## ADR-003: Retrospective Observation Window with Lead Time Buffer

### Context
Predicting future security incidents requires defining an exact causal problem formulation. Using features contemporaneous with the event causes forward-looking leakage.

### Decision
Define a 3-part temporal sequence for forecasting:
- **Observation Window ($W=60s$)**: $[t - W, t]$. Only flows ending before or at $t$ contribute to feature calculation.
- **Lead Time Buffer ($\text{lead\_time}=30s$)**: $[t, t + \text{lead\_time}]$. Provides actionable reaction time and ensures feature extraction latency does not overrun the prediction window.
- **Prediction Horizon ($H=60s$)**: $[t + \text{lead\_time}, t + \text{lead\_time} + H]$. Target $y \in \{0, 1\}$ is whether an attack flow starts within this horizon.

### Consequences
- Mathematically eliminates temporal leakage. Features strictly precede the target window.

---

## ADR-004: Chronological Temporal Splitting to Prevent Overlapping Window Leakage

### Context
Sliding observation windows across continuous telemetry with step $15s$ and window $60s$ results in adjacent feature vectors sharing $45s$ of telemetry. Random cross-validation or random train/test splitting intermixes overlapping windows between train and test sets, causing artificial inflation of evaluation scores.

### Decision
Enforce strict **Chronological Past-Train / Future-Test Splitting**:
- The first $70\%$ of chronological time-step instances are assigned to the training split.
- The remaining $30\%$ of instances (representing future time) form the testing split.
- Test instances are never interspersed with training windows.

### Consequences
- **Positive**: Realistic, leakage-free evaluation reflecting true operational deployment.
- **Trade-off**: Lower apparent accuracy on non-stationary datasets compared to leaked random splits, but scientifically valid and honest.

---

## ADR-005: Research Feasibility Gating for Predictive Models

### Context
Machine learning algorithms will readily fit patterns even on small, non-stationary, or single-class datasets, giving a false sense of security.

### Decision
Implement the **Research Feasibility Audit**:
- Before forecasting models can be trained or relied upon, the telemetry dataset is audited for:
  1. Minimum sample size ($\ge 25$ events).
  2. Temporal monotonicity ($\ge 99\%$ ordered).
  3. Class distribution (presence of ground-truth labels with both benign and attack classes).
  4. Data quality warnings ($< 40\%$ flag ratio).
- Datasets failing these criteria are marked `REJECT_FORECASTING` or `CONDITIONAL_REVIEW`.

---

## ADR-006: Unified Deployment Architecture (FastAPI Serving React SPA)

### Context
Requiring users to run separate Node.js dev servers and Python backend processes causes port collision, CORS issues, and deployment fragility.

### Decision
Compile the React frontend into static assets (`frontend/dist/`) and serve it directly from the FastAPI application using:
- `/assets` mount for Vite-emitted bundles.
- `spa_fallback` handler to serve `dist/index.html` on client-side routes (`/events`, `/forecast`, `/analytics`).
- Explicit path traversal prevention (`is_relative_to` verification and rejection of `..`).
- Missing asset protection (returning HTTP 404 for missing static files with extensions).

---

## ADR-007: Multi-Schema Ingestion for Zeek and Suricata EVE Logs

### Context
Network sensors output varying schema conventions. Zeek outputs TSV/NDJSON with dotted notation (`id.orig_h`), while Suricata outputs nested JSON (`flow.bytes_toclient`).

### Decision
Implement flexible field extraction in `JsonStreamAdapter`:
- Check for Zeek conventions: `id.orig_h`, `id.resp_h`, `orig_bytes`, `resp_bytes`.
- Check for Suricata conventions: `src_ip`, `dest_ip`, nested `flow` object.
- Parse Unix timestamps (seconds & milliseconds) and ISO-8601 strings into normalized UTC datetimes.
- Map transport layer protocols into canonical uppercase strings (`TCP`, `UDP`, `ICMP`).

---

## ADR-008: Loopback-Only Binding and Non-Promiscuous Testing Safety

### Context
Cybersecurity testing must avoid interfering with host network adapters, capturing real employee traffic without authorization, or opening externally accessible ports.

### Decision
- Default server binding strictly to loopback: `127.0.0.1:8000`.
- Do not activate promiscuous packet capture (`libpcap`/`scapy` live sniffing).
- Ingest telemetry via local files, NDJSON HTTP streams, clearly-labelled
  synthetic fixtures, and — since ADR-009 — unprivileged Windows
  connection-table polling of the local host only.

### Superseded in part
The original clause "ingest telemetry exclusively via synthetic fixtures"
is superseded by **ADR-009**, which adds genuine local telemetry. The
prohibition on packet capture, promiscuous mode and privileged collection
stands unchanged.

---

## ADR-009: Live Windows Telemetry via the OS Connection Table

### Context
The application needed a genuine operational data source. Relying on
synthetic records for live demonstration misrepresents the system's
capability, and the previous "live streamer" script fabricated records while
presenting them as live telemetry.

Richer sources exist (packet capture, Zeek/Suricata, Windows audit logging)
but each requires driver installation, elevated privileges, or configuration
changes to the host — none of which may be performed without explicit
operator approval.

### Decision
Collect genuine network telemetry by polling the **Windows TCP connection
table** via `Get-NetTCPConnection`.

- Unprivileged, no driver, no packet capture, no configuration change, and
  no third-party Python dependency (PowerShell ships with Windows).
- The OS reports a real per-connection `CreationTime`, which serves both as a
  truthful `observed_at` and as part of a stable connection identity.
- Event ids are a deterministic hash of (5-tuple, pid, creation time), making
  repeated polling idempotent at the storage layer.

### Consequences
- **Positive**: Real operational data with zero added attack surface and zero
  setup. Dedup is exact rather than heuristic.
- **Negative**: No byte/packet/duration accounting, and short-lived
  connections between polls are missed. These limits are reported by the
  collector rather than papered over, and the schema records the absent
  fields as `null` with a `missing_field` flag.
- **Deferred**: Packet-derived telemetry (and therefore volumetric features)
  remains unavailable until a privileged capture source is explicitly
  authorised.

---

## ADR-010: Refusing Evaluation Rather Than Reporting a Contaminated Score

### Context
The forecasting pipeline previously contained two fallbacks that silently
produced numbers when an honest split was impossible:

1. If the chronological training split was single-class, it fell back to an
   interleaved `[::2]` split. With overlapping sliding windows this places
   near-identical feature vectors in both train and test — direct leakage.
2. If the test split was empty, it set `X_test = X_train`, reporting a
   fitted-data score as a holdout score.

Both paths produced plausible-looking metrics from an invalid evaluation.

### Decision
Remove both fallbacks. Use a chronological split with a **train-side purge**
of `ceil((W+L+H)/S)` windows, preserving the holdout, and raise
`InsufficientEvaluationDataError` when:

- fewer than 4 training windows survive the purge, or
- no evaluation windows remain, or
- the leakage-free training period is single-class.

The API surfaces this as HTTP 422 with the full split report and a
remediation note. Metrics carry `metrics_interpretable`, and predictions
carry `is_validated_model` / `validation_status`.

### Consequences
- **Positive**: No reported metric can come from a contaminated split. A
  refusal is auditable and explains itself.
- **Negative**: Small datasets — including the repository's own 37-event
  fixture — can no longer be "evaluated". This is the correct outcome: that
  dataset never supported a defensible evaluation. The end-to-end test now
  asserts the refusal, and forecasting tests use datasets long enough to
  support a genuine holdout.

---

## ADR-011: Hostname Attribution as Evidence-Bearing Inference

### Context
Analysts need to know which domains a host talks to, but a TCP connection
records an address, not a name. Several ordinary conditions make the
reconstruction unreliable: CDNs put many hostnames on one address, DNS
answers rotate, cache entries go stale, and encrypted DNS leaves no local
observation at all.

### Decision
Infer hostnames from **locally observed DNS resolutions** and return every
attribution with its method, confidence, evidence timestamp, competing
candidates and limitations. Never mutate the connection record.

Reverse DNS is available but **off by default** and marked
`identifies_requested_host = false`, because a PTR record names the address
owner — usually a CDN edge — not the host the application requested.
Infrastructure names are excluded from "top domains" aggregation.

### Consequences
- **Positive**: no fabricated certainty. A consumer can always see why an
  attribution is or is not trustworthy.
- **Negative**: on hosts using DoH/DoT the cache is empty and most
  connections stay unattributed. This is reported with a diagnosis rather
  than hidden.

---

## ADR-012: Field Availability Is Declared, Not Inferred From Nulls

### Context
The Windows connection table exposes no byte counts, packet counts or flow
duration. Flagging every such record `MISSING_FIELD` reported all 195
profiled records as defective and buried genuine gaps.

### Decision
Declare per-source capability profiles, add `SOURCE_LIMITED` for structural
limits, and split analytics into `unsupported_field_counts` versus
`missing_field_counts`. An unrecognised source type is treated
conservatively: absence is a defect unless a declared limit explains it.

### Consequences
- **Positive**: "the sensor cannot measure this" and "this record lost data"
  are finally distinguishable; quality warnings mean something again.
- **Negative**: a new source type must declare a profile to be interpreted
  precisely.

---

## ADR-013: Backend Enforcement of the Research Gate

### Context
The feasibility audit was advisory. Nothing stopped `POST /forecast/train`
or `/forecast/predict` from being called directly, and prediction fell back
to an uncalibrated heuristic. A disabled dashboard button is not a control.

### Decision
Enforce readiness in the backend at every forecasting entry point, with
explicit states (insufficient data, missing labels, inadequate class
representation, invalid evaluation conditions, trained-not-validated,
performance inadequate, validated). Refusals return HTTP 409 with the unmet
requirements, observed-versus-required values, and next steps.

Unlabelled traffic is **not** counted as benign: ordinary local connections
carry no ground truth, and treating them as confirmed negatives would
manufacture a class balance the evidence does not support.

### Consequences
- **Positive**: no API client can obtain a model or score from data that
  cannot support one; refusals are self-explanatory and audited.
- **Negative**: locally collected telemetry alone can never pass the gate,
  since it has no incident labels. That is the correct outcome.

---

## ADR-014: Deterministic Database Location

### Context
`sqlite:///./prahari.db` resolved against the process working directory, so
the launcher (run from the project root) and a backend-directory invocation
created **different databases**. Telemetry collected through one was
invisible to the other.

### Decision
Resolve relative database paths against the project root, derived from the
package location rather than the CWD. The test suite overrides the path to a
temporary directory so it can never open the operator's live data.

### Consequences
- **Positive**: one database regardless of how the app is started; tests
  cannot touch real telemetry.
- **Negative**: a database created earlier under `backend/` is no longer
  read. It is left on disk rather than migrated automatically.

---

## ADR-015: Error Boundaries Around Page Content

### Context
Opening the Feasibility view blanked the entire application. The page threw
`TypeError: Cannot read properties of undefined (reading 'toFixed')` during
render, and because React 18 unmounts the whole tree when a render error
reaches the root — and no error boundary existed anywhere — a single bad
field reference destroyed the shell, navigation included. Recovery required
a page reload.

### Decision
Wrap the page area in an `ErrorBoundary` keyed on the active tab. A render
failure is contained to the page that caused it; the header and navigation
stay mounted; the fallback names the failing view, shows the error and a
component stack, and offers a retry. Changing tabs resets the boundary, so
a transient failure does not persist.

### Consequences
- **Positive**: no page can take down the application. A failed API call or
  an unexpected payload degrades one view instead of all of them.
- **Negative**: a boundary hides errors from the console-free user, so the
  fallback deliberately surfaces the message and stack rather than showing
  a generic apology.

---

## ADR-016: Frontend/Backend Contract Tests

### Context
The dashboard's `FeasibilityReport` interface described a response the
backend had never produced. Because the interface was internally
consistent, `tsc` accepted it — type checking cannot detect drift when the
types themselves are the stale artifact. The mismatch surfaced only at
runtime, as a crash. An automated sweep found four more instances
(`feat.contribution`, `log.created_at`, `config.host`, the whole
`AdapterHealth` shape), none of which any existing test covered.

### Decision
Add backend tests that parse the TypeScript interfaces and compare them
field-by-field against the live OpenAPI schema. Any field the frontend
declares but the backend does not return fails the suite, with the phantom
fields named. The parser is brace-aware so legitimately nested objects are
not misread as parent fields.

Verified as a genuine guard: reintroducing `overall_feasibility_score` makes
the suite fail; removing it makes it pass.

### Consequences
- **Positive**: this class of bug is now caught in CI rather than in the
  browser. Renaming a backend field breaks the build loudly.
- **Negative**: the tests couple the backend suite to the frontend source
  tree, and interfaces with no backend counterpart must be left out of the
  pairing list deliberately rather than by omission.

---

## ADR-017: Safe Formatting Helpers for API-Sourced Values

### Context
Two render-crash outages (Feasibility, then Stream & Replay) had the same
immediate cause: calling a numeric method directly on an API field the
backend does not return. `undefined.toFixed(2)` throws during render.

A sweep also found the opposite error: guards written as
`value ? format(value) : "N/A"` render a genuine **0** as unavailable —
and for this application that distinction is load-bearing, because "no
bytes transferred" and "this source cannot count bytes" are different
facts.

### Decision
Add `src/utils/format.ts` with helpers that never throw and that treat 0 as
a real measurement (`isNum` uses `Number.isFinite`, not truthiness). Absent
values render as `N/A`, never as 0. Charts receive `safeSeries`, which
drops non-finite entries.

These are a presentation safety net, explicitly **not** a substitute for a
correct contract — blanket optional chaining would have hidden all three
contract bugs instead of surfacing them.

### Consequences
- **Positive**: a missing field degrades one cell to `N/A` instead of
  destroying a page; the zero/unavailable distinction is preserved.
- **Negative**: a silently-renamed backend field now shows `N/A` rather
  than failing loudly, so the contract tests are what must catch it.

---

## ADR-018: Provenance Markers Are Not Quality Defects

### Context
`records_with_warnings` counted every quality flag. `SOURCE_LIMITED`
(a sensor limit) was excluded in session 3, but `SYNTHETIC_SAMPLE` was
not. Once synthetic fixtures were present, the dashboard reported **477 of
552** records as having data-quality warnings, which buried the 27 genuine
defects.

### Decision
Classify flags centrally in `app/schemas/events.py` via
`NON_DEFECT_QUALITY_FLAGS` and `is_quality_defect()`. `SOURCE_LIMITED` and
`SYNTHETIC_SAMPLE` describe the source and the record's provenance; neither
indicates anything wrong with the record. Both the analysis service and the
feasibility engine use the shared classification, so they cannot diverge.
The flags are still counted and displayed — just not as defects.

### Consequences
- **Positive**: the quality figure means something again; synthetic data no
  longer depresses the feasibility score for the wrong reason.
- **Negative**: a new flag must be classified deliberately, or it defaults
  to being treated as a defect (the conservative choice).

---

## ADR-019: Enrichment Is Disabled for Injected Collector Queries

### Context
`poll_once()` refreshed the real Windows DNS cache on every poll. Tests
that inject a fake `query_fn` therefore combined fabricated connections
with a real PowerShell subprocess per poll — inconsistent, and slow enough
that the backend suite reached 3h 55m under load.

### Decision
When a caller injects `query_fn`, DNS enrichment defaults to **off**;
genuine collection keeps it **on**. An explicit `refresh_dns` argument
always wins. Tests assert that an injected query spawns no subprocess.

### Consequences
- **Positive**: suite runs in ~9s; mocked tests are hermetic; "mock the OS"
  now genuinely means no OS contact.
- **Negative**: a test wanting both a fake connection table and real DNS
  must opt in explicitly — which is the correct direction for that default.

---

## ADR-020: Optional Browser Extension as the Application-Layer Producer

### Context
HTTP method, path, status and timing are not observable from the Windows
TCP connection table. The alternatives were a browser extension, a TLS-
intercepting proxy, ETW, or packet capture. Only the extension needs no
elevation, no certificate and no network change.

### Decision
Ship an optional MV3 WebExtension in `extension/`, off by default, that
reports request metadata to the local endpoint only. PraHari neither
installs nor enables it; the README documents the steps for the user.

Correctness boundaries encoded in the implementation and its tests:
query strings are discarded in the browser; bodies, cookies, headers and
credentials have no field in the payload and are rejected with 422; a
failed request is stored with a null status rather than a fabricated one;
HTTP records remain separate from connection records, with correlation
treated as probabilistic rather than asserted.

### Consequences
- **Positive**: genuine HTTP visibility becomes available through a
  reversible, user-controlled, unprivileged mechanism.
- **Negative**: covers one browser profile only, and **real-browser
  end-to-end verification remains outstanding** because installation
  requires the user. The contract is verified with a simulated producer
  that is deliberately labelled as such.

---

## ADR-021: Negative Labels Require an Observed, Labelled Horizon

### Context
Blueprint §7 states `y_t = 0` only when the observation window is complete
enough to support a negative label. The implementation did not enforce it.
`y=0` was assigned whenever no attack label appeared in the horizon —
including when the horizon contained **no events at all** (a capture gap),
and when it contained only **unlabelled** traffic.

Both fabricate ground truth. The first records "no attack occurred" from an
absence of data; the second asserts benignity that was never established —
the very assumption the readiness gate exists to prevent, contradicted
inside the labeller itself.

### Decision
A positive label is always valid: the attack evidence is present. A
**negative** label requires the horizon to contain at least
`min_horizon_events` observations, and (when `require_labelled_horizon`,
the default) at least one of them to carry a label. Windows failing this are
**excluded from the dataset**, not labelled 0, and the counts are reported
in the windowing report. The same rule applies to the event-count fallback
path, which previously bypassed it.

A fully labelled historical corpus may opt out explicitly; it is never the
silent default.

### Consequences
- **Positive**: the negative class means "observed and found benign" rather
  than "nothing seen". Unlabelled live telemetry now yields **zero** usable
  windows, which is the correct outcome.
- **Negative**: fewer instances from sparse data, and some datasets will
  produce no usable windows at all. That is the honest result.
- **Follow-on defect found and fixed**: skipped windows do not grow the
  output array, so the existing `MAX_WINDOWS` guard — which capped *emitted
  windows* — no longer bounded the loop. The cap now bounds **iterations**.

---

## ADR-022: Experiment Manifests Replay, and Fail Closed Rather Than Reproduce Approximately

### Context
A manifest that only *describes* a run proves nothing: the numbers in it
cannot be distinguished from numbers typed in by hand. Reproducibility
requires re-executing the recorded protocol and comparing outcomes.

The hard part is deciding what "reproduced" means. Training wall-clock time
and `generated_at` can never match. If every field is compared, replay always
fails; if mismatches are tolerated loosely, replay always passes.

### Decision
`research/experiment.py` records a versioned manifest (`MANIFEST_VERSION`)
containing the dataset fingerprint, provenance breakdowns, target definition,
window and split parameters, random seed, feature set, environment and
results — and **no telemetry**: no address literals and no record fields
(asserted by test, because a manifest is the artefact most likely to be
shared).

The manifest declares two explicit tuples:

- `DETERMINISTIC_OUTPUTS` — instance counts, split sizes, purge counts,
  positives, confusion matrices. These must match **exactly**.
- `NON_DETERMINISTIC_OUTPUTS` — timings and timestamps. Never compared.

`replay_experiment()` re-selects the dataset, rebuilds the windows and split,
retrains and compares. It **refuses** rather than reporting a result when the
dataset fingerprint has changed, the dataset is missing, the schema version
changed, the feature set changed, or the configuration no longer yields a
valid evaluation. All mismatches are reported together, not just the first.

### Consequences
- **Positive**: "reproduced" is a checkable claim, and the failure modes are
  named rather than silently absorbed. Replay is read-only against telemetry
  (tested), so verifying a result cannot alter the data it was computed from.
- **Negative**: a replay on a database that has since received new telemetry
  fails by design. That is correct — the recorded result was computed on
  different inputs — but it means manifests are only replayable against a
  dataset in the state they were captured.
- **A real defect this exposed**: the manifest first stored a *derived* train
  ratio (`train_instances / total_instances`). Boundary purging removes
  windows between the splits, so that value (0.636) is smaller than the
  configured one (0.7); replaying with it produced a different split and
  different metrics. `SplitIntegrityReport.configured_train_ratio` now records
  the parameter actually passed. Without a replay runner this would have gone
  unnoticed indefinitely, because every individual report was internally
  consistent.

---

## ADR-023: Retention Is Enforced Manually, Dry-Run by Default, and Never on a Timer

### Context
`retention_days` existed in configuration and was reported in the audit view,
but nothing ever deleted anything. A retention setting that is displayed and
not applied is worse than none: it states a privacy property the system does
not have.

The obvious implementation — a scheduled pruning job — is the wrong one here.
This project holds the operator's own machine telemetry, it is the only copy,
and an automatic deletion triggered at startup or on a timer could destroy
data the operator was in the middle of analysing.

### Decision
`services/retention.py` enforces retention with these properties:

- **Dry run by default.** `POST /retention/preview` changes nothing.
  Deletion requires `confirm="DELETE-EXPIRED-TELEMETRY"` verbatim.
- **Never automatic.** No scheduler, no startup hook, no background task.
  There is a test asserting that starting the application deletes nothing.
- **Age from `observed_at`, in UTC** — event time, not ingestion time. Old
  telemetry imported yesterday is eligible; recent telemetry is not,
  regardless of when it arrived.
- **Batched in independent transactions.** An interruption mid-run leaves
  whole batches committed and the database consistent, rather than a single
  enormous transaction that either locks the database or rolls back entirely.
- **Narrow scope.** Only `live_telemetry`, `historical_replay` and
  `synthetic_demo` records are eligible. Telemetry sources, import summaries,
  analyses and **audit records are never pruned** — pruning the audit trail
  would erase the evidence that pruning occurred. Test fixtures are outside
  the default policy.
- **Counters refreshed afterwards**, so a source cannot report events that
  no longer exist.
- Enforcement is audit-logged; previews are not, because nothing happened.

### Consequences
- **Positive**: the documented retention property is now real and testable,
  and the destructive path requires deliberate intent.
- **Negative**: retention does not happen unless an operator runs it, so
  stale data can persist indefinitely. That is the intended trade-off on a
  single-copy local database; an unattended deployment would need a
  scheduler, and would need to accept the risk that comes with one.

---

## ADR-024: Central Deployment Fails Closed, and an Unscoped Query Is Not "All Sources"

### Context
`DeploymentMode.CENTRAL` existed as a flag with no authentication behind it.
Enabling it would have accepted telemetry from anyone who could reach the
port. The two defensible options were to remove the flag or to implement the
security it implies; the blueprint requires the latter.

### Decision
Central mode is implemented in `core/security.py` and `api/auth.py`, and
**refuses to start without credentials**:

```
Refusing to start in CENTRAL deployment mode: Central deployment requires
credentials. Set PRAHARI_CREDENTIALS_FILE or PRAHARI_CREDENTIALS_JSON.
PraHari will not run centrally without authentication.
```

- Tokens are hashed with PBKDF2-HMAC-SHA256 (240,000 iterations) under a
  per-credential salt and compared with `hmac.compare_digest`. Plaintext is
  displayed once at mint and never stored.
- Roles separate `ingest`, `read_only` and `admin`. Only `admin` may read
  across sources or read the audit log.
- **An unscoped request returns only the caller's own source**, never
  everything. This is the decision most likely to be got wrong by accident:
  treating a missing `source_id` as "no filter" turns every sensor credential
  into a full read of the fleet. There is a test for exactly that leak.
- A request for another source returns **403**, rather than being silently
  rewritten to the caller's source. Silent rewriting would hand the client a
  response that does not answer the question it asked.
- Unknown and disabled credentials return **identical wording**, so the error
  cannot be used to enumerate which source ids exist.
- Default deny: unlisted paths require authentication; only an explicit
  public list (health) is exempt, so a newly added route is protected by
  default rather than by remembering to protect it.

Local deployment remains loopback-only and unauthenticated by design, and a
test asserts it still works with no credentials present.

### Consequences
- **Positive**: the flag now means what it says, and the failure mode of a
  misconfiguration is a refusal to start rather than an open service.
- **Negative / not claimed**: this has been exercised **over loopback only**.
  There is no rate limiting, no token rotation schedule, and no TLS
  termination in-process. Exposing a listener beyond 127.0.0.1 is outside
  this project's safety boundary, so central mode's behaviour on a real
  network is **untested**, and it remains disabled by default.
