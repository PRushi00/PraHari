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

---

## ADR-025: A Detector's Output Is Not Ground Truth, and Synthetic Labels Must Stay Visible

### Context
Two provenance faults were found while writing contract tests for the Zeek
and Suricata ingestion path. Both had the same shape: a weaker claim stored
as a stronger one, with nothing in the output to reveal it.

**A Suricata signature was stored as `dataset_ground_truth`.** An IDS
signature is that detector's opinion about a packet. A corpus label is a
statement about what actually happened. Treating them as the same thing
means a forecaster trained on alert data learns to predict *one detector's
alerts*, while precision, recall and PR-AUC all describe "attack
prediction". The result would be wrong in a way that looks fully evidenced
— the worst possible failure for this project.

**`SYNTHETIC_RULE` was declared with the same string value as
`RULE_BASED`.** In Python that makes it an alias, not a member: it never
appears in iteration, and every synthetic label was recorded as
`rule_based`. The experiment manifest exists specifically to record what a
result was computed on, and it was reporting synthetic labels as locally
derived ones. Every metric this project has produced comes from synthetic
data, so this hid the single most important caveat attached to all of them.

### Decision
`LabelProvenance` gains `DETECTOR_OUTPUT` and gives `SYNTHETIC_RULE` its own
value. The JSON adapter resolves the label and its provenance together,
never defaulting to the strongest option:

| Label source | Provenance |
|---|---|
| `label` / `classification` | `DATASET_GROUND_TRUTH` |
| `alert.signature` | `DETECTOR_OUTPUT`, plus a record-level warning |
| neither | `UNLABELED` — never inferred as benign |

A corpus label takes precedence over a detector signature on the same
record.

The readiness gate still **counts** detector labels — they are labels, and
modelling a detector's alerts is a legitimate thing to want — but reports
`non_ground_truth_labelled_events` and a plain-language caveat per
provenance, rendered on the forecast page. The requirement's own wording no
longer claims "ground truth" for labels that are not.

Separately, the event type no longer collapses to `ALERT` whenever a label
is present. The event type describes **what was observed**; the label
describes **how it was annotated**. Conflating them made an imported
labelled corpus report as nothing but alerts.

### Consequences
- **Positive**: a result computed on detector output or synthetic data now
  says so everywhere it is reported — adapter, readiness report, dashboard
  and experiment manifest. The distinction cannot be lost by accident,
  because a test asserts no provenance value is aliased.
- **Negative**: `synthetic_rule` is a new value in the API enum, so any
  stored record or external consumer expecting `rule_based` for synthetic
  data sees a different string. This is a deliberate break; the old
  behaviour was reporting something untrue.
- Two existing tests asserted `"rule_based" in label_provenance_breakdown`
  under a comment reading "Provenance makes synthetic data obvious". They
  were asserting the bug. They now assert `synthetic_rule` is present and
  that `dataset_ground_truth` is **absent**.
- All four fixes were mutation-checked: each old behaviour was reintroduced
  and the corresponding test observed to fail.

---

## ADR-026: One Name, One Meaning — Dataset Identity vs Split Setup

### Context
`SplitIntegrityReport.dataset_fingerprint` and
`ExperimentManifest.dataset_fingerprint` were computed by **two different
algorithms**. The split report hashed instance counts, window parameters,
train ratio, positive count and time range; the manifest hashed the event
identities themselves.

So `GET /forecast/integrity` and a stored manifest reported different
values under the same field name for the same data, every time. A reader
comparing them would reasonably conclude something was corrupt. Worse, the
split report's value was advertised as a dataset identity while being a
hash of shape: two entirely different corpora with the same counts,
positives and time range collide.

Found by running the two side by side during verification, not by a test —
nothing compared them, because each was internally consistent.

### Decision
The two values measure different things, so both are kept and each is named
for what it is:

| Field | Meaning |
|---|---|
| `dataset_fingerprint` | **Which records.** Content-addressed via `fingerprint_events`, the same function the experiment manifest uses, so the two now agree |
| `split_configuration_fingerprint` | **Which protocol.** Counts, window parameters, ratio, positives, time range. Not a dataset identity |

A test asserts the split report's `dataset_fingerprint` equals
`fingerprint_events(events)`, that a changed train ratio moves only the
setup hash, and that a different corpus moves only the dataset hash.

### Consequences
- **Positive**: an integrity report and a manifest can now be compared
  directly, which is the entire point of publishing a fingerprint.
- **Negative**: `dataset_fingerprint` changes from a 16-character truncation
  to a full sha256 hex string, and gains a sibling field. Any consumer
  comparing against a previously recorded 16-character value will see a
  mismatch — correctly, because the old value did not identify the dataset.

---

## ADR-027: UDP Endpoints and Interface Counters Are Separate Measurement Types

### Context
Two further unprivileged Windows sources were available and unused:
`Get-NetUDPEndpoint` and `Get-NetAdapterStatistics`. Both broaden coverage,
and both are easy to misrepresent.

A UDP endpoint record is a **locally bound socket**, not a conversation.
UDP is connectionless and Windows records no peer for an unconnected
socket. Filing these as connections — with a wildcard or inferred
destination — would manufacture peers that were never observed and corrupt
every destination-based aggregation.

Interface counters are **real** OS-measured bytes and packets, the only
genuine volume measurement available here without packet capture. They are
also per interface and cumulative, so they cannot be attributed to a
connection, a process or a destination. Writing them into
`normalized_events` would let them be summed alongside flow byte counts
from an imported dataset, producing a figure that means nothing.

### Decision
**UDP endpoints** become canonical events with a new
`EventType.UDP_ENDPOINT`. Their capability profile declares `dst_ip` and
`dst_port` **`not_applicable`** rather than missing, so their absence is
never scored as a data-quality defect. Event ids are deterministic, so
re-polling the same socket persists nothing new.

**Interface counters** are not events. They are served from
`GET /hostobs/interfaces`, and the payload carries its own scope —
`measurement_scope: "interface_cumulative"`, `attributable_to_flow:
false`, `attributable_to_process: false`. A delta between readings is
offered where one exists; across an adapter reset (a decreasing counter)
**no delta is derived**, because neither a negative nor a wrapped-around
positive describes anything that happened on the wire.

### Consequences
- **Positive**: coverage grows without any new claim about what is
  measurable. The one place real byte counts exist is exposed, with its
  limits attached to the data rather than to the documentation.
- **Negative**: `udp_endpoint` events carry no destination, so they are
  invisible to destination-based analytics. That is accurate, not a gap to
  be filled by inference.
- Verified live: 41 endpoints observed, 0 rejected; a second poll persisted
  1 new socket and suppressed 40 repeats.

---

## ADR-028: Lead Time, Uncertainty, and a Temporal Model Without a New Dependency

### Context
A single precision/recall pair cannot answer two questions the research
objective actually asks: how far ahead can it warn, and how much of the
number is noise. The blueprint also calls for a temporal model.

### Decision
**Lead-time sweep** (`research/evaluation.py`): the complete protocol is
re-run once per lead time with everything else held constant. A lead time
whose windowing or split cannot support an honest evaluation is reported as
a **refusal with its reason**, not omitted — omitting it would imply the
curve was measured and flat there.

**Bootstrap uncertainty**: percentile intervals over the held-out
instances, refused when the holdout cannot support one (fewer than 20
instances or 5 positives, or a single class). Resamples that lose a class
are skipped rather than scored as zero, since such a resample is not a
possible evaluation. Held-out truth is stored **per model**, because the
temporal model's holdout is shorter and resampling its scores against
another model's labels would misalign them silently.

**Temporal model**: a window-sequence model that concatenates the previous
`TEMPORAL_LAGS` windows, so order matters and the model sees movement
rather than a snapshot. Stacking is applied **separately to the training
and test matrices**, never before the split — done before, a test instance
near the boundary would carry training-period windows in its lags,
re-importing exactly the contamination the purge removes. The cost is the
first few instances of each side, which are dropped.

### Consequences
- **Positive**: lead time and uncertainty are now measurable, and the
  temporal model is evaluated under the same target, dataset and split as
  the others, so the comparison is like for like.
- **This is not an LSTM, and is not described as one.** A recurrent model
  needs a deep-learning dependency that is not installed, and installing
  one is outside the agreed boundary. More to the point, there is still no
  real labelled corpus to train it on — adding an LSTM now would produce an
  impressive-sounding component evaluated on data this project generated.
- The sweep multiplies training cost by the number of lead times, so the
  request is capped at 12.

---

## ADR-029: One Timestamp Policy, In One Place

### Context
Found by driving the dashboard in a browser. The Analytics page showed an
observation window starting **1/1/1601**, and the Feasibility page scored
"Temporal Monotonicity & Ordering" at **100%, PASSED**, over a span of
13,436,268,232 seconds — about 425 years. The readiness gate, over the very
same dataset, correctly reported 65,260 seconds.

Three modules implemented the same rule independently. The adapter had it,
the readiness gate had it, the descriptive analysis had never had it, and
the feasibility audit inherited the broken span and awarded full marks for
temporal integrity on a dataset whose time axis was unusable.

Sixty-five records in the operational database carry the FILETIME epoch.

### Decision
`is_plausible_timestamp()` plus `MIN_PLAUSIBLE_YEAR` and
`MAX_CLOCK_SKEW_SECONDS` live in `schemas/events.py` and are imported
everywhere. The readiness gate's private copy is gone; the analysis and
feasibility modules now use the shared definition.

The analysis reports `implausible_timestamp_events` and excludes those
records from its range; the UI says so. The feasibility temporal check
**fails** when any are present, naming the count, and its score folds in
the usable fraction of the time axis — a score of 100% beside a failed
check reads as a display bug and invites the reader to dismiss the failure.

A test asserts all three modules report the same span for the same dataset.

### Consequences
- **Positive**: the three numbers agree, and the one that was silently
  wrong now fails loudly. The duplicated policy that allowed them to
  diverge is gone.
- **Negative**: the feasibility gate now fails on the operator's current
  dataset where it previously passed that criterion. That is the correct
  reading of data containing 65 unusable timestamps.

---

## ADR-030: Averages Carry Their Denominator

### Context
The descriptive analysis reported `avg_bytes`, `avg_packets` and
`avg_duration` beside `total_events: 3669`. Only 200 of those records can
measure any of them — the other 3,469 come from the Windows connection
table, which exposes no volume at all. The dashboard did disclose this; the
API payload did not, so any other consumer would read an average over 5% of
the dataset as a property of the dataset.

The feasibility audit had the same shape of error in its class balance:
50 attack labels divided by 3,669 total events gave "1.4% attack" for a
dataset whose labelled portion is 25% attacks. The fraction mixed two
populations.

### Decision
`DescriptiveAnalysis` carries `duration_measured_count`,
`packets_measured_count` and `bytes_measured_count`. The feasibility
`attack_ratio` is computed over labelled events, and the report states
`labelled_events` and `unlabelled_events` alongside it.

### Consequences
- **Positive**: an average can no longer be read as covering more than it
  does, by a human or by an API client.
- **Negative**: `attack_ratio` changes meaning — it was a fraction of all
  events and is now a fraction of labelled events. The old value described
  nothing coherent, so this is a correction rather than a trade-off.

---

## ADR-031: An LSTM, Written in NumPy, Verified Rather Than Trusted

### Context
The blueprint names an LSTM as the intended temporal architecture. Earlier
sessions deliberately withheld one: the data could not demonstrate it added
value, and adding a model to satisfy an architectural label is explicitly
forbidden.

That reasoning covered whether to *claim* an LSTM. It did not cover whether
to *build* one. Building it makes the architecture real and makes the
negative result measurable; what must not happen is the claim outrunning
the evidence.

The practical obstacle was the dependency. PyTorch or TensorFlow is a
large install, outside the agreed boundary, for a model that here operates
on a few hundred sequences of four timesteps.

### Decision
A single-layer LSTM with a sigmoid read-out, trained by backpropagation
through time with Adam, implemented in NumPy — already a dependency, and
entirely adequate at this size.

Because it is hand-written, correctness is **demonstrated, not assumed**:

- **Gradient check.** Every sampled parameter's analytic gradient is
  compared against a central finite difference. Measured worst relative
  error: **1.3e-07**. A subtly wrong BPTT pass still produces a plausible
  loss curve, so the loss curve is not accepted as evidence.
- **Memory check.** The model is trained on a task whose label is visible
  only in the *first* timestep. It reaches **100% holdout accuracy**, and a
  memoryless model on the same task is verified to score below 0.70. The
  recurrence genuinely carries information.

Practical safeguards: forget-gate bias initialised to 1, gradient-norm
clipping, a branch-free numerically stable sigmoid, positive-class
weighting, and standardisation fitted on the training tensor only.

### Consequences
- **Positive**: the intended architecture exists, is evaluated under the
  same target, dataset and purged split as the other five models, and its
  correctness is checkable rather than asserted.
- **The result is negative, and is reported as such.** On 900 synthetic
  events the LSTM scores PR-AUC **0.751**, the worst of the four
  non-baseline models — below logistic regression. It is not promoted,
  hidden, or re-tuned until it wins.
- **Negative**: one layer, fixed epoch budget, no dropout, no early
  stopping, no GPU. It is not a substitute for a mature framework, and
  it is not described as one.
- It changes nothing about the headline caveat: trained on data this
  project generated, its score measures how well it recovers the
  generator's rule.

---

## ADR-032: Generalization Is Reported as a Gap, With Independence Stated

### Context
A chronological split answers "does it predict this environment's future".
It says nothing about "does anything it learned apply elsewhere" — which
is how a security forecaster usually fails in deployment.

A cross-environment score reported alone is unreadable. 0.6 could be a
collapse from 0.95 or a rise from 0.5.

### Decision
`generalization_evaluation()` holds out one group at a time (by
`source_id` or `data_category`), trains on the rest, and scores the
held-out group. Beside it, the **within-group** score is computed by the
ordinary chronological protocol on that group alone, so
`transfer_gap = within − cross` can be read directly.

The report states `independent_environments`. Several synthetic groups
produced by one generator are **not** independent, and in that case the
response carries an explicit warning that a small gap measures the
generator's consistency rather than the model's generality.

Groups that cannot support an interpretable score — one class, too few
instances — are reported with their reason, never dropped. Dropping them
would imply transfer was measured and acceptable.

### Consequences
- **Positive**: the project can now state a generalization result instead
  of listing it as unmeasured, and the result is framed so it cannot be
  read as stronger than it is.
- **Measured, and it is not flattering**: across two synthetic
  environments the mean transfer gap is **0.16 PR-AUC**, and on one
  held-out environment cross-group PR-AUC falls to **0.494** against a
  within-group 0.688. Even between environments from the same generator,
  performance degrades substantially.
- **Still not a real generalization claim.** Both groups are
  `synthetic_demo`. A defensible claim needs environments collected
  separately, which requires the external dataset that has not been
  acquired.

---

## ADR-033: The Build Context Is a Disclosure Channel

### Context
There was no `.dockerignore`. With `context: .` the **entire repository**
is sent to the Docker daemon on every build — including `prahari.db`, two
megabytes of genuine local network telemetry, plus `.git` and anything
under `secrets/`.

The `COPY` instructions are narrow, so none of it would reach the final
image. It would still leave the machine: a build context is transferred in
full, is recoverable from the daemon, and is routinely captured in CI
logs. "It is not in the image" is not the same as "it was not sent".

### Decision
A `.dockerignore` excluding databases and their WAL/SHM sidecars,
`secrets/`, `*credentials*.json`, `experiments/`, `.env*`, `.git/`,
caches, virtualenvs and tests.

Because Docker is not installed on this host, the container configuration
is validated **statically** instead: 18 tests assert that the ignore file
covers each sensitive path, that the Dockerfile's `/frontend/dist` target
matches the path `main.py` actually resolves, that the database URL has
four slashes (three would place telemetry in the container's ephemeral
writable layer), that the runtime user owns `/data`, that the published
port is loopback-only, and that no credential material is baked into a
layer.

### Consequences
- **Positive**: the most likely way this project would leak telemetry is
  closed, and the configuration's invariants are now checked rather than
  reviewed by eye.
- **Negative, and stated plainly**: static validation is **not** a runtime
  check. The image has never been built or run here. Nothing in these
  tests is evidence that `docker build` succeeds.
- The obsolete Compose `version` key was removed and the loopback binding
  given a comment explaining why it must stay.

---

## ADR-034: The "Best Model" Badge Is Derived, Not Written In

### Context
The forecasting table marked `random_forest_forecaster` as best with a
hardcoded string comparison, whatever the evaluation returned. With a
temporal model and an LSTM now competing on the same split, the badge
frequently sat on a model the evaluation had not chosen — in the recorded
run, on the *second* best.

An operator reads a "best" badge as a result. A wrong one is worse than
none.

### Decision
`bestModelId()` derives it from the measured PR-AUC, excluding baselines,
and returns `null` when nothing is scored rather than falling back to a
default. Baselines are excluded deliberately: a baseline beating every
real model is an important finding about the data, but it is not a model
to point an operator at.

### Consequences
- **Positive**: the badge now reports a measurement. A genuine `0` counts
  as a score; `undefined` and `NaN` do not.
- Worth stating alongside it: on the recorded run the 95% bootstrap
  intervals for the top three models **overlap heavily** (temporal
  [0.776, 0.965], random forest [0.750, 0.950], LSTM [0.596, 0.891]). The
  badge marks the highest point estimate; it is not evidence that one
  model is better than another on 49 held-out instances.

---

## ADR-035: Research Data Lives in Its Own Database, and the Path Fails Closed

### Context
The operational database holds genuine network observations collected from
this host over time. It is the only copy. A benchmark corpus is a
third-party artefact with its own labels, units, provenance and licence.

Before this change, `POST /import/csv/*` wrote wherever `get_db` pointed —
which in a normal deployment is the operational database. A single mis-aimed
benchmark import would have mixed millions of foreign rows into the
operator's live telemetry record, irreversibly and without a prompt.

### Decision
A separate `PRAHARI_RESEARCH_DATABASE_URL`, resolved by
`app/core/research_store.py`, which **raises rather than returning a
fallback** when it is missing, is not a supported SQLite target, resolves to
an operational database, or names a directory that does not exist.

Collision detection compares canonical resolved paths, so `..` segments,
symlinks and the legacy `backend/prahari.db` are all caught. The check runs
twice: once on configuration, and again on the database handle actually in
hand, so a caller that obtained its connection another way is still stopped.

The general CSV endpoints keep working for ad-hoc files but refuse
`data_category=historical_import` when the target is the operational
database, naming the research endpoint in the refusal.

### Consequences
- **Positive**: the one irreversible accident available in this codebase is
  closed, and closed before any write rather than detected afterwards.
- **Negative**: research imports now require configuration that did not
  exist before. That is the intended cost — the alternative is a default
  that silently does the wrong thing.
- Imports into any non-operational database (tests, scratch files) are
  unaffected, so no existing behaviour changed.

---

## ADR-036: An Import Must Declare What Cannot Be Inferred From the Bytes

### Context
`csv_import.py` is a permissive reader: it tries timestamp formats in order
and takes the first that parses, maps `Flow Duration` straight into a field
documented as seconds, and maps `Tot Fwd Pkts` into a field documented as a
total. Each is a reasonable convenience for an ad-hoc file and a defect for
a benchmark corpus, because none of them fails — they produce plausible
numbers that are wrong.

Three in particular:

* `02/03/2018` parses under `%d/%m/%Y` **and** `%m/%d/%Y`. Whichever is
  tried first wins, silently, and chronological order is the foundation of
  every window, split and purge in this project.
* CICFlowMeter's `Flow Duration` is microseconds. Stored unconverted in a
  "seconds" field, a 2.5-second flow becomes 2.5 million seconds.
* `Tot Fwd Pkts` is one direction of a bidirectional measurement.

### Decision
A separate strict adapter, `adapters/research_csv.py`, that refuses what it
cannot establish. The operator declares `timestamp_format`,
`source_timezone`, `duration_unit` and whether bidirectional counts are
required; the policy is recorded in the import manifest.

- `auto` **rejects** an ambiguous slash date rather than resolving it.
- `source_timezone=None` is preserved as unknown and flagged on the events.
  It is never silently called UTC.
- `duration_unit=unknown` means the column is **not imported**.
- A forward-only file leaves `packets`/`bytes_total` empty rather than
  reporting half a measurement under a total's name.

The permissive adapter keeps its role but no longer resolves ambiguous
dates, and now distinguishes missing / malformed / non-finite /
invalid-negative instead of collapsing all four to `None`.

### Consequences
- **Positive**: a benchmark import either carries declared semantics or does
  not happen. Every unit conversion is recorded.
- **Negative**: more configuration, and some files will be refused that the
  permissive adapter would have accepted. A refusal is recoverable; a
  silently misread corpus is not.

---

## ADR-037: Identity From File Bytes and Row Position, Not a Fresh UUID

### Context
Every imported row received `uuid.uuid4()`. Re-importing a file therefore
duplicated the entire corpus — `INSERT OR IGNORE` cannot deduplicate
identifiers that are new every time. Duplicate near-identical flows then sit
on both sides of a train/test boundary, which is textbook leakage, and the
experiment manifest's dataset fingerprint changes on every re-import.

### Decision
`sha256(source_file_sha256 | row_index | normalised_row_content)`.

File-and-row identity rather than content alone, deliberately: two
genuinely distinct flows can have identical feature values, and collapsing
them would delete real observations. Near-duplicate content is therefore
**counted and kept**, reported separately from exact duplicates.

The trade-off, stated because it is real: the same corpus re-released under
different bytes is treated as a different dataset. That is the conservative
direction — it over-counts rather than silently discarding data.

Existing event identity behaviour elsewhere is untouched; this applies to
the research import path only.

### Consequences
- **Positive**: re-importing a file persists nothing new, verified by test.
- **Negative**: a corpus re-exported with trivially different bytes imports
  again as new events. The manifest's source hash makes that visible.

---

## ADR-038: Provenance Filtering and Coverage Are Reported, Not Assumed

### Context
`POST /forecast/train` selected by `source_id` alone. A source id is a name
an operator chose; it carries no guarantee. Training without one pooled
labelled benchmark data with unlabelled live telemetry — two populations
with different label semantics and different measurement units — and
nothing recorded that it had happened.

Separately, `list_events` applies `ORDER BY observed_at DESC LIMIT n`. Ask
for 100,000 events from a multi-million-row corpus and you get the newest
100,000: the tail of the final capture day. Every metric then describes a
slice nobody chose, with no indication in the response.

### Decision
`research/selection.py` filters on `data_category` — the authoritative
provenance field — and **refuses** a selection spanning benchmark, live and
generated classes unless `allow_mixed_provenance=true`, recording the
composition when it is allowed.

It also returns a `SelectionCoverage`: selected against total matching,
truncation flag, coverage fraction, selection strategy, time range, and the
source / category / provenance / label breakdowns. Exposed at
`GET /forecast/coverage`. Selection is re-sorted chronologically at this
boundary rather than relying on each consumer to sort defensively.

### Consequences
- **Positive**: a truncated or mixed experiment says so in its own output.
- **Negative**: callers that previously trained across everything now get a
  409 and must choose. That is the point.

---

## ADR-039: Ongoing Attacks Are Counted, and a Persistence Baseline Runs

### Context
A window whose **observation** period already contains attack-labelled
events is not a clean pre-attack forecast. Predicting "attack soon" from
"attack now" is detection. On bursty data — a 98-minute DDoS episode spans
many consecutive windows — most positives are of exactly this kind, and
reporting the result as forecasting overstates what was demonstrated.

Relatedly, the strongest baseline for such data was missing: carry the
current state forward.

### Decision
The windowing report counts `windows_with_attack_in_observation` always,
and can exclude them (`exclude_ongoing_attack_windows`). Excluding is not
the default, because it also discards most positives on bursty data; the
count is visible either way so the choice is informed.

`PersistenceBaseline` predicts from the observation-window attack indicator
alone. That indicator describes `[t-W, t)`, strictly before the target
interval `[t+L, t+L+H)`, so no future label is used. It is passed in
separately rather than added to the feature matrix — a feature meaning "an
attack is in progress" would hand every model the same shortcut and turn the
whole evaluation into detection.

### Consequences
- **Positive**: the comparison now includes the baseline most likely to
  expose a task as trivial. In one recorded synthetic run it reached PR-AUC
  **0.755, above the LSTM's 0.751**.
- **Negative**: episode-aware splitting is still not possible — the schema
  carries no episode identifier, and inventing one would be fabricating
  structure. Splitting remains time-blocked and chronological, and that
  limitation is documented rather than worked around.

---

## ADR-040: Truncated Coverage and Degenerate Predictions Are Structured State

### Context
The synthetic rehearsal surfaced two results that were arithmetically
correct and misleading to read.

**Window truncation was prose.** When generation hit `MAX_WINDOWS` the only
record was a sentence in `WindowingReport.notes`. A caller could not tell a
partial evaluation from a complete one without parsing English, so a
20,000-window slice of a 143,751-window span looked exactly like full
coverage.

**Degeneracy was invisible.** Five models returned identical chance-level
metrics with `metrics_interpretable=True`, because that flag asked only
"were both classes present and were there at least 20 instances". It did
not ask whether the model made any distinction. A constant predictor scores
precision equal to the base rate and recall 1.0 — figures that read as a
weak-but-real result.

### Decision
Separate the claims that were being collapsed.

**Window coverage** gains four counts with distinct meanings:
`windows_eligible` (what the span and stride allow, computed from the same
loop bound rather than estimated), `windows_considered` (what the loop
examined), `windows_generated` (instances emitted — the rest were dropped
by the label-validity rules, not by the cap), and `windows_omitted`.
`windows_truncated` is the structured signal; the note remains for a human
reader but is no longer the source of truth. `require_complete_windowing`
raises `WindowCoverageIncomplete` when a caller needs completeness, and the
partial report travels with the exception.

This is kept deliberately apart from `SelectionCoverage.truncated`, which
reports a **record**-count cap. Different objects, different field names:
an evaluation can be limited by either, or both, and one must not mask the
other.

**Evaluation validity** becomes four questions instead of one:

| Field | Question |
|---|---|
| `metrics_computable` | Are the figures mathematically defined (both classes present)? |
| `sample_adequate` | Is the holdout large enough to mean anything? |
| `predictions_degenerate` | Did the model emit one class, or rank nothing? |
| `discrimination_demonstrated` | Did PR-AUC exceed the no-skill base rate? |

Metrics are **preserved, never blanked** — a degenerate model's precision
is a real number about a real prediction. What changes is that the
surrounding state says what kind of number it is.

`no_skill_pr_auc` is the positive base rate, which is the principled
reference for PR-AUC rather than an arbitrary cutoff: random ranking
achieves exactly that value. `discrimination_demonstrated=True` therefore
means "better than chance **on this sample**" and nothing more — it is not
a claim that the model is useful.

### Consequences
- **Positive**: a truncated run and a chance-level model each announce
  themselves in machine-readable state. The dashboard shows `Degenerate`,
  `No skill` and `Inconclusive` badges, and `bestModelId()` refuses to
  crown a model that demonstrated nothing.
- **Negative**: `ModelMetrics` grew nine fields. They are not derivable
  from one another, and collapsing them is what caused the problem.
- `metrics_interpretable` is retained as the composite (computable AND
  adequate) so existing consumers keep working, but it is explicitly no
  longer the whole answer.
- The contract test caught the new `WindowingReport` interface as unpaired
  and refused the suite until it was registered — working as intended.

---

## ADR-041: Time-Indexed Window Extraction

### Context
`build_dataset_instances` re-scanned the entire event list **twice per
window** — once for the observation interval, once for the horizon:

```python
obs_events    = [e for e in sorted_events if window_start <= e.observed_at < window_end]
future_events = [e for e in sorted_events if target_start <= e.observed_at < target_end]
```

That is O(events x windows). Measured on 2,000 events and 3,989 windows,
the interval scans account for essentially the whole runtime; everything
else — sorting, feature arithmetic, label checks — is incidental.

The waste compounds on sparse data. A rejection-heavy corpus examined
20,000 windows and emitted 332: both intervals were materialised for
19,668 windows that were then discarded because the horizon was empty.

This is also why the window cap, rather than the data, decided how much of
a corpus got evaluated.

### Decision
The events are already sorted, so interval boundaries are two binary
searches rather than a scan.

- `bisect_left` at **both** ends, because every interval is `[lo, hi)`:
  the low index is the first event at or after the start, the high index
  the first at or after the end. Equal timestamps fall in the same slice,
  and since `sorted` is stable their order is the input order — identical
  to the comprehension.
- Prefix sums over "is an attack label" and "has any label" answer the
  horizon and observation questions in O(1), replacing `any(...)` scans.
- The observation slice is **materialised only when a window is emitted**.
  A rejected window now costs two binary searches and two subtractions.

What deliberately did **not** change:

- The observation features are still computed exactly, per window, from
  the materialised slice. Distinct source/destination/port counts cannot
  be maintained incrementally across a sliding window without a multiset,
  and with stride ≠ window size the windows do not nest. The correct
  implementation is kept and the cost accepted.
- `MAX_WINDOWS` is unchanged. Raising it to improve apparent coverage
  would be hiding the limit, not fixing it.
- `windows_with_attack_in_observation` is still incremented **before** the
  horizon-rejection checks, so it still counts windows that are later
  rejected. Reordering for speed would silently lower it.

### Consequences
- **Positive**, measured locally on synthetic fixtures (best of 3):

  | events | windows | reference | optimized | speedup |
  |---|---|---|---|---|
  | 500 | 989 | 37 ms | 4 ms | 8.9x |
  | 2,000 | 3,989 | 499 ms | 17 ms | 30x |
  | 8,000 | 15,989 | 10,541 ms | 75 ms | **141x** |

  Growth from 500 to 2,000 events: 13.5x before, 4.0x after — matching
  the 4x increase in events rather than compounding with window count.

- **Memory** grows slightly, 4.68 to 4.96 MiB peak at 4,000 events: two
  integer prefix arrays of length n+1. Bounded and linear.
- Equivalence was established before adoption across 88 fixture-by-
  configuration pairs — features, labels, observation masks, timestamps,
  every counter and every note — plus below/at/over the cap and the
  `require_complete_windowing` refusal.
- **Not a complexity proof and not a claim about real-corpus scale.**
  These are local measurements on modest synthetic fixtures.

---

## ADR-042: One Empty-Dataset Shape, and Coverage Counters That Add Up

### Context
Two accounting defects, both found by writing the test rather than by a
failure in production.

**Inconsistent empty shape.** `build_dataset_instances` returned
`(0, n_features)` from its early-exit paths and `(0,)` when the window loop
ran but emitted nothing. `stack_lagged_windows` reads `X.shape[1]`, which
is an IndexError on the one-dimensional form. The crash was unreachable
only because the pipeline refuses fewer than four instances first — a
guard, not a contract.

**Counters that could not add up.** When time-based windowing produced no
slices, the event-count fallback ran and incremented
`windows_excluded_unlabelled_horizon` **without** incrementing
`windows_considered`. Measured on a 400-event unlabelled corpus:
considered 124, excluded 130. More windows were rejected than were ever
examined, which reads as a corrupt report. `windows_generated` was already
set from `len(X_list)` *after* the fallback, so it included fallback
output while `windows_considered` did not.

### Decision
A single `_empty_dataset()` helper used by every no-data return path,
producing `(0, len(FEATURE_NAMES))` float32 with an int32 label array —
the same shape and dtype from all three exits.

Fallback chunks are counted in `windows_considered` and in
`windows_eligible`, and tracked separately as
`fallback_chunks_considered` / `fallback_chunks_excluded` so the two
populations stay distinguishable. The identity
`considered == generated + rejected` and the ordering
`eligible >= considered >= generated` now hold on every path.

The fallback is still reported as `used_fallback_chunking`, and its note
still says the stated durations do not apply to event-count chunks. These
are not time windows; they are counted alongside them because they produce
instances and omitting them made the arithmetic incoherent.

### Consequences
- **Positive**: a caller can read `X.shape[1]` unconditionally, and the
  coverage report can be trusted to balance.
- Equivalence against a pre-change snapshot across 88 fixture-by-
  configuration pairs shows **exactly 14 differences, all intended**:
  8 are the shape change on the `one_event` fixture, 6 are the fallback
  counter change on three fixtures. The other 74 pairs are unchanged.
- **Negative**: `windows_eligible` now mixes two notions on the fallback
  path — time windows the span allowed, plus chunks examined. The
  alternative was leaving eligible below considered, which is worse.

---

## ADR-043: `duplicate_rows_exact` Counts Repeated Row Text

### Context
The counter was permanently zero for any single-file import, and nothing
said so.

Event identity is `sha256(file_sha | row_index | content)` by design
(ADR-037), so two rows in one file can never collide: the row index
differs. The counter therefore measured something that could not happen,
while a real and documented CICFlowMeter artefact — the same raw row
appearing twice — went uncounted.

### Decision
`duplicate_rows_exact` counts rows whose **raw text is byte-identical** to
an earlier row. `near_duplicate_flows` keeps its existing meaning: the
canonical fields (time, 5-tuple, label) match an earlier row. The second
is a superset of the first, and that overlap is documented rather than
engineered away — an operator auditing a corpus wants both numbers.

**Neither counter filters anything.** Both rows are stored. Two flows with
identical values may be two real events, and dropping one would delete an
observation; this is the same reasoning as ADR-037 and it has not changed.

The identity-collision check is retained as a guard for a caller that ever
feeds concatenated input, but is no longer the source of the count.

### Consequences
- **Positive**: a dead counter now reports a real property, and the two
  duplicate notions are distinguishable.
- **Negative**: the counters overlap by construction, so they must not be
  summed. Documented in the field comments and in the tests.
- The previous test asserted `duplicate_rows_exact == 0` for two identical
  rows — it was asserting the dead behaviour. Replaced with three tests
  covering byte-identical rows, canonically-equal-but-textually-different
  rows, and fully distinct rows.

---

## ADR-044: A Reported Configuration Must Describe the Run It Reports

### Context
`WindowingReport` stored the effective window, lead, horizon and stride
rounded to three decimals, while the loop ran on the unrounded floats.
On a rescaled fixture, re-deriving the window count from the report gave
40 where the run produced 39.

Found while removing an over-broad skip from the equivalence harness: the
reference, which reads the reported configuration, disagreed with
production by one window. The reference was right.

A one-window difference is small. The property it violates is not: this
project's central claim is that an evaluation can be reproduced from its
recorded parameters, and those parameters did not describe the run.

### Decision
Round once, before the loop, and use the rounded values for both the loop
and the report.

### Consequences
- A run is now reproducible from its own reported configuration, asserted
  by `test_reported_effective_config_reproduces_the_run`.
- Window counts shift by at most one on **rescaled** datasets only;
  unrescaled runs are unaffected because the values were already whole.
- Against a pre-change snapshot this accounts for 6 of 17 differences
  across 88 fixture-by-configuration pairs, all on rescaled fixtures.

---

## ADR-045: The Event-Count Fallback Must Honour the Ongoing-Attack Exclusion

### Context
A control that produced its own opposite.

`exclude_ongoing_attack_windows=True` drops windows whose observation
period already contains an attack, so an evaluation measures prediction
rather than detection. On a dense-attack dataset that can drop *every*
candidate — which empties `X_list` and triggers the event-count fallback.

The fallback did not check the flag. It re-emitted chunks whose
observation period contained attacks, so the caller received a dataset in
which **every instance had an attack already underway** — while
`windows_excluded_ongoing_attack` reported the control as having worked.

Measured on the `duplicate_timestamps` fixture before the fix:

| run | rows | fallback | instances with an attack in observation |
|---|---|---|---|
| `exclude=False` | 10 | no | 10 |
| `exclude=True` | 7 | **yes** | **7 — all of them** |

This is worse than the flag doing nothing. Doing nothing is visible; this
was silently inverted and the report corroborated the wrong answer.

### Decision
The fallback applies the same exclusion, and counts the chunks it drops in
`windows_excluded_ongoing_attack` and `fallback_chunks_excluded`.

### Consequences
- After the fix the same fixture yields **0 rows** under exclusion, with
  the observation-attack mask summing to zero. Empty is the honest answer:
  that dataset contains no clean pre-attack instance.
- A regression test asserts the mask sums to zero whenever exclusion was
  requested, and a second asserts the fix does not empty datasets that do
  have clean windows.
- Accounts for 3 of the 17 snapshot differences.
- The remaining fallback asymmetry is documented, not changed: the
  fallback does not increment `windows_with_attack_in_observation`,
  because the time-window loop runs first and already accumulates it.

### Note on the equivalence harness
The over-broad skip that hid this has been removed. The reference now
mirrors the fallback path, and the harness runs **143 tests with zero
skips** — previously 63 passed and 6 were skipped. The two defects above
were both inside the skipped region.

---

## ADR-046: PraHari Reports Ingest Lag, Not Clock Skew

### Context
The next-phase plan put clock-skew estimation first, because every window,
split and purge depends on timeline order and nothing detected a wrong
clock. Inspecting the schema before designing changed the answer.

What actually exists on a stored event:

| Field | Meaning |
|---|---|
| `observed_at` | event time, as stated by the source |
| `ingested_at` | set by a `default_factory` **when the backend constructs the event** — close to receipt, but not a transport timestamp |

What does not exist anywhere in `app/`: a monotonic clock, a sequence
number, a round-trip measurement, or any other reference. `grep` for
`monotonic`, `perf_counter` and `seq` returns nothing, and no adapter
overrides `ingested_at`.

Measuring skew requires comparing a source's clock against a trusted
reference at a known instant. **PraHari has no such reference.** The only
available quantity is

    ingest_lag = ingested_at - observed_at

which is clock offset **plus** collection latency, transport, queueing and
processing — with no way to separate the terms. Shipping that as "skew"
would attribute the whole of it to one cause the data cannot isolate.

### Decision
`app/services/clock_integrity.py` reports **ingest lag**, named as such,
with its limitations carried in the response rather than in documentation
someone has to go and find.

One rigorous inference is drawn, and only one. Delay cannot be negative —
an event cannot be normalized before it happened — so a negative lag of δ
proves the source's clock leads this host's by **at least** δ:

    clock_ahead_lower_bound = -min(ingest_lag)   when min(ingest_lag) < 0

That is a bound, not an estimate. A **positive** lag supports no skew claim
whatsoever, however large or consistent, and the module says so explicitly
rather than leaving a reader to infer it.

Also reported: sample counts, the interval covered, percentiles,
implausible-timestamp exclusions, timezone-uncertainty counts, and backward
ordering steps — with the causes of a backward step listed (clock
adjustment, out-of-order delivery, a batch of older records) and an
explicit statement that this diagnostic cannot distinguish them.

`INSUFFICIENT_EVIDENCE` is a first-class verdict. Below 30 usable samples
no verdict is offered, though the statistics still are.

**No timestamp is modified.** Diagnosing a clock is not a licence to
rewrite what a source reported; the stored data must continue to agree with
the source's own records.

### Consequences
- **Positive**: a source whose clock runs fast is now detectable, with a
  defensible lower bound. The common case — a consistently offset clock
  producing a consistently offset positive lag — remains undetectable, and
  that is stated rather than papered over.
- **Negative**: the headline capability the plan asked for cannot be
  delivered from the current schema. Real skew measurement needs a
  submission-time timestamp recorded by the receiver, which is Stage-B
  work on the ingest path.
- A defect was found by driving the endpoint rather than by a unit test:
  the ordering check walked the supplied order, but
  `Database.list_events` returns `ORDER BY observed_at DESC`, so every
  well-behaved source was reported as a continuous backward march.
  Ordering is now assessed by arrival (`ingested_at`), with ties from bulk
  inserts excluded. Two regression tests pin it.

---

## ADR-047: Source Health States Describe PraHari's Evidence, Not the Host

### Context
`TelemetrySource.last_event_at` is maintained by
`Database.refresh_source_activity` as the maximum **`observed_at`** of a
source's events. It is event time, stated by the source — not the time
PraHari last heard from anyone.

Two consequences follow directly, and neither was previously visible:

* A source whose clock runs **fast** looks fresher than it is, and can
  appear healthy while silent.
* A source whose clock runs **slow** looks staler than it is, and can be
  reported silent while reporting normally.

So source health and clock integrity are not two problems. They are one.

There is also no heartbeat. A source with nothing to report is
indistinguishable from one that has died.

### Decision
`app/services/source_health.py` classifies each source into states that are
statements about **PraHari's evidence**, never about a remote machine:
`REPORTING`, `STALE`, `SILENT`, `NEVER_SEEN`, `DISABLED`, `ERROR`,
`UNKNOWN`.

Specific choices worth recording:

- **`SILENT` never means disconnected.** The wording is "PraHari has not
  heard from it; whether it is running is unknown."
- **`NEVER_SEEN` is distinct from `SILENT`.** Nothing has ever been heard,
  which is a different operational situation from something that stopped.
- **A recorded error outranks apparent freshness**, because a source can
  fail immediately after its last successful event.
- **A `last_event_at` in the future yields `UNKNOWN`, not `REPORTING`.**
  Delay cannot be negative, so that is clock evidence, not freshness
  evidence, and no freshness judgement is made.
- **Inconsistent counters yield `UNKNOWN`** rather than a guess — an
  `event_count` above zero with no `last_event_at` means the record cannot
  be trusted.
- Every response carries `freshness_basis` and `clock_dependent: true`, so
  a consumer cannot read freshness as receipt-based by accident.

Thresholds are parameters (`fresh_seconds`, `stale_seconds`), defaulting to
5 minutes and 1 hour, and inverted thresholds are rejected rather than
silently reordered.

### Consequences
- **Positive**: a dead source is visible for the first time, and the states
  say exactly how much is actually known.
- **Negative, and the real finding**: freshness remains only as trustworthy
  as each source's clock. That is reported on every record and linked to
  `GET /sources/clock-integrity` rather than hidden.
- No heartbeat was invented. Fabricating synthetic heartbeat events to make
  the states cleaner would have made the data say something nobody
  observed.

---

## ADR-048: `received_at` — a Server-Measured Receipt, Recorded Only Where One Exists

### Context
Phase 1 established that PraHari could not measure clock skew because it
had no reference clock. The only server-side timestamp was `ingested_at`,
set by a `default_factory` **when the event object is constructed** —
which for a bulk import is normalization time, bearing no relation to when
the data arrived.

Tracing every path that persists an event (`grep insert_events`) showed
three distinct situations, which a single timestamp was conflating:

| Path | Location | Is there a receipt? |
|---|---|---|
| NDJSON sensor submission | `api/v1/stream.py:53` | **Yes** — a remote process sent it over HTTP |
| Browser producer | `api/v1/applayer.py:197` | **Yes** |
| Windows collector poll | `services/collector.py:444` | No — the backend produced it |
| UDP endpoint poll | `api/v1/hostobs.py:131` | No — same |
| CSV / research import | `api/v1/imports.py`, `research_import.py` | No — the *file* arrived now; the events did not |
| Synthetic replay | `api/v1/stream.py:123` | No — generated |

### Decision
A nullable `received_at` column on `normalized_events`, captured at the API
boundary **only** on the two genuine submission paths, before any parsing,
so a large or slow batch cannot push the recorded receipt later than the
actual arrival.

Three properties follow deliberately:

- **The client cannot supply it.** No request model carries the field; an
  injected `received_at` in the JSON body is ignored. A source could
  otherwise backdate its own arrival.
- **`NULL` means "not measured"** and is never backfilled or inferred. A
  locally collected event, an imported corpus and a pre-migration row all
  keep `NULL`, and remain distinguishable from a measured receipt.
- **One arrival, one receipt.** Every event in a batch shares the boundary
  timestamp rather than each row re-reading the clock during parsing.

The nullable additive column uses the project's existing `_ADDED_COLUMNS`
mechanism, so an existing database migrates in place without a rewrite and
without touching its rows.

### Why a column rather than a separate ingestion table
Both diagnostics read receipt alongside the event. A separate table would
add a join to every read and a foreign key for a single nullable scalar.
The additive-column path already exists in this codebase and was built for
exactly this.

### Consequences
- **Positive**: the clock diagnostic now has a reference whose assumption
  actually holds, and source freshness can be judged on evidence the
  backend measured itself rather than on the source's own claim.
- **Negative**: receipts exist only for events arriving after this change.
  Historical rows are permanently `NULL`, which is correct but means the
  diagnostics stay weak for existing data.
- A retry does not rewrite an existing receipt: `INSERT OR IGNORE` leaves
  the stored row untouched, so the first arrival remains the recorded one.

### Finding recorded, not fixed
`/stream/ingest/ndjson` is **not idempotent**. The adapter assigns
`uuid.uuid4()` per row (`adapters/json_stream.py:319`), so a re-submitted
batch is stored as new events — a sensor retrying after a timeout
double-counts its own telemetry. The research CSV importer (ADR-037) and
the Windows collector both derive deterministic ids and are idempotent;
this path is the exception.

Changing event identity on a live ingestion route was a larger change than
adding a receipt timestamp, so it was pinned by
`test_the_stream_path_is_not_idempotent_on_retry` with its consequence
stated, and recommended as the next phase.

**Closed by ADR-050** for senders that supply an event identifier or a
batch idempotency key. It remains open, deliberately, for legacy senders
that supply neither — see that record for why content equality was not
used to close the gap for them.

---

## ADR-049: Freshness Prefers Measured Receipt, and Still Does Not Mean "Healthy"

### Context
Phase 1 reported source freshness from `last_event_at`, which
`refresh_source_activity` maintains as `max(observed_at)` — **event time,
stated by the source**. A source whose clock runs fast therefore looked
fresher than it was and could appear healthy while silent.

With `received_at` available, a second basis exists that does not depend on
the source's clock at all.

### Decision
`evaluate_source_health` accepts an optional `last_received_at` and
**prefers it** when present, falling back to event time otherwise. Which
basis was used is reported on every record:

| Field | Meaning |
|---|---|
| `receipt_evidence_available` | whether the backend measured an arrival |
| `clock_dependent` | `false` on a measured receipt, `true` on the fallback |
| `freshness_basis` | the basis in words |
| `seconds_since_last_event` | still reported, so the two can be compared |

`Database.latest_received_at_by_source` supplies them, counting only
non-NULL receipts — a source that has never submitted over the API is
simply absent rather than given a fabricated one. It tolerates a
pre-migration database by returning no evidence at all.

### What has NOT changed
A measured receipt establishes that **this backend received data at time
T**. It does not establish that the endpoint is currently connected,
running or healthy, and the limitation now says so explicitly on every
record carrying receipt evidence.

`SILENT` still never means disconnected. No heartbeat was invented. A
source with nothing to report remains indistinguishable from one that has
stopped — that gap closes only with a real heartbeat, which is Stage-B
work.

### Consequences
- **Positive**: the specific failure Phase 1 identified is closed. A source
  whose clock claims an event five seconds ago, but which the backend last
  heard from three days ago, now reports `SILENT` rather than `REPORTING`.
  Pinned by
  `test_health_prefers_a_measured_receipt_over_a_skewed_event_time`.
- **Negative**: only sources submitting over the API gain this. Locally
  collected sources keep event-time freshness and say so — for those the
  two clocks are the same one, so the weakness does not apply.

---

## ADR-050: Stream Event Identity — an Opt-In Protocol, and What It Does Not Bind

### Context
ADR-048 recorded that `/stream/ingest/ndjson` was not idempotent: the
adapter assigned `uuid.uuid4()` per row, so a sensor retrying after a
timeout double-counted its own telemetry. Every window, rate and forecast
feature downstream is computed from those counts.

The fix had to avoid the opposite error. Deriving identity from content
would make two genuinely distinct events — the same host pair, the same
port, the same second — into one, which corrupts the data in the other
direction and is harder to notice.

### Decision: three tiers, in order of preference

1. **A sender-provided identifier** (`event_id`, Zeek `uid`, `uuid`,
   `record_id`, or a scalar `id`), hashed with the source into a UUIDv5 as
   `urn:prahari:source:<source>:event:<id>`. Source-scoped, so two sensors
   using the same local counter cannot collide.
2. **A batch idempotency key** (`idempotency_key` in the body, or the
   `Idempotency-Key` / `X-Idempotency-Key` header) combined with the record
   index: `urn:prahari:source:<source>:batch:<key>:record:<n>`.
3. **`uuid.uuid4()`** for a sender supplying neither — unchanged legacy
   behaviour.

Content is never used as identity. A sender that supplies no identity gets
no idempotency, and that is the honest outcome: the backend alone cannot
retrofit retry safety onto a client that does not identify what it sends.

### The canonical identity-conflict policy

Re-using an identity with different content must not silently discard the
difference. The first implementation compared only `source_id`,
`observed_at` and the five-tuple — so a changed **byte count, packet
count, duration, event type or label** was dropped in silence while the API
returned HTTP 200 and reported the record as accepted. Measured directly
before the fix: five separate mutations, all `200 / accepted_records=1`,
with the stored row unchanged.

`CONFLICT_FIELDS` in `storage/database.py` now compares all twenty
persisted fields that assert something about the observation: provenance
and time (`source_id`, `observed_at`, `data_category`), `event_type`, the
five-tuple, the measurements (`duration`, `packets`, `bytes_total`), the
training target (`label`, `label_provenance`), and the application layer
(`app_protocol`, `http_method`, `http_path`, `http_status_code`,
`http_duration_ms`, `dst_hostname`).

Six fields are excluded, each for a stated reason, listed in
`CONFLICT_FIELDS_EXCLUDED`: `event_id` is the identity being checked;
`ingested_at` and `received_at` differ on every redelivery by construction,
so comparing them would make every legitimate retry a conflict;
`raw_reference` is the record's **position** in the submitted batch, and
the same event resent at a different position is still the same event;
`schema_version` describes the encoding, and any real change it causes
surfaces in the compared values themselves; `quality_flags` are derived by
the normalizer from the compared fields rather than asserted by the sender.

A conflict raises `EventIdentityConflictError`, which the endpoint turns
into **HTTP 409** naming the differing fields. The stored event is never
modified.

### The response distinguishes stored from parsed

`accepted_records` counts what parsed and validated. It said the same thing
whether a batch was written or was a complete retry. `ImportSummary` now
also carries `stored_records` and `duplicate_records`, optional and `None`
on paths that do not report storage. Neither is persisted — the
`import_summaries` insert names its columns — so no migration is required.

A 409 is also written to the audit log. A refusal that leaves no trace is
indistinguishable from a request that never arrived.

### What a batch key does NOT bind — measured, not assumed

The key binds `(key, record index)` to an identity. It does **not** bind
the batch as a whole, and each case below has a test:

| Retry shape | Behaviour |
|---|---|
| Identical batch | Nothing stored; `duplicate_records` equals the batch size |
| Content changed at an index | **409**, whole batch rolled back |
| Records reordered | **409** — content lands on indices already taken |
| Shorter batch | Accepted, nothing stored; **the missing tail is not detected** |
| Longer batch | The extra records append at fresh indices |
| Same key, different source | Independent; no collision |

The shorter-batch case is a real boundary, not an oversight: a truncated
retry is indistinguishable from a retry of a prefix. Binding the whole
batch would need a digest of its contents carried by the sender, which is
a protocol change requiring sender coordination.

### Transactions and concurrency

`get_connection` commits on success and rolls back on any exception, so a
conflict anywhere in a batch discards the **entire** batch — verified, not
assumed. Deduplication itself rests on `INSERT OR IGNORE` against the
primary key, which is atomic, so the check-then-report sequence cannot race
into a double insert; SQLite serializes writers.

### The guarantee, stated precisely

**Not exactly-once delivery.** What holds: for a sender supplying a stable
event identifier or a batch key, redelivering the same logical event stores
at most one copy, and redelivering it with different content is refused
rather than silently merged. For a sender supplying neither, a retry still
duplicates. Nothing here detects a sender that invents a fresh identifier
for an event it already sent.

---

## ADR-051: The Ingestion Trust Boundary — Authenticated Identity Decides Where Telemetry Is Filed

### Context
Central mode already had the hard parts. `core/security.py` mints
high-entropy tokens, stores only PBKDF2-HMAC-SHA256 hashes with per-credential
salts, compares in constant time, separates `ingest` / `read_only` / `admin`,
and refuses to start without a credential store. `api/auth.py` installs
default-deny middleware that authenticates every non-public request and
attaches a `Principal`.

None of it was applied to ingestion. A single grep settles it:

```
$ grep -rn "scope_source|require_principal|require_admin" app/api/v1/
app/api/v1/events.py  ->  scope_source
```

One read path. Every write path — `/stream/ingest/ndjson`,
`/stream/replay/synthetic`, `/applayer/ingest`, `/import/csv/raw`,
`/import/csv/file`, `/research/import/csv` — took `source_id` from the
request body verbatim. `Principal.may_write()` was defined and called
nowhere. `require_admin` was defined and called nowhere.

So in central mode a sensor holding a valid credential for `sensor-a` could
post `{"source_id": "sensor-b", ...}` and the telemetry was stored as
sensor-b's. Measured, not inferred: with enforcement removed under a
monkeypatch, that request returns **HTTP 200** and one event appears under
`sensor-b`.

The impact is wider than mislabelled rows. ADR-050 scopes event identity by
source, so the claimed `source_id` also selects the **idempotency
namespace** — a caller could mint UUIDv5 collisions inside another source's
namespace, either 409-ing that source's legitimate events or merging with
them. Source health and clock integrity then describe a source that never
sent the data.

### Decision
One function, `resolve_ingest_source(request, claimed)`, is the ingestion
trust boundary. Every write path calls it **before parsing or registering
anything**, and everything downstream derives from its return value: the
adapter id, the idempotency namespace, `event.source_id`, the auto-registered
`TelemetrySource`, the import summary and the audit entry.

| Caller | Outcome |
|---|---|
| Local mode (no principal) | Claimed value passes through — loopback is unauthenticated by design, and this is the pre-existing contract |
| No / invalid / disabled credential | 401 at the middleware; **never** a fallback to the body |
| `read_only` | **403** `write_not_permitted` |
| `ingest`, claiming its own source or nothing | Ingests as itself |
| `ingest`, claiming another source | **403** `source_identity_mismatch` |
| `admin`, no source named | **400** `source_id_required` — an admin credential is not a sensor |
| `admin`, source named | Ingests on that source's behalf |

A mismatch is **refused, not silently rewritten**. A sensor sending the wrong
id is misconfigured and should be told, not have its data filed somewhere it
did not intend.

The mismatch message names only the caller's own source. It is identical
whether the claimed source is enrolled or invented, so the response cannot
enumerate the fleet — the same reasoning the middleware already applied to
unknown-versus-disabled tokens.

### A second bypass, found by a test that was passing for the wrong reason
The first draft of the admin test asked for `/audit/events`, which does not
exist, and passed on the 404 without reaching any authorization check.
Pointing it at the real route, `/audit/logs`, returned **200 for an ingest
credential**.

`security.py` states that "a sensor's credential cannot read the audit log
or change configuration". That was a property of the design, not of the
code. Both audit routes now depend on `require_admin_in_central`, which
enforces the admin role when a principal exists and is a no-op in local mode
— `require_admin` alone would turn every loopback request into a 401.

### What was deliberately NOT built
**No HTTP enrollment endpoint.** Credentials are issued offline by
`scripts/manage_credentials.py`, and `CredentialStore` is explicitly never
written by the application at runtime. An admin-authenticated minting route
would require the server to write the credential store, turning a stolen
admin token into the ability to mint ingest credentials remotely. The
existing offline CLI is the locally-controlled administrative workflow the
architecture already has; adding a second one would be a new attack surface
for no capability the operator lacks.

**No schema change, no migration.** Identity lives in the credential store,
which is a file outside the database. Nothing was added to either database,
and no historical event was given fabricated authentication evidence — an
event stored before this change carries no claim about how it was
authenticated, and `source_id` on a stored row still means "filed under",
never "proved to originate from".

### Transport
Bearer credentials are replayable by anyone who observes them. PraHari does
not terminate TLS itself, so **central mode must sit behind HTTPS**. Over
plaintext HTTP on an untrusted network these credentials are compromised on
first use. That is a deployment prerequisite, not a property of this code.

### Residual risks, stated rather than closed
- **No credential expiry, rotation or revocation list.** Revocation today
  means editing the credential file and restarting. `enabled: false` is
  honoured and tested; nothing expires on its own.
- **A compromised sensor credential still writes freely as that sensor.**
  This boundary stops impersonation, not a stolen key.
- **`source_id` is still operator-chosen** at enrollment, so uniqueness is a
  convention, not a constraint.
- **Local mode remains unauthenticated by design**, and the boundary does not
  change that. Anything reachable on that loopback port is trusted.

---

## ADR-052: Payload and Rate Limits — Enforcing Two Controls the Config Already Advertised

### Context
Blueprint §4.2 requires central ingestion to validate "identity, schema,
timestamps, payload size, rate" before accepting records. §12 lists bounded
payload limits and rate limiting as the controls for resource exhaustion and
API abuse. §18 makes "payload limits ... tested" a definition-of-done item.

`AppConfig.max_request_size_mb` has existed since the first schema and
`/audit/config` published it in a `SystemConfigReport`. Nothing read it:

```
$ grep -rn max_request_size_mb backend/app/
  core/config.py:68      # the declaration
  api/v1/audit.py:122    # reporting it
```

A client could post a body of any size and the server buffered all of it
before a validator ran. Rate limiting did not exist in any form.

This is the same defect class as ADR-051 (`may_write` and `require_admin`
defined and never called): **a control that exists as a value rather than as
behaviour, while a diagnostic endpoint reports it as a security boundary.**

### Decision
`app/api/limits.py`, two middlewares, both failing closed at the boundary.

**`RequestSizeLimitMiddleware`** rejects a body over the configured maximum
with **413**. It decides from `Content-Length` where one is sent, so an
oversized body is refused before it is read. A chunked body has no such
header; rather than buffering it to find out, it is read in bounded
increments and abandoned as soon as the limit is passed, then replayed to
the application through the standard ASGI `receive` idiom so the route still
sees its payload. A malformed `Content-Length` is a 400 rather than a guess.

**`RateLimitMiddleware`** bounds requests per caller with **429** and a
`Retry-After`, keyed by the **authenticated credential** where there is one
and by client address otherwise. The credential key is preferred because
addresses are shared behind NAT, and penalising every sensor behind one
gateway for the behaviour of a single sensor would be wrong. `/health` is
exempt so an operator can still diagnose a deployment that is refusing them.

Ordering in `main.py` is deliberate and commented, because Starlette runs
the most recently added middleware outermost:

```
CORS  →  size limit  →  central auth  →  rate limit  →  route
```

Size limit outside auth: an oversized body is refused before any PBKDF2 work.
Rate limit inside auth: so it can see the principal.

`/audit/config` now reports `request_size_limit_enforced`,
`rate_limit_enforced`, `rate_limit_requests` and `rate_limit_window_seconds`
**separately from** the configured numbers, so a disabled limiter reads as
disabled instead of being implied by the presence of a value.

### Limits of this implementation, stated not hidden
- **The rate limiter is per process.** It is a fixed-window counter in
  memory. Honest for the single-process deployment PraHari currently is; it
  is NOT distributed, and running N workers multiplies the effective
  allowance by N.
- **A fixed window permits a 2x burst across a window boundary.** A sliding
  window would not, at the cost of a timestamp per request. The counter is
  the bounded choice and the burst is documented.
- **An unauthenticated flood still reaches the credential check** and pays
  for PBKDF2 before being counted, because the limiter sits inside auth. The
  size limit bounds how large each such request may be, not how many arrive.
- **A refused request is not counted**, so a client in a retry loop can
  recover rather than holding its own window open indefinitely.
- **No numerical service target is claimed.** §16 requires measurement
  first; the defaults (600 requests / 60s) are a resource bound, not a
  benchmarked capacity.

Queue depth and backpressure (§4.2, §6) remain **not implemented**. Ingestion
is synchronous — there is no queue to measure — so reporting a depth would be
reporting a number with no referent.

---

## ADR-053: Linux Host Telemetry — the Gap Was the Adapter, Not the Service

### Context
Blueprint §4.4 names Windows and Linux as the initial support targets, and
§18 requires local deployment to run "on declared supported operating
systems" with "at least one supported host telemetry integration ... tested
on their declared supported environments". Only Windows had one.

Inspection showed the service was already platform-neutral. The only
Windows-specific things in `WindowsTelemetryCollectorService` were its
default query function and one `sys.platform == "win32"` gate; polling,
gap detection, failure counting, deterministic identity and persistence
are all platform-independent. So this is an adapter gap, not a rewrite.

### Decision
`app/adapters/linux_telemetry.py` supplies `query_linux_connections()`,
emitting **the same raw record shape** the Windows query returns:
`local_address`, `local_port`, `remote_address`, `remote_port`, `protocol`,
`state`, `owning_pid`, `process_name`, `creation_time`. Because the shape
matches, the collector, normalization, the deterministic event id and
storage are byte-for-byte the same code on both platforms — verified by
driving a Linux-produced record through `WindowsConnectionAdapter` and
checking the identity is stable across two polls.

`default_host_query_fn()` selects by platform at construction, and
`platform_supported` now accepts Linux.

**Source: `/proc/net/tcp` and `/proc/net/tcp6`, read directly.** Not `ss` or
`netstat`: both are external binaries that may be absent and whose
human-readable output would need parsing. `/proc` is the kernel's own
interface, present on any host with procfs, readable unprivileged, needs no
package, and is cheaper than spawning a process per poll.

### Honest limits, reported rather than papered over
- **Process attribution is partial without elevation.** `/proc/net/tcp`
  gives a socket inode, not a PID; resolving it means scanning
  `/proc/<pid>/fd`, which only succeeds for the same user's processes.
  Another user's connection comes back with `owning_pid` and
  `process_name` absent — never guessed.
- **Only `comm` is read, never `cmdline`.** A command line routinely carries
  passwords and tokens passed as arguments. Pinned by a test that puts a
  password in a synthetic `cmdline` and asserts it does not surface.
- **`creation_time` is None.** `/proc` exposes no socket creation time, and
  defaulting it to the poll instant would misdate every connection as having
  just started.
- **Polling has the same blind spot as the Windows table**: a connection
  opening and closing between two polls is never seen. A property of
  sampling, not a defect.
- **A missing `/proc/net/tcp` raises rather than returning empty.** Empty
  means "no connections"; unavailable means "we cannot see". §6 forbids
  turning a collection failure into benign traffic.
- **An unparseable row is skipped, not half-filled.** A partially decoded
  connection is worse than a skipped one because it looks like evidence.
- **IPv6 word-swap decoding assumes a little-endian host**, which covers
  every mainstream Linux target. A big-endian host would need a different
  word order; the module says so rather than emitting wrong addresses.

### What is NOT claimed
This has been tested against real `/proc/net/tcp` text on Windows and
against synthetic `/proc` trees. **It has not been run against a live Linux
host in this session** — the two tests that need one, and the two that need
POSIX symlinks, are skipped on Windows and report as skipped rather than
quietly vanishing from the count. Running the suite on Linux is the
remaining verification step before claiming the integration works there.

---

## ADR-054: The Operational Database Incident, and the Guard That Follows From It

### What happened
During Session 19 a one-off diagnostic script — written to answer a
question about URL trailing slashes — imported `app.main.app` and built a
`TestClient` **without overriding `get_db`**. The FastAPI lifespan called
`Database.initialize()`. Run from the repository root, `database_url`
defaults to `sqlite:///./prahari.db`, which is the operator's live
telemetry. The pending additive `received_at` migration was applied to it.

`prahari.db` sha256 `51d80b91…c69fa` → `bb0e74d5…aacf90`, size unchanged.

### What the evidence establishes
Verified by strictly read-only inspection (`file:…?mode=ro`):

| Check | `prahari.db` | `backend/prahari.db` (control) |
|---|---|---|
| `PRAGMA integrity_check` | ok | ok |
| `PRAGMA foreign_key_check` | 0 rows | 0 rows |
| Tables | 7 | 7 |
| Indexes | 9 | 9 |
| `normalized_events` columns | **26** | **25** |
| `received_at` present | yes, **all NULL** | no |
| Event rows | 3,669 | 187 |
| Newest `ingested_at` | 2026-10-12T08:43 | 2026-10-11T11:28 |

`backend/prahari.db` is the decisive control: the same codebase, never
started from the repository root, with an otherwise identical structure
and **exactly one fewer column**. That corroborates independently that the
only change was the additive column.

The newest event predates the incident (16 October) by four days, so **no
rows were written**. All 3,669 rows and every index survived, and no
receipt evidence was fabricated — every `received_at` is NULL, which is
precisely what ADR-048 requires for data that predates measurement.

**No backup exists.** A repository-wide search found only the two live
databases and their WAL sidecars. There is therefore no recovery point,
and restoration was never an available option.

### Decision: do not reverse it
An `ALTER TABLE ADD COLUMN` is not undone in SQLite without rebuilding the
table — create, copy 3,669 rows, drop, rename, recreate 9 indexes — against
a database with no backup, to remove a nullable column that holds no data
and that the running code already expects. The rebuild carries far more
risk than the column does. Recorded rather than quietly restored.

### Root cause
Not the test suite. `tests/conftest.py` already redirects
`PRAHARI_DATABASE_URL` to a throwaway directory before `app.core.config`
is imported, and that has always worked — all 926 tests pass with the new
guard in place, which proves every one of them was already isolated.

The hole was a process that is **not** pytest-managed: the default
`database_url` is relative, so the current working directory silently
decides which real database an ad-hoc script opens.

### The guard
`app/storage/guard.py`. Under pytest, `initialize()` refuses any database
that is not inside a temporary directory, failing closed with an error
naming the path and the fix. `:memory:` is permitted.
`PRAHARI_ALLOW_NONTEMP_TEST_DB=1` is an explicit, greppable escape rather
than a silent fallback.

Deliberately **not a production gate**. Outside pytest it is a no-op, so a
real deployment migrates exactly as before. Gating genuine upgrades behind
a second switch would weaken production to accommodate tests.

Second control: a migration against a table that already holds rows now
logs at **WARNING** with the row count and database path. It was an INFO
line indistinguishable from ordinary startup noise, which is how this one
went unnoticed in the moment.

`test_protected_database_guard.py` drives the actual incident shape — a
`TestClient` over the real app with no `get_db` override — and asserts it
is now refused, plus that the additive migration still works correctly on
a temporary database and preserves existing rows as NULL.

### Residual risk
`backend/prahari.db` is still at the 25-column pre-migration schema. Any
process started with `backend/` as its working directory will migrate it
the same way. That is a correct migration on a real database, so the guard
does not and should not block it — but it is the next thing that will
change a hash, and it is recorded here so it is expected rather than
alarming.

---

## ADR-055: Credential Lifecycle — Expiry, Rotation, and Revocation That Does Not Need a Restart

### Context
ADR-051 closed source impersonation but left the lifecycle untouched. A
credential had exactly one control, `enabled`, editable only by hand in
the credential file and honoured by a running process **only after a
restart**. That is not revocation; it is a note to self. A leaked token
stayed valid until someone noticed, edited a file and restarted the
service.

Verified before designing, not assumed: `Credential` carried
`credential_id`, `source_id`, `role`, `salt`, `token_hash`, `enabled`,
`created_at`, `description` — no expiry, no revocation, no rotation
linkage. The CLI had `init`, `add`, `list`, `disable`.

### Decision

**Expiry.** Optional `not_after`, ISO-8601, UTC. `None` means "does not
expire", which is what every existing credential already did — adding the
field must not silently invalidate a store an operator is running. Three
choices worth recording:

- An **unparseable** `not_after` counts as **expired**. Treating a value
  we cannot read as "no expiry" would turn a corrupted store into an
  indefinitely valid credential.
- A **naive** deadline is read as UTC, so the same store behaves
  identically on every host rather than following the server's timezone.
- The boundary is **inclusive**: valid up to `not_after`, not through it.

**Rotation.** `rotate` mints a replacement for the **same `source_id`**
and records `replaces_credential_id`. Carrying the source over is the
whole point: `source_id` scopes ingestion and the UUIDv5 idempotency
namespace (ADR-050, ADR-051), so rotating a *secret* must not move a
sensor's data into a new namespace. Pinned by a test that submits the
same event under both credentials and asserts the second stores nothing.

The old credential keeps working until `--overlap-days` elapses (default
7), so a sensor is reconfigured without a gap; `--overlap-days 0` revokes
it at once. The CLI tells the operator to confirm the sensor is reporting
and then close the overlap early.

**Revocation without a restart.** `CredentialStore` remembers the file it
loaded from and re-reads it when `(mtime, size)` changes, checked on each
authentication. `revoke` is distinct from `disable`: disable is a pause an
operator may undo, revocation is permanent and records when and why, and
the CLI refuses to rotate a revoked credential because that would revive
the identity.

Two failure modes are handled deliberately, both tested:
- A **corrupt** credential file leaves the in-memory store untouched. An
  operator who breaks the file must not thereby lock out the whole fleet,
  nor have a half-parsed store silently swapped in. The change stamp is
  not advanced, so a fixed file is picked up on the next request.
- An **emptied** file is refused for the same reason.

### Why not a remote revocation endpoint
ADR-051 declined a credential-minting route because `CredentialStore` is
never written by the application at runtime and a stolen admin token
would become the power to issue credentials. A revocation endpoint is
less dangerous — it only removes access — but it would still require the
server to write the credential store, which is the property that decision
rested on. The admin CLI plus automatic reload achieves the operational
goal (no restart) without granting the server that write.

**Stated plainly**: revocation still requires an operator with filesystem
access to run the CLI. What changed is that it now takes effect on the
next request instead of at the next restart.

### Failure wording
Unknown, disabled, revoked and expired all produce the identical message,
"Credential is not recognised." Distinguishing them would confirm which
source ids exist and which credentials once worked. Pinned by a test that
collects the message for all four and asserts the set has one element.

### What is NOT claimed
- **No cryptographic source authenticity.** These are bearer tokens;
  anyone who observes one can replay it. PraHari does not terminate TLS,
  so central mode must sit behind HTTPS. That is a deployment
  prerequisite, not a property of this code, and is not claimed as one.
- **No automatic expiry was applied to existing credentials.** They
  continue not to expire until an operator sets a lifetime.
- **Revocation is not instantaneous**: it takes effect on the next
  authenticated request, bounded by the reload check, not by a push.
- **A compromised credential still writes freely as its own source** until
  it is revoked. This is lifecycle management, not intrusion detection.

---

## ADR-056: Bounded Admission Control Instead of a Queue, and a System Health View That Says What It Did Not Measure

### Context
§6 requires "bounded queues and expose backpressure rather than consuming
unlimited memory"; §4.2 requires central deployment to expose "health, lag,
queue depth, rejected records, and last-successful-ingestion time"; §11
requires one dashboard view carrying ingestion latency, queue depth, parser
errors, rejected records, storage status and inference latency.

None of it existed. Earlier sessions recorded this as FAIL with the note
that reporting a queue depth would be reporting a number with no referent.

### Decision: admission control, not a queue
PraHari's ingestion is synchronous end to end. A request is parsed,
normalized and committed inside the handler, and the response reports what
was **stored** — `stored_records` and `duplicate_records` (ADR-050), the
409 identity conflict (ADR-050), and atomic batch rollback all depend on
that. Putting a queue in front would answer the caller before the data is
durable and break three deliberate contracts at once.

So the bound is applied at admission: `AdmissionController` caps concurrent
in-flight ingestion (default 8) and a request that cannot be admitted is
refused with **503 and `Retry-After`**, carrying `stored_records: 0`. That
delivers what §6 actually asks for — bounded memory, visible backpressure,
no unbounded growth — without inventing a durability gap.

It is wired into the real ingest path, not bolted alongside it: the slot is
reserved **before parsing**, so a flood of large bodies cannot all be
normalized into memory at once, and released by a context manager so a
conflict or database error cannot leak capacity. A test asserts exactly
that after a 409.

### `queue_depth` is null, and that is the point
The field is present because §4.2 names it, and it is **null with a note**,
never 0. Zero would assert an empty queue; null says there is no queue.
`admission_model: "bounded_concurrency_no_queue"` names the mechanism and
`in_flight` carries the real number.

This rule governs the whole of `GET /system/health`:

- A number appears only when it was measured. Unmeasured is `null`.
  `inference_latency` is null because nothing instruments it yet — not 0.
- Every block carries `available` and, when false, a `reason`, so a reader
  can tell *nothing happened* from *we cannot tell*. "No sources
  registered" is `available: true, total: 0` — a measurement. "Storage
  unreadable" is `available: false` with the error.
- The limits block reports **enforcement alongside each configured value**,
  because publishing a configured number without it is how
  `max_request_size_mb` came to be advertised as a security boundary that
  nothing read (ADR-052).

The React view mirrors all of it: unmeasured renders as "not measured",
queue depth as "no queue — synchronous ingestion", and a failed refresh
**drops the previous reading** rather than leaving a stale number under a
fresh timestamp. Eight frontend tests pin those behaviours.

### Limits
Per process, like the rate limiter. Counters reset on restart, and the
response says so. No latency SLA is claimed; §16 requires measurement
before any numerical target, and none is offered.

---

## ADR-057: A NetFlow/IPFIX Adapter That Ingests Exports, and Does Not Claim To Be a Collector

### Context
§5 lists "Network flows — NetFlow/IPFIX or equivalent exporter records" as
an adapter category with the boundary "requires an authorized exporter and
consistent field/timestamp semantics". It was the last missing category
that can be built offline.

### Decision, and the capability boundary
`adapters/netflow.py` parses the **text export** that flow tools emit —
`nfdump -o csv`, SiLK `rwcut`, YAF, and collector CSV — into canonical
events. It does **not** speak the binary NetFlow v5/v9/IPFIX wire protocol
and does not open a UDP collector port, because that means listening on the
network, which the safety boundary forbids without authorization.

The honest capability statement, and the one the capability report must
carry: *PraHari ingests flow records exported by an authorized collector;
it is not itself a flow collector.* Tested against three real export
shapes, all producing the same canonical event.

### Semantics that are routinely got wrong
- **There is no single NetFlow CSV format.** Field names differ per tool
  and version, so a documented alias set is mapped and a record missing a
  required field is **refused with a named error**, not guessed at — §5.3's
  "reject incompatible required fields rather than silently mis-mapping".
- **Counters are directional.** `nfdump` reports `ibyt` and `obyt`
  separately. Summing is right for a bidirectional record and wrong for a
  unidirectional one, so a one-way record is flagged
  (`unidirectional_byte_count` + `MISSING_FIELD`) rather than silently
  halved or doubled.
- **`observed_at` is the flow START.** Using the end would date a
  long-lived flow to when it finished — materially later, and enough to
  move it into the wrong temporal window and corrupt every feature built
  from it.
- **An unparseable timestamp returns None, never `now`.** Defaulting would
  silently re-date the flow to the import moment.
- **A flow with no volume counters is kept and flagged**, with
  `bytes_total` left None. Absent is not zero.
- **No label is ever assigned.** An exporter reports traffic, not ground
  truth, so `label_provenance` is `UNLABELED`.

### Identity
Deterministic: `sha256(adapter_id | five-tuple | flow_start)`. Collectors
routinely emit overlapping files, so a re-import must not duplicate — and
two different exporters reporting the same flow are two observations, so
identity is scoped to the exporter. Both pinned by tests.

Parsing is bounded by `max_records` and reports `truncated_at_max_records`
rather than silently stopping. `nfdump`'s trailing summary block is
excluded, so it is not parsed as a flow record.

---

## ADR-058: The Sensor Forwarding Agent — At-Least-Once, and Honest About It

### Context
§13 reserves `agents/sensor/` and §4.2 requires that "agents should buffer a
bounded amount of data during temporary disconnection, retry safely, and
avoid unbounded disk use". It had stood at FAIL across several sessions.

### Decision
`app/agents/sensor_agent.py`, reusing the existing contracts rather than
inventing parallel ones: `POST /api/v1/stream/ingest/ndjson`, the
`Authorization: Bearer` credential model (ADR-051/055), sender `event_id`
plus a batch `Idempotency-Key` (ADR-050), and the server's own response
vocabulary — 409, 413, 429, 503.

The transport is `urllib` from the standard library. An agent is the one
component most likely to run somewhere with nothing installed, so it adds
no dependency, and the transport is injectable so tests never open a
socket.

### Delivery semantics, stated precisely
**At-least-once delivery with server-side deduplication.** The agent
retries until acknowledged; the server stores at most one copy because
event identity is deterministic. That is **not** exactly-once network
delivery: a response lost in transit causes a resend, and the duplicate is
absorbed at the database, not prevented on the wire. Proved end to end
against an in-process PraHari — a resend of four events returns
`stored=0, duplicates=4` and the row count stays at four.

The buffer is **bounded and in memory**. A persistent spool was considered
and not built: it needs its own storage, atomic rename semantics and
recovery validation, and the honest default for a research agent is to say
what is lost rather than imply durability it does not have. `health()`
says so in the response itself.

### Choices worth recording
- **Permanent failures are not retried.** 400/401/403/409/413 mean the
  request itself is wrong; resending the same bytes is a loop. The batch
  is dropped with a counted, logged reason — never silently.
- **A transient failure returns the batch to the FRONT of the buffer.**
  Appending would reorder telemetry and let a failing batch starve behind
  newer events indefinitely.
- **The idempotency key is derived from the event ids**, not a counter or
  the clock, so a resend after a lost response presents the same key. A
  fresh key would allocate a new identity namespace and defeat the point.
- **`Retry-After` wins over local backoff**, capped by `max_backoff`. The
  server knows when it will be ready.
- **Jitter** on backoff so a fleet reconnecting after an outage does not
  synchronise into a thundering herd.
- **Plaintext HTTP to a non-loopback host is refused at configuration
  time.** A bearer credential over plaintext is compromised on first use,
  so this is an error rather than a warning. Loopback is allowed for local
  testing.
- **`event_id` is required by the agent** even though the API tolerates its
  absence: without it a retry is not deduplicated, and an agent that
  retries must supply one.
- **The token never appears** in `repr`, `str`, logs or `health()`.

### What it does NOT do
It registers no system service, changes no firewall rule and alters no
networking. It is a library plus a configuration object; starting it is the
operator's explicit act.

---

## ADR-059: Source and Retention Administration — One Policy Store, and a Change That Deletes Nothing

### Context
§11 requires an Administration view with "authorized source configuration,
access control, retention settings, model selection, and auditable
configuration changes". Two operations did not exist at all: enabling or
disabling a source, and changing the retention period.

### Source enable/disable
`PATCH /sources/{source_id}/enabled`, admin-gated in central mode via the
existing `require_admin_in_central`, audited, 404 on an unknown source.

Only the `enabled` column is written. An administrative toggle must not
silently rewrite a source's counters or last-event time, and a test asserts
they survive. Disabling deletes nothing — it records that no further data
is expected, which is exactly what `SourceHealth.DISABLED` already meant.

### Retention: an override, not a second store
Retention lived in `AppConfig`, which comes from the environment and cannot
be changed at runtime. The requirement was to make it settable **without
creating a second independent policy store**.

A `system_settings` table in the existing database holds operator
overrides. `AppConfig` remains the source of defaults; a row here is an
explicit, audited override of one of them. `effective_retention_days()`
returns the value **and its origin**, and both are reported together:
`retention_days`, `origin`, and `configured_default`, so a reader never has
to guess which won.

Two failure modes are deliberate, and tested:
- An **unreadable** stored override falls back to the configured default,
  not to zero. Guessing could shorten retention, and that is the direction
  that destroys data.
- An **out-of-range** stored override is ignored the same way.

### The rule the whole feature rests on
**Changing the policy deletes nothing.** Shortening retention sets a
number; pruning still requires `POST /retention/enforce` with its
confirmation token. The endpoint says so in its response, the UI says so in
a banner, and a test asserts the row count is unchanged after setting
retention to one day.

### The UI
`AdministrationPage.tsx`, wired to those real endpoints — not a mockup.
- Every mutation **re-reads from the server** rather than patching the
  table optimistically, so the UI cannot claim a success the backend never
  gave. A test asserts a rejected call surfaces the error and shows no
  success notice.
- Consequential actions confirm first.
- An unmeasured value renders as "not measured", never as 0 or a dash.
- Credentials never appear: issuance, rotation and revocation stay in the
  offline CLI (ADR-051, ADR-055), and the page says where they live.

### Residual
Credential rotation and revocation are **not** exposed in the UI. They
remain operator-run CLI commands by the decision in ADR-051: a remote
minting or revocation route would require the server to write the
credential store, which is the property that decision rested on.

---

## ADR-060: The 65 Implausible Timestamps Are Pre-Fix Residue, Not a Live Defect

### Context
The Feasibility screen reports 65 records with implausible timestamps out
of 5,524 audited, and the temporal-integrity criterion fails, so the gate
refuses to approve forecasting. The question was whether this is a live
code defect or historical data.

### Evidence (read-only inspection of the operational database)
Every one of the 65 is identical in shape:

| Property | Value |
|---|---|
| `observed_at` | `1601-01-01T00:00:00+00:00` — the **Windows FILETIME epoch** |
| `source_id` | `windows_local_host` (all 65) |
| `raw_reference` | `windows:tcp;state=TimeWait;pid=0` |
| `quality_flags` | `["missing_field"]` |

Windows returns an unset `CreationTime` as the FILETIME zero point for a
socket with no recorded start — PID 0 TimeWait entries. An early adapter
stored that verbatim as the observation time.

Four facts establish that the defect is already fixed:

1. All 65 were ingested in **one 26-minute window**, 2026-10-11 17:33–17:59.
2. They carry only `missing_field`. The current code adds `invalid_value`
   **and** `timestamp_uncertainty` to exactly this case, so these rows
   cannot have been written by it.
3. **1,612** rows elsewhere carry both of those flags — the guard working.
4. Of **3,263** Windows events ingested after that window, **zero** have a
   1601 timestamp.

The fix lives in `WindowsConnectionAdapter.validate_and_normalize`: an
implausible `creation_time` is discarded, the record falls back to the
**poll time** — which is genuine evidence, PraHari did see the connection
then — and is flagged so the substitution is visible.

### Decision
**The 65 records are left exactly as they are.** They sit in the protected
operational database, which this work may not modify. Rewriting them would
destroy the only record of what was actually stored, and the alternative —
deleting them — would make a failing gate pass by hiding its cause.

The feasibility gate's refusal is **correct behaviour and stays**. Its
score is `order_ratio × plausible_fraction`, so it moves with the verdict
rather than printing 100% beside a failure, and the detail names the
count, the exclusion and the reason.

### What was added
`tests/integration/test_timestamp_integrity_roundtrip.py` — 18 tests. The
existing unit tests stop at `validate_and_normalize`, and the research-gate
test injects 1601 directly onto an event object; neither proved a sentinel
cannot survive **persistence and serialization**. These do: adapter →
database → API, plus five sentinel shapes (FILETIME, OLE, Unix epoch,
unparseable, absent), a future creation time, and proof that the
substituted value is the recorded poll time and not `now()`.

### Remaining
Clearing the 65 rows requires either an approved, audited data-repair
operation on the operational database, or accepting that the gate stays
closed for any audit whose window includes 2026-10-11 17:33–17:59. Neither
is a code change, and neither was authorised here.

---

## ADR-061: Measured Counts Were Computed and Then Dropped on Save

### Context
Tracing dashboard metrics from the UI back to storage found a stored
analysis reporting, simultaneously:

```
avg_bytes                    11474.63      bytes_measured_count      0
avg_duration               877145.7048     duration_measured_count   0
implausible_timestamp_events      0        (65 such records exist)
```

Two different failures in one row. An average printed beside "0 measured"
is self-contradictory. Worse, the anomaly count flatly denied the 65
FILETIME records that the Feasibility screen reports in the same session.

### Root cause
`services/analysis.py` computes all four correctly — `bytes_measured_count
= len(bytes_list)` at line 241. The `descriptive_analyses` table had **no
column for any of them**, so `save_analysis` silently discarded them and
`_row_to_analysis` rebuilt the object with the Pydantic default `0`.

A comparison of the model against the schema found exactly four such
fields: `bytes_measured_count`, `packets_measured_count`,
`duration_measured_count`, `implausible_timestamp_events`. Every one is a
"how much of this was actually measured" counter — precisely the fields
whose whole purpose is to stop a reader trusting an average, and each
defaulted to the most misleading possible value.

This is the same defect class as ADR-052 and ADR-051: a value that exists
in one place, is lost at a boundary, and is read back as a confident zero.

### Decision
The four columns are added through the existing `_ADDED_COLUMNS` additive
mechanism, persisted by `save_analysis` and read by `_row_to_analysis`.

**`-1` is the sentinel for "this row predates the column"**, surfaced as
`None`. The model fields widen from `int = 0` to `Optional[int] = None`.
A stored analysis cannot be recomputed retroactively; backfilling 0 would
invent a measurement nobody took, which is the error being fixed. The
three states stay distinct:

| Value | Meaning |
|---|---|
| a number | that many events carried the field |
| `0` | measured, and none carried it — correct for the Windows table, which supplies no byte counts |
| `None` | not recorded; this analysis predates the column |

### Consequences
- **Positive**: an average can no longer appear beside a contradictory
  count, and a new analysis reports the real implausible-timestamp total
  instead of 0.
- **Negative**: the 30 analyses already stored keep `None`. They are not
  backfilled, deliberately.
- The operational database gains the columns on its next startup, through
  the same additive path as ADR-048. Not applied here: this work does not
  migrate the protected database. Tested on temporary databases only —
  `test_analysis_persistence.py`, 14 tests, including the migration from a
  pre-column schema and proof that `-1` reads as `None` and never as `0`.

---

## ADR-062: A GET Must Not Write — and the Analysis Route Did

### Context
A read-only investigation into an unexplained `descriptive_analyses`
insertion found the cause in `GET /api/v1/analysis/latest`:

```python
if recompute_if_stale and analysis.total_events != current_total:
    analysis = _build_analysis(...)
    db.save_analysis(analysis)        # a GET writing a row
```

`recompute_if_stale` defaults to True, so any GET issued while the stored
snapshot was out of date persisted a new analysis.

Two things made it worse. `_build_analysis` mints a fresh `uuid4`, so the
`INSERT OR REPLACE` never replaced anything — **30 rows, 30 distinct
ids**, six of them inside one ten-minute window while the collector ran.
And the GET path wrote no audit record, while `POST /analysis/run` does,
so the row appeared in the database with nothing attributing it.

A sweep of every `@router.get` across `api/v1/` found this was the only
GET in the API that writes.

**How it was found matters.** The write happened during an investigation
conducted under an explicit read-only constraint, caused by a `curl` to
an endpoint whose method promises safety. Browser page loads
(`OverviewPage.tsx:27`, `AnalysisPage.tsx:15`) call it on every mount, so
routine dashboard use grew the table unboundedly.

### Decision
**GET never writes, on every path.** The route now computes a fresh
result for the response and returns it **unsaved**. Persisting stays the
job of `POST /analysis/run`, which keeps its validation and its audit
record.

The intent behind the original code was right — do not serve a stale
snapshot as if current — and is preserved. What changes is that freshness
is achieved by computing, not by persisting.

Two response-only fields carry the distinction, because one flag cannot:

| `persisted` | `is_current` | Meaning |
|---|---|---|
| true | true | stored, and still describes the database |
| true | false | the stored snapshot, explicitly requested with `recompute_if_stale=false`, now out of date |
| false | true | computed for this response, accurate, **not saved** |

Neither field is persisted: they describe a response, not an analysis, and
storing them would store a fact about a past request. `_row_to_analysis`
sets `persisted=True` because a row loaded from the database is stored by
definition; the route answers currency, which is a question about live
counts.

### Consequences
- **Positive**: GET is safe again. Dashboard loads, prefetches, probes and
  read-only inspection no longer touch the database, and the unbounded
  growth is gone at its source.
- **Backward compatible**: the response gains two fields and loses none.
  A caller that ignores them sees the same analysis it saw before, and a
  stale GET still returns current numbers.
- **Not done**: the 30 rows already stored are left alone. Deleting them
  would modify operational data, and they are a legitimate record of what
  the system computed.

### Recommended separately, not implemented
A retention policy for explicitly created analyses. `POST` can still grow
the table without bound if called repeatedly, which is far less likely
than a page load but not impossible. That needs its own decision about
what to keep, and would be the first thing in this project to delete
historical records — so it should not be bundled into a defect fix.

Also worth having, and absent: request-ID middleware feeding `log_audit`.
This write took a code trace to attribute because the database records
only `user_identity="local_operator"`, with no request id, address or
user agent.

---

## ADR-063: Request Correlation Ids, Because One Write Could Not Be Attributed

### Context
ADR-062's unexplained `descriptive_analyses` row took a code trace to
attribute. `audit_events` recorded only
`user_identity="local_operator"` — no request id, method or path — so the
database could say *what* changed and *when*, never *which request*.

### Decision
`api/request_context.py` sets a correlation id per request and echoes it
in `X-Request-ID`. `log_audit` reads it from a **ContextVar**, so every
existing call site gained attribution without being edited.

A ContextVar rather than a parameter, deliberately: `log_audit` is a
`Database` method, and the storage layer must stay usable from the
collector, the CLI and tests, none of which have an HTTP request.
Threading an id through every route would touch a dozen call sites and be
forgotten by the next one added. Starlette runs sync handlers in a worker
thread via anyio, which copies the context, so the var is visible there.

- **NULL outside a request.** A collector poll, the CLI and a test have
  no request behind them, and that is recorded as NULL rather than a
  fabricated placeholder.
- **A client-supplied id is accepted but sanitised** — capped at 64
  characters and restricted to `[A-Za-z0-9._:-]`. This value is persisted
  and shown in reports, so an unbounded or control-character id would be
  a log-injection vector. It is **rejected, not truncated**: a trimmed
  10 KB header would look legitimate while no longer matching what the
  client holds.
- **Only the id is stored.** No address, no user agent, no query string —
  those would put identifying data in a long-lived table, and the id
  alone is enough to tie a row to a log line.
- **An audit entry outranks its attribution.** On a database predating
  the column the insert falls back to the original statement, so the
  event is still recorded.

### Consequences
A write like ADR-062's is now traceable from the database alone. The
column is additive and nullable; existing entries keep NULL and are not
backfilled, because no id was captured for them.

---

## ADR-064: Analysis History Is a Record, Not a Cache — So Nothing Expires It Automatically

### Context
ADR-062 fixed GET-on-read, but `POST /analysis/run` could still grow
`descriptive_analyses` without bound. The question ADR-062 deferred was
what these rows *are*.

### Decision: historical records
An analysis carries its own `computed_at`, totals, provenance,
`data_categories` and measured counts. It is a record of what PraHari
computed at a moment — evidence, not a derived cache entry that can be
regenerated at will, because the events it summarised may since have been
pruned by telemetry retention.

That settles the retention design: **nothing expires analysis history
automatically.** Not a timer, not startup, not a read, not a new run.
`test_nothing_prunes_automatically` holds that line against reads,
writes and health checks.

Trimming is an explicit administrative act, `POST /analysis/prune`:

- **Dry run by default.** Without the confirmation token
  `DELETE_ANALYSIS_HISTORY` nothing is deleted and the response names the
  analyses that would be — the same preview-then-confirm shape the
  telemetry retention service uses, because this is the only operation in
  PraHari that removes a historical record.
- **`keep` must be at least 1.** This trims history; it does not empty it.
- **Admin-gated in central mode**, audited, and the audit entry carries
  the request id from ADR-063.
- **Telemetry is never touched** — only `descriptive_analyses`.

`analysis_history_limit` defaults to **0, meaning keep everything**, and
even a positive value is only a suggestion surfaced to the endpoint. It
never causes a deletion on its own; a test asserts that.

### What was NOT done
The 30 analyses in the operational database are left alone. This work
does not run the prune against a protected database, and the endpoint
exists so the operator can decide. Deleting them would also be the first
time anything in this project removed a historical record — which is the
operator's call, not a side effect of a defect fix.

A retention policy must not become a way to hide the original GET defect:
the growth is fixed at its cause in ADR-062, and this endpoint exists for
the separate, legitimate case of an operator who has run many explicit
analyses.

---

## ADR-065: A Fix in the Source Is Not a Fix in the Process

### Context
Asked to confirm the project was complete, I probed the running
deployment rather than re-reading the previous report. The listener on
`127.0.0.1:8000` had started at 22:59 on 16 Oct; the ADR-062 fix was
committed at 23:34 and ADR-063 at 00:06. `uvicorn` runs without
`--reload`.

So the process was serving code from before both fixes, and a dashboard
page load was still appending a `descriptive_analyses` row to the
operational database. Every test passed, the tree was clean, the commit
was published — and the defect was still live. The previous report had
called the deployment "currently working", which was true of `/health`
and misleading about everything else.

### Decision: verify the process, not the repository
A deployment claim must be evidenced against the running instance. Two
rules follow.

**Probe for loaded code, not for a 200.** `/health` returned 200 on the
defective process; status codes said nothing. The usable signal was the
absence of the `x-request-id` header, which `RequestIdMiddleware` adds
unconditionally — so its absence proves the middleware is not loaded, and
therefore that the ADR-062 fix in the same working tree is not either.
One header distinguishes "the source is fixed" from "the thing answering
is fixed". That check is now in the README quickstart.

**Do not probe with a request that might write.** `GET
/analysis/latest` was the obvious way to test the fix and the one thing I
could not safely call: against a pre-fix process it would have written to
a protected database to find out whether it writes to a protected
database. The header check answered the same question at no cost. When
the only direct test of a defect would trigger the defect, find an
indirect signal.

### Why the restart needed authorization
Restarting on current code runs the additive migration that adds
`audit_events.request_id`, which `prahari.db` did not have — a schema
change to a protected database, which the standing instruction withholds
without specific authorization. Stopping a process the operator started
is likewise not a unilateral act. Both were reported with evidence and
left to the operator, who authorized backup-then-restart.

The backup is the part that mattered. An earlier accidental migration in
this project was unrecoverable precisely because no backup existed, and
an additive `ALTER TABLE` cannot be reversed without rebuilding the
table. A copy taken after a clean shutdown — verified free of `-wal`
residue and hash-matched — makes the same operation reversible.

### Consequence
ADR-062 is now evidenced on real data: five consecutive GETs against the
operational database left `descriptive_analyses` at 30 rows. Until the
restart, the fix was demonstrated only against temporary databases. The
authorized hash change is recorded in IMPLEMENTATION_STATUS.md.

The general lesson is the one this project keeps relearning in new
disguises: a value that exists in one place, is lost at a boundary, and
is read back with confidence. Here the boundary was the gap between the
file on disk and the code in memory, and "all tests pass" was the
confident zero.

---

## ADR-066: The Sensor Agent's TLS Controls Were Declared, Not Enforced

### Context
Every central-mode test ran in-process through `TestClient` — no socket,
no TLS, no second interpreter. Running PraHari as its own `uvicorn`
process over HTTPS (`tests/integration/test_central_https_e2e.py`, test PKI
minted per run by OpenSSL) exposed four agent defects that in-process
testing cannot show.

1. **`verify_tls` was read by nothing.** Setting it `False` changed
   nothing while appearing to disable verification, and there was no way
   to trust a private CA, which any internal central deployment needs.
2. **A certificate failure was retried as a network blip.** urllib wraps
   it in `URLError`, an `OSError`, so it was classed `connection_error`,
   retryable.
3. **Redirects carried the bearer token to plaintext.** CPython's redirect
   handler copies every header except content headers onto the new
   request. An HTTPS endpoint answering `302 -> http://...` would make the
   agent resend `Authorization` in cleartext to a host chosen by whoever
   controls the response. Demonstrated empirically, not asserted:
   `test_the_redirect_hazard_is_real_for_a_default_urllib_client`.
4. **One oversized batch wedged the agent forever.** The server refuses
   on `Content-Length` and closes without reading the body, so the client
   sees a dropped connection or a truncated 413, never a clean 413. That
   looks transient, so the same bytes were resent indefinitely and every
   event behind them waited. Demonstrated against the real server.

### Decision
- `ca_file` names the issuer's PEM bundle. `verify_tls=False` is
  **refused** at configuration time: a private deployment is trusted by
  naming its CA, never by switching verification off.
- Redirects are never followed; a 3xx is `redirect_refused`.
- A **channel** failure (`tls_verification_failed`, `redirect_refused`) is
  a new outcome, `halt`: not retried, and the batch is **kept**, not
  dropped. The events are valid; the channel is not. `flush_all` stops at
  the first halt rather than spinning. Only a genuine trust failure halts:
  an `SSLEOFError` is the peer closing, and stays retryable.
- `max_request_bytes` (default 4 MiB, under the server's 50 MB): an
  over-limit batch is split, its tail returned to the front of the buffer
  in order; a single event that cannot fit alone is dropped and counted
  (`events_oversized`) instead of blocking the queue.

### Not claimed
A localhost test certificate proves the client and server handle TLS
correctly. It says nothing about a production deployment's certificate
issuance, rotation or termination.

---

## ADR-067: The Audit Trail Named the Wrong Actor in Central Mode

### Context
No `log_audit` call site (there are 31) passed `user_identity`, so it
defaulted to `"local_operator"`. In central mode every entry, including an
authenticated sensor's ingest, a credential change and a prune, was
attributed to a person at the console who did none of it.

### Decision
The ADR-063 mechanism: the auth middleware publishes
`credential:<id> source:<source> role:<role>` in a context variable for
the request's duration, reset in `finally`, and `log_audit` defaults to
it. Precedence: explicit argument, then the authenticated principal, then
the local operator, which is accurate only because there is then no
authenticated caller. Only identifiers are recorded, never the token.

Verified out of process over HTTPS, and under concurrency: twenty
simultaneous requests alternating between two credentials each audit
under their own request id and their own credential.

---

## ADR-068: A Wholly Rejected Batch Was Invisible to Health

### Context
On the stream path, a batch in which **every** record was rejected skipped
the block that records measurements. The response said
`stored_records: null` ("not reported") for a count that was measured,
zero, and `controller.record_batch` never ran, so `/system/health` showed
`events_rejected: 0`. A sensor whose every record fails validation is the
failure an operator most needs to see, and it was the one health could not
show.

A related defect surfaced while testing it: a line that is valid JSON but
not an object (`[]`, `42`, `null`) reached the validator, which called
`.get()` on it. One such line made the whole batch a 500 and cost every
good record beside it.

### Decision
Measurements are recorded on every path. A non-object line is rejected as
one record, reason `record_not_an_object`.

---

## ADR-069: A Late Event Was Treated as Known to Earlier Forecasts

### Context
Blueprint section 6: "A late event may update a historical record, but it
must not be retroactively treated as information available to an earlier
forecast." The feature extractor chose window events by `observed_at`
alone and never read `received_at`. A live event observed at t-5s and
received at t+300s was counted in the forecast made at t. That is leakage,
and it flatters any model evaluated on stream-ingested data.

### Decision
A window's features use only events that had **arrived** by its prediction
time. Applied where `received_at` means arrival: stamped live telemetry.
For a historical import `received_at` is when the file was imported, years
later, so applying it would empty every window; offline replay keeps a
declared assumption that imported events were available at their event
time. Exclusions are counted in the windowing report. The dataset
fingerprint now includes receipt time for stamped live events only, so
every other fingerprint is byte-identical.

The tests were checked against the defect: with the rule reverted, three
of nine fail.

---

## ADR-070: Labels Have Provenance, and the Target Is a Specification

### Context
Three gaps with one cause: the research record did not say what its
evidence was.

1. Training read label **text** and never its provenance. A model could be
   trained and scored on another model's predictions, or on a corpus's
   labels merged with a detector's signatures.
2. The feasibility audit's "Data Provenance Integrity" check was
   `passed=True` unconditionally. It could not fail.
3. The manifest held the target as one sentence and omitted the git
   revision, a configuration hash, package versions, model parameters, the
   threshold procedure and any statement of limitations.

### Decision
- **Label policy** (`research/label_policy.py`), enforced at the single
  training entry point: `model_prediction` labels are never ground truth;
  declared provenances are never mixed in one experiment; labels without a
  declared provenance are counted, never promoted. A lone
  `detector_output` set is allowed and recorded as forecasting *detector
  alerts*, not incidents. The feasibility check applies the same policy
  and can now fail.
- This sits beside `allow_mixed_provenance` on `/forecast/train`, which
  governs `data_category`. They are different axes: an operator may still
  combine unlabelled live traffic with one labelled corpus, but no flag
  merges two kinds of label.
- **Structured target** (`research/target.py`,
  `prahari.attack_label_in_horizon` v1.1.0): event semantics and what they
  are *not* equivalent to, grouping, time origin, window, lead, horizon,
  stride, overlap and purge, positive and negative rules, incomplete-window,
  capture-gap, ongoing-attack and late-event rules, warning matching and
  suppression. Each describes what the code does, and the whole is
  fingerprinted.
- **Manifest 1.1.0**, additive: target and fingerprint, label policy, git
  revision and dirty flag, configuration hash, package versions, model
  parameters, threshold procedure, late-arrival exclusions, limitations.
  1.0.0 manifests still load; the new fields are absent, not invented.

### What the specification admits
Matching is per **window**, so `detected_events` counts windows, not
distinct attacks. Event-level lead time is **not** measured. No warning
suppression is modelled. The threshold is a fixed 0.5, never tuned on any
split and never selected on validation data. These are stated in the
manifest's limitations rather than left for a reader to discover.

---

## ADR-071: There Was No Storage Abstraction; Now There Is a Contract

### Context
Earlier reports said PostgreSQL was blocked only by the lack of a service
and that "repository abstractions already exist". The second claim was
false: there was no abstraction, only the concrete SQLite `Database`.

### Decision
`storage/contract.py` defines `TelemetryStore`, derived from every storage
call the application makes; a test fails if a call site appears outside
it. `test_storage_contract.py` is the executable half: idempotent identity,
atomic rollback on conflict, source isolation, receipt-time round trip,
eight concurrent writers with no duplicates, analysis retention, audit
attribution, settings, and persistence across reopen.

Three modules outside storage issue SQLite SQL directly
(`api/v1/audit.py`, `api/v1/system_health.py`, `services/retention.py`).
They are named in `KNOWN_ABSTRACTION_LEAKS`, and a ratchet test fails if a
fourth appears. The SQLite constructs a port must translate are listed,
and a test checks that each really occurs.

### Status, stated plainly
PostgreSQL is **MISSING**, not merely blocked: no backend, no driver, no
server. It is done when a backend satisfies the contract and passes the
suite against a real server. Not a mock: atomicity and concurrent-writer
behaviour are exactly what a mock cannot exhibit.

---

## ADR-072: No Live NetFlow Collector Was Built

### Context
The NetFlow adapter parses exported flow text; it does not open a UDP
port. A collector could be written and fed hand-built packets over
loopback.

### Decision: not built
A collector exercised only by packets this project constructs would prove
the decoder agrees with its author, not that it interprets a real
exporter's records correctly, and a UDP listener is attack surface. The
blueprint's advanced-feature rule applies: capabilities are added when
evidence supports them. No authorized exporter or observation point exists
here, so the section 18 criterion cannot be met by code. What would be
needed is listed in the acceptance matrix.

Related: the NetFlow adapter deliberately discards labels, so a CTU-13
`binetflow` file routed through it would import unlabelled: safe, but
useless for supervised work. CTU-13 labels flows Background, Normal and
Botnet. Under PraHari's attack-label rule any label other than
benign/normal/unlabeled counts as an attack, so a CTU-13 importer must map
labels explicitly, and Background must not become a negative. No such
importer exists, and none was written for label strings not yet seen.

---

## ADR-073: The Agent's Size Refusals and Ambiguous Drops Now Have a Bound

### Context
ADR-066 bounded request size because a server refusing an oversized body
"closes the connection before reading it, so the client never sees the
413". Running the current revision on Arch Linux showed that sentence is
timing, not law: on Linux loopback the 413 usually arrives intact. That
exposed three defects the Windows runs could not show.

1. **A clean 413 dropped every event in the batch.** The 413 was handled
   like 400/401/403/409 - "the request itself is wrong" - so a 50-event
   batch over the server's limit was discarded as one permanent failure,
   although the server's own message says *split the submission*, ADR-066
   says over-limit batches are split, and none of the events was at fault.
   `events_oversized` stayed 0, so health could not tell a size refusal
   from bad data.
2. **The dropped-connection shape still wedged.** With `max_request_bytes`
   set above the server's real limit, a drop is retryable, the batch went
   back to the front, and the next `flush_once` sent the same bytes again.
   The agent has no loop of its own (callers drive `flush_once` /
   `flush_all`), so "forever" was at the caller's cadence.
3. **A broken-off response could lose the batch or hide the 413.**
   `http.client.IncompleteRead` is not an `OSError`; it escaped
   `flush_once` after the batch had already left the buffer. And a 413
   whose body was cut off raised while reading the body, so a definite
   status was lost.

### Decision: classify by evidence, and bound every path

| Outcome | Evidence | Action |
|---|---|---|
| 2xx | Acknowledged | Done; counts stored and duplicates |
| 413, more than one event | The server says a body of this size is too large | Keep the events, in order; later multi-event bodies are kept below the refused size (`learned_max_request_bytes`, never rises); `batches_split` |
| 413, one event | The server refuses this event alone | Drop it; `events_oversized` and `batches_failed_permanent` |
| 400/401/403/409 | The request is wrong | Drop, counted (unchanged) |
| TLS failure, redirect | The channel is wrong | Halt, keep the events (unchanged, ADR-066) |
| Refused, unreachable, DNS, timeout, 408/425/429/5xx | Nothing was delivered, or the server is busy | Retry with backoff, keep the batch **unchanged**; never split, never set aside |
| `connection_dropped` (reset, broken pipe, abort, TLS EOF, `IncompleteRead`, remote disconnect) | Ambiguous: an outage, a size refusal, or a lost response | Retry with backoff; see below if a whole round drops |

**A round in which every attempt dropped mid-request** is the one pattern
that may mean the request cannot get through:

- **More than one event:** the batch cap (an event count) is halved,
  marked **unconfirmed** (`batches_split_unconfirmed`), and the events are
  kept. The identical batch is not resent. Because an outage looks the
  same, the cap grows back - doubling after 4 successful deliveries, up to
  `batch_size` - so a flaky network does not shrink batches for good.
- **One event:** the next buffered event is sent alone as a probe
  (`channel_probes`). If it also fails, it's an outage: both go back in
  their original order, still retryable. If it is acknowledged, the
  suspect gets one immediate further attempt; if that drops too - back to
  back with a success - the suspect is moved to an in-memory
  **dead-letter store** (`events_dead_lettered`). It is not discarded:
  `dead_letters()` lists it and `requeue_dead_letters()` puts it back at
  the front - as many as the buffer has room for, oldest first, the rest
  staying dead-lettered. The store is bounded by `buffer_capacity`;
  overflow drops the oldest dead letter and is counted
  (`events_dead_letter_overflow`).
  If the probe is refused outright (400/401/403/409, or 413 for it alone),
  that refusal applies to the probe event however it was sent, so it is
  dropped under the normal rule - and any answer proves the channel
  carries requests, so the suspect is still judged.

**Termination.** A refused body is never resent unchanged. Each
multi-event 413 strictly lowers the learned byte ceiling. Each
all-drops round at least halves the batch, so a batch reaches one event in
at most log2(batch_size) rounds; one event then ends in delivery, a
dead letter, or - with no evidence the channel works - stays buffered and
retryable, which is the correct outcome during a real outage.

Also: the transport returns the status of an HTTP error even when its body
cannot be read, so a truncated 413 is a confirmed 413; any exception a
transport raises puts the in-flight events back before propagating; and
`health()` reports `batch_size_cap`, `learned_max_request_bytes` and
`dead_letter_events`.

*Revised before commit, during the Linux closure audit (ADR-076):* the
first draft turned a clean 413 into a permanent **event-count** cap set to
half the refused batch. A 413 on two large events then held every later
batch - however small its events - to one event per request for the
agent's lifetime. A 413 is evidence about bytes, so the confirmed limit is
now a byte ceiling, applied to multi-event bodies only. The same audit
found the probe livelock and the requeue loss described above.

### Duplicates
Splitting after an ambiguous drop resends events under different batch
boundaries and therefore a different `Idempotency-Key`. That is safe only
because the agent requires `event_id`, so identity is tier 1 of ADR-050
(source + event id), independent of the batch. Pinned end to end against
the real ingest path: the server stores every multi-event batch and the
response is lost; after the split, 8 events are stored exactly once, with
`duplicates=8` and no 409.

### Trade-offs, stated
- During an outage that drops connections (rather than refusing them) the
  cap shrinks to 1 until deliveries resume and it recovers. That costs
  throughput, not events.
- Dead-lettering is the one case that changes delivery order: the event
  behind the suspect is delivered first. The probe costs one extra
  request.
- With the bound misconfigured above the limit and a server that drops
  rather than answering 413, every halving costs up to `max_attempts`
  sends with backoff. Correct `max_request_bytes` remains the fix; this is
  the safety net.
- The dead-letter store is in memory, like the buffer: lost if the process
  is killed. A dead-lettered event may already have been stored, if what
  kept failing was the response rather than the request; requeueing it is
  safe because the server deduplicates by `event_id`.

### Not claimed
Not exactly-once delivery: at-least-once on the wire, at-most-once in
storage. The dropped-connection path is exercised deterministically by
simulated servers; against the real loopback server on this Linux host the
413 arrived intact, so the out-of-process e2e test took the clean-413
branch. Not tested against a non-loopback server.

This supersedes the "413 is dropped" bullet of ADR-058 and point 4 of
ADR-066's claim that the 413 is never seen. Both are left as they were
written.

---

## ADR-074: Tests Wrote Experiment Manifests Into the Repository

### Context
`/experiments/capture` writes manifests to `<project root>/experiments/`.
The API test fixture meant to redirect them - its comment says *keep
manifests inside the test's temporary tree* - did so by setting
`cfg._test_root`, an attribute nothing reads. `project_root` is derived
from the source file's location. So every full run rewrote
`experiments/api-exp-1.json` and `api-exp-2.json` in the checkout. The
directory is gitignored, which is why nobody noticed.

### Decision
`AppConfig.experiments_dir` (`PRAHARI_EXPERIMENTS_DIR`) chooses the
directory. Empty, the default, keeps `<project root>/experiments`, so a
deployment behaves exactly as before. A relative path resolves against the
project root, like `database_url`. `tests/conftest.py` points it at the
session's throwaway directory, and the experiment fixture injects its own
`tmp_path`.

Pinned by tests: a capture lands in the injected directory and leaves the
repository's `experiments/` unchanged, by name, mtime and size; and the
suite's default configuration cannot resolve inside the repository.
Measured across a full run: both pre-existing manifests kept their
SHA-256, mtime and size.

### Not changed
The two existing manifests were written by earlier test runs, not by an
operator. They are left in place: deleting files in the checkout is the
operator's call.

---

## ADR-075: The Current Revision on Arch Linux, and What It Corrected

### Context
`docs/PLATFORM_SUPPORT.md` section 6 described a Linux re-verification
procedure that had never been run against the current code. It was run on
Arch Linux (kernel 7.2.9, Python 3.14.8, `backend/.venv-linux`). The first
full run: 3 failed, 1243 passed, 3 skipped.

### What the three failures were
- **`test_real_os_collection_is_refused_off_windows` was stale.** It
  predates ADR-053, which deliberately enabled Linux collection through
  `/proc/net/tcp`. It is replaced by two tests. On Linux, a poll reads
  `/proc` through the Linux reader only and spawns no subprocess. On a
  platform that is neither Windows nor Linux, poll and start still return
  501 and the PowerShell query is never called. The Windows-only
  `hostobs` sources (UDP endpoints, interface counters) still return 501
  off Windows.
- **`test_path_traversal_protection` could not test what it named.**
  httpx removes `..` segments before sending, so the app received
  `/etc/passwd`, and the expected 200 (the SPA shell) exists only when
  `frontend/dist` has been built. `create_app(frontend_dist=...)` now
  lets tests build a throwaway dist and send raw ASGI paths, which reach
  the `..` guard, the `/assets` mount and the symlink check. Without a
  build there is no fallback route and every non-API path is 404.
- **`test_an_unbounded_agent_would_wedge_on_that_batch`** - ADR-073.

### Two defects found alongside them
- On Linux, genuine collection defaulted `refresh_dns` on, so every real
  poll tried to spawn `powershell` to read the *Windows* DNS cache. It
  failed only because PowerShell is not installed. DNS cache enrichment
  now defaults on for Windows only.
- On Linux, collector status and source registration described the source
  as `Get-NetTCPConnection` with OS creation times. Linux now reports its
  own capability notes and source description: `/proc/net/tcp[6]`, no
  creation time (always poll time, flagged), `comm` only, no DNS
  enrichment.

### Result, current revision
`pytest -q -rs`: **1278 passed, 3 skipped**, 0 failed. The skips are the
two `live_windows` tests and `test_the_collector_selects_the_windows_query_off_linux`,
which asserts the non-Linux branch and therefore cannot run on Linux.
`tests/unit/test_linux_telemetry.py`: 30 passed, 1 skipped (that same
test). Loopback startup against a disposable database: `/health` 200 with
`x-request-id`, collector `stopped` with 0 polls, port closed after stop.

### Not claimed
Windows was not re-run for this revision. The identifiers
`source_type="windows_connection_table"`, `source_id="windows_local_host"`
and the `windows:tcp` prefix of `raw_reference` are still used for Linux
records. `analysis.py` parses that prefix, so renaming them is a
data-model change, not a fix. A full collector poll against live `/proc`
returned 200 once, during the reproduction, on pre-fix code; it was not
repeated, because collection is not started as a validation step. The
live `/proc` read itself is covered by `test_the_live_linux_table_is_readable`.

---

## ADR-076: Linux Closure Audit — Accounting at the Buffer Edge, Windows Probes Behind a Platform Gate

### Context
A full audit of the Linux workstream before returning to Windows: every
changed file re-read, every Windows-originating workflow inventoried, and
the frontend built and tested on Arch for the first time. Each defect
below was reproduced by a test that failed before its fix.

### Defects and fixes
1. **Events lost to a full buffer were undercounted** (pre-existing).
   `_return_batch` stopped at the first event that did not fit, counted
   one drop and silently lost the rest of the batch. It is reachable
   whenever the collector keeps offering while a batch is in flight. Now
   every event that cannot go back is counted; the oldest are the ones
   dropped, consistent with `DROP_OLDEST`.
2. **`requeue_dead_letters()` could lose every dead letter** (introduced
   in ADR-073's draft). Into a full buffer it dropped them, counted one,
   and reported them all as requeued. It now moves only as many as fit
   and leaves the rest dead-lettered.
3. **A refused probe livelocked the queue** (ADR-073 draft). A probe
   answered with a definite refusal put both events back, so every later
   flush repeated the same rounds. See ADR-073.
4. **One 413 capped batches at one event for good** (ADR-073 draft). See
   ADR-073.
5. **The DNS enrichment endpoints spawned PowerShell on Linux**
   (pre-existing). `POST /enrichment/dns/refresh` and `GET
   /enrichment/dns/diagnose` ran `powershell` on any platform; on a Linux
   host with PowerShell Core installed as `powershell` they would have run
   a Windows DnsClient script. ADR-075 stopped the collector calling it,
   but the API still did. The default DNS query now refuses off Windows
   before spawning anything, and the diagnosis endpoint answers in its
   usual shape stating the source is Windows-only. The dashboard calls
   both, so the status stays 200 rather than the 501 used by `hostobs`.
   The Windows parsing logic remains tested on every platform.
6. **`scripts/verify_live_launcher.py` ran against the operational
   database** (pre-existing). It started uvicorn on the default database
   from the caller's working directory with the caller's environment,
   posted a fabricated flow labelled `live_telemetry` into it, used a
   Windows-only interpreter path, printed "port released" without
   checking, and every check was an `assert` that `python -O` removes. It
   now uses its own throwaway directory, database and manifest directory,
   strips `PRAHARI_*`, binds 127.0.0.1 on a free port, files its probe as
   `synthetic_demo`, checks for real (it passes under `-O`), verifies the
   port closed, and runs on both platforms via `sys.executable`. The SPA
   checks adapt to whether `frontend/dist` exists, and a forecasting
   refusal through the research gate counts as correct behaviour on a
   near-empty database.

### Verified on Arch, beyond the backend suite
- Frontend: `npm ci` from the lockfile (239 packages, all from
  registry.npmjs.org with integrity hashes), `tsc` 0 errors, vitest
  **67 passed**, `vite build` succeeded. The build was written to a
  scratch directory, never to `frontend/dist`. The backend then served
  that real build in process: the shell for client routes, real assets as
  JS, 404 for missing files and unknown API paths, raw `..` paths refused
  with nothing disclosed.
- `verify_live_launcher.py` (16 checks pass, 1 by-design skip without a
  build), `simulate_browser_producer.py` against a throwaway loopback
  server (all contract checks), `verify_forecasting_pipeline.py`, and
  `manage_credentials.py` on a scratch file (written with mode 600).

### Result
Backend `pytest -q -rs`: **1284 passed, 3 skipped**, 0 failed (the same
three platform skips as ADR-075). Linux telemetry module: 30 passed, 1
skipped. Frontend: `tsc` 0, 67 passed, build succeeded. Both experiment
manifests byte-identical to their baseline; no operational database
existed or was created.

### Not claimed
Windows was not re-run. The collector was never started; Linux TCP
collection is verified through the live `/proc` read test and fixtures,
not a sustained run. The frontend was exercised by vitest under jsdom and
by serving its build, not in a real browser. `simulate_synthetic_stream.py`
hard-codes `127.0.0.1:8000` and was not run, because that port may belong
to an operator's instance.

---

## ADR-077: Restart-Safe Repeat Suppression, and Three More Agent Event-Loss Paths

### Context
A further Linux audit, tracing every event from creation to acknowledgement
or explicit loss. Each defect was reproduced first - against the real
collector service or the real in-process ingest app - and is pinned by a
test that failed before its fix.

### Collector
1. **A restart turned every still-open Linux connection into an identity
   conflict, and the poll's new connections were lost for good.** The
   fingerprint cache is in memory, so a restart (or the 50,000-entry
   clear) re-normalizes connections already stored. On Windows their
   `observed_at` is the OS creation time, so the re-insert is identical and
   absorbed. On Linux `/proc` has no creation time, `observed_at` is the
   poll time, the content differs, and `EventIdentityConflictError` rolled
   back the whole poll. Reproduced: 2 events expected, 1 stored.
   The collector now asks storage which ids it already holds
   (`Database.existing_event_ids`, parameterized and chunked) and does not
   re-insert them; the first observation stays canonical. Accounting is
   unchanged: re-observed connections count as accepted, not persisted,
   as `test_restart_preserves_previously_stored_events` already pinned.
2. **Fingerprints were marked seen before storage succeeded** (both
   platforms). Any failed write - disk full, a lock, the conflict above -
   meant the next poll suppressed those connections as repeats of events
   never stored. The adapter now forgets the fingerprints it first saw in
   a batch whose write failed (`forget_last_batch`).

### Sensor agent
3. **A record JSON cannot encode took its whole batch with it.** A
   `datetime` value (the usual one from a collector) passed validation,
   then made encoding raise inside `flush_once` after the batch left the
   buffer; the valid events beside it were lost, uncounted. It is now
   refused on `offer()` (`not_json_serialisable`, counted in
   `events_invalid`), and an encoding failure in flight - a record
   mutated after `offer()` - puts the batch, or the probe and the suspect,
   back before raising.
4. **Records the server rejected inside a 2xx were invisible.** The server
   validates each record and reports `rejected_records`; the agent read
   only stored and duplicate counts, so a batch with rejected records
   looked fully delivered. Now counted (`events_rejected_reported`) and
   logged with the server's reasons. Those events are gone - a resend
   would be rejected the same way - and are reported as such.
5. **A wrong endpoint URL dropped every batch.** 404 and 405 fell under the
   permanent-refusal rule. The ingest route never returns them about the
   data (its only data refusal is 403 for a source mismatch), so they now
   **halt** and keep the events (`endpoint_refused`, counted in
   `channel_refusals`), like a redirect.

### Scripts
`simulate_synthetic_stream.py` gained `--base-url` (default unchanged), so
it can be pointed at a throwaway server; it was then run against one. A
connection failure used to print an error and return `None`, so the script
crashed later with an unrelated error; it now exits 1.

### Kept as a limitation, not changed
- **Linux connection identity has no creation time.** It is the 5-tuple
  plus PID, so a later connection reusing the same 5-tuple and PID merges
  into the stored event: an undercount, not a failure. The socket inode
  would distinguish them, but it is excluded from records by ADR-053 and
  changing the identity derivation is a compatibility change to do
  deliberately, with a migration note, not inside a defect fix.
- **401/403 still drop the batch** (ADR-058). A rotated or revoked token
  therefore loses whatever is sent before the operator notices
  (`batches_failed_permanent`, `last_error_kind`). Recorded as a risk.
- **The buffer and dead-letter store are in memory**; killing the process
  loses both.

### Result
Backend `pytest -q -rs`: **1292 passed, 3 skipped**, 0 failed.

---

## ADR-078: The Dashboard Claimed Loopback It Could Not See

### Context
Found in a real browser during Windows validation of `4360ca3`. An
isolated server listening on `127.0.0.1:18765` displayed **"LOOPBACK
ENFORCED — Binding: 127.0.0.1:8000"**. Two defects:

1. The Audit page printed `LOOPBACK ENFORCED` with a green lock as a
   **literal string**. It never read `loopback_enforced`, so a backend
   reporting `false` would still have displayed "enforced". Without a
   report it invented `127.0.0.1:8000`.
2. `/audit/config` reported the **configured** host and port. uvicorn's
   `--host` and `--port` do not update configuration, so another port was
   misreported, and `start_prahari.ps1 -HostBinding 0.0.0.0` - which passed
   the address to uvicorn but not to the application - would have shown a
   LAN-exposed server as loopback-only.

### Decision
The application cannot observe the address uvicorn bound. Every request,
though, records the local address it arrived on, and that proves two
things and no more: the real serving port, and **exposure**, when a request
arrives on a non-loopback address. Arrival on loopback proves nothing
about the bind, since a wildcard bind accepts it too.

- `/audit/config` adds `serving_host`, `serving_port`,
  `listener_matches_configuration` and `binding_evidence`
  (`EXPOSED` / `UNVERIFIED` / `CONFIGURED`). `loopback_enforced` becomes
  false on proven exposure. A host that is not an IP address (a test
  client's `testserver`) is no evidence either way.
- The card is rendered from the report: `EXPOSED BEYOND LOOPBACK`,
  `BINDING UNVERIFIED`, `LOOPBACK CONFIGURED` or `BINDING UNKNOWN`. It
  never says "enforced": nothing in the application enforces the bind.
- `start_prahari.ps1` now sets `PRAHARI_HOST`/`PRAHARI_PORT` to the values
  it passes uvicorn, so the official launch path reports the truth.
  `start_prahari.bat` hard-codes `127.0.0.1:8000` on both sides, so it
  already agreed.

Verified in a real browser: the card read `BINDING UNVERIFIED —
Configured: 127.0.0.1:8000 · Serving: 127.0.0.1:18766` with the reason.

---

## ADR-079: Two Tables Headed "(UTC)" Showed Local Time

### Context
Also found in the browser. Events Explorer's **Observed At (UTC)** column
showed `1:50:09 PM` for an event the API returned as `08:20:09Z`: the page
formatted with `toLocaleString()`, so in India every row was 5 h 30 m off
its own header. The Audit log's **Timestamp (UTC)** column had the same
defect. In a forensic timeline, a header that misstates the zone of every
row is a data-integrity fault, not a cosmetic one.

### Decision
`fmtTimeUtc` renders `2026-10-17 08:20:09 UTC`, independent of the
viewer's zone, and the two UTC-headed columns use it. Pages that make no
zone claim keep browser-local time. A guard test fails if a page headed
"(UTC)" formats with the local-time function again. Verified in the
browser against the API's own timestamps.

---

## ADR-080: `-CheckOnly` Was Not a Check; the Verifier Never Stopped Windows Gracefully

### Context
Two launcher defects, both Windows-specific in effect.

1. `start_prahari.ps1 -CheckOnly` reached its exit only after it had
   created a virtual environment and run `pip install` if the venv was
   missing, run `npm ci` (which deletes and reinstalls `node_modules`) and
   a production build if the bundle was missing - and then reported
   `[SUCCESS]`, **even with the port already taken**. The last part was
   reproduced on Windows before the fix. The installing paths were not run
   against the old script, because they download packages.
2. `verify_live_launcher.py` stopped the server on Windows with
   `taskkill /F`, so the application's shutdown hook never ran there,
   while the script described "clean shutdown". On Linux, `terminate()` is
   SIGTERM, which uvicorn handles, so only Windows was unexercised.

### Decision
- `-CheckOnly` collects every unmet prerequisite (venv, bundle, port),
  prints each, creates nothing, and exits 1 if any is unmet. Three
  Windows-only tests run the real script in a temporary copy, so a missing
  prerequisite is genuinely missing, and compare the directory before and
  after: a check that creates files fails.
- The verifier starts the server in its own process group and stops it
  with `CTRL_BREAK` (SIGTERM elsewhere), falling back to force only after
  15 s. A forced stop is now a failed check, and the log must show
  `Application shutdown complete`. On Windows: 21 checks pass, under
  normal and `-O` interpreters, stopped gracefully.

A graceful stop with a dashboard tab still open was also tested against
the project's launch path (`python -m uvicorn`): it completed normally.

---

## ADR-081: Windows Boundaries That Had No Windows Test

### Context
Three protections were correct in code but unproven on Windows.

1. **Static-file escape.** The symlink-escape test skips on Windows
   without Developer Mode (WinError 1314), so the guard was never
   exercised on Windows. A directory **junction** needs no privilege and
   is the escape an unprivileged Windows user can create.
2. **The PowerShell subprocess boundary.** `query_windows_connections`
   handled a missing PowerShell, a timeout, a nonzero exit, unparseable
   output, empty output, PowerShell's single-object unwrapping and junk
   list items, and none of these branches was tested.
3. **Script injection, latent.** `states` was interpolated into the
   PowerShell script inside quotes. Only the built-in default is ever
   passed, so nothing was exploitable, but the first caller to pass a
   configurable value would have injected PowerShell.

### Decision
- A junction escape test for both static paths (SPA fallback and the
  `/assets` mount). It first checks that its junction really reaches the
  secret, so it cannot pass vacuously. Both paths refuse: 400 and 404.
- Sixteen subprocess-boundary tests. A missing executable is real; the
  other outcomes use a stand-in for `subprocess.run`, stated as such. One
  asserts the child is started from an argument list, never a shell, with
  a timeout.
- `VALID_TCP_STATES`, the 13 names Windows itself reports for the
  NetTCPConnection State enum, read on this host. Anything else is refused
  before a process is spawned. With the allow-list neutralised, three of
  the four injection tests fail.
- Six `live_windows` tests drive the host-observation and DNS endpoints
  against the real OS facilities, into temporary storage, proving the
  Linux platform gate did not switch Windows off.

---

## ADR-082: Windows Validation of the Linux Revision (`4360ca3`)

### What ran on Windows
Windows 11 Home Single Language 10.0.26300, Python 3.12.0 in the project
venv, Node 24.19.0, npm 12.0.2. Every check ran against temporary storage;
neither operational database was opened.

- Backend suite (`pytest -q -rs`): **1287 passed, 8 skipped, 0 failed**
  at the baseline. Final counts are in IMPLEMENTATION_STATUS (Session 31).
- `live_windows`: the real connection table was read, and a full
  collection path ran into a temporary database.
- Host observations and DNS through the API: 38 real UDP sockets read,
  2 adapters with counters, and the DNS path executed the Windows code,
  not the platform gate.
- Launcher verifier, frontend type-check, tests and an isolated build, and
  a real browser across every page, on two isolated servers.

### What was not verified, and why
- **Collector lifecycle against the operational database:** needs
  explicit authorization. The single-poll endpoint was deliberately not
  used as a substitute.
- **Live DNS parsing:** the Windows DNS client cache was empty on this
  host. The refresh ran the Windows path and correctly recorded nothing.
  The diagnosis does not establish why: reading the cache may need
  elevation, or browsers may use their own encrypted DNS. Populating the
  cache would mean sending DNS queries, so it was not done.
- **The verifier's POSIX shutdown branch** (SIGTERM) changed in shared
  code and cannot execute on Windows: re-run `verify_live_launcher.py` on
  Linux.

### Not a defect, recorded so it is not rediscovered
- `GET /api/v1/sources/windows_local_host` returns 404 on a fresh install,
  until collection first registers the source. The Live Telemetry page
  handles it deliberately (`.catch(() => null)`); the browser logs the 404
  anyway.
- `ConnectionResetError [WinError 10054]` in asyncio's proactor transport
  when a browser drops a keep-alive connection: Windows event-loop noise,
  logged at ERROR, harmless.
- The SPA has no URL router: `/forecast` serves the shell (correct
  server-side) but opens the Overview page, and clicking a page does not
  change the URL. A bookmark or a refresh always lands on Overview. This
  is a shared UX limitation, not a Windows defect. **Resolved by ADR-084.**

---

## ADR-083: A New Collector Inherited the Previous Collector's Memory

### Context
Found by running the real collector twice in one process. A brand-new
collector, on a brand-new temporary database, reported
`records_observed=100, duplicates_suppressed=75, events_persisted=0` on its
first poll. The adapter registry's `register()` returns the
**already-registered** adapter for an id. So every collector for the same
`source_id` silently reused the previous instance's `WindowsConnectionAdapter`,
including:

- **Its deduplication cache.** Connections the new collector's database had
  never stored were suppressed as repeats and never persisted. This was
  silent data loss whenever the collector was recreated (`reset_collector`,
  a second application instance in one process, or a test), and a
  test-order dependency in the existing live test.
- **Its configuration.** The new collector's `include_loopback` was ignored
  in favour of the old adapter's.

The adapter class is shared with the Linux reader, so the defect was not
Windows-specific; Windows found it.

### Decision
`AdapterRegistry.replace()` registers an adapter in place of any existing
one, and the collector uses it. `register()` keeps its
return-the-existing behaviour, which is right for the stateless stream
adapters. Three platform-neutral regression tests failed before the fix and
pass after it. Rerun on Linux.

---

## ADR-084: The Dashboard Has URLs, and Two Pages Had No Way In

### Context
The page lived only in React state. `/forecast` served the shell
(server-side correct) but opened Overview; a refresh always landed on
Overview; the browser's back button left the application; an unknown path
silently showed Overview. **System Health and Administration** were built,
typed and labelled, but had no navigation entry, so no user could open
them.

### Decision
History-API routing in `frontend/src/routing.ts`, with no new dependency
for eleven flat pages:

- One canonical path per page (`/`, `/live`, `/import`, `/stream`,
  `/events`, `/analytics`, `/feasibility`, `/forecast`, `/system-health`,
  `/admin`, `/audit`), keeping the four the launcher verifier probes.
- Aliases and trailing slashes resolve to the canonical path through
  `replaceState`, without adding a history entry.
- Navigation uses `pushState`; `popstate` drives back and forward; each
  route sets the document title.
- An unknown path shows **Page not found**, names the path, marks no page
  active and offers every page.
- Navigation buttons for System Health and Administration.

The server must serve the shell for every client route, or a deep link
fails before React runs. A backend test reads the routes from
`routing.ts` and checks each one, so the two route tables cannot drift
apart.

Verified in a real browser: deep link, refresh, a click to the
previously unreachable System Health page, back, forward, an alias and an
unknown path.

**Deployment note:** `frontend/dist` is git-ignored and was deliberately
not rebuilt here. Run `npm run build` in `frontend/` to serve this and
ADR-078/079 to users.

---

## ADR-085: Review of the Session's Own Changes

A second pass over the uncommitted work found four defects in it.

1. **The launcher leaked configuration into its caller.**
   `$env:PRAHARI_HOST`/`PORT` (ADR-078) were set in the calling PowerShell
   when the script was run as `.\start_prahari.ps1`, and remained after it
   returned, silently reconfiguring anything started later in that window.
   Proved: the caller saw `PRAHARI_PORT=45678` afterwards. They are now
   restored in a `finally`. The regression test runs a dummy `python.exe`,
   so no server can start; against the pre-fix script its probe shows the
   leak.
2. **The verifier mislabelled a self-exit as forced.** If the server
   exited between `poll()` and `send_signal()`, the error fell through to
   "forced". It now reports `already_exited`.
3. **The binding evidence claimed what it had not measured.** "CONFIGURED
   ... arrived on loopback" was also printed when the serving port was
   unknown or the arrival host was not an IP. Each case is now stated as
   what it is (`UNKNOWN`, or "no evidence").
4. **A loose test.** The UDP idempotency assertion could pass while
   duplicating. It now checks exact row accounting and that no endpoint is
   stored twice.

A `SyntaxWarning` introduced by the new test (an invalid `\s` escape in a
docstring) was also fixed.

---

## ADR-086: DNS Parsing and the Collector Lifecycle, Proven on Windows Without the Operational Database

### DNS parsing
The Windows DNS cache on this host is genuinely empty (unfiltered
`@(Get-DnsClientCache).Count` = 0), and filling it would mean DNS queries
or a hosts-file edit. Instead, five `live_windows` tests run the adapter's
**unmodified** PowerShell in real PowerShell, with only
`Get-DnsClientCache` replaced by a function returning client-only instances
of the real `MSFT_DNSClientCache` CIM class (`New-CimInstance
-ClientOnly`: in memory, never written to the system). One test reads that
class's schema from the operating system and checks every property the
script uses exists. A wrong name would make a full cache look exactly as
empty as this one.

Proven: filtering of CNAME and empty records inside PowerShell,
single-record handling, empty cache, IPv6 normalisation, shared-address
accumulation, end to end into a temporary database. **Not** proven:
`Get-DnsClientCache` itself returning populated objects; that needs a host
with a non-empty cache.

### Collector lifecycle
Two `live_windows` tests run the application's collector class with the
real `Get-NetTCPConnection` query and real DNS refresh, against a temporary
database. They cover: start, at least two background polls, stop, no poll
after stop, exact row accounting, start and stop audit entries, the source
marked disconnected, and Windows capability notes. A second collector
process on the same database does not conflict on connections still open
(the Linux ADR-077 fix, now proven on Windows). The operational database
and the application's own collector instance were not involved.

### Open: a shutdown hang seen twice, not reproduced
Two isolated servers stopped by `CTRL_BREAK` while a real browser held
connections logged `Shutting down` and then hung, needing a forced stop.
The log of one shows `ConnectionResetError [WinError 10054]` raised from
`self._sock.shutdown(SHUT_RDWR)` inside asyncio's proactor
`_call_connection_lost` - in CPython 3.12.0 that line sits in a `finally`
**before** `server._detach()`, so a reset there leaks the server's active
connection count. uvicorn's shutdown then awaits `server.wait_closed()`,
which on 3.12 waits for that count, without a timeout by default.

It could not be reproduced synthetically: idle keep-alive, pre-connected,
half-sent and reset connections - including resets that outlive the 5 s
keep-alive timeout - all stopped gracefully in about 0.2 s. A real browser
session with a tab open also stopped gracefully. No fix is applied without
a reproduction. Candidate mitigations, if it recurs: uvicorn's
`--timeout-graceful-shutdown` (bounds that wait and still runs the shutdown
hook), or a later 3.12 patch release of Python.

---

## ADR-087: Python Changed Under the Windows Results; the Shutdown Hang Is Not Fixed

### The interpreter changed
Python **3.12.10** was installed on this host on 17 Oct 2026 at 18:39,
after Sessions 31 and 32. The installer record dates it; neither those
sessions nor this one installed it. It upgraded in place the base
interpreter the project venv uses (`pyvenv.cfg` still says it was created
with 3.12.0). Every Windows result in ADR-078 to ADR-086 was therefore
measured on **3.12.0**, and everything was re-run on 3.12.10 rather than
inherited: dependencies import, `pip check` is clean, and the backend
suite, 15 live tests, the launcher verifier and the frontend all pass
(IMPLEMENTATION_STATUS, Session 33).

### The shutdown hang: investigated, not fixed
Two isolated servers hung on `CTRL_BREAK` during real-browser sessions on
3.12.0 (ADR-086). Further investigation on 3.12.10:

- **The real launcher**, with a real browser kept open and navigation
  aborting requests mid-flight (including the Live Telemetry page's slow
  PowerShell request), stopped **gracefully**: shutdown hook run, port
  closed, no process left.
- **A forced race in plain asyncio**: a client reset while the event loop
  was deliberately blocked, then the server closing that transport before
  the reset was processed. `server.wait_closed()` returned every time, and
  no 10054 was raised. The suspected mechanism - `sock.shutdown()` raising
  in `_call_connection_lost` before `server._detach()` - could not be
  triggered. The code is unchanged in 3.12.10, so this neither confirms nor
  rules it out.

Totals: 2 hangs in 15 observed stops, both on 3.12.0, none on 3.12.10, and
no deterministic reproduction on either. **No fix is applied**: any change
now would be speculative, and its effect could not be tested. Should it
recur, the candidate mitigation is uvicorn's `--timeout-graceful-shutdown`,
which bounds that wait and still runs the shutdown hook.

---

## ADR-088: The Dataset's Compatibility Was Measured, Not Assumed

### What was checked
CSE-CIC-IDS2018's ten processed CSVs, by reading the public bucket listing
and then the first 3,000 bytes (header plus one row) of each file over
HTTPS range requests. 30 KB in total was read, held in memory and
discarded; nothing was written to disk and no dataset was downloaded.

### Findings
- **Nine of the ten files have no `Src IP`/`Dst IP` columns** (80
  columns). The importer requires both, so every row would be rejected.
- **Tuesday 20-02-2018 (4.05 GB, 84 columns) carries all twelve mapped
  columns**, and its first row parses.
- Timestamps are day-first; the time zone is still unstated.
- Access needs no AWS CLI: plain HTTPS works. That corrects
  DATASET_ACQUISITION.md and FORECASTING_DATA_REQUIREMENTS.md, which also
  said the dataset was "importable as it stands". That was true of one file
  in ten.
- **CIC-IDS2017** is gated by a registration form requiring personal
  details. That is the operator's to submit, so its layout is unverified.

### Consequence
The only labelled data verified compatible today supports a narrow
experiment: one day, two attack episodes (DDoS-LOIC-HTTP, then
DDoS-LOIC-UDP). Under the default 70 % chronological split the test
period would very likely hold no positives. The options - download that
one file, register for CIC-IDS2017, or accept address-less flows as a
deliberate research-design change - are set out in DATASET_ACQUISITION.md.
Each needs a decision this work does not make.

---

## ADR-089: Independent Review Before the Windows Commit

### Context
Before committing `windows-closure`, an independent read-only review of the
actual diff found no blockers, three should-fix items and twelve nits. Each
was checked against the code before acting on it.

### Fixed
1. **The binding report still claimed loopback without evidence.**
   `loopback_enforced` stayed `true`, and `service_exposure` stayed
   `loopback_only`, when the serving port did not match the configuration
   or could not be read. Scenario: `uvicorn --host 0.0.0.0 --port 9000`
   without the launcher, browsed over loopback, reported loopback-only while
   reachable from the LAN. `loopback_enforced` is now a three-state value:
   `true` only when configured for loopback, serving on the configured port
   and with no exposure seen; `false` on proven exposure or a non-loopback
   host; **`null` when unverifiable**. `service_exposure` gains
   `loopback_configured_unverified`. The dashboard shows green only for
   `true` with a matching listener, and the lock icon follows. A test had
   locked the wrong value in; it now asserts `null`. Two older tests that
   asserted `true` through the test client's fake `testserver:80` now send
   their request to the configured `127.0.0.1:8000`, so the assertion holds
   on evidence; they were not weakened.
2. **IPv4-mapped arrivals.** On a dual-stack bind a local IPv4 client
   arrives as `::ffff:127.0.0.1`, which Python 3.12 does not call loopback.
   The report now judges the embedded IPv4 address. Test added.
3. **The README contradicted itself** ("not re-run on Windows" beside a
   Windows run; stale counts; "dist predates" beside "dist rebuilt"). The
   section was rewritten as one current status.
4. **The acceptance matrix overstated Linux status.** Row 12 said
   "Windows and Linux, current revision"; the Linux evidence is for
   `4360ca3`. It is now qualified.
5. Nits: ADR-082's router limitation is marked resolved by ADR-084; an
   import order in `AuditPage.tsx`; a wrong test comment about enum case.

The review also asked for an explicit test that a new collector inherits no
counters; it was added (zeroed `records_processed`/`records_rejected`, an
empty fingerprint cache, a fresh status).

### Not changed, with reasons
- **Verifier edge cases.** A graceful exit landing just after the 15 s
  timeout is labelled `already_exited`, and `CTRL_BREAK` needs a shared
  console. Both surface as failed checks, never as false passes.
- **Same-host reverse proxy.** The proxy connects over loopback, so the
  report cannot see the exposure. The evidence text already says the bind
  is not observable.
- **Routing accessibility.** Focus is not moved and the route change is not
  announced; the query string and hash are dropped on navigation. Recorded
  as follow-up work.
- **Pre-existing, outside this change set:** stream ingest with
  `source_id="windows_local_host"` returns HTTP 500 once a collector exists,
  because the stream path's `get_or_register` receives the collector's
  connection-table adapter. Confirmed, and raised as a separate task;
  **fixed in ADR-090.**

---

## ADR-090: External Ingestion Cannot Write Into a Local Producer's Source

### Context
Found by the ADR-089 review. Once the live collector existed,
`POST /stream/ingest/ndjson` with `source_id="windows_local_host"` returned
**HTTP 500**: the stream path's `get_or_register` returned the collector's
`WindowsConnectionAdapter`, which has no NDJSON importer.

The 500 was the visible half. Synthetic replay and CSV import accepted the
same id and **wrote into the host collector's live source**, mixing
synthetic or imported records into the local host's provenance. The
collector is created lazily, on the dashboard's first status poll. So
whether a write was refused depended on whether anyone had opened the
dashboard since the last restart.

### Decision
The ownership check sits in `resolve_ingest_source`, the documented
ingestion trust boundary, which every external write path calls: NDJSON
stream, synthetic replay, both CSV imports, research import and app-layer
ingest. The legitimate owners write internally and never pass through it.
After the existing identity checks, a source is refused when:

- it is a **reserved** id - the host collector's `windows_local_host` or
  the UDP observer's `windows_udp_endpoints` - whether or not the producer
  exists yet, so the outcome no longer depends on what has run; or
- a host collector has registered its adapter under it, which covers a
  collector started with a custom id.

The refusal is **403** `source_reserved_for_local_producer`, naming the
owner. Not 409: the sensor agent counts every 409 as an event-identity
conflict, and this is a refusal of the destination. A 403 is permanent, so
the agent drops the batch and records the reason instead of retrying.

Nothing legitimate is refused: no dashboard flow or script writes
externally into these ids, and ids that merely look similar are not
reserved.

All six external write paths call the guard: NDJSON stream, synthetic
replay, CSV raw, CSV file, app-layer ingest and research import. Two API
modules write without it, legitimately. `POST /enrichment/dns/observations`
writes only DNS observations under a fixed source the caller cannot choose.
`hostobs` is the UDP observer itself, the owner of its source. The
app-layer endpoint also has an older validator of its own that rejects the
collector's default id with 422; the guard covers the ids that validator
does not know - the UDP observer's and a collector under a custom id.

Sensor-agent semantics, exercised through the real endpoint: one attempt,
no retry, `conflicts` unchanged, counted under `batches_failed_permanent`,
`last_error_kind = source_reserved_for_local_producer`. The batch is
dropped, the policy the agent already applies to every 401 and 403.

Thirteen tests cover the stream, replay, CSV raw and file, app-layer
ingest, before-and-after collector creation, custom ids, central-mode
admin and the agent. With the guard neutralised, the ten defect tests fail
and the three non-regression tests pass.

---

## ADR-091: Event-Level Warning Measurement

### Context
Blueprint §10 requires an **event-level lead time**: "time between first
qualifying warning and documented event; report late warnings and events
with no warning." It also asks for a missed-event rate with its matching
rules defined, and false alarms per unit time rather than per window.

Every metric PraHari reported counted **windows**. The target
specification said so itself, in three limitations:

- `detected_events`, `missed_events` and `false_alarms` count windows, so
  one attack spanning forty windows is counted forty times;
- event-level lead time is NOT measured;
- warning suppression is not modelled, so every positive window is a
  separate warning.

Window counting cannot answer §10's question even in principle. A window
has no "first warning", and an analyst catching one attack is not
performing forty catches. The acceptance matrix carried row 9 as PARTIAL
with "event-level matching" named as the prerequisite — a code gap, not a
data gap: it does not need a labelled corpus, only rules.

### Decision
`app/research/event_level.py` converts a window-level holdout into the
event-level view. §15 requires the rules be defined *before* test
evaluation, so `MatchingRules` is a Pydantic model, returned with every
result and SHA-256 fingerprinted: a lead time is only meaningful beside
the rules that produced it, and a fingerprint makes two results
comparable or visibly not.

- **Documented event**: a run of attack-labelled records no more than
  `episode_gap_seconds` apart. Its time origin is the first such record —
  explicitly *not* scenario start, first malicious action, or compromise,
  per the target's `NOT_EQUIVALENT_TO`. A lead time inherits whatever
  delay the labelling rule carries, and the limitations say so.
- **Warning**: a run of positive windows collapsed by
  `suppression_seconds`, so a sustained alarm counts once.
- **Qualifying**: a warning issued between L and L+H before the event.
  These bounds come from the target's own lead and horizon, not from new
  parameters — a window predicting at *t* claims [t+L, t+L+H). Matching
  therefore cannot be widened until the numbers improve.

Four properties that cost more code than ignoring them would have:

1. An event no evaluated window could have warned about is **excluded and
   counted**, not scored as a miss. Scoring it would blame the model for
   windows it was never given — an event in the training period would
   otherwise count against the holdout.
2. A warning is consumed by **at most one** event: the earliest it
   qualifies for. Two close events cannot both be credited to one alarm.
3. Quartiles are **refused** below four warned events.
4. With no documented event in reach, the report **refuses** rather than
   returning a perfect score over nothing.

### What running it found
On a trained holdout, the rate-threshold baseline scores a window-level
recall of **1.000** while warning **0 of 3 events**. It flags every
window, so suppression collapses its permanent alarm into a single
warning — which reads as "1 false alarm", i.e. as a quiet model.

The detection verdict is correct: an alarm that never stops says nothing
new at the moment it matters, which is precisely what suppression
encodes. But the burden was understated. `alarm_duty_cycle` is therefore
reported beside the warning count, and leads the limitations above 50%,
so a low warning count cannot be misread as precision. The discrepancy
between window recall and event-level warning is the finding this module
exists to surface, not a defect in it.

### Scope
`HoldoutPredictions` now carries each row's prediction time, refusing a
misaligned list rather than trimming it; the stacked and LSTM models'
times are sliced exactly as their rows are. `POST /forecast/event-level`
re-reads the holdout in memory and never retrains, so nothing about the
test period can influence the model. The dashboard panel shows the
distribution rather than a bare median, and prints the matching rules and
fingerprint beneath it.

The target specification moves 1.1.0 → **1.2.0**: the three limitations
now say which scope they apply to and where the event-level numbers are
read from, instead of declaring the capability absent. The window-level
metrics still count windows, and still say so.

### Evidence
24 unit tests fixing the arithmetic by hand, mutation-checked: reversing
the first-qualifying scan, disabling suppression, scoring out-of-coverage
events and allowing warning reuse each break tests. 11 integration tests
through the real pipeline and API, no skips. 8 frontend tests.

### Not established
Nothing here makes a forecasting claim. On synthetic labels every number
describes invented data, and the report says so before any metric.

---

## ADR-092: A PostgreSQL Backend, Proven Against a Real Server

### Context
The blueprint proposes "SQLite local; PostgreSQL central" (§4.3, §9).
ADR-071 wrote the storage contract and corrected an earlier status report
that had claimed "repository abstractions already exist" — they did not.
It then stated what still did not exist: "It does not make PostgreSQL
work. No PostgreSQL backend exists, no driver is installed, and no server
was available to test against."

The condition for closing it was written down at the same time: a backend
satisfying the Protocol, a driver, and the conformance suite passing
against a REAL server — "A mock does not count: the properties tested
here - atomic batches, idempotent identity, concurrent writers - are
exactly what a mock cannot exhibit."

A PostgreSQL 16.15 server was available in this environment, so the
runtime half of that blocker no longer held.

### Decision
`app/storage/postgres.py` implements `TelemetryStore` over psycopg 3.

**Timestamps are ISO-8601 TEXT, as on SQLite, not `timestamptz`.** Native
timestamps are the more idiomatic DDL, but they would make this backend
return subtly different objects from the same logical row: different
resolution, normalised offset, and a dependence on the server's timezone
setting. Identical semantics across backends is worth more here than
idiomatic columns, and ISO-8601 UTC text orders lexicographically, so
`ORDER BY observed_at` and `MAX(received_at)` behave as before. The cost
— no server-side date arithmetic — is paid by nothing in the contract.
Booleans stay INTEGER 0/1 for the same reason.

**A batch inserts in `event_id` order.** PostgreSQL makes a transaction
wait on a row another uncommitted transaction has inserted, so two
overlapping batches acquiring ids in opposite orders deadlock and one is
aborted. SQLite cannot fail this way because it serialises writers. One
global acquisition order removes the cycle.

This was verified, not assumed: shuffling the order makes the
eight-writer contract test fail **3 runs out of 3** with
`DeadlockDetected` ("Process 6988 waits for ShareLock on transaction
1032 ... while inserting index tuple in relation normalized_events"), and
the sorted version passes 3 of 3.

**An in-process write lock was written and then removed.** It made the
concurrency test pass without testing anything — eight threads serialised
by a lock never exercise concurrent transactions — and it would do
nothing for a second process against the same database, which is exactly
the central-mode case the blueprint describes. The ordering carries the
guarantee; the lock would only have hidden whether it worked.

**Both backends share one set of row converters**, promoted to module
level in `database.py`. Two backends restating the same mapping is how
they drift into returning different objects from one row. Cross-backend
equivalence tests assert `model_dump()` equality for events (including an
all-null one), analyses (including the `-1` "not recorded" sentinel) and
import summaries.

**psycopg is optional.** Local mode runs on SQLite and must not be made
to depend on a driver it never loads. `PostgresStore` refuses to
construct without it rather than falling back to SQLite: silently writing
central telemetry to a database other than the configured one would be
worse than failing.

### Defects this found
Two that the shared conformance suite never reached, caught by the
PostgreSQL-specific tests: `AmbiguousParameter` from an uncast parameter
in `refresh_source_activity`'s CASE predicate, and a foreign-key
violation that had to be raised rather than absorbed as a duplicate —
absorbing it would have discarded the event and reported success.

Two conformance tests were themselves SQLite-specific and are now
backend-neutral: one compared `tuple(row)`, which yields the KEYS of a
psycopg dict row, and one reopened SQLite regardless of the parametrized
backend.

### Evidence
Backend suite with the server: **1400 passed, 22 skipped, 0 failed**.
Conformance suite: 23 passed, every parametrized test running against
both backends. PostgreSQL-specific suite: 15 tests.

Without `PRAHARI_TEST_POSTGRES_DSN` the 23 PostgreSQL tests **skip**
(1377 passed, 45 skipped). A machine with no server has no evidence about
PostgreSQL, and a green run there must not read as if it had.

### Not established
The application still runs on SQLite. The three leaks in
`KNOWN_ABSTRACTION_LEAKS` still issue SQLite-dialect SQL directly, so
this backend cannot yet be substituted under the running application —
that, not the backend, is now what stands between a conforming store and
a PostgreSQL deployment. A conformance run says nothing about production
deployment, TLS termination, backups, migrations or a tuned server, and
the server used here was a loopback instance with trust authentication.

---

## ADR-093: Closing the Abstraction Leaks — The Application Runs on PostgreSQL

### Context
ADR-071 recorded three modules outside `storage/` that opened a raw
connection and issued SQLite-dialect SQL themselves:

- `app/api/v1/audit.py` — `SELECT * FROM audit_events ORDER BY id DESC`
- `app/api/v1/system_health.py` — `PRAGMA integrity_check`,
  `journal_mode`, `page_count`, `page_size`, `table_info`
- `app/services/retention.py` — counting and deleting events by
  `observed_at`, category and source

It also recorded what they cost: "A second backend cannot be substituted
until each moves behind a method of this contract", and kept a ratchet
test so a fourth could not appear unnoticed.

ADR-092 then built a conforming PostgreSQL store and had to carry the
same caveat: conforming, but not substitutable. The leaks, not the
backend, were what stood between the two.

### Decision
The queries move behind the contract; the **policy stays where it was**.

- `list_audit_events(limit, offset, resource_type)` returns plain dicts.
  Storage describes rows; the route decides how to present them.
- `count_events_before` / `count_events_at_or_after` /
  `oldest_event_ids_before` / `delete_events_by_id`. Retention's
  eligibility rules, deletion budget, batching and the confirmation
  requirement stay in `services/retention.py`, which is where an operator
  safeguard belongs. Only the SQL moved. Each batch is still its own
  transaction.
- `storage_diagnostics()` — **each backend describes itself**.

That last one is the interesting case. The PRAGMAs were not a dialect
difference to translate; PostgreSQL has no equivalent of
`PRAGMA integrity_check`, and its WAL is not a per-database mode to
report. Two wrong answers were available: drop the fields, which loses a
real SQLite check an operator relies on; or map them to something
plausible, which would report "ok" for a check nobody ran.

Both keys are therefore **present and None**, each with a note saying
why, and `healthy` is accompanied by `health_basis` — "PRAGMA
integrity_check" on SQLite, "the store answered a query; no structural
check was run" on PostgreSQL. The dashboard renders a null integrity
check as "not measured" rather than borrowing the green tick. This is
§11's honesty rule applied to the storage layer: a displayed metric must
be traceable to a measurement, and a backend may not claim another's.

`KNOWN_ABSTRACTION_LEAKS` is now empty, and the ratchet test asserts that
no module outside `storage/` opens a connection at all.

### Evidence
`tests/integration/test_app_on_postgres.py` serves the **real FastAPI
application** with a `PostgresStore` in place of SQLite and drives it
through the three routes that used to leak, plus ingestion, event query,
sources and analysis. If any SQLite dialect remained in the request path,
these fail rather than a reviewer having to take the claim on trust.

The new contract methods are tested on **both** backends in the
conformance suite: audit ordering, paging and filtering; the cutoff
partitioning exactly (`before + at_or_after == total`); category and
source scoping; oldest-first deletion touching only what was named; an
empty category list refused rather than read as "everything"; and
diagnostics never reporting a check that was not run.

Backend with a server: **1426 passed, 22 skipped, 0 failed**. Without a
DSN: 1389 passed, 61 skipped. Frontend: `tsc` 0, 100 passed, build OK.

### A semantic change the move introduced, and its fix
The original retention loop selected ids and deleted them **inside one
transaction**. Behind the contract they are two calls, so a row another
writer removed in between would have been counted as this run's deletion.

`delete_events_by_id` therefore returns the rows **actually** removed —
`cursor.rowcount`, not `len(event_ids)` — and retention adds that rather
than the number of ids it asked for. The count is what an operator is
told was destroyed, so it has to be a measurement rather than an
intention. Both backends are tested on it: re-deleting the same ids
returns 0, and a mix of present and absent ids counts only the present.

### Incidental fix
`audit.py`'s route accepted only `limit`, while the dashboard had been
sending `offset` and `resource_type` as well — silently ignored by
FastAPI. Now that the query has one home, both are honoured.

### Not established
The application *can* run on PostgreSQL; it is not *deployed* on
PostgreSQL. Configuration still selects SQLite, and no migration path
from an existing SQLite database exists. Nothing about production
deployment, TLS termination, connection pooling, backups or a tuned
server is claimed: the evidence is a loopback server with trust
authentication, exercised by a test client.

---

## ADR-094: A Database URL the Wiring Cannot Serve Is Refused

### Context
Found while reviewing whether the PostgreSQL backend (ADR-092/093) could
simply be selected by configuration.

`database_url` carries a scheme — the default is
`sqlite:///./prahari.db` — so setting `PRAHARI_DATABASE_URL` to a
PostgreSQL URL *looks* like configuring PostgreSQL.

It was not. `AppConfig.get_database_path()` read the path only when the
URL began with `sqlite:///`, and otherwise fell back to
`Path("prahari.db")` — the operator's live telemetry. An operator who
pointed PraHari at PostgreSQL would have got a system that read and wrote
the local SQLite file while appearing to be configured for a central
store, with no error and nothing in the logs to say so.

### Decision
A non-SQLite URL now raises `UnsupportedDatabaseURL`, naming the URL,
saying that only `sqlite:///` is wired up, and saying that a conforming
PostgreSQL backend exists but is not selectable here.

§13's configuration rules are "Validate all configuration before starting
collection or inference" and "Fail closed when a required credential,
model artifact, or target definition is missing". A silent fallback to a
*different store than the one configured* is the opposite of both.

### Why PostgreSQL is not simply wired up
The backend conforms and the application runs on it under test (ADR-093),
but selecting it from configuration is not a matter of swapping the
class. Two protections are currently defined in terms of a database
**file path**:

- `app/core/research_store.py` keeps research data out of the operational
  database by comparing resolved paths (`is_operational_database`,
  `operational_database_paths`);
- `app/storage/guard.py` refuses to migrate a non-temporary database under
  pytest by inspecting the path.

Under PostgreSQL neither comparison means anything, and a backend swap
that silently dropped research isolation would be a worse outcome than
not offering the choice. Making PostgreSQL selectable requires restating
those two protections in terms of a store identity rather than a path.
That is a separate piece of work, and it is named here rather than
half-done.

### Evidence
`tests/unit/test_database.py` covers the refusal for `postgresql://`,
`postgres://` and `mysql://`, asserting the message says what is
supported, and covers that a SQLite URL still resolves against the
project root. Backend 1428 passed, 22 skipped, 0 failed with a server; 1389 passed, 61 skipped without one.

---

## ADR-095: Dataset Facts Are Measured, Not Inferred From a Sample

### Context
Found by running PraHari on its first real corpus (CSE-CIC-IDS2018,
607,785 imported flows spanning 31 minutes). The readiness gate refused
to allow training:

> Insufficient data: 50000 events spanning 104s. At least 200 events over
> 1800s are required.

The dataset spans **1,859 seconds**, not 104. Three call sites — the
readiness assessment and the two research-audit endpoints — read
`db.list_events(limit=50_000)` and then judged *dataset-level* properties
from that slice.

`list_events` orders by `observed_at DESC`, so the slice is the **most
recent** 50,000 rows. On synthetic fixtures, which are sparse, 50,000
events cover hours and the slice resembles the dataset. On a real corpus
they cover **104 seconds**, and the gate concluded that a perfectly
adequate dataset was too short to train on.

The same shape of error had already been recorded once, for the training
selector, and `SelectionCoverage` exists because of it. It had not been
applied to the gate that decides whether training may happen at all.

### Decision
A dataset's **count** and **span** are measured by the store:

- `event_time_range(source_id, not_before, not_after)` joins the storage
  contract, implemented on both backends as a `MIN`/`MAX` aggregate.
  Timestamps are stored as ISO-8601 UTC text, which orders
  lexicographically, so the extremes are exact. The plausibility bounds
  are passed in by the caller, so the rule that a 1601 timestamp is not
  evidence of a four-century span stays in one place rather than being
  restated in SQL.
- `assess_readiness` takes optional `dataset_event_count` and
  `dataset_span_seconds`. When supplied, the sufficiency requirements use
  them. Label and quality ratios still come from the sample, which is what
  a sample can honestly give, and the report now says so:
  `607785 events (label/quality read from a 50000-event sample)`.

The training selection ceiling moves from 100,000 to 2,000,000 for the
same reason: it was a resource bound chosen when only synthetic fixtures
existed, and on a real corpus it silently reduced the dataset to its last
few minutes — routinely one class, which the gate then refused. It is not
a research decision, and `SelectionCoverage` already reports truncation
honestly when it bites.

### What was deliberately NOT changed
The same run failed the data-quality check: 100 % of records carry
`timestamp_uncertainty`, because the publisher documents no timezone, and
only `SOURCE_LIMITED` and `SYNTHETIC_SAMPLE` are excluded from the defect
count.

There is a real argument that an undocumented source timezone is a
source-level limitation rather than a per-record defect — the importer's
own warning says relative ordering within a file is unaffected. **It was
left alone.** Reclassifying a quality flag immediately after it blocked a
run is result-driven tuning, which this project forbids: thresholds are
set before results are seen, not after.

The distinction that decided it: the span was a **measurement error** —
the code reported 104s for something that is 1,859s — and a wrong
measurement is wrong whatever it implies. The quality classification is a
**judgement** about what counts as a defect, and a judgement may not be
revised because of the verdict it produced. The first was fixed; the
second was reported and left to the operator.

### Evidence
Two conformance tests on both backends: the span is measured over the
whole selection and is scoped per source; an empty selection reports
`None` rather than a zero-width span; and plausibility bounds keep a 1601
record from stretching the span across centuries.

After the fix the same corpus reports `607785 events`, `1859s`,
`can_train: true`. Backend 1432 passed, 22 skipped, 0 failed.

---

## ADR-096: The Address-less Feature Schema, and What It Measured

### Context
Nine of the ten CSE-CIC-IDS2018 processed CSVs carry no `Src IP`, no
`Dst IP` and no `Flow ID`, so their endpoint addresses are unrecoverable
(checked, not assumed — ADR-095's provenance record). PraHari's importer
required both addresses, so those nine days were rejected row by row.

That cost was not evenly distributed. The one day PraHari **could** read,
20 Feb, holds a single attack onset, which cannot support a chronological
split. The nine it could not read include **Thursday 15 Feb, which holds
five separated onsets in one morning** — the only shape of data that can
answer the research question at all.

### Decision
Two features need addresses: `distinct_src_ips` and `distinct_dst_ips`.

The tempting fix is to accept address-less rows and let them compute
`len(set()) == 0`. That is a **fabricated measurement**: "no distinct
source addresses were observed" is a claim about the traffic, and a false
one — the flows had addresses, the export dropped them.

So the columns are **removed**, and what results is a different, named
schema rather than the same schema with two zeroes in it:

- `prahari.window_features.full.v1` — 12 features
- `prahari.window_features.addressless.v1` — 10 features

The schema is decided from the events, recorded in the windowing report
with its feature names, and stated in a note. A **mixture** is refused
(`MixedAddressAvailabilityError`): counting distinct addresses over a set
where some rows structurally lack them undercounts by exactly the
address-less share, and nothing in the number would show it.

The import policy gains `address_columns`, **declared and header-checked
in both directions**, for the same reason `timestamp_format` is declared:
declaring them absent when the file has them would discard real data;
declaring them required when the file lacks them rejects every row, one
at a time, for a fact that is true of the whole file. Address-less rows
are flagged `SOURCE_LIMITED`, which is already excluded from the quality
defect count — it describes the source, not the record.

### What it measured
Thursday 15 Feb imported cleanly: 659,226 flows, 0 rejected, reconciles,
two attack types (GoldenEye 41,508; Slowloris 10,990). `near_duplicate_flows`
rose to 481,160 (73 %, against 22,341 on the addressed day) — a direct
consequence of dropping addresses, counted and kept rather than dropped.

The result depends entirely on where the split falls, and that is the
finding:

| Split | Holdout contains | LSTM PR-AUC | Persistence PR-AUC |
|---|---|---|---|
| 0.6 (test starts 11:08) | attack **continuations** only | **0.9925** | 0.9562 |
| 0.5 (test starts 10:41) | an actual **onset** (11:00) | **0.3387** | 0.9420 |

At 0.6 every learned model looks strong and the event-level evaluation
**refuses**: all five documented onsets precede the holdout, so no
evaluated window could have warned for any of them. The 131 positive test
windows are continuations of an attack that began in the training period.
PR-AUC 0.9925 is measuring "an attack is ongoing", not "an attack is
coming".

At 0.5, with one genuine onset in the holdout, every learned model
collapses — the LSTM to 0.3387, random forest to 0.2112, the temporal
stack to 0.2259, against a constant baseline of 0.3115. Only
`baseline_persistence` ("attack now ⇒ attack next") stays strong at
0.9420, because detection is what this data supports.

Event-level, LSTM, at the 0.5 split:

| Measure | Value |
|---|---|
| Events in coverage | 1 (4 excluded: their onsets precede the holdout) |
| Events warned | **0** |
| Missed-event rate | **1.0** |
| Late warnings | 2 (fired during the attack) |
| False alarms | 7 — 3.08 per hour |
| Alarm duty cycle | 9.0 % |
| Lead time | none to report |

The split was moved from 0.6 to 0.5 to obtain event-level **coverage**,
not to improve a metric, and both runs are reported above precisely so
that choice is visible. Moving it made every headline number worse.

### Conclusion
**On this corpus PraHari's learned models do not forecast attack onsets.**
What looked like strong performance was detection of attacks already in
progress, and the persistence baseline does that better. The blueprint
anticipated exactly this: "Any model that cannot beat it has demonstrated
nothing."

One event in coverage is too few for a robust rate, and the report says
so in its own limitations. This is a negative result on one day of one
corpus, not a claim about the approach in general.

### Evidence
8 unit tests, mutation-checked: keeping the columns (reporting a zero) and
tolerating a mixture each break tests. Both declaration guards verified
through the real API, in both directions. Backend 1442 passed, 22 skipped,
0 failed.

### Not established
A 10-feature schema is not comparable with the 12-feature one; no
controlled ablation between them has been run. The address-less days are
also truncated at the spreadsheet row limit (ADR-095), so they are
partial captures.

---

## ADR-097: Store Identity — PostgreSQL Becomes Selectable

### Context
ADR-092 built a conforming PostgreSQL backend. ADR-093 closed the three
abstraction leaks so the application could be served from it. ADR-094
then refused a PostgreSQL `database_url` outright, and said why it was
not simply wired up:

> Two protections are currently defined in terms of a database **file
> path**: research-store isolation ... and the protected-database guard
> ... Under PostgreSQL neither comparison means anything, and a backend
> swap that silently dropped research isolation would be a worse outcome
> than not offering the choice.

It named restating both in terms of a store identity as the next piece of
work. This is that work.

### Decision
**A store identity** both kinds of store can produce:

- SQLite → `sqlite:/abs/path/prahari.db`
- PostgreSQL → `postgresql:<host>/<database>#<schema>`

It is **credential-free by construction**, because it is compared, logged
and reported — a DSN password must never travel with it, and a test
asserts that. Scoping by schema is what lets one server hold several
distinct stores.

**Research-store isolation** no longer demands a path. When the
operational store has none, it contributes none, and a SQLite research
store then cannot collide with it at all — the guarantee holds trivially
rather than being dropped. The well-known operational filenames stay
protected regardless of what the live store happens to be, so a stray
import still cannot land in one.

**The protected-store guard** gains `assert_safe_schema_to_initialize`.
`path_is_temporary` cannot see a PostgreSQL store, and the equivalent
question is whether the schema is a throwaway one. Without it, a test
against a configured server would run DDL in `public` — the schema a
deployment would use. `PostgresStore.initialize()` calls it, under the
same explicit opt-out as the file guard.

**`get_db` selects the backend from the scheme.** Both satisfy
`TelemetryStore`, so nothing downstream branches on which is in use, and
the dependency's return type is deliberately the contract rather than
`Database`. The three callers that only *displayed* the path now use
`store_descriptor()`.

### Evidence
The application was started with
`PRAHARI_DATABASE_URL=postgresql://...` and nothing else changed:

| Check | Result |
|---|---|
| `/api/v1/health` | `connected: true`, store `postgresql:/prahari_live/prahari_live#prahari_live_run` |
| `/api/v1/system/health` | `backend: postgresql`, server 16.15, `integrity_check: null` with its note |
| Ingest 600 synthetic flows | 600 accepted, 0 rejected |
| Query back | 600 total |
| `POST /analysis/run` | 600 events analysed |
| **Real Chromium against it** | **27/27** |

10 tests, mutation-checked: ignoring the scheme (restoring the ADR-094
defect) and a guard that always allows each break one. Backend 1452
passed, 22 skipped, 0 failed; frontend `tsc` 0, 100 passed.

### Not established
A deployment, still. There is no migration path from an existing SQLite
database, and nothing about TLS termination, connection pooling, backups,
failover or a tuned server is tested — the evidence is a loopback server
with trust authentication. The research store remains SQLite-only, which
is deliberate: it holds a local research artefact, not operational
telemetry.

---

## ADR-098: A Real Browser, Because jsdom Is Not One

### Context
Every frontend check ran in jsdom. jsdom does not execute a real History
API, does not round-trip a reload, and does not fetch from a real server.
Three recorded defects were only visible once something actually
rendered: ADR-084 (the page lived in React state, so every refresh
returned to Overview), ADR-089 (the binding card), and the blank-page
`undefined.toFixed` that unmounted the whole tree.

The acceptance matrix carried "a real-browser session" as an outstanding
prerequisite on row 1. It needed a browser, not the operator's machine —
and this container ships Chromium.

### Decision
`scripts/verify_browser_session.py` drives **real Chromium** against the
**real backend** serving the **real `frontend/dist` bundle**, asserting
what jsdom cannot: every canonical route and alias as a typed deep link,
a reload that stays put, back and forward, an unknown path rendering Not
Found, a React root that is never empty, and no uncaught error.

**One assertion was corrected rather than kept.** "No console errors"
failed on a 404 from `GET /api/v1/sources/windows_local_host` — the
dashboard probing for the Windows collector's source, which legitimately
does not exist on Linux and which the page handles. A browser logs a
console error for **every** 4xx, including handled ones, so console text
cannot tell a defect from a probe. The check now classifies *responses*:
a 404 under `/api/v1/sources/` is an expected absence, anything else is a
failure. The same shape of false positive as the `src_ip` substring in
the manifest privacy test — a loose proxy colliding with legitimate
behaviour, fixed by testing the intent.

### Evidence
27 checks, 0 failures, against both a SQLite-backed and a
PostgreSQL-backed instance. Mutation-checked: a wrong expected heading
and a wrong expected alias target each produce a failure, so the checks
are not vacuous.

### Not established
One browser engine on one platform. No screenshot or visual-regression
comparison, no interaction beyond navigation — no form is filled, no
training is started from the UI — and no mobile or reduced-viewport
check.

---

## ADR-099: The Host Collector's Source Identity Is Configurable

### Context
`MULTI_SYSTEM_CAPABILITY.md` records "Multiple endpoint identities" as
PARTIAL and offers two resolutions: a per-source collector registry, or
"accept that each endpoint runs its own agent". The second was already
the deployment story for Windows — and it did not work.

`DEFAULT_SOURCE_ID = "windows_local_host"` was a constant.
`StartCollectorRequest` carried only `interval_seconds`, and no
configuration field or environment variable reached the collector. Every
Windows host that ran PraHari therefore filed telemetry under the same
source id.

That is not only ambiguous labelling.
`WindowsConnectionAdapter.fingerprint` hashes the adapter id as its
**first** component, so two hosts sharing the id produce the same
`event_id` for a connection matching on protocol, addresses, ports, pid
and creation time. Storage is `INSERT OR IGNORE`, so the second host's
observation is silently discarded and the row is attributed to the
first. Verified directly: two adapters on the default id return
`d6ffcb93-…` for the same record; with distinct ids they diverge.

The surrounding machinery already anticipated this. The service and the
adapter both take the id as a parameter, and `local_producer_owning`
documents "a collector started with a custom source id". Only the
configuration path was missing.

### Decision
Add `collector_source_id`, resolved by
`AppConfig.resolved_collector_source_id()`.

* **Unset means the historical default.** An existing installation keeps
  its source and its stored events; this is not a migration.
* **A configured id is validated once, at resolution.** Lowercase
  `[a-z][a-z0-9_-]*`, at most 64 characters. An id reaching the adapter
  is already baked into event identity, and a bad one could not be
  corrected later without orphaning everything stored under it.
* **The UDP-endpoint observer's id is refused.** Two in-process
  producers on one source would leave the reservation guard unable to
  name which owns it.
* **It fails closed at startup**, not at the first status poll, so a
  misconfiguration cannot present as a healthy server that breaks when
  an operator opens the dashboard.
* **The reservation guard covers the configured id** (ADR-090). The
  collector is built lazily, so between a restart and the first status
  poll the adapter registry is empty; the reserved layer must name the
  configured id or external telemetry could be filed into the live
  host's own source during that window. A rejected id falls back to
  protecting the default rather than protecting nothing.

### What this does not do
It does not make one backend process collect for several hosts — the
collector is still a process-global singleton, and
`MULTI_SYSTEM_CAPABILITY.md` still records that correctly. It makes the
one-agent-per-host deployment work, which is what that document already
proposed as acceptable.

It also **cannot repair data already collected**. Two hosts that have
already run under the default id hold events that cannot be told apart
afterwards; the id must be set before their data is brought together.

### Verification
15 regression tests. Mutation-checked: a factory ignoring the
configuration, a guard not covering the configured id, and a validator
accepting anything each break a test. The guard test initially passed
under mutation because an earlier test had left that adapter in the
process-wide registry — it was reaching the registry layer, not the
reserved layer. It now empties the registry first, which is the
post-restart state it claims to be testing.

---

## ADR-100: Event Statistics Are Measured, Not Sampled

### Context
`GET /events/stats/summary` reported `total_events` from a full
`COUNT(*)`, then built its label, event-type and data-category
breakdowns from `db.list_events(limit=1000)`.

Below a thousand stored events the two agree, so the endpoint looks
correct in every small test and in a fresh installation. Past that, one
response carries a total describing every event beside breakdowns
describing only the newest thousand, and nothing in the response says
which is which.

**This is ADR-095's defect in a second place.** There, readiness
reported "0 positive" for a corpus holding 52,498 attack-labelled events
because its 50,000-row sample was the day's tail. The fix added
`label_counts()`, a GROUP BY, with a docstring arguing against "reading
a sample that may be drawn entirely from one end of the capture" — and
changed readiness only. This endpoint kept sampling.

It is not hypothetical. A Windows collector under observation reached
699 events in 22 minutes of 15-second polling, so a working afternoon
crosses the cap. Reproduced on a throwaway store: 1,200 events whose
oldest 150 are attack-labelled report `total_events: 1200` with a
breakdown summing to 1,000 — and **zero attacks**.

### Decision
Add `event_breakdown()` to the storage contract, implemented by both
backends as three GROUP BYs, and have the endpoint use it.

The response shape is unchanged — same three dictionaries, same
`"unlabeled"` key for events with no label — so no caller changes. Only
the values become complete.

`sources_count` was already a full `list_sources()` and is untouched.

### Alternatives rejected
*Raise the sample cap.* It moves the threshold without removing it, and
leaves a response that is correct until it quietly is not.

*Label the breakdowns "sampled" in the response.* Honest, and cheaper,
but the question the endpoint exists to answer is how many events of
each kind are stored. A sampled answer to that is not worth returning
when a GROUP BY costs one query.

### Verification
4 regression tests, at 1,200 and 1,100 events so the shortfall is
produced by the old cap rather than by fixture size. Mutation-checked:
restoring the 1000-row sample breaks the sum assertion and the
oldest-label assertion. A third test pins that the breakdown agrees with
`count_events(label=…)` and with `label_counts()`, so the new path
cannot disagree with the counts already trusted elsewhere.

Full suite: 1427 passed, 66 skipped, 0 failed (Linux).
PostgreSQL's implementation is **not** covered: no server is available
in this container and those tests skip rather than pass against a mock.

---

## ADR-101: A Store Identity Pinned to a POSIX Path

### Context
ADR-099 and ADR-100 close with the same caveat: "everything here ran on
Linux. The 24 `live_windows` tests skip in this environment, so no
Windows claim rests on these runs." Running the full suite on Windows 11
is what that caveat asks for, and it surfaced one failure out of 1,441 —
unrelated to either fix:

```
tests/integration/test_store_selection.py::test_a_sqlite_url_identifies_as_its_resolved_path
AssertionError: assert False
  where False = 'sqlite:C:\Users\...\prahari.db'.startswith('sqlite:/')
```

`AppConfig.store_identity()` returns `f"sqlite:{self.get_database_path()}"`,
and `get_database_path()` resolves to an **absolute** path. On Linux that
opens with a separator, so `sqlite:/home/...` satisfies
`startswith("sqlite:/")`. On Windows it opens with a drive letter, so the
identity reads `sqlite:C:` and then the path, and the assertion fails.

ADR-097's store-selection suite had only ever run on Linux. The
acceptance matrix carried `1336 passed, 8 skipped, 0 failed` for Windows
from a revision predating it, so nothing had contradicted the claim.

### Decision: fix the test, not the identity
The assertion was the thing encoding a platform assumption, not the
product.

`store_identity()` is documented as "a canonical, comparable name for the
configured store", and that is all its consumers want: it is logged
(`main.py`), displayed (`/health`, `/research/import`), and compared for
inequality (`research_store.py`). Nothing parses it as a URI, and it is
deliberately not one — a URI would need escaping rules that a comparison
does not benefit from. A host spelling its own absolute paths its own way
is correct behaviour.

Rewriting the identity as `sqlite:///C:/Users/...` to satisfy a leading
slash would change a value that the protected-store guard and the
research-isolation check both compare, to buy nothing.

So the test now asserts the actual contract — scheme plus resolved
absolute path — on any platform:

```python
assert resolved.is_absolute()
assert identity == f"sqlite:{resolved}"
```

### Regression test
`test_the_sqlite_identity_makes_no_posix_path_assumption` pins it
separately and names the defect, so a future rewrite back to a
separator-prefixed form fails on Linux as well as on Windows rather than
silently passing on one of them.

### Evidence
`tests/integration/test_store_selection.py`: 10 passed, 1 skipped
(PostgreSQL, no `psycopg`).

Full backend suite on Windows 11, Python 3.12.10, on this branch:

| Run | Result |
|---|---|
| 7ad866e as inherited | **1 failed, 1440 passed, 52 skipped** in 149.5 s |
| with this fix | **1442 passed, 52 skipped, 0 failed** in 150.2 s |

All **15** `live_windows` tests pass against real connection-table
collection. ADR-099 and ADR-100 both refer to "the 24 `live_windows`
tests"; `pytest -m live_windows --collect-only` collects **15** on this
revision, so that figure is wrong in both ADRs. The marker count, not the
Windows result, is what was misstated.

The Linux runs recorded in ADR-099 and ADR-100 report 66 skips against
52 here. The difference is platform, in both directions: Linux skips the
15 `live_windows` tests and Windows skips the Linux `/proc` and symlink
tests. A working copy with no `.git` skips a further 19
(`test_ignore_rules.py` needs `git check-ignore`), which is why a figure
measured outside a checkout is not comparable.

### Not established
Whether `store_identity()` should be a URI at all. It is compared and
displayed, never parsed, so the question was not forced here. The
PostgreSQL branch of `store_identity()` is covered by tests that run
without a server, but `event_breakdown()` and the ADR-099 reservation
guard on PostgreSQL remain unexercised — no server was available, and
those tests skip rather than pass against a mock.

---

## ADR-104: The PostgreSQL Backend Is Now Exercised, Including a Path That Never Ran

### Context
ADR-092 built `PostgresStore`, ADR-097 made it selectable, and ADR-100
added `event_breakdown()` to the storage contract and implemented it in
both backends. Every one of those closed with the same caveat: the
PostgreSQL tests **skip** without a server, and skipping is not passing.

The container running this work was recycled between sessions, so the
server ADR-092 and ADR-097 used was gone and 44 tests were skipping.

### Decision
Run a real server here and close the caveat rather than carry it
forward. PostgreSQL 16.15, initialised in a throwaway cluster owned by
the `postgres` user, trust auth, loopback socket only.

Full suite **with** the server: **1474 passed, 22 skipped, 0 failed**.
Without it: 1428 passed, 66 skipped. The 22 remaining skips are
Windows-only.

### What this found
`event_breakdown()` was in the contract Protocol and implemented twice,
but **nothing called the PostgreSQL implementation.** ADR-100's own
endpoint test drives `Database` directly, so the second implementation
shipped having never executed. The 60 passing storage tests did not
touch it; the method simply had no caller on that side.

A cross-backend conformance test now covers it, and the gap it closes is
real rather than theoretical: with the PostgreSQL implementation mutated
to use SQLite's `?` placeholder instead of `%s`, the `[postgres]`
parametrization fails with `ProgrammingError` while `[sqlite]` passes.
That is exactly the class of defect an unexercised second implementation
hides — correct-looking code that cannot run.

### The general lesson, recorded because it recurs
Adding a method to `contract.py` does not make the conformance suite
test it. The suite tests what it has a test for. ADR-093 emptied
`KNOWN_ABSTRACTION_LEAKS` and a test asserts both backends *implement*
every contract member, but implementing and exercising are different
claims. A new contract member needs a parametrized test in the same
change, or the second backend's version is decoration.

### Not established
Still no PostgreSQL **deployment**: no migration path from an existing
SQLite database, and TLS, connection pooling, backups, failover and a
tuned server remain untested. This was a loopback cluster with trust
auth, created and discarded for the test run. The acceptance matrix's
PostgreSQL row says the same.

---

## ADR-105: No Security-Platform Adapter Will Be Built Without a Format

### Context
Blueprint §5 lists six adapter categories. Five exist: host telemetry,
network flows (parsing), network sensor (Zeek/Suricata-shaped),
file/replay and synthetic. The sixth — IDS/IPS, firewall, EDR or SIEM
exports and APIs — has none, and `BLUEPRINT_COVERAGE.md` has carried §5
as `PARTIAL` for that reason.

Asked which export format was available to target, the operator's answer
was that none is: nothing available, and no way to find out.

### Decision: not built, and the reason recorded
This is ADR-072's reasoning applied to a second adapter category. There,
a NetFlow collector fed packets this project constructs was refused
because it "would prove the decoder agrees with its author, and a UDP
listener is attack surface". The same holds here with nothing to listen
to: an adapter written against an imagined Splunk, Wazuh or Defender
export would encode this project's guess at a schema, pass tests built
from the same guess, and mis-map silently against the real thing.

§5.3 requires rejecting incompatible required fields "with a useful
error rather than silently mis-mapping them". A mapping invented without
a real export cannot honour that, because there is no ground truth for
what the required fields are.

So §5 stays `PARTIAL` **by decision, not by omission**, and this is the
entry that says so. It is a missing input, not missing work.

### What would change it
One real export file — a Wazuh `alerts.json`, a Suricata-fed SIEM
export, a Windows Defender or Sysmon EVTX export, a pfSense or OPNsense
firewall log. The `json_stream.py` adapter already handles
Zeek/Suricata-shaped JSON, so a JSON-lines security export is the
shortest path and may need field aliases rather than a new adapter.

Until then no fabricated adapter is better than a plausible one, which
is the §12 honesty rule applied to code instead of to numbers.

---

## ADR-106: Inference Latency Is Measured

### Context
Blueprint §10 lists "inference latency and throughput" among the
measurements an evaluation reports. Nothing measured it. The System
Health models block returned a hardcoded `inference_latency: None` with a
comment saying no instrument existed — honest, and a gap
`BLUEPRINT_COVERAGE.md` carried as `ABSENT — never measured`.

### Decision
`services/inference_metrics.py`, deliberately the same shape as
`services/admission.py`'s latency summary so a reader comparing
ingestion and inference compares like with like.

**What is measured is the decision that matters.** The instrument times
`ThreatForecastingPipeline.predict_recent_window` — feature extraction
plus model scoring — and nothing else. It excludes:

* the readiness gate, which refuses before any model runs;
* the database read that fetches the window, which measures storage;
* automatic training, which is not inference and is thousands of times
  slower, so a single autotrain would dominate every percentile.

A figure that mixed those in would describe the endpoint, not the model.
§16 keeps ingestion delay and processing delay separate for the same
reason, and the response carries a `measures` string saying so, because a
latency number without its boundary invites exactly that misreading.

Recorded per **resolved** model id: a random forest and a NumPy LSTM are
different measurements, and averaging them answers no question anyone
asked. Samples are bounded at 256, as admission control's are, so a
long-running process cannot grow the list without limit — and the
events-per-window list is trimmed in step with the latencies, or
throughput would be quoted against a window size never measured with it.

Throughput is windows per second derived from those same samples and
reported beside the events-per-window range, rather than as an
independent claim: a rate without its window size is not reproducible.

Nothing measured yields `None`, not a structure full of nulls. An empty
shape reads as a measurement of zero, which would claim instantaneous
inference.

### A pre-existing test that pinned a literal
`test_unmeasured_inference_latency_is_null_not_zero` asserted
`inference_latency is None` unconditionally. That held only because the
field was a constant; it tested a literal, not a behaviour. With a real
instrument, whether samples exist depends on whether anything in the
process ran a prediction first.

It now asserts the invariant its own name claims — absent, or carrying
real samples, never a populated shape of nulls or zeros — following the
precedent its neighbour already documents for the model registry:
"asserting an empty registry would only test the suite's ordering."

### Verification
11 regression tests. Mutation-checked: an empty summary returning a
zero-filled shape, unbounded samples, and System Health reverting to a
hardcoded `None` each break a test; a phantom zero-filled model entry
breaks four, including the rewritten one.

Full suite with a real PostgreSQL 16.15 server: **1485 passed, 22
skipped, 0 failed** (Linux).

### Not established
No latency figure is published anywhere as a service target. §16 is
explicit that numerical targets are agreed only after measurement, and
these are per-process samples from a development container — not a
benchmark of any deployment. §10's **throughput under load** is still
unmeasured; that needs the §16 ingestion benchmark, which does not exist
yet.

---

## ADR-107: Calibration Is a Reliability Curve, Not One Number

### Context
Blueprint §10 requires calibration among the reported measurements. Only
a Brier score existed, and `BLUEPRINT_COVERAGE.md` carried §10's
calibration row as `PARTIAL — Brier score is computed; no reliability
curve`.

A Brier score mixes calibration with discrimination. A model can improve
it by growing sharper while staying badly calibrated, and it cannot
answer the question an operator actually has: *when this model says 0.8,
does the thing happen about 80 % of the time?*

### Decision
`research/calibration.py` builds a reliability curve — predicted
probability against observed frequency, per bin, with the count each bin
rests on — reached by `POST /forecast/calibration`. It uses the holdout
already in memory, the same split and labels every other metric was
computed on, and never retrains.

**What it refuses**, which is the part that matters:

* **A single-class holdout.** Observed frequency would be 0 or 1 in
  every populated bin whatever the model predicted, so the curve would
  describe the holdout rather than the model. This is ADR-091's refusal
  applied to calibration.
* **Fewer than 20 scored windows.** Ten bins over a handful of windows
  is a list of individual predictions wearing a histogram's name.
* **Values outside [0, 1]**, which mean the caller passed decision
  scores. A frequency cannot be compared with one.

**Why counts travel with every bin.** An observed frequency computed
from three windows is noise with a decimal point. This project has twice
been misled by a statistic whose sample size was not in view — window
recall 1.000 on a single-class holdout (ADR-091) and PR-AUC 0.9925
measuring attack continuation (ADR-096). So every bin carries `count`,
bins below four samples are marked `frequency_reliable: false`, and the
summary error is reported **twice**: over all bins and over reliable
bins only. Those disagree whenever a thin bin is badly calibrated, and
one number would hide which population it described.

Nothing is smoothed, interpolated or dropped to make the curve look
continuous. An empty bin is reported as empty: "the model never
predicted in this range" is a finding about the model, not a hole to
fill. The gap is signed, so over- and under-confidence stay
distinguishable rather than collapsing into a magnitude.

Expected calibration error is count-weighted — the usual definition, and
stated in the report rather than assumed, because an unweighted mean
over bins lets a three-sample bin outvote a three-hundred-sample one.

### Verification
15 regression tests. Mutation-checked: scoring a single-class holdout
instead of refusing, treating every bin as reliable, an unweighted mean
over bins, and a top-edge off-by-one that silently drops predictions of
exactly 1.0 — each breaks the test that names it.

Two of those tests initially failed because **my own fixtures** were
single-class, which the implementation correctly refused. The fixtures
were wrong, not the code.

Full suite with a real PostgreSQL 16.15 server: **1500 passed, 22
skipped, 0 failed** (Linux).

### Not established
Calibration is measured on the holdout the model was evaluated on, so it
says nothing about calibration on another period, deployment or dataset.
Equal-width binning means a model whose predictions cluster in one range
leaves most bins empty — visible in the counts, and a fact about the
model rather than a defect in the measurement. And a well-calibrated
model can still be useless: calibration is independent of
discrimination, so it must be read beside PR-AUC and the event-level
report, never instead of them.
