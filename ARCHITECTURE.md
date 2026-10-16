# PraHari — System Architecture & Engineering Specification

**System Name**: PraHari — The Digital Sentinel  
**Architecture Version**: 1.0.0  
**Scope**: Unified Full-Stack Cybersecurity Intelligence, Multi-Format Telemetry Ingestion, SQLite Persistence, Descriptive Analytics, and Causal Future Threat Forecasting.

---

## 1. High-Level Architecture Overview

PraHari is structured as an integrated, monolithic application designed for local and edge deployment with zero cloud dependencies. It unifies a high-performance Python FastAPI backend, a transactional SQLite database with WAL mode, and a compiled modern React SPA dashboard served directly on loopback (`127.0.0.1:8000`).

```
                              ┌─────────────────────────────────────────────────────────┐
                              │                 PRAHARI SYSTEM BOUNDARY                 │
                              │                                                         │
  Ingestion Sources           │   FastAPI Backend (Port 8000 / Loopback)                │
  ─────────────────           │   ──────────────────────────────────                    │
  • CSV Datasets              │   ├── Static File & SPA Fallback Handler                │
    (CIC-IDS2017/2018) ────►  │   │   └── Serves React Production Assets from dist/     │
  • Zeek conn.log (NDJSON) ──►│   │                                                     │
  • Suricata EVE Flow ───────►│   ├── Ingestion Adapters & Canonical Normalizer         │
  • Synthetic Replay Stream ─►│   │   ├── IP / Port / Timestamp Validation Engine       │
                              │   │   └── Quality Flagging & Rejection Accounting       │
                              │   │                                                     │
                              │   ├── SQLite Storage Engine (WAL Mode + Foreign Keys)   │
                              │   │   ├── telemetry_sources                             │
                              │   │   ├── normalized_events                             │
                              │   │   ├── import_summaries                              │
                              │   │   ├── descriptive_analyses                          │
                              │   │   └── audit_events                                  │
                              │   │                                                     │
                              │   ├── Descriptive Analytics Engine (Factual Summary)    │
                              │   │                                                     │
                              │   ├── Research Feasibility Engine (Scientific Gating)   │
                              │   │   └── Monotonicity, Label Balance, Sample Adequacy  │
                              │   │                                                     │
                              │   └── Causal Threat Forecasting Pipeline                │
                              │       ├── Window Feature Extractor (W=60s, L=30s, H=60s)│
                              │       ├── Chronological Temporal Split (No Leakage)     │
                              │       ├── Baselines: Majority Class & Rate Threshold    │
                              │       └── Models: Logistic Regression & Random Forest   │
                              └─────────────────────────────────────────────────────────┘
                                                           │
                                                           ▼
                              ┌─────────────────────────────────────────────────────────┐
                              │               React + TypeScript SOC SPA                │
                              │  • Overview Dashboard • Ingestion Dropzone & Replay     │
                              │  • Events Explorer    • Descriptive Analytics View      │
                              │  • Research Gate Audit• Threat Forecasting Benchmarks   │
                              └─────────────────────────────────────────────────────────┘
```

---

## 2. Ingestion Adapters & Canonical Normalization

All raw inputs pass through strict schema validation before persistence:
1. **CSV Import Adapter (`CsvImportAdapter`)**:
   - Parses multi-column flow logs (e.g., CIC-IDS2017/2018).
   - Validates IPv4/IPv6 addresses, transport ports (`0` to `65535`), and timestamp formats.
   - Rejects corrupted or out-of-range rows and categorizes rejection reasons (`invalid src_ip`, `invalid dst_port`, `invalid timestamp`).
   - Assigns `QualityFlag` warnings for suspicious durations, high ports, or timestamp uncertainty.
2. **JSON Stream Adapter (`JsonStreamAdapter`)**:
   - Supports line-delimited JSON (NDJSON).
   - Automatically detects and maps **Zeek** `conn.log` (`id.orig_h`, `id.resp_h`, `id.orig_p`, `id.resp_p`, `proto`, `duration`, `orig_bytes`, `resp_bytes`).
   - Automatically detects and maps **Suricata EVE** format (`src_ip`, `dest_ip`, `src_port`, `dest_port`, `flow.bytes_toclient`, `flow.bytes_toserver`, `flow.age`).
   - Normalizes Unix timestamps (seconds and milliseconds) and ISO-8601 strings into UTC `datetime` objects.
3. **Synthetic Flow Generator (`SyntheticFlowGenerator`)**:
   - Generates deterministic, controlled flow sequences for testing, demonstration, and offline evaluation without touching physical network cards.

---

## 3. Storage Layer (`Database`)

PraHari uses an embedded SQLite database (`prahari.db`) with:
- **Write-Ahead Logging (`PRAGMA journal_mode=WAL`)** for concurrent read/write throughput.
- **Foreign Key Enforcement (`PRAGMA foreign_keys=ON`)** for referential integrity.
- **Idempotent Insertion**: Events are inserted using `INSERT OR IGNORE INTO normalized_events` based on unique `event_id` UUIDs, preventing duplicate flow recording across replayed batches.
- **Audit Logging**: Every mutation (imports, analysis computations, model trainings, configuration changes) is recorded in `audit_events`.

---

## 4. Descriptive Analytics vs. Predictive Forecasting

A core principle of PraHari is the strict separation between **factual observations** and **speculative predictions**:

### A. Descriptive Analytics Engine
- Computes factual summaries of historical telemetry:
  - Event count, time boundaries (`earliest`, `latest`).
  - Label distribution and protocol breakdowns (TCP, UDP, ICMP).
  - Top source and destination IP addresses, top destination ports.
  - Duration, packet, and byte aggregates.
  - Quality flags and warning frequencies.
- Does **not** fit models, predict future events, or produce propensity scores.

### B. Causal Future Threat Forecasting Engine
- **Objective**: Predict whether a security incident will occur in a future prediction window based strictly on retrospective network telemetry.
- **Observation Window ($W$)**: 60.0 seconds $[t - W, t]$.
- **Lead Time Buffer**: 30.0 seconds $[t, t + \text{lead\_time}]$.
- **Prediction Horizon ($H$)**: 60.0 seconds $[t + \text{lead\_time}, t + \text{lead\_time} + H]$.
- **Causal Feature Extraction**:
  - `flow_count`, `distinct_src_ips`, `distinct_dst_ips`, `distinct_dst_ports`
  - `total_bytes`, `avg_bytes_per_flow`, `total_packets`, `avg_packets_per_flow`
  - `tcp_ratio`, `udp_ratio`, `avg_duration`, `byte_rate_per_sec`
- **Leakage Prevention (purged chronological split)**:
  - Sliding windows with stride $15s$ overlap: each feature vector shares
    $W - S$ seconds of telemetry with its neighbour.
  - A window's label describes $[t+L, t+L+H]$ — a period that *later* windows
    observe as input. A bare index split therefore leaks twice over: test
    windows re-observe training telemetry, and training labels describe data
    that test windows take as features.
  - PraHari enforces **chronological splitting with a train-side purge**.
    Training windows whose label horizon reaches into the evaluation period
    are dropped; the holdout is left intact. The purge spans
    $\lceil (W + L + H)/S \rceil$ windows.
  - Instances are **never** reassigned across the boundary. If purging leaves
    too few training windows, or the training period is single-class, or no
    holdout remains, the pipeline **refuses** to train and returns the split
    evidence (HTTP 422) rather than reporting a contaminated score.
  - The split is published at `GET /api/v1/forecast/integrity`.
- **Configuration disclosure**: short datasets force the nominal $W/L/H/S$ to
  be rescaled. The configuration *actually used* is reported in every
  windowing report, so no result can cite the nominal parameters for an
  evaluation that did not use them.
- **Metric self-description**: every metric carries `test_positive_count`,
  `test_negative_count` and `metrics_interpretable`. With zero positive test
  windows, recall/F1/PR-AUC are undefined as measures of detection ability
  and are flagged as such.
- **Prediction provenance**: `/forecast/predict` always reports
  `is_validated_model`, `validation_status` and `is_actionable_forecast`. A
  score from an untrained or unvalidated model is explicitly labelled
  UNVALIDATED and must not be read as a forecast.
- **Baselines & Metrics**:
  - Compared against `Majority Class Baseline` and `Rate Threshold Baseline`.
  - Evaluates Precision, Recall, F1, PR-AUC, ROC-AUC, and **Brier Score Loss** ($BS = \frac{1}{N}\sum(p_i - y_i)^2$).

---

## 5. Research Feasibility Gating Engine

To prevent unscientific claims of predictive capability, the **Research Feasibility Audit** evaluates candidate datasets against four criteria before forecasting models are enabled:
1. **Sample Size Adequacy**: Requires minimum 25 events for statistical validity.
2. **Temporal Monotonicity**: Verifies that $\ge 99\%$ of timestamps are chronologically ordered.
3. **Label Integrity & Class Balance**: Ensures ground-truth labels exist and neither class comprises $100\%$ of data.
4. **Data Quality & Artifact Audit**: Ensures records with warnings do not exceed $40\%$.
- Output recommendation: `PERMIT_FORECASTING`, `CONDITIONAL_REVIEW`, or `REJECT_FORECASTING`.

**Scope of the gate (stated precisely).** The feasibility audit is
*advisory*: it reports a verdict, it does not disable endpoints. The binding
guarantee is enforced separately in the forecasting pipeline itself, which
refuses evaluation that cannot be made leakage-free and labels every
unvalidated score as such. `/api/v1/audit/config` describes this honestly
rather than claiming a hard gate the system does not implement.

---

## 6. Unified Deployment & Web Security Architecture

- **Loopback Binding**: Services default strictly to `127.0.0.1:8000` to prevent exposure on external interfaces.
- **SPA Routing & Path Traversal Protection**:
  - Direct static files (e.g., `/favicon.svg`, `/assets/index.js`) are served directly.
  - Missing assets with extensions return clean **HTTP 404**.
  - Client-side deep links (paths without file extensions like `/events`, `/forecast`) fall back to `dist/index.html` (HTTP 200).
  - Traversal sequences (`..` or escaped paths) are rejected with HTTP 400, preventing directory escape outside the compiled `frontend/dist` directory.
- **Port Conflict Preflight**: Turnkey launcher checks port availability with `Get-NetTCPConnection` before spawning processes.

---

## 9. Live Windows Telemetry Collection

### Source selection

| Candidate | Verdict |
|---|---|
| **Windows TCP connection table** (`Get-NetTCPConnection`) | **Selected.** Genuine per-connection metadata, unprivileged, no driver, no packet capture, no new dependency, and it reports a real connection `CreationTime`. |
| Packet capture (npcap/WinPcap + scapy) | Rejected for now: requires driver installation and elevated privileges, both of which need explicit operator approval. |
| Windows event / firewall logs | Rejected for now: requires audit-policy changes to produce per-connection records. |
| Zeek / Suricata | Rejected for now: requires a separately authorised monitoring deployment. |

The least invasive source that satisfies the requirement was chosen, as
required. Richer sources remain available as a documented future expansion
and are gated on explicit approval.

### Pipeline

```
Windows TCP connection table (Get-NetTCPConnection, unprivileged)
   -> query_windows_connections()        subprocess, timeout-bounded, worker thread
   -> WindowsConnectionAdapter           validation + canonical mapping
   -> deterministic event_id             sha256(5-tuple + pid + creation_time)
   -> Database.insert_events()           INSERT OR IGNORE -> idempotent
   -> refresh_source_activity()          counters derived from storage
   -> /api/v1/events, /analysis, dashboard
```

### Design properties

- **Non-blocking.** Both the OS query and the SQLite write run via
  `asyncio.to_thread`, so polling never blocks the API event loop.
- **Idempotent.** The `event_id` is a deterministic hash of the connection's
  identity, so the same open connection observed across many polls collapses
  to one stored row. Repeat sightings are counted as *duplicates suppressed*,
  not as new events and not as rejections.
- **Honest absence.** Byte counts, packet counts and flow duration are not
  obtainable from this source. They are stored as `null` and flagged
  `missing_field`; they are never estimated.
- **Event time, not poll time.** `observed_at` is the OS-reported connection
  creation time. Only when that is unavailable does it fall back to poll
  time, and then the record is flagged `timestamp_uncertainty`.
- **Typed accurately.** Records are `event_type = connection`, not
  `network_flow`, because they carry no flow accounting.
- **Unlabelled.** `label_provenance = unlabeled`. No attack ground truth
  exists for locally observed traffic and none is fabricated.
- **Observable failure.** Poll failures, consecutive-failure counts,
  collection gaps and source status are all reported; the collector halts
  after 5 consecutive failures and marks the source `error`.
- **Clean lifecycle.** Start/stop are idempotent; application shutdown stops
  the collector and marks the source `disconnected`.

### Security and privacy boundary

- Loopback binding (`127.0.0.1`) is unchanged; the ingestion API is not
  exposed to the LAN for the collector's benefit (it runs in-process).
- No packet capture, no promiscuous mode, no raw sockets, no driver, no
  elevated privileges, no network configuration change.
- Only this host is observed. No other device or household traffic.
- No payload is captured. Process *id* is retained as provenance; process
  name is not collected.
- Telemetry stays in the local SQLite database and is transmitted nowhere.
  `*.db` is gitignored so collected telemetry cannot be committed.

---

## 10. Connection Intelligence and Domain Enrichment

### Pipeline

```
Windows TCP connection table ──┐
  (5-tuple, state, PID,        │
   process name, start time)   │
                               ├──► canonical NormalizedEvent ──► SQLite
Windows DNS client cache ──────┤         (record never mutated)      │
  (A/AAAA observations)        │                                     │
                               │                                     ▼
Authorized app-layer producer ─┘                        DomainAttribution
  (HTTP metadata, opt-in)                           computed alongside, with
                                                     method + confidence +
                                                     evidence + limitations
```

### Hostname attribution is an inference, carried with its evidence

A connection records an address, never a name. Every attribution therefore
reports `method`, `confidence`, `evidence_observed_at`, competing
`candidate_hostnames`, and plain-language `limitations`.

Confidence is deliberately coarse — the local evidence does not support
finer gradations, and a numeric score would imply precision we lack:

| Confidence | When |
|---|---|
| HIGH | One recent local resolution for this exact address, or a hostname reported directly by an app-layer source |
| MEDIUM | Recent resolution, but several hostnames share the address (CDN / shared hosting) |
| LOW | Stale evidence, or reverse DNS |
| NONE | No defensible association |

Two conditions are handled explicitly because they are the common ones:

* **Shared addresses and CDNs.** When several hostnames have resolved to one
  address, confidence is capped at MEDIUM and all candidates are listed. The
  specific hostname a connection used cannot be determined from the address.
* **Stale evidence.** Beyond 30 minutes, attribution drops to LOW, because
  DNS answers rotate.

### Requested host vs. address owner

`DomainAttribution.identifies_requested_host` distinguishes the two cases in
a machine-readable way:

* `true` — a DNS resolution this machine performed, or an app-layer report.
  This speaks to the hostname the application actually asked for.
* `false` — **reverse DNS**. A PTR record names whoever owns the address,
  typically a CDN edge (`server-….cloudfront.net`), and is usually unrelated
  to the site visited.

Reverse DNS is **off by default**, generates DNS queries when enabled, is
never used for routable-address-only analytics aggregation, and is rendered
in the UI as `IP OWNER` rather than as a domain.

### Known visibility limit on this host

`Get-DnsClientCache` returns no records on the development machine, and
`Resolve-DnsName -CacheOnly` confirms entries are absent immediately after a
successful resolution. The practical cause is encrypted DNS (DoH/DoT), which
bypasses the Windows resolver cache entirely. The API reports this as an
explicit `diagnosis` rather than as "no domains observed", because the two
are very different statements.

---

## 11. Data-Quality Semantics

A null has several possible meanings, and collapsing them makes a
structurally limited sensor look like a failing one. Field availability is
therefore declared per source type:

| Availability | Meaning |
|---|---|
| `populated` | Value present and valid |
| `missing_unexpected` | Source supports the field; value absent — a real defect |
| `unsupported_by_source` | Source cannot provide it — a known limit, not a defect |
| `not_applicable` | Meaningless for this event type |
| `invalid` | Present but failed validation |

Consequences enforced throughout:

* `QualityFlag.SOURCE_LIMITED` marks a structural limit and does **not**
  count a record as "warned". `MISSING_FIELD` is reserved for genuine gaps.
* Analyses report `unsupported_field_counts` separately from
  `missing_field_counts`.
* Metrics that cannot be computed stay `null`; zero is never substituted.
* An unrecognised source type is read conservatively — absence cannot be
  excused by a limit that was never declared.

---

## 12. Derived Provenance

An analysis describes the data it summarized. `data_category`,
`data_categories` and `source_breakdown` are computed **from the analyzed
events**; a caller may choose which events to analyze but cannot declare
what they are. An analysis spanning several categories reports `mixed`, and
one over zero events reports `undetermined`.

---

## 13. Resource Bounds

Window generation is driven by the data's time span divided by the stride.
A single corrupt timestamp — in practice the Windows FILETIME epoch
(1601-01-01), emitted for sockets with no recorded start — implied a span of
~425 years and ~895 million loop iterations, hanging the request thread.

Three independent guards now apply:

1. The ingestion adapter rejects implausible timestamps (before 2000, or
   more than an hour in the future) and falls back to poll time, flagged.
2. Windowing excludes implausible timestamps from the observation range.
3. `MAX_WINDOWS` caps generation regardless of input, and the cap is
   reported when reached.

---

## 14. Reproducible Experiments

`app/research/experiment.py` + `app/api/v1/experiments.py`.

```
POST /experiments/capture   -> build and store a manifest of an evaluation
GET  /experiments           -> list stored manifests
GET  /experiments/{id}      -> read one manifest
POST /experiments/{id}/replay -> re-execute and compare
```

A manifest (`MANIFEST_VERSION`) records:

| Group | Contents |
|---|---|
| Dataset | `dataset_fingerprint` (sha256 over schema version, count, and each event's id / time / label / source / category), event count, time range, source and provenance breakdowns |
| Protocol | window / lead / horizon / stride, purge count, `configured_train_ratio`, random seed, target definition, feature set |
| Environment | Python version, platform, library versions |
| Results | per-model metrics and confusion matrices |

It records **no telemetry** — no address literals and no record fields — so
a manifest is safe to share. A test asserts this, because the manifest is
the artefact most likely to leave the machine.

Replay re-selects the dataset, rebuilds windows and split, retrains, and
compares only `DETERMINISTIC_OUTPUTS` (counts, split sizes, positives,
confusion matrices). `NON_DETERMINISTIC_OUTPUTS` (timings, timestamps) are
never compared, so replay is neither always-failing nor vacuous.

Replay **refuses** — rather than reporting a number — when the dataset
fingerprint changed, the dataset is missing, `SCHEMA_VERSION` changed, the
feature set changed, or the configuration no longer yields a valid
evaluation. All mismatches are reported together. Replay is read-only
against telemetry. See ADR-022.

---

## 15. Retention Enforcement

`app/services/retention.py` + `app/api/v1/retention.py`.

```
GET  /retention/policy    -> effective policy and eligible categories
POST /retention/preview   -> counts only; changes nothing
POST /retention/enforce   -> deletes, requires confirm="DELETE-EXPIRED-TELEMETRY"
```

- Dry run by default; deletion needs the confirmation token verbatim.
- **Never automatic**: no scheduler, no startup hook (tested).
- Age computed from `observed_at` in UTC — event time, not ingestion time.
- Eligible categories: `live_telemetry`, `historical_replay`,
  `synthetic_demo`. Sources, import summaries, analyses and audit records
  are never pruned.
- Deletes run in batches, each in its own transaction, so an interruption
  leaves whole batches committed.
- Source counters are refreshed afterwards.

See ADR-023.

---

## 16. Central Deployment Security

`app/core/security.py` + `app/api/auth.py`, wired in `app/main.py`.

Local deployment is loopback-only and unauthenticated by design. Central
mode **fails closed**: `create_app()` raises at startup if no credential
store is configured, rather than serving unauthenticated.

```
Request -> CentralAuthMiddleware -> Principal(credential_id, source_id, role)
                |                        |
         default deny                 scope_source(requested, principal)
         (public: health)                     |
                                    own source | 403 cross-source
```

| Element | Implementation |
|---|---|
| Token storage | PBKDF2-HMAC-SHA256, 240,000 iterations, per-credential salt; plaintext shown once at mint, never persisted |
| Comparison | `hmac.compare_digest` |
| Roles | `ingest` (write + read own), `read_only` (read own), `admin` (all sources + audit log) |
| Unscoped query | Returns **only the caller's source** — never all sources |
| Cross-source query | **403**, not a silent rewrite |
| Unknown vs disabled | Identical response text, so source ids cannot be enumerated |
| Management | `scripts/manage_credentials.py` (`init` / `add` / `list` / `disable`); store holds hashes only; `secrets/` is gitignored |

Verified over **loopback only**. No rate limiting, no in-process TLS, and no
exposure beyond `127.0.0.1`. Central mode is disabled by default. See
ADR-024.

---

## 17. Additional Host Observation Sources

`app/adapters/windows_host_observations.py` + `app/api/v1/hostobs.py`.

```
POST /hostobs/udp/poll      -> canonical events (EventType.UDP_ENDPOINT)
GET  /hostobs/interfaces    -> its own payload, never canonical events
GET  /hostobs/capabilities  -> declared limits of both
```

Both are unprivileged, read-only, operator-triggered, and Windows-only
(`501 unsupported_platform` elsewhere).

### Why they are kept apart

They measure different things, and the schema says so:

| | UDP endpoint table | Interface counters |
|---|---|---|
| Unit of observation | one bound local socket | one network interface |
| Time semantics | point-in-time snapshot | cumulative since adapter reset |
| Stored as | `normalized_events` | **never** stored as events |
| Destination | **not applicable** — UDP has no peer here | not applicable |
| Attributable to a flow/process | process yes, flow no | **neither** |

A UDP endpoint is a socket binding, not a conversation. A destination is
not missing from these records — it does not exist, and the capability
profile uses `FieldAvailability.NOT_APPLICABLE` so their absence is never
scored as a data-quality defect.

Interface counters are the only genuine byte and packet measurement
available without packet capture, and they are the easiest to misuse:
summed beside flow byte counts from an imported dataset they produce a
figure that means nothing. The payload therefore carries its own scope.

Deltas are computed between consecutive readings held in process. A
decreasing counter means the adapter reset, and **no delta is derived** —
neither a negative nor a wrapped-around positive describes traffic.

See ADR-027.

---

## 18. Lead Time, Uncertainty and the Temporal Model

`app/research/evaluation.py`, plus `temporal_window_stack` in
`app/models/forecaster.py`.

```
POST /forecast/lead-time-curve  -> performance against warning time
GET  /forecast/uncertainty      -> bootstrap intervals for the last evaluation
```

### Lead-time sweep

One full protocol run per lead time, everything else frozen and recorded in
`LeadTimeCurve.protocol`. A lead whose windowing or split cannot support an
honest evaluation is a `LeadTimePoint` with `evaluated=False` and a
`refusal_reason` — present in the curve, not dropped from it.

### Uncertainty

Percentile bootstrap over the held-out instances, with floors below which
an interval is refused rather than produced (20 instances, 5 positives,
both classes). Resamples that lose a class are skipped, not scored zero.

`HoldoutPredictions` stores truth **per model**, because the temporal
model's holdout is shorter by `TEMPORAL_LAGS`; resampling its scores
against another model's labels would misalign them silently.

### Temporal model

```
instance i  ->  [ window i-3 | window i-2 | window i-1 | window i ]
```

Order matters, so this is a sequence model rather than a snapshot
classifier. Stacking is applied **after** the chronological split,
separately to each side. Applied before, a test instance near the boundary
would carry training-period windows in its lags, re-importing exactly the
contamination the purge exists to remove.

It is not an LSTM. See ADR-028.

---

## 19. Timestamp Plausibility — One Definition

`is_plausible_timestamp()`, `MIN_PLAUSIBLE_YEAR`, `MAX_CLOCK_SKEW_SECONDS`
in `app/schemas/events.py`.

Windows reports an unset socket creation time as the FILETIME epoch
(1601-01-01). One such record implies a ~425-year span, which corrupts
window generation, split boundaries, rate features, and any audit that
measures elapsed observation.

This rule previously existed as three independent copies, and they
disagreed:

| Module | Before | After |
|---|---|---|
| Windows adapter | rejected them | unchanged |
| Readiness gate | excluded them (65,260s span) | uses the shared helper |
| Descriptive analysis | **no check** (range began 1601) | excludes and counts them |
| Feasibility audit | inherited the broken span, scored 100% PASSED over 425 years | **fails**, naming the count |

The analysis reports `implausible_timestamp_events` and the dashboard shows
it. The feasibility temporal score folds in the usable fraction of the time
axis, so the number moves with the verdict.

A test asserts all three modules report the same span for the same
dataset. See ADR-029.

---

## 20. Measurement Denominators

`DescriptiveAnalysis` carries `duration_measured_count`,
`packets_measured_count` and `bytes_measured_count` beside the averages.

On a mixed dataset these differ from `total_events` by an order of
magnitude: 3,469 of 3,669 records on this host come from the connection
table, which exposes no volume at all. An average over the remaining 200
is not a property of the dataset, and an API consumer cannot tell without
being told.

The feasibility `attack_ratio` is likewise computed over the labelled
population rather than all events, with `labelled_events` and
`unlabelled_events` reported alongside. See ADR-030.
