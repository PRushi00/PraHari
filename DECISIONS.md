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
- Ingest telemetry exclusively via synthetic fixtures, local files, and simulated NDJSON HTTP streams.
