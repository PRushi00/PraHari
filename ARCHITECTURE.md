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
- **Leakage Prevention**:
  - Sliding windows with step $15s$ share telemetry with adjacent windows (autocorrelation).
  - Shuffling train/test instances would leak training data into test evaluation!
  - PraHari strictly enforces **Chronological Temporal Splitting** (e.g., first 70% of chronological windows for training, remaining 30% for testing).
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

---

## 6. Unified Deployment & Web Security Architecture

- **Loopback Binding**: Services default strictly to `127.0.0.1:8000` to prevent exposure on external interfaces.
- **SPA Routing & Path Traversal Protection**:
  - Direct static files (e.g., `/favicon.svg`, `/assets/index.js`) are served directly.
  - Missing assets with extensions return clean **HTTP 404**.
  - Client-side deep links (paths without file extensions like `/events`, `/forecast`) fall back to `dist/index.html` (HTTP 200).
  - Traversal sequences (`..` or escaped paths) are rejected with HTTP 400, preventing directory escape outside the compiled `frontend/dist` directory.
- **Port Conflict Preflight**: Turnkey launcher checks port availability with `Get-NetTCPConnection` before spawning processes.
