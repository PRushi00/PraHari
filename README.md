# PraHari — The Digital Sentinel

> Unified Cybersecurity Telemetry Ingestion, Canonical Normalization, SQLite Persistence, Descriptive Analytics, Research Feasibility Gating, and Causal Future Threat Forecasting.

---

## 1. System Overview

PraHari is a production-grade, local-first cybersecurity intelligence platform designed for dependable telemetry processing, auditability, and honest predictive threat modeling. It unifies high-throughput telemetry ingestion, schema validation, transactional SQLite persistence, factual descriptive profiling, and a causal machine-learning forecasting engine into a single executable application served on loopback (`127.0.0.1:8000`).

```
[ Ingestion Sources ] ──► [ Ingestion & Normalizer ] ──► [ SQLite (WAL) ] ──► [ Analytics & Forecasting ] ──► [ Unified SPA Dashboard ]
 • CSV (CIC-IDS)          • IP/Port/Time Validation      • Events               • Descriptive Profiling        • Overview & Explorer
 • Zeek (conn.log)        • UTC Normalization            • Sources              • Feasibility Gating           • Threat Forecaster
 • Suricata (EVE Flow)    • Quality Flags & Rejection    • Analyses             • Causal ML Pipeline           • Stream Simulator
 • Synthetic Replay       • Canonical Schema 1.0.0       • Audit Log            • Brier Score Calibration      • Audit Log Viewer
```

---

## 2. Key Architecture Pillars

- **Unified Single-Port Deployment**: FastAPI backend serves the production React SPA directly on `http://127.0.0.1:8000/`. Client-side deep links (`/events`, `/forecast`, `/analytics`) fall back gracefully to `index.html` with strict path-traversal prevention.
- **Multi-Format Ingestion**: Native adapters for multi-column CSVs, Zeek `conn.log` NDJSON, Suricata EVE logs, and synthetic flow streams.
- **Factual Descriptive Analysis vs. Forecasting**: Factual empirical summaries are strictly segregated from predictive modeling to prevent operator confusion.
- **Causal Threat Forecasting**: Retrospective observation window ($W=60s$), lead time buffer ($30s$), and future prediction horizon ($H=60s$). Enforces chronological temporal splitting to eliminate overlapping-window leakage.
- **Research Feasibility Engine**: Gating mechanism requiring $\ge 25$ events, $\ge 99\%$ temporal monotonicity, and label balance before predictive forecasting is permitted.
- **Zero-Dependency SQLite Persistence**: Embedded SQLite with WAL mode (`PRAGMA journal_mode=WAL`) and foreign keys (`PRAGMA foreign_keys=ON`).

---

## 3. Directory Layout

```
Implementation/
├── backend/
│   ├── app/
│   │   ├── adapters/          # Ingestion adapters (csv_import.py, json_stream.py, synthetic_replay.py)
│   │   ├── api/v1/            # Endpoints: health, events, sources, import, stream, analysis, research, forecast, audit
│   │   ├── core/              # Config, profile settings, and loopback defaults
│   │   ├── models/            # Feature extractor, forecaster pipeline, model registry
│   │   ├── research/          # Feasibility audit engine and scientific gating
│   │   ├── schemas/           # Pydantic canonical models (events.py)
│   │   ├── services/          # Descriptive analysis engine (analysis.py)
│   │   ├── storage/           # SQLite database layer with WAL mode
│   │   └── main.py            # FastAPI application & SPA static server
│   ├── tests/
│   │   ├── fixtures/          # sample_flows.csv (45-row fixture with valid & malformed rows)
│   │   ├── integration/       # API, deployment/SPA, and end-to-end pipeline tests
│   │   └── unit/              # Adapters, database, analysis, forecaster, research tests
│   └── prahari.db             # Local SQLite database
├── frontend/
│   ├── src/                   # React + TypeScript SOC interface
│   ├── dist/                  # Pre-compiled production bundle served by FastAPI
│   └── package.json
├── scripts/
│   ├── live_data_streamer.py       # Live telemetry streaming probe
│   ├── verify_live_launcher.py     # Live server launch & API workflow verification script
│   └── verify_forecasting_pipeline.py # Empirical forecasting evaluation audit script
├── start_prahari.ps1          # PowerShell turnkey launcher (port conflict preflight, venv check)
├── start_prahari.bat          # Windows batch launcher
├── Dockerfile                 # Multi-stage container definition
├── docker-compose.yml         # Container compose config with persistent volume
├── ARCHITECTURE.md            # Detailed system architecture specification
├── DECISIONS.md               # Architecture Decision Records (ADRs)
└── IMPLEMENTATION_STATUS.md   # Complete verification matrix & test results
```

---

## 4. Quickstart & Deployment

### Option A: PowerShell Turnkey Launcher (Recommended)
1. Run preflight conflict verification:
   ```powershell
   powershell -ExecutionPolicy Bypass -File .\start_prahari.ps1 -CheckOnly
   ```
2. Launch PraHari on `127.0.0.1:8000`:
   ```powershell
   powershell -ExecutionPolicy Bypass -File .\start_prahari.ps1
   ```
3. Open your browser:
   - **Unified SOC Dashboard**: [http://127.0.0.1:8000/](http://127.0.0.1:8000/)
   - **Interactive API Documentation**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

### Option B: Windows Batch Launcher
Double-click or run:
```cmd
start_prahari.bat
```

### Option C: Manual Backend Launch
```powershell
.\backend\.venv\Scripts\python.exe -m uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 8000
```

---

## 5. Live Telemetry Streaming Probe

To stream simulated live Zeek and Suricata flow records into the running application and view real-time propensity evaluations:
```powershell
.\backend\.venv\Scripts\python.exe scripts\live_data_streamer.py --count 10 --interval 1.0
```

---

## 6. Verification & Automated Test Suites

### Run All 33 Automated Tests
```powershell
cd backend
.\.venv\Scripts\python.exe -m pytest tests/ -v
```

### Run Live Server & Lifecycle Verification
```powershell
.\backend\.venv\Scripts\python.exe scripts\verify_live_launcher.py
```

### Run Empirical Forecasting Audit
```powershell
.\backend\.venv\Scripts\python.exe scripts\verify_forecasting_pipeline.py
```

### Recompile Frontend Production Bundle
```powershell
cd frontend
npm run build
```

---

## 7. Documentation Index

- [ARCHITECTURE.md](ARCHITECTURE.md): Full technical architecture, data model, causal window formulation, and security model.
- [DECISIONS.md](DECISIONS.md): Architecture Decision Records (ADR-001 through ADR-008).
- [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md): Empirical test verification matrix, forecasting findings, and environmental limitations.
