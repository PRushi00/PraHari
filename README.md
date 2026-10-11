# PraHari — The Digital Sentinel

> Cross-platform cybersecurity telemetry ingestion, canonical normalization, SQLite persistence, factual descriptive analysis, and modern SOC monitoring interface.

---

## 1. System Overview

PraHari is designed according to the Master Engineering Specification as a dependable, production-grade cybersecurity intelligence platform. It establishes a verifiable vertical slice from raw telemetry ingestion through canonical validation, transactional SQLite storage, factual descriptive analytics, and a high-performance React SOC dashboard.

### Core Architecture Flow

```
[ Historical CSV / File Upload / Direct Ingestion ]
                    │
                    ▼
      [ CSV Import Adapter & Validation Engine ]
       ├── Timestamp sanity checks & format parser
       ├── IP address syntax & subnet validation
       ├── Port boundaries (0–65535) & proto lookup
       └── Strict error rejection vs quality warning flags
                    │
                    ▼
     [ Canonical NormalizedEvent (Pydantic v2 Schema) ]
                    │
                    ▼
       [ SQLite Storage Layer (WAL Mode + FK) ]
       ├── telemetry_sources
       ├── normalized_events
       ├── import_summaries
       ├── descriptive_analyses
       └── audit_events
                    │
                    ▼
        [ Descriptive Analysis Service ]
       └── Factual statistics: IP top-talkers, ports, durations, protocols
                    │
                    ▼
       [ FastAPI Backend Endpoints (v1) ]
       ├── GET  /api/v1/health
       ├── GET  /api/v1/events (paginated & filterable)
       ├── POST /api/v1/import/csv/raw & /file
       ├── GET  /api/v1/sources
       └── POST /api/v1/analysis/run & GET /latest
                    │
                    ▼
  [ Modern React + TypeScript + Vite SOC Dashboard ]
       ├── Overview: ECharts distributions, active counters, quick fixture seeder
       ├── Ingestion & Import: File upload dropzone, raw text editor, rejection audit table
       ├── Events Explorer: Live filterable event log with detailed inspection drawer
       └── Descriptive Analysis: Factual telemetry profiling & data quality flag metrics
```

---

## 2. Research Feasibility & Ethical Safeguards

- **Descriptive Statistics Only**: Until real-world datasets (e.g. CIC-IDS2018) have completed formal data leakage audits and the Research Feasibility Gate has been signed off, predictive machine-learning forecasting remains gated.
- **Strict Data Segregation**: Every event is explicitly stamped with `data_category` (`historical_import`, `synthetic`, `live_stream`) and `label_provenance` (`dataset_ground_truth`, `unlabeled`).
- **Audit Trails**: Every administrative mutation, source creation, and import job is logged in SQLite's `audit_events` table.

---

## 3. Directory Layout

```
Prahari Implement_Implementation/
├── backend/
│   ├── app/
│   │   ├── adapters/          # Ingestion adapters (csv_import.py)
│   │   ├── api/               # API endpoints & dependency injection
│   │   │   └── v1/            # Health, events, sources, imports, analysis
│   │   ├── core/              # Profile-based AppConfig with safe loopback defaults
│   │   ├── schemas/           # Pydantic canonical models (events.py)
│   │   ├── services/          # Descriptive analysis engine (analysis.py)
│   │   ├── storage/           # SQLite manager with WAL & transaction support
│   │   └── main.py            # FastAPI application entrypoint
│   ├── tests/
│   │   ├── fixtures/          # sample_flows.csv (45-row valid & invalid test dataset)
│   │   ├── unit/              # Isolated tests for adapters, schemas, database, analysis
│   │   └── integration/       # End-to-end FastAPI test suite
│   └── prahari.db             # Local SQLite database (seeded)
└── frontend/
    ├── src/
    │   ├── components/        # Header, navigation, status pills
    │   ├── pages/             # Overview, Ingestion/Import, Events, Analysis
    │   ├── services/          # Typed API client (api.ts)
    │   ├── types/             # TypeScript definitions
    │   ├── App.tsx            # Main application layout
    │   └── index.css          # Cyber Sentinel SOC theme design system
    ├── index.html
    ├── package.json
    ├── tsconfig.json
    └── vite.config.ts         # Vite bundler configured with backend proxy
```

---

## 4. Running the Platform

### A. Run Backend (FastAPI)

From `Prahari Implement_Implementation/backend`:
```powershell
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```
Interactive API documentation will be available at:
- Swagger UI: `http://127.0.0.1:8000/docs`
- Redoc: `http://127.0.0.1:8000/redoc`
- Health check: `http://127.0.0.1:8000/api/v1/health`

### B. Run Frontend (React + Vite)

From `Prahari Implement_Implementation/frontend`:
```powershell
npm run dev
```
Open your browser to:
- `http://127.0.0.1:5173`

---

## 5. Running the Test Suite

From the workspace root or backend folder:
```powershell
python -m pytest "Prahari Implement_Implementation/backend/tests" -v
```

All 9 test suites cover:
- Health check verification
- Source registration and lifecycle
- Strict rejection of invalid IPs, ports, and corrupted timestamps
- Accurate acceptance and normalization of valid flows
- Database transaction safety and isolation
- Descriptive historical analysis computation
