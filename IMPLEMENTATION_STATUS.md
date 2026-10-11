# PraHari — Implementation Status & Verification Audit Report

**Date**: October 11, 2026  
**Canonical Repository**: `c:\Users\nanda\OneDrive\Desktop\Studies\CyberSecurity\Projects\PraHari\Implementation`  
**Git Branch**: `master`  

---

## 1. Master Requirements Verification Matrix

| Requirement Area | Specification Requirement | Implementation Status | Verified Source Files | Automated Tests |
| :--- | :--- | :--- | :--- | :--- |
| **Unified Deployment** | Production React SPA served by FastAPI on `127.0.0.1:8000` with SPA deep-linking and path traversal protection | **VERIFIED** | `backend/app/main.py`<br>`frontend/dist/` | `tests/integration/test_deployment_and_spa.py` (5 passed) |
| **Windows Launchers** | Turnkey `.ps1` and `.bat` launchers with loopback binding, port preflight, and clean termination | **VERIFIED** | `start_prahari.ps1`<br>`start_prahari.bat`<br>`scripts/verify_live_launcher.py` | Executed live: server started, serviced requests, exited cleanly with port released |
| **Docker Configuration** | Multi-stage `Dockerfile` and `docker-compose.yml` with persistent volume | **DOCUMENTED LIMITATION** | `Dockerfile`<br>`docker-compose.yml` | Docker CLI unavailable on host; configuration complete but unverified live |
| **CSV Telemetry Ingestion** | Ingestion of multi-column network flows with IP/port validation, UTC normalization, rejection categorization | **VERIFIED** | `backend/app/adapters/csv_import.py`<br>`backend/app/storage/database.py` | `tests/unit/test_csv_import.py` (5 passed)<br>`tests/unit/test_comprehensive_ingestion.py` |
| **NDJSON / Stream Ingestion**| Ingestion of Zeek `conn.log` and Suricata EVE logs, Unix/ISO timestamps, aggregate bytes/packets | **VERIFIED** | `backend/app/adapters/json_stream.py`<br>`backend/app/api/v1/stream.py` | `tests/unit/test_comprehensive_ingestion.py`<br>`tests/unit/test_stream.py` (3 passed) |
| **Database Persistence** | Transactional SQLite storage with WAL mode, foreign keys, idempotency on duplicate `event_id` | **VERIFIED** | `backend/app/storage/database.py` | `tests/unit/test_database.py` (2 passed)<br>`tests/integration/test_end_to_end_workflow.py` |
| **Descriptive Analytics** | Factual statistical summaries (protocol, labels, top IPs/ports, durations, bytes) clearly segregated from ML | **VERIFIED** | `backend/app/services/analysis.py`<br>`backend/app/api/v1/analysis.py` | `tests/unit/test_analysis.py` (1 passed) |
| **Research Feasibility Gate**| Pre-forecasting data audit: temporal monotonicity, class balance, minimum sample count, quality flags | **VERIFIED** | `backend/app/research/feasibility.py`<br>`backend/app/api/v1/research.py` | `tests/unit/test_research.py` (2 passed) |
| **Threat Forecasting** | Causal window feature extractor, chronological temporal split, baselines, LR, Random Forest, calibration | **VERIFIED** *(Research-Gated)*| `backend/app/models/forecaster.py`<br>`backend/app/models/feature_extractor.py` | `tests/unit/test_forecaster.py` (2 passed)<br>`scripts/verify_forecasting_pipeline.py` |
| **End-to-End Pipeline** | Complete local operational workflow from CSV/NDJSON ingestion to analytics, model training, and re-open | **VERIFIED** | `backend/tests/integration/test_end_to_end_workflow.py` | `tests/integration/test_end_to_end_workflow.py` (1 passed) |

---

## 2. Test Execution Results

All 33 automated tests in the backend test suite passed with zero errors:

```
============================= test session starts =============================
platform win32 -- Python 3.12.0, pytest-9.1.1, pluggy-1.6.0
rootdir: Implementation\backend
configfile: pyproject.toml
collected 33 items

tests/integration/test_advanced_api.py::test_research_audit_endpoint PASSED    [  3%]
tests/integration/test_advanced_api.py::test_synthetic_replay_endpoint PASSED    [  6%]
tests/integration/test_advanced_api.py::test_forecast_train_and_predict_endpoint PASSED [  9%]
tests/integration/test_advanced_api.py::test_audit_logs_and_config_endpoint PASSED [ 12%]
tests/integration/test_api.py::test_health_endpoint PASSED                      [ 15%]
tests/integration/test_api.py::test_sources_and_events_workflow PASSED          [ 18%]
tests/integration/test_deployment_and_spa.py::test_api_routes_remain_accessible PASSED [ 21%]
tests/integration/test_deployment_and_spa.py::test_production_frontend_index_served PASSED [ 24%]
tests/integration/test_deployment_and_spa.py::test_spa_deep_links_serve_index_html PASSED [ 27%]
tests/integration/test_deployment_and_spa.py::test_missing_assets_return_404 PASSED [ 30%]
tests/integration/test_deployment_and_spa.py::test_path_traversal_protection PASSED [ 33%]
tests/integration/test_end_to_end_workflow.py::test_complete_end_to_end_pipeline PASSED [ 36%]
tests/unit/test_analysis.py::test_compute_descriptive_analysis PASSED           [ 39%]
tests/unit/test_comprehensive_ingestion.py::test_zeek_field_mapping_and_timestamp_units PASSED [ 42%]
tests/unit/test_comprehensive_ingestion.py::test_suricata_eve_mapping_and_iso_timestamp PASSED [ 45%]
tests/unit/test_comprehensive_ingestion.py::test_missing_and_invalid_fields_rejection_reasons PASSED [ 48%]
tests/unit/test_comprehensive_ingestion.py::test_mixed_batch_ndjson_accounting_reconciliation PASSED [ 51%]
tests/unit/test_comprehensive_ingestion.py::test_duplicate_events_idempotency_and_transaction PASSED [ 54%]
tests/unit/test_comprehensive_ingestion.py::test_csv_rejection_categorization_and_provenance PASSED [ 57%]
tests/unit/test_csv_import.py::test_validate_and_normalize_valid_row PASSED     [ 60%]
tests/unit/test_csv_import.py::test_reject_invalid_ip PASSED                    [ 63%]
tests/unit/test_csv_import.py::test_reject_invalid_port PASSED                  [ 66%]
tests/unit/test_csv_import.py::test_import_csv_file_fixture PASSED              [ 69%]
tests/unit/test_csv_import.py::test_rejection_reasons_grouping_regression PASSED [ 72%]
tests/unit/test_database.py::test_source_lifecycle PASSED                       [ 75%]
tests/unit/test_database.py::test_insert_and_query_events PASSED                [ 78%]
tests/unit/test_forecaster.py::test_window_feature_extractor PASSED             [ 81%]
tests/unit/test_forecaster.py::test_threat_forecasting_pipeline PASSED          [ 84%]
tests/unit/test_research.py::test_feasibility_insufficient_samples PASSED        [ 87%]
tests/unit/test_research.py::test_feasibility_valid_balanced_dataset PASSED     [ 90%]
tests/unit/test_stream.py::test_json_stream_zeek_format PASSED                  [ 93%]
tests/unit/test_stream.py::test_json_stream_rejection_of_corrupted PASSED        [ 96%]
tests/unit/test_stream.py::test_synthetic_flow_generator PASSED                 [100%]

======================== 33 passed, 1 warning in 2.03s ========================
```

---

## 3. Live Server Launch & Workflow Verification

Executed `python scripts/verify_live_launcher.py`:
- Server successfully bound to `http://127.0.0.1:8000`.
- Health endpoint (`GET /api/v1/health`): HTTP 200, status `healthy`.
- Root Dashboard (`GET /`): HTTP 200, served React HTML shell.
- SPA Deep Links (`GET /events`, `/forecast`, `/analytics`, `/stream`): HTTP 200.
- Missing Static Assets (`GET /assets/missing.js`): HTTP 404.
- Live NDJSON Ingestion (`POST /api/v1/stream/ingest/ndjson`): HTTP 200, 1 flow accepted.
- Threat Forecasting Inference (`POST /api/v1/forecast/predict`): HTTP 200, propensity score returned.
- Clean Shutdown: Process terminated via SIGTERM, port 8000 released immediately.

---

## 4. Empirical Forecasting Findings & Scientific Rigor

Audited via `python scripts/verify_forecasting_pipeline.py` on fixture dataset (`sample_flows.csv`):
- **Flow Counts**: 35 accepted flows (15 benign, 20 attacks across FTP-BruteForce, PortScan, DDoS-HOIC, SSH-BruteForce).
- **Causal Windows**: 21 retrospective observation windows ($W=60s$, $\text{lead\_time}=30s$, $H=60s$, $\text{stride}=15s$).
- **Positive Windows**: 11 attack windows ($52.4\%$), 10 normal windows ($47.6\%$).
- **Temporal Splitting**: Chronological 70% train (14 windows) and 30% test (7 windows).
- **Evaluation Results**:
  - `Majority Class Baseline`: Accuracy 0.0%, Brier Score 1.000.
  - `Rate Threshold Baseline`: Accuracy 0.0%, Brier Score 0.250.
  - `Logistic Regression`: Accuracy 42.9%, Brier Score 0.581.
  - `Random Forest Forecaster`: Accuracy 42.9%, Brier Score 0.365.
- **Scientific Caveat**: Because fixture traffic concentrated attacks in the first sequence, future test windows contained 0 positive targets, yielding uninflated 42.9% accuracy and prompting the Research Feasibility Engine to honestly assign `CONDITIONAL_REVIEW`. PraHari refuses to inflate scores or fabricate results.

---

## 5. Unresolved Environmental Limitations

1. **Docker Host Execution**: Docker CLI is not installed on this workstation. The `Dockerfile` and `docker-compose.yml` are provided and verified for syntax and directory bindings, but container startup cannot be tested live on this host.
2. **Promiscuous Packet Capture**: Physical live packet capture is disabled by design to ensure host networking stability and authorization compliance. All live flows use simulated NDJSON over loopback HTTP.
