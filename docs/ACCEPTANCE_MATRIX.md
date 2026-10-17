# PraHari — Blueprint Acceptance Matrix

Every acceptance criterion in **§18 Definition of done** of the 18-page
blueprint, plus the proposed defaults the blueprint names elsewhere
(PostgreSQL, TLS, Linux, live flow collection). This supersedes the status
column of `REQUIREMENTS_MATRIX.md`, which used a looser vocabulary and had
gone stale in places.

**Assessed 17 Oct 2026 on Windows 11, Python 3.12.0, Node 24.19.0.**

| Status | Meaning |
|---|---|
| `VERIFIED` | Implemented, and executed evidence exists in the scope stated |
| `PARTIAL` | Implemented for part of the scope; the remainder is named |
| `MISSING` | Not implemented |
| `BLOCKED` | Cannot be completed without an external resource or authorization |
| `NOT_APPLICABLE_WITH_JUSTIFICATION` | Outside the blueprint's current scope, with the reason |

**Overall: not fully verified.** Real-data forecasting, current-revision
Linux, live network-flow collection, PostgreSQL and a remote TLS deployment
are not. No percentage is given; the criteria are not equally weighted.

Commands below run from `backend/` unless shown otherwise.

---

## §18 criteria

| # | Criterion | Status | Evidence | Reproduce | Remaining prerequisite |
|---|---|---|---|---|---|
| 1 | Local deployment runs end-to-end on declared supported OSes | `PARTIAL` | **Windows:** launched via `start_prahari.ps1`, healthy in ~2 s, dashboard/`/docs`/`/system/health` 200, restarted and re-verified 17 Oct. **Linux:** current revision run on Arch (Python 3.14.8): started on 127.0.0.1 against a disposable database, `/health` 200 with `x-request-id`, collector status `stopped`, shut down cleanly - `PLATFORM_SUPPORT.md` §6, ADR-075. The Windows checks above predate that revision | `powershell -File ..\start_prahari.ps1 -CheckOnly`; `curl http://127.0.0.1:8000/api/v1/health` | Re-run the Windows checks on the current revision |
| 2 | Central deployment accepts authenticated telemetry from distinct, authorized identities | `VERIFIED` (loopback) | PraHari as a **separate process over HTTPS**, central mode, hashed credential file: two sensors deliver, are deduplicated, and are audited under their own credentials | `pytest tests/integration/test_central_https_e2e.py -v` | Remote network deployment: see TLS row |
| 3 | ≥1 host and ≥1 network-level integration tested on declared environments | `PARTIAL` | Host: Windows connection table, live-verified; Linux `/proc/net/tcp` reader run against the live table on Arch by test, collector not started (ADR-075). Network-level: flow-**export** parsing (30 tests). No live collector exists (ADR-072) | `pytest tests/unit/test_netflow_adapter.py -q` | An authorized exporter and observation point |
| 4 | Replay and live ingestion use the same canonical contracts | `VERIFIED` | One `NormalizedEvent` schema for every adapter; deterministic identity shared by stream and replay | `pytest tests/integration/test_stream_idempotency.py -q` | — |
| 5 | Adapters expose capability and health; failures visible | `VERIFIED` | `/system/health`, capability reports. **Fixed this session:** a batch where every record was rejected never reached health (ADR-068) | `pytest tests/integration/test_audit_identity_and_rejection_visibility.py -q` | — |
| 6 | Target, horizon, label and negative-label rules documented and tested | `VERIFIED` | Structured, versioned, fingerprinted target `prahari.attack_label_in_horizon` v1.1.0 (ADR-070) stating every rule, including its shortfalls | `pytest tests/integration/test_label_policy_target_and_manifest.py -q` | — |
| 7 | Dataset provenance, hashes, schemas, audit, feature definitions, split manifests | `PARTIAL` | Tooling complete: import policy, per-file hashes, audit report, manifest 1.1.0 with git revision, configuration hash and split parameters. **No real dataset has been audited** | `pytest tests/integration/test_experiment_replay.py -q` | An approved corpus (`docs/DATASET_ACQUISITION.md`) |
| 8 | Baseline and temporal models on one valid target, leakage-resistant | `PARTIAL` | Constant, rate-threshold, logistic regression, random forest and NumPy LSTM on one chronological purged split. **Fixed:** late live events leaked into earlier windows (ADR-069); labels of mixed or model provenance were accepted (ADR-070). **Synthetic data only** | `pytest tests/unit/test_prediction_time_availability.py -q` | Real labelled data |
| 9 | Precision/recall, PR-AUC, false alarms, missed events, lead time, generalization | `PARTIAL` | All computed — at **window** level. Event-level lead time is **not** measured; lead time is studied across configured offsets. No real-data numbers exist | `pytest tests/ -q -k "lead_time or generaliz"` | Event-level matching; real data |
| 10 | Dashboard uses actual backend results; distinguishes observed, forecast, confirmed | `VERIFIED` | 67 frontend tests (passing on Windows and on Arch Linux, ADR-076); earlier UI→API→DB trace reconciled exactly | `cd frontend && npx vitest run` | — |
| 11 | Central authn, authz, isolation, payload limits, audit, retention tested | `VERIFIED` | Now also **over real HTTPS**: 401 without/with bad credential, 403 cross-source and read-only, revocation without restart, 413 with server log evidence, per-credential rate limit, no token in server log. **Fixed:** audit named the wrong actor (ADR-067) | `pytest tests/integration/test_central_https_e2e.py tests/integration/test_central_security.py -q` | — |
| 12 | Replay, adapter contract, unit, integration, security, end-to-end tests pass | `VERIFIED` (Windows, earlier revision; Linux, current revision) | Windows: **1245 passed, 4 skipped, 0 failed**; the 4 skips are Linux-only and are not counted as passes. Arch Linux, current revision: **1292 passed, 3 skipped, 0 failed**; the 3 skips are two `live_windows` tests and the non-Linux collector-selection test | `pytest -q -rs` | Windows run on the current revision |
| 13 | Reproducibility manifests and troubleshooting docs match the implementation | `VERIFIED` | Manifest 1.1.0 records what was previously missing; 1.0.0 manifests still load; replay verified | `pytest tests/integration/test_experiment_replay.py -q` | — |
| 14 | No automatic network changes or disruptive response | `VERIFIED` | No code path alters routes, firewall or interfaces; collectors off by default; no listener built speculatively (ADR-072) | `grep -rniE "netsh|iptables|route add|New-NetFirewallRule" app/` (no matches expected) | — |
| 15 | Limitations, negative results, unsupported platforms, failed experiments documented | `VERIFIED` | README §27, ADRs, and limitations now carried inside every manifest | — | — |

## Proposed defaults named elsewhere in the blueprint

| Item | Status | Evidence | Remaining prerequisite |
|---|---|---|---|
| PostgreSQL central store | `MISSING` (backend) / `BLOCKED` (runtime) | No PostgreSQL code existed; an earlier report wrongly said abstractions did. Now: `storage/contract.py` and a 13-test conformance suite run against SQLite; three raw-SQL leaks named and ratcheted (ADR-071) | A backend implementing the contract, a driver, and a real server for the suite. A mock does not count |
| TLS — local | `VERIFIED` | Test PKI minted per run; verified handshake; hostname mismatch, untrusted issuer and missing CA refused; no plaintext served; redirect to plaintext refused (ADR-066) | — |
| TLS — remote/production | `BLOCKED` | No remote host. A localhost certificate says nothing about production issuance or rotation | A host with TLS termination and a real certificate |
| Real-data forecasting validation | `BLOCKED` | No labelled corpus acquired; the gate correctly refuses | Approval to acquire a corpus; see `docs/DATASET_ACQUISITION.md` |
| Linux, current revision | `VERIFIED` (test suite, frontend, loopback runtime) | Arch Linux, kernel 7.2.9, Python 3.14.8: backend 1292 passed, 3 skipped; Linux telemetry module 30 passed, 1 skipped; frontend `tsc` 0, 67 passed, build succeeded; loopback startup and `verify_live_launcher.py` clean. The collector was not started during validation - `PLATFORM_SUPPORT.md` §6, ADR-075 to ADR-077 | A sustained Linux collector run; a real-browser session |
| Live NetFlow/IPFIX | `BLOCKED` | No exporter; collector deliberately not built (ADR-072) | Authorized exporter, observation point, permission to listen |
| macOS | `NOT_APPLICABLE_WITH_JUSTIFICATION` | The blueprint sets "Windows and Linux; macOS assessed later" | — |

## Ports and listeners (read-only, 17 Oct)

| Check | Result |
|---|---|
| Operational instance | `127.0.0.1:8000`, one interpreter (PID 37664) under its venv launcher; nothing bound beyond loopback |
| Test servers | The HTTPS suite binds an ephemeral `127.0.0.1` port and asserts it closed afterwards; none remained after the full run |
| `TIME_WAIT` false conflict | Fixed earlier in `start_prahari.ps1` (`-State Listen`) |
| PostgreSQL / flow ports (5432, 2055, 4739, 9995, 9996) | Nothing listening |
