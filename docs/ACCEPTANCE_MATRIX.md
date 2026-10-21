# PraHari — Blueprint Acceptance Matrix

Every acceptance criterion in **§18 Definition of done** of the 18-page
blueprint, plus the proposed defaults the blueprint names elsewhere
(PostgreSQL, TLS, Linux, live flow collection). This supersedes the status
column of `REQUIREMENTS_MATRIX.md`, which used a looser vocabulary and had
gone stale in places.

**Assessed 17 Oct 2026 on Windows 11, Python 3.12.0, Node 24.19.0.**
**Updated 21 Oct 2026 on Linux (kernel 6.18.44), Python 3.13.16, Node
22.22.0, PostgreSQL 16.15** — rows 1, 9 and 12 and the PostgreSQL and
Linux rows below. Nothing else was re-assessed, so every other row still
carries its 17 Oct evidence.

| Status | Meaning |
|---|---|
| `VERIFIED` | Implemented, and executed evidence exists in the scope stated |
| `PARTIAL` | Implemented for part of the scope; the remainder is named |
| `MISSING` | Not implemented |
| `BLOCKED` | Cannot be completed without an external resource or authorization |
| `NOT_APPLICABLE_WITH_JUSTIFICATION` | Outside the blueprint's current scope, with the reason |

**Overall: not fully verified.** Real-data forecasting, live network-flow
collection and a remote TLS deployment are not. PostgreSQL and
current-revision Linux now are, within the scope each row states. No percentage is given; the criteria are not equally weighted.

Commands below run from `backend/` unless shown otherwise.

---

## §18 criteria

| # | Criterion | Status | Evidence | Reproduce | Remaining prerequisite |
|---|---|---|---|---|---|
| 1 | Local deployment runs end-to-end on declared supported OSes | `PARTIAL` | **Windows:** launched via `start_prahari.ps1`, healthy in ~2 s, dashboard/`/docs`/`/system/health` 200, restarted and re-verified 17 Oct. **Linux:** current revision run on Arch (Python 3.14.8): started on 127.0.0.1 against a disposable database, `/health` 200 with `x-request-id`, collector status `stopped`, shut down cleanly - `PLATFORM_SUPPORT.md` §6, ADR-075. **Windows, current revision (17 Oct, ADR-082):** launcher verifier 21/21 with graceful shutdown; `-CheckOnly` now side-effect-free; real browser across every page on isolated servers | `powershell -File ..\start_prahari.ps1 -CheckOnly`; `python scripts\verify_live_launcher.py` | A real-browser Linux session; a sustained Linux collector run |
| 2 | Central deployment accepts authenticated telemetry from distinct, authorized identities | `VERIFIED` (loopback) | PraHari as a **separate process over HTTPS**, central mode, hashed credential file: two sensors deliver, are deduplicated, and are audited under their own credentials | `pytest tests/integration/test_central_https_e2e.py -v` | Remote network deployment: see TLS row |
| 3 | ≥1 host and ≥1 network-level integration tested on declared environments | `PARTIAL` | Host: Windows connection table, live-verified; Linux `/proc/net/tcp` reader run against the live table on Arch by test, collector not started (ADR-075). Network-level: flow-**export** parsing (30 tests). No live collector exists (ADR-072) | `pytest tests/unit/test_netflow_adapter.py -q` | An authorized exporter and observation point |
| 4 | Replay and live ingestion use the same canonical contracts | `VERIFIED` | One `NormalizedEvent` schema for every adapter; deterministic identity shared by stream and replay | `pytest tests/integration/test_stream_idempotency.py -q` | — |
| 5 | Adapters expose capability and health; failures visible | `VERIFIED` | `/system/health`, capability reports. **Fixed this session:** a batch where every record was rejected never reached health (ADR-068) | `pytest tests/integration/test_audit_identity_and_rejection_visibility.py -q` | — |
| 6 | Target, horizon, label and negative-label rules documented and tested | `VERIFIED` | Structured, versioned, fingerprinted target `prahari.attack_label_in_horizon` v1.1.0 (ADR-070) stating every rule, including its shortfalls | `pytest tests/integration/test_label_policy_target_and_manifest.py -q` | — |
| 7 | Dataset provenance, hashes, schemas, audit, feature definitions, split manifests | `PARTIAL` | Tooling complete: import policy, per-file hashes, audit report, manifest 1.1.0 with git revision, configuration hash and split parameters. **No real dataset has been audited.** Compatibility verified by header reads: 1 of 10 CSE-CIC-IDS2018 processed files is importable as-is (ADR-088) | `pytest tests/integration/test_experiment_replay.py -q` | An approved corpus (`docs/DATASET_ACQUISITION.md`) |
| 8 | Baseline and temporal models on one valid target, leakage-resistant | `PARTIAL` | Constant, rate-threshold, logistic regression, random forest and NumPy LSTM on one chronological purged split. **Fixed:** late live events leaked into earlier windows (ADR-069); labels of mixed or model provenance were accepted (ADR-070). **Synthetic data only** | `pytest tests/unit/test_prediction_time_availability.py -q` | Real labelled data |
| 9 | Precision/recall, PR-AUC, false alarms, missed events, lead time, generalization | `PARTIAL` | All computed at window level, **and now at event level** (ADR-091): first-qualifying-warning lead time with its distribution, missed-event rate, late warnings, false alarms per hour and alarm duty cycle, under fingerprinted matching rules. Running it found the rate-threshold baseline scoring window recall **1.000** while warning **0 of 3 events**. No real-data numbers exist | `pytest tests/unit/test_event_level.py tests/integration/test_event_level_api.py -q` | Real data |
| 10 | Dashboard uses actual backend results; distinguishes observed, forecast, confirmed | `VERIFIED` | 67 frontend tests (passing on Windows and on Arch Linux, ADR-076); earlier UI→API→DB trace reconciled exactly | `cd frontend && npx vitest run` | — |
| 11 | Central authn, authz, isolation, payload limits, audit, retention tested | `VERIFIED` | Now also **over real HTTPS**: 401 without/with bad credential, 403 cross-source and read-only, revocation without restart, 413 with server log evidence, per-credential rate limit, no token in server log. **Fixed:** audit named the wrong actor (ADR-067) | `pytest tests/integration/test_central_https_e2e.py tests/integration/test_central_security.py -q` | — |
| 12 | Replay, adapter contract, unit, integration, security, end-to-end tests pass | `VERIFIED` on Windows and on Linux | **Windows, Python 3.12.10:** 1336 passed, 8 skipped, 0 failed; 15 `live_windows` pass. **Linux, Python 3.13.16, merged `windows-closure` revision (21 Oct):** 1335 passed, 22 skipped, 0 failed on the inherited revision — so ADR-080, ADR-083 and ADR-089 now have Linux evidence — then **1400 passed, 22 skipped, 0 failed** with this session's work and a PostgreSQL server, or 1377 passed / 45 skipped without one. Frontend on Linux: `tsc` 0, 99 passed, build succeeds. All 22 Linux skips are Windows-only or explicitly non-Linux. Skips are never counted as passes | `pytest -q -rs` | — |
| 13 | Reproducibility manifests and troubleshooting docs match the implementation | `VERIFIED` | Manifest 1.1.0 records what was previously missing; 1.0.0 manifests still load; replay verified | `pytest tests/integration/test_experiment_replay.py -q` | — |
| 14 | No automatic network changes or disruptive response | `VERIFIED` | No code path alters routes, firewall or interfaces; collectors off by default; no listener built speculatively (ADR-072) | `grep -rniE "netsh|iptables|route add|New-NetFirewallRule" app/` (no matches expected) | — |
| 15 | Limitations, negative results, unsupported platforms, failed experiments documented | `VERIFIED` | README §27, ADRs, and limitations now carried inside every manifest | — | — |

## Proposed defaults named elsewhere in the blueprint

| Item | Status | Evidence | Remaining prerequisite |
|---|---|---|---|
| PostgreSQL central store | `VERIFIED` (conformance) / `PARTIAL` (substitutable) | `storage/postgres.py` (ADR-092) satisfies the contract and passes the conformance suite against **a real PostgreSQL 16.15 server** — every parametrized test on both backends — plus a 15-test PostgreSQL suite and cross-backend equivalence (`model_dump()` equality for events, analyses and import summaries). The batch-ordering that prevents deadlock is mutation-checked: shuffled fails 3/3 with `DeadlockDetected`, sorted passes 3/3. Two defects found and fixed. Without a DSN the 23 tests **skip**, never pass | The three `KNOWN_ABSTRACTION_LEAKS` still issue SQLite SQL, so the app cannot yet run on it. Production deployment, TLS, backups and migrations are untested; the server used was loopback with trust auth |
| TLS — local | `VERIFIED` | Test PKI minted per run; verified handshake; hostname mismatch, untrusted issuer and missing CA refused; no plaintext served; redirect to plaintext refused (ADR-066) | — |
| TLS — remote/production | `BLOCKED` | No remote host. A localhost certificate says nothing about production issuance or rotation | A host with TLS termination and a real certificate |
| Real-data forecasting validation | `BLOCKED` | No labelled corpus acquired; the gate correctly refuses | Approval to acquire a corpus; see `docs/DATASET_ACQUISITION.md` |
| Linux, current revision | `VERIFIED` (test suite, frontend) | **21 Oct 2026, kernel 6.18.44, Python 3.13.16, Node 22.22.0:** the merged `windows-closure` revision ran clean on Linux — backend 1335 passed, 22 skipped, 0 failed; frontend `tsc` 0, 99 passed, production build succeeded. This closes the parity gap the previous row left open: ADR-080 (verifier SIGTERM branch), ADR-083 (registry `replace`) and ADR-089 (binding report) had only Windows evidence and now have Linux evidence too. Earlier Arch run at `4360ca3`: `PLATFORM_SUPPORT.md` §6, ADR-075 to ADR-077 | A sustained Linux collector run; a real-browser session; the launcher itself is Windows PowerShell |
| Live NetFlow/IPFIX | `BLOCKED` | No exporter; collector deliberately not built (ADR-072) | Authorized exporter, observation point, permission to listen |
| macOS | `NOT_APPLICABLE_WITH_JUSTIFICATION` | The blueprint sets "Windows and Linux; macOS assessed later" | — |

## Ports and listeners (read-only, 17 Oct)

| Check | Result |
|---|---|
| Operational instance | `127.0.0.1:8000`, one interpreter (PID 37664) under its venv launcher; nothing bound beyond loopback |
| Test servers | The HTTPS suite binds an ephemeral `127.0.0.1` port and asserts it closed afterwards; none remained after the full run |
| `TIME_WAIT` false conflict | Fixed earlier in `start_prahari.ps1` (`-State Listen`) |
| PostgreSQL / flow ports (5432, 2055, 4739, 9995, 9996) | Nothing listening |

## Windows validation of `4360ca3` (17 Oct 2026)

| Gate | Status | Evidence |
|---|---|---|
| Windows backend | `VERIFIED` | Python 3.12.10: 1336 passed, 8 skipped (all explained), 0 failed, 3 upstream deprecation warnings |
| Windows telemetry | `VERIFIED WITH LIMITATIONS` | 15 `live_windows` tests: TCP, UDP and interface counters read live into temporary storage; the DNS script runs in real PowerShell over instances of the real `MSFT_DNSClientCache` class, its property names checked against the OS schema (ADR-086). Unproven: `Get-DnsClientCache` returning populated objects - the cache on this host is empty |
| Launcher | `VERIFIED` | Verifier 23/23 (`python` and `-O`, incl. `/system-health` and `/admin`), graceful stop. The **real `start_prahari.ps1`** was run against a temporary database: it served the rebuilt `frontend/dist` bundle, every client route, and a binding report of `CONFIGURED` (configured port = serving port), then stopped gracefully. `-CheckOnly` side-effect-free |
| Frontend | `VERIFIED` | `tsc` 0, 91 passed; `frontend/dist` rebuilt; real browser through the real launcher: deep links, refresh, back/forward, aliases, unknown routes; binding card green only with evidence (ADR-089) |
| Cross-platform parity | `VERIFIED` (shared code) | Shared changes pass on Windows and, since 21 Oct, on Linux: ADR-080 (verifier SIGTERM branch), ADR-083 (registry `replace`) and ADR-089 (binding report) ran there with the rest of the suite. What remains platform-specific is genuinely so — the launcher is Windows PowerShell and the live host collector is Windows-only; those skip on Linux by design |
| Preservation | `VERIFIED` | Both databases, sidecars, `db_backups/`, `experiments/` and `frontend/dist` byte-identical before and after |
| Collector lifecycle | `VERIFIED` (temporary database) | The application's collector class, real query, start/poll/stop and restart into a temporary database (ADR-086). Running the application's own collector against `prahari.db` remains an operator decision, not a test |
| Graceful shutdown | `VERIFIED WITH LIMITATIONS` | 2 hangs in 15 observed stops, both on Python 3.12.0 with a real browser; none on 3.12.10, including the real launcher with a browser open. Not reproduced; no fix applied (ADR-087) |
