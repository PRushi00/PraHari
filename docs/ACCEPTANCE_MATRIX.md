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

**Also updated 21 Oct 2026 on Windows 11, Python 3.12.10** — rows 1, 12
and 13. This is the Windows run that ADR-099 and ADR-100 asked for
("everything here ran on Linux... no Windows claim rests on these runs").
It found one unrelated failure, now fixed (ADR-101).

| Status | Meaning |
|---|---|
| `VERIFIED` | Implemented, and executed evidence exists in the scope stated |
| `PARTIAL` | Implemented for part of the scope; the remainder is named |
| `MISSING` | Not implemented |
| `BLOCKED` | Cannot be completed without an external resource or authorization |
| `NOT_APPLICABLE_WITH_JUSTIFICATION` | Outside the blueprint's current scope, with the reason |

**Overall: not fully verified**, but the scientific rows now have real
evidence. Live network-flow collection and a remote TLS deployment remain
unverified. Rows 7, 8 and 9 are measured on a real corpus (ADR-095,
ADR-096) and **the measured answer is negative**: the learned models do
not forecast attack onsets on this data; the strong figures measure
detection of attacks already in progress, which a trivial persistence
rule does better. That is a result, not a gap in tooling. PostgreSQL and
current-revision Linux are verified within the scope each row states. No percentage is given; the criteria are not equally weighted.

Commands below run from `backend/` unless shown otherwise.

---

## §18 criteria

| # | Criterion | Status | Evidence | Reproduce | Remaining prerequisite |
|---|---|---|---|---|---|
| 1 | Local deployment runs end-to-end on declared supported OSes | `VERIFIED` (Linux) / `PARTIAL` (Windows revision) | **Linux, 21 Oct:** the application was served and driven by **real Chromium** — 27/27 checks (ADR-098): every canonical route and alias as a typed deep link, reload stays put, back/forward, unknown path renders Not Found, React root never empty, no uncaught error. Run against a SQLite-backed AND a PostgreSQL-backed instance. **Windows:** launched via `start_prahari.ps1`, healthy in ~2 s, verifier 23/23, real browser across every page (17 Oct) | `python scripts/verify_browser_session.py --url http://127.0.0.1:8099` | **Windows run of this revision now done (21 Oct 2026):** full backend suite 1442 passed / 52 skipped / 0 failed, all 15 `live_windows` green, and the live collector exercised through the API on real Windows 11 telemetry — two processes on distinct source ids, 66 shared connections resolving to 66 distinct `event_id`s (ADR-099), and `GET /events/stats/summary` measured complete at 1,250 events (ADR-100). **Still outstanding:** the real-Chromium verifier has not been re-run on Windows for this revision, and no *sustained* collector run exists — the longest observed here was 101 polls / 25 minutes / 416 events, which is below the 1000-event threshold ADR-100 is about |
| 2 | Central deployment accepts authenticated telemetry from distinct, authorized identities | `VERIFIED` (loopback) | PraHari as a **separate process over HTTPS**, central mode, hashed credential file: two sensors deliver, are deduplicated, and are audited under their own credentials | `pytest tests/integration/test_central_https_e2e.py -v` | Remote network deployment: see TLS row |
| 3 | ≥1 host and ≥1 network-level integration tested on declared environments | `PARTIAL` | Host: Windows connection table, live-verified; Linux `/proc/net/tcp` reader run against the live table on Arch by test, collector not started (ADR-075). Network-level: flow-**export** parsing (30 tests). No live collector exists (ADR-072) | `pytest tests/unit/test_netflow_adapter.py -q` | An authorized exporter and observation point |
| 4 | Replay and live ingestion use the same canonical contracts | `VERIFIED` | One `NormalizedEvent` schema for every adapter; deterministic identity shared by stream and replay | `pytest tests/integration/test_stream_idempotency.py -q` | — |
| 5 | Adapters expose capability and health; failures visible | `VERIFIED` | `/system/health`, capability reports. **Fixed this session:** a batch where every record was rejected never reached health (ADR-068) | `pytest tests/integration/test_audit_identity_and_rejection_visibility.py -q` | — |
| 6 | Target, horizon, label and negative-label rules documented and tested | `VERIFIED` | Structured, versioned, fingerprinted target `prahari.attack_label_in_horizon` v1.1.0 (ADR-070) stating every rule, including its shortfalls | `pytest tests/integration/test_label_policy_target_and_manifest.py -q` | — |
| 7 | Dataset provenance, hashes, schemas, audit, feature definitions, split manifests | `VERIFIED` | **A real corpus has now been acquired and audited** (21 Oct, ADR-095, `docs/DATASET_PROVENANCE_IDS2018.md`): CSE-CIC-IDS2018, all 10 processed CSVs, 6.41 GB, SHA-256 per file, citation-only terms accepted by the operator. 607,785 flows imported under an explicit policy — 0 rejected, reconciles — with an import manifest and an experiment manifest carrying the dataset fingerprint and git revision. The audit found four source defects the pipeline would otherwise have absorbed silently: a 12-hour clock with no AM/PM, seven files truncated at the 2²⁰ spreadsheet limit, addresses absent (and unrecoverable) from 9 of 10 files, and two distinct attacks sharing one label | `POST /research/import/csv` then `POST /research/audit`; see the provenance doc | — |
| 8 | Baseline and temporal models on one valid target, leakage-resistant | `VERIFIED` | **An interpretable real-data evaluation now exists** (ADR-096): Thursday 15-02-2018, 659,226 flows, a purged chronological split with both classes on both sides (train 72/467, test 171/378), every model `metrics_interpretable: true`. Constant, rate-threshold, persistence, logistic regression, random forest, temporal stack and NumPy LSTM all evaluated on one target under the `addressless.v1` feature schema. **Fixed earlier:** late-event leakage (ADR-069), mixed label provenance (ADR-070) | `POST /forecast/train` with `train_ratio=0.5` on `ids2018-thu15feb` | A second corpus, for cross-dataset generalization |
| 9 | Precision/recall, PR-AUC, false alarms, missed events, lead time, generalization | `VERIFIED` (measured) / result is **negative** | All computed on real data at window AND event level (ADR-091, ADR-096). **The measurement is the finding:** at a split whose holdout holds only attack continuations the LSTM scores PR-AUC 0.9925 and the event-level report REFUSES (no onset in reach); at a split containing a real onset the LSTM falls to 0.3387, below the 0.3115 constant baseline, while persistence holds 0.9420. Event-level: 1 event in coverage, **0 warned, missed-event rate 1.0**, 2 late warnings, 7 false alarms (3.08/h), duty cycle 9.0 %, no lead time | `POST /forecast/event-level` on `ids2018-thu15feb` | More events in coverage: 1 is too few for a robust rate |
| 10 | Dashboard uses actual backend results; distinguishes observed, forecast, confirmed | `VERIFIED` | 67 frontend tests (passing on Windows and on Arch Linux, ADR-076); earlier UI→API→DB trace reconciled exactly | `cd frontend && npx vitest run` | — |
| 11 | Central authn, authz, isolation, payload limits, audit, retention tested | `VERIFIED` | Now also **over real HTTPS**: 401 without/with bad credential, 403 cross-source and read-only, revocation without restart, 413 with server log evidence, per-credential rate limit, no token in server log. **Fixed:** audit named the wrong actor (ADR-067) | `pytest tests/integration/test_central_https_e2e.py tests/integration/test_central_security.py -q` | — |
| 12 | Replay, adapter contract, unit, integration, security, end-to-end tests pass | `VERIFIED` on Windows and on Linux | **Windows 11, Python 3.12.10, 21 Oct 2026, this branch:** 7ad866e as inherited gave **1 failed, 1440 passed, 52 skipped**; with ADR-101's fix, **1442 passed, 52 skipped, 0 failed** in 150 s, and all **15 `live_windows` pass** against real connection-table collection (`pytest -m live_windows -q`). The one failure was `test_store_selection.py::test_a_sqlite_url_identifies_as_its_resolved_path`, which pinned the store identity as `startswith("sqlite:/")` — true only where an absolute path opens with a separator; ADR-097's suite had only ever run on Linux. **ADR-099 and ADR-100 refer to "the 24 `live_windows` tests"; the marker collects 15.** Linux reports 66 skips against 52 here because each platform skips the other's tests; a working copy with no `.git` skips 19 more (`test_ignore_rules.py`). The earlier figure in this row (1336 passed, 8 skipped) predates ADR-092 onward. **Linux, Python 3.13.16, merged `windows-closure` revision (21 Oct):** 1335 passed, 22 skipped, 0 failed on the inherited revision — so ADR-080, ADR-083 and ADR-089 now have Linux evidence — then **1400 passed, 22 skipped, 0 failed** with this session's work and a PostgreSQL server, or 1377 passed / 45 skipped without one. Frontend on Linux: `tsc` 0, 99 passed, build succeeds. All 22 Linux skips are Windows-only or explicitly non-Linux. Skips are never counted as passes | `pytest -q -rs` | — |
| 13 | Reproducibility manifests and troubleshooting docs match the implementation | `VERIFIED` | Manifest 1.1.0 records what was previously missing; 1.0.0 manifests still load; replay verified. **The troubleshooting half of this row was an overclaim until 21 Oct 2026** — `BLUEPRINT_COVERAGE.md` carried §15 as `ABSENT as a guide` while this row read `VERIFIED`. `docs/TROUBLESHOOTING.md` now exists: fifteen rows, eleven distinct ADRs cited, every behavioural claim read in the source or exercised against a running instance. Rows 7 and 13 carry a measured Windows before/after for this revision's own two fixes (ADR-100, ADR-099) | `pytest tests/integration/test_experiment_replay.py -q` | — |
| 14 | No automatic network changes or disruptive response | `VERIFIED` | No code path alters routes, firewall or interfaces; collectors off by default; no listener built speculatively (ADR-072) | `grep -rniE "netsh|iptables|route add|New-NetFirewallRule" app/` (no matches expected) | — |
| 15 | Limitations, negative results, unsupported platforms, failed experiments documented | `VERIFIED` | README §27, ADRs, and limitations now carried inside every manifest | — | — |

## Proposed defaults named elsewhere in the blueprint

| Item | Status | Evidence | Remaining prerequisite |
|---|---|---|---|
| PostgreSQL central store | `VERIFIED` (selectable and running) / `BLOCKED` (deployment) | `storage/postgres.py` (ADR-092) satisfies the contract and passes the conformance suite against **a real PostgreSQL 16.15 server**, every parametrized test on both backends (43), plus a 15-test PostgreSQL suite and cross-backend equivalence (`model_dump()` equality for events, analyses and import summaries). The batch ordering that prevents deadlock is mutation-checked: shuffled fails 3/3 with `DeadlockDetected`, sorted passes 3/3. Two defects found and fixed. The three abstraction leaks are **closed** (ADR-093), `KNOWN_ABSTRACTION_LEAKS` is empty, and the **real FastAPI application is served from PostgreSQL** through audit, system health, retention, ingestion, event query, sources and analysis. Without a DSN the PostgreSQL tests **skip**, never pass. **Selectable from configuration since ADR-097:** `PRAHARI_DATABASE_URL=postgresql://…` starts the real application on PostgreSQL — health reports `backend: postgresql`, 600 flows ingested and queried back, analysis run, and **real Chromium drove the dashboard against it, 27/27**. Store identity is credential-free; the protected-store guard now covers a schema, which the path guard could not see | A PostgreSQL **deployment**: no migration path from an existing SQLite database, and TLS termination, pooling, backups, failover and a tuned server are untested. The server used was loopback with trust auth. **Re-verified 21 Oct 2026 against a fresh PostgreSQL 16.15 cluster (ADR-104): full suite 1474 passed, 22 skipped, 0 failed with the server, versus 1428 passed / 66 skipped without it — the 22 remaining skips are Windows-only.** That run also found `event_breakdown()` (ADR-100) had been added to the contract and implemented for both backends while **nothing ever called the PostgreSQL implementation**; a cross-backend conformance test now covers it, and mutating that implementation to SQLite's `?` placeholder fails `[postgres]` while `[sqlite]` passes |
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
