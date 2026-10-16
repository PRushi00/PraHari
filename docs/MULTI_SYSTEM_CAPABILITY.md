# PraHari — Multi-System and Organization-Wide Monitoring Capability Audit

What PraHari can actually do today for monitoring more than one machine,
traced through code, tests and configuration rather than inferred from
type names or placeholders.

**This is an architecture audit. No collector was deployed, no system was
enrolled, no network was monitored, and no configuration was changed.**

Status vocabulary:

| | |
|---|---|
| **IMPLEMENTED AND TESTED** | Code exists, is reachable through the API, and tests exercise it |
| **IMPLEMENTED, UNDER-TESTED** | Code exists and is reachable; tests do not cover the behaviour |
| **PARTIAL** | Some of the capability exists; a named part does not |
| **NOT IMPLEMENTED** | No code performs this |
| **UNKNOWN** | Evidence insufficient to classify |

---

## A. Endpoint collection

| Capability | Status | Evidence | Limitations | Required work | Priority |
|---|---|---|---|---|---|
| Windows TCP connection-table collection | **IMPLEMENTED AND TESTED** | `app/adapters/windows_telemetry.py`; `app/services/collector.py`; `tests/integration/test_windows_collector.py` (22) | Connection metadata only. Snapshot polling misses connections shorter than the interval | — | — |
| Windows UDP endpoint table | **IMPLEMENTED AND TESTED** | `app/adapters/windows_host_observations.py`; `app/api/v1/hostobs.py`; `tests/unit/test_host_observations.py` | Locally bound sockets only. **No remote peer exists**, so these carry no destination | — | — |
| Interface byte/packet counters | **IMPLEMENTED AND TESTED** | same module, `InterfaceStatisticsProbe` | Per-interface and cumulative. **Not attributable** to a flow, process or destination | — | — |
| Linux collector | **NOT IMPLEMENTED** | `collector.py:195` `platform_supported` returns `sys.platform == "win32"` unless a query function is injected | Linux hosts report state `unsupported`; `/hostobs/*` returns 501 | A `/proc/net/tcp` or `ss` adapter | **High** |
| macOS collector | **NOT IMPLEMENTED** | No adapter exists | — | A `netstat`/`lsof` adapter | Medium |
| Multiple endpoint identities | **PARTIAL** | `telemetry_sources` table, `source_id` on every event (`schemas/events.py`); central credentials are per-source (`core/security.py`) | **The collector is a process-global singleton** — `collector.py:558` `_collector: Optional[...] = None`. One backend process collects for **one** source | Per-source collector registry, or accept that each endpoint runs its own agent | **High** |
| Source enrollment / registration | **PARTIAL** | Auto-registration on first ingest (`api/v1/imports.py`, `api/v1/stream.py`); credentials minted offline by `scripts/manage_credentials.py` | No enrollment API, no token distribution, no approval step. An operator edits a JSON file | Enrollment endpoint + credential issuance flow | **High** |
| Source health and last-seen | **IMPLEMENTED AND TESTED** | `CollectorStatus` (`collector.py:74-104`): `last_success_at`, `consecutive_failures`, `collection_gaps`; `db.refresh_source_activity` | Health is reported for the **local** collector. A remote source's liveness is inferred from its last event only | Per-source heartbeat and staleness thresholds | **High** |
| Reconnection / missing telemetry | **IMPLEMENTED, UNDER-TESTED** | `_detect_gap`, `CollectionGap`, `MAX_CONSECUTIVE_FAILURES` (`collector.py:302`) | Gaps are detected and recorded for the local collector; there is no equivalent for a remote source that stops submitting | Staleness detection on the ingest side | **High** |
| Authentication of source submissions | **IMPLEMENTED AND TESTED** | `core/security.py`, `api/auth.py`; `tests/integration/test_central_security.py` (24) | **Verified over loopback only.** No rate limiting, no TLS in-process | Network exposure review, TLS termination | **High** |
| Duplicate / replay handling | **IMPLEMENTED AND TESTED** | Deterministic event ids (`windows_telemetry.py`, `research_csv.py`); `INSERT OR IGNORE` (`database.py:404`); `tests/integration/test_research_ingestion.py` | Idempotent by content. **No nonce or timestamp window**, so a captured payload can be re-submitted indefinitely — it simply inserts nothing | Replay window or submission nonce | Medium |

---

## B. Network visibility

| Capability | Status | Evidence | Limitations | Required work | Priority |
|---|---|---|---|---|---|
| TCP connection metadata | **IMPLEMENTED AND TESTED** | `windows_telemetry.py` | 5-tuple, state, owning process, creation time. No payload | — | — |
| UDP visibility | **PARTIAL** | `windows_host_observations.py` | Bound sockets only. UDP is connectionless, so **no conversation is observable** from the endpoint table | A sensor, not an endpoint change | Medium |
| Per-flow packet and byte counts | **NOT IMPLEMENTED** | `windows_telemetry.py:410-412` sets `duration/packets/bytes_total` to `None` with a `SOURCE_LIMITED` flag | The Windows connection table does not expose them. Interface counters are a different measurement type and are kept apart | A network sensor, or packet capture (out of scope) | Medium |
| DNS / domain activity | **PARTIAL** | `app/services/enrichment.py`; `GET /enrichment/dns/diagnose` | Implemented and reachable, but **yields nothing on this host**: the DNS client cache reads empty as non-admin. The diagnosis declines to name a cause | Evidence distinguishing the candidate explanations | Low |
| East-west traffic between endpoints | **PARTIAL** | Each endpoint sees its own connections | Visible **only** where both ends run a collector, and then as two independent one-sided records. There is **no join** | Correlation on 5-tuple + time (Stage D) | **High** |
| Traffic involving systems without a collector | **NOT IMPLEMENTED** | — | Invisible unless the other end is a collector host's peer | Authorized passive sensor | **High** |
| Passive network sensor integration | **PARTIAL** | `app/adapters/json_stream.py` ingests Zeek `conn.log` / Suricata EVE; `POST /stream/ingest/ndjson`; `tests/unit/test_network_sensor_adapters.py` (21), `tests/integration/test_sensor_ingest_roundtrip.py` (5) | The **ingest contract** is implemented and tested. **No live sensor has ever produced data into PraHari** | Authorized segment, tap/mirror port, sensor host | **High** |
| Packet-level monitoring | **NOT IMPLEMENTED — out of scope** | No capture code exists anywhere | Permanent: no promiscuous mode, no driver, no TLS interception | — | — |

> **The honest summary of this section:** PraHari sees what the hosts
> running its collector can see about their own sockets. That is not
> network-wide visibility, and the connection table is not a substitute
> for packet-level monitoring.

---

## C. Central ingestion and correlation

| Capability | Status | Evidence | Limitations | Required work | Priority |
|---|---|---|---|---|---|
| Multiple source ingestion | **IMPLEMENTED AND TESTED** | `POST /stream/ingest/ndjson`, `/import/csv/*`, `/applayer/*`; per-source credentials | Works. Load behaviour at many concurrent sources is unmeasured | Concurrency testing | Medium |
| Stable source identifiers | **IMPLEMENTED AND TESTED** | `telemetry_sources` primary key; `source_id` on every event | Operator-chosen strings. **No uniqueness enforcement across machines** — two hosts can claim one id | Identity issued at enrollment | **High** |
| Cross-source event correlation | **NOT IMPLEMENTED** | No correlation code exists. `grep -rn "correlat"` over `app/` matches only a confidence-level docstring in `schemas/events.py:221` | Events from two endpoints describing one conversation stay unrelated rows | Correlation engine (Stage D) | **High** |
| Timestamp / timezone consistency | **PARTIAL** | `is_plausible_timestamp` in `schemas/events.py`, one shared definition; UTC-aware storage throughout | Normalisation is consistent. **No clock-skew detection between sources** — a host with a wrong clock silently reorders the merged timeline | Per-source skew estimation | **High** |
| Provenance isolation | **IMPLEMENTED AND TESTED** | `app/research/selection.py`; `app/core/research_store.py`; `tests/integration/test_forecast_validity.py`, `test_research_ingestion.py` | Benchmark / live / generated separated and refused when mixed | — | — |
| Duplicate delivery | **IMPLEMENTED AND TESTED** | Deterministic ids + `INSERT OR IGNORE` | Safe to re-deliver. See replay note in §A | — | — |
| Per-source errors and health | **PARTIAL** | `AdapterRegistry` health, `audit_events`, source `status` | Adapter-level health exists. No per-source error budget or alerting | Health rollup per source | Medium |
| Scale and backpressure | **NOT IMPLEMENTED** | No rate limiting, queueing, or backpressure anywhere (`grep` for rate_limit/throttle/backpressure returns nothing) | Request size caps exist (5,000-record batch, 100,000-row import). SQLite single-writer is the throughput ceiling | Queue + load testing | **High** |

---

## D. Enterprise security and operations

| Capability | Status | Evidence | Limitations | Required work | Priority |
|---|---|---|---|---|---|
| Authentication | **IMPLEMENTED AND TESTED** | `core/security.py`: PBKDF2-HMAC-SHA256, 240k iterations, per-credential salt, constant-time compare | Loopback-verified only | Network exposure review | **High** |
| Authorization / source scoping | **IMPLEMENTED AND TESTED** | `Principal.may_access_source` (`security.py:163`), `assert_source_access` (`:174`); `api/auth.py` | An unscoped query returns only the caller's source; cross-source is 403 | — | — |
| Credential lifecycle | **PARTIAL** | `scripts/manage_credentials.py`: `init`, `add`, `list`, `disable` | **No expiry, no rotation, no revocation list.** `disable` is a manual JSON edit; a leaked token is valid until someone edits a file | Expiry, rotation, audited revocation | **High** |
| Tenant / organizational isolation | **NOT IMPLEMENTED** | No tenant concept anywhere (`grep -rn "tenant\|organization"` over `app/` returns nothing) | Source-level isolation only. One deployment serves one organization | Tenant model if multi-org is ever required | Low |
| Retention and access policy | **IMPLEMENTED AND TESTED** | `app/services/retention.py`; `tests/integration/test_retention.py` (20) | Manual, dry-run default, confirmation token, never scheduled. Audit records never pruned | Scheduled retention would need its own risk review | — |
| Central service availability | **NOT IMPLEMENTED** | Single process, single SQLite file | No HA, no failover, no replication | Out of scope for the current architecture | Low |
| Failure recovery | **PARTIAL** | WAL journaling, batched retention transactions, graceful collector shutdown (`main.py` lifespan) | No backup or restore procedure is implemented or documented | Backup/restore runbook | **High** |
| Deployment and update | **PARTIAL** | `Dockerfile`, `docker-compose.yml`, `.dockerignore`, startup scripts; `tests/integration/test_container_config.py` (18, **static only**) | **The image has never been built or run** — Docker is not installed on the development host | Build and run the container once | Medium |
| Auditability of PraHari itself | **IMPLEMENTED AND TESTED** | `audit_events` table; `GET /audit/logs`; retention never prunes it | Records ingestion, training, blocked forecasts, retention runs, credential use | — | — |

---

## Staged roadmap

Each stage is separately scoped work requiring review. **None of it is
implemented by this audit.**

### Stage A — Multi-endpoint collection
Linux collector (`/proc/net/tcp`), a per-source collector registry
replacing the process-global singleton, and an agent packaging story. The
singleton (`collector.py:558`) is the concrete blocker: one backend
process currently collects for one source.

### Stage B — Reliable central ingestion and source management
Enrollment API with issued identities (removing operator-chosen `source_id`
collisions), credential expiry and rotation, per-source heartbeat and
staleness detection, and backpressure. SQLite's single-writer limit should
be measured before it is assumed adequate.

### Stage C — Network-wide visibility
Authorized passive sensors. The ingest contract is already built and
tested; what is missing is written authorization for a segment, a tap or
mirror port, and a sensor host. **This is a permissions problem before it
is an engineering problem.**

### Stage D — Cross-source correlation and alerting
Join one-sided observations from two endpoints into conversations; detect
and compensate clock skew; define alerting with evidence attached. Nothing
of this exists today.

### Stage E — Resilience, access control, scale, operations
Backup/restore, availability, load testing, and a container that has
actually been run.

---

## What this audit changed

Nothing in the collector, protocol, sensor, deployment or identity
architecture. Two narrow correctness fixes were made in the research
pipeline and are documented in ADR-042; everything in the tables above is
observation.
