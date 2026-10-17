# Starting Specification — Multi-Source Collection (Stage A/B)

Evidence-backed scope for the next phase. **Nothing here is implemented.**
This document exists so the work can be reviewed before it starts.

Capability context: [MULTI_SYSTEM_CAPABILITY.md](MULTI_SYSTEM_CAPABILITY.md).

---

## 1. The current singleton, precisely

`backend/app/services/collector.py`:

```python
_collector: Optional[WindowsTelemetryCollectorService] = None

def get_collector(db: Database) -> WindowsTelemetryCollectorService:
    global _collector
    if _collector is None:
        _collector = WindowsTelemetryCollectorService(db=db)
    return _collector
```

Observed lifecycle:

| Stage | Behaviour |
|---|---|
| Creation | Lazily, on the first `get_collector(db)` — i.e. the first `/collector/*` request |
| Identity | `source_id` defaults to `DEFAULT_SOURCE_ID`; `get_collector` never passes one, so **the default is the only id a running backend will ever use** |
| Replacement | `reset_collector(db, **kwargs)` constructs a new one. Used by tests and shutdown |
| Shutdown | `app/main.py` lifespan calls `collector.stop()` if running |
| Concurrency | One `asyncio` task, one interval, one database handle |

**The constructor already accepts `source_id`, `interval_seconds`,
`include_loopback` and `query_fn` per instance.** The limitation is not in
the service — it is that exactly one instance is reachable. That makes this
a registry problem, not a rewrite.

---

## 2. Required: per-source collector registry

Replace the module-global with a keyed registry.

```
CollectorRegistry
  get(source_id) -> service | None
  create(source_id, config) -> service        # refuses a duplicate id
  stop(source_id) / stop_all()
  statuses() -> list[CollectorStatus]
```

Requirements:

1. One running service per `source_id`; creating a second for the same id
   is an error, not a silent replacement.
2. `GET /collector/status` must become per-source. The current response is
   a single `CollectorStatus`; changing it is an **API break** and needs a
   versioning decision (new list endpoint vs. changed shape).
3. Shutdown stops every service and waits for each task.
4. A failing collector must not take the others down —
   `MAX_CONSECUTIVE_FAILURES` is currently per-service, which is correct.
5. Bounded: a cap on concurrent collectors, since each holds a database
   handle and SQLite has one writer.

**Open question for review:** does one backend process supervise many
local collectors, or does each endpoint run its own agent submitting to a
central instance? These are different products. The registry is needed for
the first; for the second the priority is §4 instead. The capability audit
assumes the second is the real goal.

---

## 3. Source identity and authentication

Current state (`app/core/security.py`, `scripts/manage_credentials.py`):

| Property | Status |
|---|---|
| Per-source credentials, PBKDF2-HMAC-SHA256, 240k iterations | Implemented, tested |
| Role separation `ingest` / `read_only` / `admin` | Implemented, tested |
| Unscoped query returns only the caller's source | Implemented, tested |
| Credential issuance | **Offline CLI only** — an operator edits a JSON file |
| Expiry / rotation / revocation list | **Not implemented** |
| `source_id` uniqueness across machines | **Not enforced** — any string is accepted |

Required:

1. An enrollment endpoint that **issues** the `source_id` rather than
   accepting an operator-chosen one, removing collision by construction.
2. Credential expiry (`not_after`) checked at authentication.
3. Rotation: overlapping validity so a source can re-key without a gap.
4. Revocation that takes effect without a file edit, and is audited.
5. Enrollment must be an admin-authenticated operation, and the issued
   token must be shown once — matching the existing mint behaviour.

---

## 4. Source health, last-seen and failure handling

Implemented today for the **local** collector only
(`CollectorStatus`, `collector.py:74-104`): `last_success_at`,
`consecutive_failures`, `collection_gaps`, `_detect_gap`.

Missing for **remote** sources:

1. A heartbeat distinct from data submission — a source with nothing to
   report is indistinguishable from one that has died.
2. A staleness threshold per source, with a derived state
   (`healthy` / `stale` / `silent`) rather than a timestamp a reader must
   interpret.
3. Gap detection on the ingest side mirroring `_detect_gap`.
4. An API surfacing all sources' health in one response.

Acceptance: a source stopped for longer than its threshold is reported
`silent` without an operator inspecting timestamps.

---

## 5. Clock skew and duplicate delivery

**Duplicate delivery is solved.** Deterministic event ids plus
`INSERT OR IGNORE` (`database.py:404`) make re-delivery idempotent, and
`tests/integration/test_research_ingestion.py` proves a repeat import
persists nothing new.

**Replay is not.** There is no nonce and no timestamp window, so a captured
payload can be re-submitted indefinitely. It inserts nothing, so the
impact is limited to log noise — worth closing, not urgent.

**Clock skew is not handled at all,** and this is the serious one. Every
event is stored UTC-aware and `is_plausible_timestamp` rejects absurd
values, but there is no per-source skew estimation. A host whose clock is
wrong by minutes silently reorders the merged timeline — and every window,
split and purge in the forecasting pipeline depends on that ordering.

Required:

1. Record ingest-time alongside `observed_at` so `ingest - observed` gives
   a per-source skew estimate.
2. Report estimated skew per source; flag beyond a threshold.
3. Decide explicitly whether to correct or only report. **Recommendation:
   report only.** Silently rewriting timestamps would make the stored data
   disagree with the source's own records.
4. Cross-source correlation (Stage D) must not proceed before this exists.

---

## 6. Linux collector feasibility

`platform_supported` gates on `sys.platform == "win32"` unless a query
function is injected (`collector.py:195`), so the service itself is
already platform-neutral — the adapter is not.

Feasible without new dependencies: `/proc/net/tcp` and `/proc/net/tcp6`
are readable unprivileged and give the 5-tuple, state and inode. Mapping
inode to process requires scanning `/proc/<pid>/fd`, which only resolves
for processes owned by the same user without elevation.

Required abstraction: a `ConnectionTableSource` protocol —
`query() -> list[dict]` plus a capability profile — implemented by the
existing Windows adapter and a new Linux one, with the collector depending
on the protocol rather than on PowerShell.

Honest limits to document up front: process attribution will be partial
without elevation, and `/proc/net/tcp` has the same snapshot-polling blind
spot as the Windows table.

**Linux runtime is already verified for everything else:** 727 passed /
2 skipped on Ubuntu 26.04.

---

## 7. Central ingestion and correlation boundaries

In scope for Stage B: enrollment, per-source health, credential lifecycle,
backpressure. **No rate limiting, queueing or backpressure exists today** *(Superseded 17 Oct 2026: per-credential rate limiting is in `api/limits.py` and bounded admission control in `services/admission.py`; current status in `docs/ACCEPTANCE_MATRIX.md`.)*
and SQLite's single writer is the throughput ceiling — measure before
assuming it is adequate.

Explicitly **out of scope** until Stage B lands: cross-source correlation.
It needs stable issued identities (§3) and skew handling (§5). Building it
first would produce confident joins over an untrustworthy timeline.

---

## 8. Tests and acceptance criteria

Local multi-source operation, all with synthetic fixtures and temporary
databases:

1. Two collectors with distinct `source_id`s run concurrently; events land
   under the correct source.
2. Creating a second collector for an existing id is refused.
3. Stopping one leaves the other running.
4. One failing repeatedly does not stop the other; its
   `consecutive_failures` rises in isolation.
5. Shutdown stops every service and leaves no running task.
6. A source silent beyond its threshold reports `silent`.
7. Enrollment issues a unique id; a client cannot choose one.
8. An expired credential fails authentication; a rotated one succeeds
   during the overlap.
9. Per-source skew is estimated and reported; a skewed source is flagged
   and its timestamps are **not** rewritten.
10. The Linux adapter returns the same canonical shape as the Windows one
    against a fixture, and reports partial process attribution honestly.
11. Re-delivery of an identical batch persists nothing new (extends the
    existing idempotency test to the multi-source case).

**Release gate for the phase:** 1–6 and 11 passing on Windows and Linux,
with the operational database untouched. Items 7–9 may land in a second
increment; 10 is independent.

---

## 9. Priority

| | Work | Why |
|---|---|---|
| 1 | Clock-skew estimation and reporting (§5) | Everything downstream depends on timeline order, and nothing currently detects a wrong clock |
| 2 | Per-source health and staleness (§4) | A dead source is currently invisible |
| 3 | Enrollment with issued identity (§3) | Removes `source_id` collisions by construction |
| 4 | Collector registry (§2) | Required only if one process supervises many collectors — resolve the §2 open question first |
| 5 | Linux adapter (§6) | Independent of the rest; can proceed in parallel |
| 6 | Credential expiry and rotation (§3) | Security debt, not a blocker for local multi-source |
| 7 | Backpressure (§7) | Needs measurement before design |

Correlation (Stage D) is deliberately absent from this list.

---

## Phase 1 outcome (implemented)

### §5 Clock skew — **superseded by evidence**

The plan put skew estimation first. Inspecting the schema before designing
changed the answer: **PraHari has no reference clock**, so skew cannot be
measured at all.

Verified facts, not assumptions:

| Field | What it is |
|---|---|
| `observed_at` | event time stated by the source |
| `ingested_at` | set by a `default_factory` at **object construction** in the backend — not a transport timestamp |

No monotonic clock, no sequence numbers, no round-trip measurement exist
(`grep` over `app/` returns nothing), and no adapter overrides
`ingested_at`.

Delivered instead: `GET /sources/clock-integrity`, reporting **ingest lag**
(`ingested_at - observed_at`) named as such, with its confounds attached.
One rigorous inference is drawn — delay cannot be negative, so a negative
lag of δ proves the source clock leads by **at least** δ. A positive lag
supports no skew claim, and the response says so.

**Was outstanding for real skew measurement:** a receiver-side submission
timestamp on the ingest path. **Closed in Phase 2** — see below.

### §4 Source health — **implemented**

`GET /sources/health` returns per-source state with the basis attached.
The finding that shaped it: `last_event_at` is max(`observed_at`), i.e.
**event time**, so freshness is only as trustworthy as each source's clock.
Health and clock integrity are one problem, and the response links them.

`SILENT` never means disconnected; `NEVER_SEEN` is distinct from it; a
future `last_event_at` yields `UNKNOWN` rather than `REPORTING`. No
heartbeat was invented.

### §2, §3, §6 — unchanged, still documented only

The collector registry, enrollment and the Linux adapter were deliberately
not implemented. The §2 open question (central supervision vs per-endpoint
agents) remains unresolved and still gates the registry work.

---

## Phase 2 outcome (implemented)

### The receiver-side timestamp — **implemented**

`received_at`, a nullable column on `normalized_events`, stamped at the API
boundary **before parsing** on the two paths where a remote process actually
submits data: `POST /stream/ingest/ndjson` and `POST /applayer/ingest`.
Locally collected events, file imports and synthetic replay record `NULL`,
meaning *not measured*, and are never backfilled. The client cannot supply
the field; an injected value in the request body is discarded.

Consequences for the two Phase 1 diagnostics:

* The clock diagnostic reports its `lag_reference` on every response, and
  asserts the lower bound and the `SOURCE_CLOCK_AHEAD` verdict **only**
  against a measured receipt.
* Source health prefers a measured receipt over event time and reports
  `clock_dependent: false` when it does — closing the §4 failure where a
  fast clock made a silent source look healthy.

See ADR-048 and ADR-049.

### Still not solved, and not claimed

1. **Exact skew is still not measurable.** A receipt bounds transit, not
   offset: a steadily offset clock producing a steadily offset *positive*
   lag remains undetectable. Closing that needs a round-trip exchange
   (request-sent / request-received / response-sent / response-received),
   not another timestamp on the event.
2. **No heartbeat (§4.1).** A source with nothing to report is still
   indistinguishable from one that has died. Unchanged.
3. **Historical rows have no receipt**, so the diagnostics remain weak on
   existing data.

### New finding — §5 duplicate delivery is narrower than stated

§5 above says duplicate delivery is solved. That holds for the research
importer and the collector, which derive deterministic ids. It does **not**
hold for `POST /stream/ingest/ndjson`: `adapters/json_stream.py:319` assigns
`uuid.uuid4()` per row, so a sensor retrying after a timeout double-counts
its own telemetry. Pinned by
`test_the_stream_path_is_not_idempotent_on_retry`.

**Addressed in Phase 3** — see below.

---

## Phase 3 outcome (implemented)

### Stream identity — **implemented, opt-in**

`/stream/ingest/ndjson` now derives a deterministic, source-scoped event id
from a sender-provided identifier (`event_id`, Zeek `uid`, `uuid`,
`record_id`, scalar `id`) or, failing that, from a batch idempotency key
plus record index. A sender supplying neither keeps the old `uuid4()`
behaviour unchanged.

Re-using an identity with different content returns **HTTP 409** naming the
differing fields, and the stored event is not modified. The response
separates `stored_records` from `accepted_records`, so a retry no longer
reports rows it did not write.

See ADR-050 for the canonical conflict policy, the fields excluded from it
and why, and the measured batch-key boundaries.

### The guarantee, and its edges

Not exactly-once delivery. For a sender supplying identity, redelivery
stores at most one copy and a conflicting redelivery is refused. For a
legacy sender it still duplicates — closing that would require content
equality, which would collapse distinct events that merely look alike.

A batch key binds `(key, index)`, not the batch: a **shorter** retry is
accepted and the dropped tail is not detected. Binding the whole batch
needs a sender-supplied digest, which is a protocol change requiring sender
coordination.

### What this changes about priority

§5's claim that duplicate delivery is solved now holds for the collector,
the research importer **and** identity-bearing stream senders. The
remaining item in §5 is replay protection (no nonce, no timestamp window),
which inserts nothing and so stays low priority.

Next: **§3 enrollment with issued identity** — partly addressed in Phase 4
(below).

---

## Phase 4 outcome (implemented)

### §3 source identity — **enforcement implemented, issuance unchanged**

The credential model in §3's table was already real. What was missing was
that nothing applied it to ingestion: every write path trusted the request
body's `source_id`, so a valid credential for one sensor could file
telemetry — and occupy the idempotency namespace — of any other.

`resolve_ingest_source` is now the single ingestion trust boundary, applied
to all six write paths. See ADR-051 for the decision table, the audit-log
bypass found alongside it, and the residual risks.

Unchanged from §3's table, and still outstanding:

| Property | Status |
|---|---|
| Credential issuance | **Still offline CLI only**, deliberately — see ADR-051 |
| Expiry / rotation / revocation list | **Still not implemented** |
| `source_id` uniqueness across machines | **Still not enforced** |

### What this does not give

Not cryptographic source authenticity. Bearer tokens are replayable by
anyone who observes them, PraHari does not terminate TLS, and central mode
must therefore sit behind HTTPS. A stolen sensor credential still writes
freely as that sensor.

### Next

**Credential lifecycle (§3 items 2–4): expiry, rotation with an overlap
window, and revocation that takes effect without a file edit.** It is now
the weakest link: the boundary is enforced, but a leaked credential is valid
until an operator edits a file and restarts.
