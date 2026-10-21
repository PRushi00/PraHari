# PraHari — Troubleshooting and Failure Handling

Blueprint **§15** asks for a fifteen-row table of *symptom → investigate
first → safe response*. `docs/BLUEPRINT_COVERAGE.md` carried §15 as
`ABSENT as a guide`: the behaviour largely existed — the research gate
refuses, reports state their limitations, counters reconcile — but an
operator who hit "suspiciously perfect metrics" had nowhere to look, even
though this project has produced exactly that twice and diagnosed it both
times. Those diagnoses lived only in `DECISIONS.md`. This guide moves them
where an operator will find them.

**Written 21 Oct 2026 against `ccr-58caddbd-1gv7jn` at 7ad866e, on
Windows 11, Python 3.12.10.** Every row cites the ADR that recorded the
real diagnosis, and every behavioural claim was read in the source or
executed. Where a row was executed, the numbers are given.

Rows 7 and 13 cover the two defects this revision **fixes** (ADR-100 and
ADR-099). Both were reproduced on Windows against the previous revision
and re-tested against this one, so each row carries a before and an
after. They are kept in the table because an operator on an older build
will still meet them, and because the ADR-099 case leaves data that
cannot be repaired afterwards.

Two conventions run through the whole table:

* **Read the counters before restarting anything.** PraHari's ingestion
  accounting reconciles exactly:
  `records_observed_total` = `events_persisted_total` +
  `duplicates_suppressed_total` + `records_filtered_by_policy_total` +
  `records_rejected_total`. Checked against a live Windows collector over
  35 polls while writing this guide —
  `observed=3590 persisted=144 duplicates=1865 filtered=1581 rejected=0`,
  and `144 + 1865 + 1581 + 0 = 3590`. A restart destroys the evidence
  that tells you which of several indistinguishable causes you have.
* **A refusal is usually the answer, not the fault.** The research gate,
  the event-level report and the admission controller all refuse rather
  than return a confident number over inadequate evidence. Satisfy what
  the refusal names; do not relax it. ADR-095 declined to reclassify a
  quality flag immediately after that flag blocked a run, because
  revising a judgement to change the verdict it produced is result-driven
  tuning.

No row in this guide asks you to change a route, a firewall rule or an
interface. PraHari contains no such code path (§18 criterion 14), and
troubleshooting it never requires one.

---

## The table

| # | Symptom | Investigate first | Safe response |
|---|---|---|---|
| 1 | No live events appearing | `GET /api/v1/collector/status` — `state`, `platform_supported`, and all five accounting counters | Read the counters before restarting. High `records_filtered_by_policy_total` is policy, not fault (ADR-083) |
| 2 | Collector reports `state=unsupported` | `platform_supported` and `platform_name` in the same response | Nothing to fix: the collector refused rather than run a Windows query off Windows. `POST /collector/start` answers 501 (ADR-075) |
| 3 | Queue grows continuously | `GET /api/v1/system/health` → `queue_depth`, `admission_model` | Cannot occur: PraHari has no queue. `queue_depth` is `null` by design, never 0 |
| 4 | Model predicts nearly all negatives | The constant baseline's score on the same split | Compare before touching the model. On this corpus near-all-negative is close to the best the data supports (ADR-096) |
| 5 | Suspiciously perfect metrics | `POST /api/v1/forecast/event-level`, and `alarm_duty_cycle` | Never read a window-level figure as a forecasting claim. This project hit this twice (ADR-091, ADR-096) |
| 6 | Implausibly long lead time | The matching-rules fingerprint returned beside the result | Lead time's origin is the first attack-*labelled* record, not compromise. Do not widen L/H (ADR-091) |
| 7 | Event counts disagree between two endpoints, or the label breakdown shows no attacks | Whether this build has `event_breakdown()`; otherwise the store's own `count_events(label=…)` | Fixed in this revision (ADR-100). On an older build the breakdowns are the newest 1000 events only, and can report **zero attacks** while attacks are stored |
| 8 | A source shows `stale` or `silent` | `GET /api/v1/sources/health`, then `GET /api/v1/sources/clock-integrity` | Never read `silent` as "the host is down". PraHari has no heartbeat |
| 9 | Ingestion counters read zero while events exist | `records_observed_total` vs `duplicates_suppressed_total` vs `events_persisted_total` | Observed high, persisted 0, duplicates high means inherited adapter state, not a storage fault (ADR-083) |
| 10 | Training refused by the research gate | The 409 body: `readiness_state`, `unmet_requirements`, `next_steps` | Satisfy the named requirement. Do not relax a threshold after seeing a result (ADR-095) |
| 11 | Readiness says the dataset is too short, or a split reports "0 positive" | Whether the figure is a store measurement or a 50,000-row sample | The readiness report states which. A sample ordered `observed_at DESC` is the corpus *tail* (ADR-095) |
| 12 | No network-level (NetFlow) events ever appear | Nothing — no live flow collector exists | By decision, not fault. Acceptance matrix row 3 names the prerequisite (ADR-072) |
| 13 | Two machines' telemetry is indistinguishable | `GET /api/v1/collector/status` → `source_id` on each host, and the startup log line | Set `PRAHARI_COLLECTOR_SOURCE_ID` per host **before** their data is brought together. Events already collected under one id cannot be told apart afterwards (ADR-099) |
| 14 | Every row of an import is rejected | The declared import policy against the file's actual header | Declare the columns the file has. Rejecting every row states a whole-file fact one row at a time (ADR-096) |
| 15 | Ingest returns 503, or latency climbs | `in_flight`, `peak_in_flight`, `capacity`, latency percentiles | A 503 is durability being protected, not data lost. The sensor agent retries with backoff (ADR-073) |

---

## The rows in detail

### 1 · No live events appearing

`GET /api/v1/collector/status` carries everything needed to separate the
causes, and a restart erases it.

Three distinct conditions look identical from the dashboard:

* **The collector never started.** `state` is `stopped`, and
  `polls_attempted` is 0.
* **It is polling, and most records are excluded on purpose.**
  `records_filtered_by_policy_total` counts connections deliberately out
  of scope — loopback is off unless `include_loopback` is set, and only
  the TCP states in `collected_tcp_states` are collected. These are
  **not** rejections; counting them as rejected would overstate
  data-quality problems. Executed on this host, one poll reported
  `observed=110 accepted=63 filtered=47`, and over eleven polls
  `records_observed_total=1066` against `events_persisted_total=75` with
  `duplicates_suppressed_total=538` — a quiet desktop whose connection
  table is mostly the same long-lived sockets re-observed.
* **It is polling and persisting nothing.** See row 9.

**Safe response.** Record the counters, then `POST /api/v1/collector/poll`
for exactly one synchronous poll and compare. Do not restart the process
first.

### 2 · Collector reports `state=unsupported`

`default_host_query_fn` in `app/services/collector.py` selects the host
query at construction, not import. On an unsupported platform the Windows
function is returned and `platform_supported` is `False`, so the collector
**refuses to start rather than calling it**. Both
`POST /api/v1/collector/start` and `POST /api/v1/collector/poll` answer
`501` naming the platform, and `status()` reports `unsupported` rather
than `stopped`, so the state is not mistaken for an operator choice.

Do not confuse two different 503s: a *failed poll* answers
`503 Collection poll failed: <error>`, which is about this host's
connection table. The 503 in row 15 is admission control refusing new
ingestion work. They share a status code and nothing else.

On Linux a `/proc/net/tcp` reader exists and has been run against the live
table by test, but no collector is started (ADR-075).

**Safe response.** Nothing. This is a refusal, and it is correct.

### 3 · Queue grows continuously

**This symptom cannot occur.** PraHari has no ingestion queue, and says so
in the response rather than reporting a reassuring zero.

`app/services/admission.py` is admission control, not a queue:
`DEFAULT_MAX_WAIT_SECONDS = 0.0`, so a request over capacity is **rejected
immediately with 503**, never buffered. Answering a request before the
data is durable is the thing a queue would require, and that is what was
declined. `GET /api/v1/system/health` therefore reports, under
`ingestion.data` (not at the top level):

```
"admission_model":   "bounded_concurrency_no_queue",
"queue_depth":       null,
"queue_depth_note":  "Ingestion is synchronous: a request is parsed,
                      stored and answered in the handler, so no queue
                      exists. Bounding is applied by capping concurrent
                      in-flight work instead. null means 'no queue',
                      not 'an empty queue'."
```

Read live from a running instance while writing this guide.

**Safe response.** A `null` here is not a broken gauge — a `0` would be
the lie. If you are seeing refusals, that is row 15.

### 4 · Model predicts nearly all negatives

Check what the trivial baselines score on the same split before changing
anything about the model.

On Thursday 15 Feb of CSE-CIC-IDS2018 at the 0.5 split (ADR-096), with one
genuine attack onset in the holdout:

| Model | PR-AUC |
|---|---|
| `baseline_constant` | 0.3115 |
| LSTM | 0.3387 |
| Temporal stack | 0.2259 |
| Random forest | 0.2112 |
| `baseline_persistence` | 0.9420 |

A model that predicts almost nothing but negatives is scoring barely above
a constant — and the blueprint's own rule applies: a model that cannot
beat the trivial baseline has demonstrated nothing. Persistence stays
strong because **detection** is what this data supports, not forecasting.

**Safe response.** Do not rebalance classes or retune to lift the number.
Establish first whether the holdout contains an attack *onset* at all
(row 5); a holdout of pure continuations or a single class makes the
question unanswerable rather than the model bad.

### 5 · Suspiciously perfect metrics

This project has produced this twice, and both diagnoses were the same
shape: the metric was real, and the *question it answered* was not the one
being asked.

**Window recall 1.000 while warning nothing (ADR-091).** On a trained
holdout the rate-threshold baseline scored a window-level recall of
**1.000** while warning **0 of 3 events**. It flags every window, so
warning suppression collapses its permanent alarm into a single warning —
which then reads as "1 false alarm", i.e. as a *quiet, precise* model.
`alarm_duty_cycle` is reported beside the warning count for exactly this
reason, and leads the limitations above 50 %.

**PR-AUC 0.9925 measuring continuation (ADR-096).** At the 0.6 split the
LSTM scored **0.9925** — and the event-level evaluation **refused**: all
five documented onsets preceded the holdout, so no evaluated window could
have warned for any of them. The 131 positive test windows were
continuations of an attack that began during training. The figure measures
"an attack is ongoing", not "an attack is coming". Moving the split to 0.5
to obtain genuine event-level coverage made every headline number worse —
which is why both runs are reported.

**Safe response.** Run `POST /api/v1/forecast/event-level`. With no
documented event in reach it **refuses** rather than returning a perfect
score over nothing, and that refusal is the finding. Then read
`alarm_duty_cycle`, and check where the split falls relative to the
onsets. A window-level figure is never a forecasting claim.

### 6 · Implausibly long lead time

A lead time is only meaningful beside the rules that produced it, so
`MatchingRules` is returned with every result and SHA-256 fingerprinted
(ADR-091).

The usual cause is the **time origin**. A documented event's origin is the
first attack-labelled record — explicitly *not* scenario start, not first
malicious action, not compromise (the target's own `NOT_EQUIVALENT_TO`). A
lead time therefore inherits whatever delay the labelling rule carries, and
the limitations say so. A label that fires late makes the lead time look
long.

Also check: quartiles are **refused** below four warned events, so a long
median over two warnings will not be reported at all.

**Safe response.** Compare the rules fingerprint between the two runs you
are contrasting; if it differs, the numbers are not comparable. Do **not**
widen the qualifying bounds — L and H come from the target's own lead and
horizon, not from new parameters, precisely so matching cannot be widened
until the numbers improve.

### 7 · Event counts disagree between two endpoints

**Fixed in this revision (ADR-100), and verified on Windows both ways.**

Before, `GET /api/v1/events/stats/summary` took its total from the store
but its three breakdowns from a capped sample:

```python
total  = db.count_events()
sample = db.list_events(limit=1000)      # <- the defect
```

Past 1000 stored events the total described every event while the
breakdowns beside it described only the newest thousand, and nothing in
the response said which was which. The dangerous form is not a mismatched
sum — it is a **silently empty label breakdown**: ADR-100 reproduced a
store of 1,200 events whose oldest 150 were attack-labelled reporting
`total_events: 1200`, a breakdown summing to 1,000, and **zero attacks**.
This is ADR-095's defect in a second place, where a 50,000-row sample of
a real corpus was the day's tail and readiness reported "0 positive" for
52,498 attack-labelled events.

It is reached in ordinary use. A Windows collector under observation
reached 699 events in 22 minutes of 15-second polling, so a working
afternoon crosses the cap.

Now the endpoint calls `db.event_breakdown()` — three GROUP BYs in the
storage contract, implemented by both backends. The response shape is
unchanged; only the values become complete.

Measured on Windows against two byte-identical seeded stores of 1,250
events, one served by this revision and one by its parent:

```
--- FIXED (7ad866e) ---                --- UNFIXED (parent) ---
total_events          : 1250           total_events          : 1250
sum(labels)           : 1250  True     sum(labels)           : 1000  False
sum(event_types)      : 1250  True     sum(event_types)      : 1000  False
sum(data_categories)  : 1250  True     sum(data_categories)  : 1000  False
```

**Below the cap even the old code is exactly right**, which is why this
survived. A live Windows instance on the parent revision holding 416
events reported all three breakdowns summing to 416.

**Safe response.** On this revision or later, the breakdowns are
measured; trust them. On an older build, trust `total_events` and the
`total` field of `GET /api/v1/events`, and get per-label counts from
`count_events(label=…)` rather than from the summary — above all do not
read an empty `labels` breakdown as "no attacks stored".

### 8 · A source shows `stale` or `silent`

`GET /api/v1/sources/health`. Defaults are deliberately generous — fresh
300 s, stale 3600 s, both overridable per call — because calling a source
silent is an operational claim and a wrong one wastes an operator's time.

Two properties of this endpoint matter more than the verdict:

* **There is no heartbeat.** Every state describes PraHari's *evidence*,
  not the remote machine. `silent` means "no events recorded"; it never
  asserts that a host is down. A source with nothing to report is silent
  and healthy.
* **Freshness is derived from event time reported by the source.** A host
  whose clock runs fast appears fresher than it is; one whose clock runs
  slow can be reported silent while reporting normally.

**Safe response.** Check `GET /api/v1/sources/clock-integrity` before
drawing any conclusion, and read `seconds_since_last_event` beside
`seconds_since_last_receipt` — receipt time is PraHari's own clock and is
not subject to the source's.

### 9 · Ingestion counters read zero while events exist

Found on Windows by running the real collector twice in one process
(ADR-083). The process-wide adapter registry returned the
already-registered adapter for a source id, so each new collector silently
reused the previous instance's adapter — including its **deduplication
cache**. On a fresh database the live run reported:

```
records_observed=100  duplicates_suppressed=75  events_persisted=0
```

The new collector suppressed as "repeats" connections that database had
never stored. Its `include_loopback` setting was ignored in favour of the
old adapter's too.

**Investigate first.** The five counters reconcile, so their *shape*
identifies the cause: observed high, persisted zero and duplicates high
points at inherited adapter state, not at storage. Observed high with
`records_filtered_by_policy_total` high is row 1. Observed high with
`records_rejected_total` high is a data-quality problem, and
`rejection_reasons` names it.

**Safe response.** Use a fresh process for a fresh database. Never
conclude "storage is broken" from `events_persisted_total=0` alone.

### 10 · Training refused by the research gate

The refusal is designed, and it is specific. `POST /api/v1/forecast/train`
answers **409** with:

```json
{
  "error": "forecasting_blocked_by_research_gate",
  "readiness_state": "...",
  "message": "...",
  "unmet_requirements": [{"name": "...", "required": "...",
                          "observed": "...", "detail": "..."}],
  "next_steps": ["..."]
}
```

`GET /api/v1/forecast/readiness` returns the same report without
attempting training. The states are ordered by increasing readiness, from
`insufficient_data` through `missing_or_invalid_labels`,
`invalid_evaluation_conditions`, `inadequate_class_representation`,
`evaluated_performance_inadequate` and `trained_not_validated` to
`validated_with_documented_conditions`, and **the first applicable state
is reported** — so you are told the nearest blocking problem, not the last
one checked. The refusal is also written to the audit log under
`resource_type: research_gate`.

**Safe response.** Satisfy the requirement the body names. Do not relax a
threshold because it blocked you: thresholds are set before results are
seen. If the gate's figures themselves look wrong, that is row 11.

### 11 · Readiness says the dataset is too short, or a split reports "0 positive"

The gate once refused a perfectly adequate corpus with (ADR-095):

> Insufficient data: 50000 events spanning 104s. At least 200 events over
> 1800s are required.

The dataset spanned **1,859 seconds**, not 104. Three call sites judged
*dataset-level* properties from `db.list_events(limit=50_000)`, and
`list_events` orders by `observed_at DESC` — so the slice was the **most
recent** 50,000 rows, which on a real corpus covered 104 seconds. On sparse
synthetic fixtures the same slice covers hours and resembles the dataset,
which is why it survived so long. The same shape of error produced a
"0 positive" split: a selection ceiling chosen for synthetic fixtures
reduced a real corpus to its last few minutes, routinely one class.

Count and span are now measured by the store (`event_time_range`, a
`MIN`/`MAX` aggregate on both backends), and the report distinguishes what
is measured from what is sampled:

```
607785 events (label/quality read from a 50000-event sample)
```

**Safe response.** Before believing any dataset-level figure, check
whether it is a measurement or a sample — the readiness report now says.
Label and quality ratios still come from the sample, which is what a
sample can honestly give.

### 12 · No network-level (NetFlow) events ever appear

There is nothing misconfigured. **No live flow collector exists**
(ADR-072). The NetFlow adapter parses exported flow *text*; it does not
open a UDP port. One was deliberately not built: a collector exercised
only by packets this project constructs would prove the decoder agrees
with its author, not that it reads a real exporter correctly, and a UDP
listener is attack surface. No authorized exporter or observation point
exists here, so §18 criterion 3 cannot be met by code.

A related trap: the NetFlow adapter **discards labels**, so a CTU-13
`binetflow` file routed through it imports unlabelled — safe, but useless
for supervised work. CTU-13's `Background` label must not become a
negative, and no importer mapping those labels exists.

**Safe response.** Don't hunt for a listener. `docs/ACCEPTANCE_MATRIX.md`
row 3 states the prerequisite: an authorized exporter and an observation
point.

### 13 · Two machines' telemetry is indistinguishable

**Fixed in this revision (ADR-099), and verified on Windows both ways.**

Before, `DEFAULT_SOURCE_ID = "windows_local_host"` was a constant,
`StartCollectorRequest` carried only `interval_seconds`, and no
configuration field reached the collector, so every Windows host filed
telemetry under one id.

That is not just ambiguous labelling.
`WindowsConnectionAdapter.fingerprint` hashes the adapter id as its
**first** component and storage is `INSERT OR IGNORE`, so two hosts
sharing the id produce the same `event_id` for a connection matching on
protocol, addresses, ports, pid and creation time — and **the second
host's observation is silently discarded, the row attributed to the
first**.

Measured on Windows, two processes with separate databases, the same live
connection table:

```
parent revision, PRAHARI_COLLECTOR_SOURCE_ID ignored
  port 8124 source_id = windows_local_host
  port 8125 source_id = windows_local_host
  shared connections 63 -> identical event_id 63, different 0

this revision, PRAHARI_COLLECTOR_SOURCE_ID honoured
  port 8201 source_id = sussy-a
  port 8202 source_id = sussy-b
  shared connections 66 -> identical event_id 0, different 66
```

The startup log now states the identity before the database is opened —
`Host collector will file telemetry as sussy-a` — and a bad value **fails
closed at startup** rather than at the first dashboard poll:

```
PRAHARI_COLLECTOR_SOURCE_ID="Bad Id"
app.core.config.InvalidCollectorSourceId: collector_source_id 'Bad Id'
must be lowercase letters, digits, '-' or '_', and start with a letter.
ERROR:    Application startup failed. Exiting.
```

Ids are `[a-z][a-z0-9_-]*`, at most 64 characters. **Unset means the
historical default**, so an existing single-host installation keeps its
source and its stored events — this is not a migration. The
UDP-endpoint observer's id is refused, and the ADR-090 reservation guard
covers the configured id so external telemetry cannot be filed into the
live host's own source in the window between a restart and the first
status poll.

**Safe response.** Set `PRAHARI_COLLECTOR_SOURCE_ID` on each host
**before** their data is brought together. ADR-099 cannot repair data
already collected: two hosts that have already run under the default id
hold events that cannot be told apart afterwards, and the id cannot be
changed later without orphaning everything stored under it. Verify with
`GET /api/v1/collector/status` on each host and with the startup log line.

**What this does not mean.** It is not host *isolation*, and it does not
make one backend collect for several hosts — the collector is still a
process-global singleton. It makes the one-agent-per-host deployment
work. Isolation needs central ingestion with per-source credentials,
which is separate work.

### 14 · Every row of an import is rejected

Check the declared import policy against the file's actual header before
looking at the data at all.

Nine of the ten processed CSE-CIC-IDS2018 CSVs carry no `Src IP`, no
`Dst IP` and no `Flow ID` (ADR-096). The importer required both addresses,
so those nine days were rejected **row by row** — for a fact that is true
of the whole file. The cost was severe: the one day PraHari could read
held a single onset and could not support a chronological split, while
Thursday 15 Feb, with five separated onsets in one morning, was among the
nine it could not.

`address_columns` is now **declared and header-checked in both
directions**, for the same reason `timestamp_format` is: declaring columns
absent when the file has them discards real data, and declaring them
required when the file lacks them rejects everything. A **mixture** is
refused outright (`MixedAddressAvailabilityError`), because counting
distinct addresses across rows where some structurally lack them
undercounts by exactly the address-less share and nothing in the result
would show it.

**Safe response.** Declare what the file actually has, and accept the
named schema that follows — `prahari.window_features.addressless.v1` (10
features) rather than the full 12. Do **not** accept address-less rows
into the full schema and let them compute `len(set()) == 0`: "no distinct
source addresses were observed" is a claim about the traffic, and a false
one.

### 15 · Ingest returns 503, or latency climbs

`GET /api/v1/system/health` reports `in_flight`, `peak_in_flight`,
`capacity` and latency percentiles under `ingestion.data`. Over capacity
the controller refuses immediately — `Ingestion is at capacity (N/M in
flight).` — rather than buffering (row 3). On the instance used while
writing this guide, `capacity` was 8.

On the sending side the sensor agent classifies by evidence (ADR-073) and
every path is bounded:

* **503 / 429 / 5xx / timeout / unreachable** — nothing was delivered, so
  retry with backoff and keep the batch **unchanged**; never split, never
  set aside.
* **413 on a multi-event body** — the events are kept in order, and later
  multi-event bodies stay below the refused size
  (`learned_max_request_bytes`, which never rises); `batches_split`
  increments.
* **413 on a single event** — that one event is dropped, counted under
  `events_oversized` and `batches_failed_permanent`.
* **400 / 401 / 403 / 409** — the request is wrong; drop and count.
* **TLS failure or redirect** — the channel is wrong; halt and keep the
  events.

**Safe response.** Read the counters rather than inferring loss. A 503
with a retrying agent is back-pressure working; `events_oversized` is the
only counter that means an event was deliberately discarded.

---

## Symptoms that cannot occur in this codebase

Worth stating, so time is not spent looking:

* **A growing queue.** There is no queue (row 3).
* **A failing live NetFlow listener.** None exists (row 12).
* **An automatic network, route or firewall change.** No code path alters
  routes, firewall rules or interfaces, collectors are off by default, and
  no listener was built speculatively (§18 criterion 14, ADR-072).
* **A PostgreSQL URL silently reading the local SQLite file.** That was
  ADR-094's defect; `get_db` now selects the backend from the URL's
  scheme, and a URL the wiring cannot serve is refused at startup.

---

## Limitations of this guide

* Rows 7 and 13 were executed on Windows 11 against **this revision and
  its parent**, so each carries a measured before and after. Rows 1, 2, 3,
  8, 10 and 15 were read in the source and their endpoints exercised
  against a running instance. Rows 4, 5, 6, 11, 12 and 14 restate
  diagnoses recorded in `DECISIONS.md` from runs on the CSE-CIC-IDS2018
  corpus; they were not re-executed here.
* Row 7's divergence was crossed on a **seeded** store of 1,250 events,
  not on live telemetry. The live Windows instance observed while writing
  this reached 416 events in 25 minutes of 15-second polling and was still
  below the cap. The mechanism is a literal `limit=1000` and does not
  depend on how the events arrived; ADR-100 records a collector reaching
  699 events in 22 minutes, so a working afternoon crosses it.
* Row 13's two "hosts" are two processes on one machine with separate
  databases and distinct ids. That is what demonstrates per-host **event
  identity**; it is not a second machine, and it does not demonstrate host
  **isolation**, which needs central ingestion with per-source
  credentials.
* **The PostgreSQL paths behind both fixes are unexercised here.**
  `event_breakdown()` and the reservation guard are implemented for
  PostgreSQL, but no server was available, and those tests skip rather
  than pass against a mock. Everything measured above is SQLite.
* Row 12 describes an absence by decision. If a live flow collector is
  ever built, that row stops being a "cannot occur" and becomes an
  ordinary diagnostic one.
