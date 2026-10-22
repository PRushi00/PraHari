# PraHari — Ingestion Operational Acceptance (§16)

Blueprint §16 requires that, **before claiming a supported live
integration**, an operator record the measured event rate, ingestion and
processing delay, queue behaviour, dropped or rejected records, reconnect
behaviour, resource consumption, and the duration and environment of the
test. Nothing had measured any of it. This is that measurement.

**Reproduce:** `python scripts/benchmark_ingestion.py --url <server>
--batches N --batch-size M --concurrency C`

---

## What this is, and is not

It is a **load measurement of one machine**, over loopback, with
synthetic records, against a throwaway SQLite file.

It is **not a service target**. §16 is explicit that numerical targets
are agreed only *after* measurement, and no figure here is published as a
promise. It says nothing about a deployment on other hardware, over a
network, or against PostgreSQL.

It is **not a measurement of any real sensor**. The records are generated
by the benchmark, so this measures PraHari's ingestion path. The
reconnect probe is a deliberate connection failure against a closed port,
which exercises the client's retry rather than a sensor's.

## Environment

| | |
|---|---|
| Platform | `Linux-6.18.44-fc-v139-x86_64-with-glibc2.39` |
| Python | 3.13.16 |
| CPUs | 4 |
| Storage backend | sqlite (throwaway file) |
| Transport | loopback HTTP, no TLS |
| Admission capacity | 8 concurrent, **no queue** |

## Scenario A — steady state (concurrency 4, below capacity 8)

| Measure | Value |
|---|---|
| Records offered | 10,000 in 40 batches of 250 |
| Duration | **1.92 s** |
| Event rate | **7105.7 records/s** |
| HTTP statuses | `{'200': 40}` |
| Stored | **10000** · rejected 0 · duplicate 0 |
| Request latency (client) | p50 **120.897 ms** · p95 429.347 ms · p99 1070.947 ms · max 1070.947 ms |
| Processing latency (server) | p50 49.4 ms · p95 183.832 ms · max 724.122 ms |
| Admitted / refused | 40 / 0 |
| Queue depth | `null` — there is no queue |

**Client and server reconcile exactly:** the client counted
10000 stored and the server's own counter moved by 10000.
That reconciliation is the point of the measurement; a figure that only
one side agreed with would not be evidence.

## Scenario B — saturation (concurrency 24, three times capacity)

| Measure | Value |
|---|---|
| Records offered | 12,000 in 60 batches of 200 |
| Duration | **0.623 s** |
| HTTP statuses | `{'200': 8, '503': 52}` |
| Admitted | **8** |
| **Refused for overload (503)** | **52** |
| Stored | **1600** (= admitted batches x 200), reconciling with the server |
| Request latency (client) | p50 73.21 ms · p95 444.118 ms · p99 543.433 ms |

This is the behaviour §6 and `services/admission.py` describe, measured
rather than asserted: **over capacity, work is refused immediately with
503 and nothing is buffered.** No record was silently dropped — every
offered record is accounted for as either stored or refused. A system
that queued here would show rising latency and a growing backlog; this
one shows a hard edge, which is the deliberate design.

## Reconnect behaviour

| Probe | Result |
|---|---|
| Request to a closed port | refused immediately (`URLError`) |
| Live endpoint afterwards | recovered, HTTP 200 |

The client surfaces a connection failure rather than hanging, and a
failed connection does not poison the next one.

## Dropped and rejected records

Zero records were dropped in either scenario. The distinction the
benchmark keeps, and §16 needs:

* **rejected** — a record the adapter refused (0 here);
* **duplicate** — a record already stored, deduplicated by deterministic
  identity. This is correct behaviour, never counted as a failure;
* **refused for overload** — a whole batch declined at admission, which
  the sender must retry. Nothing is lost, but nothing is stored either.

An earlier run of this benchmark reported "0 stored" with a throughput
figure of 52,000 records/s, because every request was malformed and
returned 422. The script now fails loudly when nothing was stored *and*
nothing was deliberately refused, since a rate computed over failed
requests is exactly the fabricated measurement this project refuses.

## Resource consumption

Sampled from the **server** process every 50 ms while the load ran — not
from the benchmark process, which would measure the wrong thing.

| | Steady state | Saturation |
|---|---|---|
| Samples | 38 | 16 |
| RSS at start | 180.4 MB | 191.0 MB |
| RSS peak | **190.2 MB** | **203.3 MB** |
| RSS growth over the run | 9.8 MB | 12.4 MB |
| CPU peak | 138.5 % | 119.1 % |
| CPU mean while busy | 95.4 % | 91.2 % |

CPU can exceed 100 % because the host has several cores. **The growth
figures are not evidence about a leak**: each run lasts a second or two,
and an allocator that has not returned memory to the OS looks identical
to one that is retaining it. A leak claim needs a sustained run, which
this is not.

`psutil` is **not** a runtime dependency of PraHari and was not made one
— §9.2 prefers small dependencies until a measured need justifies more,
and this need is a verification tool's, not the application's. Without
it the report states `available: false` **with the reason**, rather than
omitting the section or estimating a figure:

```json
{"available": false, "reason": "psutil is not installed, so resource
use was not sampled. Install it (pip install psutil) and re-run."}
```

To measure it: `pip install psutil`, then re-run.

---

## PostgreSQL — the same two scenarios

The first revision of this report listed "No PostgreSQL run" as its
largest gap, noting that **the storage backend is the most likely thing
to change these numbers**. It was. Both scenarios were re-run against a
real PostgreSQL 16.15 server (ADR-116).

| | |
|---|---|
| Platform | `Linux-6.18.44-fc-v140-x86_64-with-glibc2.39` |
| Server | PostgreSQL 16.15 (Ubuntu), a throwaway cluster, schema `bench` |
| Transport | loopback HTTP to the app; loopback TCP to the database |
| Everything else | identical to the SQLite runs |

### Steady state (concurrency 4, below capacity 8)

| Measure | SQLite | **PostgreSQL** |
|---|---|---|
| Records offered | 10,000 | 10,000 |
| Duration | 1.92 s | **4.06 s** |
| Event rate | 7105.7 rec/s | **2460.4 rec/s** |
| Request latency p50 | 120.9 ms | **404.4 ms** |
| Request latency p95 | 429.3 ms | **475.5 ms** |
| Request latency p99 | 1070.9 ms | **508.3 ms** |
| Stored / rejected / duplicate | 10000 / 0 / 0 | **10000 / 0 / 0** |
| RSS peak | 190.2 MB | **196.6 MB** |
| CPU mean while busy | 95.4 % | **107.0 %** |

**PostgreSQL ingests at roughly 35 % of SQLite's rate here** — 2.9x
slower on the same machine, same records, same code. That is the
headline, and it is the reason the SQLite figures must never be quoted
as PraHari's throughput.

The *tail* moves the other way: p99 is **508 ms on PostgreSQL against
1071 ms on SQLite**. SQLite's higher mean rate comes with a worse worst
case, which is consistent with a single writer serialising behind a
lock, and it is why the distribution is reported rather than an average.

### Saturation (concurrency 24, three times capacity)

| Measure | SQLite | **PostgreSQL** |
|---|---|---|
| HTTP statuses | `{200: 8, 503: 52}` | **`{200: 8, 503: 52}`** |
| Admitted / refused | 8 / 52 | **8 / 52** |
| Stored | 1600 | **1600** |
| Queue depth | `null` | **`null`** |

**Identical, to the record.** The refusal boundary is a property of
admission control (`services/admission.py`), not of the storage backend:
it caps concurrent in-flight work, so it refuses at the same point
whatever is underneath. The slower backend did not push *more* work into
refusal, because admission counts requests in flight rather than time
spent.

### Verified from outside the application

The application's own counters said 11,600 records were stored across
both runs. Asked directly, the database said **11,620**:

```sql
SELECT count(*) FROM bench.normalized_events;  -- 11620
```

The difference is exactly accounted for: the reconnect probe's recovery
check posts a 10-record batch to the live endpoint after the counters
are read, once per run (`scripts/benchmark_ingestion.py`). 10,000 +
1,600 + 2x10 = **11,620**.

That cross-check is the point. A throughput figure taken only from the
process that produced the load is a claim about that process; a count
read out of the database by a different client is evidence that the rows
exist.

---

## What this does not establish

* **No tuning of either backend.** PostgreSQL ran on `initdb` defaults
  on the same host as the application. A deployment would separate them
  and tune `shared_buffers`, `synchronous_commit` and the WAL — any of
  which could move the 2460 rec/s figure substantially in either
  direction. It is a floor measured on defaults, not a ceiling.
* **No network.** Loopback removes the transport that a real sensor
  would cross.
* **No sustained run.** Both scenarios last a second or two, which is why the memory-growth figures are reported but not interpreted. Behaviour over
  hours — file growth, WAL checkpointing, memory drift — is unmeasured.
* **`peak_in_flight` is a process-lifetime high-water mark**, not a
  per-run figure, and is labelled as such in the JSON.
