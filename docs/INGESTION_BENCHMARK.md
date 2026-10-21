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
| Duration | **1.407 s** |
| Event rate | **7105.7 records/s** |
| HTTP statuses | `{'200': 40}` |
| Stored | **10000** · rejected 0 · duplicate 0 |
| Request latency (client) | p50 **87.864 ms** · p95 286.27 ms · p99 1287.119 ms · max 1287.119 ms |
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

Not instrumented. The benchmark records CPU count and platform but does
not sample process memory or CPU during the run, so §16's
resource-consumption item is **recorded as unmeasured** rather than
estimated.

## What this does not establish

* **No PostgreSQL run.** SQLite only; the storage backend is the most
  likely thing to change these numbers.
* **No network.** Loopback removes the transport that a real sensor
  would cross.
* **No sustained run.** Both scenarios last seconds. Behaviour over
  hours — file growth, WAL checkpointing, memory drift — is unmeasured.
* **`peak_in_flight` is a process-lifetime high-water mark**, not a
  per-run figure, and is labelled as such in the JSON.
