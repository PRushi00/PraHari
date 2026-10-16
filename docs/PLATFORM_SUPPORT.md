# Platform Support and Network Sensor Deployment

What has actually been executed on which platform, and what a real network
sensor deployment would require. Blueprint items 1 and 3.

Nothing here is a projection presented as a result.

---

## 1. Platform status

| Platform | Status | Basis |
|---|---|---|
| **Windows 11** | **Verified — runtime** | 394 backend tests, 36 frontend tests, live collection, all nine pages driven in a browser, loopback central-mode run |
| **Linux (Ubuntu 26.04, Python 3.14.4, WSL2)** | **Verified — runtime** | 392 backend tests passed, 2 skipped; application started, served and shut down cleanly |
| macOS | **Not assessed** | No macOS machine available |
| Docker | **Not verified** | Docker is not installed on this host and installing it is outside the agreed boundary |

### Linux: what was actually run

A pre-existing Ubuntu 26.04 WSL2 environment was used. Dependencies were
installed into a **virtual environment under the user's home directory** —
no system packages, no `apt`, no root.

```
python: Python 3.14.4   platform: linux
392 passed, 2 skipped in 13.29s
```

The two skips are the `live_windows` tests, which require a real Windows
connection table and are correctly skipped elsewhere.

Application startup was then verified directly:

```
GET /health               -> 200  status=healthy mode=local
GET /collector/status     -> 200  state=unsupported platform=Linux 6.18.33.2-microsoft-standard-WSL2
GET /events               -> 200  total=0
GET /hostobs/capabilities -> 200  profiles=['windows_udp_endpoint', 'windows_interface_counters']
POST /hostobs/udp/poll    -> 501  unsupported_platform
GET /hostobs/interfaces   -> 501  unsupported_platform
```

The Windows-only sources refuse cleanly with 501 and a named reason; they
do not crash, and they do not pretend to work.

### Two portability defects this found

Running the suite on Linux is what exposed them. Static analysis had said
the code was portable; it was wrong.

**1. The platform gate refused injected sources.** `collector.py` gated on
`sys.platform == "win32"` before checking whether the caller had supplied
its own query function. Twelve collector tests that inject a fake query
failed on Linux with *"unavailable on platform 'linux'"*, and a genuine
alternative producer would have been refused for the same wrong reason.
The gate exists to stop the **PowerShell probe** running where there is no
Windows connection table — not to stop collection as such. It now applies
only when no source is injected, which also gave the collector API its
first Linux coverage. The real OS path is still refused off Windows, and
there is a test for that.

**2. The operational-database guards tested a substring, not the
property.** Two tests asserted the database URL contained `tmp` or `temp`.
On Linux a throwaway database under `$HOME` is isolated by any reasonable
reading, and they failed. They now assert what actually matters: the
resolved path is **not** the repository's `prahari.db`.

### What remains Windows-specific

| Component | Portable? |
|---|---|
| API, ingestion, analytics, forecasting, research gate, retention, experiments, central security | **Yes** — all verified running on Linux |
| Frontend / SPA serving | **Yes** |
| TCP connection-table collection (`Get-NetTCPConnection`) | **No** — Windows only, reports `unsupported` elsewhere |
| UDP endpoint table (`Get-NetUDPEndpoint`) | **No** — 501 elsewhere |
| Interface counters (`Get-NetAdapterStatistics`) | **No** — 501 elsewhere |
| DNS cache enrichment | **No** — Windows DNS client only |

A Linux deployment therefore runs everything except local host collection,
and says so rather than failing.

---

## 2. There is no packet-capture sensor, by design

PraHari does not capture packets, and will not. No promiscuous mode, no
capture driver, no span port, no TLS interception, no privilege elevation.

Local sources read OS tables — the same information `netstat` shows.

Consequences, stated plainly:

- No payloads, so no content inspection.
- No visibility into other hosts. A machine on a switched network sees its
  own sockets, not its neighbours'.
- Connections shorter than the poll interval can be missed entirely; gaps
  are detected and recorded rather than interpolated.
- No application-layer fields unless the optional browser producer is
  enabled, and that sees one browser, not the host.

---

## 3. What each local source can and cannot measure

| Source | Provides | Does **not** provide |
|---|---|---|
| TCP connection table | 5-tuple, TCP state, owning process, creation time | bytes, packets, flow duration, payload, app layer |
| UDP endpoint table | local address/port, owning process, creation time | **any remote peer** (UDP is connectionless), bytes, packets, duration |
| Interface counters | **real** cumulative bytes and packets, per interface | attribution to any connection, process or destination |

### Volume measurement, honestly

Interface counters are the only genuine byte and packet measurement
available on this host without packet capture. They are **interface-level
and cumulative since the adapter last reset**, so they are reported through
their own endpoint and are **never written into `normalized_events`**.

```
GET /api/v1/hostobs/interfaces
```

The payload states its own scope — `measurement_scope:
"interface_cumulative"`, `attributable_to_flow: false`,
`attributable_to_process: false` — so a consumer cannot mistake it for flow
accounting. Summing it alongside the byte counts of an imported flow
dataset would produce a number that means nothing, and the capability
profile says so.

A delta between two readings is offered where one exists. Across an adapter
reset (a decreasing counter) **no delta is derived**, because neither a
negative nor a wrapped-around positive describes anything that happened on
the wire.

### UDP endpoints are not connections

```
POST /api/v1/hostobs/udp/poll
```

Emitted as `EventType.UDP_ENDPOINT` with `dst_ip` and `dst_port` declared
**not applicable** — not missing. Windows records no peer for an
unconnected socket, so inventing one would manufacture destinations that
were never observed and corrupt every destination-based aggregation.

Verified live on this host: 41 endpoints observed, 41 normalized, 0
rejected; a second poll persisted 1 new socket and suppressed 40 repeats,
confirming deterministic identity.

---

## 4. Deploying a real network sensor

The supported route for genuine network-wide telemetry is an **existing
sensor** writing JSON, which PraHari normalizes. PraHari is the analysis
and research layer; it is not the sensor.

### Requirements the operator must satisfy first

| Requirement | Why |
|---|---|
| **Written authorization** for the network segment | Monitoring a network you do not own or administer is not a technical question. A shared or institutional network needs the owner's permission in writing |
| A **tap or mirror port**, or host-based agents | A switched network gives a sensor nothing by default |
| A host to run the sensor, with elevated privileges **there** | Capture needs them; PraHari still does not |
| A retention and access decision | Captured metadata about other people's traffic is personal data in most jurisdictions |

PraHari provides none of this automatically, and no part of it will
configure a tap, change an interface, or enable capture.

### Wiring a sensor in

**Suricata** — `suricata.yaml`, EVE output:

```yaml
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - flow
        - dns
        - http
        - alert
```

**Zeek** — load the JSON writer so `conn.log` is newline-delimited JSON:

```
redef LogAscii::use_json = T;
```

The endpoint takes a JSON body carrying the NDJSON payload as a string, so
sensor output is wrapped rather than streamed raw:

```bash
python -c "import json; print(json.dumps({'source_id':'suricata-01','ndjson_content':open('eve.json',encoding='utf-8').read(),'data_category':'historical_import'}))" > payload.json
```

```bash
curl -X POST http://127.0.0.1:8000/api/v1/stream/ingest/ndjson -H "Content-Type: application/json" --data-binary @payload.json
```

The response is an `ImportSummary` in which `accepted + rejected = total`,
with a reason recorded for every rejection. A batch is capped at 50,000
records, so a long-running sensor should be shipped in chunks.

### What the adapter guarantees

Pinned by `tests/unit/test_network_sensor_adapters.py` (21) and
`tests/integration/test_sensor_ingest_roundtrip.py` (5):

| Behaviour | Guarantee |
|---|---|
| Zeek id form | Flattened `id.orig_h` and nested `id` normalize identically |
| Zeek unset `"-"` | Stays absent. **Never** read as `0` |
| Zero measurements | `0` bytes, `0.0` seconds and port `0` are preserved as recorded values, not collapsed to "no data" |
| Timestamps | Seconds and milliseconds distinguished; non-UTC offsets converted, not truncated |
| IPv6 | Accepted |
| Suricata `dns` / `http` / `alert` | Mapped to `dns_query` / `http_request` / `alert` |
| Unknown fields | Ignored, not fatal |
| Unrecognised protocol | Passed through unchanged, not rewritten to a known one |
| Malformed record | Rejected with a reason; the rest of the batch still imports, and accepted + rejected reconciles to total |

### The label rule that matters most

**A Suricata signature is recorded as `detector_output`, never as ground
truth.**

An IDS signature is that detector's opinion. If it were stored as
`dataset_ground_truth`, a forecaster trained on it would learn to predict
*one detector's alerts* while every metric claimed it predicted attacks —
and the claim would look fully evidenced.

| Label source | Provenance recorded |
|---|---|
| `label` / `classification` (corpus states it) | `dataset_ground_truth` |
| `alert.signature` (a detector decided it) | `detector_output` + an explicit warning |
| Neither | `unlabeled` — never inferred as benign |

A corpus label takes precedence over a detector signature on the same
record. The readiness report counts detector labels — they are labels — but
reports them under `non_ground_truth_labelled_events` with a caveat shown
on the dashboard, so a verdict built on them cannot read as a verdict built
on ground truth.

The event type is kept separate from the label: a labelled flow is still a
`network_flow`.

---

## 5. Summary

| Claim | Status |
|---|---|
| Runs on Windows | **Verified at runtime** |
| Runs on Linux | **Verified at runtime** (local host collection unavailable there, and reported as such) |
| Runs on macOS | **Unknown** |
| Runs in Docker | **Unverified** — Docker not installed on this host |
| Ingests Zeek JSON | **Verified against fixtures and over HTTP**, not against a live Zeek instance |
| Ingests Suricata EVE | **Verified against fixtures and over HTTP**, not against a live Suricata instance |
| Measures bytes/packets per flow | **No** — not available from any local source. Interface-level counters only |
| Captures packets | **No, and will not** |
| Has been run against a real network sensor | **No** |
