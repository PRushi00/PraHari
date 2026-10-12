# Application-Layer Visibility — Design, Trade-offs and Status

**Status:** receiving half implemented and tested; **disabled by default**.
No producer is bundled, and none will be installed without explicit approval.

---

## 1. What the question actually is

PraHari's live source is the Windows TCP connection table. It observes that
a connection to `142.250.190.46:443` exists, owned by `msedge`. It cannot
observe:

- which hostname the application asked for,
- the HTTP method or path,
- the response status,
- request timing or size.

None of that is recoverable from TCP metadata. A destination port is a
convention, not evidence: port 443 does not prove HTTPS was spoken, and an
HTTP status code is an application-layer value that has no TCP equivalent.

Getting that detail requires observing the application layer itself, which
is a materially different undertaking with real privacy and trust costs.

---

## 2. Options evaluated

### Option A — Browser extension (recommended if pursued)

A WebExtension using `chrome.webRequest` / `browser.webRequest` observes
requests the browser makes and POSTs metadata to PraHari.

| | |
|---|---|
| **Sees** | Method, full URL, status, timing, initiator, resource type — for the instrumented browser only |
| **Privileges** | None beyond installing an extension. No admin, no driver |
| **TLS** | Not decrypted. The browser already has the plaintext; nothing is intercepted |
| **Certificates** | None installed |
| **System changes** | None. No proxy, no routes, no firewall rules |
| **Coverage** | Only that browser. Not other applications, not background services |
| **Privacy exposure** | High: full URLs including search queries and tokens |
| **Reversibility** | Uninstall the extension |
| **Effort** | Moderate — a small extension plus a build/load step |

**Why this is preferred:** it is the only option that needs no privilege
escalation, no TLS interception and no system configuration change, and it
is trivially reversible.

### Option B — Local inspection proxy (mitmproxy / Fiddler style)

A local proxy terminates TLS and re-originates it, logging requests.

| | |
|---|---|
| **Sees** | Everything through the proxy, across applications |
| **Privileges** | Elevated for system-wide proxy settings |
| **TLS** | **Decrypted.** This is the decisive objection |
| **Certificates** | Requires installing a root CA into the trust store |
| **System changes** | Proxy settings, possibly firewall rules |
| **Coverage** | Broad, but breaks certificate-pinned applications |
| **Privacy exposure** | Very high: plaintext of all traffic, including banking and authentication flows |
| **Reversibility** | Must remove the CA *and* the proxy configuration; a forgotten root CA is a lasting weakness |
| **Effort** | High, plus ongoing breakage |

**Why this is not recommended:** installing a root CA makes the machine
permanently vulnerable to anyone who obtains that key, and the capability it
buys — HTTP metadata — does not justify weakening the host's trust store.

### Option C — Windows ETW HTTP providers

| | |
|---|---|
| **Privileges** | Administrator required |
| **Coverage** | Mostly WinHTTP/WinINet; modern browsers use their own stacks |
| **Verdict** | High cost, poor coverage for the traffic of interest |

### Option D — Packet capture (npcap + TLS SNI extraction)

Recovers the requested hostname from the TLS ClientHello without decryption.

| | |
|---|---|
| **Privileges** | Driver installation and elevation |
| **Sees** | SNI hostname only — no method, path or status |
| **Limitation** | Encrypted Client Hello (ECH) is rolling out and hides SNI |
| **Verdict** | Driver installation for hostname-only visibility; defer |

---

## 3. What is implemented

The **receiving half of Option A**, which needs no privileges and changes
nothing on the host:

- `POST /api/v1/applayer/ingest` accepts HTTP request metadata.
- `GET /api/v1/applayer/status` reports whether it is enabled and on what terms.
- Records normalize into the canonical schema as `event_type=http_request`
  with `source_type=application_layer`, so their provenance is distinct from
  connection telemetry.
- The source capability profile marks `http_*` as supported for this source
  and `unsupported_by_source` for every other, so the UI can only show HTTP
  fields when a genuine app-layer source supplied them.

### Enabling it

```bash
PRAHARI_ENABLE_APPLICATION_LAYER_INGEST=true
```

Enabling the endpoint captures nothing by itself. A producer must exist, and
building or installing one is a separate decision for the operator.

### Privacy controls

- The payload schema has **no field** for bodies, headers, cookies,
  authorization or credentials, and unknown fields are rejected (HTTP 422) —
  so a misconfigured producer fails loudly rather than having secrets
  silently discarded.
- Query strings are **stripped** by default (`?q=...` is removed), because
  they routinely carry search terms, session identifiers and tokens. Opt in
  with `PRAHARI_APPLAYER_RETAIN_QUERY_STRINGS=true`.
- An app-layer source may not reuse the connection collector's source id, so
  the two can never be conflated.
- Records are deterministically keyed, so a producer retrying a batch cannot
  duplicate data.

---

## 4. What is deliberately not implemented

PraHari does **not**, and will not without explicit approval:

- configure a system or browser proxy,
- install or trust a root certificate,
- decrypt TLS,
- change browser security settings,
- install packet-capture drivers or start packet capture,
- request elevated privileges,
- modify firewall rules, routes, interfaces or DNS configuration.

---

## 5. Implementing a producer (sketch)

A minimal Chrome/Edge extension:

```js
// background.js — metadata only; never bodies, headers or cookies.
const pending = new Map();

chrome.webRequest.onBeforeRequest.addListener(
  (d) => { pending.set(d.requestId, { started: d.timeStamp, method: d.method, url: d.url }); },
  { urls: ["<all_urls>"] }
);

chrome.webRequest.onCompleted.addListener((d) => {
  const start = pending.get(d.requestId);
  pending.delete(d.requestId);
  fetch("http://127.0.0.1:8000/api/v1/applayer/ingest", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      source_id: "browser_probe",
      producer: "browser-extension",
      records: [{
        observed_at: new Date(d.timeStamp).toISOString(),
        method: d.method,
        url: d.url,                       // query string stripped server-side
        status_code: d.statusCode,
        duration_ms: start ? d.timeStamp - start.started : null,
        dst_ip: d.ip || null,
        dst_port: d.url.startsWith("https://") ? 443 : 80,
      }],
    }),
  }).catch(() => {});                      // never disrupt browsing
}, { urls: ["<all_urls>"] });
```

Batch records before sending in anything beyond a prototype.

### Correlating with connection telemetry

Once both sources are present, an HTTP record and a TCP connection can be
related when they share a destination IP, destination port and a close
timestamp. That correlation is **probabilistic** — connection reuse and
HTTP/2 multiplexing mean several requests share one connection — so it
should be surfaced with a confidence value, exactly as hostname attribution
is, rather than asserted as a fact.

---

## 6. Current state

| Capability | Status |
|---|---|
| HTTP metadata schema and storage | Implemented |
| Ingestion endpoint with privacy controls | Implemented, disabled by default |
| Capability-aware UI (HTTP shown only when genuinely sourced) | Implemented |
| Producer (extension or proxy) | **Not implemented** — requires operator decision |
| TLS interception | **Will not implement** without explicit approval |
| Live HTTP data in this deployment | **None.** No producer is configured |

Until a producer exists, the dashboard shows application-layer fields as
"not observed", which is the truthful state.
