# PraHari Local Telemetry Probe (optional browser extension)

Reports HTTP request **metadata** from one browser profile to your local
PraHari instance, so the dashboard can show what the Windows TCP connection
table structurally cannot: request method, response status, hostname and
timing.

**Installing this is your decision.** PraHari does not install it, does not
enable it, and works fully without it.

---

## Status

| | |
|---|---|
| Extension source | **Implemented** (`manifest.json`, `background.js`, `popup.html`, `popup.js`) |
| Backend ingestion contract | **Implemented and verified** — 12 automated tests |
| End-to-end with a **simulated** producer | **Verified** — `scripts/simulate_browser_producer.py` |
| End-to-end from a **real browser** | **NOT VERIFIED** — requires you to install it |

The simulated verifier posts the exact envelope `background.js` builds, so
the contract is proven. It does **not** prove a real browser produces that
data. Until you install the extension and confirm, PraHari shows HTTP as
not observed.

---

## What it collects

**Only this, per request:**

| Field | Example |
|---|---|
| Timestamp | `2026-10-12T09:00:00Z` |
| Method | `GET` |
| URL origin + path (**no query string**) | `https://docs.example.com/guide` |
| Status code *(only if the browser reported one)* | `200` |
| Duration | `142` ms |
| Destination IP / port | `93.184.216.34` / `443` |

**It never collects:** request or response bodies · cookies · authorization
or any other headers · credentials or tokens · form fields · **query
strings** (discarded in the browser, before transmission) · page content ·
search terms · other browser profiles · other applications.

**It never:** installs a certificate · intercepts TLS · configures a proxy ·
changes network settings · requires administrator privileges · contacts any
host other than your local PraHari endpoint.

A failed request carries **no HTTP status**. It is reported with a null
status and shown as *"no response"* — never as a fabricated code.

---

## Install (Chrome / Edge)

1. **Enable ingestion** in PraHari and restart it:

```bash
set PRAHARI_ENABLE_APPLICATION_LAYER_INGEST=true
```

2. Open `chrome://extensions` (or `edge://extensions`).
3. Turn on **Developer mode**.
4. Click **Load unpacked** and select this `extension/` folder.
5. Click the extension icon, then **Start collection**. It is **off** until
   you do this.
6. The browser will ask for permission to observe sites. That permission is
   *optional* in the manifest — you grant it explicitly and can revoke it at
   any time from the extensions page.
7. Browse normally, then open PraHari → **Live Telemetry** →
   **Application-Layer Telemetry**.

### Firefox

The manifest is MV3 and uses `chrome.*` APIs. Firefox needs a `browser.*`
shim and a `browser_specific_settings` block; not currently provided.

---

## Stopping and removing

- **Stop**: click the icon → **Stop collection**. Queued records that have
  not been sent are discarded immediately.
- **Remove**: remove it from `chrome://extensions`.
- **Delete collected data**: the records live only in your local PraHari
  SQLite database under source id `browser_probe`.

---

## Verifying it works

With PraHari running and ingestion enabled:

```bash
python scripts/simulate_browser_producer.py
```

That exercises the contract with simulated records. To confirm a **real**
browser is reporting, install the extension, start collection, load a page,
then check that **Application-Layer Telemetry** lists it with source id
`browser_probe` (the simulator uses `browser_probe_simulated`, so the two
are never confused).

---

## Honest limits

- Covers **only the browser profile** it is installed in — not other
  browsers, not other applications, not system traffic.
- `chrome.webRequest` is observational here; the extension requests no
  blocking permission and cannot modify traffic.
- Some responses (served from cache, or aborted) produce no status code.
- HTTP/3 and QUIC requests are reported by the browser, but PraHari's
  connection collector reads only the **TCP** table, so those will not have
  a matching connection record.
- Correlating an HTTP transaction to a specific TCP connection is
  **probabilistic** — connection reuse and HTTP/2 multiplexing mean many
  requests share one connection. PraHari therefore keeps them as separate
  records and does not assert a correlation it cannot defend.
