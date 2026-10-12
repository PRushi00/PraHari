/**
 * PraHari Local Telemetry Probe — background service worker.
 *
 * Reports HTTP request METADATA from this browser profile to a local
 * PraHari instance so the dashboard can show what the Windows TCP
 * connection table structurally cannot: request method, response status,
 * hostname and timing.
 *
 * ── What this deliberately does NOT do ────────────────────────────
 *   • No request or response bodies.
 *   • No cookies, authorization headers or any other headers.
 *   • No credentials, tokens or form fields.
 *   • No query strings or URL fragments — the path is truncated at "?".
 *   • No page content and no search terms.
 *   • No TLS interception, no proxy, no certificate, no elevation.
 *   • Sends only to the configured local PraHari endpoint; nowhere else.
 *
 * Collection is OFF until the user turns it on, and the host permission
 * for observed sites is OPTIONAL — the browser prompts for it, and the
 * user can revoke it at any time.
 */

const DEFAULTS = {
  enabled: false,
  endpoint: "http://127.0.0.1:8000/api/v1/applayer/ingest",
  sourceId: "browser_probe",
  // Batch so a busy page does not generate one POST per request.
  flushIntervalSeconds: 10,
  maxBatch: 200,
};

/** Requests seen but not yet completed, keyed by requestId. */
const pending = new Map();
/** Completed metadata awaiting the next flush. */
let queue = [];
/** Counters surfaced in the popup so the user can see what is happening. */
let stats = { observed: 0, sent: 0, failed: 0, lastError: null, lastSentAt: null };

async function config() {
  const stored = await chrome.storage.local.get(DEFAULTS);
  return { ...DEFAULTS, ...stored };
}

/**
 * Reduce a URL to the minimum needed for connection analysis.
 * Returns the origin plus a query-free path — never the query or fragment.
 */
function minimalUrl(rawUrl) {
  try {
    const u = new URL(rawUrl);
    if (u.protocol !== "http:" && u.protocol !== "https:") return null;
    return {
      hostname: u.hostname,
      origin: u.origin,
      // Path only. Anything after "?" or "#" is discarded here, in the
      // browser, so it is never transmitted at all.
      path: u.pathname || "/",
      scheme: u.protocol.replace(":", ""),
    };
  } catch {
    return null;
  }
}

/** Never report traffic to PraHari itself — that would be a feedback loop. */
function isSelfTraffic(hostname, endpoint) {
  try {
    return hostname === new URL(endpoint).hostname;
  } catch {
    return false;
  }
}

chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    pending.set(details.requestId, {
      startedAt: details.timeStamp,
      method: details.method,
      url: details.url,
      type: details.type,
    });
    // Bound memory if a request never completes.
    if (pending.size > 5000) {
      const oldest = pending.keys().next().value;
      pending.delete(oldest);
    }
  },
  { urls: ["<all_urls>"] }
);

function record(details, statusCode, failed) {
  const start = pending.get(details.requestId);
  pending.delete(details.requestId);

  const parts = minimalUrl(details.url);
  if (!parts) return;

  config().then((cfg) => {
    if (!cfg.enabled) return;
    if (isSelfTraffic(parts.hostname, cfg.endpoint)) return;

    stats.observed += 1;
    queue.push({
      observed_at: new Date(start ? start.startedAt : details.timeStamp).toISOString(),
      method: details.method,
      // Origin + path, no query string.
      url: `${parts.origin}${parts.path}`,
      // Only a status the browser actually reported. A failed request has
      // none, and inventing one would misrepresent the outcome.
      status_code: failed ? null : statusCode ?? null,
      duration_ms:
        start && details.timeStamp > start.startedAt
          ? Math.round(details.timeStamp - start.startedAt)
          : null,
      dst_ip: details.ip || null,
      dst_port: parts.scheme === "https" ? 443 : 80,
      resource_type: details.type || null,
    });
    if (queue.length >= cfg.maxBatch) flush();
  });
}

chrome.webRequest.onCompleted.addListener(
  (d) => record(d, d.statusCode, false),
  { urls: ["<all_urls>"] }
);

// A failed request produces no HTTP status. It is still reported, with a
// null status, so the dashboard can distinguish "no response" from "200".
chrome.webRequest.onErrorOccurred.addListener(
  (d) => record(d, null, true),
  { urls: ["<all_urls>"] }
);

async function flush() {
  if (queue.length === 0) return;
  const cfg = await config();
  if (!cfg.enabled) {
    queue = [];
    return;
  }

  const batch = queue.splice(0, cfg.maxBatch);
  try {
    const res = await fetch(cfg.endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        source_id: cfg.sourceId,
        source_name: "Browser Telemetry Probe (this profile)",
        producer: "browser-extension",
        records: batch.map((r) => ({
          observed_at: r.observed_at,
          method: r.method,
          url: r.url,
          status_code: r.status_code,
          duration_ms: r.duration_ms,
          dst_ip: r.dst_ip,
          dst_port: r.dst_port,
        })),
      }),
    });
    if (!res.ok) {
      stats.failed += batch.length;
      stats.lastError = `HTTP ${res.status}`;
      return;
    }
    stats.sent += batch.length;
    stats.lastSentAt = new Date().toISOString();
    stats.lastError = null;
  } catch (err) {
    // Never disrupt browsing because the local collector is down.
    stats.failed += batch.length;
    stats.lastError = String(err && err.message ? err.message : err);
  }
}

chrome.alarms.create("prahari-flush", { periodInMinutes: DEFAULTS.flushIntervalSeconds / 60 });
chrome.alarms.onAlarm.addListener((a) => {
  if (a.name === "prahari-flush") flush();
});

// Popup control surface.
chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg?.type === "getState") {
    config().then((cfg) =>
      sendResponse({ ...cfg, stats, queued: queue.length, pending: pending.size })
    );
    return true;
  }
  if (msg?.type === "setEnabled") {
    chrome.storage.local.set({ enabled: !!msg.enabled }).then(() => {
      if (!msg.enabled) {
        // Stopping discards anything not yet sent, so disabling really
        // stops collection rather than deferring it.
        queue = [];
        pending.clear();
      }
      sendResponse({ ok: true });
    });
    return true;
  }
  if (msg?.type === "flushNow") {
    flush().then(() => sendResponse({ ok: true, stats }));
    return true;
  }
  if (msg?.type === "resetStats") {
    stats = { observed: 0, sent: 0, failed: 0, lastError: null, lastSentAt: null };
    sendResponse({ ok: true });
    return true;
  }
  return false;
});
