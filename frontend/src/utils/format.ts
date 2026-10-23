/**
 * Safe formatting helpers for values that come from the API.
 *
 * Two render-crash outages traced to the same mistake: calling a numeric
 * method directly on an API field that the backend does not return.
 * `undefined.toFixed(2)` throws during render, which (before the error
 * boundary existed) blanked the entire application.
 *
 * These helpers never throw, and they deliberately preserve the difference
 * between **zero** (a real measurement) and **unavailable** (no value).
 * A missing measurement renders as `N/A`; it is never silently shown as 0,
 * because "no bytes were transferred" and "this source cannot count bytes"
 * are different facts.
 *
 * They are a presentation safety net, not a substitute for a correct data
 * contract — see backend/tests/integration/test_frontend_api_contract.py,
 * which fails the build when a TypeScript interface and the API diverge.
 */

export const UNAVAILABLE = "N/A";

/** True only for a real, finite number. Zero is a real number. */
export function isNum(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value);
}

/** Fixed-decimal format, or `N/A` when the value is absent or invalid. */
export function fmtFixed(
  value: unknown,
  digits = 2,
  fallback: string = UNAVAILABLE
): string {
  return isNum(value) ? value.toFixed(digits) : fallback;
}

/** Integer with thousands separators, or `N/A`. */
export function fmtInt(value: unknown, fallback: string = UNAVAILABLE): string {
  return isNum(value) ? Math.round(value).toLocaleString() : fallback;
}

/**
 * Ratio (0–1) rendered as a percentage, or `N/A`.
 * Pass `alreadyPercent` when the value is already 0–100.
 */
export function fmtPercent(
  value: unknown,
  digits = 1,
  { alreadyPercent = false }: { alreadyPercent?: boolean } = {}
): string {
  if (!isNum(value)) return UNAVAILABLE;
  return `${(alreadyPercent ? value : value * 100).toFixed(digits)}%`;
}

/** Locale timestamp, or `N/A` for a missing or unparseable date. */
export function fmtTime(value: unknown, fallback: string = UNAVAILABLE): string {
  if (typeof value !== "string" || !value.trim()) return fallback;
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? fallback : d.toLocaleString();
}

/**
 * An instant rendered in UTC, labelled as such: "2026-10-17 08:20:09 UTC".
 *
 * For any column whose header says UTC (ADR-079). `fmtTime` renders in the
 * browser's local zone, so the Events and Audit tables - both headed
 * "(UTC)" - showed local time under a UTC label: in India every timestamp
 * was 5 h 30 m off its own header. Independent of the viewer's zone, so a
 * timeline reads the same for every analyst.
 */
export function fmtTimeUtc(value: unknown, fallback: string = UNAVAILABLE): string {
  if (typeof value !== "string" || !value.trim()) return fallback;
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return fallback;
  return d.toISOString().replace("T", " ").replace(/\.\d{3}Z$/, " UTC");
}

/** Relative age such as "12s ago", or `N/A`. */
export function fmtRelative(value: unknown, fallback: string = UNAVAILABLE): string {
  if (typeof value !== "string" || !value.trim()) return fallback;
  const t = new Date(value).getTime();
  if (Number.isNaN(t)) return fallback;
  const secs = (Date.now() - t) / 1000;
  if (secs < 0) return "just now";
  if (secs < 60) return `${Math.round(secs)}s ago`;
  if (secs < 3600) return `${Math.round(secs / 60)}m ago`;
  if (secs < 86400) return `${Math.round(secs / 3600)}h ago`;
  return `${Math.round(secs / 86400)}d ago`;
}

/**
 * Elapsed time between two timestamps, derived rather than read from a
 * field. Returns `N/A` unless both ends are valid and ordered.
 */
export function fmtElapsed(
  start: unknown,
  end: unknown,
  fallback: string = UNAVAILABLE
): string {
  if (typeof start !== "string" || typeof end !== "string") return fallback;
  const a = new Date(start).getTime();
  const b = new Date(end).getTime();
  if (Number.isNaN(a) || Number.isNaN(b) || b < a) return fallback;
  const secs = (b - a) / 1000;
  if (secs < 1) return `${Math.round(secs * 1000)}ms`;
  if (secs < 60) return `${secs.toFixed(2)}s`;
  return `${Math.floor(secs / 60)}m ${Math.round(secs % 60)}s`;
}

/**
 * A duration in seconds, as a person would say it: "3h 24m", "12m 5s".
 *
 * Distinct from `fmtElapsed`, which takes two timestamps. A null or
 * non-finite input returns the fallback rather than "0s", because an
 * unmeasured uptime and a machine that just booted are different
 * claims (ADR-125).
 */
export function fmtDuration(
  seconds: unknown,
  fallback: string = UNAVAILABLE
): string {
  if (!isNum(seconds) || seconds < 0) return fallback;
  const total = Math.floor(seconds);
  const d = Math.floor(total / 86400);
  const h = Math.floor((total % 86400) / 3600);
  const m = Math.floor((total % 3600) / 60);
  const sec = total % 60;
  if (d > 0) return `${d}d ${h}h`;
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m ${sec}s`;
  return `${sec}s`;
}

/**
 * Chart-safe numeric series: drops non-finite entries so a charting
 * library is never handed NaN or null.
 */
export function safeSeries(values: unknown[]): number[] {
  return values.filter(isNum);
}

/* ──────────────────────────────────────────────────────────────────
   Labels versus identifiers (ADR-114)
   ────────────────────────────────────────────────────────────────── */

/**
 * Turn an underscore-separated VALUE into readable prose.
 *
 * Use this only for values that **describe a condition** — a source
 * state, a data category, a quality flag, a rejection reason. Those are
 * prose wearing an underscore, and `timestamp_uncertainty` reads far
 * better as "Timestamp uncertainty".
 *
 * Do **NOT** use it on an identifier: a `source_id`, `model_id`,
 * `event_id`, schema field name or feature name. Those are keys the
 * system matches on exactly, and rendering `windows_local_host` as
 * "Windows Local Host" would invent a second spelling for one thing —
 * an operator comparing the screen with a config file or an API
 * response would then find no match. Identifiers belong in `<code>`,
 * which the stylesheet renders in mono so the difference is visible.
 *
 * Acronyms the project uses are preserved rather than title-cased into
 * nonsense ("Dns" and "Ip" help nobody).
 */
const KEEP_UPPER = new Set([
  "ip", "tcp", "udp", "dns", "http", "https", "url", "uri", "id", "ids",
  "api", "cpu", "rss", "csv", "json", "ndjson", "utc", "sql", "xss",
  "pr", "auc", "roc", "ddos", "dos", "ftp", "ssh", "tls", "ssl", "os",
]);

export function humanise(value: unknown, fallback: string = UNAVAILABLE): string {
  if (typeof value !== "string" || value.trim() === "") return fallback;

  const words = value
    .trim()
    .replace(/[_-]+/g, " ")
    .replace(/\s+/g, " ")
    .split(" ");

  return words
    .map((word, index) => {
      const lower = word.toLowerCase();
      if (KEEP_UPPER.has(lower)) return lower.toUpperCase();
      // Only the first word is capitalised: sentence case reads as prose,
      // Title Case Reads As A Heading And Is Harder To Scan.
      if (index === 0) return lower.charAt(0).toUpperCase() + lower.slice(1);
      return lower;
    })
    .join(" ");
}
