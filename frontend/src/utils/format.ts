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
 * Chart-safe numeric series: drops non-finite entries so a charting
 * library is never handed NaN or null.
 */
export function safeSeries(values: unknown[]): number[] {
  return values.filter(isNum);
}
