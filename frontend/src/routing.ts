// Client-side routing on the History API (ADR-084).
//
// The dashboard kept its page in React state and never touched the URL, so
// a deep link such as /forecast served the shell (correct, server-side) but
// opened Overview, a refresh always landed on Overview, and the browser's
// back and forward buttons left the application. Two pages - System Health
// and Administration - had no navigation entry at all and could not be
// reached.
//
// No router dependency: the application has thirteen flat pages and no
// nested routes, which the History API covers directly.

import type { NavTab } from "./components/Header";

/** One canonical path per page. */
export const ROUTES: Record<NavTab, string> = {
  overview: "/",
  live: "/live",
  import: "/import",
  stream: "/stream",
  events: "/events",
  sources: "/sources",
  analysis: "/analytics",
  research: "/feasibility",
  forecast: "/forecast",
  investigate: "/investigate",
  traffic: "/traffic",
  dns: "/dns",
  system: "/system-health",
  admin: "/admin",
  audit: "/audit",
};

/** Other spellings a person might type, redirected to the canonical path. */
const ALIASES: Record<string, NavTab> = {
  "/overview": "overview",
  "/index.html": "overview",
  "/live-telemetry": "live",
  "/analysis": "analysis",
  "/research": "research",
  "/forecasting": "forecast",
  "/system": "system",
  "/health": "system",
  "/administration": "admin",
  "/security": "audit",
  "/telemetry-sources": "sources",
  "/investigation": "investigate",
  "/connections": "traffic",
  "/dns-activity": "dns",
};

const BY_PATH: Record<string, NavTab> = Object.fromEntries(
  (Object.entries(ROUTES) as [NavTab, string][]).map(([tab, path]) => [path, tab]),
);

/** Lower-cased, without a trailing slash (except the root itself). */
export function normalisePath(pathname: string): string {
  const lower = (pathname || "/").toLowerCase();
  const trimmed = lower.length > 1 ? lower.replace(/\/+$/, "") : lower;
  return trimmed || "/";
}

export interface Resolved {
  /** The page to show, or null for an unknown path. */
  tab: NavTab | null;
  /** The path to show in the address bar; differs when the input was an alias. */
  canonicalPath: string;
}

export function resolvePath(pathname: string): Resolved {
  const path = normalisePath(pathname);
  const tab = BY_PATH[path] ?? ALIASES[path] ?? null;
  return { tab, canonicalPath: tab ? ROUTES[tab] : pathname };
}

export function pathFor(tab: NavTab): string {
  return ROUTES[tab];
}
