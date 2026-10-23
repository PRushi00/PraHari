// Shared navigation helpers for the tests that walk the application
// (ADR-124).
//
// The header used to list every page, so a test could click any page by
// name in one go. It now lists four workspaces, and the pages live in
// each workspace's own strip — so reaching a page can take two clicks.
//
// These helpers hide that, and nothing else. They still refuse to click
// any button whose text happens to name a page: the Overview page's own
// links say things like "Start the collector" and "View all" (ADR-115),
// and a test that clicked one of those would pass while the navigation
// was broken.
//
// The workspace layout is read from `WORKSPACES`, the application's own
// definition, rather than copied here — a page moved between workspaces
// must not need this file edited to keep the tests honest.

import { fireEvent, screen, within } from "@testing-library/react";
import { WORKSPACES, type NavTab } from "../components/Header";

/** Page label -> the workspace that contains it. */
const OWNER = new Map<string, string>();
/** Page label -> its NavTab, for assertions that need the tab id. */
export const TAB_OF_LABEL = new Map<string, NavTab>();

for (const ws of WORKSPACES) {
  for (const entry of ws.tabs) {
    OWNER.set(entry.label, ws.label);
    TAB_OF_LABEL.set(entry.label, entry.tab);
  }
}
// Overview is a workspace with no pages: it is reached directly.
OWNER.set("Overview", "Overview");
TAB_OF_LABEL.set("Overview", "overview");

/** Every page label the header can reach, workspace by workspace. */
export const ALL_PAGE_LABELS: string[] = [
  "Overview",
  ...WORKSPACES.flatMap((w) => w.tabs.map((t) => t.label)),
];

function primaryNav() {
  return screen.getByRole("navigation", { name: /Primary/i });
}

function workspaceNav() {
  return screen.queryByRole("navigation", { name: /pages$/i });
}

/**
 * The button for a top-level workspace, in the primary navigation.
 *
 * Exact match: "System" must not also match "System Health".
 */
export function workspaceButton(label: string): HTMLElement {
  return within(primaryNav()).getByRole("button", {
    name: new RegExp(`^${label}$`),
  });
}

/**
 * Click through to a page by its label, opening its workspace first if
 * that is where it lives. Returns the button that was clicked last.
 */
export function gotoPage(label: string): HTMLElement {
  const owner = OWNER.get(label);
  if (!owner) throw new Error(`No workspace contains a page called "${label}"`);

  if (owner === "Overview") {
    const button = workspaceButton("Overview");
    fireEvent.click(button);
    return button;
  }

  // Open the workspace unless one of its pages is already showing.
  if (!workspaceNav() || !queryPageButton(label)) {
    fireEvent.click(workspaceButton(owner));
  }

  const button = pageButton(label);
  fireEvent.click(button);
  return button;
}

function queryPageButton(label: string): HTMLElement | null {
  const nav = workspaceNav();
  if (!nav) return null;
  return within(nav).queryByRole("button", { name: new RegExp(`^${label}$`) });
}

/** The button for a page, inside the current workspace's strip. */
export function pageButton(label: string): HTMLElement {
  const found = queryPageButton(label);
  if (!found) {
    throw new Error(
      `"${label}" is not in the open workspace's navigation. ` +
        `Open ${OWNER.get(label)} first.`,
    );
  }
  return found;
}

/**
 * The page the navigation currently marks as current, or null when no
 * page is (an unknown path).
 *
 * Inside a workspace that is the page in its strip; on Overview, which
 * has no strip, it is the primary button itself.
 */
export function activePageLabel(): string | null {
  const page = document.querySelector(".workspace-nav .workspace-btn.active");
  if (page) return (page.textContent ?? "").trim();
  const workspace = document.querySelector(".nav-tabs .nav-btn.active");
  return workspace ? (workspace.textContent ?? "").trim() : null;
}

/** The workspace the header marks as current, or null on an unknown path. */
export function activeWorkspaceLabel(): string | null {
  const active = document.querySelector(".nav-tabs .nav-btn.active");
  return active ? (active.textContent ?? "").trim() : null;
}
