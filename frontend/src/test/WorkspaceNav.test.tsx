import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { render, screen, within } from "@testing-library/react";
import { App } from "../App";
import { api } from "../services/api";
import { WORKSPACES, workspaceOf, defaultTabOf } from "../components/Header";
import { ROUTES } from "../routing";
import { activeWorkspaceLabel, gotoPage, workspaceButton } from "./navigate";

/**
 * The four-workspace header (ADR-124).
 *
 * The old header listed all fifteen pages across three stacked rows.
 * Every page was one click away, which was the point, but the row was
 * the first thing on screen and the last thing anyone could read.
 *
 * The risk in fixing that is losing a page: a page not in the primary
 * row and not in any workspace strip is unreachable, and nothing would
 * say so. These tests exist for that.
 */

function failAllApiCalls() {
  const boom = () => Promise.reject(new Error("HTTP 503: backend unavailable"));
  for (const key of Object.keys(api) as (keyof typeof api)[]) {
    if (typeof api[key] === "function") {
      vi.spyOn(api, key as any).mockImplementation(boom as any);
    }
  }
}

function visit(path: string) {
  window.history.replaceState({}, "", path);
  render(<App />);
}

beforeEach(() => {
  vi.spyOn(console, "error").mockImplementation(() => {});
  failAllApiCalls();
});

afterEach(() => {
  vi.restoreAllMocks();
  window.history.replaceState({}, "", "/");
});

describe("primary navigation", () => {
  it("offers exactly four destinations", () => {
    visit("/");
    const buttons = within(
      screen.getByRole("navigation", { name: /Primary/i }),
    ).getAllByRole("button");

    expect(buttons.map((b) => (b.textContent ?? "").trim())).toEqual([
      "Overview",
      "Network",
      "Security",
      "System",
    ]);
  });

  it("does not repeat a workspace's pages in the header", () => {
    // The specific failure being prevented: a second permanent row of
    // every page, which is the layout this replaced.
    visit("/live");
    const primary = screen.getByRole("navigation", { name: /Primary/i });

    for (const label of ["Live Telemetry", "Events Explorer", "Administration"]) {
      expect(
        within(primary).queryByRole("button", { name: new RegExp(`^${label}$`) }),
      ).toBeNull();
    }
  });

  // One render per test: two mounted Apps would both be in the document
  // and the active-marker lookup would find the first one's.
  it("marks System as current on an operations page", () => {
    visit("/audit");
    expect(activeWorkspaceLabel()).toBe("System");
  });

  it("marks Network as current on DNS Activity", () => {
    visit("/dns");
    expect(activeWorkspaceLabel()).toBe("Network");
  });

  it("shows no workspace strip on Overview", () => {
    // A summary with tabs is not a summary.
    visit("/");
    expect(screen.queryByRole("navigation", { name: /pages$/i })).toBeNull();
  });

  it("shows no workspace strip on an unknown path", () => {
    visit("/definitely-not-a-page");
    expect(screen.queryByRole("navigation", { name: /pages$/i })).toBeNull();
    expect(activeWorkspaceLabel()).toBeNull();
  });
});

describe("every page survives the restructure", () => {
  it("assigns every route to exactly one workspace", () => {
    // A page in no workspace cannot be opened from the header at all.
    const placed = WORKSPACES.flatMap((w) => w.tabs.map((t) => t.tab));
    const everyTab = Object.keys(ROUTES) as (keyof typeof ROUTES)[];

    for (const tab of everyTab) {
      if (tab === "overview") continue;
      expect(
        placed.filter((t) => t === tab),
        `${tab} should appear in exactly one workspace`,
      ).toHaveLength(1);
    }
  });

  it("reaches every page through the header", () => {
    visit("/");
    for (const ws of WORKSPACES) {
      for (const entry of ws.tabs) {
        gotoPage(entry.label);
        expect(window.location.pathname).toBe(ROUTES[entry.tab]);
      }
    }
  });

  it("opens a workspace on a page that belongs to it", () => {
    for (const ws of WORKSPACES) {
      const landing = defaultTabOf(ws.id);
      expect(workspaceOf(landing)).toBe(ws.id);
    }
  });

  it("keeps the deep link for a page that moved workspace", () => {
    // Audit & Security sat under "Operate" and now sits under System.
    // Its URL did not change, so an existing bookmark still works.
    visit("/audit");
    expect(window.location.pathname).toBe("/audit");
    expect(activeWorkspaceLabel()).toBe("System");
  });
});

describe("header actions", () => {
  it("sends Add device to the existing registration page", () => {
    // It must reuse the device registration that already exists rather
    // than imply that registering installs anything.
    visit("/");
    const button = screen.getByRole("button", { name: /Add device/i });
    button.click();
    expect(window.location.pathname).toBe(ROUTES.sources);
  });

  it("reports the backend's health, not the host's", () => {
    // "Host online" would be a claim about a machine nothing measured.
    visit("/");
    expect(screen.queryByText(/host online/i)).toBeNull();
  });

  it("returns to Overview from a workspace", () => {
    visit("/analytics");
    workspaceButton("Overview").click();
    expect(window.location.pathname).toBe("/");
  });
});
