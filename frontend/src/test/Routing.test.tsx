// Deep-link routing (ADR-084). Before this, the page lived only in React
// state: /forecast opened Overview, a refresh always landed on Overview, the
// back button left the application, and System Health and Administration
// had no way in at all.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";

import { App } from "../App";
import { api } from "../services/api";
import { ROUTES, normalisePath, pathFor, resolvePath } from "../routing";

/**
 * The button in the primary navigation, not any button whose text
 * happens to name a page: the Overview page's own links say things
 * like "Open the Events Explorer" (ADR-115).
 */
function navButton(name: RegExp) {
  return within(screen.getByRole("navigation", { name: /Primary/i })).getByRole(
    "button",
    { name },
  );
}

function failAllApiCalls() {
  // Pages must render their own error states; routing must not depend on data.
  const boom = () => Promise.reject(new Error("HTTP 503: backend unavailable"));
  for (const key of Object.keys(api) as (keyof typeof api)[]) {
    if (typeof api[key] === "function") vi.spyOn(api, key as any).mockImplementation(boom as any);
  }
}

function activeNavLabel(): string | null {
  const active = document.querySelector("nav .nav-btn.active");
  return active ? (active.textContent ?? "").trim() : null;
}

function visit(path: string) {
  window.history.replaceState({}, "", path);
  render(<App />);
}

describe("resolvePath", () => {
  it("maps every canonical path to its page and back", () => {
    for (const [tab, path] of Object.entries(ROUTES)) {
      expect(resolvePath(path).tab).toBe(tab);
      expect(pathFor(tab as keyof typeof ROUTES)).toBe(path);
    }
  });

  it("accepts trailing slashes and any letter case", () => {
    expect(resolvePath("/Forecast/").tab).toBe("forecast");
    expect(normalisePath("/EVENTS//")).toBe("/events");
    expect(normalisePath("/")).toBe("/");
  });

  it("resolves an alias to the canonical path", () => {
    expect(resolvePath("/research")).toEqual({ tab: "research", canonicalPath: "/feasibility" });
    expect(resolvePath("/analysis")).toEqual({ tab: "analysis", canonicalPath: "/analytics" });
  });

  it("reports an unknown path as no page, keeping what was asked for", () => {
    expect(resolvePath("/no-such-page")).toEqual({ tab: null, canonicalPath: "/no-such-page" });
  });

  it("keeps the paths the launcher verifier probes", () => {
    for (const p of ["/events", "/forecast", "/analytics", "/stream"]) {
      expect(resolvePath(p).tab).not.toBeNull();
    }
  });
});

describe("App routing", () => {
  beforeEach(() => {
    vi.spyOn(console, "error").mockImplementation(() => {});
    failAllApiCalls();
  });
  afterEach(() => {
    vi.restoreAllMocks();
    window.history.replaceState({}, "", "/");
  });

  it("opens the page a deep link names", async () => {
    visit("/forecast");
    await waitFor(() => expect(activeNavLabel()).toBe("Threat Forecasting"));
    expect(document.title).toBe("Threat Forecasting · PraHari");
  });

  it("reaches the two pages that had no navigation entry", async () => {
    visit("/system-health");
    await waitFor(() => expect(activeNavLabel()).toBe("System Health"));
    fireEvent.click(navButton(/Administration/i));
    await waitFor(() => expect(window.location.pathname).toBe("/admin"));
    expect(activeNavLabel()).toBe("Administration");
  });

  it("puts each navigation in the address bar and history", async () => {
    visit("/");
    const before = window.history.length;

    fireEvent.click(navButton(/Events Explorer/i));

    expect(window.location.pathname).toBe("/events");
    expect(window.history.length).toBe(before + 1);
    expect(activeNavLabel()).toBe("Events Explorer");
  });

  it("does not add a history entry when the current page is clicked again", async () => {
    visit("/events");
    const before = window.history.length;
    fireEvent.click(navButton(/Events Explorer/i));
    expect(window.history.length).toBe(before);
  });

  it("follows the browser's back and forward buttons", async () => {
    visit("/");
    fireEvent.click(navButton(/Analytics/i));
    fireEvent.click(navButton(/Audit & Security/i));
    expect(activeNavLabel()).toBe("Audit & Security");

    await act(async () => { window.history.back(); });
    await waitFor(() => expect(activeNavLabel()).toBe("Analytics"));
    expect(window.location.pathname).toBe("/analytics");

    await act(async () => { window.history.forward(); });
    await waitFor(() => expect(activeNavLabel()).toBe("Audit & Security"));
  });

  it("shows an alias at its canonical address without a new history entry", async () => {
    window.history.replaceState({}, "", "/");
    window.history.pushState({}, "", "/research");
    const before = window.history.length;
    render(<App />);

    await waitFor(() => expect(window.location.pathname).toBe("/feasibility"));
    expect(window.history.length).toBe(before);
    expect(activeNavLabel()).toBe("Feasibility");
  });

  it("says an unknown path is not a page instead of showing Overview", async () => {
    visit("/definitely/not-a-page");

    await waitFor(() => expect(screen.getByText("Page not found")).toBeInTheDocument());
    expect(screen.getByText("/definitely/not-a-page")).toBeInTheDocument();
    expect(activeNavLabel()).toBeNull();
    expect(document.title).toBe("Page not found · PraHari");

    fireEvent.click(screen.getAllByRole("button", { name: "Overview" })[0]);
    await waitFor(() => expect(window.location.pathname).toBe("/"));
    expect(screen.queryByText("Page not found")).not.toBeInTheDocument();
  });

  it("survives a refresh on a page: a fresh render of the same URL opens it", async () => {
    visit("/");
    fireEvent.click(navButton(/Stream & Replay/i));
    const { unmount } = render(<App />); // a second mount reads the address bar
    await waitFor(() =>
      expect(document.querySelectorAll("nav .nav-btn.active")).toHaveLength(2));
    unmount();
    expect(window.location.pathname).toBe("/stream");
  });
});
