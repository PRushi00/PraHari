import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { TrafficPage } from "../pages/TrafficPage";
import { GuidedModeProvider } from "../components/GuidedMode";
import { api } from "../services/api";

/**
 * Traffic Explorer (ADR-122).
 *
 * Direction is an INFERENCE. A column reading "Outbound" beside a
 * connection is read as fact, so these pin that it never stops looking
 * like one:
 *
 *   * an inferred value is labelled inferred, an observed one observed;
 *   * `unknown` renders as a real answer, never a blank;
 *   * `unknown` is selectable — it is the set PraHari declined to call,
 *     which is the set worth auditing;
 *   * no bytes, packets or bandwidth column exists, because the
 *     connection table measures none of them.
 */

function conn(over: Record<string, unknown> = {}) {
  return {
    event: {
      event_id: "evt-1",
      source_id: "windows_local_host",
      observed_at: "2026-10-22T12:00:00.000Z",
      src_ip: "192.168.1.10",
      dst_ip: "93.184.216.34",
      src_port: 54321,
      dst_port: 443,
      protocol: "TCP",
      ...(over.event as object | undefined),
    },
    connection_state: "ESTABLISHED",
    process_name: "chrome.exe",
    process_id: 1234,
    domain_attribution: null,
    direction: {
      direction: "outbound",
      confidence: "inferred",
      method: "ephemeral_port_asymmetry",
      reason: "The local port (54321) is in the ephemeral range",
      limitations: ["not from observing who opened the socket"],
    },
    source_type: "windows_connection_table",
    unsupported_fields: [],
    source_limitations: [],
    ...over,
  };
}

function page(connections: unknown[]) {
  return {
    total: connections.length,
    limit: 200,
    offset: 0,
    returned: connections.length,
    connections,
    filters_applied: {},
    enrichment_note: "Hostnames and direction are both INFERRED.",
  };
}

function renderPage() {
  return render(
    <GuidedModeProvider>
      <TrafficPage />
    </GuidedModeProvider>,
  );
}

beforeEach(() => {
  vi.spyOn(api, "getConnections").mockResolvedValue(page([conn()]) as never);
});

afterEach(() => vi.restoreAllMocks());

describe("traffic explorer", () => {
  it("labels an inferred direction as inferred", async () => {
    renderPage();
    await waitFor(() => expect(screen.getByText("Outbound")).toBeInTheDocument());
    expect(screen.getByText("inferred")).toBeInTheDocument();
  });

  it("labels a loopback direction as observed, not inferred", async () => {
    vi.spyOn(api, "getConnections").mockResolvedValue(
      page([
        conn({
          direction: {
            direction: "local",
            confidence: "observed",
            method: "loopback_addresses",
            reason: "Both endpoints are loopback addresses",
            limitations: [],
          },
        }),
      ]) as never,
    );
    renderPage();

    await waitFor(() => expect(screen.getByText("Local")).toBeInTheDocument());
    expect(screen.getByText("observed")).toBeInTheDocument();
    expect(screen.queryByText("inferred")).not.toBeInTheDocument();
  });

  it("renders an undecidable direction as Unknown, not as a blank", async () => {
    vi.spyOn(api, "getConnections").mockResolvedValue(
      page([
        conn({
          direction: {
            direction: "unknown",
            confidence: "none",
            method: "port_asymmetry_absent",
            reason: "Both ports are ephemeral",
            limitations: [],
          },
        }),
      ]) as never,
    );
    renderPage();

    await waitFor(() => expect(screen.getByText("Unknown")).toBeInTheDocument());
  });

  it("carries the method and reason with the value, not in a legend", async () => {
    const { container } = renderPage();
    await waitFor(() => expect(screen.getByText("Outbound")).toBeInTheDocument());

    const titled = [...container.querySelectorAll("[title]")].map(
      (el) => el.getAttribute("title") ?? "",
    );
    const onDirection = titled.find((x) => x.includes("ephemeral_port_asymmetry"));
    expect(onDirection, "the direction cell carries no method").toBeTruthy();
    expect(onDirection).toContain("not from observing who opened the socket");
  });

  it("offers unknown as a filter value, because declines are auditable", async () => {
    renderPage();
    await waitFor(() => expect(screen.getByText("Outbound")).toBeInTheDocument());

    const select = screen.getByLabelText(/Direction/i);
    fireEvent.change(select, { target: { value: "unknown" } });

    await waitFor(() => {
      expect(api.getConnections).toHaveBeenLastCalledWith(
        expect.objectContaining({ direction: "unknown" }),
      );
    });
  });

  it("shows no bytes, packets or bandwidth column", async () => {
    // The Windows connection table measures none of them. A column of
    // blanks invites someone to fill it.
    const { container } = renderPage();
    await waitFor(() => expect(screen.getByText("Outbound")).toBeInTheDocument());

    const headers = [...container.querySelectorAll("th")].map((h) => h.textContent ?? "");
    expect(headers.join(" ")).not.toMatch(/bytes|packets|bandwidth|traffic/i);
  });

  it("reports an unattributed hostname as unknown rather than empty", async () => {
    renderPage();
    await waitFor(() => expect(screen.getByText("Outbound")).toBeInTheDocument());
    expect(screen.getByText("unknown")).toBeInTheDocument();
  });

  it("surfaces a backend failure instead of rendering an empty table", async () => {
    vi.spyOn(api, "getConnections").mockRejectedValue(new Error("boom"));
    renderPage();
    await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent("boom"));
  });
});
