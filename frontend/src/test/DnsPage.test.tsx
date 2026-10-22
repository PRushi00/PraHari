import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { DnsPage } from "../pages/DnsPage";
import { GuidedModeProvider } from "../components/GuidedMode";
import { api } from "../services/api";

/**
 * DNS Activity (ADR-122).
 *
 * The data has existed since ADR-120 and had nowhere to be seen. The
 * risks in surfacing it:
 *
 *   * a hostname shown without its address and evidence source is not
 *     evidence of anything;
 *   * an empty table and a host that resolved nothing look identical,
 *     and are opposite claims;
 *   * cache and event-log evidence must stay distinguishable;
 *   * a collection result that reports only what was stored presents a
 *     partial read as a complete one.
 */

const ROW = {
  ip_address: "93.184.216.34",
  hostname: "example.com",
  observed_at: "2026-10-22T12:00:00.000Z",
  method: "dns_query_log",
  ttl_seconds: null,
  source_id: "windows_dns_events",
};

function page(observations: unknown[], note = "Every row is a locally observed resolution.") {
  return {
    total_stored: observations.length,
    returned: observations.length,
    observations,
    method_filter: null,
    note,
  };
}

function renderPage() {
  return render(
    <GuidedModeProvider>
      <DnsPage />
    </GuidedModeProvider>,
  );
}

beforeEach(() => {
  vi.spyOn(api, "getDnsObservations").mockResolvedValue(page([ROW]) as never);
});

afterEach(() => vi.restoreAllMocks());

describe("DNS activity", () => {
  it("shows the name, the address it resolved to, and the evidence source", async () => {
    renderPage();

    await waitFor(() => expect(screen.getByText("example.com")).toBeInTheDocument());
    expect(screen.getByText("93.184.216.34")).toBeInTheDocument();
    expect(screen.getByText("DNS query log")).toBeInTheDocument();
  });

  it("reports an absent TTL as not reported rather than as zero", async () => {
    renderPage();
    await waitFor(() => expect(screen.getByText("example.com")).toBeInTheDocument());

    expect(screen.getByText("not reported")).toBeInTheDocument();
    expect(screen.queryByText("0s")).not.toBeInTheDocument();
  });

  it("explains an empty store instead of showing a blank table", async () => {
    // "Nothing collected" and "this host resolved nothing" are opposite
    // claims that look identical on screen.
    vi.spyOn(api, "getDnsObservations").mockResolvedValue(
      page(
        [],
        "No DNS evidence has been collected. That is not the same as this host resolving nothing.",
      ) as never,
    );
    renderPage();

    await waitFor(() => {
      expect(
        screen.getByText(/not the same as this host resolving nothing/),
      ).toBeInTheDocument();
    });
  });

  it("keeps the two evidence sources filterable apart", async () => {
    renderPage();
    await waitFor(() => expect(screen.getByText("example.com")).toBeInTheDocument());

    fireEvent.change(screen.getByLabelText(/Evidence source/i), {
      target: { value: "dns_cache_observation" },
    });

    await waitFor(() => {
      expect(api.getDnsObservations).toHaveBeenLastCalledWith(
        expect.objectContaining({ method: "dns_cache_observation" }),
      );
    });
  });

  it("reports what a collection skipped, not only what it stored", async () => {
    vi.spyOn(api, "collectDnsEvents").mockResolvedValue({
      succeeded: true,
      records_read: 40,
      observations_recorded: 3,
      skipped_failed_query: 12,
    } as never);
    renderPage();
    await waitFor(() => expect(screen.getByText("example.com")).toBeInTheDocument());

    fireEvent.click(screen.getByRole("button", { name: /Collect from event log/i }));

    await waitFor(() => {
      const status = screen.getByRole("status");
      expect(status).toHaveTextContent("Read 40 record(s)");
      expect(status).toHaveTextContent("stored 3");
      expect(status).toHaveTextContent("12 query/queries did not resolve");
    });
  });

  it("surfaces a refused collection with its specific reason", async () => {
    vi.spyOn(api, "collectDnsEvents").mockResolvedValue({
      succeeded: false,
      error:
        "Microsoft-Windows-DNS-Client/Operational exists but is disabled, which is the Windows default.",
    } as never);
    renderPage();
    await waitFor(() => expect(screen.getByText("example.com")).toBeInTheDocument());

    fireEvent.click(screen.getByRole("button", { name: /Collect from event log/i }));

    await waitFor(() => {
      expect(screen.getByRole("alert")).toHaveTextContent(/is disabled/);
    });
  });
});
