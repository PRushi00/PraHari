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

    fireEvent.click(screen.getByRole("button", { name: /Collect once/i }));

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

    fireEvent.click(screen.getByRole("button", { name: /Collect once/i }));

    await waitFor(() => {
      expect(screen.getByRole("alert")).toHaveTextContent(/is disabled/);
    });
  });

  it("refreshes observations on its own while collection is running", async () => {
    // The point of ADR-127: evidence appears without a button press.
    vi.useFakeTimers();
    try {
      vi.spyOn(api, "getDnsCollectorStatus").mockResolvedValue({
        state: "running",
        platform_supported: true,
        platform_name: "Windows 11",
        interval_seconds: 5,
        batch_size: 500,
        started_at: null, stopped_at: null, last_poll_at: null,
        last_success_at: "2026-10-22T12:00:00.000Z",
        polls_attempted: 3, polls_succeeded: 3, polls_failed: 0,
        consecutive_failures: 0, records_read_total: 40,
        observations_recorded_total: 12, skipped_failed_query_total: 1,
        bookmark: 4821, log_resets_seen: 0, last_error: null, notes: [],
      } as never);
      const get = vi.spyOn(api, "getDnsObservations").mockResolvedValue(page([ROW]) as never);

      renderPage();
      await vi.waitFor(() => expect(get).toHaveBeenCalledTimes(1));

      await vi.advanceTimersByTimeAsync(5000);
      await vi.waitFor(() => expect(get.mock.calls.length).toBeGreaterThan(1));
    } finally {
      vi.useRealTimers();
    }
  });

  it("does not poll while collection is stopped", async () => {
    // A stopped collector produces nothing new, so refreshing against
    // it is traffic that cannot change the answer.
    vi.useFakeTimers();
    try {
      vi.spyOn(api, "getDnsCollectorStatus").mockResolvedValue({
        state: "stopped", platform_supported: true, platform_name: "Windows 11",
        interval_seconds: 5, batch_size: 500,
        started_at: null, stopped_at: null, last_poll_at: null, last_success_at: null,
        polls_attempted: 0, polls_succeeded: 0, polls_failed: 0,
        consecutive_failures: 0, records_read_total: 0,
        observations_recorded_total: 0, skipped_failed_query_total: 0,
        bookmark: 0, log_resets_seen: 0, last_error: null, notes: [],
      } as never);
      const get = vi.spyOn(api, "getDnsObservations").mockResolvedValue(page([ROW]) as never);

      renderPage();
      await vi.waitFor(() => expect(get).toHaveBeenCalledTimes(1));

      await vi.advanceTimersByTimeAsync(30000);
      expect(get).toHaveBeenCalledTimes(1);
    } finally {
      vi.useRealTimers();
    }
  });

  it("keeps the evidence-source filter across an automatic refresh", async () => {
    vi.useFakeTimers();
    try {
      vi.spyOn(api, "getDnsCollectorStatus").mockResolvedValue({
        state: "running", platform_supported: true, platform_name: "Windows 11",
        interval_seconds: 5, batch_size: 500,
        started_at: null, stopped_at: null, last_poll_at: null, last_success_at: null,
        polls_attempted: 1, polls_succeeded: 1, polls_failed: 0,
        consecutive_failures: 0, records_read_total: 1,
        observations_recorded_total: 1, skipped_failed_query_total: 0,
        bookmark: 10, log_resets_seen: 0, last_error: null, notes: [],
      } as never);
      const get = vi.spyOn(api, "getDnsObservations").mockResolvedValue(page([ROW]) as never);

      renderPage();
      await vi.waitFor(() => expect(get).toHaveBeenCalled());

      fireEvent.change(screen.getByLabelText(/Evidence source/i), {
        target: { value: "dns_cache_observation" },
      });
      await vi.waitFor(() =>
        expect(get).toHaveBeenLastCalledWith(
          expect.objectContaining({ method: "dns_cache_observation" }),
        ),
      );

      // The timer must not quietly drop back to an unfiltered query.
      await vi.advanceTimersByTimeAsync(5000);
      await vi.waitFor(() =>
        expect(get).toHaveBeenLastCalledWith(
          expect.objectContaining({ method: "dns_cache_observation" }),
        ),
      );
    } finally {
      vi.useRealTimers();
    }
  });

  it("explains that continuous collection needs Windows", async () => {
    // A Linux backend cannot read a Windows host's event log, and the
    // page must say that rather than offering a button that fails.
    vi.spyOn(api, "getDnsCollectorStatus").mockResolvedValue({
      state: "unsupported", platform_supported: false, platform_name: "Linux 6.18",
      interval_seconds: 8, batch_size: 500,
      started_at: null, stopped_at: null, last_poll_at: null, last_success_at: null,
      polls_attempted: 0, polls_succeeded: 0, polls_failed: 0,
      consecutive_failures: 0, records_read_total: 0,
      observations_recorded_total: 0, skipped_failed_query_total: 0,
      bookmark: 0, log_resets_seen: 0, last_error: null, notes: [],
    } as never);
    renderPage();

    await waitFor(() =>
      expect(screen.getByText(/Continuous collection needs Windows/i)).toBeInTheDocument(),
    );
    expect(screen.getByRole("button", { name: /Collect continuously/i })).toBeDisabled();
  });

  it("distinguishes a failed refresh from an empty host", async () => {
    vi.spyOn(api, "getDnsObservations").mockRejectedValue(new Error("backend down"));
    renderPage();

    await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent("backend down"));
    expect(
      screen.getByText(/not a statement that this host resolved nothing/i),
    ).toBeInTheDocument();
  });
});
