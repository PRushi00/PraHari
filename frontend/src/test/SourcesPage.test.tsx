import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { SourcesPage } from "../pages/SourcesPage";
import { api } from "../services/api";

/**
 * Sources view (blueprint §11, ADR-108).
 *
 * §11 asks for "source identity, capability, last event and adapter
 * errors" in one view. These tests pin the honesty properties rather
 * than the layout, because the ways a source page misleads are specific:
 *
 *   * the adapter registry lists only adapters EXERCISED IN THIS PROCESS,
 *     so a source with no adapter row must read as not-seen-since-startup,
 *     never as a healthy adapter;
 *   * adapter errors are the thing §11 names, so they must be visible
 *     rather than folded into a status dot;
 *   * freshness is derived from SOURCE-REPORTED event time, so the basis
 *     and the no-heartbeat caveat travel with the figures;
 *   * a source that has never reported says so, instead of rendering a
 *     blank or an epoch date.
 */

const healthSummary = {
  evaluated_at: "2026-10-21T12:00:00.000Z",
  fresh_threshold_seconds: 300,
  stale_threshold_seconds: 3600,
  counts_by_state: { reporting: 1, silent: 1 },
  notes: [
    "PraHari has no heartbeat. Silence means 'no events recorded', never 'the host is down'.",
  ],
  sources: [
    {
      source_id: "windows_local_host",
      name: "Windows Local Host (Sussy)",
      source_type: "windows_connection_table",
      state: "reporting",
      enabled: true,
      recorded_status: "active",
      event_count: 688,
      last_event_at: "2026-10-21T11:59:50.000Z",
      seconds_since_last_event: 10,
      fresh_threshold_seconds: 300,
      stale_threshold_seconds: 3600,
      evaluated_at: "2026-10-21T12:00:00.000Z",
      last_received_at: null,
      seconds_since_last_receipt: null,
      receipt_evidence_available: false,
      freshness_basis: "max(observed_at) reported by the source — event time, not receipt time",
      clock_dependent: true,
      reasons: ["An event 10s ago, within the 300s freshness window."],
      limitations: ["No heartbeat exists: a silent source may be healthy with nothing to report."],
    },
    {
      source_id: "remote_sensor_b",
      name: "Remote Sensor B",
      source_type: "json_stream",
      state: "silent",
      enabled: true,
      recorded_status: "active",
      event_count: 0,
      last_event_at: null,
      seconds_since_last_event: null,
      fresh_threshold_seconds: 300,
      stale_threshold_seconds: 3600,
      evaluated_at: "2026-10-21T12:00:00.000Z",
      last_received_at: null,
      seconds_since_last_receipt: null,
      receipt_evidence_available: false,
      freshness_basis: "max(observed_at) reported by the source — event time, not receipt time",
      clock_dependent: true,
      reasons: ["No event has ever been recorded for this source."],
      limitations: [],
    },
  ],
};

// Only the Windows collector's adapter has run in this process.
const adapters = [
  {
    adapter_id: "windows_local_host",
    adapter_type: "windows_connection_table",
    is_healthy: false,
    last_active_at: "2026-10-21T11:59:51.000Z",
    records_processed: 688,
    records_rejected: 12,
    error_message: "PowerShell query timed out after 10s",
  },
];

const capabilities = [
  {
    source_type: "windows_connection_table",
    description: "Live TCP connection metadata from the local Windows connection table.",
    fields: {},
    limitations: ["Byte and packet counts are NOT available from this source."],
  },
];

beforeEach(() => {
  vi.spyOn(api, "getSourceHealth").mockResolvedValue(healthSummary as never);
  vi.spyOn(api, "getStreamAdapters").mockResolvedValue(adapters as never);
  vi.spyOn(api, "getSourceCapabilities").mockResolvedValue(capabilities as never);
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("Sources view", () => {
  it("shows every registered source with its identity", async () => {
    render(<SourcesPage />);

    await waitFor(() => {
      expect(screen.getByText("Windows Local Host (Sussy)")).toBeInTheDocument();
    });
    expect(screen.getByText("Remote Sensor B")).toBeInTheDocument();
    expect(screen.getByText("windows_local_host")).toBeInTheDocument();
    expect(screen.getByText("remote_sensor_b")).toBeInTheDocument();
  });

  it("surfaces adapter errors rather than folding them into a status dot", async () => {
    render(<SourcesPage />);

    await waitFor(() => {
      expect(
        screen.getByText(/PowerShell query timed out after 10s/),
      ).toBeInTheDocument();
    });
    // The rejected count is part of "adapter errors" and must be legible.
    expect(screen.getByText("12")).toBeInTheDocument();
  });

  it("reports a source with no adapter row as unseen, not as healthy", async () => {
    // The registry only lists adapters exercised since startup. Showing
    // nothing, or a green dot, would both be false.
    render(<SourcesPage />);

    await waitFor(() => {
      expect(
        screen.getByText(/No adapter has run for this source in this backend process/),
      ).toBeInTheDocument();
    });
    expect(screen.getByText(/not an adapter failure/)).toBeInTheDocument();
  });

  it("states the freshness basis beside the figures", async () => {
    render(<SourcesPage />);

    await waitFor(() => {
      expect(
        screen.getAllByText(/event time, not receipt time/).length,
      ).toBeGreaterThan(0);
    });
    expect(
      screen.getAllByText(/freshness falls back to source-reported event time/)
        .length,
    ).toBeGreaterThan(0);
  });

  it("carries the no-heartbeat caveat", async () => {
    render(<SourcesPage />);

    await waitFor(() => {
      expect(screen.getByText(/never 'the host is down'/)).toBeInTheDocument();
    });
  });

  it("says a source has never reported instead of rendering a blank", async () => {
    render(<SourcesPage />);

    await waitFor(() => {
      expect(screen.getByText(/never — no event recorded/)).toBeInTheDocument();
    });
  });

  it("names an undeclared capability rather than leaving it empty", async () => {
    render(<SourcesPage />);

    await waitFor(() => {
      expect(
        screen.getByText(/No capability report is published for source type/),
      ).toBeInTheDocument();
    });
  });

  it("still renders identity when adapter health is unavailable", async () => {
    // A secondary endpoint failing must not blank the page this exists for.
    vi.spyOn(api, "getStreamAdapters").mockRejectedValue(new Error("503"));

    render(<SourcesPage />);

    await waitFor(() => {
      expect(screen.getByText("Windows Local Host (Sussy)")).toBeInTheDocument();
    });
  });

  it("reports an empty registry as empty", async () => {
    vi.spyOn(api, "getSourceHealth").mockResolvedValue({
      ...healthSummary,
      sources: [],
      counts_by_state: {},
    } as never);

    render(<SourcesPage />);

    await waitFor(() => {
      expect(
        screen.getByText(/No telemetry source is registered/),
      ).toBeInTheDocument();
    });
  });
});
