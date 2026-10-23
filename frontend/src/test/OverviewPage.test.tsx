import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { OverviewPage } from "../pages/OverviewPage";
import { GuidedModeProvider } from "../components/GuidedMode";
import { api } from "../services/api";

/**
 * Overview (ADR-124).
 *
 * This is the page most likely to be read as a claim about the network
 * rather than about the store, so what it must never do:
 *
 *   * present a registered device as a monitored one;
 *   * let a DNS observation be counted as a connection;
 *   * swallow a refusal and look like a button that did nothing.
 */

function stats(total = 0) {
  return {
    total_events: total,
    sources_count: 0,
    labels: {},
    event_types: {},
    data_categories: {},
  };
}

function renderPage(over: Partial<Record<string, unknown>> = {}) {
  vi.spyOn(api, "getHealth").mockResolvedValue({
    status: "healthy",
    app_name: "PraHari",
    app_version: "0.1.0",
    schema_version: "1.0.0",
    deployment_mode: "local",
    uptime_seconds: 10,
    database: { connected: true, path: "x", sources_count: 0, events_count: 0 },
    timestamp: new Date().toISOString(),
  } as never);
  vi.spyOn(api, "getEventStats").mockResolvedValue(
    (over.stats ?? stats()) as never,
  );
  vi.spyOn(api, "getLatestAnalysis").mockResolvedValue(null as never);
  vi.spyOn(api, "getSourceHealth").mockResolvedValue({
    evaluated_at: new Date().toISOString(),
    sources: [],
    counts_by_state: {},
    fresh_threshold_seconds: 60,
    stale_threshold_seconds: 600,
    notes: [],
  } as never);
  vi.spyOn(api, "getCollectorStatus").mockResolvedValue({
    state: "stopped",
    platform_supported: false,
    platform_name: "Linux",
    source_id: "windows_local_host",
  } as never);
  const conns = (over.connections ?? []) as unknown[];
  vi.spyOn(api, "getConnections").mockResolvedValue({
    total: conns.length, limit: 6, offset: 0, returned: conns.length,
    connections: conns, filters_applied: {}, enrichment_note: "",
  } as never);
  vi.spyOn(api, "getDnsObservations").mockResolvedValue({
    total_stored: 0, returned: 0, observations: [], method_filter: null, note: "",
  } as never);

  return render(
    <GuidedModeProvider>
      <OverviewPage
        onNavigateToImport={() => {}}
        onRefreshAll={() => {}}
        onNavigate={() => {}}
      />
    </GuidedModeProvider>,
  );
}

beforeEach(() => vi.spyOn(console, "error").mockImplementation(() => {}));
afterEach(() => vi.restoreAllMocks());

describe("overview", () => {
  it("says registering a device is not monitoring it", async () => {
    renderPage();
    await waitFor(() =>
      expect(screen.getByText("Registered sources")).toBeInTheDocument(),
    );
    expect(
      screen.getByText(/does not start monitoring/i),
    ).toBeInTheDocument();
  });

  it("counts DNS observations apart from connections", async () => {
    // A resolved name is evidence of a lookup, never of a connection.
    renderPage();
    await waitFor(() =>
      expect(screen.getByText("DNS observations")).toBeInTheDocument(),
    );
    expect(screen.getByText("Stored connections")).toBeInTheDocument();
    expect(screen.getByText(/not of a connection/i)).toBeInTheDocument();
  });

  it("reports a collector that cannot run on this platform", async () => {
    renderPage();
    await waitFor(() =>
      expect(
        screen.getByText(/No connection collector exists for Linux/i),
      ).toBeInTheDocument(),
    );
  });

  it("shows why a sample import was refused instead of going quiet", async () => {
    // The specific regression: this was a console.error and nothing
    // else, so a deliberate refusal looked like a dead button.
    vi.spyOn(api, "importRawCsv").mockRejectedValue(
      new Error(
        "Refusing to import into the operational telemetry database. " +
          "Use POST /api/v1/research/import/csv instead.",
      ),
    );
    renderPage();

    await waitFor(() =>
      expect(screen.getByRole("button", { name: /Load sample data/i })).toBeEnabled(),
    );
    fireEvent.click(screen.getByRole("button", { name: /Load sample data/i }));

    await waitFor(() => {
      expect(screen.getByRole("alert")).toHaveTextContent(
        /Use POST \/api\/v1\/research\/import\/csv/,
      );
    });
  });

  it("names the sample data as sample, under its own source id", async () => {
    renderPage();
    await waitFor(() =>
      expect(screen.getByText(/No telemetry stored yet/i)).toBeInTheDocument(),
    );
    expect(screen.getByText(/soc_perimeter_sensor/)).toBeInTheDocument();
    expect(screen.getByText(/never mix/i)).toBeInTheDocument();
  });

  it("offers no sample-data prompt once telemetry exists", async () => {
    renderPage({ stats: stats(1200) });
    await waitFor(() =>
      expect(screen.getByText("Stored connections")).toBeInTheDocument(),
    );
    expect(screen.queryByText(/No telemetry stored yet/i)).toBeNull();
  });

  it("does not print a direction and its absent confidence as one word", async () => {
    // Rendered as "Unknownnone": the value and the qualifier ran
    // together, and "none" beside "Unknown" states the same absence
    // twice (ADR-124).
    const connection = [
        {
          event: {
            event_id: "e1", source_id: "s", observed_at: "2026-10-22T12:00:00.000Z",
            src_ip: "10.0.0.1", dst_ip: "10.0.0.2", src_port: 5000, dst_port: 443,
            protocol: "TCP",
          },
          connection_state: null, process_name: null, process_id: null,
          domain_attribution: null,
          direction: {
            direction: "unknown", confidence: "none",
            method: "no_local_perspective", reason: "Not collected on this host",
            limitations: [],
          },
          source_type: "csv_import", unsupported_fields: [], source_limitations: [],
        },
    ];

    renderPage({ stats: stats(1), connections: connection });

    await waitFor(() => expect(screen.getByText("Unknown")).toBeInTheDocument());
    expect(screen.queryByText(/Unknownnone/)).toBeNull();
    expect(screen.queryByText("none")).toBeNull();
  });
});
