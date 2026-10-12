import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { render, screen, waitFor, fireEvent } from "@testing-library/react";
import { App } from "../App";
import { api } from "../services/api";

/**
 * Navigation regression tests.
 *
 * Reported failure: opening Feasibility blanked the entire application and
 * only a page reload recovered it. These tests walk every tab and assert
 * that the shell survives, including when the API returns empty data or
 * fails outright.
 */

const TABS = [
  "Overview",
  "Live Telemetry",
  "CSV Import",
  "Stream & Replay",
  "Events Explorer",
  "Analytics",
  "Feasibility",
  "Threat Forecasting",
  "Audit & Security",
];

/** Minimal valid responses matching the real backend contracts. */
function mockApiWithData() {
  vi.spyOn(api, "getHealth").mockResolvedValue({
    status: "healthy",
    app_name: "PraHari",
    app_version: "0.1.0",
    schema_version: "1.0.0",
    deployment_mode: "local",
    uptime_seconds: 10,
    database: { connected: true, path: "x", sources_count: 1, events_count: 3 },
    timestamp: new Date().toISOString(),
  } as any);
  vi.spyOn(api, "getSources").mockResolvedValue([]);
  vi.spyOn(api, "getEvents").mockResolvedValue({ total: 0, limit: 50, offset: 0, events: [] } as any);
  vi.spyOn(api, "getEventStats").mockResolvedValue({
    total_events: 0, sources_count: 0, labels: {}, event_types: {}, data_categories: {},
  } as any);
  vi.spyOn(api, "getLatestAnalysis").mockResolvedValue(null as any);
  vi.spyOn(api, "getImportHistory").mockResolvedValue([]);
  vi.spyOn(api, "getResearchReport").mockResolvedValue(null as any);
  vi.spyOn(api, "getForecastingModels").mockResolvedValue({} as any);
  vi.spyOn(api, "getForecastReadiness").mockResolvedValue({
    state: "insufficient_data",
    can_train: false,
    can_serve_validated_forecast: false,
    summary: "Insufficient data.",
    requirements: [],
    unmet_requirements: ["sufficient_events"],
    next_steps: ["Collect more telemetry."],
    total_events: 3,
    implausible_timestamp_events: 0,
    labelled_events: 0,
    positive_events: 0,
    negative_events: 0,
    time_span_seconds: 10,
    data_categories: {},
    label_provenances: {},
    prediction_target: "Binary: will an attack occur in the horizon?",
    prediction_horizon_seconds: 60,
    observation_window_seconds: 60,
    lead_time_seconds: 30,
    evaluated_at: new Date().toISOString(),
  } as any);
  vi.spyOn(api, "getForecastIntegrity").mockResolvedValue(null as any);
  vi.spyOn(api, "getAuditLogs").mockResolvedValue([]);
  vi.spyOn(api, "getSecurityConfig").mockResolvedValue({
    app_name: "PraHari", app_version: "0.1.0", schema_version: "1.0.0",
    deployment_mode: "local", host_binding: "127.0.0.1", port: 8000,
    loopback_enforced: true, authentication_required: false,
    max_request_size_mb: 50, database_url: "sqlite", retention_days: 365,
    security_boundaries: {},
  } as any);
  vi.spyOn(api, "getCollectorStatus").mockResolvedValue({
    state: "stopped", platform_supported: true, platform_name: "Windows 11",
    source_id: "windows_local_host", source_type: "windows_connection_table",
    data_category: "live_telemetry", interval_seconds: 15, include_loopback: false,
    collected_tcp_states: ["Established"], started_at: null, stopped_at: null,
    last_poll_at: null, last_success_at: null, latest_event_observed_at: null,
    polls_attempted: 0, polls_succeeded: 0, polls_failed: 0, consecutive_failures: 0,
    records_observed_total: 0, events_accepted_total: 0, events_persisted_total: 0,
    duplicates_suppressed_total: 0, records_filtered_by_policy_total: 0,
    records_rejected_total: 0, rejection_reasons: {}, last_error: null,
    collection_gaps: [], capability_notes: ["Connection metadata only."],
  } as any);
  vi.spyOn(api, "getConnections").mockResolvedValue({
    total: 0, limit: 200, offset: 0, returned: 0, connections: [],
    filters_applied: {}, enrichment_note: "",
  } as any);
  vi.spyOn(api, "getEnrichmentStatus").mockResolvedValue({
    method: "dns_cache_observation", last_refresh_at: null, refresh_count: 0,
    observations_recorded: 0, total_observations_stored: 0,
    distinct_ips_with_evidence: 0, stale_after_seconds: 1800,
    cache_appears_unavailable: true, diagnosis: "DNS cache empty.",
    last_error: null, limitations: ["Inferred, not recorded."],
  } as any);
  vi.spyOn(api, "getSource").mockResolvedValue(null as any);
}

/** Every call rejects — the shell must still survive navigation. */
function mockApiAllFailing() {
  const boom = () => Promise.reject(new Error("HTTP 503: backend unavailable"));
  for (const key of Object.keys(api) as (keyof typeof api)[]) {
    if (typeof api[key] === "function") {
      vi.spyOn(api, key as any).mockImplementation(boom as any);
    }
  }
}

async function visitEveryTab() {
  for (const tab of TABS) {
    const button = screen.getByRole("button", { name: new RegExp(tab, "i") });
    fireEvent.click(button);
    // The application shell must remain mounted after every navigation.
    await waitFor(() => {
      expect(screen.getByText("PraHari")).toBeInTheDocument();
    });
    // A blank body is the exact reported failure.
    expect(document.body.textContent?.trim().length ?? 0).toBeGreaterThan(50);
  }
}

describe("Application navigation", () => {
  beforeEach(() => {
    vi.spyOn(console, "error").mockImplementation(() => {});
  });
  afterEach(() => vi.restoreAllMocks());

  it("renders every tab without blanking the application", async () => {
    mockApiWithData();
    render(<App />);
    await waitFor(() => expect(screen.getByText("PraHari")).toBeInTheDocument());
    await visitEveryTab();
  });

  it("survives navigating to every tab when every API call fails", async () => {
    mockApiAllFailing();
    render(<App />);
    await waitFor(() => expect(screen.getByText("PraHari")).toBeInTheDocument());
    await visitEveryTab();
  });

  it("returns to a working page after visiting Feasibility", async () => {
    mockApiWithData();
    render(<App />);
    await waitFor(() => expect(screen.getByText("PraHari")).toBeInTheDocument());

    fireEvent.click(screen.getByRole("button", { name: /Feasibility/i }));
    await waitFor(() =>
      expect(screen.getByText(/Research Feasibility Scorecard/i)).toBeInTheDocument()
    );

    // Previously this required a full page reload.
    fireEvent.click(screen.getByRole("button", { name: /Overview/i }));
    await waitFor(() => expect(screen.getByText("PraHari")).toBeInTheDocument());
    expect(screen.queryByText(/Research Feasibility Scorecard/i)).not.toBeInTheDocument();
  });

  it("keeps navigation usable when one page throws during render", async () => {
    mockApiWithData();
    // Force the Feasibility view to throw by breaking its contract.
    vi.spyOn(api, "getResearchReport").mockResolvedValue({
      dataset_id: "d",
      evaluated_at: "2026-10-12T08:00:00Z",
      gate_passed: false,
      overall_score: 0.5,
      recommendation: "REJECT_FORECASTING",
      checks: { not: "an array" },
      metrics: {},
    } as any);

    render(<App />);
    await waitFor(() => expect(screen.getByText("PraHari")).toBeInTheDocument());

    fireEvent.click(screen.getByRole("button", { name: /Feasibility/i }));
    await waitFor(() => expect(screen.getByText("PraHari")).toBeInTheDocument());

    // Navigation must still work, with or without the boundary engaging.
    fireEvent.click(screen.getByRole("button", { name: /Analytics/i }));
    await waitFor(() => expect(screen.getByText("PraHari")).toBeInTheDocument());
    expect(document.body.textContent?.trim().length ?? 0).toBeGreaterThan(50);
  });
});
