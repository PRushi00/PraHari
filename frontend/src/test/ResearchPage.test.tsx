import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { render, screen, waitFor, fireEvent } from "@testing-library/react";
import { ResearchPage } from "../pages/ResearchPage";
import { ErrorBoundary } from "../components/ErrorBoundary";
import { api } from "../services/api";

/**
 * Regression tests for the Feasibility page.
 *
 * The page previously rendered an invented schema (`audit_id`,
 * `overall_feasibility_score`, `temporal_monotonicity`, …) that the backend
 * never produced, so `undefined.toFixed(1)` threw and blanked the app.
 * These tests use the REAL backend contract.
 */

/** A response matching backend app/research/feasibility.py exactly. */
const realReport = {
  dataset_id: "all_persisted_telemetry",
  evaluated_at: "2026-10-12T08:19:24.000Z",
  gate_passed: false,
  overall_score: 0.525,
  recommendation: "REJECT_FORECASTING",
  checks: [
    {
      check_name: "Temporal Monotonicity & Ordering",
      passed: true,
      score: 1.0,
      details: "Span: 99.0s. Temporal order ratio: 100.0%.",
      risk_level: "low",
    },
    {
      check_name: "Label Ground Truth & Balance",
      passed: false,
      score: 0.1,
      details: "No ground-truth labels are present on any of 210 events.",
      risk_level: "high",
    },
  ],
  metrics: { total_events: 210, attack_count: 0, benign_count: 0 },
};

describe("ResearchPage (Feasibility)", () => {
  beforeEach(() => {
    vi.spyOn(console, "error").mockImplementation(() => {});
    vi.spyOn(api, "getSources").mockResolvedValue([]);
  });
  afterEach(() => vi.restoreAllMocks());

  it("renders the real backend contract without crashing", async () => {
    vi.spyOn(api, "getResearchReport").mockResolvedValue(realReport as any);

    render(<ResearchPage />);

    await waitFor(() =>
      expect(screen.getByText("GATE NOT PASSED")).toBeInTheDocument()
    );
    // overall_score is 0..1 and rendered as a percentage.
    expect(screen.getByText("52.5%")).toBeInTheDocument();
    expect(screen.getByText("REJECT FORECASTING")).toBeInTheDocument();
    expect(screen.getByText(/Temporal Monotonicity/)).toBeInTheDocument();
    expect(screen.getByText(/Research Criteria \(1\/2 passed\)/)).toBeInTheDocument();
  });

  it("shows an empty state when no audit exists (null response)", async () => {
    vi.spyOn(api, "getResearchReport").mockResolvedValue(null as any);

    render(<ResearchPage />);

    await waitFor(() =>
      expect(screen.getByText(/No feasibility audit has been run yet/i)).toBeInTheDocument()
    );
    expect(screen.getByRole("button", { name: /Run Audit Now/i })).toBeInTheDocument();
  });

  it("shows a recoverable error state when the API fails", async () => {
    vi.spyOn(api, "getResearchReport").mockRejectedValue(new Error("HTTP 500: boom"));

    render(<ResearchPage />);

    await waitFor(() => expect(screen.getByText(/HTTP 500: boom/)).toBeInTheDocument());
    // Recoverable, not fatal.
    expect(screen.getByRole("button", { name: /Retry/i })).toBeInTheDocument();
  });

  it("still renders when the source list fails to load", async () => {
    vi.spyOn(api, "getSources").mockRejectedValue(new Error("sources down"));
    vi.spyOn(api, "getResearchReport").mockResolvedValue(realReport as any);

    render(<ResearchPage />);

    // One failing request must not take out the whole view.
    await waitFor(() => expect(screen.getByText("GATE NOT PASSED")).toBeInTheDocument());
  });

  it("tolerates a report with missing checks and metrics", async () => {
    vi.spyOn(api, "getResearchReport").mockResolvedValue({
      dataset_id: "d",
      evaluated_at: "2026-10-12T08:00:00Z",
      gate_passed: true,
      overall_score: 0.9,
      recommendation: "PERMIT_FORECASTING",
    } as any);

    render(<ResearchPage />);

    await waitFor(() => expect(screen.getByText("GATE PASSED")).toBeInTheDocument());
    expect(screen.getByText(/returned no individual criteria/i)).toBeInTheDocument();
  });

  it("tolerates a non-numeric overall_score instead of throwing", async () => {
    vi.spyOn(api, "getResearchReport").mockResolvedValue({
      ...realReport,
      overall_score: undefined,
    } as any);

    render(<ResearchPage />);

    // The exact failure that blanked the app must now render a dash.
    await waitFor(() => expect(screen.getByText("GATE NOT PASSED")).toBeInTheDocument());
    expect(screen.getAllByText("—").length).toBeGreaterThan(0);
  });

  it("an unexpected render failure is contained by the boundary", async () => {
    // Simulate a future contract break: checks is a string, not an array.
    vi.spyOn(api, "getResearchReport").mockResolvedValue({
      ...realReport,
      checks: "not-an-array",
      metrics: null,
    } as any);

    render(
      <div>
        <nav>nav stays</nav>
        <ErrorBoundary pageName="Feasibility" resetKey="research">
          <ResearchPage />
        </ErrorBoundary>
      </div>
    );

    await waitFor(() => expect(screen.getByText("nav stays")).toBeInTheDocument());
    // Either it rendered defensively, or the boundary caught it — never blank.
    const rendered =
      screen.queryByText("GATE NOT PASSED") ??
      screen.queryByText(/failed to render/i);
    expect(rendered).not.toBeNull();
  });

  it("runs an audit on demand and displays the result", async () => {
    vi.spyOn(api, "getResearchReport").mockResolvedValue(null as any);
    const runAudit = vi
      .spyOn(api, "runResearchAudit")
      .mockResolvedValue(realReport as any);

    render(<ResearchPage />);
    await waitFor(() =>
      expect(screen.getByRole("button", { name: /Run Audit Now/i })).toBeInTheDocument()
    );

    fireEvent.click(screen.getByRole("button", { name: /Run Audit Now/i }));

    await waitFor(() => expect(screen.getByText("GATE NOT PASSED")).toBeInTheDocument());
    expect(runAudit).toHaveBeenCalled();
  });
});
