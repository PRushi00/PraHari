import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { render, screen, waitFor, fireEvent } from "@testing-library/react";
import { InvestigationPage } from "../pages/InvestigationPage";
import { api } from "../services/api";

/**
 * Investigation view (blueprint §11, ADR-109).
 *
 * The risk here is not layout, it is a table of numbers that reads as an
 * explanation when it is not one. `value x GLOBAL importance` says
 * nothing about why THIS window scored as it did, so these pin:
 *
 *   * the attribution limitations render WITH the numbers, not behind a
 *     disclosure and not omitted;
 *   * a model with no comparable feature rows shows the reason instead
 *     of an empty or invented table;
 *   * a truncated window still reports the whole-window count, and says
 *     which is which;
 *   * an evaluation that issued no warnings says so, rather than
 *     rendering an empty page that looks broken.
 */

const eventLevel = {
  available: true,
  refusal_reason: null,
  model_id: "baseline_threshold",
  warnings_detail: [
    {
      warning_index: 0,
      issued_at: "2026-10-21T12:02:00.000Z",
      last_window_at: "2026-10-21T12:03:00.000Z",
      windows: 3,
      peak_score: 0.9123,
      outcome: "detection",
      matched_event_index: 0,
      lead_time_seconds: 45,
    },
  ],
};

const baseInvestigation = {
  available: true,
  refusal_reason: null,
  model_id: "baseline_threshold",
  warning_index: 0,
  outcome: "detection",
  issued_at: "2026-10-21T12:02:00.000Z",
  last_window_at: "2026-10-21T12:03:00.000Z",
  windows: 3,
  peak_score: 0.9123,
  matched_event_index: 0,
  lead_time_seconds: 45,
  window_event_count: 12,
  window_events_shown: 12,
  window_events: [
    {
      event_id: "evt-1",
      source_id: "host-a",
      observed_at: "2026-10-21T12:02:10.000Z",
      event_type: "connection",
      data_category: "live_telemetry",
      schema_version: "1.0.0",
      label: null,
    },
  ],
  window_truncated: false,
  contributions: [
    { feature: "event_rate", value: 42, importance_weight: 0.3, impact: 12.6 },
    { feature: "distinct_dst_ips", value: 8, importance_weight: 0.08, impact: 0.64 },
  ],
  contributions_available: true,
  contributions_unavailable_reason: null,
  attribution_method:
    "feature value x the model's GLOBAL feature importance, the same attribution the live prediction path uses.",
  attribution_limitations: [
    "This is not a local explanation. The importance is computed over the whole training set.",
    "A real local attribution (SHAP, or permutation on this row) would be a different measurement and is not implemented.",
  ],
  sources: [
    {
      source_id: "host-a",
      events_in_window: 12,
      first_at: "2026-10-21T12:02:05.000Z",
      last_at: "2026-10-21T12:02:58.000Z",
    },
  ],
  related_before: [],
  related_after: [],
  related_window_seconds: 300,
  notes: [],
};

beforeEach(() => {
  vi.spyOn(api, "evaluateEventLevel").mockResolvedValue(eventLevel as never);
  vi.spyOn(api, "investigateWarning").mockResolvedValue(
    baseInvestigation as never,
  );
});

afterEach(() => {
  vi.restoreAllMocks();
});

async function openFirstWarning() {
  render(<InvestigationPage />);
  fireEvent.click(screen.getByText("Load warnings"));
  await waitFor(() => {
    expect(screen.getByText("Investigate")).toBeInTheDocument();
  });
  fireEvent.click(screen.getByText("Investigate"));
}

describe("Investigation view", () => {
  it("lists the warnings an evaluation issued", async () => {
    render(<InvestigationPage />);
    fireEvent.click(screen.getByText("Load warnings"));

    await waitFor(() => {
      expect(screen.getByText("detection")).toBeInTheDocument();
    });
    expect(screen.getByText("0.9123")).toBeInTheDocument();
  });

  it("renders the attribution limitations with the numbers", async () => {
    // Without these the table reads as a local explanation and misleads.
    await openFirstWarning();

    await waitFor(() => {
      expect(screen.getByText(/event_rate/)).toBeInTheDocument();
    });
    expect(screen.getByText(/not a local explanation/)).toBeInTheDocument();
    expect(screen.getByText(/SHAP/)).toBeInTheDocument();
    expect(screen.getByText(/GLOBAL feature importance/)).toBeInTheDocument();
  });

  it("shows the reason when a model has no comparable feature rows", async () => {
    vi.spyOn(api, "investigateWarning").mockResolvedValue({
      ...baseInvestigation,
      model_id: "lstm_forecaster",
      contributions: [],
      contributions_available: false,
      contributions_unavailable_reason:
        "Model 'lstm_forecaster' has no comparable feature rows in the holdout.",
    } as never);

    await openFirstWarning();

    await waitFor(() => {
      expect(
        screen.getByText(/no comparable feature rows in the holdout/),
      ).toBeInTheDocument();
    });
  });

  it("distinguishes the whole-window count from the shown subset", async () => {
    vi.spyOn(api, "investigateWarning").mockResolvedValue({
      ...baseInvestigation,
      window_event_count: 240,
      window_events_shown: 200,
      window_truncated: true,
    } as never);

    await openFirstWarning();

    await waitFor(() => {
      expect(screen.getByText(/Input window — 240 events/)).toBeInTheDocument();
    });
    expect(
      screen.getByText(/the whole window, not the shown subset/),
    ).toBeInTheDocument();
  });

  it("shows which sources contributed to the window", async () => {
    await openFirstWarning();

    await waitFor(() => {
      expect(screen.getByText("host-a")).toBeInTheDocument();
    });
  });

  it("reports an evaluation that issued no warnings as a result", async () => {
    vi.spyOn(api, "evaluateEventLevel").mockResolvedValue({
      ...eventLevel,
      warnings_detail: [],
    } as never);

    render(<InvestigationPage />);
    fireEvent.click(screen.getByText("Load warnings"));

    await waitFor(() => {
      expect(
        screen.getByText(/issued no warnings at the operating point/),
      ).toBeInTheDocument();
    });
  });

  it("surfaces a refusal from the backend", async () => {
    vi.spyOn(api, "evaluateEventLevel").mockResolvedValue({
      available: false,
      refusal_reason: "The holdout contains no evaluated windows.",
      warnings_detail: [],
    } as never);

    render(<InvestigationPage />);
    fireEvent.click(screen.getByText("Load warnings"));

    await waitFor(() => {
      expect(
        screen.getByText(/The holdout contains no evaluated windows/),
      ).toBeInTheDocument();
    });
  });
});
