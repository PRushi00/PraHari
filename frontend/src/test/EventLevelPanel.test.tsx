import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import { ForecastPage } from "../pages/ForecastPage";
import { api } from "../services/api";
import { EventLevelReport } from "../types";

/**
 * Event-level warning panel (blueprint §10, ADR-091).
 *
 * The window-level table and this panel answer different questions about
 * the same holdout, and the §11 honesty rules apply to both: a refusal
 * must read as a refusal, an unmeasured quartile must not render as a
 * number, and a lead time must never appear without the matching rules
 * that produced it.
 */

const rules = {
  episode_gap_seconds: 300,
  min_lead_seconds: 30,
  max_lead_seconds: 150,
  suppression_seconds: 300,
  threshold: 0.5,
  attack_label_rule: "a label is an ATTACK label when ...",
  event_time_origin: "The first attack-labelled record of the episode.",
  episode_rule: "Attack-labelled records no more than 300s apart are one event.",
  warning_rule: "A window scoring >= 0.5 opens a warning.",
  qualifying_rule: "A warning qualifies 30s to 150s before the event.",
  reuse_rule: "A warning is consumed by at most one event.",
  coverage_rule: "An event is in scope only when a window could have warned.",
  late_rule: "A warning inside an event's span is LATE.",
};

const report = (overrides: Partial<EventLevelReport> = {}): EventLevelReport =>
  ({
    available: true,
    refusal_reason: null,
    model_id: "random_forest_forecaster",
    rules,
    rules_fingerprint: "a".repeat(64),
    evaluated_windows: 284,
    first_prediction_at: "2026-06-01T12:00:00.000Z",
    last_prediction_at: "2026-06-01T13:10:45.000Z",
    evaluated_span_seconds: 4245,
    events_out_of_coverage: 5,
    events_total: 8,
    events_warned: 6,
    events_missed: 2,
    missed_event_rate: 0.25,
    lead_time: {
      count: 6,
      min_seconds: 45,
      p25_seconds: 60,
      median_seconds: 90,
      p75_seconds: 120,
      max_seconds: 150,
      mean_seconds: 94.2,
      quartiles_available: true,
      note: "",
    },
    positive_windows: 40,
    warnings_issued: 9,
    windows_per_warning: 4.4,
    alarm_duty_cycle: 0.14,
    detections: 6,
    late_warnings: 1,
    false_alarms: 2,
    false_alarms_per_hour: 1.7,
    label_provenance: ["dataset_ground_truth"],
    events: [],
    warnings_detail: [],
    limitations: ["An event's time origin is its first attack-LABELLED record."],
    ...overrides,
  }) as EventLevelReport;

beforeEach(() => {
  vi.spyOn(api, "getSources").mockResolvedValue([]);
  vi.spyOn(api, "getForecastingModels").mockResolvedValue({
    random_forest_forecaster: {
      model_name: "Random Forest Forecaster",
      model_type: "random_forest",
      precision: 0.8,
      recall: 0.7,
      f1_score: 0.75,
      pr_auc: 0.82,
      false_positive_rate: 0.05,
      train_instances: 100,
      test_instances: 40,
    } as never,
  });
  vi.spyOn(api, "getForecastReadiness").mockResolvedValue(null as never);
  vi.spyOn(api, "getForecastIntegrity").mockResolvedValue(null as never);
});

afterEach(() => {
  vi.restoreAllMocks();
});

async function measure() {
  render(<ForecastPage />);
  const button = await screen.findByRole("button", { name: /measure event-level/i });
  fireEvent.click(button);
}

describe("event-level warning panel", () => {
  it("reports events warned, not windows classified", async () => {
    vi.spyOn(api, "evaluateEventLevel").mockResolvedValue(report());
    await measure();

    const panel = await screen.findByTestId("event-level-report");
    expect(panel).toHaveTextContent("6 / 8");
    expect(panel).toHaveTextContent("25.0%");
  });

  it("shows the lead-time distribution, not only the median", async () => {
    vi.spyOn(api, "evaluateEventLevel").mockResolvedValue(report());
    await measure();

    const panel = await screen.findByTestId("event-level-report");
    expect(panel).toHaveTextContent(/min 45s/);
    expect(panel).toHaveTextContent(/p25 60s/);
    expect(panel).toHaveTextContent(/median 90s/);
    expect(panel).toHaveTextContent(/p75 120s/);
    expect(panel).toHaveTextContent(/max 150s/);
  });

  it("prints the refusal note instead of inventing quartiles", async () => {
    vi.spyOn(api, "evaluateEventLevel").mockResolvedValue(
      report({
        lead_time: {
          count: 2,
          min_seconds: 45,
          p25_seconds: null,
          median_seconds: 90,
          p75_seconds: null,
          max_seconds: 150,
          mean_seconds: 97.5,
          quartiles_available: false,
          note: "2 warned event(s): too few for quartiles.",
        },
      })
    );
    await measure();

    const panel = await screen.findByTestId("event-level-report");
    expect(panel).toHaveTextContent(/too few for quartiles/);
    expect(panel).not.toHaveTextContent(/p25/);
  });

  it("never shows a lead time without the rules that produced it", async () => {
    vi.spyOn(api, "evaluateEventLevel").mockResolvedValue(report());
    await measure();

    const panel = await screen.findByTestId("event-level-report");
    expect(panel).toHaveTextContent(/Matching rules/);
    expect(panel).toHaveTextContent(/30–150s before an event/);
    expect(panel).toHaveTextContent(/suppression 300s/);
    expect(panel).toHaveTextContent("a".repeat(12));
  });

  it("surfaces the alarm duty cycle so a low warning count cannot be misread", async () => {
    vi.spyOn(api, "evaluateEventLevel").mockResolvedValue(
      report({
        alarm_duty_cycle: 1.0,
        warnings_issued: 1,
        false_alarms: 1,
        events_warned: 0,
        events_missed: 8,
        missed_event_rate: 1.0,
        limitations: [
          "The alarm was active for 100% of the evaluated windows. Read the duty cycle, not the warning count.",
        ],
      })
    );
    await measure();

    const panel = await screen.findByTestId("event-level-report");
    expect(panel).toHaveTextContent("100.0%");
    expect(screen.getByTestId("event-level-limitations")).toHaveTextContent(
      /Read the duty cycle, not the warning count/
    );
  });

  it("renders a backend refusal as a refusal, not as an empty result", async () => {
    vi.spyOn(api, "evaluateEventLevel").mockRejectedValue(
      new Error("No attack-labelled record in the stream, so there is no documented event.")
    );
    await measure();

    const refusal = await screen.findByTestId("event-level-refusal");
    expect(refusal).toHaveTextContent(/no documented event/i);
    expect(screen.queryByTestId("event-level-report")).toBeNull();
  });

  it("states how many events lay outside the holdout's reach", async () => {
    vi.spyOn(api, "evaluateEventLevel").mockResolvedValue(report());
    await measure();

    const panel = await screen.findByTestId("event-level-report");
    expect(panel).toHaveTextContent(/5 event\(s\) lay outside/);
  });

  it("shows the aggregation that turned positive windows into warnings", async () => {
    vi.spyOn(api, "evaluateEventLevel").mockResolvedValue(report());
    await measure();

    const panel = await screen.findByTestId("event-level-report");
    expect(panel).toHaveTextContent(/40 positive window\(s\) aggregated into 9 warning\(s\)/);
  });
});
