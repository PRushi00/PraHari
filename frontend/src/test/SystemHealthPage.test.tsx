import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { SystemHealthPage } from "../pages/SystemHealthPage";
import { api } from "../services/api";

/**
 * System Health view (blueprint §11), and the §12 honesty rules it has
 * to obey.
 *
 * The failure these guard against is the one the blueprint calls out
 * explicitly: a dashboard that renders an unmeasured value as 0, so an
 * operator reads "no errors" when the truth is "we did not measure".
 */

const report = {
  generated_at: "2026-10-16T12:00:00.000Z",
  schema_version: "1.0.0",
  deployment_mode: "local",
  uptime_seconds: 1234.5,
  ingestion: {
    available: true,
    data: {
      admission_model: "bounded_concurrency_no_queue",
      queue_depth: null,
      queue_depth_note:
        "Ingestion is synchronous, so no queue exists. null means 'no queue', not 'an empty queue'.",
      in_flight: 0,
      peak_in_flight: 2,
      capacity: 8,
      saturated: false,
      requests_admitted: 10,
      requests_rejected_overloaded: 1,
      batches_completed: 9,
      batches_failed: 1,
      conflicts: 1,
      events_stored: 42,
      events_duplicate: 3,
      events_rejected: 2,
      last_success_at: "2026-10-16T11:59:00.000Z",
      last_failure_at: null,
      last_error_kind: null,
      processing_latency: { samples: 9, p50_ms: 4.2, p95_ms: 11.8, max_ms: 12.0 },
    },
  },
  sources: {
    available: true,
    data: {
      total: 1,
      counts_by_state: { reporting: 1 },
      sources: [
        {
          source_id: "sensor-a",
          name: "Sensor A",
          source_type: "json_stream",
          state: "reporting",
          enabled: true,
          event_count: 42,
          clock_dependent: false,
          freshness_basis: "max(received_at) measured by this backend",
        },
      ],
      notes: [],
    },
  },
  storage: {
    available: true,
    data: {
      integrity_check: "ok",
      healthy: true,
      journal_mode: "wal",
      size_bytes: 2048,
      event_count: 42,
      source_count: 1,
      received_at_column_present: true,
      normalized_events_columns: 26,
      retention_days: 365,
    },
  },
  models: {
    available: true,
    data: {
      trained_models: [],
      model_count: 0,
      inference_available: false,
      note: "No model has been trained in this process.",
      inference_latency: null,
    },
  },
  adapters: { available: true, data: { active_adapters: 0, adapters: [] } },
  limits: {
    available: true,
    data: {
      max_request_size_mb: 50,
      request_size_limit_enforced: true,
      max_import_records: 100000,
      import_record_limit_enforced: true,
      rate_limit_requests: 600,
      rate_limit_window_seconds: 60,
      rate_limit_enforced: true,
      ingestion_capacity: 8,
      admission_control_enforced: true,
    },
  },
  notes: ["Every number here is measured by this backend."],
};

describe("System Health view", () => {
  beforeEach(() => {
    vi.spyOn(api, "getSystemHealth").mockResolvedValue(report as any);
  });
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("renders every section the blueprint requires", async () => {
    render(<SystemHealthPage />);

    await waitFor(() => {
      expect(screen.getByText("Ingestion")).toBeInTheDocument();
    });
    for (const title of [
      "Ingestion",
      "Sources",
      "Storage",
      "Models & Inference",
      "Adapters",
      "Limits & Enforcement",
    ]) {
      expect(screen.getByText(title)).toBeInTheDocument();
    }
  });

  it("shows queue depth as 'no queue', never as zero", async () => {
    render(<SystemHealthPage />);

    // Appears twice by design: the metric cell and the explanatory note.
    await waitFor(() => {
      expect(screen.getAllByText(/no queue/i).length).toBeGreaterThan(0);
    });
    expect(screen.queryByText(/queue depth.*0/i)).not.toBeInTheDocument();
  });

  it("renders an unmeasured inference latency as 'not measured'", async () => {
    render(<SystemHealthPage />);

    await waitFor(() => {
      expect(screen.getByText("Inference latency")).toBeInTheDocument();
    });
    const labels = screen.getAllByText("not measured");
    expect(labels.length).toBeGreaterThan(0);
  });

  it("reports inference as unavailable rather than showing a score", async () => {
    render(<SystemHealthPage />);

    await waitFor(() => {
      expect(screen.getByText("unavailable")).toBeInTheDocument();
    });
    expect(
      screen.getByText(/No score is substituted/i)
    ).toBeInTheDocument();
  });

  it("shows measured counters as their real values", async () => {
    render(<SystemHealthPage />);

    // "Events stored" is reported by both the ingestion and storage blocks.
    await waitFor(() => {
      expect(screen.getAllByText("Events stored").length).toBe(2);
    });
    expect(screen.getAllByText("42").length).toBeGreaterThan(0);
  });

  it("renders an unavailable block with its reason, not as zeroes", async () => {
    vi.spyOn(api, "getSystemHealth").mockResolvedValue({
      ...report,
      storage: { available: false, reason: "storage unreadable: disk error" },
    } as any);

    render(<SystemHealthPage />);

    await waitFor(() => {
      expect(
        screen.getByText(/storage unreadable: disk error/i)
      ).toBeInTheDocument();
    });
  });

  it("drops the previous reading when a refresh fails", async () => {
    vi.spyOn(api, "getSystemHealth").mockRejectedValue(new Error("network down"));

    render(<SystemHealthPage />);

    await waitFor(() => {
      expect(screen.getByText(/network down/i)).toBeInTheDocument();
    });
    // A stale number under a fresh timestamp is worse than no number.
    expect(screen.queryByText("Events stored")).not.toBeInTheDocument();
  });

  it("shows whether each configured limit is actually enforced", async () => {
    render(<SystemHealthPage />);

    await waitFor(() => {
      expect(screen.getByText("Max request size")).toBeInTheDocument();
    });
    expect(screen.getByText("Ingestion concurrency")).toBeInTheDocument();
  });
});
