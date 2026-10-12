import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { render, screen, waitFor, fireEvent } from "@testing-library/react";
import { StreamReplayPage } from "../pages/StreamReplayPage";
import { ErrorBoundary } from "../components/ErrorBoundary";
import { api } from "../services/api";

/**
 * Regression tests for the confirmed Stream & Replay crash.
 *
 * `TypeError: Cannot read properties of undefined (reading 'toFixed')` —
 * the page read `duration_seconds` and `simulated_attack_ratio` from the
 * replay response, but POST /stream/replay/synthetic returns an
 * ImportSummary, which has neither.
 */

/** The response the backend genuinely returns. */
const importSummary = {
  import_id: "11111111-2222-3333-4444-555555555555",
  source_id: "synthetic_replay_engine",
  source_file: "<synthetic_generator>",
  data_category: "synthetic_demo",
  started_at: "2026-10-12T08:00:00.000Z",
  completed_at: "2026-10-12T08:00:00.350Z",
  total_records: 200,
  accepted_records: 200,
  rejected_records: 0,
  warnings_count: 0,
  rejection_reasons: {},
  schema_version: "1.0.0",
};

const adapterHealth = [
  {
    adapter_id: "windows_local_host",
    adapter_type: "windows_connection_table",
    is_healthy: true,
    last_active_at: "2026-10-12T08:00:00.000Z",
    records_processed: 56,
    records_rejected: 0,
    error_message: null,
  },
];

describe("StreamReplayPage", () => {
  beforeEach(() => {
    vi.spyOn(console, "error").mockImplementation(() => {});
    vi.spyOn(api, "getStreamAdapters").mockResolvedValue(adapterHealth as any);
  });
  afterEach(() => vi.restoreAllMocks());

  it("renders adapter health from the real contract", async () => {
    render(<StreamReplayPage />);
    await waitFor(() =>
      expect(screen.getByText("windows_local_host")).toBeInTheDocument()
    );
    expect(screen.getByText(/WINDOWS_CONNECTION_TABLE/i)).toBeInTheDocument();
    expect(screen.getByText("HEALTHY")).toBeInTheDocument();
  });

  it("renders the replay result without crashing on the real response", async () => {
    vi.spyOn(api, "replaySyntheticFlows").mockResolvedValue(importSummary as any);

    render(<StreamReplayPage />);
    await waitFor(() =>
      expect(screen.getByRole("button", { name: /Generate & Seed Replay/i })).toBeInTheDocument()
    );

    fireEvent.click(screen.getByRole("button", { name: /Generate & Seed Replay/i }));

    await waitFor(() =>
      expect(screen.getByText(/Replay Batch Generated Successfully/i)).toBeInTheDocument()
    );
    // Elapsed is DERIVED from the summary's timestamps, not read from a
    // field that does not exist.
    expect(screen.getByText("350ms")).toBeInTheDocument();
    // 200 appears for both total and accepted records.
    expect(screen.getAllByText("200").length).toBeGreaterThanOrEqual(2);
    // Synthetic records stay labelled as such.
    expect(screen.getByText("synthetic_demo")).toBeInTheDocument();
  });

  it("does not crash when the replay response omits optional fields", async () => {
    vi.spyOn(api, "replaySyntheticFlows").mockResolvedValue({
      import_id: "x",
      source_id: "synthetic_replay_engine",
      data_category: "synthetic_demo",
      started_at: "2026-10-12T08:00:00.000Z",
      // completed_at, totals and counts all absent
    } as any);

    render(<StreamReplayPage />);
    await waitFor(() =>
      expect(screen.getByRole("button", { name: /Generate & Seed Replay/i })).toBeInTheDocument()
    );
    fireEvent.click(screen.getByRole("button", { name: /Generate & Seed Replay/i }));

    await waitFor(() =>
      expect(screen.getByText(/Replay Batch Generated Successfully/i)).toBeInTheDocument()
    );
    // Absent measurements render as N/A — never as a fabricated zero.
    expect(screen.getAllByText("N/A").length).toBeGreaterThan(0);
  });

  it("shows a recoverable error when the replay request fails", async () => {
    vi.spyOn(api, "replaySyntheticFlows").mockRejectedValue(
      new Error("HTTP 500: generator unavailable")
    );

    render(<StreamReplayPage />);
    await waitFor(() =>
      expect(screen.getByRole("button", { name: /Generate & Seed Replay/i })).toBeInTheDocument()
    );
    fireEvent.click(screen.getByRole("button", { name: /Generate & Seed Replay/i }));

    await waitFor(() =>
      expect(screen.getByText(/generator unavailable/i)).toBeInTheDocument()
    );
    // A failed request must not be presented as a success.
    expect(screen.queryByText(/Replay Batch Generated Successfully/i)).not.toBeInTheDocument();
  });

  it("renders when adapter health is empty", async () => {
    vi.spyOn(api, "getStreamAdapters").mockResolvedValue([] as any);
    render(<StreamReplayPage />);
    await waitFor(() =>
      expect(screen.getByText(/Streaming Ingestion & Synthetic Replay/i)).toBeInTheDocument()
    );
  });

  it("renders when adapter health fails to load", async () => {
    vi.spyOn(api, "getStreamAdapters").mockRejectedValue(new Error("adapters down"));
    render(<StreamReplayPage />);
    await waitFor(() =>
      expect(screen.getByText(/Streaming Ingestion & Synthetic Replay/i)).toBeInTheDocument()
    );
  });

  it("a contract break is contained rather than blanking the app", async () => {
    // Simulate a future regression: a numeric field becomes a string.
    vi.spyOn(api, "getStreamAdapters").mockResolvedValue([
      { ...adapterHealth[0], records_processed: "lots" },
    ] as any);

    render(
      <div>
        <nav>nav stays</nav>
        <ErrorBoundary pageName="Stream & Replay" resetKey="stream">
          <StreamReplayPage />
        </ErrorBoundary>
      </div>
    );

    await waitFor(() => expect(screen.getByText("nav stays")).toBeInTheDocument());
    const ok =
      screen.queryByText(/Streaming Ingestion/i) ??
      screen.queryByText(/failed to render/i);
    expect(ok).not.toBeNull();
  });
});
