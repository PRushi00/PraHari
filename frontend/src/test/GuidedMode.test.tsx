import { describe, expect, it, beforeEach, afterEach, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import {
  Advanced,
  Caption,
  Explain,
  GuidedModeProvider,
  GuidedModeToggle,
  NextSteps,
} from "../components/GuidedMode";
import { LiveTelemetryPage } from "../pages/LiveTelemetryPage";
import { api } from "../services/api";

/**
 * Guided mode (blueprint §11, ADR-115).
 *
 * The risk in a "simpler view" is not layout, it is that the simpler
 * view quietly becomes a less honest one. PraHari's whole posture is
 * that it says what it does not know; a beginner mode that tucks the
 * caveats behind a chevron would invert that for exactly the reader
 * least able to notice.
 *
 * So these pin the boundary:
 *
 *   * `<Advanced>` defers dense diagnostics and nothing else — the
 *     capability limits and the collection-gap warning on Live
 *     Telemetry render in BOTH modes, unconditionally;
 *   * `<Caption>` is a translation of one number, never a second
 *     number;
 *   * expert mode restores the page exactly, with every panel open;
 *   * the preference survives a reload, and unreadable storage falls
 *     back to the default instead of throwing.
 */

function renderGuided(ui: React.ReactElement, guided = true) {
  try {
    window.localStorage.setItem("prahari.guidedMode", guided ? "on" : "off");
  } catch {
    /* the provider's own fallback is exercised separately */
  }
  return render(<GuidedModeProvider>{ui}</GuidedModeProvider>);
}

describe("guided mode mechanics", () => {
  afterEach(() => {
    try {
      window.localStorage.clear();
    } catch {
      /* nothing to clear */
    }
    vi.restoreAllMocks();
  });

  it("is on by default, so a newcomer gets help without knowing to ask", () => {
    render(
      <GuidedModeProvider>
        <GuidedModeToggle />
        <Explain>plain words here</Explain>
      </GuidedModeProvider>,
    );
    expect(screen.getByText("plain words here")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Guided/i })).toHaveAttribute(
      "aria-pressed",
      "true",
    );
  });

  it("hides explanations in expert mode and restores them when toggled back", () => {
    renderGuided(
      <>
        <GuidedModeToggle />
        <Explain>plain words here</Explain>
      </>,
    );
    fireEvent.click(screen.getByRole("button", { name: /Guided/i }));
    expect(screen.queryByText("plain words here")).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: /Guided/i }));
    expect(screen.getByText("plain words here")).toBeInTheDocument();
  });

  it("remembers the choice across a remount", () => {
    const first = renderGuided(<GuidedModeToggle />);
    fireEvent.click(screen.getByRole("button", { name: /Guided/i }));
    first.unmount();

    render(
      <GuidedModeProvider>
        <GuidedModeToggle />
      </GuidedModeProvider>,
    );
    expect(screen.getByRole("button", { name: /Guided/i })).toHaveAttribute(
      "aria-pressed",
      "false",
    );
  });

  it("falls back to guided when storage cannot be read", () => {
    vi.spyOn(Storage.prototype, "getItem").mockImplementation(() => {
      throw new Error("storage blocked");
    });
    render(
      <GuidedModeProvider>
        <Explain>plain words here</Explain>
      </GuidedModeProvider>,
    );
    expect(screen.getByText("plain words here")).toBeInTheDocument();
  });

  it("defers an advanced panel in guided mode and reveals it on request", () => {
    renderGuided(
      <Advanced title="Ingestion accounting" summary="7 seen">
        <p>dense counters</p>
      </Advanced>,
    );
    expect(screen.queryByText("dense counters")).not.toBeInTheDocument();
    expect(screen.getByText("7 seen")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: /Ingestion accounting/i }));
    expect(screen.getByText("dense counters")).toBeInTheDocument();
  });

  it("renders an advanced panel outright in expert mode, with no wrapper to open", () => {
    // The expert's page must be what it always was: no chevron, no click.
    renderGuided(
      <Advanced title="Ingestion accounting">
        <p>dense counters</p>
      </Advanced>,
      false,
    );
    expect(screen.getByText("dense counters")).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: /Ingestion accounting/i }),
    ).not.toBeInTheDocument();
  });

  it("translates a caption without changing the number it describes", () => {
    const { rerender } = renderGuided(
      <>
        <span>400</span>
        <Caption plain="Connections PraHari saved" expert="Normalized canonical flows" />
      </>,
    );
    expect(screen.getByText("Connections PraHari saved")).toBeInTheDocument();
    expect(screen.getByText("400")).toBeInTheDocument();

    rerender(
      <GuidedModeProvider>
        <span>400</span>
        <Caption plain="Connections PraHari saved" expert="Normalized canonical flows" />
      </GuidedModeProvider>,
    );
    expect(screen.getByText("400")).toBeInTheDocument();
  });

  it("shows next steps only in guided mode", () => {
    const onSelect = vi.fn();
    renderGuided(
      <NextSteps steps={[{ label: "Bring in data", detail: "Import a CSV.", onSelect }]} />,
    );
    fireEvent.click(screen.getByRole("button", { name: /Bring in data/i }));
    expect(onSelect).toHaveBeenCalledOnce();

    renderGuided(
      <NextSteps steps={[{ label: "Bring in data", detail: "Import a CSV.", onSelect }]} />,
      false,
    );
    // The first render is still mounted, so exactly one remains.
    expect(screen.getAllByRole("button", { name: /Bring in data/i })).toHaveLength(1);
  });
});

/* ---- The boundary that matters ----------------------------------- */

const status = {
  running: false,
  platform_supported: true,
  refusal_reason: null,
  source_id: "windows_local_host",
  interval_seconds: 5,
  records_observed_total: 120,
  events_accepted_total: 100,
  duplicates_suppressed_total: 15,
  records_filtered_by_policy_total: 3,
  records_rejected_total: 2,
  rejection_reasons: {},
  collection_gaps: [
    {
      started_at: "2026-10-21T10:00:00Z",
      ended_at: "2026-10-21T10:04:00Z",
      duration_seconds: 240,
    },
  ],
  capability_notes: [
    "No packet contents are read; only connection metadata is recorded.",
  ],
  collected_tcp_states: ["ESTABLISHED", "LISTEN"],
  include_loopback: false,
  data_category: "live_telemetry",
  last_poll_at: "2026-10-21T10:05:00Z",
  last_error: null,
};

describe("guided mode never hides a caveat", () => {
  beforeEach(() => {
    vi.spyOn(api, "getCollectorStatus").mockResolvedValue(status as never);
    vi.spyOn(api, "getConnections").mockResolvedValue({
      connections: [],
      total: 0,
      returned: 0,
    } as never);
    vi.spyOn(api, "getSource").mockResolvedValue(null as never);
    vi.spyOn(api, "getEnrichmentStatus").mockResolvedValue(null as never);
  });

  afterEach(() => {
    try {
      window.localStorage.clear();
    } catch {
      /* nothing to clear */
    }
    vi.restoreAllMocks();
  });

  it.each([true, false])(
    "shows the collection-gap warning with guided=%s",
    async (guided) => {
      // A gap is a hole in the evidence: a connection that opened and
      // closed inside one was never observed at all. Deferring that
      // behind a chevron would mislead the reader least equipped to
      // ask for it.
      renderGuided(<LiveTelemetryPage onDataChanged={() => undefined} />, guided);

      await waitFor(() => {
        expect(screen.getByText("Collection Gaps")).toBeInTheDocument();
      });
      expect(
        screen.getByText(/opened and closed\s+inside a gap were never observed/),
      ).toBeInTheDocument();
    },
  );

  it.each([true, false])(
    "shows the honest capability limits with guided=%s",
    async (guided) => {
      renderGuided(<LiveTelemetryPage onDataChanged={() => undefined} />, guided);

      await waitFor(() => {
        expect(
        screen.getByText(/What This Source Can and Cannot See/i),
      ).toBeInTheDocument();
      expect(
        screen.getByText(/never estimated/i),
      ).toBeInTheDocument();
      });
    },
  );
});
