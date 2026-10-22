import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import { HostAndDevices, methodFor } from "../components/HostAndDevices";
import { GuidedModeProvider } from "../components/GuidedMode";

/**
 * This host / Other devices (ADR-118).
 *
 * The design proposal this implements showed a device inventory with
 * per-device traffic — "OnePlus-Phone ↑420 MB ↓210 MB", "Smart-TV
 * ↑310 MB" — for devices with no agent and no sensor. Its own text
 * forbade that; its mock-up did it anyway, because an empty column
 * looks like a bug and a plausible number does not.
 *
 * PraHari does not measure per-device bytes. So these pin:
 *
 *   * no traffic or bandwidth figure is rendered for a device, in
 *     either the populated or the empty branch;
 *   * an unmonitored network is an explicit empty state that says
 *     knowing an address is not monitoring — not a blank table;
 *   * the monitoring method is DERIVED from `source_type`, so it
 *     cannot be set to flatter a device;
 *   * an imported file is not counted as a device.
 */

function source(over: Partial<Record<string, unknown>> = {}) {
  return {
    source_id: "host-a",
    name: "Workstation A",
    source_type: "windows_connection_table",
    state: "reporting",
    enabled: true,
    event_count: 120,
    last_event_at: "2026-10-22T07:00:00.000Z",
    fresh_threshold_seconds: 120,
    stale_threshold_seconds: 900,
    evaluated_at: "2026-10-22T07:01:00.000Z",
    ...over,
  } as never;
}

function renderPanel(sources: unknown[], localSourceId: string | null) {
  return render(
    <GuidedModeProvider>
      <HostAndDevices
        sources={sources as never}
        localSourceId={localSourceId}
        onOpenDevices={vi.fn()}
      />
    </GuidedModeProvider>,
  );
}

/** Anything that would read as a measured transfer volume. */
const TRAFFIC = /\b\d+(\.\d+)?\s?(B|KB|MB|GB|TB|Kbps|Mbps|Gbps)\b|[↑↓]/;

describe("host and devices panel", () => {
  it("renders no traffic figure for a device, because none is measured", () => {
    const { container } = renderPanel(
      [
        source(),
        source({
          source_id: "phone-1",
          name: "OnePlus-Phone",
          source_type: "json_stream",
          event_count: 42,
        }),
      ],
      "host-a",
    );

    expect(screen.getByText("OnePlus-Phone")).toBeInTheDocument();
    expect(container.textContent ?? "").not.toMatch(TRAFFIC);
  });

  it("says plainly that knowing an address is not monitoring", () => {
    renderPanel([source()], "host-a");

    expect(screen.getByText(/No other device is registered/)).toBeInTheDocument();
    expect(
      screen.getByText(/Knowing a device's address is not monitoring it/),
    ).toBeInTheDocument();
  });

  it("reports an absent local collector rather than implying one", () => {
    // Linux has no Windows connection-table collector. That is a state
    // to render, not to hide behind a zero.
    renderPanel([], null);

    expect(
      screen.getByText(/No collector is registered for this machine/),
    ).toBeInTheDocument();
  });

  it("does not count an imported file as a device", () => {
    renderPanel(
      [
        source(),
        source({
          source_id: "ids2018",
          name: "CIC-IDS2018 import",
          source_type: "csv_import",
          event_count: 400000,
        }),
      ],
      "host-a",
    );

    expect(screen.queryByText("CIC-IDS2018 import")).not.toBeInTheDocument();
    expect(screen.getByText(/No other device is registered/)).toBeInTheDocument();
  });

  it("derives the monitoring method from the source type", () => {
    // Not from a field a caller can set: a device does not become
    // monitored by being described as monitored.
    expect(methodFor("windows_connection_table")).toBe("host-agent");
    expect(methodFor("json_stream")).toBe("network-sensor");
    expect(methodFor("csv_import")).toBe("file-import");
    expect(methodFor("something_invented")).toBe("unknown");
  });

  it("shows an unrecognised source type as not established, never as monitored", () => {
    renderPanel(
      [source(), source({ source_id: "x", name: "Mystery", source_type: "whatever" })],
      "host-a",
    );

    expect(screen.getByText("Not established")).toBeInTheDocument();
  });
});

describe("source count versus device count", () => {
  it("names the sources it is not counting, so the two numbers reconcile", () => {
    // The Overview stat card counts SOURCES; this column counts
    // DEVICES. Seeing "2 sources" beside "0 devices" with no
    // explanation would make a reader doubt one of them.
    render(
      <GuidedModeProvider>
        <HostAndDevices
          sources={
            [
              source(),
              source({ source_id: "f", source_type: "csv_import", name: "Import" }),
              source({ source_id: "agg", source_type: "aggregate", name: "All" }),
            ] as never
          }
          localSourceId="host-a"
          onOpenDevices={vi.fn()}
        />
      </GuidedModeProvider>,
    );

    expect(
      screen.getByText(/2 other registered sources are not counted here/),
    ).toBeInTheDocument();
  });
});
