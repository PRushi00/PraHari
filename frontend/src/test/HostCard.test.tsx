import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { HostCard } from "../components/HostCard";
import { ActivityChart } from "../components/ActivityChart";
import { fmtDuration } from "../utils/format";

/**
 * The host card and the activity chart (ADR-125).
 *
 * The trap in the host card is that there are two uptimes — the
 * machine's and this API process's — and they differ by hours. The
 * process's shown under a label reading "Uptime", beside a hostname and
 * an IP address, is read as the machine's.
 *
 * The trap in the chart is that a line implies continuity. Every point
 * must be counted from a stored record, and a gap must not be drawn as
 * though something were measured there.
 */

const HOST = {
  hostname: "PRAHARI-WIN",
  hostname_reason: null,
  local_ip: "192.168.1.24",
  local_ip_reason: null,
  operating_system: "Windows 11",
  host_uptime_seconds: 12_240, // 3h 24m
  host_uptime_reason: null,
  host_uptime_source: "psutil.boot_time",
  process_uptime_seconds: 95,
  measured_at: "2026-10-22T12:00:00.000Z",
  limitations: ["Identifies the machine PraHari runs on."],
};

const COLLECTOR = {
  state: "running",
  platform_supported: true,
  platform_name: "Windows",
  source_id: "windows_local_host",
} as never;

describe("host card", () => {
  it("shows what the machine is", () => {
    render(<HostCard host={HOST as never} collector={COLLECTOR} loading={false} />);

    expect(screen.getByText("PRAHARI-WIN")).toBeInTheDocument();
    expect(screen.getByText("192.168.1.24")).toBeInTheDocument();
    expect(screen.getByText("Windows 11")).toBeInTheDocument();
  });

  it("keeps the machine's uptime apart from the process's", () => {
    render(<HostCard host={HOST as never} collector={COLLECTOR} loading={false} />);

    expect(screen.getByText("Host uptime")).toBeInTheDocument();
    expect(screen.getByText("PraHari uptime")).toBeInTheDocument();
    expect(screen.getByText("3h 24m")).toBeInTheDocument();
    expect(screen.getByText("1m 35s")).toBeInTheDocument();
    // A bare "Uptime" is the label that caused the confusion.
    expect(screen.queryByText("Uptime")).toBeNull();
  });

  it("says why an uptime is missing instead of borrowing the other one", () => {
    const noUptime = {
      ...HOST,
      host_uptime_seconds: null,
      host_uptime_reason: "psutil is not installed and /proc/uptime does not exist",
      host_uptime_source: null,
    };
    render(<HostCard host={noUptime as never} collector={COLLECTOR} loading={false} />);

    expect(screen.getByText("not available")).toBeInTheDocument();
    // The process uptime must NOT be promoted into the host's row.
    expect(screen.queryByText("1m 35s")).toBeInTheDocument(); // its own row
    expect(screen.queryByText("0s")).toBeNull();
  });

  it("reports a collector that is not running without calling it an error", () => {
    render(
      <HostCard
        host={HOST as never}
        collector={{ ...(COLLECTOR as object), state: "stopped" } as never}
        loading={false}
      />,
    );
    expect(screen.getByText(/Collector not running/i)).toBeInTheDocument();
  });
});

describe("fmtDuration", () => {
  it("never renders an unmeasured duration as zero", () => {
    expect(fmtDuration(null)).toBe("N/A");
    expect(fmtDuration(undefined)).toBe("N/A");
    expect(fmtDuration(NaN)).toBe("N/A");
    expect(fmtDuration(-1)).toBe("N/A");
    // A real zero is still a real measurement.
    expect(fmtDuration(0)).toBe("0s");
  });

  it("reads the way a person would say it", () => {
    expect(fmtDuration(12_240)).toBe("3h 24m");
    expect(fmtDuration(95)).toBe("1m 35s");
    expect(fmtDuration(200_000)).toBe("2d 7h");
  });
});

function connAt(iso: string, direction = "outbound") {
  return {
    event: {
      event_id: `e-${iso}-${direction}`,
      source_id: "s",
      observed_at: iso,
      src_ip: "10.0.0.1",
      dst_ip: "10.0.0.2",
      src_port: 5000,
      dst_port: 443,
      protocol: "TCP",
    },
    connection_state: null,
    process_name: null,
    process_id: null,
    domain_attribution: null,
    direction: {
      direction,
      confidence: "inferred",
      method: "ephemeral_port_asymmetry",
      reason: "r",
      limitations: [],
    },
    source_type: "windows_connection_table",
    unsupported_fields: [],
    source_limitations: [],
  };
}

describe("activity chart", () => {
  it("says nothing to plot rather than drawing an empty axis", () => {
    render(<ActivityChart connections={[]} totalStored={0} loading={false} />);
    expect(screen.getByText(/Nothing to plot/i)).toBeInTheDocument();
    expect(screen.getByText(/statement about the store/i)).toBeInTheDocument();
  });

  it("counts from stored records and says how many", () => {
    const rows = [
      connAt("2026-10-22T12:00:10.000Z"),
      connAt("2026-10-22T12:00:20.000Z"),
      connAt("2026-10-22T12:02:00.000Z"),
    ];
    render(
      <ActivityChart connections={rows as never} totalStored={3} loading={false} />,
    );
    expect(
      screen.getByText(/counted from 3 stored records/i),
    ).toBeInTheDocument();
  });

  it("says when it is charting only part of the store", () => {
    const rows = [connAt("2026-10-22T12:00:10.000Z")];
    render(
      <ActivityChart connections={rows as never} totalStored={900} loading={false} />,
    );
    expect(screen.getByText(/of 900 — the most recent are charted/i)).toBeInTheDocument();
  });

  it("never presents an inferred direction as observed", () => {
    const rows = [connAt("2026-10-22T12:00:10.000Z")];
    render(
      <ActivityChart connections={rows as never} totalStored={1} loading={false} />,
    );
    expect(
      screen.getByText(/Direction is inferred, never observed/i),
    ).toBeInTheDocument();
  });

  it("ignores a record whose timestamp cannot be read", () => {
    // An unparseable time is not a zero and must not become a point.
    const rows = [connAt("not-a-date"), connAt("2026-10-22T12:00:10.000Z")];
    render(
      <ActivityChart connections={rows as never} totalStored={2} loading={false} />,
    );
    expect(screen.queryByText(/Nothing to plot/i)).toBeNull();
  });

  it("plots nothing when no record has a readable timestamp", () => {
    const rows = [connAt("not-a-date"), connAt("also-not-a-date")];
    render(
      <ActivityChart connections={rows as never} totalStored={2} loading={false} />,
    );
    expect(screen.getByText(/Nothing to plot/i)).toBeInTheDocument();
  });

  it("labels the window it drew, not N/A", async () => {
    // fmtTime takes an ISO string and these buckets are epoch millis,
    // so the header read "N/A – N/A" over a chart full of real points.
    const rows = [
      connAt("2026-10-22T12:00:10.000Z"),
      connAt("2026-10-22T12:05:10.000Z"),
    ];
    const { container } = render(
      <ActivityChart connections={rows as never} totalStored={2} loading={false} />,
    );
    const meta = container.querySelector(".panel-meta");
    expect(meta?.textContent ?? "").not.toMatch(/N\/A/);
    expect(meta?.textContent ?? "").toMatch(/\d/);
  });
});
