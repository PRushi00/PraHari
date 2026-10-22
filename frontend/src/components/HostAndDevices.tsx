// This host / Other devices — the two-column summary (ADR-118).
//
// The honesty rule that shapes this component, and why it matters here
// more than anywhere else in the application:
//
// The design proposal this implements showed a device inventory with
// per-device traffic — "OnePlus-Phone ↑420 MB ↓210 MB", "Smart-TV
// ↑310 MB" — for devices with no agent and no sensor. Its own text
// forbade exactly that; its mock-up did it anyway, because an empty
// column looks like a bug and a plausible number does not.
//
// So: a device PraHari has not collected from HAS NO TRAFFIC FIGURES
// here. Knowing an address is not monitoring. What is rendered instead
// is the monitoring method and the evidence state, and where there is
// no evidence it says so — the same rule as `not measured` never being
// drawn as zero.

import React from "react";
import { Monitor, Network } from "lucide-react";
import { SourceHealthRecord } from "../types";
import { Explain } from "./GuidedMode";
import { humanise } from "../utils/format";

/**
 * How PraHari came to have records from a source. This is derived from
 * `source_type`, which the adapter registry defines — it is not a
 * separate field someone can set to flatter a device.
 */
export type MonitoringMethod = "host-agent" | "network-sensor" | "file-import" | "unknown";

const METHOD_BY_SOURCE_TYPE: Record<string, MonitoringMethod> = {
  windows_connection_table: "host-agent",
  windows_udp_endpoint: "host-agent",
  windows_interface_counters: "host-agent",
  application_layer: "host-agent",
  json_stream: "network-sensor",
  csv_import: "file-import",
  synthetic_replay: "file-import",
};

export function methodFor(sourceType: string): MonitoringMethod {
  return METHOD_BY_SOURCE_TYPE[sourceType] ?? "unknown";
}

const METHOD_LABEL: Record<MonitoringMethod, string> = {
  "host-agent": "Agent on the machine",
  "network-sensor": "Network sensor",
  "file-import": "Imported file",
  unknown: "Not established",
};

interface Props {
  /** Source health as the backend reports it. */
  sources: SourceHealthRecord[];
  /** The collector's own source id, when a collector is running here. */
  localSourceId: string | null;
  onOpenDevices: () => void;
}

export const HostAndDevices: React.FC<Props> = ({
  sources,
  localSourceId,
  onOpenDevices,
}) => {
  const local = localSourceId
    ? sources.find((s) => s.source_id === localSourceId) ?? null
    : null;

  // Everything that is not this machine and did not arrive as a file.
  // An imported CSV is evidence, but it is not a device being watched,
  // and counting it as one would overstate the deployment.
  const devices = sources.filter(
    (s) =>
      s.source_id !== localSourceId &&
      methodFor(s.source_type) !== "file-import" &&
      s.source_type !== "aggregate",
  );

  // Registered sources that are neither this host nor a device: imported
  // files, and the `all_sources` aggregate scope.
  const excluded = sources.length - devices.length - (local ? 1 : 0);

  return (
    <div className="host-devices">
      <section className="host-devices-col">
        <header className="host-devices-head">
          <Monitor size={18} />
          <h3>This host</h3>
          <span className="host-devices-count">{local ? 1 : 0}</span>
        </header>
        <Explain>
          The machine PraHari is running on. It can see its own network
          connections directly, without anything else being installed.
        </Explain>

        {local ? (
          <dl className="host-devices-facts">
            <dt>Source</dt>
            <dd>
              <code>{local.source_id}</code>
            </dd>
            <dt>State</dt>
            <dd>
              <span className={`badge badge-${local.state}`}>
                {humanise(local.state)}
              </span>
            </dd>
            <dt>Events stored</dt>
            <dd>{local.event_count}</dd>
            <dt>Last event</dt>
            <dd>
              {local.last_event_at ?? (
                <span className="metric-unavailable">none recorded</span>
              )}
            </dd>
          </dl>
        ) : (
          <p className="host-devices-empty">
            No collector is registered for this machine. Start it from{" "}
            <strong>Live Telemetry</strong> to record this host&apos;s own
            network connections.
          </p>
        )}
      </section>

      <section className="host-devices-col">
        <header className="host-devices-head">
          <Network size={18} />
          <h3>Other devices</h3>
          <span className="host-devices-count">{devices.length}</span>
        </header>
        <Explain>
          Other machines PraHari is collecting from. A device appears here
          once something reports on its behalf — an agent running on it, or
          a network sensor that can see its traffic.
        </Explain>

        {devices.length === 0 ? (
          <>
            <p className="host-devices-empty">
              No other device is registered. PraHari is watching this machine
              only.
            </p>
            {/* The honest empty state. Listing addresses found on the
                network — with traffic figures beside them — would be
                inventing evidence that does not exist. */}
            <p className="host-devices-empty">
              Knowing a device&apos;s address is not monitoring it: nothing on
              this network is observed until an agent or a sensor reports it.
            </p>
            <button className="btn btn-secondary" onClick={onOpenDevices}>
              Register a device
            </button>
          </>
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th>Device</th>
                <th>How it is monitored</th>
                <th>Events</th>
                <th>State</th>
              </tr>
            </thead>
            <tbody>
              {devices.map((d) => (
                <tr key={d.source_id}>
                  <td>
                    {d.name || <code>{d.source_id}</code>}
                    <div className="cell-note">
                      <code>{d.source_type}</code>
                    </div>
                  </td>
                  <td>{METHOD_LABEL[methodFor(d.source_type)]}</td>
                  <td>{d.event_count}</td>
                  <td>
                    <span className={`badge badge-${d.state}`}>
                      {humanise(d.state)}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        {/* No traffic column, in either branch. PraHari does not measure
            per-device bytes, and a column of blanks invites someone to
            fill it. */}

        {/* The stat card above counts SOURCES; this column counts
            DEVICES, and the two differ whenever a file has been
            imported. Both numbers are correct and a reader seeing "2
            sources" beside "0 devices" would reasonably doubt one of
            them, so the difference is named rather than left to be
            worked out. */}
        {excluded > 0 && (
          <p className="panel-note">
            {excluded} other registered source
            {excluded === 1 ? " is" : "s are"} not counted here: an imported
            file is evidence, but it is not a device being watched.
          </p>
        )}
      </section>
    </div>
  );
};
