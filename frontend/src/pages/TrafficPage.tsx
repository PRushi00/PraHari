// Traffic Explorer — connections, filterable, with direction (§11, ADR-122).
//
// What this page is careful about, and why:
//
//   * **Direction is an inference and says so.** The connection table
//     does not report who opened the socket. A column reading
//     "Outbound" is read as fact, so every value carries its method and
//     an `unknown` is rendered as a real answer rather than a blank.
//   * **`unknown` is filterable.** It is the set PraHari declined to
//     call, which is the set worth auditing — hiding it behind "no
//     filter" would make the declines invisible.
//   * **No bytes, no packets, no bandwidth** unless the record actually
//     carries them. The Windows connection table measures none of it,
//     and a column of blanks invites someone to fill it.

import React, { useCallback, useEffect, useState } from "react";
import { AlertTriangle, Filter, RefreshCw } from "lucide-react";
import { api } from "../services/api";
import {
  ConnectionDetail,
  PaginatedConnectionsResponse,
  TrafficDirection,
} from "../types";
import { Explain } from "../components/GuidedMode";
import { fmtTime, humanise } from "../utils/format";

const DIRECTIONS: { value: "" | TrafficDirection; label: string }[] = [
  { value: "", label: "Any direction" },
  { value: "outbound", label: "Outbound" },
  { value: "inbound", label: "Inbound" },
  { value: "local", label: "Local (loopback)" },
  { value: "unknown", label: "Unknown — not inferable" },
];

const DIRECTION_COLOUR: Record<TrafficDirection, string> = {
  outbound: "#38bdf8",
  inbound: "#f59e0b",
  local: "#a78bfa",
  unknown: "#94a3b8",
};

/** The direction cell: the verdict, and how it was reached. */
const DirectionCell: React.FC<{ record: ConnectionDetail }> = ({ record }) => {
  const assessment = record.direction;
  if (!assessment) {
    return <span className="metric-unavailable">not assessed</span>;
  }
  return (
    <span
      style={{ color: DIRECTION_COLOUR[assessment.direction] }}
      // The method and reason are the difference between a verdict and
      // a claim. They travel with the cell rather than a legend.
      title={`${assessment.reason}\n\nMethod: ${assessment.method}${
        assessment.limitations.length
          ? `\n\n${assessment.limitations.join("\n")}`
          : ""
      }`}
    >
      {humanise(assessment.direction)}
      {assessment.confidence === "inferred" && (
        <span className="cell-note">inferred</span>
      )}
      {assessment.confidence === "observed" && (
        <span className="cell-note">observed</span>
      )}
    </span>
  );
};

export const TrafficPage: React.FC = () => {
  const [page, setPage] = useState<PaginatedConnectionsResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [direction, setDirection] = useState<string>("");
  const [dstIp, setDstIp] = useState("");
  const [dstPort, setDstPort] = useState("");
  const [protocol, setProtocol] = useState("");
  const [process, setProcess] = useState("");
  const [hostname, setHostname] = useState("");

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      setPage(
        await api.getConnections({
          direction: direction || undefined,
          dst_ip: dstIp || undefined,
          dst_port: dstPort ? Number(dstPort) : undefined,
          protocol: protocol || undefined,
          process: process || undefined,
          hostname: hostname || undefined,
          limit: 200,
        }),
      );
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, [direction, dstIp, dstPort, protocol, process, hostname]);

  useEffect(() => {
    load();
  }, [load]);

  const rows = page?.connections ?? [];

  return (
    <div className="page-container">
      <div className="page-header">
        <div>
          <h1 className="page-title">
            <Filter size={20} /> Traffic Explorer
          </h1>
          <p className="page-subtitle">
            Every stored connection, filterable by direction, address, port,
            protocol, process and attributed hostname.
          </p>
          <Explain>
            One row per network connection PraHari has recorded. Direction is
            worked out from the port numbers rather than observed directly, so
            each value says how it was decided — hover it to see.
          </Explain>
        </div>
        <button className="btn" onClick={load} disabled={loading}>
          <RefreshCw size={14} className={loading ? "spin" : ""} />{" "}
          {loading ? "Loading…" : "Refresh"}
        </button>
      </div>

      <section className="panel">
        <div className="form-row">
          <label>
            Direction
            <select
              className="form-select"
              value={direction}
              onChange={(e) => setDirection(e.target.value)}
            >
              {DIRECTIONS.map((d) => (
                <option key={d.value} value={d.value}>
                  {d.label}
                </option>
              ))}
            </select>
          </label>
          <label>
            Destination address
            <input
              className="form-input"
              value={dstIp}
              onChange={(e) => setDstIp(e.target.value)}
              placeholder="93.184."
            />
          </label>
          <label>
            Destination port
            <input
              className="form-input"
              value={dstPort}
              onChange={(e) => setDstPort(e.target.value)}
              placeholder="443"
              inputMode="numeric"
            />
          </label>
          <label>
            Protocol
            <input
              className="form-input"
              value={protocol}
              onChange={(e) => setProtocol(e.target.value)}
              placeholder="TCP"
            />
          </label>
          <label>
            Process
            <input
              className="form-input"
              value={process}
              onChange={(e) => setProcess(e.target.value)}
              placeholder="chrome"
            />
          </label>
          <label>
            Hostname
            <input
              className="form-input"
              value={hostname}
              onChange={(e) => setHostname(e.target.value)}
              placeholder="example.com"
            />
          </label>
        </div>
        <p className="panel-note">
          <strong>Unknown is a filter value, not an absence.</strong> It selects
          the connections PraHari declined to call — the set worth auditing.
        </p>
      </section>

      {error && (
        <div className="status-banner status-error" role="alert">
          <AlertTriangle size={16} /> {error}
        </div>
      )}

      {page && (
        <section className="panel">
          <div className="panel-header">
            <h3>
              {page.returned} of {page.total} connection
              {page.total === 1 ? "" : "s"}
            </h3>
          </div>

          {rows.length === 0 ? (
            <p className="host-devices-empty">
              No connection matches these filters. If nothing matches without
              filters either, no telemetry has been collected yet.
            </p>
          ) : (
            <div className="table-container">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Observed</th>
                    <th>Direction</th>
                    <th>Source</th>
                    <th>Destination</th>
                    <th>Port</th>
                    <th>Protocol</th>
                    <th>Process</th>
                    <th>Hostname</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((r) => (
                    <tr key={r.event.event_id}>
                      <td>{fmtTime(r.event.observed_at)}</td>
                      <td>
                        <DirectionCell record={r} />
                      </td>
                      <td>
                        <code>{r.event.src_ip ?? "—"}</code>
                        {r.event.src_port ? `:${r.event.src_port}` : ""}
                      </td>
                      <td>
                        <code>{r.event.dst_ip ?? "—"}</code>
                      </td>
                      <td>{r.event.dst_port ?? "—"}</td>
                      <td>{r.event.protocol ?? "—"}</td>
                      <td>
                        {r.process_name ?? (
                          <span className="metric-unavailable">not reported</span>
                        )}
                      </td>
                      <td>
                        {r.domain_attribution?.hostname ? (
                          <>
                            {r.domain_attribution.hostname}
                            <div className="cell-note">
                              {humanise(r.domain_attribution.method)} ·{" "}
                              {r.domain_attribution.confidence}
                            </div>
                          </>
                        ) : (
                          <span className="metric-unavailable">unknown</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {/* No bytes, packets or bandwidth columns. The Windows
              connection table measures none of them, and a column of
              blanks invites someone to fill it (ADR-118). */}
          <p className="panel-note">{page.enrichment_note}</p>
        </section>
      )}
    </div>
  );
};
