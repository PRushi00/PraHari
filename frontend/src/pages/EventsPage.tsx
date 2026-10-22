import React, { useState, useEffect } from "react";
import { Filter, Eye, X, ChevronLeft, ChevronRight, ShieldCheck, AlertOctagon } from "lucide-react";
import { api } from "../services/api";
import { NormalizedEvent } from "../types";

import { fmtTimeUtc, humanise } from "../utils/format";
export const EventsPage: React.FC = () => {
  const [events, setEvents] = useState<NormalizedEvent[]>([]);
  const [total, setTotal] = useState(0);
  const [limit] = useState(25);
  const [offset, setOffset] = useState(0);
  const [selectedLabel, setSelectedLabel] = useState<string>("");
  const [loading, setLoading] = useState(true);
  const [selectedEvent, setSelectedEvent] = useState<NormalizedEvent | null>(null);

  const fetchEvents = async () => {
    setLoading(true);
    try {
      const res = await api.getEvents({
        label: selectedLabel || undefined,
        limit,
        offset,
      });
      setEvents(res.events);
      setTotal(res.total);
    } catch (err) {
      console.error("Failed to load events:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchEvents();
  }, [offset, selectedLabel]);

  const handleLabelFilterChange = (lbl: string) => {
    setSelectedLabel(lbl);
    setOffset(0);
  };

  return (
    <div>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1.5rem" }}>
        <div>
          <h1 style={{ fontSize: "var(--text-xl)", letterSpacing: "-0.02em" }}>
            Canonical Security Events
          </h1>
          <p style={{ color: "var(--text-muted)", fontSize: "var(--text-xs)", marginTop: "0.2rem" }}>
            Query normalized telemetry with explicit provenance and quality assurance flags.
          </p>
        </div>

        {/* Filter controls */}
        <div style={{ display: "flex", gap: "0.5rem", alignItems: "center" }}>
          <Filter size={15} color="#94a3b8" />
          <select
            value={selectedLabel}
            onChange={(e) => handleLabelFilterChange(e.target.value)}
            style={{ width: "auto", minWidth: "160px" }}
          >
            <option value="">All Security Labels</option>
            <option value="Benign">Benign</option>
            <option value="SSH-BruteForce">SSH-BruteForce</option>
            <option value="DDoS-HOIC">DDoS-HOIC</option>
            <option value="PortScan">PortScan</option>
            <option value="FTP-BruteForce">FTP-BruteForce</option>
          </select>
        </div>
      </div>

      {/* Main Table */}
      <div className="glass-panel" style={{ padding: "1.25rem" }}>
        <div className="table-container">
          <table>
            <thead>
              <tr>
                <th>Observed At (UTC)</th>
                <th>Source IP : Port</th>
                <th>Destination IP : Port</th>
                <th>Proto</th>
                <th>Classification</th>
                <th>Quality Flags</th>
                <th style={{ textAlign: "right" }}>Inspect</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr>
                  <td colSpan={7} style={{ textAlign: "center", padding: "3rem", color: "var(--text-dim)" }}>
                    Loading events...
                  </td>
                </tr>
              ) : events.length > 0 ? (
                events.map((ev) => {
                  const isBenign = ev.label?.toLowerCase() === "benign";
                  return (
                    <tr key={ev.event_id} onClick={() => setSelectedEvent(ev)} style={{ cursor: "pointer" }}>
                      <td>{fmtTimeUtc(ev.observed_at, "—")}</td>
                      <td>
                        {ev.src_ip || "-"}:{ev.src_port ?? "-"}
                      </td>
                      <td>
                        {ev.dst_ip || "-"}:{ev.dst_port ?? "-"}
                      </td>
                      <td>{ev.protocol || "OTHER"}</td>
                      <td>
                        <span className={isBenign ? "badge badge-benign" : "badge badge-attack"}>
                          {isBenign ? <ShieldCheck size={11} /> : <AlertOctagon size={11} />}
                          {ev.label || "Unlabeled"}
                        </span>
                      </td>
                      <td>
                        {ev.quality_flags.length > 0 ? (
                          <div style={{ display: "flex", gap: "0.3rem", flexWrap: "wrap" }}>
                            {ev.quality_flags.map((qf) => (
                              <span key={qf} className="badge badge-warning">
                                {humanise(qf)}
                              </span>
                            ))}
                          </div>
                        ) : (
                          <span style={{ color: "var(--text-dim)", fontSize: "var(--text-2xs)" }}>Clean</span>
                        )}
                      </td>
                      <td style={{ textAlign: "right" }}>
                        <button
                          className="btn btn-secondary"
                          style={{ padding: "0.25rem 0.6rem", fontSize: "var(--text-2xs)" }}
                          onClick={(e) => {
                            e.stopPropagation();
                            setSelectedEvent(ev);
                          }}
                        >
                          <Eye size={12} />
                        </button>
                      </td>
                    </tr>
                  );
                })
              ) : (
                <tr>
                  <td colSpan={7} style={{ textAlign: "center", padding: "3rem", color: "var(--text-dim)" }}>
                    No events found matching current criteria.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination Bar */}
        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            marginTop: "1.25rem",
            paddingTop: "1rem",
            borderTop: "1px solid var(--border-subtle)",
          }}
        >
          <div style={{ fontSize: "var(--text-2xs)", color: "var(--text-dim)" }}>
            Showing {Math.min(offset + 1, total)} to {Math.min(offset + limit, total)} of {total} events
          </div>

          <div style={{ display: "flex", gap: "0.5rem" }}>
            <button
              className="btn btn-secondary"
              disabled={offset === 0}
              onClick={() => setOffset(Math.max(0, offset - limit))}
              style={{ padding: "0.35rem 0.75rem" }}
            >
              <ChevronLeft size={14} />
              Previous
            </button>
            <button
              className="btn btn-secondary"
              disabled={offset + limit >= total}
              onClick={() => setOffset(offset + limit)}
              style={{ padding: "0.35rem 0.75rem" }}
            >
              Next
              <ChevronRight size={14} />
            </button>
          </div>
        </div>
      </div>

      {/* Inspection Drawer */}
      {selectedEvent && (
        <div className="drawer-backdrop" onClick={() => setSelectedEvent(null)}>
          <div className="drawer" onClick={(e) => e.stopPropagation()}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1.5rem" }}>
              <h2 style={{ fontSize: "var(--text-lg)" }}>Canonical Event Inspector</h2>
              <button
                onClick={() => setSelectedEvent(null)}
                style={{ background: "none", border: "none", color: "var(--text-muted)", cursor: "pointer" }}
              >
                <X size={20} />
              </button>
            </div>

            <div style={{ marginBottom: "1.5rem" }}>
              <div style={{ fontSize: "var(--text-2xs)", color: "var(--text-dim)", textTransform: "uppercase" }}>Event ID</div>
              <div style={{ fontFamily: "var(--font-mono)", fontSize: "var(--text-xs)", wordBreak: "break-all", marginTop: "0.2rem" }}>
                {selectedEvent.event_id}
              </div>
            </div>

            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "1rem", marginBottom: "1.5rem" }}>
              <div>
                <div style={{ fontSize: "var(--text-2xs)", color: "var(--text-dim)" }}>Schema Version</div>
                <div style={{ fontWeight: 600 }}>{selectedEvent.schema_version}</div>
              </div>
              <div>
                <div style={{ fontSize: "var(--text-2xs)", color: "var(--text-dim)" }}>Data Category</div>
                <div style={{ fontWeight: 600 }}>{humanise(selectedEvent.data_category)}</div>
              </div>
              <div>
                <div style={{ fontSize: "var(--text-2xs)", color: "var(--text-dim)" }}>Observed Timestamp</div>
                <div style={{ fontSize: "var(--text-xs)", fontFamily: "var(--font-mono)" }}>
                  {new Date(selectedEvent.observed_at).toISOString()}
                </div>
              </div>
              <div>
                <div style={{ fontSize: "var(--text-2xs)", color: "var(--text-dim)" }}>Ingested Timestamp</div>
                <div style={{ fontSize: "var(--text-xs)", fontFamily: "var(--font-mono)" }}>
                  {new Date(selectedEvent.ingested_at).toISOString()}
                </div>
              </div>
            </div>

            <div style={{ marginBottom: "1.5rem", background: "rgba(15, 23, 42, 0.6)", padding: "1rem", borderRadius: "8px" }}>
              <h4 style={{ fontSize: "var(--text-md)", color: "var(--text-muted)", marginBottom: "0.5rem" }}>Flow Endpoints</h4>
              <div style={{ fontFamily: "var(--font-mono)", fontSize: "var(--text-xs)" }}>
                <div>Src: {selectedEvent.src_ip || "N/A"}:{selectedEvent.src_port ?? "N/A"}</div>
                <div>Dst: {selectedEvent.dst_ip || "N/A"}:{selectedEvent.dst_port ?? "N/A"}</div>
                <div>Protocol: {selectedEvent.protocol}</div>
                <div>Duration: {selectedEvent.duration} µs</div>
                <div>Packets: {selectedEvent.packets}</div>
                <div>Bytes: {selectedEvent.bytes_total}</div>
              </div>
            </div>

            <div style={{ marginBottom: "1.5rem" }}>
              <div style={{ fontSize: "var(--text-2xs)", color: "var(--text-dim)", marginBottom: "0.4rem" }}>Raw Audit Reference</div>
              <div style={{ fontFamily: "var(--font-mono)", fontSize: "var(--text-xs)", color: "#38bdf8" }}>
                {selectedEvent.raw_reference || "None"}
              </div>
            </div>

            <div>
              <div style={{ fontSize: "var(--text-2xs)", color: "var(--text-dim)", marginBottom: "0.5rem" }}>Full Canonical JSON</div>
              <pre
                style={{
                  background: "#080c14",
                  padding: "1rem",
                  borderRadius: "8px",
                  fontSize: "var(--text-2xs)",
                  fontFamily: "var(--font-mono)",
                  overflowX: "auto",
                  border: "1px solid var(--border-subtle)",
                }}
              >
                {JSON.stringify(selectedEvent, null, 2)}
              </pre>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
