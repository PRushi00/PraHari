import React, { useCallback, useEffect, useState } from "react";
import { AlertTriangle, Globe, Info, RefreshCw } from "lucide-react";
import { api } from "../services/api";
import { AppLayerStatus, NormalizedEvent } from "../types";
import { fmtFixed, fmtTime } from "../utils/format";

/**
 * Application-layer telemetry panel.
 *
 * HTTP method, path, status and timing are NOT observable from the Windows
 * TCP connection table. They appear here only when an authorized
 * application-layer producer reports them, and the panel states plainly
 * which of the two situations the user is looking at.
 */

const STATUS_COLOR = (code: number | null | undefined): string => {
  if (typeof code !== "number") return "var(--text-dim)";
  if (code < 300) return "#10b981";
  if (code < 400) return "#06b6d4";
  if (code < 500) return "#f59e0b";
  return "#f43f5e";
};

export const AppLayerPanel: React.FC = () => {
  const [status, setStatus] = useState<AppLayerStatus | null>(null);
  const [events, setEvents] = useState<NormalizedEvent[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    const [st, page] = await Promise.allSettled([
      api.getAppLayerStatus(),
      api.getEvents({ event_type: "http_request", limit: 50 }),
    ]);

    if (st.status === "fulfilled") setStatus(st.value);
    else setError(st.reason instanceof Error ? st.reason.message : String(st.reason));

    if (page.status === "fulfilled") {
      setEvents(page.value.events ?? []);
      setTotal(page.value.total ?? 0);
    }
    setLoading(false);
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const enabled = status?.enabled === true;
  const hasData = events.length > 0;

  return (
    <div className="glass-panel" style={{ padding: "1.25rem 1.5rem" }}>
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          flexWrap: "wrap",
          gap: "0.75rem",
        }}
      >
        <h3 style={{ margin: 0, display: "flex", alignItems: "center", gap: "0.5rem" }}>
          <Globe size={18} />
          Application-Layer Telemetry
        </h3>
        <div style={{ display: "flex", alignItems: "center", gap: "0.6rem" }}>
          <span
            className="status-pill"
            title={
              enabled
                ? "Ingestion endpoint is enabled. Data appears only when a producer sends it."
                : "Opt-in and currently disabled."
            }
          >
            <span
              className="status-dot"
              style={{ backgroundColor: enabled ? "#10b981" : "#64748b" }}
            />
            <span>{enabled ? "INGEST ENABLED" : "INGEST DISABLED"}</span>
          </span>
          <button className="btn btn-secondary" onClick={load} disabled={loading}>
            <RefreshCw size={14} className={loading ? "spin-icon" : ""} /> Refresh
          </button>
        </div>
      </div>

      {error && (
        <div
          className="badge badge-attack"
          style={{ marginTop: "0.9rem", display: "block", padding: "0.6rem" }}
        >
          <AlertTriangle size={14} /> {error}
        </div>
      )}

      {/* The honest default state: nothing observed, and why. */}
      {!hasData && (
        <div
          style={{
            marginTop: "1rem",
            padding: "1rem 1.1rem",
            background: "rgba(0,0,0,0.2)",
            border: "1px solid var(--border-subtle)",
            borderRadius: "6px",
            fontSize: "var(--text-xs)",
            lineHeight: 1.75,
          }}
        >
          <div style={{ fontWeight: 600, marginBottom: "0.4rem" }}>
            No HTTP transactions have been observed
          </div>
          <div style={{ color: "var(--text-dim)" }}>
            The Windows TCP connection table cannot see HTTP. A successful TCP
            connection is <strong>not</strong> an HTTP 200, and a destination
            port is not proof of an application protocol — so no method, path,
            status or timing is shown for connection-only observations.
            {!enabled && (
              <>
                {" "}
                Ingestion is currently <strong>disabled</strong>; enable it with{" "}
                <code>PRAHARI_ENABLE_APPLICATION_LAYER_INGEST=true</code> and
                install the optional browser probe in <code>extension/</code>.
              </>
            )}
            {enabled && (
              <>
                {" "}
                Ingestion is enabled, but no producer has sent anything yet.
                Load the probe from <code>extension/</code> and press{" "}
                <em>Start collection</em> in its popup.
              </>
            )}
          </div>
        </div>
      )}

      {hasData && (
        <>
          <div
            style={{
              marginTop: "0.75rem",
              fontSize: "var(--text-2xs)",
              color: "var(--text-dim)",
              lineHeight: 1.7,
            }}
          >
            Showing {events.length} of {total} HTTP transactions reported by an
            authorized application-layer producer. These are separate records
            from connection telemetry — a row here means the request was
            genuinely observed, not inferred from a TCP connection.
          </div>

          <div className="table-container" style={{ marginTop: "0.9rem" }}>
            <table style={{ width: "100%", fontSize: "var(--text-2xs)" }}>
              <thead>
                <tr>
                  <th style={{ textAlign: "left" }}>Observed</th>
                  <th style={{ textAlign: "left" }}>Method</th>
                  <th style={{ textAlign: "left" }}>Host</th>
                  <th style={{ textAlign: "left" }}>Path</th>
                  <th style={{ textAlign: "left" }}>Status</th>
                  <th style={{ textAlign: "right" }}>Duration</th>
                  <th style={{ textAlign: "left" }}>Source</th>
                </tr>
              </thead>
              <tbody>
                {events.map((e) => (
                  <tr key={e.event_id}>
                    <td style={{ whiteSpace: "nowrap" }}>{fmtTime(e.observed_at, "—")}</td>
                    <td>{e.http_method ?? "—"}</td>
                    <td>{e.dst_hostname ?? e.dst_ip ?? "—"}</td>
                    <td style={{ wordBreak: "break-all" }}>{e.http_path ?? "—"}</td>
                    <td style={{ color: STATUS_COLOR(e.http_status_code) }}>
                      {typeof e.http_status_code === "number" ? (
                        e.http_status_code
                      ) : (
                        <span
                          style={{ color: "var(--text-dim)", fontStyle: "italic" }}
                          title="The browser reported no HTTP status — typically a failed or aborted request. No status is invented."
                        >
                          no response
                        </span>
                      )}
                    </td>
                    <td style={{ textAlign: "right" }}>
                      {typeof e.http_duration_ms === "number"
                        ? `${fmtFixed(e.http_duration_ms, 0)} ms`
                        : "—"}
                    </td>
                    <td style={{ color: "var(--text-dim)" }}>{e.source_id}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}

      {/* Privacy terms, read from the backend rather than asserted here. */}
      {status && (
        <div
          style={{
            marginTop: "1rem",
            paddingTop: "0.9rem",
            borderTop: "1px solid var(--border-subtle)",
            fontSize: "var(--text-2xs)",
            color: "var(--text-dim)",
            lineHeight: 1.75,
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: "0.4rem", marginBottom: "0.3rem" }}>
            <Info size={13} /> <strong>Collection terms</strong>
          </div>
          Query strings are {status.retain_query_strings ? "RETAINED by operator configuration" : "stripped"}.
          Never accepted: {status.never_accepted.slice(0, 6).join(", ")}.
          <ul style={{ margin: "0.5rem 0 0", paddingLeft: "1.1rem" }}>
            {status.notes.map((n, i) => (
              <li key={i}>{n}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
};
