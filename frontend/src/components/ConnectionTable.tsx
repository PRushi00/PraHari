import React, { useMemo, useState } from "react";
import { ChevronDown, ChevronRight } from "lucide-react";
import { ConnectionDetail, DomainAttribution } from "../types";

type SortKey =
  | "observed_at"
  | "dst_ip"
  | "dst_port"
  | "hostname"
  | "process_name"
  | "connection_state";

interface Props {
  connections: ConnectionDetail[];
  loading?: boolean;
}

const CONFIDENCE_COLOR: Record<string, string> = {
  high: "#10b981",
  medium: "#f59e0b",
  low: "#94a3b8",
  none: "#64748b",
};

const fmtTime = (iso: string | null | undefined): string => {
  if (!iso) return "—";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? "—" : d.toLocaleString();
};

/**
 * Render a hostname together with what it actually means.
 *
 * A reverse-DNS result names the address owner, not the site requested, so
 * it is rendered distinctly and never as "the domain".
 */
const HostnameCell: React.FC<{ attribution: DomainAttribution | null }> = ({ attribution }) => {
  if (!attribution || !attribution.hostname) {
    return (
      <span style={{ color: "var(--text-dim)", fontStyle: "italic" }} title={attribution?.limitations?.join(" ")}>
        unknown
      </span>
    );
  }

  const color = CONFIDENCE_COLOR[attribution.confidence] ?? "#64748b";
  const isOwner = !attribution.identifies_requested_host;

  return (
    <span title={attribution.limitations.join("\n")}>
      <span style={{ color: isOwner ? "var(--text-dim)" : "inherit" }}>
        {attribution.hostname}
      </span>
      <span
        style={{
          marginLeft: "0.4rem",
          fontSize: "0.62rem",
          padding: "0.05rem 0.3rem",
          borderRadius: "3px",
          border: `1px solid ${color}`,
          color,
          whiteSpace: "nowrap",
        }}
      >
        {isOwner ? "IP OWNER" : attribution.confidence.toUpperCase()}
      </span>
    </span>
  );
};

export const ConnectionTable: React.FC<Props> = ({ connections, loading }) => {
  const [sortKey, setSortKey] = useState<SortKey>("observed_at");
  const [sortDesc, setSortDesc] = useState(true);
  const [expanded, setExpanded] = useState<string | null>(null);

  const sorted = useMemo(() => {
    const value = (c: ConnectionDetail): string | number => {
      switch (sortKey) {
        case "dst_ip":
          return c.event.dst_ip ?? "";
        case "dst_port":
          return c.event.dst_port ?? -1;
        case "hostname":
          return c.domain_attribution?.hostname ?? "";
        case "process_name":
          return c.process_name ?? "";
        case "connection_state":
          return c.connection_state ?? "";
        default:
          return c.event.observed_at ?? "";
      }
    };
    return [...connections].sort((a, b) => {
      const va = value(a);
      const vb = value(b);
      const cmp = typeof va === "number" && typeof vb === "number"
        ? va - vb
        : String(va).localeCompare(String(vb));
      return sortDesc ? -cmp : cmp;
    });
  }, [connections, sortKey, sortDesc]);

  const toggleSort = (key: SortKey) => {
    if (key === sortKey) setSortDesc((d) => !d);
    else {
      setSortKey(key);
      setSortDesc(true);
    }
  };

  const header = (key: SortKey, label: string) => (
    <th
      onClick={() => toggleSort(key)}
      style={{ textAlign: "left", cursor: "pointer", userSelect: "none", whiteSpace: "nowrap" }}
      title="Click to sort"
    >
      {label}
      {sortKey === key && <span style={{ marginLeft: 4 }}>{sortDesc ? "▼" : "▲"}</span>}
    </th>
  );

  if (loading) {
    return (
      <div style={{ padding: "1.5rem", textAlign: "center", color: "var(--text-dim)" }}>
        Loading connections…
      </div>
    );
  }

  if (connections.length === 0) {
    return (
      <div style={{ padding: "2rem", textAlign: "center", color: "var(--text-dim)", fontSize: "0.85rem" }}>
        No connections match the current filters.
      </div>
    );
  }

  return (
    <div className="table-container">
      <table style={{ width: "100%", fontSize: "0.76rem" }}>
        <thead>
          <tr>
            <th style={{ width: "1.5rem" }} />
            {header("observed_at", "Started")}
            <th style={{ textAlign: "left" }}>Source</th>
            {header("dst_ip", "Destination")}
            {header("dst_port", "Port")}
            {header("hostname", "Host (inferred)")}
            {header("process_name", "Process")}
            {header("connection_state", "State")}
            <th style={{ textAlign: "left" }}>App layer</th>
          </tr>
        </thead>
        <tbody>
          {sorted.map((c) => {
            const e = c.event;
            const open = expanded === e.event_id;
            const hasHttp = e.http_method !== null && e.http_method !== undefined;
            return (
              <React.Fragment key={e.event_id}>
                <tr
                  onClick={() => setExpanded(open ? null : e.event_id)}
                  style={{ cursor: "pointer" }}
                >
                  <td>{open ? <ChevronDown size={13} /> : <ChevronRight size={13} />}</td>
                  <td style={{ whiteSpace: "nowrap" }}>{fmtTime(e.observed_at)}</td>
                  <td>
                    {e.src_ip}
                    {e.src_port !== null ? `:${e.src_port}` : ""}
                  </td>
                  <td>{e.dst_ip ?? "—"}</td>
                  <td>{e.dst_port ?? "—"}</td>
                  <td><HostnameCell attribution={c.domain_attribution} /></td>
                  <td>
                    {c.process_name ?? (
                      <span style={{ color: "var(--text-dim)", fontStyle: "italic" }}>
                        {c.process_id ? `pid ${c.process_id}` : "unknown"}
                      </span>
                    )}
                  </td>
                  <td>{c.connection_state ?? "—"}</td>
                  <td>
                    {hasHttp ? (
                      <span>
                        {e.http_method} {e.http_status_code ?? ""}
                      </span>
                    ) : (
                      <span
                        style={{ color: "var(--text-dim)", fontStyle: "italic" }}
                        title="This source observes connection metadata only. HTTP detail requires an authorized application-layer source."
                      >
                        not observed
                      </span>
                    )}
                  </td>
                </tr>

                {open && (
                  <tr>
                    <td colSpan={9} style={{ background: "rgba(255,255,255,0.02)", padding: "0.9rem 1.2rem" }}>
                      <div
                        style={{
                          display: "grid",
                          gridTemplateColumns: "repeat(auto-fit, minmax(230px, 1fr))",
                          gap: "1rem",
                        }}
                      >
                        <div>
                          <div style={{ fontWeight: 600, marginBottom: "0.4rem" }}>Connection</div>
                          <Detail label="Event ID" value={e.event_id} />
                          <Detail label="Observed at" value={fmtTime(e.observed_at)} />
                          <Detail label="Ingested at" value={fmtTime(e.ingested_at)} />
                          <Detail label="Transport" value={e.protocol ?? "—"} />
                          <Detail label="State" value={c.connection_state ?? "—"} />
                          <Detail
                            label="Process"
                            value={
                              c.process_name
                                ? `${c.process_name}${c.process_id ? ` (pid ${c.process_id})` : ""}`
                                : "unknown"
                            }
                          />
                        </div>

                        <div>
                          <div style={{ fontWeight: 600, marginBottom: "0.4rem" }}>Provenance</div>
                          <Detail label="Source" value={e.source_id} />
                          <Detail label="Source type" value={c.source_type ?? "—"} />
                          <Detail label="Data category" value={e.data_category} />
                          <Detail label="Reference" value={e.raw_reference ?? "—"} />
                          <Detail
                            label="Quality flags"
                            value={e.quality_flags.length ? e.quality_flags.join(", ") : "none"}
                          />
                        </div>

                        <div>
                          <div style={{ fontWeight: 600, marginBottom: "0.4rem" }}>
                            Hostname attribution
                          </div>
                          {c.domain_attribution && c.domain_attribution.hostname ? (
                            <>
                              <Detail label="Hostname" value={c.domain_attribution.hostname} />
                              <Detail label="Method" value={c.domain_attribution.method} />
                              <Detail label="Confidence" value={c.domain_attribution.confidence} />
                              <Detail
                                label="Identifies requested host"
                                value={c.domain_attribution.identifies_requested_host ? "yes" : "NO — address owner only"}
                              />
                              <Detail
                                label="Evidence time"
                                value={fmtTime(c.domain_attribution.evidence_observed_at)}
                              />
                              {c.domain_attribution.candidate_count > 1 && (
                                <Detail
                                  label="Other names on this IP"
                                  value={c.domain_attribution.candidate_hostnames.join(", ")}
                                />
                              )}
                            </>
                          ) : (
                            <div style={{ color: "var(--text-dim)", fontSize: "0.72rem" }}>
                              No hostname could be attributed.
                            </div>
                          )}
                          {c.domain_attribution?.limitations?.length ? (
                            <ul
                              style={{
                                margin: "0.5rem 0 0",
                                paddingLeft: "1rem",
                                fontSize: "0.68rem",
                                color: "var(--text-dim)",
                              }}
                            >
                              {c.domain_attribution.limitations.map((l, i) => (
                                <li key={i}>{l}</li>
                              ))}
                            </ul>
                          ) : null}
                        </div>

                        <div>
                          <div style={{ fontWeight: 600, marginBottom: "0.4rem" }}>
                            Application layer
                          </div>
                          {hasHttp ? (
                            <>
                              <Detail label="Method" value={e.http_method ?? "—"} />
                              <Detail label="Path" value={e.http_path ?? "—"} />
                              <Detail label="Status" value={String(e.http_status_code ?? "—")} />
                              <Detail
                                label="Duration"
                                value={e.http_duration_ms !== null && e.http_duration_ms !== undefined
                                  ? `${e.http_duration_ms} ms`
                                  : "—"}
                              />
                              <Detail label="Protocol" value={e.app_protocol ?? "—"} />
                            </>
                          ) : (
                            <div style={{ color: "var(--text-dim)", fontSize: "0.72rem", lineHeight: 1.6 }}>
                              Not observed by this source. A destination port
                              is not evidence of an application protocol, and
                              HTTP status codes are not TCP states. These
                              fields appear only when an authorized
                              application-layer source reports them.
                            </div>
                          )}

                          <div style={{ marginTop: "0.6rem", fontSize: "0.68rem", color: "var(--text-dim)" }}>
                            <strong>Unavailable from this source:</strong>{" "}
                            {c.unsupported_fields.join(", ") || "none"}
                          </div>
                        </div>
                      </div>
                    </td>
                  </tr>
                )}
              </React.Fragment>
            );
          })}
        </tbody>
      </table>
    </div>
  );
};

const Detail: React.FC<{ label: string; value: string }> = ({ label, value }) => (
  <div style={{ display: "flex", gap: "0.5rem", fontSize: "0.72rem", marginBottom: "0.2rem" }}>
    <span style={{ color: "var(--text-dim)", minWidth: "8.5rem" }}>{label}</span>
    <span style={{ wordBreak: "break-all" }}>{value}</span>
  </div>
);
