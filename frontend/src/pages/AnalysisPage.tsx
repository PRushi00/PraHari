import React, { useState, useEffect } from "react";
import { RefreshCw, AlertCircle, Info } from "lucide-react";
import { api } from "../services/api";
import { DescriptiveAnalysis } from "../types";

import { UNAVAILABLE, fmtFixed, fmtInt, fmtTime, isNum, humanise } from "../utils/format";
export const AnalysisPage: React.FC = () => {
  const [analysis, setAnalysis] = useState<DescriptiveAnalysis | null>(null);
  const [loading, setLoading] = useState(true);
  const [recomputing, setRecomputing] = useState(false);

  const fetchAnalysis = async () => {
    setLoading(true);
    try {
      const res = await api.getLatestAnalysis();
      setAnalysis(res);
    } catch (err) {
      console.error("Failed to fetch descriptive analysis:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAnalysis();
  }, []);

  const handleRecompute = async () => {
    setRecomputing(true);
    try {
      const res = await api.runDescriptiveAnalysis();
      setAnalysis(res);
    } catch (err) {
      console.error("Failed to recompute analysis:", err);
    } finally {
      setRecomputing(false);
    }
  };

  /**
   * Explain a metric's availability for the analyzed set.
   *
   * With mixed provenance some sources may supply a field while others
   * cannot, so "unsupported" alone is not the whole story. Saying "not
   * measurable" beside a displayed value is a contradiction, which is what
   * the previous version did.
   */
  const availabilityNote = (field: string, hasValue: boolean, whenPresent: string): string => {
    const missingFrom = (analysis?.unsupported_field_counts || {})[field] ?? 0;
    const total = analysis?.total_events ?? 0;
    if (!hasValue) {
      return missingFrom > 0
        ? "Not measurable by the contributing source"
        : "No value available for the analyzed set";
    }
    if (missingFrom > 0) {
      return `${whenPresent} — excludes ${missingFrom} of ${total} records whose source cannot measure it`;
    }
    return whenPresent;
  };

  return (
    <div>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1.5rem" }}>
        <div>
          <h1 style={{ fontSize: "var(--text-xl)", letterSpacing: "-0.02em" }}>
            Descriptive Historical Analysis
          </h1>
          <p style={{ color: "var(--text-muted)", fontSize: "var(--text-xs)", marginTop: "0.2rem" }}>
            Objective statistical profiling of ingested network telemetry.
          </p>
        </div>

        <button className="btn btn-primary" onClick={handleRecompute} disabled={recomputing}>
          <RefreshCw size={15} className={recomputing ? "spin" : ""} />
          {recomputing ? "Computing..." : "Recompute Analysis"}
        </button>
      </div>

      {/* Research Gate Notice Alert */}
      <div
        className="glass-panel"
        style={{
          padding: "1.25rem",
          marginBottom: "1.75rem",
          border: "1px solid rgba(6, 182, 212, 0.4)",
          background: "rgba(6, 182, 212, 0.06)",
          display: "flex",
          gap: "1rem",
          alignItems: "flex-start",
        }}
      >
        <Info size={22} color="#38bdf8" style={{ flexShrink: 0, marginTop: "0.2rem" }} />
        <div>
          <h4 style={{ fontSize: "var(--text-md)", color: "#38bdf8", marginBottom: "0.25rem" }}>
            Research Feasibility Guardrail Active
          </h4>
          <p style={{ color: "var(--text-muted)", fontSize: "var(--text-xs)", lineHeight: 1.5 }}>
            This service computes strictly factual retrospective statistics summarizing observed telemetry. In compliance
            with the Master Engineering Specification, predictive machine-learning forecasting models will not be enabled
            until the formal dataset audit and research gate criteria are fully passed.
          </p>
        </div>
      </div>

      {loading ? (
        <div style={{ textAlign: "center", padding: "4rem", color: "var(--text-dim)" }}>
          Loading analysis profile...
        </div>
      ) : !analysis || analysis.total_events === 0 ? (
        <div className="glass-panel" style={{ padding: "3rem", textAlign: "center" }}>
          <AlertCircle size={36} color="#94a3b8" style={{ margin: "0 auto 1rem" }} />
          <h3 style={{ fontSize: "var(--text-lg)", marginBottom: "0.5rem" }}>No Analysis Available</h3>
          <p style={{ color: "var(--text-muted)", fontSize: "var(--text-xs)", maxWidth: "480px", margin: "0 auto 1.5rem" }}>
            Import or seed events first to calculate factual statistical profiles across IP addresses, ports, and protocols.
          </p>
          <button className="btn btn-primary" onClick={handleRecompute} disabled={recomputing}>
            Compute Initial Analysis
          </button>
        </div>
      ) : (
        <div>
          {/* Metrics summary cards */}
          <div className="stat-grid" style={{ marginBottom: "2rem" }}>
            <div className="glass-panel stat-card">
              <div className="stat-label">Total Events Profiled</div>
              <div className="stat-value">{fmtInt(analysis.total_events)}</div>
              <div className="stat-subtext">
                {analysis.is_mixed_provenance
                  ? "Mixed provenance — see breakdown below"
                  : `Category: ${analysis.data_category}`}
              </div>
            </div>

            <div className="glass-panel stat-card blue">
              <div className="stat-label">Average Flow Duration</div>
              <div className="stat-value">
                {isNum(analysis.avg_duration)
                  ? `${(analysis.avg_duration / 1000).toFixed(1)} ms`
                  : UNAVAILABLE}
              </div>
              <div className="stat-subtext">
                {availabilityNote("duration", isNum(analysis.avg_duration), "Mean connection length")}
              </div>
            </div>

            <div className="glass-panel stat-card emerald">
              <div className="stat-label">Average Packet Volume</div>
              <div className="stat-value">
                {fmtFixed(analysis.avg_packets, 0)}
              </div>
              <div className="stat-subtext">
                {availabilityNote("packets", isNum(analysis.avg_packets), "Packets per flow")}
              </div>
            </div>

            <div className="glass-panel stat-card amber">
              <div className="stat-label">Data Quality Warnings</div>
              <div className="stat-value">{analysis.records_with_warnings}</div>
              <div className="stat-subtext">
                Genuine defects only — source limits counted separately
              </div>
            </div>
          </div>

          {/* Provenance — derived from the analyzed events, not declared */}
          <div className="glass-panel" style={{ padding: "1.5rem", marginBottom: "2rem" }}>
            <h3 style={{ fontSize: "var(--text-md)", marginBottom: "0.25rem" }}>
              Data Provenance
            </h3>
            <p style={{ color: "var(--text-dim)", fontSize: "var(--text-2xs)", marginBottom: "1rem" }}>
              Derived from the records actually summarized, so live telemetry,
              historical imports and synthetic fixtures stay distinguishable.
            </p>
            <div
              style={{
                display: "grid",
                gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))",
                gap: "1.25rem",
              }}
            >
              <div>
                <div style={{ fontSize: "var(--text-2xs)", color: "var(--text-muted)", marginBottom: "0.4rem" }}>
                  By data category
                </div>
                {Object.entries(analysis.data_categories || {}).map(([cat, count]) => (
                  <div key={cat} style={{ fontSize: "var(--text-xs)", marginBottom: "0.2rem" }}>
                    <span
                      className={cat === "live_telemetry" ? "badge badge-benign" : "badge badge-info"}
                    >
                      {humanise(cat)}
                    </span>{" "}
                    {count}
                  </div>
                ))}
                {Object.keys(analysis.data_categories || {}).length === 0 && (
                  <div style={{ color: "var(--text-dim)", fontSize: "var(--text-xs)" }}>No events.</div>
                )}
              </div>

              <div>
                <div style={{ fontSize: "var(--text-2xs)", color: "var(--text-muted)", marginBottom: "0.4rem" }}>
                  By source
                </div>
                {Object.entries(analysis.source_breakdown || {}).map(([src, count]) => (
                  <div key={src} style={{ fontSize: "var(--text-xs)", marginBottom: "0.2rem" }}>
                    <code>{src}</code> {count}
                  </div>
                ))}
              </div>

              <div>
                <div style={{ fontSize: "var(--text-2xs)", color: "var(--text-muted)", marginBottom: "0.4rem" }}>
                  Observation window
                </div>
                <div style={{ fontSize: "var(--text-xs)" }}>
                  {fmtTime(analysis.time_range_start, "—")}
                </div>
                <div style={{ fontSize: "var(--text-xs)" }}>
                  to{" "}
                  {fmtTime(analysis.time_range_end, "—")}
                </div>
                {(analysis.implausible_timestamp_events ?? 0) > 0 && (
                  <div
                    style={{
                      fontSize: "var(--text-2xs)",
                      color: "#f59e0b",
                      marginTop: "0.4rem",
                      lineHeight: 1.5,
                    }}
                  >
                    {analysis.implausible_timestamp_events} record(s) carry a
                    timestamp that cannot describe a real observation (before
                    2000 or far in the future) and are excluded from this
                    window. Including one would imply a span of centuries.
                  </div>
                )}
                <div style={{ fontSize: "var(--text-2xs)", color: "var(--text-dim)", marginTop: "0.4rem" }}>
                  Computed {fmtTime(analysis.computed_at, "—")}
                </div>
              </div>
            </div>

            {(analysis.source_limitations || []).length > 0 && (
              <div style={{ marginTop: "1.25rem" }}>
                <div style={{ fontSize: "var(--text-2xs)", color: "var(--text-muted)", marginBottom: "0.4rem" }}>
                  Limits of the contributing sources
                </div>
                <ul
                  style={{
                    margin: 0,
                    paddingLeft: "1.1rem",
                    fontSize: "var(--text-2xs)",
                    color: "var(--text-dim)",
                    lineHeight: 1.7,
                  }}
                >
                  {analysis.source_limitations.map((l, i) => (
                    <li key={i}>{l}</li>
                  ))}
                </ul>
              </div>
            )}
          </div>

          {/* Top Talkers Tables */}
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "1.5rem", marginBottom: "2rem" }}>
            <div className="glass-panel" style={{ padding: "1.5rem" }}>
              <h3 style={{ fontSize: "var(--text-md)", marginBottom: "0.25rem" }}>Top Source IP Addresses</h3>
              <p style={{ color: "var(--text-dim)", fontSize: "var(--text-2xs)", marginBottom: "1rem" }}>
                Identified origin nodes in the dataset
              </p>
              <div className="table-container">
                <table>
                  <thead>
                    <tr>
                      <th>Source IP</th>
                      <th style={{ textAlign: "right" }}>Flow Count</th>
                    </tr>
                  </thead>
                  <tbody>
                    {analysis.top_src_ips.map((item) => (
                      <tr key={item.ip}>
                        <td>{item.ip}</td>
                        <td style={{ textAlign: "right" }}>{item.count}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            <div className="glass-panel" style={{ padding: "1.5rem" }}>
              <h3 style={{ fontSize: "var(--text-md)", marginBottom: "0.25rem" }}>Top Destination IP Addresses</h3>
              <p style={{ color: "var(--text-dim)", fontSize: "var(--text-2xs)", marginBottom: "1rem" }}>
                Target infrastructure and internal endpoints
              </p>
              <div className="table-container">
                <table>
                  <thead>
                    <tr>
                      <th>Destination IP</th>
                      <th style={{ textAlign: "right" }}>Flow Count</th>
                    </tr>
                  </thead>
                  <tbody>
                    {analysis.top_dst_ips.map((item) => (
                      <tr key={item.ip}>
                        <td>{item.ip}</td>
                        <td style={{ textAlign: "right" }}>{item.count}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>

          {/* Data Quality and Missing Fields Audit */}
          <div className="glass-panel" style={{ padding: "1.5rem" }}>
            <h3 style={{ fontSize: "var(--text-md)", marginBottom: "0.25rem" }}>
              Data Quality Assurance & Missing Fields Audit
            </h3>
            <p style={{ color: "var(--text-dim)", fontSize: "var(--text-2xs)", marginBottom: "1rem" }}>
              Audit results generated during normalization pipeline
            </p>

            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "1.5rem" }}>
              <div>
                <h4 style={{ fontSize: "var(--text-md)", color: "var(--text-muted)", marginBottom: "0.5rem" }}>
                  Quality Flag Frequencies
                </h4>
                {Object.keys(analysis.quality_flag_counts).length > 0 ? (
                  <div className="table-container">
                    <table>
                      <thead>
                        <tr>
                          <th>Flag Identifier</th>
                          <th style={{ textAlign: "right" }}>Incidents</th>
                        </tr>
                      </thead>
                      <tbody>
                        {Object.entries(analysis.quality_flag_counts).map(([flag, count]) => (
                          <tr key={flag}>
                            <td>
                              <span className="badge badge-warning" style={{ marginRight: "0.5rem" }}>
                                FLAG
                              </span>
                              {humanise(flag)}
                            </td>
                            <td style={{ textAlign: "right" }}>{count}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : (
                  <div style={{ color: "var(--text-dim)", fontSize: "var(--text-xs)" }}>No quality flags recorded.</div>
                )}
              </div>

              <div>
                <h4 style={{ fontSize: "var(--text-md)", color: "var(--text-muted)", marginBottom: "0.25rem" }}>
                  Fields Unavailable From the Source
                </h4>
                <p style={{ color: "var(--text-dim)", fontSize: "var(--text-2xs)", marginBottom: "0.5rem" }}>
                  These are structural limits of the telemetry source, not data
                  defects. The source cannot measure them, so they are stored as
                  null rather than estimated.
                </p>
                {Object.keys(analysis.unsupported_field_counts || {}).length > 0 ? (
                  <div className="table-container" style={{ marginBottom: "1.25rem" }}>
                    <table>
                      <thead>
                        <tr>
                          <th>Field Name</th>
                          <th style={{ textAlign: "right" }}>Records Affected</th>
                        </tr>
                      </thead>
                      <tbody>
                        {Object.entries(analysis.unsupported_field_counts).map(([field, count]) => (
                          <tr key={field}>
                            <td><code>{field}</code></td>
                            <td style={{ textAlign: "right" }}>{count}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : (
                  <div style={{ color: "var(--text-dim)", fontSize: "var(--text-xs)", marginBottom: "1.25rem" }}>
                    All canonical fields are supported by the contributing sources.
                  </div>
                )}

                <h4 style={{ fontSize: "var(--text-md)", color: "var(--text-muted)", marginBottom: "0.25rem" }}>
                  Genuinely Missing Fields
                </h4>
                <p style={{ color: "var(--text-dim)", fontSize: "var(--text-2xs)", marginBottom: "0.5rem" }}>
                  Fields the source <em>does</em> support but did not provide —
                  these are real gaps worth investigating.
                </p>
                {Object.keys(analysis.missing_field_counts).length > 0 ? (
                  <div className="table-container">
                    <table>
                      <thead>
                        <tr>
                          <th>Field Name</th>
                          <th style={{ textAlign: "right" }}>Missing Count</th>
                        </tr>
                      </thead>
                      <tbody>
                        {Object.entries(analysis.missing_field_counts).map(([field, count]) => (
                          <tr key={field}>
                            <td><code>{field}</code></td>
                            <td style={{ textAlign: "right" }}>{count}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : (
                  <div style={{ color: "var(--text-dim)", fontSize: "var(--text-xs)" }}>
                    No unexplained gaps: every field the sources support was populated.
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
