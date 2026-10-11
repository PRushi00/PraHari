import React, { useState, useEffect } from "react";
import { RefreshCw, AlertCircle, Info } from "lucide-react";
import { api } from "../services/api";
import { DescriptiveAnalysis } from "../types";

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

  return (
    <div>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1.5rem" }}>
        <div>
          <h1 style={{ fontSize: "1.6rem", fontWeight: 700, letterSpacing: "-0.02em" }}>
            Descriptive Historical Analysis
          </h1>
          <p style={{ color: "var(--text-muted)", fontSize: "0.85rem", marginTop: "0.2rem" }}>
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
          <h4 style={{ fontSize: "0.95rem", fontWeight: 600, color: "#38bdf8", marginBottom: "0.25rem" }}>
            Research Feasibility Guardrail Active
          </h4>
          <p style={{ color: "var(--text-muted)", fontSize: "0.85rem", lineHeight: 1.5 }}>
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
          <h3 style={{ fontSize: "1.2rem", marginBottom: "0.5rem" }}>No Analysis Available</h3>
          <p style={{ color: "var(--text-muted)", fontSize: "0.85rem", maxWidth: "480px", margin: "0 auto 1.5rem" }}>
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
              <div className="stat-value">{analysis.total_events.toLocaleString()}</div>
              <div className="stat-subtext">Category: {analysis.data_category}</div>
            </div>

            <div className="glass-panel stat-card blue">
              <div className="stat-label">Average Flow Duration</div>
              <div className="stat-value">
                {analysis.avg_duration ? `${(analysis.avg_duration / 1000).toFixed(1)} ms` : "N/A"}
              </div>
              <div className="stat-subtext">Mean connection length</div>
            </div>

            <div className="glass-panel stat-card emerald">
              <div className="stat-label">Average Packet Volume</div>
              <div className="stat-value">
                {analysis.avg_packets ? analysis.avg_packets.toFixed(0) : "N/A"}
              </div>
              <div className="stat-subtext">Packets per flow</div>
            </div>

            <div className="glass-panel stat-card amber">
              <div className="stat-label">Quality Warnings</div>
              <div className="stat-value">{analysis.records_with_warnings}</div>
              <div className="stat-subtext">Flows with audit flags</div>
            </div>
          </div>

          {/* Top Talkers Tables */}
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "1.5rem", marginBottom: "2rem" }}>
            <div className="glass-panel" style={{ padding: "1.5rem" }}>
              <h3 style={{ fontSize: "1rem", fontWeight: 600, marginBottom: "0.25rem" }}>Top Source IP Addresses</h3>
              <p style={{ color: "var(--text-dim)", fontSize: "0.75rem", marginBottom: "1rem" }}>
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
              <h3 style={{ fontSize: "1rem", fontWeight: 600, marginBottom: "0.25rem" }}>Top Destination IP Addresses</h3>
              <p style={{ color: "var(--text-dim)", fontSize: "0.75rem", marginBottom: "1rem" }}>
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
            <h3 style={{ fontSize: "1rem", fontWeight: 600, marginBottom: "0.25rem" }}>
              Data Quality Assurance & Missing Fields Audit
            </h3>
            <p style={{ color: "var(--text-dim)", fontSize: "0.75rem", marginBottom: "1rem" }}>
              Audit results generated during normalization pipeline
            </p>

            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "1.5rem" }}>
              <div>
                <h4 style={{ fontSize: "0.85rem", color: "var(--text-muted)", marginBottom: "0.5rem" }}>
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
                              {flag}
                            </td>
                            <td style={{ textAlign: "right" }}>{count}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : (
                  <div style={{ color: "var(--text-dim)", fontSize: "0.85rem" }}>No quality flags recorded.</div>
                )}
              </div>

              <div>
                <h4 style={{ fontSize: "0.85rem", color: "var(--text-muted)", marginBottom: "0.5rem" }}>
                  Missing / Omitted Optional Fields
                </h4>
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
                            <td>{field}</td>
                            <td style={{ textAlign: "right" }}>{count}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : (
                  <div style={{ color: "var(--text-dim)", fontSize: "0.85rem" }}>All fields fully populated.</div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
