import React, { useState, useEffect } from "react";
import {
  CheckCircle,
  AlertTriangle,
  XCircle,
  RefreshCw,
  ShieldCheck,
  FileCheck,
} from "lucide-react";
import { api } from "../services/api";
import { FeasibilityReport, TelemetrySource } from "../types";

export const ResearchPage: React.FC = () => {
  const [report, setReport] = useState<FeasibilityReport | null>(null);
  const [sources, setSources] = useState<TelemetrySource[]>([]);
  const [selectedSource, setSelectedSource] = useState<string>("");
  const [loading, setLoading] = useState(false);
  const [runningAudit, setRunningAudit] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchSources = async () => {
    try {
      const data = await api.getSources();
      setSources(data);
    } catch (err: any) {
      console.error(err);
    }
  };

  const fetchExistingReport = async () => {
    setLoading(true);
    try {
      const rep = await api.getResearchReport();
      setReport(rep);
    } catch (err: any) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const runAudit = async () => {
    setRunningAudit(true);
    setError(null);
    try {
      const rep = await api.runResearchAudit(selectedSource || undefined);
      setReport(rep);
    } catch (err: any) {
      setError(err.message || "Failed to execute research feasibility audit");
    } finally {
      setRunningAudit(false);
    }
  };

  useEffect(() => {
    fetchSources();
    fetchExistingReport();
  }, []);

  const getMetricIcon = (passed: boolean, severity: string) => {
    if (passed) return <CheckCircle size={18} style={{ color: "#10b981" }} />;
    if (severity === "critical") return <XCircle size={18} style={{ color: "#f43f5e" }} />;
    return <AlertTriangle size={18} style={{ color: "#f59e0b" }} />;
  };

  return (
    <div className="page-container">
      {/* Header & Controls */}
      <div className="page-header" style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: "1rem" }}>
        <div>
          <h1 className="page-title">Research Feasibility Scorecard</h1>
          <p className="page-subtitle">
            Scientific integrity audit evaluating temporal monotonicity, class balance, label provenance, and causal leakage prevention.
          </p>
        </div>
        <div style={{ display: "flex", gap: "0.75rem", alignItems: "center" }}>
          <select
            className="form-select"
            value={selectedSource}
            onChange={(e) => setSelectedSource(e.target.value)}
            style={{ width: "220px" }}
          >
            <option value="">All Telemetry Sources</option>
            {sources.map((s) => (
              <option key={s.source_id} value={s.source_id}>
                {s.name} ({s.event_count} flows)
              </option>
            ))}
          </select>
          <button
            className="btn btn-primary"
            onClick={runAudit}
            disabled={runningAudit}
          >
            <RefreshCw size={15} className={runningAudit ? "spin-icon" : ""} />
            {runningAudit ? "Running Audit..." : "Run Feasibility Audit"}
          </button>
        </div>
      </div>

      {error && (
        <div className="glass-panel" style={{ padding: "1rem", marginBottom: "1.5rem", borderLeft: "4px solid var(--accent-rose)", color: "#fca5a5" }}>
          <div style={{ display: "flex", gap: "0.5rem", alignItems: "center" }}>
            <AlertTriangle size={18} />
            <span>{error}</span>
          </div>
        </div>
      )}

      {loading && !report ? (
        <div className="glass-panel" style={{ padding: "3rem", textAlign: "center", color: "var(--text-muted)" }}>
          <RefreshCw size={28} className="spin-icon" style={{ margin: "0 auto 1rem auto" }} />
          <p>Loading research feasibility baseline...</p>
        </div>
      ) : !report ? (
        <div className="glass-panel" style={{ padding: "3rem", textAlign: "center", color: "var(--text-muted)" }}>
          <FileCheck size={36} style={{ color: "var(--accent-cyan)", margin: "0 auto 1rem auto" }} />
          <h3>No Feasibility Audit Executed Yet</h3>
          <p style={{ marginTop: "0.5rem" }}>
            Execute a research feasibility audit across persisted events to verify scientific readiness for ML threat forecasting.
          </p>
          <button className="btn btn-primary" onClick={runAudit} style={{ marginTop: "1.5rem" }} disabled={runningAudit}>
            Run Audit Now
          </button>
        </div>
      ) : (
        <>
          {/* Main Status & Score Overview */}
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", gap: "1.25rem", marginBottom: "1.5rem" }}>
            {/* Feasibility Gate Card */}
            <div className="glass-panel" style={{ padding: "1.5rem" }}>
              <div style={{ fontSize: "0.8rem", color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "0.05em" }}>
                Feasibility Gate Status
              </div>
              <div style={{ display: "flex", alignItems: "center", gap: "0.75rem", marginTop: "0.75rem" }}>
                {report.gate_passed ? (
                  <CheckCircle size={32} style={{ color: "#10b981" }} />
                ) : (
                  <XCircle size={32} style={{ color: "#f43f5e" }} />
                )}
                <div>
                  <div style={{ fontSize: "1.4rem", fontWeight: 700, color: report.gate_passed ? "#10b981" : "#f43f5e" }}>
                    {report.gate_passed ? "GATE PASSED" : "GATE REJECTED"}
                  </div>
                  <div style={{ fontSize: "0.8rem", color: "var(--text-dim)" }}>
                    {report.gate_passed ? "Ready for Predictive ML" : "Insufficient for Causal Claims"}
                  </div>
                </div>
              </div>
            </div>

            {/* Scorecard Metric */}
            <div className="glass-panel" style={{ padding: "1.5rem" }}>
              <div style={{ fontSize: "0.8rem", color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "0.05em" }}>
                Overall Feasibility Index
              </div>
              <div style={{ display: "flex", alignItems: "baseline", gap: "0.5rem", marginTop: "0.75rem" }}>
                <span style={{ fontSize: "2rem", fontWeight: 800, color: "var(--accent-cyan)" }}>
                  {report.overall_feasibility_score.toFixed(1)}
                </span>
                <span style={{ color: "var(--text-dim)", fontSize: "1rem" }}>/ 100.0</span>
              </div>
              <div style={{ fontSize: "0.8rem", color: "var(--text-dim)", marginTop: "0.25rem" }}>
                Audit ID: <code style={{ color: "var(--text-muted)" }}>{report.audit_id.slice(0, 8)}</code> • {report.total_events} events evaluated
              </div>
            </div>

            {/* Recommendation Summary */}
            <div className="glass-panel" style={{ padding: "1.5rem" }}>
              <div style={{ fontSize: "0.8rem", color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "0.05em" }}>
                Scientific Recommendation
              </div>
              <div style={{ marginTop: "0.75rem", fontSize: "0.9rem", color: "var(--text-main)", lineHeight: 1.5 }}>
                {report.recommendation}
              </div>
            </div>
          </div>

          {/* Detailed Criteria Checklist */}
          <div className="glass-panel" style={{ padding: "1.75rem", marginBottom: "1.5rem" }}>
            <h2 style={{ fontSize: "1.1rem", fontWeight: 600, marginBottom: "1.25rem", display: "flex", alignItems: "center", gap: "0.5rem" }}>
              <ShieldCheck size={20} style={{ color: "var(--accent-cyan)" }} />
              Research Criteria Verification Checklist
            </h2>

            <div style={{ display: "grid", gridTemplateColumns: "1fr", gap: "1rem" }}>
              {/* Criterion 1: Monotonicity */}
              <div className="glass-panel" style={{ padding: "1rem 1.25rem", background: "rgba(15, 23, 42, 0.4)" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "0.35rem" }}>
                  <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", fontWeight: 600 }}>
                    {getMetricIcon(report.temporal_monotonicity.passed, report.temporal_monotonicity.severity)}
                    <span>Temporal Monotonicity & Chronological Ordering</span>
                  </div>
                  <span className="badge" style={{ background: report.temporal_monotonicity.passed ? "rgba(16, 185, 129, 0.2)" : "rgba(244, 63, 94, 0.2)", color: report.temporal_monotonicity.passed ? "#10b981" : "#f43f5e" }}>
                    {report.temporal_monotonicity.passed ? "PASSED" : "VIOLATION"}
                  </span>
                </div>
                <div style={{ fontSize: "0.85rem", color: "var(--text-muted)" }}>
                  {report.temporal_monotonicity.rationale}
                </div>
              </div>

              {/* Criterion 2: Class Balance */}
              <div className="glass-panel" style={{ padding: "1rem 1.25rem", background: "rgba(15, 23, 42, 0.4)" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "0.35rem" }}>
                  <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", fontWeight: 600 }}>
                    {getMetricIcon(report.class_balance.passed, report.class_balance.severity)}
                    <span>Class Balance & Attack Diversity</span>
                  </div>
                  <span className="badge" style={{ background: report.class_balance.passed ? "rgba(16, 185, 129, 0.2)" : "rgba(245, 158, 11, 0.2)", color: report.class_balance.passed ? "#10b981" : "#f59e0b" }}>
                    {report.class_balance.passed ? "VALID" : "SKEWED"}
                  </span>
                </div>
                <div style={{ fontSize: "0.85rem", color: "var(--text-muted)" }}>
                  {report.class_balance.rationale}
                </div>
              </div>

              {/* Criterion 3: Label Provenance */}
              <div className="glass-panel" style={{ padding: "1rem 1.25rem", background: "rgba(15, 23, 42, 0.4)" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "0.35rem" }}>
                  <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", fontWeight: 600 }}>
                    {getMetricIcon(report.label_provenance.passed, report.label_provenance.severity)}
                    <span>Ground Truth Label Provenance</span>
                  </div>
                  <span className="badge" style={{ background: report.label_provenance.passed ? "rgba(16, 185, 129, 0.2)" : "rgba(244, 63, 94, 0.2)", color: report.label_provenance.passed ? "#10b981" : "#f43f5e" }}>
                    {report.label_provenance.passed ? "VERIFIED" : "UNAUDITED"}
                  </span>
                </div>
                <div style={{ fontSize: "0.85rem", color: "var(--text-muted)" }}>
                  {report.label_provenance.rationale}
                </div>
              </div>

              {/* Criterion 4: Source Diversity */}
              <div className="glass-panel" style={{ padding: "1rem 1.25rem", background: "rgba(15, 23, 42, 0.4)" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "0.35rem" }}>
                  <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", fontWeight: 600 }}>
                    {getMetricIcon(report.source_diversity.passed, report.source_diversity.severity)}
                    <span>Source Telemetry Diversity</span>
                  </div>
                  <span className="badge" style={{ background: report.source_diversity.passed ? "rgba(16, 185, 129, 0.2)" : "rgba(245, 158, 11, 0.2)", color: report.source_diversity.passed ? "#10b981" : "#f59e0b" }}>
                    {report.source_diversity.passed ? "SUFFICIENT" : "SINGLE-SOURCE"}
                  </span>
                </div>
                <div style={{ fontSize: "0.85rem", color: "var(--text-muted)" }}>
                  {report.source_diversity.rationale}
                </div>
              </div>

              {/* Criterion 5: Forward Leakage Risk */}
              <div className="glass-panel" style={{ padding: "1rem 1.25rem", background: "rgba(15, 23, 42, 0.4)" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "0.35rem" }}>
                  <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", fontWeight: 600 }}>
                    {getMetricIcon(report.causal_leakage_risk.passed, report.causal_leakage_risk.severity)}
                    <span>Causal Isolation & Forward Leakage Prevention</span>
                  </div>
                  <span className="badge" style={{ background: report.causal_leakage_risk.passed ? "rgba(16, 185, 129, 0.2)" : "rgba(244, 63, 94, 0.2)", color: report.causal_leakage_risk.passed ? "#10b981" : "#f43f5e" }}>
                    {report.causal_leakage_risk.passed ? "PROTECTED" : "LEAKAGE RISK"}
                  </span>
                </div>
                <div style={{ fontSize: "0.85rem", color: "var(--text-muted)" }}>
                  {report.causal_leakage_risk.rationale}
                </div>
              </div>
            </div>
          </div>

          {/* Advisory Warnings Card */}
          {report.advisory_warnings && report.advisory_warnings.length > 0 && (
            <div className="glass-panel" style={{ padding: "1.5rem", borderLeft: "4px solid var(--accent-amber)" }}>
              <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", color: "var(--accent-amber)", fontWeight: 600, marginBottom: "0.75rem" }}>
                <AlertTriangle size={18} />
                <span>Advisory Findings & Research Caveats</span>
              </div>
              <ul style={{ paddingLeft: "1.25rem", color: "var(--text-muted)", fontSize: "0.85rem", lineHeight: 1.6 }}>
                {report.advisory_warnings.map((warn, i) => (
                  <li key={i}>{warn}</li>
                ))}
              </ul>
            </div>
          )}
        </>
      )}
    </div>
  );
};
