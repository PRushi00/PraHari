import React, { useCallback, useEffect, useState } from "react";
import {
  AlertTriangle,
  CheckCircle,
  FileCheck,
  Info,
  RefreshCw,
  ShieldCheck,
  XCircle,
} from "lucide-react";
import { api } from "../services/api";
import {
  FeasibilityCheckResult,
  FeasibilityReport,
  TelemetrySource,
} from "../types";

/**
 * Research Feasibility Scorecard.
 *
 * Renders the backend's actual FeasibilityReport contract
 * (app/research/feasibility.py). The checklist is driven by the `checks`
 * array rather than hard-coded criterion names, so a backend that adds or
 * renames a check cannot leave this page referencing a field that no longer
 * exists — the failure mode that previously blanked the application.
 */

const RISK_COLOR: Record<string, string> = {
  low: "#10b981",
  medium: "#f59e0b",
  high: "#f43f5e",
  critical: "#f43f5e",
};

const RECOMMENDATION_STYLE: Record<string, { color: string; label: string }> = {
  PERMIT_FORECASTING: { color: "#10b981", label: "PERMIT FORECASTING" },
  CONDITIONAL_REVIEW: { color: "#f59e0b", label: "CONDITIONAL REVIEW" },
  REJECT_FORECASTING: { color: "#f43f5e", label: "REJECT FORECASTING" },
};

const fmtTime = (iso?: string | null): string => {
  if (!iso) return "—";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? "—" : d.toLocaleString();
};

/** Percent formatter that tolerates a missing or non-numeric score. */
const pct = (value: unknown): string =>
  typeof value === "number" && Number.isFinite(value)
    ? `${(value * 100).toFixed(1)}%`
    : "—";

export const ResearchPage: React.FC = () => {
  const [report, setReport] = useState<FeasibilityReport | null>(null);
  const [sources, setSources] = useState<TelemetrySource[]>([]);
  const [selectedSource, setSelectedSource] = useState<string>("");
  const [loading, setLoading] = useState(true);
  const [runningAudit, setRunningAudit] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const loadInitial = useCallback(async () => {
    setLoading(true);
    setError(null);
    // Sources and the existing report are fetched independently: a failure
    // in one must not prevent the other from rendering.
    const [srcResult, repResult] = await Promise.allSettled([
      api.getSources(),
      api.getResearchReport(),
    ]);

    if (srcResult.status === "fulfilled") {
      setSources(srcResult.value ?? []);
    } else {
      console.error("Failed to load telemetry sources:", srcResult.reason);
    }

    if (repResult.status === "fulfilled") {
      setReport(repResult.value ?? null);
    } else {
      setError(
        repResult.reason instanceof Error
          ? repResult.reason.message
          : "Failed to load the existing feasibility audit."
      );
    }
    setLoading(false);
  }, []);

  useEffect(() => {
    loadInitial();
  }, [loadInitial]);

  const runAudit = async () => {
    setRunningAudit(true);
    setError(null);
    try {
      const rep = await api.runResearchAudit(selectedSource || undefined);
      setReport(rep ?? null);
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Failed to execute the feasibility audit."
      );
    } finally {
      setRunningAudit(false);
    }
  };

  const checks: FeasibilityCheckResult[] = Array.isArray(report?.checks)
    ? report!.checks
    : [];
  const metrics = report?.metrics ?? {};
  const rec = report
    ? RECOMMENDATION_STYLE[report.recommendation] ?? {
        color: "var(--text-muted)",
        label: String(report.recommendation ?? "UNKNOWN"),
      }
    : null;

  return (
    <div className="page-container">
      {/* Header & controls */}
      <div
        className="page-header"
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "flex-start",
          flexWrap: "wrap",
          gap: "1rem",
        }}
      >
        <div>
          <h1 className="page-title">Research Feasibility Scorecard</h1>
          <p className="page-subtitle">
            Audits stored telemetry for temporal integrity, label ground truth,
            provenance and data quality before any forecasting claim is made.
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
                {s.name} ({s.event_count} events)
              </option>
            ))}
          </select>
          <button className="btn btn-primary" onClick={runAudit} disabled={runningAudit}>
            <RefreshCw size={15} className={runningAudit ? "spin-icon" : ""} />
            {runningAudit ? "Running Audit..." : "Run Feasibility Audit"}
          </button>
        </div>
      </div>

      {/* Error state — recoverable, never fatal */}
      {error && (
        <div
          className="glass-panel"
          style={{
            padding: "1rem 1.25rem",
            marginBottom: "1.5rem",
            borderLeft: "4px solid var(--accent-rose)",
            color: "#fca5a5",
          }}
        >
          <div style={{ display: "flex", gap: "0.5rem", alignItems: "center" }}>
            <AlertTriangle size={18} />
            <span>{error}</span>
          </div>
          <button
            className="btn btn-secondary"
            onClick={loadInitial}
            style={{ marginTop: "0.9rem" }}
          >
            <RefreshCw size={14} /> Retry
          </button>
        </div>
      )}

      {/* Loading state */}
      {loading ? (
        <div
          className="glass-panel"
          style={{ padding: "3rem", textAlign: "center", color: "var(--text-muted)" }}
        >
          <RefreshCw size={28} className="spin-icon" style={{ margin: "0 auto 1rem auto" }} />
          <p>Loading research feasibility baseline…</p>
        </div>
      ) : !report ? (
        /* Empty state */
        <div
          className="glass-panel"
          style={{ padding: "3rem", textAlign: "center", color: "var(--text-muted)" }}
        >
          <FileCheck size={36} style={{ color: "var(--accent-cyan)", margin: "0 auto 1rem auto" }} />
          <h3>No feasibility audit has been run yet</h3>
          <p style={{ marginTop: "0.5rem" }}>
            Run an audit over the persisted events to assess whether the data can
            support defensible forecasting research.
          </p>
          <button
            className="btn btn-primary"
            onClick={runAudit}
            style={{ marginTop: "1.5rem" }}
            disabled={runningAudit}
          >
            Run Audit Now
          </button>
        </div>
      ) : (
        <>
          {/* Summary */}
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fit, minmax(270px, 1fr))",
              gap: "1.25rem",
              marginBottom: "1.5rem",
            }}
          >
            <div className="glass-panel" style={{ padding: "1.5rem" }}>
              <div
                style={{
                  fontSize: "var(--text-xs)",
                  color: "var(--text-muted)",
                  textTransform: "uppercase",
                  letterSpacing: "0.05em",
                }}
              >
                Feasibility Gate
              </div>
              <div style={{ display: "flex", alignItems: "center", gap: "0.75rem", marginTop: "0.75rem" }}>
                {report.gate_passed ? (
                  <CheckCircle size={32} style={{ color: "#10b981" }} />
                ) : (
                  <XCircle size={32} style={{ color: "#f43f5e" }} />
                )}
                <div>
                  <div
                    style={{
                      fontSize: "var(--text-lg)",
                      fontWeight: 700,
                      color: report.gate_passed ? "#10b981" : "#f43f5e",
                    }}
                  >
                    {report.gate_passed ? "GATE PASSED" : "GATE NOT PASSED"}
                  </div>
                  <div style={{ fontSize: "var(--text-xs)", color: "var(--text-dim)" }}>
                    {report.gate_passed
                      ? "All audited criteria satisfied"
                      : "One or more criteria unsatisfied"}
                  </div>
                </div>
              </div>
            </div>

            <div className="glass-panel" style={{ padding: "1.5rem" }}>
              <div
                style={{
                  fontSize: "var(--text-xs)",
                  color: "var(--text-muted)",
                  textTransform: "uppercase",
                  letterSpacing: "0.05em",
                }}
              >
                Overall Feasibility Score
              </div>
              <div style={{ display: "flex", alignItems: "baseline", gap: "0.4rem", marginTop: "0.75rem" }}>
                <span style={{ fontSize: "var(--text-2xl)", fontWeight: 800, color: "var(--accent-cyan)" }}>
                  {pct(report.overall_score)}
                </span>
              </div>
              <div style={{ fontSize: "var(--text-2xs)", color: "var(--text-dim)", marginTop: "0.25rem" }}>
                Dataset: <code style={{ color: "var(--text-muted)" }}>{report.dataset_id}</code>
                <br />
                Evaluated {fmtTime(report.evaluated_at)}
              </div>
            </div>

            <div className="glass-panel" style={{ padding: "1.5rem" }}>
              <div
                style={{
                  fontSize: "var(--text-xs)",
                  color: "var(--text-muted)",
                  textTransform: "uppercase",
                  letterSpacing: "0.05em",
                }}
              >
                Recommendation
              </div>
              <div
                style={{
                  marginTop: "0.75rem",
                  fontSize: "var(--text-lg)",
                  fontWeight: 700,
                  color: rec?.color,
                }}
              >
                {rec?.label}
              </div>
              <div style={{ fontSize: "var(--text-2xs)", color: "var(--text-dim)", marginTop: "0.4rem", lineHeight: 1.5 }}>
                Advisory. Forecasting is additionally gated in the backend — see
                Threat Forecasting for the enforced readiness state.
              </div>
            </div>
          </div>

          {/* Criteria checklist — driven by the API, not hard-coded */}
          <div className="glass-panel" style={{ padding: "1.75rem", marginBottom: "1.5rem" }}>
            <h2
              style={{
                fontSize: "var(--text-lg)",
                marginBottom: "1.25rem",
                display: "flex",
                alignItems: "center",
                gap: "0.5rem",
              }}
            >
              <ShieldCheck size={20} style={{ color: "var(--accent-cyan)" }} />
              Research Criteria ({checks.filter((c) => c.passed).length}/{checks.length} passed)
            </h2>

            {checks.length === 0 ? (
              <div style={{ color: "var(--text-dim)", fontSize: "var(--text-xs)" }}>
                The audit returned no individual criteria.
              </div>
            ) : (
              <div style={{ display: "grid", gap: "1rem" }}>
                {checks.map((check, i) => {
                  const color = RISK_COLOR[check.risk_level] ?? "var(--text-muted)";
                  return (
                    <div
                      key={`${check.check_name}-${i}`}
                      className="glass-panel"
                      style={{ padding: "1rem 1.25rem", background: "rgba(15, 23, 42, 0.4)" }}
                    >
                      <div
                        style={{
                          display: "flex",
                          justifyContent: "space-between",
                          alignItems: "center",
                          gap: "1rem",
                          marginBottom: "0.35rem",
                          flexWrap: "wrap",
                        }}
                      >
                        <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", fontWeight: 600 }}>
                          {check.passed ? (
                            <CheckCircle size={18} style={{ color: "#10b981" }} />
                          ) : check.risk_level === "critical" || check.risk_level === "high" ? (
                            <XCircle size={18} style={{ color: "#f43f5e" }} />
                          ) : (
                            <AlertTriangle size={18} style={{ color: "#f59e0b" }} />
                          )}
                          <span>{check.check_name}</span>
                        </div>
                        <div style={{ display: "flex", gap: "0.5rem", alignItems: "center" }}>
                          <span style={{ fontSize: "var(--text-2xs)", color: "var(--text-dim)" }}>
                            score {pct(check.score)}
                          </span>
                          <span
                            className="badge"
                            style={{ background: "rgba(255,255,255,0.06)", color }}
                          >
                            {check.passed ? "PASSED" : String(check.risk_level ?? "").toUpperCase()}
                          </span>
                        </div>
                      </div>
                      <div style={{ fontSize: "var(--text-xs)", color: "var(--text-muted)", lineHeight: 1.6 }}>
                        {check.details}
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          {/* Measured values behind the verdict */}
          {Object.keys(metrics).length > 0 && (
            <div className="glass-panel" style={{ padding: "1.5rem" }}>
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: "0.5rem",
                  fontWeight: 600,
                  marginBottom: "0.9rem",
                }}
              >
                <Info size={18} style={{ color: "var(--accent-cyan)" }} />
                <span>Measured Dataset Properties</span>
              </div>
              <div
                style={{
                  display: "grid",
                  gridTemplateColumns: "repeat(auto-fit, minmax(170px, 1fr))",
                  gap: "1rem",
                }}
              >
                {Object.entries(metrics).map(([key, value]) => (
                  <div key={key}>
                    <div style={{ fontSize: "var(--text-lg)", fontWeight: 600 }}>{String(value)}</div>
                    <div style={{ fontSize: "var(--text-2xs)", color: "var(--text-dim)" }}>
                      {key.replace(/_/g, " ")}
                    </div>
                  </div>
                ))}
              </div>
              <div
                style={{
                  marginTop: "1.1rem",
                  fontSize: "var(--text-2xs)",
                  color: "var(--text-dim)",
                  lineHeight: 1.7,
                }}
              >
                Locally observed traffic carries no incident ground truth, so an
                audit of live telemetry alone will report no attack labels. That
                is an accurate finding, not a collection failure.
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
};
