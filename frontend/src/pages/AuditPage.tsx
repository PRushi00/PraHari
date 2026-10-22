import React, { useState, useEffect } from "react";
import {
  Lock,
  CheckCircle,
  AlertTriangle,
  RefreshCw,
  FileText,
  Activity,
} from "lucide-react";
import { api } from "../services/api";
import { AuditLog, SecurityConfig } from "../types";

import { fmtTimeUtc, humanise } from "../utils/format";

// What the Network Isolation card may claim, from the report alone. Green
// only when the backend has evidence for it (ADR-089): a null claim, or an
// older backend that does not report the listener, is unverified.
export function describeBinding(config: SecurityConfig | null): { label: string; color: string } {
  if (!config) return { label: "BINDING UNKNOWN", color: "#f59e0b" };
  if (config.loopback_enforced === false) return { label: "EXPOSED BEYOND LOOPBACK", color: "#ef4444" };
  if (config.loopback_enforced !== true || config.listener_matches_configuration !== true) {
    return { label: "BINDING UNVERIFIED", color: "#f59e0b" };
  }
  return { label: "LOOPBACK CONFIGURED", color: "#10b981" };
}
export const AuditPage: React.FC = () => {
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [config, setConfig] = useState<SecurityConfig | null>(null);
  const binding = describeBinding(config);
  const [selectedResourceType, setSelectedResourceType] = useState<string>("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchAuditData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [logsData, configData] = await Promise.all([
        api.getAuditLogs({ limit: 100, resource_type: selectedResourceType || undefined }),
        api.getSecurityConfig().catch(() => null),
      ]);
      setLogs(logsData);
      setConfig(configData);
    } catch (err: any) {
      setError(err.message || "Failed to load audit logs");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAuditData();
  }, [selectedResourceType]);

  return (
    <div className="page-container">
      {/* Page Header */}
      <div className="page-header" style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: "1rem" }}>
        <div>
          <h1 className="page-title">Security Boundaries & System Audit Logs</h1>
          <p className="page-subtitle">
            Immutable tracking of telemetry actions, model training sessions, and strict loopback boundary enforcement.
          </p>
        </div>
        <button
          className="btn btn-secondary"
          onClick={fetchAuditData}
          disabled={loading}
        >
          <RefreshCw size={15} className={loading ? "spin-icon" : ""} />
          Refresh Audit Trail
        </button>
      </div>

      {error && (
        <div className="glass-panel" style={{ padding: "1rem", marginBottom: "1.5rem", borderLeft: "4px solid var(--accent-rose)", color: "#fca5a5" }}>
          <div style={{ display: "flex", gap: "0.5rem", alignItems: "center" }}>
            <AlertTriangle size={18} />
            <span>{error}</span>
          </div>
        </div>
      )}

      {/* Security Compliance & Boundary Cards */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", gap: "1.25rem", marginBottom: "1.75rem" }}>
        {/* Loopback Status */}
        <div className="glass-panel" style={{ padding: "1.5rem" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "0.5rem" }}>
            <span style={{ fontSize: "var(--text-xs)", color: "var(--text-muted)", textTransform: "uppercase" }}>
              Network Isolation
            </span>
            <Lock size={18} style={{ color: binding.color }} />
          </div>
          {/* Rendered from the report, never asserted (ADR-078). This card
              used to print LOOPBACK ENFORCED unconditionally, and
              "127.0.0.1:8000" when the report was missing. */}
          <div
            data-testid="network-isolation-status"
            style={{ fontSize: "var(--text-lg)", fontWeight: 700, color: binding.color }}
          >
            {binding.label}
          </div>
          <div style={{ fontSize: "var(--text-xs)", color: "var(--text-dim)", marginTop: "0.25rem" }}>
            {config ? (
              <>
                Configured: <code>{`${config.host_binding}:${config.port}`}</code>
                {config.serving_port != null && (
                  <> · Serving: <code>{`${config.serving_host ?? "?"}:${config.serving_port}`}</code></>
                )}
              </>
            ) : (
              "Binding unknown: the configuration report could not be loaded."
            )}
          </div>
          {config?.binding_evidence && (
            <div style={{ fontSize: "var(--text-2xs)", color: "var(--text-dim)", marginTop: "0.35rem" }}>
              {config.binding_evidence}
            </div>
          )}
        </div>

        {/* Sniffing Disabled */}
        <div className="glass-panel" style={{ padding: "1.5rem" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "0.5rem" }}>
            <span style={{ fontSize: "var(--text-xs)", color: "var(--text-muted)", textTransform: "uppercase" }}>
              Packet Sniffing Boundary
            </span>
            <CheckCircle size={18} style={{ color: "#10b981" }} />
          </div>
          <div style={{ fontSize: "var(--text-lg)", fontWeight: 700, color: "#10b981" }}>
            {config?.security_boundaries?.["packet_capture_in_use"] === false
              ? "NO PACKET CAPTURE"
              : "PACKET CAPTURE STATE UNKNOWN"}
          </div>
          <div style={{ fontSize: "var(--text-xs)", color: "var(--text-dim)", marginTop: "0.25rem" }}>
            No raw socket or host interface modification permitted
          </div>
        </div>

        {/* Offline Eval Mode */}
        <div className="glass-panel" style={{ padding: "1.5rem" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "0.5rem" }}>
            <span style={{ fontSize: "var(--text-xs)", color: "var(--text-muted)", textTransform: "uppercase" }}>
              Evaluation Mode
            </span>
            <Activity size={18} style={{ color: "var(--accent-cyan)" }} />
          </div>
          <div style={{ fontSize: "var(--text-lg)", fontWeight: 700, color: "var(--accent-cyan)" }}>
            {String(
              config?.security_boundaries?.["live_collector_state"] ?? "unknown"
            ).toUpperCase()}
          </div>
          <div style={{ fontSize: "var(--text-xs)", color: "var(--text-dim)", marginTop: "0.25rem" }}>
            {/* Reported by the backend rather than hardcoded: the previous
                fixed list omitted the live Windows source entirely. */}
            {String(
              config?.security_boundaries?.["live_collection_method"] ??
                "Collection method not reported"
            )}
          </div>
        </div>
      </div>

      {/* Audit Trail Table */}
      <div className="glass-panel" style={{ padding: "1.75rem" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1.25rem", flexWrap: "wrap", gap: "1rem" }}>
          <div>
            <h2 style={{ fontSize: "var(--text-lg)", display: "flex", alignItems: "center", gap: "0.5rem" }}>
              <FileText size={20} style={{ color: "var(--accent-cyan)" }} />
              Immutable Audit Action Log
            </h2>
            <p style={{ fontSize: "var(--text-xs)", color: "var(--text-dim)", marginTop: "0.2rem" }}>
              Every ingestion, model training, evaluation, and research audit is logged with timestamp and resource ID.
            </p>
          </div>
          <div>
            <select
              className="form-select"
              value={selectedResourceType}
              onChange={(e) => setSelectedResourceType(e.target.value)}
              style={{ width: "200px" }}
            >
              <option value="">All Resource Types</option>
              <option value="model_pipeline">Model Pipelines</option>
              <option value="csv_import">CSV Imports</option>
              <option value="json_stream">JSON Streaming</option>
              <option value="synthetic_replay">Synthetic Replay</option>
              <option value="research_audit">Research Feasibility</option>
              <option value="system">System Core</option>
            </select>
          </div>
        </div>

        {loading && logs.length === 0 ? (
          <div style={{ padding: "3rem", textAlign: "center", color: "var(--text-muted)" }}>
            <RefreshCw size={28} className="spin-icon" style={{ margin: "0 auto 1rem auto" }} />
            <p>Loading audit trail...</p>
          </div>
        ) : logs.length === 0 ? (
          <div style={{ padding: "3rem", textAlign: "center", color: "var(--text-muted)" }}>
            <p>No audit actions recorded yet.</p>
          </div>
        ) : (
          <div style={{ overflowX: "auto" }}>
            <table className="data-table" style={{ width: "100%", textAlign: "left" }}>
              <thead>
                <tr>
                  <th>Timestamp (UTC)</th>
                  <th>Action</th>
                  <th>Resource Type</th>
                  <th>Resource ID</th>
                  <th>Details</th>
                </tr>
              </thead>
              <tbody>
                {logs.map((log) => (
                  <tr key={log.id}>
                    <td style={{ fontSize: "var(--text-xs)", fontFamily: "var(--font-mono)", color: "var(--text-muted)", whiteSpace: "nowrap" }}>
                      {fmtTimeUtc(log.timestamp, "—")}
                    </td>
                    <td style={{ fontWeight: 600, color: "var(--accent-cyan)" }}>
                      <code>{log.action}</code>
                    </td>
                    <td>
                      <span className="badge" style={{ background: "rgba(255,255,255,0.06)", color: "var(--text-main)" }}>
                        {humanise(log.resource_type)}
                      </span>
                    </td>
                    <td style={{ fontSize: "var(--text-xs)", color: "var(--text-dim)" }}>
                      {log.resource_id || "—"}
                    </td>
                    <td style={{ fontSize: "var(--text-xs)", color: "var(--text-muted)" }}>
                      {log.details || "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};
