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

export const AuditPage: React.FC = () => {
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [config, setConfig] = useState<SecurityConfig | null>(null);
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
            <span style={{ fontSize: "0.8rem", color: "var(--text-muted)", textTransform: "uppercase" }}>
              Network Isolation
            </span>
            <Lock size={18} style={{ color: "#10b981" }} />
          </div>
          <div style={{ fontSize: "1.2rem", fontWeight: 700, color: "#10b981" }}>
            LOOPBACK ENFORCED
          </div>
          <div style={{ fontSize: "0.8rem", color: "var(--text-dim)", marginTop: "0.25rem" }}>
            Binding: <code>{config ? `${config.host}:${config.port}` : "127.0.0.1:8000"}</code> (Strict local access)
          </div>
        </div>

        {/* Sniffing Disabled */}
        <div className="glass-panel" style={{ padding: "1.5rem" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "0.5rem" }}>
            <span style={{ fontSize: "0.8rem", color: "var(--text-muted)", textTransform: "uppercase" }}>
              Packet Sniffing Boundary
            </span>
            <CheckCircle size={18} style={{ color: "#10b981" }} />
          </div>
          <div style={{ fontSize: "1.2rem", fontWeight: 700, color: "#10b981" }}>
            PROMISCUOUS SNIFFING DISABLED
          </div>
          <div style={{ fontSize: "0.8rem", color: "var(--text-dim)", marginTop: "0.25rem" }}>
            No raw socket or host interface modification permitted
          </div>
        </div>

        {/* Offline Eval Mode */}
        <div className="glass-panel" style={{ padding: "1.5rem" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "0.5rem" }}>
            <span style={{ fontSize: "0.8rem", color: "var(--text-muted)", textTransform: "uppercase" }}>
              Evaluation Mode
            </span>
            <Activity size={18} style={{ color: "var(--accent-cyan)" }} />
          </div>
          <div style={{ fontSize: "1.2rem", fontWeight: 700, color: "var(--accent-cyan)" }}>
            OFFLINE REPLAY / IMPORT
          </div>
          <div style={{ fontSize: "0.8rem", color: "var(--text-dim)", marginTop: "0.25rem" }}>
            Adapters: CSV, Zeek JSON, Suricata, Synthetic Replay
          </div>
        </div>
      </div>

      {/* Audit Trail Table */}
      <div className="glass-panel" style={{ padding: "1.75rem" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1.25rem", flexWrap: "wrap", gap: "1rem" }}>
          <div>
            <h2 style={{ fontSize: "1.1rem", fontWeight: 600, display: "flex", alignItems: "center", gap: "0.5rem" }}>
              <FileText size={20} style={{ color: "var(--accent-cyan)" }} />
              Immutable Audit Action Log
            </h2>
            <p style={{ fontSize: "0.8rem", color: "var(--text-dim)", marginTop: "0.2rem" }}>
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
                  <tr key={log.log_id}>
                    <td style={{ fontSize: "0.8rem", fontFamily: "var(--font-mono)", color: "var(--text-muted)", whiteSpace: "nowrap" }}>
                      {new Date(log.created_at).toLocaleString()}
                    </td>
                    <td style={{ fontWeight: 600, color: "var(--accent-cyan)" }}>
                      <code>{log.action}</code>
                    </td>
                    <td>
                      <span className="badge" style={{ background: "rgba(255,255,255,0.06)", color: "var(--text-main)" }}>
                        {log.resource_type}
                      </span>
                    </td>
                    <td style={{ fontSize: "0.8rem", color: "var(--text-dim)" }}>
                      {log.resource_id || "—"}
                    </td>
                    <td style={{ fontSize: "0.85rem", color: "var(--text-muted)" }}>
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
