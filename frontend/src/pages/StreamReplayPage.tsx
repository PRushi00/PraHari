import React, { useState, useEffect } from "react";
import {
  Radio,
  Play,
  CheckCircle,
  AlertTriangle,
  Code,
  Zap,
} from "lucide-react";
import { api } from "../services/api";
import { AdapterHealth, SyntheticReplayResponse, ImportSummary } from "../types";

import { fmtElapsed, fmtInt, fmtTime } from "../utils/format";
import { Explain } from "../components/GuidedMode";
export const StreamReplayPage: React.FC<{ onReplayComplete?: () => void }> = ({ onReplayComplete }) => {
  const [adapters, setAdapters] = useState<AdapterHealth[]>([]);
  const [replayCount, setReplayCount] = useState<number>(100);
  const [attackRatio, setAttackRatio] = useState<number>(0.25);
  const [seed, setSeed] = useState<number>(42);
  const [replaying, setReplaying] = useState(false);
  const [replayResult, setReplayResult] = useState<SyntheticReplayResponse | null>(null);

  // NDJSON streaming state
  const [ndjsonSourceId, setNdjsonSourceId] = useState<string>("zeek_sensor_01");
  const [ndjsonSourceName, setNdjsonSourceName] = useState<string>("Zeek Core Sensor");
  const [ndjsonFormat, setNdjsonFormat] = useState<string>("zeek");
  const [ndjsonContent, setNdjsonContent] = useState<string>("");
  const [ingesting, setIngesting] = useState(false);
  const [ingestResult, setIngestResult] = useState<ImportSummary | null>(null);
  const [error, setError] = useState<string | null>(null);

  const fetchAdapters = async () => {
    try {
      const data = await api.getStreamAdapters();
      setAdapters(data);
    } catch (err: any) {
      console.error(err);
    }
  };

  useEffect(() => {
    fetchAdapters();
  }, []);

  const handleSyntheticReplay = async () => {
    setReplaying(true);
    setError(null);
    try {
      const res = await api.replaySyntheticFlows({
        source_id: "synthetic_replay_engine",
        source_name: "Synthetic Enterprise Replay",
        count: replayCount,
        attack_ratio: attackRatio,
        seed: seed,
      });
      setReplayResult(res);
      fetchAdapters();
      if (onReplayComplete) onReplayComplete();
    } catch (err: any) {
      setError(err.message || "Synthetic replay failed");
    } finally {
      setReplaying(false);
    }
  };

  const handleLoadSampleNdjson = () => {
    if (ndjsonFormat === "zeek") {
      setNdjsonContent(
        JSON.stringify({
          ts: Date.now() / 1000 - 60,
          uid: "Cabcdef123456789",
          "id.orig_h": "192.168.1.105",
          "id.orig_p": 49152,
          "id.resp_h": "10.0.0.1",
          "id.resp_p": 443,
          proto: "tcp",
          duration: 0.125,
          orig_bytes: 1240,
          resp_bytes: 8450,
          conn_state: "SF",
        }) +
          "\n" +
          JSON.stringify({
            ts: Date.now() / 1000 - 30,
            uid: "Cxyz987654321000",
            "id.orig_h": "198.51.100.22",
            "id.orig_p": 54321,
            "id.resp_h": "10.0.0.5",
            "id.resp_p": 22,
            proto: "tcp",
            duration: 0.05,
            orig_bytes: 520,
            resp_bytes: 380,
            conn_state: "REJ",
          })
      );
    } else {
      setNdjsonContent(
        JSON.stringify({
          timestamp: new Date(Date.now() - 45000).toISOString(),
          event_type: "flow",
          src_ip: "192.168.1.150",
          src_port: 52000,
          dest_ip: "1.1.1.1",
          dest_port: 53,
          proto: "UDP",
          flow: { bytes_toclient: 120, bytes_toserver: 64, pkts_toclient: 1, pkts_toserver: 1, age: 0.01 },
        })
      );
    }
  };

  const handleIngestNdjson = async () => {
    if (!ndjsonContent.trim()) {
      setError("Please provide NDJSON content or load a sample template");
      return;
    }
    setIngesting(true);
    setError(null);
    try {
      const res = await api.ingestNdjsonStream({
        source_id: ndjsonSourceId,
        source_name: ndjsonSourceName,
        format: ndjsonFormat,
        ndjson_content: ndjsonContent,
      });
      setIngestResult(res);
      fetchAdapters();
      if (onReplayComplete) onReplayComplete();
    } catch (err: any) {
      setError(err.message || "NDJSON ingestion failed");
    } finally {
      setIngesting(false);
    }
  };

  return (
    <div className="page-container">
      {/* Page Header */}
      <div className="page-header">
        <h1 className="page-title">Streaming Ingestion & Synthetic Replay</h1>
        <p className="page-subtitle">
          Safe telemetry streaming via Zeek / Suricata JSON logs and deterministic synthetic flow replay engines.
        </p>
        <Explain>
          Feed records in continuously, or replay a synthetic stream to see
          how the system behaves under load. Synthetic records are marked as
          such and never counted as real evidence.
        </Explain>
      </div>

      {error && (
        <div className="glass-panel" style={{ padding: "1rem", marginBottom: "1.5rem", borderLeft: "4px solid var(--accent-rose)", color: "#fca5a5" }}>
          <div style={{ display: "flex", gap: "0.5rem", alignItems: "center" }}>
            <AlertTriangle size={18} />
            <span>{error}</span>
          </div>
        </div>
      )}

      {/* Adapter Status Cards */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", gap: "1.25rem", marginBottom: "1.75rem" }}>
        {adapters.map((ad, idx) => (
          <div key={idx} className="glass-panel" style={{ padding: "1.5rem" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "0.5rem" }}>
              <span style={{ fontSize: "var(--text-xs)", color: "var(--text-muted)", textTransform: "uppercase" }}>
                {ad.adapter_type} Adapter
              </span>
              <span className="badge" style={{ background: ad.is_healthy ? "rgba(16, 185, 129, 0.2)" : "rgba(244, 63, 94, 0.2)", color: ad.is_healthy ? "#10b981" : "#f43f5e" }}>
                {ad.is_healthy ? "HEALTHY" : "ERROR"}
              </span>
            </div>
            <div style={{ fontSize: "var(--text-lg)", fontWeight: 700, color: "var(--text-main)", marginBottom: "0.5rem" }}>
              {ad.adapter_id}
            </div>
            <div style={{ fontSize: "var(--text-xs)", color: "var(--text-dim)", display: "flex", gap: "1rem" }}>
              <span>Processed: <strong style={{ color: "#10b981" }}>{fmtInt(ad.records_processed)}</strong></span>
              <span>Rejected: <strong style={{ color: (ad.records_rejected ?? 0) > 0 ? "#f43f5e" : "var(--text-dim)" }}>{fmtInt(ad.records_rejected)}</strong></span>
            </div>
            <div style={{ fontSize: "var(--text-2xs)", color: "var(--text-dim)", marginTop: "0.4rem" }}>
              Last active: {fmtTime(ad.last_active_at, "never")}
            </div>
            {ad.error_message && (
              <div style={{ fontSize: "var(--text-2xs)", color: "#fca5a5", marginTop: "0.35rem" }}>
                {ad.error_message}
              </div>
            )}
          </div>
        ))}
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(380px, 1fr))", gap: "1.75rem" }}>
        {/* Synthetic Generator Card */}
        <div className="glass-panel" style={{ padding: "1.75rem" }}>
          <h2 style={{ fontSize: "var(--text-lg)", marginBottom: "0.5rem", display: "flex", alignItems: "center", gap: "0.5rem" }}>
            <Zap size={20} style={{ color: "var(--accent-cyan)" }} />
            Deterministic Synthetic Flow Generator
          </h2>
          <p style={{ fontSize: "var(--text-xs)", color: "var(--text-dim)", marginBottom: "1.25rem" }}>
            Generates realistic enterprise benign traffic punctuated with episodic brute-force, scan, and DoS attack bursts. Tagged explicitly as synthetic demo.
          </p>

          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "1rem", marginBottom: "1rem" }}>
            <div>
              <label style={{ fontSize: "var(--text-xs)", color: "var(--text-muted)", display: "block", marginBottom: "0.3rem" }}>
                Flow Batch Size
              </label>
              <input
                type="number"
                className="form-input"
                min="10"
                max="2000"
                value={replayCount}
                onChange={(e) => setReplayCount(parseInt(e.target.value) || 50)}
                style={{ width: "100%" }}
              />
            </div>
            <div>
              <label style={{ fontSize: "var(--text-xs)", color: "var(--text-muted)", display: "block", marginBottom: "0.3rem" }}>
                PRNG Seed
              </label>
              <input
                type="number"
                className="form-input"
                value={seed}
                onChange={(e) => setSeed(parseInt(e.target.value) || 42)}
                style={{ width: "100%" }}
              />
            </div>
          </div>

          <div style={{ marginBottom: "1.5rem" }}>
            <div style={{ display: "flex", justifyContent: "space-between", fontSize: "var(--text-xs)", color: "var(--text-muted)", marginBottom: "0.3rem" }}>
              <span>Attack Burst Ratio</span>
              <span style={{ fontWeight: 600, color: "var(--accent-cyan)" }}>{(attackRatio * 100).toFixed(0)}%</span>
            </div>
            <input
              type="range"
              min="0.0"
              max="0.8"
              step="0.05"
              value={attackRatio}
              onChange={(e) => setAttackRatio(parseFloat(e.target.value))}
              style={{ width: "100%", accentColor: "var(--accent-cyan)" }}
            />
          </div>

          <button
            className="btn btn-primary"
            onClick={handleSyntheticReplay}
            disabled={replaying}
            style={{ width: "100%", justifyContent: "center" }}
          >
            <Play size={16} className={replaying ? "spin-icon" : ""} />
            {replaying ? "Generating Flows..." : "Generate & Seed Replay"}
          </button>

          {replayResult && (
            <div style={{ marginTop: "1.5rem", padding: "1rem", borderRadius: "var(--radius-md)", background: "rgba(6, 182, 212, 0.08)", border: "1px solid var(--border-highlight)" }}>
              <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", color: "#10b981", fontWeight: 600, fontSize: "var(--text-xs)" }}>
                <CheckCircle size={18} />
                <span>Replay Batch Generated Successfully</span>
              </div>
              <div style={{ fontSize: "var(--text-xs)", color: "var(--text-muted)", marginTop: "0.5rem", display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0.5rem" }}>
                <div>Records Generated: <strong>{fmtInt(replayResult.total_records)}</strong></div>
                <div>Accepted: <strong style={{ color: "#10b981" }}>{fmtInt(replayResult.accepted_records)}</strong></div>
                <div>Rejected: <strong style={{ color: (replayResult.rejected_records ?? 0) > 0 ? "#f43f5e" : "var(--text-dim)" }}>{fmtInt(replayResult.rejected_records)}</strong></div>
                {/* Elapsed time is DERIVED from the summary's own timestamps.
                    The previous code read a duration_seconds field that the
                    backend never returns. */}
                <div>Elapsed: <strong>{fmtElapsed(replayResult.started_at, replayResult.completed_at)}</strong></div>
                <div style={{ gridColumn: "1 / -1" }}>
                  Category: <strong>{replayResult.data_category ?? "—"}</strong>{" "}
                  <span style={{ color: "var(--text-dim)" }}>
                    (synthetic records, kept distinct from live telemetry)
                  </span>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* NDJSON Stream Ingest Card */}
        <div className="glass-panel" style={{ padding: "1.75rem" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "0.5rem" }}>
            <h2 style={{ fontSize: "var(--text-lg)", display: "flex", alignItems: "center", gap: "0.5rem" }}>
              <Radio size={20} style={{ color: "var(--accent-indigo)" }} />
              NDJSON Stream Ingestion
            </h2>
            <button className="btn btn-secondary" onClick={handleLoadSampleNdjson} style={{ padding: "0.3rem 0.6rem", fontSize: "var(--text-2xs)" }}>
              <Code size={14} /> Load Sample
            </button>
          </div>
          <p style={{ fontSize: "var(--text-xs)", color: "var(--text-dim)", marginBottom: "1.25rem" }}>
            Simulate real-time sensor streams by posting newline-delimited JSON logs in Zeek or Suricata format.
          </p>

          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "1rem", marginBottom: "1rem" }}>
            <div>
              <label style={{ fontSize: "var(--text-xs)", color: "var(--text-muted)", display: "block", marginBottom: "0.3rem" }}>
                Log Format
              </label>
              <select
                className="form-select"
                value={ndjsonFormat}
                onChange={(e) => setNdjsonFormat(e.target.value)}
                style={{ width: "100%" }}
              >
                <option value="zeek">Zeek (conn.log JSON)</option>
                <option value="suricata">Suricata (eve.json)</option>
                <option value="ndjson">Generic NDJSON Flow</option>
              </select>
            </div>
            <div>
              <label style={{ fontSize: "var(--text-xs)", color: "var(--text-muted)", display: "block", marginBottom: "0.3rem" }}>
                Sensor Source ID
              </label>
              <input
                type="text"
                className="form-input"
                value={ndjsonSourceId}
                onChange={(e) => setNdjsonSourceId(e.target.value)}
                style={{ width: "100%" }}
              />
            </div>
            <div>
              <label style={{ fontSize: "var(--text-xs)", color: "var(--text-muted)", display: "block", marginBottom: "0.3rem" }}>
                Sensor Display Name
              </label>
              <input
                type="text"
                className="form-input"
                value={ndjsonSourceName}
                onChange={(e) => setNdjsonSourceName(e.target.value)}
                style={{ width: "100%" }}
              />
            </div>
          </div>

          <div style={{ marginBottom: "1.25rem" }}>
            <label style={{ fontSize: "var(--text-xs)", color: "var(--text-muted)", display: "block", marginBottom: "0.3rem" }}>
              Stream Payload (One JSON Object Per Line)
            </label>
            <textarea
              className="form-input"
              rows={5}
              value={ndjsonContent}
              onChange={(e) => setNdjsonContent(e.target.value)}
              placeholder='{"ts": 1700000000.0, "id.orig_h": "192.168.1.50", "id.resp_h": "10.0.0.1", ...}'
              style={{ width: "100%", fontFamily: "var(--font-mono)", fontSize: "var(--text-2xs)", lineHeight: 1.4 }}
            />
          </div>

          <button
            className="btn btn-primary"
            onClick={handleIngestNdjson}
            disabled={ingesting}
            style={{ width: "100%", justifyContent: "center" }}
          >
            <Play size={16} className={ingesting ? "spin-icon" : ""} />
            {ingesting ? "Ingesting Stream..." : "Ingest Stream Batch"}
          </button>

          {ingestResult && (
            <div style={{ marginTop: "1.5rem", padding: "1rem", borderRadius: "var(--radius-md)", background: "rgba(99, 102, 241, 0.08)", border: "1px solid var(--border-subtle)" }}>
              <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", color: "#10b981", fontWeight: 600, fontSize: "var(--text-xs)" }}>
                <CheckCircle size={18} />
                <span>Stream Ingestion Complete</span>
              </div>
              <div style={{ fontSize: "var(--text-xs)", color: "var(--text-muted)", marginTop: "0.5rem", display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0.5rem" }}>
                <div>Total Records: <strong>{ingestResult.total_records}</strong></div>
                <div>Accepted: <strong style={{ color: "#10b981" }}>{ingestResult.accepted_records}</strong></div>
                <div>Rejected: <strong style={{ color: ingestResult.rejected_records > 0 ? "#f43f5e" : "var(--text-dim)" }}>{ingestResult.rejected_records}</strong></div>
                <div>Warnings: <strong>{ingestResult.warnings_count}</strong></div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
