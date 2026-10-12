import React, { useState, useEffect } from "react";
import { Upload, FileText, CheckCircle2, XCircle, History } from "lucide-react";
import { api } from "../services/api";
import { ImportSummary } from "../types";

import { fmtTime } from "../utils/format";
interface ImportPageProps {
  onImportComplete: () => void;
}

export const ImportPage: React.FC<ImportPageProps> = ({ onImportComplete }) => {
  const [sourceId, setSourceId] = useState("perimeter_gw_01");
  const [sourceName, setSourceName] = useState("Perimeter Gateway");
  const [rawCsv, setRawCsv] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [importing, setImporting] = useState(false);
  const [currentSummary, setCurrentSummary] = useState<ImportSummary | null>(null);
  const [history, setHistory] = useState<ImportSummary[]>([]);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const loadHistory = async () => {
    try {
      const hist = await api.getImportHistory();
      setHistory(hist);
    } catch (err) {
      console.error("Failed to load import history:", err);
    }
  };

  useEffect(() => {
    loadHistory();
  }, []);

  const handleRawImport = async () => {
    if (!rawCsv.trim()) {
      setErrorMessage("Please enter or paste CSV content");
      return;
    }
    setImporting(true);
    setErrorMessage(null);
    try {
      const summary = await api.importRawCsv({
        source_id: sourceId,
        source_name: sourceName,
        csv_content: rawCsv,
      });
      setCurrentSummary(summary);
      await api.runDescriptiveAnalysis(sourceId);
      await loadHistory();
      onImportComplete();
    } catch (err: any) {
      setErrorMessage(err.message || "Import failed");
    } finally {
      setImporting(false);
    }
  };

  const handleFileUpload = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!file) {
      setErrorMessage("Please select a file to upload");
      return;
    }
    setImporting(true);
    setErrorMessage(null);
    try {
      const formData = new FormData();
      formData.append("file", file);
      formData.append("source_id", sourceId);
      formData.append("source_name", sourceName);

      const summary = await api.importCsvFile(formData);
      setCurrentSummary(summary);
      await api.runDescriptiveAnalysis(sourceId);
      await loadHistory();
      onImportComplete();
    } catch (err: any) {
      setErrorMessage(err.message || "Upload failed");
    } finally {
      setImporting(false);
    }
  };

  const insertSampleTemplate = () => {
    setRawCsv(`Src IP,Dst IP,Src Port,Dst Port,Protocol,Timestamp,Flow Duration,Tot Fwd Pkts,TotLen Fwd Pkts,Label
192.168.1.100,10.0.0.1,51000,443,6,2026-02-15 12:00:00,150000,12,3400,Benign
192.168.1.101,10.0.0.1,51002,443,6,2026-02-15 12:00:02,120000,10,2800,Benign
172.16.0.45,192.168.1.10,38000,22,6,2026-02-15 12:01:00,500000,8,1600,SSH-BruteForce
10.10.10.5,192.168.1.5,44000,80,6,2026-02-15 12:02:00,25000,2,128,DDoS-HOIC
999.999.999.999,10.0.0.1,51000,443,6,2026-02-15 12:03:00,1000,1,64,Benign
192.168.1.100,10.0.0.1,75000,443,6,2026-02-15 12:03:05,1000,1,64,Benign`);
  };

  return (
    <div>
      <div style={{ marginBottom: "1.5rem" }}>
        <h1 style={{ fontSize: "1.6rem", fontWeight: 700, letterSpacing: "-0.02em" }}>
          Telemetry Ingestion & CSV Import
        </h1>
        <p style={{ color: "var(--text-muted)", fontSize: "0.85rem", marginTop: "0.2rem" }}>
          Validates each record against network protocol standards and maps valid rows into the canonical NormalizedEvent schema.
        </p>
      </div>

      {errorMessage && (
        <div
          style={{
            background: "rgba(244, 63, 94, 0.15)",
            border: "1px solid rgba(244, 63, 94, 0.4)",
            padding: "1rem",
            borderRadius: "8px",
            color: "#fb7185",
            marginBottom: "1.5rem",
            display: "flex",
            alignItems: "center",
            gap: "0.5rem",
          }}
        >
          <XCircle size={18} />
          <span>{errorMessage}</span>
        </div>
      )}

      {/* Ingestion Configuration Card */}
      <div className="glass-panel" style={{ padding: "1.5rem", marginBottom: "1.5rem" }}>
        <h3 style={{ fontSize: "1rem", fontWeight: 600, marginBottom: "1rem" }}>Telemetry Source Metadata</h3>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "1rem" }}>
          <div>
            <label style={{ display: "block", fontSize: "0.75rem", color: "var(--text-muted)", marginBottom: "0.3rem" }}>
              Source Identifier (Unique ID)
            </label>
            <input
              type="text"
              value={sourceId}
              onChange={(e) => setSourceId(e.target.value)}
              placeholder="e.g. perimeter_gw_01"
            />
          </div>
          <div>
            <label style={{ display: "block", fontSize: "0.75rem", color: "var(--text-muted)", marginBottom: "0.3rem" }}>
              Source Friendly Name
            </label>
            <input
              type="text"
              value={sourceName}
              onChange={(e) => setSourceName(e.target.value)}
              placeholder="e.g. Perimeter Gateway IDS"
            />
          </div>
        </div>
      </div>

      {/* Two columns: File Upload vs Raw Text Paste */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "1.5rem", marginBottom: "2rem" }}>
        {/* File Upload Box */}
        <div className="glass-panel" style={{ padding: "1.5rem" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", marginBottom: "0.5rem" }}>
            <Upload size={18} color="#38bdf8" />
            <h3 style={{ fontSize: "1rem", fontWeight: 600 }}>Option A: Upload CSV File</h3>
          </div>
          <p style={{ color: "var(--text-dim)", fontSize: "0.75rem", marginBottom: "1.25rem" }}>
            Supports CIC-IDS2018 format and standard network flow exports (.csv, .txt)
          </p>

          <div
            style={{
              border: "2px dashed var(--border-subtle)",
              borderRadius: "10px",
              padding: "2rem 1rem",
              textAlign: "center",
              marginBottom: "1rem",
              background: "rgba(15, 23, 42, 0.4)",
            }}
          >
            <input
              type="file"
              accept=".csv,.txt"
              id="csvFileInput"
              style={{ display: "none" }}
              onChange={(e) => setFile(e.target.files?.[0] || null)}
            />
            <label htmlFor="csvFileInput" style={{ cursor: "pointer", display: "inline-block" }}>
              <FileText size={32} color="#94a3b8" style={{ margin: "0 auto 0.5rem" }} />
              <div style={{ fontSize: "0.85rem", color: "var(--text-main)", fontWeight: 500 }}>
                {file ? file.name : "Click to select a CSV file"}
              </div>
              <div style={{ fontSize: "0.75rem", color: "var(--text-dim)", marginTop: "0.25rem" }}>
                {file ? `${(file.size / 1024).toFixed(1)} KB` : "Drag and drop or browse"}
              </div>
            </label>
          </div>

          <button
            className="btn btn-primary"
            style={{ width: "100%", justifyContent: "center" }}
            onClick={handleFileUpload}
            disabled={importing || !file}
          >
            {importing ? "Processing..." : "Validate & Import File"}
          </button>
        </div>

        {/* Raw Text Paste */}
        <div className="glass-panel" style={{ padding: "1.5rem" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "0.5rem" }}>
            <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
              <FileText size={18} color="#34d399" />
              <h3 style={{ fontSize: "1rem", fontWeight: 600 }}>Option B: Paste Raw CSV</h3>
            </div>
            <button
              onClick={insertSampleTemplate}
              style={{
                background: "none",
                border: "none",
                color: "#38bdf8",
                fontSize: "0.75rem",
                cursor: "pointer",
                textDecoration: "underline",
              }}
            >
              Insert Test Sample
            </button>
          </div>
          <p style={{ color: "var(--text-dim)", fontSize: "0.75rem", marginBottom: "1rem" }}>
            Directly test ingestion and observe validation rejection mechanics
          </p>

          <textarea
            rows={7}
            value={rawCsv}
            onChange={(e) => setRawCsv(e.target.value)}
            placeholder="Src IP,Dst IP,Src Port,Dst Port,Protocol,Timestamp,Flow Duration,..."
            style={{ marginBottom: "1rem", resize: "vertical" }}
          />

          <button
            className="btn btn-primary"
            style={{ width: "100%", justifyContent: "center" }}
            onClick={handleRawImport}
            disabled={importing || !rawCsv.trim()}
          >
            {importing ? "Processing..." : "Validate & Ingest Text"}
          </button>
        </div>
      </div>

      {/* Result Breakdown Card */}
      {currentSummary && (
        <div className="glass-panel" style={{ padding: "1.5rem", marginBottom: "2rem", border: "1px solid var(--accent-cyan)" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", marginBottom: "1rem" }}>
            <CheckCircle2 size={20} color="#10b981" />
            <h3 style={{ fontSize: "1.1rem", fontWeight: 700 }}>Ingestion & Validation Report</h3>
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: "1rem", marginBottom: "1.5rem" }}>
            <div style={{ background: "rgba(15, 23, 42, 0.6)", padding: "1rem", borderRadius: "8px" }}>
              <div style={{ color: "var(--text-dim)", fontSize: "0.75rem" }}>Total Records Parsed</div>
              <div style={{ fontSize: "1.4rem", fontWeight: 700, fontFamily: "var(--font-mono)", marginTop: "0.2rem" }}>
                {currentSummary.total_records}
              </div>
            </div>

            <div style={{ background: "rgba(16, 185, 129, 0.1)", border: "1px solid rgba(16, 185, 129, 0.3)", padding: "1rem", borderRadius: "8px" }}>
              <div style={{ color: "#34d399", fontSize: "0.75rem" }}>Accepted & Persisted</div>
              <div style={{ fontSize: "1.4rem", fontWeight: 700, fontFamily: "var(--font-mono)", color: "#34d399", marginTop: "0.2rem" }}>
                {currentSummary.accepted_records}
              </div>
            </div>

            <div style={{ background: "rgba(244, 63, 94, 0.1)", border: "1px solid rgba(244, 63, 94, 0.3)", padding: "1rem", borderRadius: "8px" }}>
              <div style={{ color: "#fb7185", fontSize: "0.75rem" }}>Rejected (Corrupted)</div>
              <div style={{ fontSize: "1.4rem", fontWeight: 700, fontFamily: "var(--font-mono)", color: "#fb7185", marginTop: "0.2rem" }}>
                {currentSummary.rejected_records}
              </div>
            </div>

            <div style={{ background: "rgba(245, 158, 11, 0.1)", border: "1px solid rgba(245, 158, 11, 0.3)", padding: "1rem", borderRadius: "8px" }}>
              <div style={{ color: "#fbbf24", fontSize: "0.75rem" }}>Warnings / Flags</div>
              <div style={{ fontSize: "1.4rem", fontWeight: 700, fontFamily: "var(--font-mono)", color: "#fbbf24", marginTop: "0.2rem" }}>
                {currentSummary.warnings_count}
              </div>
            </div>
          </div>

          {/* Rejection reasons table */}
          {Object.keys(currentSummary.rejection_reasons).length > 0 && (
            <div>
              <h4 style={{ fontSize: "0.85rem", fontWeight: 600, color: "var(--text-muted)", marginBottom: "0.5rem" }}>
                Explicit Rejection Reasons:
              </h4>
              <div className="table-container">
                <table>
                  <thead>
                    <tr>
                      <th>Rejection Reason / Violation</th>
                      <th style={{ width: "120px" }}>Count</th>
                    </tr>
                  </thead>
                  <tbody>
                    {Object.entries(currentSummary.rejection_reasons).map(([reason, count]) => (
                      <tr key={reason}>
                        <td>
                          <span className="badge badge-attack" style={{ marginRight: "0.5rem" }}>REJECTED</span>
                          {reason}
                        </td>
                        <td>{count}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Import History Table */}
      <div className="glass-panel" style={{ padding: "1.5rem" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", marginBottom: "1rem" }}>
          <History size={18} color="#94a3b8" />
          <h3 style={{ fontSize: "1rem", fontWeight: 600 }}>Past Import Audit Log</h3>
        </div>

        <div className="table-container">
          <table>
            <thead>
              <tr>
                <th>Source ID</th>
                <th>File / Origin</th>
                <th>Started At</th>
                <th>Total</th>
                <th>Accepted</th>
                <th>Rejected</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {history.length > 0 ? (
                history.map((h) => (
                  <tr key={h.import_id}>
                    <td>{h.source_id}</td>
                    <td>{h.source_file || "<direct-stream>"}</td>
                    <td>{fmtTime(h.started_at, "—")}</td>
                    <td>{h.total_records}</td>
                    <td style={{ color: "#34d399" }}>{h.accepted_records}</td>
                    <td style={{ color: h.rejected_records > 0 ? "#fb7185" : "inherit" }}>
                      {h.rejected_records}
                    </td>
                    <td>
                      <span className={h.rejected_records === 0 ? "badge badge-benign" : "badge badge-warning"}>
                        {h.rejected_records === 0 ? "Clean" : "Filtered"}
                      </span>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={7} style={{ textAlign: "center", color: "var(--text-dim)", padding: "2rem" }}>
                    No import history logged yet.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
