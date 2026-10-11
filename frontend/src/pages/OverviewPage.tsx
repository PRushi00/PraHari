import React, { useEffect, useState } from "react";
import ReactECharts from "echarts-for-react";
import { ShieldAlert, Server, Network, Layers, RefreshCw, UploadCloud, CheckCircle } from "lucide-react";
import { api } from "../services/api";
import { EventSummaryStats, HealthResponse, DescriptiveAnalysis } from "../types";

interface OverviewPageProps {
  onNavigateToImport: () => void;
  onRefreshAll: () => void;
}

export const OverviewPage: React.FC<OverviewPageProps> = ({ onNavigateToImport, onRefreshAll }) => {
  const [stats, setStats] = useState<EventSummaryStats | null>(null);
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [analysis, setAnalysis] = useState<DescriptiveAnalysis | null>(null);
  const [loading, setLoading] = useState(true);
  const [seeding, setSeeding] = useState(false);
  const [seedSuccess, setSeedSuccess] = useState(false);

  const loadData = async () => {
    setLoading(true);
    try {
      const [h, s, a] = await Promise.all([
        api.getHealth(),
        api.getEventStats(),
        api.getLatestAnalysis(),
      ]);
      setHealth(h);
      setStats(s);
      setAnalysis(a);
    } catch (err) {
      console.error("Failed to load overview data:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleSeedSampleData = async () => {
    setSeeding(true);
    try {
      const sampleCsv = `Src IP,Dst IP,Src Port,Dst Port,Protocol,Timestamp,Flow Duration,Tot Fwd Pkts,TotLen Fwd Pkts,Label
192.168.1.105,10.0.0.1,51420,443,6,2026-02-15 08:30:00,1250000,15,4500,Benign
192.168.1.105,10.0.0.1,51422,443,6,2026-02-15 08:30:05,850000,8,2100,Benign
192.168.1.110,10.0.0.5,49152,80,6,2026-02-15 08:30:10,320000,4,840,Benign
192.168.1.120,8.8.8.8,55123,53,17,2026-02-15 08:30:15,45000,2,140,Benign
172.16.0.50,192.168.1.100,41001,22,6,2026-02-15 08:31:00,500000,6,1200,SSH-BruteForce
172.16.0.50,192.168.1.100,41002,22,6,2026-02-15 08:31:02,520000,6,1200,SSH-BruteForce
10.200.0.15,192.168.1.10,33001,80,6,2026-02-15 08:32:00,15000,1,64,DDoS-HOIC
10.200.0.16,192.168.1.10,33002,80,6,2026-02-15 08:32:00,16000,1,64,DDoS-HOIC
192.168.2.200,192.168.1.10,60001,21,6,2026-02-15 08:33:00,20000,2,100,PortScan
192.168.2.200,192.168.1.10,60002,22,6,2026-02-15 08:33:01,20000,2,100,PortScan
172.16.5.99,192.168.1.50,52100,21,6,2026-02-15 08:34:00,300000,5,600,FTP-BruteForce
999.999.999.999,10.0.0.1,51420,443,6,2026-02-15 08:38:00,1000,2,100,Benign
192.168.1.105,10.0.0.1,70000,443,6,2026-02-15 08:38:02,1000,2,100,Benign`;

      await api.importRawCsv({
        source_id: "soc_perimeter_sensor",
        source_name: "Perimeter Flow Sensor (CIC-IDS Fixture)",
        csv_content: sampleCsv,
      });

      await api.runDescriptiveAnalysis("soc_perimeter_sensor");
      setSeedSuccess(true);
      await loadData();
      onRefreshAll();
      setTimeout(() => setSeedSuccess(false), 4000);
    } catch (err) {
      console.error("Seeding failed:", err);
    } finally {
      setSeeding(false);
    }
  };

  // ECharts Option: Traffic Labels Pie
  const labelChartData = Object.entries(stats?.labels || {}).map(([name, value]) => ({
    name,
    value,
    itemStyle: {
      color:
        name.toLowerCase() === "benign"
          ? "#10b981"
          : name.includes("BruteForce")
          ? "#f43f5e"
          : name.includes("DDoS")
          ? "#f59e0b"
          : "#06b6d4",
    },
  }));

  const labelPieOption = {
    backgroundColor: "transparent",
    tooltip: { trigger: "item", formatter: "{b}: {c} events ({d}%)" },
    legend: {
      bottom: 0,
      textStyle: { color: "#94a3b8", fontSize: 11 },
    },
    series: [
      {
        name: "Security Classification",
        type: "pie",
        radius: ["45%", "70%"],
        avoidLabelOverlap: false,
        itemStyle: {
          borderRadius: 8,
          borderColor: "#0f172a",
          borderWidth: 2,
        },
        label: { show: false },
        emphasis: {
          label: {
            show: true,
            fontSize: 13,
            fontWeight: "bold",
            color: "#fff",
          },
        },
        data: labelChartData.length > 0 ? labelChartData : [{ name: "No Data", value: 1, itemStyle: { color: "#334155" } }],
      },
    ],
  };

  // ECharts Option: Top Targeted Ports Bar
  const topPorts = analysis?.top_dst_ports || [];
  const portsBarOption = {
    backgroundColor: "transparent",
    tooltip: { trigger: "axis" },
    grid: { left: "10%", right: "8%", bottom: "15%", top: "10%" },
    xAxis: {
      type: "category",
      data: topPorts.map((p) => `Port ${p.port}`),
      axisLabel: { color: "#94a3b8", fontSize: 11 },
      axisLine: { lineStyle: { color: "#334155" } },
    },
    yAxis: {
      type: "value",
      axisLabel: { color: "#94a3b8", fontSize: 11 },
      splitLine: { lineStyle: { color: "rgba(51, 65, 85, 0.4)" } },
    },
    series: [
      {
        name: "Flow Hits",
        type: "bar",
        data: topPorts.map((p) => p.count),
        itemStyle: {
          color: {
            type: "linear",
            x: 0,
            y: 0,
            x2: 0,
            y2: 1,
            colorStops: [
              { offset: 0, color: "#38bdf8" },
              { offset: 1, color: "#1e40af" },
            ],
          },
          borderRadius: [4, 4, 0, 0],
        },
      },
    ],
  };

  return (
    <div>
      {/* Top action row */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1.5rem" }}>
        <div>
          <h1 style={{ fontSize: "1.6rem", fontWeight: 700, letterSpacing: "-0.02em" }}>
            SOC Monitoring & Analytics Dashboard
          </h1>
          <p style={{ color: "var(--text-muted)", fontSize: "0.85rem", marginTop: "0.2rem" }}>
            Verified Ingestion Pipeline • Canonical Schema v{health?.schema_version || "1.0.0"} • SQLite Persistence
          </p>
        </div>

        <div style={{ display: "flex", gap: "0.75rem" }}>
          <button className="btn btn-secondary" onClick={loadData} disabled={loading}>
            <RefreshCw size={15} className={loading ? "spin" : ""} />
            Refresh
          </button>
          <button className="btn btn-primary" onClick={handleSeedSampleData} disabled={seeding}>
            {seedSuccess ? <CheckCircle size={15} color="#34d399" /> : <UploadCloud size={15} />}
            {seeding ? "Importing Fixture..." : seedSuccess ? "Fixture Ingested!" : "Load Sample Fixture"}
          </button>
        </div>
      </div>

      {/* Stat Cards */}
      <div className="stat-grid">
        <div className="glass-panel stat-card">
          <div className="stat-header">
            <span className="stat-label">Persisted Events</span>
            <Network className="stat-icon" size={20} />
          </div>
          <div className="stat-value">{stats?.total_events.toLocaleString() || "0"}</div>
          <div className="stat-subtext">Normalized canonical flows</div>
        </div>

        <div className="glass-panel stat-card blue">
          <div className="stat-header">
            <span className="stat-label">Telemetry Sources</span>
            <Server className="stat-icon" size={20} style={{ color: "var(--accent-blue)" }} />
          </div>
          <div className="stat-value">{stats?.sources_count || "0"}</div>
          <div className="stat-subtext">Active sensors & import channels</div>
        </div>

        <div className="glass-panel stat-card rose">
          <div className="stat-header">
            <span className="stat-label">Security Classifications</span>
            <ShieldAlert className="stat-icon" size={20} style={{ color: "var(--accent-rose)" }} />
          </div>
          <div className="stat-value">{Object.keys(stats?.labels || {}).length}</div>
          <div className="stat-subtext">
            {Object.keys(stats?.labels || {}).filter((k) => k.toLowerCase() !== "benign").length} attack categories detected
          </div>
        </div>

        <div className="glass-panel stat-card emerald">
          <div className="stat-header">
            <span className="stat-label">System Storage</span>
            <Layers className="stat-icon" size={20} style={{ color: "var(--accent-emerald)" }} />
          </div>
          <div className="stat-value">WAL Mode</div>
          <div className="stat-subtext">SQLite transaction isolation</div>
        </div>
      </div>

      {/* If database is empty, show welcoming prompt */}
      {(!stats || stats.total_events === 0) && (
        <div
          className="glass-panel"
          style={{
            padding: "2.5rem",
            textAlign: "center",
            marginBottom: "2rem",
            background: "linear-gradient(135deg, rgba(6, 182, 212, 0.08), rgba(15, 23, 42, 0.8))",
          }}
        >
          <div style={{ maxWidth: "560px", margin: "0 auto" }}>
            <h2 style={{ fontSize: "1.25rem", marginBottom: "0.5rem" }}>Telemetry Store is Currently Empty</h2>
            <p style={{ color: "var(--text-muted)", fontSize: "0.9rem", marginBottom: "1.5rem" }}>
              The PraHari ingest pipeline is ready to validate, normalize, and audit network flows. You can load our
              curated 45-row CIC-IDS2018 test fixture with 1-click or upload your own CSV file.
            </p>
            <div style={{ display: "flex", gap: "1rem", justifyContent: "center" }}>
              <button className="btn btn-primary" onClick={handleSeedSampleData} disabled={seeding}>
                <UploadCloud size={16} />
                Load Sample CIC-IDS Fixture
              </button>
              <button className="btn btn-secondary" onClick={onNavigateToImport}>
                Upload Custom CSV
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Charts Row */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "1.5rem", marginBottom: "2rem" }}>
        <div className="glass-panel" style={{ padding: "1.5rem" }}>
          <h3 style={{ fontSize: "1rem", fontWeight: 600, marginBottom: "0.5rem" }}>Security Label Breakdown</h3>
          <p style={{ color: "var(--text-dim)", fontSize: "0.75rem", marginBottom: "1rem" }}>
            Distribution of benign vs attack classes across imported telemetry
          </p>
          <div style={{ height: "260px" }}>
            <ReactECharts option={labelPieOption} style={{ height: "100%", width: "100%" }} />
          </div>
        </div>

        <div className="glass-panel" style={{ padding: "1.5rem" }}>
          <h3 style={{ fontSize: "1rem", fontWeight: 600, marginBottom: "0.5rem" }}>Top Destination Ports</h3>
          <p style={{ color: "var(--text-dim)", fontSize: "0.75rem", marginBottom: "1rem" }}>
            Factual distribution of connection endpoints (e.g. 443, 80, 22, 21)
          </p>
          <div style={{ height: "260px" }}>
            {topPorts.length > 0 ? (
              <ReactECharts option={portsBarOption} style={{ height: "100%", width: "100%" }} />
            ) : (
              <div
                style={{
                  height: "100%",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  color: "var(--text-dim)",
                  fontSize: "0.85rem",
                }}
              >
                No port distribution data available yet
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Recent Analysis Summary Card */}
      {analysis && (
        <div className="glass-panel" style={{ padding: "1.5rem" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1rem" }}>
            <div>
              <h3 style={{ fontSize: "1rem", fontWeight: 600 }}>Descriptive Analysis Summary</h3>
              <p style={{ color: "var(--text-dim)", fontSize: "0.75rem" }}>
                Computed at {new Date(analysis.computed_at).toLocaleString()} • Scope: {analysis.source_id}
              </p>
            </div>
            <span className="badge badge-info">Factual Statistics Only (No Forecast)</span>
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: "1rem" }}>
            <div style={{ background: "rgba(15, 23, 42, 0.5)", padding: "1rem", borderRadius: "8px" }}>
              <div style={{ color: "var(--text-dim)", fontSize: "0.75rem" }}>Unique Source IPs</div>
              <div style={{ fontSize: "1.3rem", fontWeight: 700, fontFamily: "var(--font-mono)", marginTop: "0.25rem" }}>
                {analysis.unique_src_ips}
              </div>
            </div>
            <div style={{ background: "rgba(15, 23, 42, 0.5)", padding: "1rem", borderRadius: "8px" }}>
              <div style={{ color: "var(--text-dim)", fontSize: "0.75rem" }}>Unique Destination IPs</div>
              <div style={{ fontSize: "1.3rem", fontWeight: 700, fontFamily: "var(--font-mono)", marginTop: "0.25rem" }}>
                {analysis.unique_dst_ips}
              </div>
            </div>
            <div style={{ background: "rgba(15, 23, 42, 0.5)", padding: "1rem", borderRadius: "8px" }}>
              <div style={{ color: "var(--text-dim)", fontSize: "0.75rem" }}>Avg Flow Duration</div>
              <div style={{ fontSize: "1.3rem", fontWeight: 700, fontFamily: "var(--font-mono)", marginTop: "0.25rem" }}>
                {analysis.avg_duration ? `${(analysis.avg_duration / 1000).toFixed(1)} ms` : "N/A"}
              </div>
            </div>
            <div style={{ background: "rgba(15, 23, 42, 0.5)", padding: "1rem", borderRadius: "8px" }}>
              <div style={{ color: "var(--text-dim)", fontSize: "0.75rem" }}>Records With Warnings</div>
              <div style={{ fontSize: "1.3rem", fontWeight: 700, fontFamily: "var(--font-mono)", marginTop: "0.25rem" }}>
                {analysis.records_with_warnings}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
