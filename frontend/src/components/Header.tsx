import React from "react";
import {
  Shield,
  Activity,
  Database,
  FileSpreadsheet,
  BarChart2,
  Radio,
  FileCheck,
  TrendingUp,
  Lock,
} from "lucide-react";
import { HealthResponse } from "../types";

export type NavTab =
  | "overview"
  | "import"
  | "stream"
  | "events"
  | "analysis"
  | "research"
  | "forecast"
  | "audit";

interface HeaderProps {
  activeTab: NavTab;
  onSelectTab: (tab: NavTab) => void;
  health: HealthResponse | null;
  loadingHealth: boolean;
}

export const Header: React.FC<HeaderProps> = ({
  activeTab,
  onSelectTab,
  health,
  loadingHealth,
}) => {
  return (
    <header className="app-header">
      <div className="brand-section">
        <div className="brand-icon">
          <Shield size={22} />
        </div>
        <div>
          <div className="brand-title">PraHari</div>
          <div className="brand-subtitle">The Digital Sentinel • SOC Core</div>
        </div>
      </div>

      <nav className="nav-tabs">
        <button
          className={`nav-btn ${activeTab === "overview" ? "active" : ""}`}
          onClick={() => onSelectTab("overview")}
        >
          <Activity size={15} />
          Overview
        </button>
        <button
          className={`nav-btn ${activeTab === "import" ? "active" : ""}`}
          onClick={() => onSelectTab("import")}
        >
          <FileSpreadsheet size={15} />
          CSV Import
        </button>
        <button
          className={`nav-btn ${activeTab === "stream" ? "active" : ""}`}
          onClick={() => onSelectTab("stream")}
        >
          <Radio size={15} />
          Stream & Replay
        </button>
        <button
          className={`nav-btn ${activeTab === "events" ? "active" : ""}`}
          onClick={() => onSelectTab("events")}
        >
          <Database size={15} />
          Events Explorer
        </button>
        <button
          className={`nav-btn ${activeTab === "analysis" ? "active" : ""}`}
          onClick={() => onSelectTab("analysis")}
        >
          <BarChart2 size={15} />
          Analytics
        </button>
        <button
          className={`nav-btn ${activeTab === "research" ? "active" : ""}`}
          onClick={() => onSelectTab("research")}
        >
          <FileCheck size={15} />
          Feasibility
        </button>
        <button
          className={`nav-btn ${activeTab === "forecast" ? "active" : ""}`}
          onClick={() => onSelectTab("forecast")}
        >
          <TrendingUp size={15} />
          Threat Forecasting
        </button>
        <button
          className={`nav-btn ${activeTab === "audit" ? "active" : ""}`}
          onClick={() => onSelectTab("audit")}
        >
          <Lock size={15} />
          Audit & Security
        </button>
      </nav>

      <div style={{ display: "flex", alignItems: "center", gap: "1rem" }}>
        <div className="status-pill">
          <span className="status-dot" style={{ backgroundColor: health?.status === "healthy" ? "#10b981" : "#f59e0b" }} />
          <span>
            {loadingHealth
              ? "CONNECTING..."
              : health?.status === "healthy"
              ? `SYSTEM ONLINE (v${health.schema_version})`
              : "DEGRADED"}
          </span>
        </div>
      </div>
    </header>
  );
};
