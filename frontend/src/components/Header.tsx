import React from "react";
import { Shield, Activity, Database, FileSpreadsheet, BarChart2 } from "lucide-react";
import { HealthResponse } from "../types";

export type NavTab = "overview" | "import" | "events" | "analysis";

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
          Ingestion & Import
        </button>
        <button
          className={`nav-btn ${activeTab === "events" ? "active" : ""}`}
          onClick={() => onSelectTab("events")}
        >
          <Database size={15} />
          Normalized Events
        </button>
        <button
          className={`nav-btn ${activeTab === "analysis" ? "active" : ""}`}
          onClick={() => onSelectTab("analysis")}
        >
          <BarChart2 size={15} />
          Descriptive Analysis
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
