import React from "react";
import {
  Shield,
  Activity,
  Database,
  FileSpreadsheet,
  BarChart2,
  Radio,
  Wifi,
  FileCheck,
  TrendingUp,
  Lock,
  HeartPulse,
  Settings,
  Search,
  Filter,
  Globe,
} from "lucide-react";
import { HealthResponse } from "../types";
import { GuidedModeToggle, useGuidedMode } from "./GuidedMode";

export type NavTab =
  | "overview"
  | "live"
  | "import"
  | "stream"
  | "events"
  | "sources"
  | "analysis"
  | "research"
  | "forecast"
  | "investigate"
  | "traffic"
  | "dns"
  | "system"
  | "admin"
  | "audit";

interface HeaderProps {
  // null on an unknown path: no page is current (ADR-084).
  activeTab: NavTab | null;
  onSelectTab: (tab: NavTab) => void;
  health: HealthResponse | null;
  loadingHealth: boolean;
}

interface NavEntry {
  tab: NavTab;
  label: string;
  icon: React.ReactNode;
}

/**
 * Thirteen flat tabs is a complexity problem of its own: nothing says
 * which of them a newcomer should open first, or that `Feasibility`
 * comes before `Threat Forecasting` (ADR-115).
 *
 * **Monitor and Forecast are peers** (ADR-118). A proposal to make
 * PraHari a monitoring dashboard would have moved forecasting into
 * "advanced views"; `README.md` defines this system as causal future
 * threat forecasting, and monitoring dashboards are a solved category
 * while a forecaster that refuses when the data cannot support a claim
 * is not. Neither workflow is subordinate to the other.
 *
 * `Operate` is a third group because settings and audit are a different
 * kind of activity, not a lesser one. Every tab remains reachable in
 * every mode: this changes what the row makes you read, never what it
 * lets you open.
 */
const NAV_GROUPS: { legend: string; entries: NavEntry[] }[] = [
  {
    legend: "Monitor",
    entries: [
      { tab: "overview", label: "Overview", icon: <Activity size={15} /> },
      { tab: "live", label: "Live Telemetry", icon: <Wifi size={15} /> },
      { tab: "sources", label: "Devices & Sources", icon: <Radio size={15} /> },
      { tab: "traffic", label: "Traffic", icon: <Filter size={15} /> },
      { tab: "dns", label: "DNS Activity", icon: <Globe size={15} /> },
      { tab: "events", label: "Events Explorer", icon: <Database size={15} /> },
      { tab: "analysis", label: "Analytics", icon: <BarChart2 size={15} /> },
      { tab: "import", label: "CSV Import", icon: <FileSpreadsheet size={15} /> },
      { tab: "stream", label: "Stream & Replay", icon: <Radio size={15} /> },
    ],
  },
  {
    legend: "Forecast",
    entries: [
      { tab: "research", label: "Feasibility", icon: <FileCheck size={15} /> },
      { tab: "forecast", label: "Threat Forecasting", icon: <TrendingUp size={15} /> },
      { tab: "investigate", label: "Investigation", icon: <Search size={15} /> },
    ],
  },
  {
    legend: "Operate",
    entries: [
      { tab: "system", label: "System Health", icon: <HeartPulse size={15} /> },
      { tab: "admin", label: "Administration", icon: <Settings size={15} /> },
      { tab: "audit", label: "Audit & Security", icon: <Lock size={15} /> },
    ],
  },
];

export const Header: React.FC<HeaderProps> = ({
  activeTab,
  onSelectTab,
  health,
  loadingHealth,
}) => {
  const { guided } = useGuidedMode();

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

      <nav className="nav-tabs" aria-label="Primary">
        {NAV_GROUPS.map((group) => (
          <div className="nav-group" key={group.legend}>
            {/* The legend is guidance, so it goes with the rest of the
                guidance. An expert reads the tab names directly. */}
            {guided && <span className="nav-group-label">{group.legend}</span>}
            <div className="nav-group-row">
              {group.entries.map((entry) => (
                <button
                  key={entry.tab}
                  className={`nav-btn ${activeTab === entry.tab ? "active" : ""}`}
                  onClick={() => onSelectTab(entry.tab)}
                >
                  {entry.icon}
                  {entry.label}
                </button>
              ))}
            </div>
          </div>
        ))}
      </nav>

      <div style={{ display: "flex", alignItems: "center", gap: "1rem" }}>
        <GuidedModeToggle />
        <div className="status-pill">
          <span
            className="status-dot"
            style={{
              backgroundColor: health?.status === "healthy" ? "#10b981" : "#f59e0b",
            }}
          />
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
