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
  Network,
  ShieldCheck,
  Server,
  Plus,
} from "lucide-react";
import { HealthResponse } from "../types";
import { GuidedModeToggle } from "./GuidedMode";

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

/** The four places a person can be. Everything else lives inside one. */
export type Workspace = "overview" | "network" | "security" | "system";

export interface NavEntry {
  tab: NavTab;
  label: string;
  icon: React.ReactNode;
}

interface WorkspaceDef {
  id: Workspace;
  label: string;
  icon: React.ReactNode;
  /** Pages inside this workspace, in the order its secondary nav shows them. */
  tabs: NavEntry[];
}

/**
 * Four primary destinations, not fifteen.
 *
 * The previous header listed every page across three stacked rows
 * (Monitor / Forecast / Operate, ADR-118). Every page was one click
 * away, which was the intent, but the row was the first thing on screen
 * and the last thing anyone could read: fifteen choices with no order
 * among them, pushing real telemetry below the fold.
 *
 * The pages have not changed and none has been removed. What changed is
 * that the header now answers "where am I" instead of "what exists" —
 * the inventory moved into each workspace, next to the work it belongs
 * to, where the list is short enough to read.
 *
 * `overview` carries no secondary nav on purpose: it is a summary, and a
 * summary with tabs is not one.
 */
export const WORKSPACES: WorkspaceDef[] = [
  {
    id: "overview",
    label: "Overview",
    icon: <Activity size={15} />,
    tabs: [],
  },
  {
    id: "network",
    label: "Network",
    icon: <Network size={15} />,
    tabs: [
      { tab: "live", label: "Live Telemetry", icon: <Wifi size={14} /> },
      { tab: "traffic", label: "Connections", icon: <Filter size={14} /> },
      { tab: "dns", label: "DNS Activity", icon: <Globe size={14} /> },
      { tab: "sources", label: "Devices & Sources", icon: <Radio size={14} /> },
      { tab: "events", label: "Events Explorer", icon: <Database size={14} /> },
      { tab: "analysis", label: "Analytics", icon: <BarChart2 size={14} /> },
      { tab: "import", label: "CSV Import", icon: <FileSpreadsheet size={14} /> },
      { tab: "stream", label: "Stream & Replay", icon: <Radio size={14} /> },
    ],
  },
  {
    id: "security",
    label: "Security",
    icon: <ShieldCheck size={15} />,
    tabs: [
      { tab: "forecast", label: "Threat Forecasting", icon: <TrendingUp size={14} /> },
      { tab: "investigate", label: "Investigation", icon: <Search size={14} /> },
      { tab: "research", label: "Feasibility", icon: <FileCheck size={14} /> },
    ],
  },
  {
    id: "system",
    label: "System",
    icon: <Server size={15} />,
    tabs: [
      { tab: "system", label: "System Health", icon: <HeartPulse size={14} /> },
      { tab: "admin", label: "Administration", icon: <Settings size={14} /> },
      { tab: "audit", label: "Audit & Security", icon: <Lock size={14} /> },
    ],
  },
];

const WORKSPACE_OF: Record<NavTab, Workspace> = (() => {
  const map = { overview: "overview" } as Record<NavTab, Workspace>;
  for (const ws of WORKSPACES) {
    for (const entry of ws.tabs) map[entry.tab] = ws.id;
  }
  return map;
})();

/** Which workspace a page belongs to. Total over NavTab by construction. */
export function workspaceOf(tab: NavTab): Workspace {
  return WORKSPACE_OF[tab];
}

/**
 * The page a workspace opens on when its primary button is clicked.
 *
 * Security opens on Threat Forecasting rather than Feasibility. ADR-115
 * established that a newcomer should run Feasibility first, and that
 * still holds — but it is the Overview page that says so, in the words
 * a newcomer needs. Opening the Security workspace on a readiness audit
 * would answer a question the operator did not ask.
 */
export function defaultTabOf(workspace: Workspace): NavTab {
  const ws = WORKSPACES.find((w) => w.id === workspace);
  return ws && ws.tabs.length ? ws.tabs[0].tab : "overview";
}

export function tabsOf(workspace: Workspace): NavEntry[] {
  return WORKSPACES.find((w) => w.id === workspace)?.tabs ?? [];
}

interface HeaderProps {
  // null on an unknown path: no page is current (ADR-084).
  activeTab: NavTab | null;
  onSelectTab: (tab: NavTab) => void;
  onAddDevice: () => void;
  health: HealthResponse | null;
  loadingHealth: boolean;
}

export const Header: React.FC<HeaderProps> = ({
  activeTab,
  onSelectTab,
  onAddDevice,
  health,
  loadingHealth,
}) => {
  const active = activeTab ? workspaceOf(activeTab) : null;

  // The pill reports the API PraHari is talking to. It deliberately does
  // not say "host online": nothing here has measured the host.
  const ok = health?.status === "healthy";
  const statusLabel = loadingHealth
    ? "Connecting…"
    : ok
    ? "Backend online"
    : "Backend degraded";

  return (
    <header className="app-header">
      <div className="brand-section">
        <div className="brand-icon">
          <Shield size={20} />
        </div>
        <div>
          <div className="brand-title">PraHari</div>
          <div className="brand-subtitle">Network Security</div>
        </div>
      </div>

      <nav className="nav-tabs" aria-label="Primary">
        {WORKSPACES.map((ws) => (
          <button
            key={ws.id}
            className={`nav-btn ${active === ws.id ? "active" : ""}`}
            aria-current={active === ws.id ? "page" : undefined}
            onClick={() => onSelectTab(defaultTabOf(ws.id))}
          >
            {ws.icon}
            {ws.label}
          </button>
        ))}
      </nav>

      <div className="header-actions">
        <GuidedModeToggle />
        <div
          className="status-pill"
          title={
            ok
              ? `Schema v${health?.schema_version}. This reports the PraHari API, not the health of this machine.`
              : "PraHari could not reach its own API."
          }
        >
          <span
            className="status-dot"
            style={{ backgroundColor: ok ? "#10b981" : "#f59e0b" }}
          />
          <span>{statusLabel}</span>
        </div>
        <button className="btn btn-primary btn-sm" onClick={onAddDevice}>
          <Plus size={14} /> Add device
        </button>
      </div>
    </header>
  );
};

interface WorkspaceNavProps {
  activeTab: NavTab;
  onSelectTab: (tab: NavTab) => void;
}

/**
 * The pages of the current workspace. Rendered only when there is more
 * than one, so Overview shows no empty strip.
 */
export const WorkspaceNav: React.FC<WorkspaceNavProps> = ({
  activeTab,
  onSelectTab,
}) => {
  const workspace = workspaceOf(activeTab);
  const entries = tabsOf(workspace);
  if (entries.length < 2) return null;

  const label = WORKSPACES.find((w) => w.id === workspace)?.label ?? "";

  return (
    <nav className="workspace-nav" aria-label={`${label} pages`}>
      {entries.map((entry) => (
        <button
          key={entry.tab}
          className={`workspace-btn ${activeTab === entry.tab ? "active" : ""}`}
          aria-current={activeTab === entry.tab ? "page" : undefined}
          onClick={() => onSelectTab(entry.tab)}
        >
          {entry.icon}
          {entry.label}
        </button>
      ))}
    </nav>
  );
};
