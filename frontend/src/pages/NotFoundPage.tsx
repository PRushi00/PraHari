import React from "react";
import { Compass } from "lucide-react";

import type { NavTab } from "../components/Header";
import { ROUTES } from "../routing";

interface NotFoundPageProps {
  path: string;
  labels: Record<string, string>;
  onNavigate: (tab: NavTab) => void;
}

// An unknown path used to fall through to Overview, so a mistyped or stale
// link looked like it had worked. It now says what was asked for (ADR-084).
export const NotFoundPage: React.FC<NotFoundPageProps> = ({ path, labels, onNavigate }) => (
  <div className="glass-panel" style={{ padding: "2rem", maxWidth: 720, margin: "2rem auto" }}>
    <div style={{ display: "flex", alignItems: "center", gap: "0.75rem", marginBottom: "0.75rem" }}>
      <Compass size={22} style={{ color: "#f59e0b" }} />
      <h2 style={{ margin: 0 }}>Page not found</h2>
    </div>
    <p style={{ color: "var(--text-muted)" }}>
      There is no PraHari page at <code>{path}</code>. Nothing was loaded for it.
    </p>
    <ul style={{ listStyle: "none", padding: 0, display: "flex", flexWrap: "wrap", gap: "0.5rem" }}>
      {(Object.keys(ROUTES) as NavTab[]).map((tab) => (
        <li key={tab}>
          <button className="nav-btn" onClick={() => onNavigate(tab)}>
            {labels[tab] ?? tab}
          </button>
        </li>
      ))}
    </ul>
  </div>
);
