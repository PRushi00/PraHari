import React, { useState, useEffect } from "react";
import { Header, NavTab } from "./components/Header";
import { ErrorBoundary } from "./components/ErrorBoundary";
import { OverviewPage } from "./pages/OverviewPage";
import { ImportPage } from "./pages/ImportPage";
import { LiveTelemetryPage } from "./pages/LiveTelemetryPage";
import { StreamReplayPage } from "./pages/StreamReplayPage";
import { EventsPage } from "./pages/EventsPage";
import { AnalysisPage } from "./pages/AnalysisPage";
import { ResearchPage } from "./pages/ResearchPage";
import { ForecastPage } from "./pages/ForecastPage";
import { SystemHealthPage } from "./pages/SystemHealthPage";
import { AdministrationPage } from "./pages/AdministrationPage";
import { AuditPage } from "./pages/AuditPage";
import { api } from "./services/api";
import { HealthResponse } from "./types";

const PAGE_LABELS: Record<string, string> = {
  overview: "Overview",
  live: "Live Telemetry",
  import: "CSV Import",
  stream: "Stream & Replay",
  events: "Events Explorer",
  analysis: "Analytics",
  research: "Feasibility",
  forecast: "Threat Forecasting",
  system: "System Health",
  admin: "Administration",
  audit: "Audit & Security",
};

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<NavTab>("overview");
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [loadingHealth, setLoadingHealth] = useState(true);

  const fetchHealth = async () => {
    try {
      const data = await api.getHealth();
      setHealth(data);
    } catch (err) {
      console.error("Health check error:", err);
    } finally {
      setLoadingHealth(false);
    }
  };

  useEffect(() => {
    fetchHealth();
    const interval = setInterval(fetchHealth, 15000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div style={{ minHeight: "100vh", display: "flex", flexDirection: "column" }}>
      <Header
        activeTab={activeTab}
        onSelectTab={setActiveTab}
        health={health}
        loadingHealth={loadingHealth}
      />

      <main className="main-content" style={{ flex: 1 }}>
        {/* A render error inside a page must not unmount the application.
            Keying on activeTab resets the boundary on navigation, so a
            failed view recovers instead of staying broken forever. */}
        <ErrorBoundary pageName={PAGE_LABELS[activeTab] ?? activeTab} resetKey={activeTab}>
        {activeTab === "overview" && (
          <OverviewPage
            onNavigateToImport={() => setActiveTab("import")}
            onRefreshAll={fetchHealth}
          />
        )}
        {activeTab === "live" && (
          <LiveTelemetryPage onDataChanged={fetchHealth} />
        )}
        {activeTab === "import" && (
          <ImportPage onImportComplete={fetchHealth} />
        )}
        {activeTab === "stream" && (
          <StreamReplayPage onReplayComplete={fetchHealth} />
        )}
        {activeTab === "events" && <EventsPage />}
        {activeTab === "analysis" && <AnalysisPage />}
        {activeTab === "research" && <ResearchPage />}
        {activeTab === "forecast" && <ForecastPage />}
        {activeTab === "system" && <SystemHealthPage />}
        {activeTab === "admin" && <AdministrationPage />}
        {activeTab === "audit" && <AuditPage />}
        </ErrorBoundary>
      </main>

      <footer
        style={{
          padding: "1.5rem 2rem",
          borderTop: "1px solid var(--border-subtle)",
          textAlign: "center",
          fontSize: "0.75rem",
          color: "var(--text-dim)",
          background: "rgba(7, 10, 18, 0.8)",
        }}
      >
        PraHari — The Digital Sentinel &copy; {new Date().getFullYear()} • Canonical Security Telemetry & AI Assurance
      </footer>
    </div>
  );
};
