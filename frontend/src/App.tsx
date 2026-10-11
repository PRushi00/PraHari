import React, { useState, useEffect } from "react";
import { Header, NavTab } from "./components/Header";
import { OverviewPage } from "./pages/OverviewPage";
import { ImportPage } from "./pages/ImportPage";
import { StreamReplayPage } from "./pages/StreamReplayPage";
import { EventsPage } from "./pages/EventsPage";
import { AnalysisPage } from "./pages/AnalysisPage";
import { ResearchPage } from "./pages/ResearchPage";
import { ForecastPage } from "./pages/ForecastPage";
import { AuditPage } from "./pages/AuditPage";
import { api } from "./services/api";
import { HealthResponse } from "./types";

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
        {activeTab === "overview" && (
          <OverviewPage
            onNavigateToImport={() => setActiveTab("import")}
            onRefreshAll={fetchHealth}
          />
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
        {activeTab === "audit" && <AuditPage />}
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
