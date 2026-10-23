import React, { useState, useEffect, useCallback } from "react";
import { Header, NavTab, WorkspaceNav } from "./components/Header";
import { ErrorBoundary } from "./components/ErrorBoundary";
import { GuidedModeProvider } from "./components/GuidedMode";
import { OverviewPage } from "./pages/OverviewPage";
import { ImportPage } from "./pages/ImportPage";
import { LiveTelemetryPage } from "./pages/LiveTelemetryPage";
import { StreamReplayPage } from "./pages/StreamReplayPage";
import { EventsPage } from "./pages/EventsPage";
import { SourcesPage } from "./pages/SourcesPage";
import { InvestigationPage } from "./pages/InvestigationPage";
import { TrafficPage } from "./pages/TrafficPage";
import { DnsPage } from "./pages/DnsPage";
import { AnalysisPage } from "./pages/AnalysisPage";
import { ResearchPage } from "./pages/ResearchPage";
import { ForecastPage } from "./pages/ForecastPage";
import { SystemHealthPage } from "./pages/SystemHealthPage";
import { AdministrationPage } from "./pages/AdministrationPage";
import { AuditPage } from "./pages/AuditPage";
import { NotFoundPage } from "./pages/NotFoundPage";
import { pathFor, resolvePath } from "./routing";
import { api } from "./services/api";
import { HealthResponse } from "./types";

const PAGE_LABELS: Record<string, string> = {
  overview: "Overview",
  live: "Live Telemetry",
  import: "CSV Import",
  stream: "Stream & Replay",
  events: "Events Explorer",
  sources: "Sources",
  analysis: "Analytics",
  research: "Feasibility",
  forecast: "Threat Forecasting",
  investigate: "Investigation",
  traffic: "Traffic",
  dns: "DNS Activity",
  system: "System Health",
  admin: "Administration",
  audit: "Audit & Security",
};

export const App: React.FC = () => {
  // The URL is the source of truth for the page (ADR-084): a deep link or
  // a refresh opens the page it names, and back/forward move between pages.
  const [route, setRoute] = useState(() => resolvePath(window.location.pathname));
  const activeTab = route.tab;

  const setActiveTab = useCallback((tab: NavTab) => {
    const path = pathFor(tab);
    if (window.location.pathname !== path) {
      window.history.pushState({ tab }, "", path);
    }
    setRoute({ tab, canonicalPath: path });
  }, []);

  useEffect(() => {
    // An alias or trailing slash is shown as the canonical path, without
    // adding a history entry.
    const initial = resolvePath(window.location.pathname);
    if (initial.tab && initial.canonicalPath !== window.location.pathname) {
      window.history.replaceState({ tab: initial.tab }, "", initial.canonicalPath);
    }
    const onPopState = () => setRoute(resolvePath(window.location.pathname));
    window.addEventListener("popstate", onPopState);
    return () => window.removeEventListener("popstate", onPopState);
  }, []);

  useEffect(() => {
    document.title = activeTab
      ? `${PAGE_LABELS[activeTab]} · PraHari`
      : "Page not found · PraHari";
  }, [activeTab]);
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
    <GuidedModeProvider>
    <div style={{ minHeight: "100vh", display: "flex", flexDirection: "column" }}>
      <Header
        activeTab={activeTab}
        onSelectTab={setActiveTab}
        onAddDevice={() => setActiveTab("sources")}
        health={health}
        loadingHealth={loadingHealth}
      />
      {/* The current workspace's pages. Nothing is rendered for Overview
          or for an unknown path, so neither shows an empty strip. */}
      {activeTab && <WorkspaceNav activeTab={activeTab} onSelectTab={setActiveTab} />}

      <main className="main-content" style={{ flex: 1 }}>
        {/* A render error inside a page must not unmount the application.
            Keying on activeTab resets the boundary on navigation, so a
            failed view recovers instead of staying broken forever. */}
        <ErrorBoundary
          pageName={activeTab ? PAGE_LABELS[activeTab] : "Page not found"}
          resetKey={activeTab ?? `not-found:${route.canonicalPath}`}
        >
        {activeTab === null && (
          <NotFoundPage
            path={route.canonicalPath}
            labels={PAGE_LABELS}
            onNavigate={setActiveTab}
          />
        )}
        {activeTab === "overview" && (
          <OverviewPage
            onNavigateToImport={() => setActiveTab("import")}
            onRefreshAll={fetchHealth}
            onNavigate={setActiveTab}
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
        {activeTab === "sources" && <SourcesPage />}
        {activeTab === "analysis" && <AnalysisPage />}
        {activeTab === "research" && <ResearchPage />}
        {activeTab === "forecast" && <ForecastPage />}
        {activeTab === "investigate" && <InvestigationPage />}
        {activeTab === "traffic" && <TrafficPage />}
        {activeTab === "dns" && <DnsPage />}
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
          fontSize: "var(--text-2xs)",
          color: "var(--text-dim)",
          background: "rgba(7, 10, 18, 0.8)",
        }}
      >
        PraHari — The Digital Sentinel &copy; {new Date().getFullYear()} • Canonical Security Telemetry & AI Assurance
      </footer>
    </div>
    </GuidedModeProvider>
  );
};
