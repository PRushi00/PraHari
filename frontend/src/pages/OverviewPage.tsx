// Overview — host, network and security signals at a glance (ADR-124).
//
// This page is the one most likely to be read as a claim about the
// network, so every figure on it names what it counted:
//
//   * **Stored, not seen.** Counts describe PraHari's store, not the
//     wire. A quiet number means little was collected, which is not the
//     same as little having happened.
//   * **Registered is not monitored.** A device appears once someone
//     types its address in. Nothing watches it until an agent or a
//     sensor reports on its behalf, and the card says so rather than
//     letting a row imply coverage (ADR-118).
//   * **DNS evidence is not connection evidence.** A resolved name is
//     proof a lookup happened, never proof a connection followed, so
//     the two panels stay apart and are labelled apart.
//   * **No chart without data behind it.** Where there is nothing to
//     plot the panel says what is missing and what to do about it.

import React, { useCallback, useEffect, useState } from "react";
import ReactECharts from "echarts-for-react";
import {
  Activity,
  AlertTriangle,
  CheckCircle,
  Database,
  Globe,
  RefreshCw,
  Radio,
  Server,
  UploadCloud,
} from "lucide-react";
import { api } from "../services/api";
import {
  CollectorStatus,
  ConnectionDetail,
  DescriptiveAnalysis,
  DnsObservationRow,
  EventSummaryStats,
  HealthResponse,
  HostIdentity,
  SourceHealthRecord,
} from "../types";

import { fmtInt, fmtTime, humanise } from "../utils/format";
import { Caption, Explain } from "../components/GuidedMode";
import { HostAndDevices } from "../components/HostAndDevices";
import { HostCard } from "../components/HostCard";
import { ActivityChart } from "../components/ActivityChart";
import { NavTab } from "../components/Header";

interface OverviewPageProps {
  onNavigateToImport: () => void;
  onRefreshAll: () => void;
  onNavigate: (tab: NavTab) => void;
}

/** A headline figure with the question it actually answers. */
const MetricCard: React.FC<{
  label: string;
  value: React.ReactNode;
  icon: React.ReactNode;
  tone?: string;
  children: React.ReactNode;
}> = ({ label, value, icon, tone = "", children }) => (
  <div className={`glass-panel stat-card ${tone}`}>
    <div className="stat-header">
      <span className="stat-label">{label}</span>
      <span className="stat-icon">{icon}</span>
    </div>
    <div className="stat-value">{value}</div>
    <div className="stat-subtext">{children}</div>
  </div>
);

export const OverviewPage: React.FC<OverviewPageProps> = ({
  onNavigateToImport,
  onRefreshAll,
  onNavigate,
}) => {
  const [stats, setStats] = useState<EventSummaryStats | null>(null);
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [analysis, setAnalysis] = useState<DescriptiveAnalysis | null>(null);
  const [sources, setSources] = useState<SourceHealthRecord[]>([]);
  const [collector, setCollector] = useState<CollectorStatus | null>(null);
  const [connections, setConnections] = useState<ConnectionDetail[]>([]);
  /** A wider slice, timestamps only, for the activity chart. */
  const [timeline, setTimeline] = useState<ConnectionDetail[]>([]);
  const [timelineTotal, setTimelineTotal] = useState(0);
  const [dnsRows, setDnsRows] = useState<DnsObservationRow[]>([]);
  const [dnsTotal, setDnsTotal] = useState<number | null>(null);
  const [host, setHost] = useState<HostIdentity | null>(null);
  // The collector's own source id, when one is running on this machine.
  // Absent on a platform with no collector, which the panel renders
  // rather than hides.
  const [localSourceId, setLocalSourceId] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [updatedAt, setUpdatedAt] = useState<string | null>(null);
  const [seeding, setSeeding] = useState(false);
  const [seedSuccess, setSeedSuccess] = useState(false);
  /**
   * Why a sample import was refused.
   *
   * This used to be a `console.error` and nothing else, so a refusal
   * looked exactly like a button that did nothing. The backend guards
   * the operational database against research corpora and explains
   * itself when it refuses (ADR-124); that explanation is the single
   * most useful thing on the screen at that moment, and it was being
   * thrown away.
   */
  const [seedError, setSeedError] = useState<string | null>(null);

  const loadData = useCallback(async () => {
    setLoading(true);
    try {
      // Every panel is independent. One failing endpoint must not blank
      // the others, so each settles on its own.
      const [
        h, s, a, sourceHealth, collectorStatus, conns, dns, hostInfo, recent,
      ] = await Promise.all([
          api.getHealth().catch(() => null),
          api.getEventStats().catch(() => null),
          api.getLatestAnalysis().catch(() => null),
          api.getSourceHealth().catch(() => null),
          api.getCollectorStatus().catch(() => null),
          api.getConnections({ limit: 6 }).catch(() => null),
          api.getDnsObservations({ limit: 6 }).catch(() => null),
          api.getHostIdentity().catch(() => null),
          // Enrichment off: the chart needs timestamps and direction,
          // not hostname attribution, and resolving 400 of them would
          // cost far more than the panel is worth.
          api
            .getConnections({ limit: 400, include_enrichment: false })
            .catch(() => null),
        ]);

      if (h) setHealth(h);
      if (s) setStats(s);
      if (a) setAnalysis(a);
      if (sourceHealth) setSources(sourceHealth.sources ?? []);
      if (collectorStatus) {
        setCollector(collectorStatus);
        setLocalSourceId(collectorStatus.source_id ?? null);
      }
      if (conns) setConnections(conns.connections ?? []);
      if (dns) {
        setDnsRows(dns.observations ?? []);
        setDnsTotal(dns.total_stored);
      }
      if (hostInfo) setHost(hostInfo);
      if (recent) {
        setTimeline(recent.connections ?? []);
        setTimelineTotal(recent.total);
      }
      setUpdatedAt(new Date().toISOString());
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const handleSeedSampleData = async () => {
    setSeeding(true);
    setSeedError(null);
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
    } catch (err) {
      setSeedError(err instanceof Error ? err.message : String(err));
    } finally {
      setSeeding(false);
    }
  };

  // ---- Charts, from stored records only ---------------------------
  const labelChartData = Object.entries(stats?.labels || {}).map(
    ([name, value]) => ({
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
    }),
  );

  const labelPieOption = {
    backgroundColor: "transparent",
    tooltip: { trigger: "item", formatter: "{b}: {c} events ({d}%)" },
    legend: { bottom: 0, textStyle: { color: "#94a3b8", fontSize: 12 } },
    series: [
      {
        name: "Security Classification",
        type: "pie",
        radius: ["48%", "72%"],
        avoidLabelOverlap: false,
        itemStyle: { borderRadius: 6, borderColor: "#0f172a", borderWidth: 2 },
        label: { show: false },
        emphasis: {
          label: { show: true, fontSize: 13, fontWeight: "bold", color: "#fff" },
        },
        data: labelChartData,
      },
    ],
  };

  const topPorts = analysis?.top_dst_ports || [];
  const portsBarOption = {
    backgroundColor: "transparent",
    tooltip: { trigger: "axis" },
    grid: { left: "12%", right: "6%", bottom: "14%", top: "8%" },
    xAxis: {
      type: "category",
      data: topPorts.map((p) => `Port ${p.port}`),
      axisLabel: { color: "#94a3b8", fontSize: 12 },
      axisLine: { lineStyle: { color: "#334155" } },
    },
    yAxis: {
      type: "value",
      axisLabel: { color: "#94a3b8", fontSize: 12 },
      splitLine: { lineStyle: { color: "rgba(51, 65, 85, 0.4)" } },
    },
    series: [
      {
        name: "Connections",
        type: "bar",
        data: topPorts.map((p) => p.count),
        itemStyle: {
          color: {
            type: "linear",
            x: 0, y: 0, x2: 0, y2: 1,
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

  const attackLabels = Object.keys(stats?.labels || {}).filter(
    (k) => !["benign", "unlabeled"].includes(k.toLowerCase()),
  ).length;

  const collectorRunning = collector?.state === "running";
  const storedEvents = stats?.total_events ?? 0;

  return (
    <div className="page-container">
      <div className="page-header compact">
        <div>
          <h1 className="page-title">
            <Activity size={18} /> Overview
          </h1>
          <p className="page-subtitle">
            Your host, network activity and security signals at a glance.
          </p>
        </div>
        <div className="header-actions">
          {updatedAt && (
            <span className="panel-meta">Last updated {fmtTime(updatedAt)}</span>
          )}
          <button className="btn btn-sm" onClick={loadData} disabled={loading}>
            <RefreshCw size={14} className={loading ? "spin" : ""} /> Refresh
          </button>
        </div>
      </div>

      <Explain>
        This page summarises the network records PraHari currently holds.
        Nothing here is a prediction — these are counts of what has already
        been collected or imported. Forecasting lives under{" "}
        <strong>Security</strong>, and it only runs once there is enough data
        for it to mean anything.
      </Explain>

      {/* ---- Four figures, each naming what it counted -------------- */}
      <div className="stat-grid">
        <MetricCard
          label="Stored connections"
          value={fmtInt(storedEvents, "0")}
          icon={<Database size={18} />}
        >
          <Caption
            plain="Network connections PraHari has recorded and saved"
            expert="Normalized canonical flows in storage"
          />
        </MetricCard>

        <MetricCard
          label="DNS observations"
          value={dnsTotal === null ? "—" : fmtInt(dnsTotal, "0")}
          icon={<Globe size={18} />}
          tone="blue"
        >
          {/* A name resolving is not a connection being made. Keeping
              this figure in its own card stops it being read as one. */}
          <Caption
            plain="Name lookups observed on this machine — evidence of a lookup, not of a connection"
            expert="dns_query_log and dns_cache_observation rows"
          />
        </MetricCard>

        <MetricCard
          label="Registered sources"
          value={fmtInt(stats?.sources_count, "0")}
          icon={<Server size={18} />}
          tone="emerald"
        >
          {/* The brief's rule and ADR-118's: registration is not
              coverage, and this is where someone would assume it was. */}
          <Caption
            plain="Registering a device records its address. It does not start monitoring it."
            expert="Rows in telemetry_sources; monitoring requires an agent or sensor"
          />
        </MetricCard>

        <MetricCard
          label="Collector"
          value={collector ? humanise(collector.state) : "—"}
          icon={<Radio size={18} />}
          tone={
            collectorRunning
              ? "emerald"
              : collector?.state === "error"
              ? "rose"
              : "blue"
          }
        >
          {collector ? (
            collector.platform_supported ? (
              <>
                {collector.platform_name} ·{" "}
                {collector.last_success_at
                  ? `last poll ${fmtTime(collector.last_success_at)}`
                  : "no successful poll yet"}
              </>
            ) : (
              <>No connection collector exists for {collector.platform_name}.</>
            )
          ) : (
            <Caption
              plain="Could not read the collector's state"
              expert="GET /collector/status failed"
            />
          )}
        </MetricCard>
      </div>

      {storedEvents > 0 && (
        <ActivityChart
          connections={timeline}
          totalStored={timelineTotal}
          loading={loading}
        />
      )}

      {/* ---- This host / other devices ----------------------------- */}
      <div className="split-grid">
        <HostCard host={host} collector={collector} loading={loading} />
        {/* ADR-118's devices panel, reused unchanged: it already keeps
            registered and monitored apart, which is the claim that
            matters most on this page. */}
        <HostAndDevices
          sources={sources}
          localSourceId={localSourceId}
          onOpenDevices={() => onNavigate("sources")}
          showHost={false}
        />
      </div>

      {/* ---- Recent connections and recent DNS, side by side -------- */}
      <div className="split-grid">
        <section className="panel">
          <div className="panel-header tight">
            <h3>Recent connections</h3>
            <button className="btn btn-sm" onClick={() => onNavigate("traffic")}>
              View all
            </button>
          </div>
          {connections.length === 0 ? (
            <div className="empty-state">
              <p className="empty-title">No connections recorded.</p>
              <p className="empty-body">
                {collectorRunning
                  ? "The collector is running but has stored nothing yet."
                  : "Start the collector from Live Telemetry to record this machine's own connections."}
              </p>
            </div>
          ) : (
            <div className="table-container">
              <table className="data-table compact">
                <thead>
                  <tr>
                    <th>Direction</th>
                    <th>Destination</th>
                    <th>Port</th>
                    <th>Process</th>
                    <th>Time</th>
                  </tr>
                </thead>
                <tbody>
                  {connections.map((c) => (
                    <tr key={c.event.event_id}>
                      <td>
                        {c.direction ? (
                          <span
                            className="direction-cell"
                            title={`${c.direction.reason}\n\nMethod: ${c.direction.method}`}
                          >
                            {humanise(c.direction.direction)}
                            {/* "Unknown · none" states the same absence
                                twice. The qualifier is shown only when
                                it qualifies something. */}
                            {c.direction.confidence !== "none" && (
                              <span className="cell-note">
                                {c.direction.confidence}
                              </span>
                            )}
                          </span>
                        ) : (
                          <span className="metric-unavailable">not assessed</span>
                        )}
                      </td>
                      <td>
                        <code>{c.event.dst_ip ?? "—"}</code>
                        {c.domain_attribution?.hostname && (
                          <div className="cell-note">
                            {c.domain_attribution.hostname}
                          </div>
                        )}
                      </td>
                      <td>{c.event.dst_port ?? "—"}</td>
                      <td>
                        {c.process_name ?? (
                          <span className="metric-unavailable">not reported</span>
                        )}
                      </td>
                      <td>{fmtTime(c.event.observed_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>

        <section className="panel">
          <div className="panel-header tight">
            <h3>DNS activity</h3>
            <button className="btn btn-sm" onClick={() => onNavigate("dns")}>
              View all
            </button>
          </div>
          {dnsRows.length === 0 ? (
            <div className="empty-state">
              <p className="empty-title">No DNS evidence collected.</p>
              <p className="empty-body">
                That is a statement about what PraHari has read, not about
                whether this host resolved anything.
              </p>
            </div>
          ) : (
            <div className="table-container">
              <table className="data-table compact">
                <thead>
                  <tr>
                    <th>Name</th>
                    <th>Resolved to</th>
                    <th>Evidence</th>
                    <th>Time</th>
                  </tr>
                </thead>
                <tbody>
                  {dnsRows.map((r) => (
                    <tr key={`${r.ip_address}|${r.hostname}|${r.observed_at}`}>
                      <td>{r.hostname}</td>
                      <td>
                        <code>{r.ip_address}</code>
                      </td>
                      <td>{humanise(r.method)}</td>
                      <td>{fmtTime(r.observed_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      </div>

      {/* ---- Sample data, always labelled as such ------------------- */}
      {storedEvents === 0 && (
        <section className="panel">
          <div className="empty-state">
            <p className="empty-title">No telemetry stored yet</p>
            <p className="empty-body">
              Import a CSV of network flows, start the live collector, or load
              a small labelled sample to see how the pipeline behaves. Sample
              records are real CIC-IDS2018 rows and are stored under their own
              source id, <code>soc_perimeter_sensor</code>, so they never mix
              with telemetry from this machine.
            </p>
            <div style={{ display: "flex", gap: "0.75rem", flexWrap: "wrap", justifyContent: "center" }}>
              <button
                className="btn btn-primary btn-sm"
                onClick={handleSeedSampleData}
                disabled={seeding}
              >
                {seedSuccess ? <CheckCircle size={14} /> : <UploadCloud size={14} />}
                {seeding
                  ? "Importing sample…"
                  : seedSuccess
                  ? "Sample imported"
                  : "Load sample data"}
              </button>
              <button className="btn btn-sm" onClick={onNavigateToImport}>
                Upload a CSV
              </button>
              <button className="btn btn-sm" onClick={() => onNavigate("live")}>
                Start the collector
              </button>
            </div>
            {seedError && (
              <div
                className="status-banner status-error"
                role="alert"
                style={{ marginTop: "1rem", textAlign: "left" }}
              >
                <AlertTriangle size={16} />
                <div>
                  <strong>The sample import was refused.</strong>
                  <div className="banner-note">{seedError}</div>
                </div>
              </div>
            )}
          </div>
        </section>
      )}

      {/* ---- Charts, only where there is something to plot ---------- */}
      {storedEvents > 0 && (
        <div className="split-grid">
          <section className="panel">
            <div className="panel-header tight">
              <h3>Security label breakdown</h3>
              <span className="panel-meta">
                {attackLabels} attack label{attackLabels === 1 ? "" : "s"} present
              </span>
            </div>
            <p className="panel-note">
              The labels come with the data; PraHari did not decide them.
            </p>
            {labelChartData.length === 0 ? (
              <div className="empty-state">
                <p className="empty-body">
                  Stored records carry no labels at all, which is not the same
                  as carrying a "benign" one.
                </p>
              </div>
            ) : (
              <ReactECharts
                option={labelPieOption}
                style={{ height: 260 }}
                notMerge
              />
            )}
          </section>

          <section className="panel">
            <div className="panel-header tight">
              <h3>Top destination ports</h3>
            </div>
            <p className="panel-note">
              Where the recorded connections were going. 443 is HTTPS, 22 is SSH.
            </p>
            {topPorts.length === 0 ? (
              <div className="empty-state">
                <p className="empty-body">
                  No port distribution yet — run an analysis from the Analytics
                  page over the stored records.
                </p>
              </div>
            ) : (
              <ReactECharts
                option={portsBarOption}
                style={{ height: 260 }}
                notMerge
              />
            )}
          </section>
        </div>
      )}

      {health && (
        <p className="panel-note" style={{ textAlign: "center" }}>
          Canonical schema v{health.schema_version} · {health.deployment_mode}{" "}
          deployment · {health.database.connected ? "storage connected" : "storage unavailable"}
        </p>
      )}
    </div>
  );
};
