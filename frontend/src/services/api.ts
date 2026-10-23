import {
  DescriptiveAnalysis,
  EventSummaryStats,
  HealthResponse,
  ImportSummary,
  NormalizedEvent,
  PaginatedEventsResponse,
  TelemetrySource,
  SystemHealthReport,
  SourceHealthSummary,
  RetentionPolicy,
} from "../types";

const BASE_URL = "/api/v1";

/**
 * A refusal, in words a person can act on.
 *
 * The backend refuses with a structured body — `{error, message,
 * remedy}` — because the remedy is the useful part. This was being
 * passed through `JSON.stringify`, so what reached the screen was one
 * unbroken line of braces and quotes with the remedy buried in it.
 */
function formatDetail(detail: unknown, fallback: string): string {
  if (typeof detail === "string") return detail;
  if (detail && typeof detail === "object") {
    const d = detail as Record<string, unknown>;
    const parts = [d.message, d.remedy].filter(
      (x): x is string => typeof x === "string" && x.length > 0,
    );
    if (parts.length) return parts.join(" ");
    // A validation error arrives as a list of per-field problems.
    if (Array.isArray(detail)) {
      const msgs = detail
        .map((item) =>
          item && typeof item === "object"
            ? (item as Record<string, unknown>).msg
            : null,
        )
        .filter((x): x is string => typeof x === "string");
      if (msgs.length) return msgs.join("; ");
    }
  }
  return fallback;
}

async function request<T>(endpoint: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE_URL}${endpoint}`, {
    ...options,
    headers: {
      Accept: "application/json",
      ...options?.headers,
    },
  });

  if (!res.ok) {
    let errorDetail = `HTTP ${res.status}: ${res.statusText}`;
    try {
      const errJson = await res.json();
      if (errJson.detail) {
        errorDetail = formatDetail(errJson.detail, errorDetail);
      }
    } catch {
      // ignore
    }
    throw new Error(errorDetail);
  }

  return res.json();
}

export const api = {
  // System Health
  getHealth: (): Promise<HealthResponse> => request<HealthResponse>("/health"),

  getHostIdentity: (): Promise<import("../types").HostIdentity> =>
    request<import("../types").HostIdentity>("/system/host"),

  getSystemHealth: (): Promise<SystemHealthReport> =>
    request<SystemHealthReport>("/system/health"),

  getSourceHealth: (): Promise<SourceHealthSummary> =>
    request<SourceHealthSummary>("/sources/health"),

  setSourceEnabled: (
    sourceId: string,
    enabled: boolean,
    reason = ""
  ): Promise<TelemetrySource> =>
    request<TelemetrySource>(`/sources/${encodeURIComponent(sourceId)}/enabled`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ enabled, reason }),
    }),

  getRetentionPolicy: (): Promise<RetentionPolicy> =>
    request<RetentionPolicy>("/retention/policy"),

  /** `null` clears the override and restores the configured default. */
  updateRetentionPolicy: (
    retentionDays: number | null,
    reason = ""
  ): Promise<RetentionPolicy> =>
    request<RetentionPolicy>("/retention/policy", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ retention_days: retentionDays, reason }),
    }),

  // Telemetry Sources
  getDnsObservations: (params?: {
    limit?: number;
    method?: string;
  }): Promise<import("../types").DnsObservationsPage> => {
    const sp = new URLSearchParams();
    Object.entries(params || {}).forEach(([k, v]) => {
      if (v !== undefined && v !== null && v !== "") sp.append(k, String(v));
    });
    const q = sp.toString();
    return request<import("../types").DnsObservationsPage>(
      `/enrichment/dns/observations${q ? `?${q}` : ""}`
    );
  },

  collectDnsEvents: (): Promise<Record<string, unknown>> =>
    request<Record<string, unknown>>("/enrichment/dns/events/collect", {
      method: "POST",
    }),

  getSources: (): Promise<TelemetrySource[]> => request<TelemetrySource[]>("/sources"),
  createSource: (data: { source_id: string; name: string; source_type: string; description?: string }): Promise<TelemetrySource> =>
    request<TelemetrySource>("/sources", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(data),
    }),
  getSource: (sourceId: string): Promise<TelemetrySource> => request<TelemetrySource>(`/sources/${sourceId}`),

  // Normalized Events
  getEvents: (params?: {
    source_id?: string;
    label?: string;
    event_type?: string;
    limit?: number;
    offset?: number;
  }): Promise<PaginatedEventsResponse> => {
    const searchParams = new URLSearchParams();
    if (params?.source_id) searchParams.append("source_id", params.source_id);
    if (params?.label) searchParams.append("label", params.label);
    if (params?.event_type) searchParams.append("event_type", params.event_type);
    if (params?.limit) searchParams.append("limit", params.limit.toString());
    if (params?.offset !== undefined) searchParams.append("offset", params.offset.toString());
    const query = searchParams.toString();
    return request<PaginatedEventsResponse>(`/events${query ? `?${query}` : ""}`);
  },
  getEvent: (eventId: string): Promise<NormalizedEvent> => request<NormalizedEvent>(`/events/${eventId}`),
  getEventStats: (): Promise<EventSummaryStats> => request<EventSummaryStats>("/events/stats/summary"),

  // CSV Import
  importRawCsv: (data: {
    source_id: string;
    source_name?: string;
    csv_content: string;
    max_records?: number;
  }): Promise<ImportSummary> =>
    request<ImportSummary>("/import/csv/raw", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(data),
    }),

  importCsvFile: (formData: FormData): Promise<ImportSummary> =>
    request<ImportSummary>("/import/csv/file", {
      method: "POST",
      body: formData,
    }),

  getImportHistory: (sourceId?: string): Promise<ImportSummary[]> => {
    const url = sourceId ? `/import/history?source_id=${encodeURIComponent(sourceId)}` : "/import/history";
    return request<ImportSummary[]>(url);
  },

  // Descriptive Analysis
  runDescriptiveAnalysis: (sourceId?: string): Promise<DescriptiveAnalysis> =>
    request<DescriptiveAnalysis>("/analysis/run", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ source_id: sourceId || null }),
    }),

  getLatestAnalysis: (sourceId?: string): Promise<DescriptiveAnalysis | null> => {
    const url = sourceId ? `/analysis/latest?source_id=${encodeURIComponent(sourceId)}` : "/analysis/latest";
    return request<DescriptiveAnalysis | null>(url);
  },

  listAnalyses: (): Promise<DescriptiveAnalysis[]> => request<DescriptiveAnalysis[]>("/analysis"),

  // Research Feasibility Audit
  runResearchAudit: (sourceId?: string): Promise<import("../types").FeasibilityReport> =>
    request<import("../types").FeasibilityReport>("/research/audit", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ source_id: sourceId || null }),
    }),

  // Backend exposes the latest audit at GET /research/audit. The previous
  // path (/research/report) does not exist and silently returned the SPA
  // shell, so this call always failed to parse.
  getResearchReport: (): Promise<import("../types").FeasibilityReport | null> =>
    request<import("../types").FeasibilityReport | null>("/research/audit"),

  // Threat Forecasting & Predictive ML
  trainForecastingModels: (data?: {
    source_id?: string;
    max_events?: number;
    train_ratio?: number;
  }): Promise<Record<string, import("../types").ModelMetrics>> =>
    request<Record<string, import("../types").ModelMetrics>>("/forecast/train", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(data || {}),
    }),

  getForecastingModels: (): Promise<Record<string, import("../types").ModelMetrics>> =>
    request<Record<string, import("../types").ModelMetrics>>("/forecast/models"),

  predictIncidentPropensity: (data?: {
    source_id?: string;
    model_id?: string;
    threshold?: number;
    window_limit?: number;
  }): Promise<import("../types").PredictionResult> =>
    request<import("../types").PredictionResult>("/forecast/predict", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(data || {}),
    }),

  // Streaming & Synthetic Replay
  ingestNdjsonStream: (data: {
    source_id: string;
    source_name?: string;
    format?: string;
    ndjson_content: string;
  }): Promise<ImportSummary> =>
    request<ImportSummary>("/stream/ingest/ndjson", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(data),
    }),

  replaySyntheticFlows: (data?: {
    source_id?: string;
    source_name?: string;
    count?: number;
    attack_ratio?: number;
    seed?: number;
  }): Promise<ImportSummary> =>
    request<ImportSummary>("/stream/replay/synthetic", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(data || {}),
    }),

  getStreamAdapters: (): Promise<import("../types").AdapterHealth[]> =>
    request<import("../types").AdapterHealth[]>("/stream/adapters"),

  // Audit Logs & Compliance Config
  getAuditLogs: (params?: {
    limit?: number;
    offset?: number;
    resource_type?: string;
  }): Promise<import("../types").AuditLog[]> => {
    const sp = new URLSearchParams();
    if (params?.limit) sp.append("limit", params.limit.toString());
    if (params?.offset !== undefined) sp.append("offset", params.offset.toString());
    if (params?.resource_type) sp.append("resource_type", params.resource_type);
    const query = sp.toString();
    return request<import("../types").AuditLog[]>(`/audit/logs${query ? `?${query}` : ""}`);
  },

  // Live Windows Telemetry Collector
  getCollectorStatus: (): Promise<import("../types").CollectorStatus> =>
    request<import("../types").CollectorStatus>("/collector/status"),

  startCollector: (intervalSeconds: number): Promise<import("../types").CollectorStatus> =>
    request<import("../types").CollectorStatus>("/collector/start", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ interval_seconds: intervalSeconds }),
    }),

  stopCollector: (): Promise<import("../types").CollectorStatus> =>
    request<import("../types").CollectorStatus>("/collector/stop", { method: "POST" }),

  pollCollectorOnce: (): Promise<import("../types").PollResult> =>
    request<import("../types").PollResult>("/collector/poll", { method: "POST" }),

  // Connection intelligence
  getConnections: (params?: {
    source_id?: string;
    data_category?: string;
    dst_port?: number;
    protocol?: string;
    connection_state?: string;
    process?: string;
    dst_ip?: string;
    hostname?: string;
    direction?: string;
    include_enrichment?: boolean;
    allow_reverse_dns?: boolean;
    limit?: number;
    offset?: number;
  }): Promise<import("../types").PaginatedConnectionsResponse> => {
    const sp = new URLSearchParams();
    Object.entries(params || {}).forEach(([k, v]) => {
      if (v !== undefined && v !== null && v !== "") sp.append(k, String(v));
    });
    const q = sp.toString();
    return request<import("../types").PaginatedConnectionsResponse>(
      `/events/connections${q ? `?${q}` : ""}`
    );
  },

  getSourceCapabilities: (): Promise<import("../types").SourceCapability[]> =>
    request<import("../types").SourceCapability[]>("/events/capabilities"),

  // Domain enrichment
  getEnrichmentStatus: (): Promise<import("../types").EnrichmentStatus> =>
    request<import("../types").EnrichmentStatus>("/enrichment/status"),

  diagnoseDns: (): Promise<Record<string, unknown>> =>
    request<Record<string, unknown>>("/enrichment/dns/diagnose"),

  refreshDnsObservations: (): Promise<Record<string, unknown>> =>
    request<Record<string, unknown>>("/enrichment/dns/refresh", { method: "POST" }),

  // Forecasting readiness
  getForecastReadiness: (): Promise<import("../types").ReadinessReport> =>
    request<import("../types").ReadinessReport>("/forecast/readiness"),

  getForecastIntegrity: (): Promise<import("../types").SplitIntegrityReport | null> =>
    request<import("../types").SplitIntegrityReport | null>("/forecast/integrity"),

  // Optional application-layer telemetry
  getAppLayerStatus: (): Promise<import("../types").AppLayerStatus> =>
    request<import("../types").AppLayerStatus>("/applayer/status"),

  getSecurityConfig: (): Promise<import("../types").SecurityConfig> =>
    request<import("../types").SecurityConfig>("/audit/config"),

  /**
   * Event-level warning performance for the evaluation already in memory.
   *
   * Never retrains: it re-reads the holdout the last training produced, so
   * the numbers describe the same split and the same operating point as the
   * window-level metrics beside them.
   */
  evaluateEventLevel: (data?: {
    model_id?: string;
    source_id?: string;
    episode_gap_seconds?: number;
    suppression_seconds?: number;
    threshold?: number;
  }): Promise<import("../types").EventLevelReport> =>
    request<import("../types").EventLevelReport>("/forecast/event-level", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(data || {}),
    }),

  // §11 investigation drill-down (ADR-109): the evidence behind one
  // RECORDED warning, as opposed to the live prediction the Forecast
  // page explains.
  investigateWarning: (data: {
    warning_index: number;
    model_id?: string;
    source_id?: string;
    episode_gap_seconds?: number;
    suppression_seconds?: number;
    threshold?: number;
  }): Promise<import("../types").WarningInvestigation> =>
    request<import("../types").WarningInvestigation>("/forecast/investigate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(data),
    }),
};
