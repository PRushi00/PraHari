import {
  DescriptiveAnalysis,
  EventSummaryStats,
  HealthResponse,
  ImportSummary,
  NormalizedEvent,
  PaginatedEventsResponse,
  TelemetrySource,
} from "../types";

const BASE_URL = "/api/v1";

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
        errorDetail = typeof errJson.detail === "string" ? errJson.detail : JSON.stringify(errJson.detail);
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

  // Telemetry Sources
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

  getResearchReport: (): Promise<import("../types").FeasibilityReport | null> =>
    request<import("../types").FeasibilityReport | null>("/research/report"),

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
  }): Promise<import("../types").SyntheticReplayResponse> =>
    request<import("../types").SyntheticReplayResponse>("/stream/replay/synthetic", {
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

  getSecurityConfig: (): Promise<import("../types").SecurityConfig> =>
    request<import("../types").SecurityConfig>("/audit/config"),
};
