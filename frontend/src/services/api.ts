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
};
