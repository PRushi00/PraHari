export type DataCategory = "raw" | "normalized" | "historical_import" | "live_stream" | "synthetic";

export type EventType = "network_flow" | "process" | "dns" | "auth" | "file" | "alert";

export type LabelProvenance = "dataset_ground_truth" | "synthetic_rule" | "operator_annotated" | "unlabeled";

export type QualityFlag =
  | "missing_field"
  | "timestamp_uncertainty"
  | "invalid_value"
  | "rate_limit_artifact"
  | "synthetic_sample";

export interface NormalizedEvent {
  event_id: string;
  schema_version: string;
  source_id: string;
  data_category: DataCategory;
  observed_at: string;
  ingested_at: string;
  event_type: EventType;
  src_ip?: string | null;
  dst_ip?: string | null;
  src_port?: number | null;
  dst_port?: number | null;
  protocol?: string | null;
  duration?: number | null;
  packets?: number | null;
  bytes_total?: number | null;
  label?: string | null;
  label_provenance: LabelProvenance;
  quality_flags: QualityFlag[];
  raw_reference?: string | null;
}

export interface TelemetrySource {
  source_id: string;
  name: string;
  source_type: string;
  description?: string;
  enabled: boolean;
  created_at: string;
  last_event_at?: string | null;
  event_count: number;
  status: string;
}

export interface ImportSummary {
  import_id: string;
  source_id: string;
  source_file?: string | null;
  data_category: DataCategory;
  started_at: string;
  completed_at?: string | null;
  total_records: number;
  accepted_records: number;
  rejected_records: number;
  warnings_count: number;
  rejection_reasons: Record<string, number>;
  schema_version: string;
}

export interface DescriptiveAnalysis {
  analysis_id: string;
  analysis_type: string;
  source_id: string;
  computed_at: string;
  schema_version: string;
  data_category: DataCategory;
  total_events: number;
  events_by_type: Record<string, number>;
  events_by_label: Record<string, number>;
  events_by_protocol: Record<string, number>;
  time_range_start?: string | null;
  time_range_end?: string | null;
  missing_field_counts: Record<string, number>;
  quality_flag_counts: Record<string, number>;
  records_with_warnings: number;
  unique_src_ips: number;
  unique_dst_ips: number;
  unique_src_ports: number;
  unique_dst_ports: number;
  top_src_ips: Array<{ ip: string; count: number }>;
  top_dst_ips: Array<{ ip: string; count: number }>;
  top_dst_ports: Array<{ port: number; count: number }>;
  avg_duration?: number | null;
  avg_packets?: number | null;
  avg_bytes?: number | null;
  total_bytes?: number | null;
}

export interface HealthResponse {
  status: string;
  app_name: string;
  app_version: string;
  schema_version: string;
  deployment_mode: string;
  uptime_seconds: number;
  database: {
    connected: boolean;
    path: string;
    sources_count: number;
    events_count: number;
  };
  timestamp: string;
}

export interface PaginatedEventsResponse {
  total: number;
  limit: number;
  offset: number;
  events: NormalizedEvent[];
}

export interface EventSummaryStats {
  total_events: number;
  sources_count: number;
  labels: Record<string, number>;
  event_types: Record<string, number>;
}
