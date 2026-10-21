// Canonical enum values, mirroring backend app/schemas/events.py.
// These had drifted badly: DataCategory omitted "live_telemetry" entirely
// and EventType omitted "connection" — the two values the live Windows
// collector actually produces. Enum drift does not crash at runtime (types
// are erased), but it makes the type system actively misleading.
// Contract test: backend/tests/integration/test_frontend_api_contract.py

export type DataCategory =
  | "live_telemetry"
  | "historical_import"
  | "historical_replay"
  | "synthetic_demo"
  | "test_fixture"
  | "mixed"          // aggregate result spanning several categories
  | "undetermined";  // aggregate over zero events

export type EventType =
  | "network_flow"
  | "connection"
  | "dns_query"
  | "http_request"
  | "udp_endpoint"
  | "alert"
  | "host_event"
  | "unknown";

export type LabelProvenance =
  | "dataset_ground_truth"
  | "rule_based"
  | "synthetic_rule"
  | "detector_output"
  | "model_prediction"
  | "analyst_annotation"
  | "unlabeled";

export type QualityFlag =
  | "missing_field"
  | "parse_warning"
  | "timestamp_uncertainty"
  | "truncated"
  | "duplicate_candidate"
  | "schema_warning"
  | "invalid_value"
  | "synthetic_sample"
  | "source_limited";  // structural source limit, NOT a data defect

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

  // Application-layer fields. Populated ONLY by an authorized app-layer
  // source; the TCP connection collector always leaves these null.
  app_protocol?: string | null;
  http_method?: string | null;
  http_path?: string | null;
  http_status_code?: number | null;
  http_duration_ms?: number | null;
  dst_hostname?: string | null;
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
  implausible_timestamp_events?: number;
  duration_measured_count?: number;
  packets_measured_count?: number;
  bytes_measured_count?: number;
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

  // Derived provenance and quality split
  data_categories: Record<string, number>;
  source_breakdown: Record<string, number>;
  is_mixed_provenance: boolean;
  unsupported_field_counts: Record<string, number>;
  source_limitations: string[];
  events_by_connection_state: Record<string, number>;
  events_by_process: Record<string, number>;
  top_dst_hostnames: { hostname: string; count: number }[];
  hostname_attributed_count: number;
  events_per_hour: Record<string, number>;
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

// Research Feasibility Types
//
// These mirror backend app/research/feasibility.py exactly. An earlier
// version described a schema the backend never produced (audit_id,
// overall_feasibility_score, per-criterion objects). Because the type was
// internally consistent, tsc accepted it, and the mismatch only surfaced at
// runtime as `undefined.toFixed(...)` — which blanked the whole app.
// Contract test: backend/tests/integration/test_frontend_api_contract.py

export interface FeasibilityCheckResult {
  check_name: string;
  passed: boolean;
  /** 0.0 - 1.0 */
  score: number;
  details: string;
  risk_level: "low" | "medium" | "high" | "critical";
}

export interface FeasibilityReport {
  dataset_id: string;
  evaluated_at: string;
  gate_passed: boolean;
  /** 0.0 - 1.0 (NOT a 0-100 index) */
  overall_score: number;
  recommendation: "PERMIT_FORECASTING" | "CONDITIONAL_REVIEW" | "REJECT_FORECASTING" | string;
  checks: FeasibilityCheckResult[];
  metrics: Record<string, number | string>;
}

// Threat Forecasting Types
// Mirrors backend ModelMetrics (app/models/forecaster.py). Several fields
// are optional there, so they are optional here and must be formatted with
// the helpers in utils/format rather than called on directly.
export interface ModelMetrics {
  model_name: string;
  model_type: string;
  train_instances?: number | null;
  test_instances?: number | null;
  training_duration_seconds?: number | null;
  training_time_seconds: number;
  accuracy: number;
  precision: number;
  recall: number;
  /** Always present. `f1_score` is an optional alias of the same value. */
  f1: number;
  f1_score?: number | null;
  roc_auc?: number | null;
  pr_auc?: number | null;
  brier_score?: number | null;
  false_positive_rate: number;
  feature_importance: Record<string, number>;
  feature_importances?: Record<string, number> | null;
  confusion_matrix: number[][];
  sample_count: number;
  // Evaluation context that travels with every metric.
  evaluated_on_holdout: boolean;
  test_positive_count: number;
  test_negative_count: number;
  // Three separate questions, deliberately not collapsed:
  //  metrics_computable  — both classes present, so the figures are defined
  //  sample_adequate     — enough held-out instances to mean anything
  //  predictions_degenerate — the model emitted one class, or ranked nothing
  //  discrimination_demonstrated — PR-AUC above the no-skill base rate.
  //    true means "better than chance on this sample", NOT "a useful model".
  metrics_computable?: boolean;
  sample_adequate?: boolean;
  predictions_degenerate?: boolean;
  predicted_positive_count?: number;
  predicted_negative_count?: number;
  distinct_score_count?: number;
  scores_constant?: boolean;
  no_skill_pr_auc?: number | null;
  discrimination_demonstrated?: boolean | null;
  metrics_interpretable: boolean;
  interpretation_warnings: string[];
}

export interface FeatureContribution {
  feature: string;
  value: number;
  /** Backend field is `impact` (value x importance_weight). */
  impact: number;
  importance_weight: number;
}

/** One source's contribution to an investigated window (§11, ADR-109). */
export interface SourceReference {
  source_id: string;
  events_in_window: number;
  first_at?: string | null;
  last_at?: string | null;
}

/**
 * `POST /forecast/investigate` — the evidence behind one recorded warning.
 *
 * `contributions` is `value x GLOBAL importance`, NOT a local explanation;
 * `attribution_limitations` carries that and must be rendered with it.
 */
export interface WarningInvestigation {
  available: boolean;
  refusal_reason?: string | null;
  model_id?: string | null;
  warning_index: number;
  outcome: string;
  issued_at?: string | null;
  last_window_at?: string | null;
  windows: number;
  peak_score?: number | null;
  matched_event_index?: number | null;
  lead_time_seconds?: number | null;
  window_event_count: number;
  window_events_shown: number;
  window_events: NormalizedEvent[];
  window_truncated: boolean;
  contributions: FeatureContribution[];
  contributions_available: boolean;
  contributions_unavailable_reason?: string | null;
  attribution_method: string;
  attribution_limitations: string[];
  sources: SourceReference[];
  related_before: NormalizedEvent[];
  related_after: NormalizedEvent[];
  related_window_seconds: number;
  notes: string[];
}

export interface PredictionResult {
  prediction_id: string;
  predicted_at: string;
  model_name: string;
  propensity_score: number;
  predicted_incident: boolean;
  threshold_used: number;
  lead_time_seconds: number;
  horizon_seconds: number;
  top_contributing_features: FeatureContribution[];
}

// Streaming & Replay Types
// Mirrors backend AdapterHealth (app/adapters/base.py). The previous shape
// (adapter_name/format/is_running/records_accepted/last_activity) was never
// returned by the API.
export interface AdapterHealth {
  adapter_id: string;
  adapter_type: string;
  is_healthy: boolean;
  last_active_at?: string | null;
  records_processed: number;
  records_rejected: number;
  error_message?: string | null;
}

// POST /stream/replay/synthetic returns an ImportSummary — the same shape as
// every other ingestion path. An earlier SyntheticReplayResponse interface
// invented generated_records / simulated_attack_ratio / duration_seconds /
// status, none of which the backend returns; `duration_seconds.toFixed(2)`
// therefore threw and broke the Stream & Replay page.
// Contract test: backend/tests/integration/test_frontend_api_contract.py
export type SyntheticReplayResponse = ImportSummary;

// Audit & System Compliance Types
// Mirrors backend AuditLogItem (app/api/v1/audit.py). The previous shape
// used log_id/created_at, which the backend never returned — the timestamp
// column rendered "Invalid Date".
export interface AuditLog {
  id: number;
  timestamp: string;
  action: string;
  resource_type: string;
  resource_id: string;
  details: string;
  user_identity: string;
}

// Mirrors backend SystemConfigReport (app/api/v1/audit.py). The previous
// shape used `host` and `supported_adapters`, which the backend never
// returned — the dashboard rendered "Binding: undefined:8000".
// security_boundaries is now derived from live state, so its keys are
// descriptive rather than a fixed set of booleans.
export interface SecurityConfig {
  app_name: string;
  app_version: string;
  schema_version: string;
  deployment_mode: string;
  host_binding: string;
  port: number;
  // null: the configuration does not describe the listener (ADR-089).
  loopback_enforced: boolean | null;
  authentication_required: boolean;
  max_request_size_mb: number;
  database_url: string;
  retention_days: number;
  // Measured, not configured (ADR-078): the local address the request
  // actually arrived on, and whether the configuration describes it.
  serving_host?: string | null;
  serving_port?: number | null;
  listener_matches_configuration?: boolean | null;
  binding_evidence?: string;
  security_boundaries: Record<string, unknown>;
}

// ──────────────────────────────────────────────────────────────────
// Live Windows Telemetry Collector
// ──────────────────────────────────────────────────────────────────

export interface CollectionGap {
  gap_start: string;
  gap_end: string;
  gap_seconds: number;
  reason: string;
}

export interface CollectorStatus {
  state: "stopped" | "running" | "error" | "unsupported";
  platform_supported: boolean;
  platform_name: string;
  source_id: string;
  source_type: string;
  data_category: string;

  interval_seconds: number;
  include_loopback: boolean;
  collected_tcp_states: string[];

  started_at: string | null;
  stopped_at: string | null;
  last_poll_at: string | null;
  last_success_at: string | null;
  latest_event_observed_at: string | null;

  polls_attempted: number;
  polls_succeeded: number;
  polls_failed: number;
  consecutive_failures: number;

  records_observed_total: number;
  events_accepted_total: number;
  events_persisted_total: number;
  duplicates_suppressed_total: number;
  records_filtered_by_policy_total: number;
  records_rejected_total: number;
  rejection_reasons: Record<string, number>;

  last_error: string | null;
  collection_gaps: CollectionGap[];
  capability_notes: string[];
}

export interface PollResult {
  polled_at: string;
  succeeded: boolean;
  records_observed: number;
  events_accepted: number;
  events_persisted: number;
  duplicates_suppressed: number;
  records_filtered_by_policy: number;
  records_rejected: number;
  rejection_reasons: Record<string, number>;
  latest_event_observed_at: string | null;
  error: string | null;
}

// ──────────────────────────────────────────────────────────────────
// Connection intelligence, enrichment, readiness
// ──────────────────────────────────────────────────────────────────

export interface DomainAttribution {
  hostname: string | null;
  method: string;
  confidence: "high" | "medium" | "low" | "none";
  evidence_observed_at: string | null;
  evidence_age_seconds: number | null;
  candidate_hostnames: string[];
  candidate_count: number;
  limitations: string[];
  identifies_requested_host: boolean;
  attribution_kind: string;
}

export interface ConnectionDetail {
  event: NormalizedEvent;
  connection_state: string | null;
  process_name: string | null;
  process_id: number | null;
  domain_attribution: DomainAttribution | null;
  source_type: string | null;
  unsupported_fields: string[];
  source_limitations: string[];
}

export interface PaginatedConnectionsResponse {
  total: number;
  limit: number;
  offset: number;
  returned: number;
  connections: ConnectionDetail[];
  filters_applied: Record<string, unknown>;
  enrichment_note: string;
}

export interface EnrichmentStatus {
  method: string;
  last_refresh_at: string | null;
  refresh_count: number;
  observations_recorded: number;
  total_observations_stored: number;
  distinct_ips_with_evidence: number;
  stale_after_seconds: number;
  cache_appears_unavailable: boolean;
  diagnosis: string | null;
  last_error: string | null;
  limitations: string[];
}

export interface SourceCapability {
  source_type: string;
  description: string;
  fields: Record<string, string>;
  limitations: string[];
}

export interface ReadinessRequirement {
  name: string;
  satisfied: boolean;
  required: string;
  observed: string;
  detail: string;
}

export interface ReadinessReport {
  state: string;
  can_train: boolean;
  can_serve_validated_forecast: boolean;
  summary: string;
  requirements: ReadinessRequirement[];
  unmet_requirements: string[];
  next_steps: string[];
  total_events: number;
  implausible_timestamp_events: number;
  labelled_events: number;
  positive_events: number;
  negative_events: number;
  time_span_seconds: number;
  data_categories: Record<string, number>;
  label_provenances: Record<string, number>;
  non_ground_truth_labelled_events: number;
  label_caveats: string[];
  prediction_target: string;
  prediction_horizon_seconds: number;
  observation_window_seconds: number;
  lead_time_seconds: number;
  evaluated_at: string;
}

export interface WindowingReport {
  windows_limit: number;
  windows_eligible: number;
  windows_considered: number;
  windows_generated: number;
  windows_omitted: number;
  windows_truncated: boolean;
  windows_with_attack_in_observation?: number;
  windows_excluded_ongoing_attack?: number;
  notes?: string[];
}

export interface SplitIntegrityReport {
  // Window-generation truncation. Distinct from SelectionCoverage.truncated,
  // which reports a record-count cap on which EVENTS were fetched.
  windowing_truncated?: boolean;
  windows_omitted?: number;
  windowing?: WindowingReport | null;
  total_instances: number;
  train_instances: number;
  test_instances: number;
  purged_instances: number;
  embargo_windows: number;
  embargo_seconds: number;
  train_positive: number;
  train_negative: number;
  test_positive: number;
  test_negative: number;
  split_strategy: string;
  train_end_timestamp: string | null;
  test_start_timestamp: string | null;
}

export interface AppLayerStatus {
  enabled: boolean;
  retain_query_strings: boolean;
  source_type: string;
  accepted_fields: string[];
  never_accepted: string[];
  producer_required: boolean;
  notes: string[];
}

/**
 * System Health (blueprint §11).
 *
 * `data` is deliberately loose: the backend owns the shape of each
 * block, and pinning it here would mean editing two places whenever a
 * measurement is added. `available` and `reason` are the contract.
 */
export interface HealthBlock {
  available: boolean;
  reason?: string | null;
  data?: Record<string, any>;
}

export interface SystemHealthReport {
  generated_at: string;
  schema_version: string;
  deployment_mode: string;
  uptime_seconds: number;
  ingestion: HealthBlock;
  sources: HealthBlock;
  storage: HealthBlock;
  models: HealthBlock;
  adapters: HealthBlock;
  limits: HealthBlock;
  notes: string[];
}

/** One source's health, as `GET /sources/health` reports it. */
export interface SourceHealthRecord {
  source_id: string;
  name: string;
  source_type: string;
  state: string;
  enabled: boolean;
  recorded_status?: string | null;
  event_count: number;
  last_event_at?: string | null;
  seconds_since_last_event?: number | null;
  fresh_threshold_seconds: number;
  stale_threshold_seconds: number;
  evaluated_at: string;
  last_received_at?: string | null;
  seconds_since_last_receipt?: number | null;
  receipt_evidence_available: boolean;
  freshness_basis: string;
  clock_dependent: boolean;
  reasons: string[];
  limitations: string[];
}

export interface SourceHealthSummary {
  evaluated_at: string;
  sources: SourceHealthRecord[];
  counts_by_state: Record<string, number>;
  fresh_threshold_seconds: number;
  stale_threshold_seconds: number;
  notes: string[];
}

/**
 * `GET`/`PUT /retention/policy`. A plain dict response on the backend,
 * so this shape is maintained here and is not schema-paired.
 */
export interface RetentionPolicy {
  retention_days: number;
  origin: string;
  configured_default?: number;
  default_eligible_categories?: string[];
  enforcement?: string;
  automatic_pruning?: boolean;
  confirmation_required?: boolean;
  notes?: string[];
  override_cleared?: boolean;
  previous_retention_days?: number;
  note?: string;
}

// ──────────────────────────────────────────────────────────────────
// Event-level warning performance (ADR-091)
//
// The window-level metrics answer "how many windows were classified
// correctly". These answer blueprint §10's question instead: how long
// before a documented event the first qualifying warning arrived, how
// many events got no warning, and how many alerts an analyst would read.
// ──────────────────────────────────────────────────────────────────

/** The matching protocol, frozen and fingerprinted before results are read. */
export interface MatchingRules {
  episode_gap_seconds: number;
  min_lead_seconds: number;
  max_lead_seconds: number;
  suppression_seconds: number;
  threshold: number;
  attack_label_rule: string;
  event_time_origin: string;
  episode_rule: string;
  warning_rule: string;
  qualifying_rule: string;
  reuse_rule: string;
  coverage_rule: string;
  late_rule: string;
}

export interface DocumentedEvent {
  event_index: number;
  started_at: string;
  ended_at: string;
  labelled_records: number;
  labels: string[];
  source_ids: string[];
  in_coverage: boolean;
  out_of_coverage_reason: string | null;
  warned: boolean;
  lead_time_seconds: number | null;
  detecting_warning_index: number | null;
  late_warning_indices: number[];
}

export interface IssuedWarning {
  warning_index: number;
  issued_at: string;
  last_window_at: string;
  windows: number;
  peak_score: number;
  outcome: "detection" | "late" | "false_alarm";
  matched_event_index: number | null;
  lead_time_seconds: number | null;
}

/** Quartiles are absent below four warned events, never computed from one. */
export interface LeadTimeDistribution {
  count: number;
  min_seconds: number | null;
  p25_seconds: number | null;
  median_seconds: number | null;
  p75_seconds: number | null;
  max_seconds: number | null;
  mean_seconds: number | null;
  quartiles_available: boolean;
  note: string;
}

export interface EventLevelReport {
  available: boolean;
  refusal_reason: string | null;
  model_id: string | null;
  rules: MatchingRules;
  rules_fingerprint: string;
  evaluated_windows: number;
  first_prediction_at: string | null;
  last_prediction_at: string | null;
  evaluated_span_seconds: number;
  events_out_of_coverage: number;
  events_total: number;
  events_warned: number;
  events_missed: number;
  missed_event_rate: number | null;
  lead_time: LeadTimeDistribution;
  positive_windows: number;
  warnings_issued: number;
  windows_per_warning: number | null;
  alarm_duty_cycle: number | null;
  detections: number;
  late_warnings: number;
  false_alarms: number;
  false_alarms_per_hour: number | null;
  label_provenance: string[];
  events: DocumentedEvent[];
  warnings_detail: IssuedWarning[];
  limitations: string[];
}
