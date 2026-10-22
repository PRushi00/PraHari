import React, { useState, useEffect, useCallback } from "react";
import {
  Activity,
  AlertTriangle,
  CheckCircle,
  Database,
  Gauge,
  HardDrive,
  Layers,
  RefreshCw,
  Shield,
  XCircle,
} from "lucide-react";
import { api } from "../services/api";
import { SystemHealthReport, HealthBlock } from "../types";
import { fmtTime, humanise } from "../utils/format";
import { Explain } from "../components/GuidedMode";

/**
 * System Health (blueprint §11).
 *
 * The honesty rules of §12 drive every rendering decision here:
 *
 *  - A measured number is shown. Anything the backend reported as null
 *    renders as "not measured", never as 0 — zero is itself a reading.
 *  - A block the backend could not read renders its reason, so the
 *    operator can tell "nothing happened" from "we cannot tell".
 *  - Queue depth is shown as "no queue" because PraHari has none;
 *    printing 0 would assert an empty one.
 *
 * Nothing on this page is synthetic or illustrative.
 */

/** A value that may genuinely not have been measured. */
const Measured: React.FC<{
  value: number | string | null | undefined;
  suffix?: string;
  unavailableLabel?: string;
}> = ({ value, suffix = "", unavailableLabel = "not measured" }) => {
  if (value === null || value === undefined) {
    return <span className="metric-unavailable">{unavailableLabel}</span>;
  }
  return (
    <span className="metric-value">
      {typeof value === "number" ? value.toLocaleString() : value}
      {suffix}
    </span>
  );
};

const BlockShell: React.FC<{
  title: string;
  icon: React.ReactNode;
  block: HealthBlock | undefined;
  children: (data: Record<string, any>) => React.ReactNode;
}> = ({ title, icon, block, children }) => (
  <section className="panel system-health-block">
    <div className="panel-header">
      <h3>
        {icon} {title}
      </h3>
    </div>
    {!block ? (
      <p className="metric-unavailable">Not reported by this backend.</p>
    ) : !block.available ? (
      <div className="status-banner status-warn">
        <AlertTriangle size={16} />
        <span>
          Unavailable — {block.reason ?? "no reason given"}
        </span>
      </div>
    ) : (
      children(block.data ?? {})
    )}
  </section>
);

export const SystemHealthPage: React.FC = () => {
  const [report, setReport] = useState<SystemHealthReport | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchReport = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      setReport(await api.getSystemHealth());
    } catch (err) {
      setError(err instanceof Error ? err.message : "Request failed");
      // The previous reading is NOT kept on screen: a stale number with
      // a fresh timestamp is worse than no number.
      setReport(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchReport();
  }, [fetchReport]);

  return (
    <div className="page system-health-page">
      <div className="page-header">
        <div>
          <h2>
            <Activity size={20} /> System Health
          </h2>
          <p className="page-subtitle">
            Operational measurements taken by this backend. Values the backend
            did not measure are shown as “not measured”, never as zero.
          </p>
          <Explain>
            “Not measured” above means PraHari never took that reading — it
            does not mean the reading was zero. The two look the same on a
            dashboard and mean opposite things, which is why they are kept
            apart here.
          </Explain>
        </div>
        <button className="btn" onClick={fetchReport} disabled={loading}>
          <RefreshCw size={16} className={loading ? "spinning" : ""} />
          Refresh
        </button>
      </div>

      {error && (
        <div className="status-banner status-error">
          <XCircle size={16} />
          <span>Could not read system health: {error}</span>
        </div>
      )}

      {report && (
        <>
          <div className="summary-row">
            <div className="summary-card">
              <span className="summary-label">Deployment</span>
              <span className="summary-value">{report.deployment_mode}</span>
            </div>
            <div className="summary-card">
              <span className="summary-label">Uptime</span>
              <span className="summary-value">
                {Math.round(report.uptime_seconds).toLocaleString()}s
              </span>
            </div>
            <div className="summary-card">
              <span className="summary-label">Schema</span>
              <span className="summary-value">{report.schema_version}</span>
            </div>
            <div className="summary-card">
              <span className="summary-label">Generated</span>
              <span className="summary-value">
                {fmtTime(report.generated_at)}
              </span>
            </div>
          </div>

          <BlockShell
            title="Ingestion"
            icon={<Gauge size={18} />}
            block={report.ingestion}
          >
            {(d) => (
              <>
                <div className="metric-grid">
                  <div className="metric">
                    <span className="metric-label">Queue depth</span>
                    <span className="metric-unavailable">
                      no queue — synchronous ingestion
                    </span>
                  </div>
                  <div className="metric">
                    <span className="metric-label">In flight</span>
                    <Measured value={d.in_flight} />
                    <span className="metric-sub">
                      of {d.capacity} capacity
                      {d.saturated ? " (saturated)" : ""}
                    </span>
                  </div>
                  <div className="metric">
                    <span className="metric-label">Peak in flight</span>
                    <Measured value={d.peak_in_flight} />
                  </div>
                  <div className="metric">
                    <span className="metric-label">Events stored</span>
                    <Measured value={d.events_stored} />
                  </div>
                  <div className="metric">
                    <span className="metric-label">Duplicates suppressed</span>
                    <Measured value={d.events_duplicate} />
                  </div>
                  <div className="metric">
                    <span className="metric-label">Records rejected</span>
                    <Measured value={d.events_rejected} />
                  </div>
                  <div className="metric">
                    <span className="metric-label">Refused (overloaded)</span>
                    <Measured value={d.requests_rejected_overloaded} />
                  </div>
                  <div className="metric">
                    <span className="metric-label">Identity conflicts</span>
                    <Measured value={d.conflicts} />
                  </div>
                  <div className="metric">
                    <span className="metric-label">Last success</span>
                    <Measured
                      value={d.last_success_at ? fmtTime(d.last_success_at) : null}
                      unavailableLabel="none yet"
                    />
                  </div>
                  <div className="metric">
                    <span className="metric-label">Processing p50</span>
                    <Measured value={d.processing_latency?.p50_ms} suffix=" ms" />
                  </div>
                  <div className="metric">
                    <span className="metric-label">Processing p95</span>
                    <Measured value={d.processing_latency?.p95_ms} suffix=" ms" />
                  </div>
                  <div className="metric">
                    <span className="metric-label">Latency samples</span>
                    <Measured value={d.processing_latency?.samples} />
                  </div>
                </div>
                <p className="panel-note">{d.queue_depth_note}</p>
              </>
            )}
          </BlockShell>

          <BlockShell
            title="Sources"
            icon={<Layers size={18} />}
            block={report.sources}
          >
            {(d) =>
              d.total === 0 ? (
                <p className="metric-unavailable">
                  No telemetry source is registered yet.
                </p>
              ) : (
                <>
                  <div className="metric-grid">
                    {Object.entries(d.counts_by_state ?? {}).map(([state, n]) => (
                      <div className="metric" key={state}>
                        <span className="metric-label">{humanise(state)}</span>
                        <Measured value={n as number} />
                      </div>
                    ))}
                  </div>
                  <table className="data-table">
                    <thead>
                      <tr>
                        <th>Source</th>
                        <th>Type</th>
                        <th>State</th>
                        <th>Events</th>
                        <th>Freshness basis</th>
                      </tr>
                    </thead>
                    <tbody>
                      {(d.sources ?? []).map((s: any) => (
                        <tr key={s.source_id}>
                          <td>{s.name || <code>{s.source_id}</code>}</td>
                          <td><code>{s.source_type}</code></td>
                          <td>
                            <span className={`badge badge-${s.state}`}>
                              {humanise(s.state)}
                            </span>
                          </td>
                          <td>{s.event_count?.toLocaleString() ?? "—"}</td>
                          <td className="cell-note">
                            {s.clock_dependent
                              ? "event time (source clock)"
                              : "server receipt"}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  <p className="panel-note">
                    States describe PraHari&apos;s evidence, not whether a
                    remote host is running. There is no heartbeat: a silent
                    source may be healthy with nothing to report.
                  </p>
                </>
              )
            }
          </BlockShell>

          <BlockShell
            title="Storage"
            icon={<HardDrive size={18} />}
            block={report.storage}
          >
            {(d) => (
              <div className="metric-grid">
                <div className="metric">
                  <span className="metric-label">Integrity</span>
                  {/* A backend with no equivalent structural check reports
                      null, and that reads as "not measured" rather than
                      borrowing the healthy tick from a check nobody ran. */}
                  {d.integrity_check == null ? (
                    <Measured value={null} />
                  ) : (
                    <span
                      className={d.healthy ? "metric-value ok" : "metric-value bad"}
                    >
                      {d.healthy ? <CheckCircle size={14} /> : <XCircle size={14} />}{" "}
                      {d.integrity_check}
                    </span>
                  )}
                </div>
                <div className="metric">
                  <span className="metric-label">Store</span>
                  <Measured value={d.backend} />
                </div>
                <div className="metric">
                  <span className="metric-label">Events stored</span>
                  <Measured value={d.event_count} />
                </div>
                <div className="metric">
                  <span className="metric-label">Database size</span>
                  <Measured
                    value={
                      d.size_bytes != null
                        ? Math.round(d.size_bytes / 1024)
                        : null
                    }
                    suffix=" KiB"
                  />
                </div>
                <div className="metric">
                  <span className="metric-label">Journal mode</span>
                  <Measured value={d.journal_mode} />
                </div>
                <div className="metric">
                  <span className="metric-label">Received-at column</span>
                  <span className="metric-value">
                    {d.received_at_column_present ? "applied" : "not applied"}
                  </span>
                </div>
                <div className="metric">
                  <span className="metric-label">Retention</span>
                  <Measured value={d.retention_days} suffix=" days" />
                </div>
              </div>
            )}
          </BlockShell>

          <BlockShell
            title="Models & Inference"
            icon={<Database size={18} />}
            block={report.models}
          >
            {(d) => (
              <>
                <div className="metric-grid">
                  <div className="metric">
                    <span className="metric-label">Trained models</span>
                    <Measured value={d.model_count} />
                  </div>
                  <div className="metric">
                    <span className="metric-label">Inference</span>
                    <span className="metric-value">
                      {d.inference_available ? "available" : "unavailable"}
                    </span>
                  </div>
                  <div className="metric">
                    <span className="metric-label">Inference latency</span>
                    <Measured value={d.inference_latency} suffix=" ms" />
                  </div>
                </div>
                {d.note && <p className="panel-note">{d.note}</p>}
                {!d.inference_available && (
                  <p className="panel-note">
                    No score is substituted when a model is unavailable.
                  </p>
                )}
              </>
            )}
          </BlockShell>

          <BlockShell
            title="Adapters"
            icon={<Activity size={18} />}
            block={report.adapters}
          >
            {(d) =>
              (d.adapters ?? []).length === 0 ? (
                <p className="metric-unavailable">
                  No adapter has run in this process yet.
                </p>
              ) : (
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Adapter</th>
                      <th>Type</th>
                      <th>Processed</th>
                      <th>Rejected</th>
                      <th>Last error</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(d.adapters ?? []).map((a: any) => (
                      <tr key={a.adapter_id}>
                        <td>{a.adapter_id}</td>
                        <td>{a.adapter_type}</td>
                        <td>{a.records_processed?.toLocaleString() ?? "—"}</td>
                        <td>{a.records_rejected?.toLocaleString() ?? "—"}</td>
                        <td className="cell-note">{a.last_error ?? "none"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )
            }
          </BlockShell>

          <BlockShell
            title="Limits & Enforcement"
            icon={<Shield size={18} />}
            block={report.limits}
          >
            {(d) => (
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Control</th>
                    <th>Configured</th>
                    <th>Enforced</th>
                  </tr>
                </thead>
                <tbody>
                  <tr>
                    <td>Max request size</td>
                    <td>{d.max_request_size_mb} MB</td>
                    <td>{d.request_size_limit_enforced ? "yes" : "no"}</td>
                  </tr>
                  <tr>
                    <td>Max import records</td>
                    <td>{d.max_import_records?.toLocaleString()}</td>
                    <td>{d.import_record_limit_enforced ? "yes" : "no"}</td>
                  </tr>
                  <tr>
                    <td>Rate limit</td>
                    <td>
                      {d.rate_limit_requests} / {d.rate_limit_window_seconds}s
                    </td>
                    <td>{d.rate_limit_enforced ? "yes" : "no"}</td>
                  </tr>
                  <tr>
                    <td>Ingestion concurrency</td>
                    <td>{d.ingestion_capacity}</td>
                    <td>{d.admission_control_enforced ? "yes" : "no"}</td>
                  </tr>
                </tbody>
              </table>
            )}
          </BlockShell>

          <div className="panel panel-muted">
            <ul className="note-list">
              {report.notes?.map((n, i) => (
                <li key={i}>{n}</li>
              ))}
            </ul>
          </div>
        </>
      )}
    </div>
  );
};
