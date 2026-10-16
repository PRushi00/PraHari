import React, { useCallback, useEffect, useState } from "react";
import {
  AlertTriangle,
  CheckCircle,
  Clock,
  Power,
  RefreshCw,
  Settings,
  ShieldAlert,
  XCircle,
} from "lucide-react";
import { api } from "../services/api";
import { RetentionPolicy, SourceHealthSummary, SourceHealthRecord } from "../types";

/**
 * Administration (blueprint §11).
 *
 * Every control here calls a real backend endpoint:
 *   PATCH /sources/{id}/enabled   — enable or disable a source
 *   PUT   /retention/policy       — set or clear the retention override
 *
 * Rules this view holds to:
 *  - Nothing is reported as done before the backend confirms it. The
 *    table is re-read from the server after a mutation rather than
 *    being patched optimistically.
 *  - A consequential action is confirmed first.
 *  - A measurement the backend did not take renders as "unknown", never
 *    as 0 or as a dash that could be mistaken for one.
 *  - Changing retention is described as a policy change, because it
 *    deletes nothing; pruning is a separate confirmed operation.
 */

const Unknown: React.FC<{ label?: string }> = ({ label = "unknown" }) => (
  <span className="metric-unavailable">{label}</span>
);

const Seconds: React.FC<{ value: number | null | undefined }> = ({ value }) =>
  value === null || value === undefined ? (
    <Unknown label="not measured" />
  ) : (
    <span>{Math.round(value).toLocaleString()}s ago</span>
  );

export const AdministrationPage: React.FC = () => {
  const [health, setHealth] = useState<SourceHealthSummary | null>(null);
  const [policy, setPolicy] = useState<RetentionPolicy | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busySource, setBusySource] = useState<string | null>(null);
  const [draftDays, setDraftDays] = useState<string>("");
  const [savingPolicy, setSavingPolicy] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [h, p] = await Promise.all([
        api.getSourceHealth(),
        api.getRetentionPolicy(),
      ]);
      setHealth(h);
      setPolicy(p);
      setDraftDays(String(p.retention_days));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Request failed");
      setHealth(null);
      setPolicy(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const toggleSource = async (record: SourceHealthRecord) => {
    const next = !record.enabled;
    const verb = next ? "Enable" : "Disable";
    const warning = next
      ? ""
      : "\n\nDisabling stops PraHari expecting telemetry from it. No stored events are deleted.";
    if (
      !window.confirm(
        `${verb} source "${record.source_id}"?${warning}`
      )
    ) {
      return;
    }

    setBusySource(record.source_id);
    setError(null);
    setNotice(null);
    try {
      await api.setSourceEnabled(record.source_id, next);
      // Re-read from the server. The UI must not claim success from its
      // own optimistic guess.
      await load();
      setNotice(`Source "${record.source_id}" is now ${next ? "enabled" : "disabled"}.`);
    } catch (err) {
      setError(
        `Could not ${verb.toLowerCase()} "${record.source_id}": ` +
          (err instanceof Error ? err.message : "request failed")
      );
    } finally {
      setBusySource(null);
    }
  };

  const savePolicy = async (clear: boolean) => {
    const parsed = clear ? null : Number(draftDays);
    if (!clear && (!Number.isInteger(parsed) || (parsed as number) < 1)) {
      setError("Retention must be a whole number of days, at least 1.");
      return;
    }
    const summary = clear
      ? "Clear the override and fall back to the configured default?"
      : `Set retention to ${parsed} days?`;
    if (
      !window.confirm(
        `${summary}\n\nThis changes POLICY only. No records are deleted by this ` +
          `action; pruning remains a separate, confirmed operation.`
      )
    ) {
      return;
    }

    setSavingPolicy(true);
    setError(null);
    setNotice(null);
    try {
      const updated = await api.updateRetentionPolicy(parsed);
      setPolicy(updated);
      setDraftDays(String(updated.retention_days));
      setNotice(
        `Retention is now ${updated.retention_days} days (${updated.origin}). ` +
          `No records were deleted.`
      );
    } catch (err) {
      setError(
        "Could not update retention: " +
          (err instanceof Error ? err.message : "request failed")
      );
    } finally {
      setSavingPolicy(false);
    }
  };

  const sources = health?.sources ?? [];

  return (
    <div className="page administration-page">
      <div className="page-header">
        <div>
          <h2>
            <Settings size={20} /> Administration
          </h2>
          <p className="page-subtitle">
            Source and retention management. Changes are audited, validated on
            the server, and confirmed before they are applied.
          </p>
        </div>
        <button className="btn" onClick={load} disabled={loading}>
          <RefreshCw size={16} className={loading ? "spinning" : ""} /> Refresh
        </button>
      </div>

      {error && (
        <div className="status-banner status-error" role="alert">
          <XCircle size={16} /> <span>{error}</span>
        </div>
      )}
      {notice && (
        <div className="status-banner status-ok" role="status">
          <CheckCircle size={16} /> <span>{notice}</span>
        </div>
      )}

      <section className="panel">
        <div className="panel-header">
          <h3>
            <Power size={18} /> Telemetry sources
          </h3>
        </div>

        {loading && !health ? (
          <p className="metric-unavailable">Loading sources…</p>
        ) : sources.length === 0 ? (
          <p className="metric-unavailable">
            No telemetry source is registered.
          </p>
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th>Source</th>
                <th>Type</th>
                <th>State</th>
                <th>Events</th>
                <th>Last event</th>
                <th>Freshness basis</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {sources.map((s) => (
                <tr key={s.source_id}>
                  <td>
                    <strong>{s.name || s.source_id}</strong>
                    <div className="cell-note">{s.source_id}</div>
                  </td>
                  <td>{s.source_type}</td>
                  <td>
                    <span className={`badge badge-${s.state}`}>{s.state}</span>
                  </td>
                  <td>
                    {s.event_count === null || s.event_count === undefined ? (
                      <Unknown />
                    ) : (
                      s.event_count.toLocaleString()
                    )}
                  </td>
                  <td>
                    <Seconds value={s.seconds_since_last_event} />
                  </td>
                  <td className="cell-note">
                    {s.clock_dependent === false
                      ? "server receipt"
                      : "event time (source clock)"}
                  </td>
                  <td>
                    <button
                      className={s.enabled ? "btn btn-danger" : "btn"}
                      onClick={() => toggleSource(s)}
                      disabled={busySource === s.source_id}
                      aria-label={`${s.enabled ? "Disable" : "Enable"} source ${s.source_id}`}
                    >
                      {busySource === s.source_id
                        ? "Working…"
                        : s.enabled
                        ? "Disable"
                        : "Enable"}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        <p className="panel-note">
          Credentials are never shown here. They are issued, rotated and revoked
          offline with <code>scripts/manage_credentials.py</code>; a revocation
          takes effect on the next request without restarting the backend.
        </p>
      </section>

      <section className="panel">
        <div className="panel-header">
          <h3>
            <Clock size={18} /> Retention policy
          </h3>
        </div>

        {!policy ? (
          <p className="metric-unavailable">
            {loading ? "Loading policy…" : "Policy unavailable."}
          </p>
        ) : (
          <>
            <div className="metric-grid">
              <div className="metric">
                <span className="metric-label">In force</span>
                <span className="metric-value">{policy.retention_days} days</span>
                <span className="metric-sub">{policy.origin}</span>
              </div>
              <div className="metric">
                <span className="metric-label">Configured default</span>
                <span className="metric-value">
                  {policy.configured_default ?? "—"} days
                </span>
              </div>
              <div className="metric">
                <span className="metric-label">Automatic pruning</span>
                <span className="metric-value">
                  {policy.automatic_pruning ? "enabled" : "disabled"}
                </span>
              </div>
              <div className="metric">
                <span className="metric-label">Enforcement</span>
                <span className="metric-value">{policy.enforcement}</span>
              </div>
            </div>

            <div className="form-row">
              <label htmlFor="retention-days">Retention (days)</label>
              <input
                id="retention-days"
                type="number"
                min={1}
                max={36500}
                value={draftDays}
                onChange={(e) => setDraftDays(e.target.value)}
                disabled={savingPolicy}
              />
              <button
                className="btn btn-primary"
                onClick={() => savePolicy(false)}
                disabled={savingPolicy}
              >
                {savingPolicy ? "Saving…" : "Set policy"}
              </button>
              <button
                className="btn"
                onClick={() => savePolicy(true)}
                disabled={savingPolicy || policy.origin !== "operator_override"}
              >
                Clear override
              </button>
            </div>

            <div className="status-banner status-warn">
              <AlertTriangle size={16} />
              <span>
                Changing this value sets policy only. <strong>No records are
                deleted by this action.</strong> Pruning happens when an
                operator runs enforcement with its confirmation token.
              </span>
            </div>

            {policy.notes && (
              <ul className="note-list">
                {policy.notes.map((n, i) => (
                  <li key={i}>{n}</li>
                ))}
              </ul>
            )}
          </>
        )}
      </section>

      <section className="panel panel-muted">
        <h3>
          <ShieldAlert size={18} /> Authorization
        </h3>
        <p>
          On a central deployment these operations require an admin credential;
          a sensor credential is refused with HTTP 403. A loopback deployment is
          unauthenticated by design, so the controls are available to the local
          operator. Every change is written to the audit log.
        </p>
      </section>
    </div>
  );
};
