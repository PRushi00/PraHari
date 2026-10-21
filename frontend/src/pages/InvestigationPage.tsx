// Investigation — from a warning to the evidence behind it (§11, ADR-109).
//
// The Forecast page explains a LIVE prediction. This explains a RECORDED
// one: pick a warning from the event-level evaluation, and see the window
// the model scored, the records inside it, which sources contributed, and
// what happened either side.
//
// The honesty rules that shape this page:
//
//   * The contribution figures are `value x GLOBAL importance`, which is
//     NOT a local explanation. The limitations are rendered WITH the
//     numbers, not behind a disclosure, because the table reads as an
//     explanation and would mislead on its own.
//   * A model whose input is not a window feature vector (persistence,
//     the temporal stack, the LSTM) gets no contributions and the reason
//     is shown — never an attribution against the wrong feature names.
//   * The window event count is the WHOLE window; the list may be
//     truncated, and says so, so the two are never confused.

import React, { useCallback, useState } from "react";
import { AlertTriangle, Search } from "lucide-react";
import { api } from "../services/api";
import { EventLevelReport, WarningInvestigation } from "../types";

const OUTCOME_COLOUR: Record<string, string> = {
  detection: "#10b981",
  late: "#f59e0b",
  false_alarm: "#ef4444",
};

export const InvestigationPage: React.FC = () => {
  const [report, setReport] = useState<EventLevelReport | null>(null);
  const [investigation, setInvestigation] = useState<WarningInvestigation | null>(
    null,
  );
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const loadWarnings = useCallback(async () => {
    setLoading(true);
    setError(null);
    setInvestigation(null);
    try {
      setReport(await api.evaluateEventLevel({}));
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, []);

  const investigate = useCallback(async (index: number) => {
    setLoading(true);
    setError(null);
    try {
      setInvestigation(await api.investigateWarning({ warning_index: index }));
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, []);

  return (
    <div>
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          gap: "1rem",
        }}
      >
        <h2 style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
          <Search size={20} /> Investigation
        </h2>
        <button className="btn" onClick={loadWarnings} disabled={loading}>
          {loading ? "Working…" : "Load warnings"}
        </button>
      </div>

      <div className="card">
        <p style={{ margin: 0 }}>
          Drill from a warning issued during evaluation to the window that
          produced it. Warnings come from the evaluation already in memory,
          so training must have run in this backend process.
        </p>
      </div>

      {error && (
        <div className="card" style={{ borderColor: "#ef4444" }}>
          <AlertTriangle size={16} /> {error}
        </div>
      )}

      {report && !report.available && (
        <div className="card">
          <strong>No warnings to investigate.</strong>
          <p style={{ marginBottom: 0 }}>
            {report.refusal_reason ??
              "The event-level evaluation produced no result."}
          </p>
        </div>
      )}

      {report?.available && (
        <div className="card">
          <h3>Warnings ({report.warnings_detail?.length ?? 0})</h3>
          {(report.warnings_detail?.length ?? 0) === 0 ? (
            <p style={{ marginBottom: 0 }}>
              This evaluation issued no warnings at the operating point
              used. That is a result, not an empty page.
            </p>
          ) : (
            <table style={{ width: "100%" }}>
              <thead>
                <tr>
                  <th>#</th>
                  <th>Issued</th>
                  <th>Windows</th>
                  <th>Peak</th>
                  <th>Outcome</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {report.warnings_detail.map((w) => (
                  <tr key={w.warning_index}>
                    <td>{w.warning_index}</td>
                    <td>{new Date(w.issued_at).toISOString()}</td>
                    <td>{w.windows}</td>
                    <td>{w.peak_score?.toFixed(4)}</td>
                    <td style={{ color: OUTCOME_COLOUR[w.outcome] }}>
                      {w.outcome}
                    </td>
                    <td>
                      <button
                        className="btn"
                        disabled={loading}
                        onClick={() => investigate(w.warning_index)}
                      >
                        Investigate
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      {investigation && !investigation.available && (
        <div className="card" style={{ borderColor: "#f59e0b" }}>
          <AlertTriangle size={16} /> {investigation.refusal_reason}
        </div>
      )}

      {investigation?.available && (
        <>
          <div className="card">
            <h3>
              Warning #{investigation.warning_index} ·{" "}
              <span style={{ color: OUTCOME_COLOUR[investigation.outcome] }}>
                {investigation.outcome}
              </span>
            </h3>
            <table style={{ width: "100%" }}>
              <tbody>
                <tr>
                  <td>Model</td>
                  <td>
                    <code>{investigation.model_id}</code>
                  </td>
                </tr>
                <tr>
                  <td>Window scored</td>
                  <td>
                    {investigation.issued_at} → {investigation.last_window_at} (
                    {investigation.windows} window
                    {investigation.windows === 1 ? "" : "s"})
                  </td>
                </tr>
                <tr>
                  <td>Peak score</td>
                  <td>{investigation.peak_score?.toFixed(4) ?? "—"}</td>
                </tr>
                <tr>
                  <td>Lead time</td>
                  <td>
                    {investigation.lead_time_seconds === null ||
                    investigation.lead_time_seconds === undefined
                      ? "— (no matched event)"
                      : `${investigation.lead_time_seconds.toFixed(1)}s`}
                  </td>
                </tr>
              </tbody>
            </table>
          </div>

          {/* Contributing features — §11. The limitations render WITH the
              table, because the numbers read as an explanation alone. */}
          <div className="card">
            <h3>Contributing features</h3>
            {investigation.contributions_available ? (
              <>
                <table style={{ width: "100%" }}>
                  <thead>
                    <tr>
                      <th>Feature</th>
                      <th>Value</th>
                      <th>Global importance</th>
                      <th>Product</th>
                    </tr>
                  </thead>
                  <tbody>
                    {investigation.contributions.map((c) => (
                      <tr key={c.feature}>
                        <td>
                          <code>{c.feature}</code>
                        </td>
                        <td>{c.value}</td>
                        <td>{c.importance_weight}</td>
                        <td>
                          <strong>{c.impact}</strong>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                <p style={{ marginBottom: "0.25rem" }}>
                  <strong>Method:</strong> {investigation.attribution_method}
                </p>
                <ul style={{ marginTop: 0 }}>
                  {investigation.attribution_limitations.map((l) => (
                    <li key={l}>{l}</li>
                  ))}
                </ul>
              </>
            ) : (
              <p style={{ marginBottom: 0 }}>
                {investigation.contributions_unavailable_reason}
              </p>
            )}
          </div>

          <div className="card">
            <h3>Sources in this window</h3>
            {investigation.sources.length === 0 ? (
              <p style={{ marginBottom: 0 }}>
                No stored event falls inside this window.
              </p>
            ) : (
              <table style={{ width: "100%" }}>
                <thead>
                  <tr>
                    <th>Source</th>
                    <th>Events</th>
                    <th>First</th>
                    <th>Last</th>
                  </tr>
                </thead>
                <tbody>
                  {investigation.sources.map((s) => (
                    <tr key={s.source_id}>
                      <td>
                        <code>{s.source_id}</code>
                      </td>
                      <td>{s.events_in_window}</td>
                      <td>{s.first_at}</td>
                      <td>{s.last_at}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>

          <div className="card">
            <h3>
              Input window — {investigation.window_event_count} event
              {investigation.window_event_count === 1 ? "" : "s"}
            </h3>
            {investigation.window_truncated && (
              <p style={{ color: "#f59e0b" }}>
                Showing the first {investigation.window_events_shown}. The
                count above is the whole window, not the shown subset.
              </p>
            )}
            <ul>
              {investigation.window_events.slice(0, 25).map((e) => (
                <li key={e.event_id}>
                  <code>{e.observed_at}</code> · {e.source_id} ·{" "}
                  {e.event_type}
                  {e.label ? ` · ${e.label}` : ""}
                </li>
              ))}
            </ul>
          </div>

          <div className="card">
            <h3>
              Related activity (±{investigation.related_window_seconds}s)
            </h3>
            <h4>Before ({investigation.related_before.length})</h4>
            {investigation.related_before.length === 0 ? (
              <p>Nothing recorded in the window before.</p>
            ) : (
              <ul>
                {investigation.related_before.slice(-10).map((e) => (
                  <li key={e.event_id}>
                    <code>{e.observed_at}</code> · {e.source_id}
                  </li>
                ))}
              </ul>
            )}
            <h4>After ({investigation.related_after.length})</h4>
            {investigation.related_after.length === 0 ? (
              <p style={{ marginBottom: 0 }}>
                Nothing recorded in the window after.
              </p>
            ) : (
              <ul>
                {investigation.related_after.slice(0, 10).map((e) => (
                  <li key={e.event_id}>
                    <code>{e.observed_at}</code> · {e.source_id}
                  </li>
                ))}
              </ul>
            )}
          </div>

          {investigation.notes.length > 0 && (
            <div className="card">
              <ul style={{ marginBottom: 0 }}>
                {investigation.notes.map((n) => (
                  <li key={n}>{n}</li>
                ))}
              </ul>
            </div>
          )}
        </>
      )}
    </div>
  );
};
