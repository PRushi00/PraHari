// Sources — one view per telemetry source (blueprint §11, ADR-108).
//
// §11 lists a Sources view carrying "source identity, capability, last
// event and adapter errors". Those four lived in three places:
// Administration held identity and the enable toggle, Live Telemetry held
// the local collector's own counters, and capability was reachable only
// through `GET /events/capabilities`. Nothing showed one source whole, and
// a remote sensor had no page of its own at all.
//
// The honesty rules that shape this page:
//
//   * Freshness is derived from event time REPORTED BY THE SOURCE, so a
//     host with a slow clock looks staler than it is. The basis is shown
//     beside every figure rather than buried in a tooltip.
//   * There is no heartbeat. Silence means "no events recorded", never
//     "the host is down", and a source legitimately idle is
//     indistinguishable from one that has stopped.
//   * The adapter registry lists only adapters EXERCISED IN THIS PROCESS.
//     A source with no adapter row has not been seen since the backend
//     started — which is not the same as an adapter that is failing, and
//     the two are never collapsed into one indicator here.

import React, { useCallback, useEffect, useState } from "react";
import { AlertTriangle, RefreshCw, Radio } from "lucide-react";
import { api } from "../services/api";
import {
  AdapterHealth,
  SourceCapability,
  SourceHealthRecord,
  SourceHealthSummary,
} from "../types";

const STATE_COLOUR: Record<string, string> = {
  fresh: "#10b981",
  reporting: "#10b981",
  stale: "#f59e0b",
  silent: "#ef4444",
  never_reported: "#6b7280",
};

function stateColour(state: string): string {
  return STATE_COLOUR[state] ?? "#6b7280";
}

function ago(seconds: number | null | undefined): string {
  if (seconds === null || seconds === undefined) return "—";
  if (seconds < 90) return `${Math.round(seconds)}s ago`;
  if (seconds < 5400) return `${Math.round(seconds / 60)}m ago`;
  return `${(seconds / 3600).toFixed(1)}h ago`;
}

interface SourceCardProps {
  record: SourceHealthRecord;
  adapter?: AdapterHealth;
  capability?: SourceCapability;
}

const SourceCard: React.FC<SourceCardProps> = ({ record, adapter, capability }) => (
  <div className="card" data-testid={`source-${record.source_id}`}>
    <div
      style={{
        display: "flex",
        alignItems: "baseline",
        justifyContent: "space-between",
        gap: "1rem",
        flexWrap: "wrap",
      }}
    >
      <div>
        <h3 style={{ margin: 0 }}>{record.name}</h3>
        <code style={{ fontSize: "0.85em", opacity: 0.8 }}>{record.source_id}</code>
        <span style={{ marginLeft: "0.6rem", opacity: 0.7 }}>{record.source_type}</span>
      </div>
      <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
        <span
          className="status-dot"
          style={{ backgroundColor: stateColour(record.state) }}
        />
        <strong>{record.state}</strong>
        {!record.enabled && (
          <span style={{ color: "#f59e0b" }}>· ingestion disabled</span>
        )}
      </div>
    </div>

    <table style={{ width: "100%", marginTop: "0.75rem" }}>
      <tbody>
        <tr>
          <td>Events stored</td>
          <td>
            <strong>{record.event_count.toLocaleString()}</strong>
          </td>
        </tr>
        <tr>
          <td>Last event</td>
          <td>
            {record.last_event_at ? (
              <>
                {new Date(record.last_event_at).toISOString()}{" "}
                <span style={{ opacity: 0.7 }}>
                  ({ago(record.seconds_since_last_event)})
                </span>
              </>
            ) : (
              <span style={{ opacity: 0.7 }}>never — no event recorded</span>
            )}
          </td>
        </tr>
        <tr>
          <td>Measured receipt</td>
          <td>
            {record.receipt_evidence_available ? (
              <>
                {record.last_received_at}{" "}
                <span style={{ opacity: 0.7 }}>
                  ({ago(record.seconds_since_last_receipt)})
                </span>
              </>
            ) : (
              <span style={{ opacity: 0.7 }}>
                none — freshness falls back to source-reported event time
              </span>
            )}
          </td>
        </tr>
        <tr>
          <td>Freshness basis</td>
          <td style={{ opacity: 0.85 }}>{record.freshness_basis}</td>
        </tr>
      </tbody>
    </table>

    {record.reasons.length > 0 && (
      <ul style={{ marginTop: "0.5rem" }}>
        {record.reasons.map((r) => (
          <li key={r}>{r}</li>
        ))}
      </ul>
    )}

    {/* Adapter errors — §11 names these explicitly. A source with no
        adapter row is reported as not-seen-in-this-process, which is a
        different statement from a healthy adapter. */}
    <h4 style={{ marginBottom: "0.25rem" }}>Adapter</h4>
    {adapter ? (
      <div>
        <span
          className="status-dot"
          style={{ backgroundColor: adapter.is_healthy ? "#10b981" : "#ef4444" }}
        />{" "}
        <code>{adapter.adapter_type}</code> · processed{" "}
        <strong>{adapter.records_processed.toLocaleString()}</strong> · rejected{" "}
        <strong
          style={{ color: adapter.records_rejected > 0 ? "#f59e0b" : undefined }}
        >
          {adapter.records_rejected.toLocaleString()}
        </strong>
        {adapter.error_message && (
          <div style={{ color: "#ef4444", marginTop: "0.35rem" }}>
            <AlertTriangle size={14} /> {adapter.error_message}
          </div>
        )}
      </div>
    ) : (
      <p style={{ opacity: 0.75, margin: 0 }}>
        No adapter has run for this source in this backend process. That is
        not an adapter failure — the registry only lists adapters actually
        exercised since startup.
      </p>
    )}

    {/* Capability — what this kind of source can and cannot report, so a
        blank field is read as "not observable here" rather than "missing". */}
    <h4 style={{ marginBottom: "0.25rem" }}>Capability</h4>
    {capability ? (
      <>
        <p style={{ margin: "0 0 0.35rem" }}>{capability.description}</p>
        {capability.limitations.length > 0 && (
          <ul>
            {capability.limitations.map((l) => (
              <li key={l}>{l}</li>
            ))}
          </ul>
        )}
      </>
    ) : (
      <p style={{ opacity: 0.75, margin: 0 }}>
        No capability report is published for source type{" "}
        <code>{record.source_type}</code>, so what it can observe is
        undeclared.
      </p>
    )}

    {record.limitations.length > 0 && (
      <>
        <h4 style={{ marginBottom: "0.25rem" }}>Limitations</h4>
        <ul>
          {record.limitations.map((l) => (
            <li key={l}>{l}</li>
          ))}
        </ul>
      </>
    )}
  </div>
);

export const SourcesPage: React.FC = () => {
  const [summary, setSummary] = useState<SourceHealthSummary | null>(null);
  const [adapters, setAdapters] = useState<AdapterHealth[]>([]);
  const [capabilities, setCapabilities] = useState<SourceCapability[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchAll = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      // Adapter health and capability are secondary: a failure in either
      // must not blank the identity and freshness this page exists for.
      const [health, adapterList, capabilityList] = await Promise.all([
        api.getSourceHealth(),
        api.getStreamAdapters().catch(() => [] as AdapterHealth[]),
        api.getSourceCapabilities().catch(() => [] as SourceCapability[]),
      ]);
      setSummary(health);
      setAdapters(adapterList);
      setCapabilities(capabilityList);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchAll();
  }, [fetchAll]);

  const adapterFor = (sourceId: string) =>
    adapters.find((a) => a.adapter_id === sourceId);
  const capabilityFor = (sourceType: string) =>
    capabilities.find((c) => c.source_type === sourceType);

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
          <Radio size={20} /> Sources
        </h2>
        <button className="btn" onClick={fetchAll} disabled={loading}>
          <RefreshCw size={14} /> {loading ? "Refreshing…" : "Refresh"}
        </button>
      </div>

      {error && (
        <div className="card" style={{ borderColor: "#ef4444" }}>
          <AlertTriangle size={16} /> Could not load source health: {error}
        </div>
      )}

      {summary && summary.sources.length === 0 && (
        <div className="card">
          <p style={{ margin: 0 }}>
            No telemetry source is registered. A source appears here the
            first time it delivers an event, or when the local collector is
            started.
          </p>
        </div>
      )}

      {summary && summary.sources.length > 0 && (
        <>
          <div className="card">
            <strong>
              {summary.sources.length} source
              {summary.sources.length === 1 ? "" : "s"}
            </strong>{" "}
            ·{" "}
            {Object.entries(summary.counts_by_state)
              .map(([state, n]) => `${n} ${state}`)
              .join(" · ")}{" "}
            · evaluated {new Date(summary.evaluated_at).toISOString()}
            <ul style={{ marginTop: "0.5rem" }}>
              {summary.notes.map((n) => (
                <li key={n}>{n}</li>
              ))}
            </ul>
          </div>

          {summary.sources.map((s) => (
            <SourceCard
              key={s.source_id}
              record={s}
              adapter={adapterFor(s.source_id)}
              capability={capabilityFor(s.source_type)}
            />
          ))}
        </>
      )}
    </div>
  );
};
