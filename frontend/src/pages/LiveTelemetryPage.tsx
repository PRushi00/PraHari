import React, { useCallback, useEffect, useRef, useState } from "react";
import {
  Activity,
  AlertTriangle,
  CheckCircle,
  Database,
  Info,
  Play,
  RefreshCw,
  Radio,
  Square,
  XCircle,
} from "lucide-react";
import { api } from "../services/api";
import { ConnectionTable } from "../components/ConnectionTable";
import { AppLayerPanel } from "../components/AppLayerPanel";
import { fmtFixed, fmtInt, humanise } from "../utils/format";
import {
  CollectorStatus,
  ConnectionDetail,
  EnrichmentStatus,
  PollResult,
  TelemetrySource,
} from "../types";

const STATE_STYLES: Record<string, { color: string; label: string }> = {
  running: { color: "#10b981", label: "COLLECTING" },
  stopped: { color: "#94a3b8", label: "NOT COLLECTING" },
  error: { color: "#f43f5e", label: "COLLECTION ERROR" },
  unsupported: { color: "#f59e0b", label: "UNSUPPORTED PLATFORM" },
};

const fmtTime = (iso: string | null): string => {
  if (!iso) return "—";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? "—" : d.toLocaleString();
};

const relativeSeconds = (iso: string | null): string => {
  if (!iso) return "never";
  const secs = (Date.now() - new Date(iso).getTime()) / 1000;
  if (Number.isNaN(secs)) return "never";
  if (secs < 60) return `${Math.max(0, Math.round(secs))}s ago`;
  if (secs < 3600) return `${Math.round(secs / 60)}m ago`;
  return `${Math.round(secs / 3600)}h ago`;
};

export const LiveTelemetryPage: React.FC<{ onDataChanged?: () => void }> = ({
  onDataChanged,
}) => {
  const [status, setStatus] = useState<CollectorStatus | null>(null);
  const [source, setSource] = useState<TelemetrySource | null>(null);
  const [connections, setConnections] = useState<ConnectionDetail[]>([]);
  const [eventTotal, setEventTotal] = useState(0);
  const [returnedCount, setReturnedCount] = useState(0);
  const [lastPoll, setLastPoll] = useState<PollResult | null>(null);
  const [enrichment, setEnrichment] = useState<EnrichmentStatus | null>(null);
  const [dnsDiag, setDnsDiag] = useState<Record<string, any> | null>(null);

  // Connection filters
  const [filterHostname, setFilterHostname] = useState("");
  const [filterProcess, setFilterProcess] = useState("");
  const [filterDstIp, setFilterDstIp] = useState("");
  const [filterPort, setFilterPort] = useState("");
  const [filterState, setFilterState] = useState("");
  const [allowReverseDns, setAllowReverseDns] = useState(false);

  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [interval, setIntervalSeconds] = useState(15);

  const timerRef = useRef<number | null>(null);

  const load = useCallback(
    async (showSpinner = false) => {
      if (showSpinner) setLoading(true);
      try {
        const st = await api.getCollectorStatus();
        setStatus(st);
        setError(null);

        // Scoped to the collector's own source, so this page can never
        // present imported or synthetic records as live observations.
        const [page, src, enr] = await Promise.all([
          api.getConnections({
            source_id: st.source_id,
            data_category: "live_telemetry",
            hostname: filterHostname || undefined,
            process: filterProcess || undefined,
            dst_ip: filterDstIp || undefined,
            dst_port: filterPort ? Number(filterPort) : undefined,
            connection_state: filterState || undefined,
            allow_reverse_dns: allowReverseDns,
            limit: 200,
          }),
          api.getSource(st.source_id).catch(() => null),
          api.getEnrichmentStatus().catch(() => null),
        ]);
        // Diagnose DNS visibility only when there is no evidence, so the
        // empty state can explain itself instead of looking like a failure.
        if (enr && enr.total_observations_stored === 0) {
          api.diagnoseDns().then(setDnsDiag).catch(() => setDnsDiag(null));
        } else {
          setDnsDiag(null);
        }
        setConnections(page.connections);
        setEventTotal(page.total);
        setReturnedCount(page.returned);
        setSource(src);
        setEnrichment(enr);
      } catch (err) {
        setError(err instanceof Error ? err.message : String(err));
      } finally {
        setLoading(false);
      }
    },
    [filterHostname, filterProcess, filterDstIp, filterPort, filterState, allowReverseDns]
  );

  useEffect(() => {
    load(true);
  }, [load]);

  // Poll the status endpoint while collection is running so the operator sees
  // live progress; stop polling when it is not, to avoid pointless requests.
  useEffect(() => {
    if (timerRef.current) {
      window.clearInterval(timerRef.current);
      timerRef.current = null;
    }
    if (status?.state === "running") {
      timerRef.current = window.setInterval(() => load(false), 5000);
    }
    return () => {
      if (timerRef.current) window.clearInterval(timerRef.current);
    };
  }, [status?.state, load]);

  const act = async (fn: () => Promise<unknown>) => {
    setBusy(true);
    setError(null);
    try {
      await fn();
      await load(false);
      onDataChanged?.();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  const handleStart = () => act(() => api.startCollector(interval));
  const handleStop = () => act(() => api.stopCollector());
  const handlePollOnce = () =>
    act(async () => {
      const result = await api.pollCollectorOnce();
      setLastPoll(result);
    });

  const style = STATE_STYLES[status?.state ?? "stopped"] ?? STATE_STYLES.stopped;
  const unsupported = status ? !status.platform_supported : false;
  const running = status?.state === "running";

  if (loading) {
    return (
      <div className="glass-panel" style={{ padding: "2rem", textAlign: "center" }}>
        <RefreshCw size={20} className="spin" />
        <div style={{ marginTop: "0.75rem", color: "var(--text-dim)" }}>
          Loading live telemetry status…
        </div>
      </div>
    );
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "1.25rem" }}>
      {/* ── Header / controls ───────────────────────────────── */}
      <div className="glass-panel" style={{ padding: "1.25rem 1.5rem" }}>
        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            flexWrap: "wrap",
            gap: "1rem",
          }}
        >
          <div>
            <h2 style={{ margin: 0, display: "flex", alignItems: "center", gap: "0.6rem" }}>
              <Radio size={20} style={{ color: style.color }} />
              Live Windows Telemetry
            </h2>
            <div style={{ color: "var(--text-dim)", fontSize: "var(--text-xs)", marginTop: "0.35rem" }}>
              Genuine TCP connection metadata polled from this host&apos;s Windows
              connection table
            </div>
          </div>

          <div style={{ display: "flex", alignItems: "center", gap: "0.75rem", flexWrap: "wrap" }}>
            <div className="status-pill">
              <span
                className="status-dot"
                style={{ backgroundColor: style.color }}
              />
              <span>{style.label}</span>
            </div>

            <label style={{ fontSize: "var(--text-2xs)", color: "var(--text-dim)" }}>
              Interval
              <input
                type="number"
                min={2}
                max={3600}
                value={interval}
                disabled={running || busy}
                onChange={(e) => setIntervalSeconds(Number(e.target.value) || 15)}
                style={{
                  width: "4.5rem",
                  marginLeft: "0.4rem",
                  padding: "0.3rem 0.4rem",
                  background: "rgba(255,255,255,0.05)",
                  border: "1px solid var(--border-subtle)",
                  borderRadius: "4px",
                  color: "inherit",
                }}
              />
              <span style={{ marginLeft: "0.25rem" }}>s</span>
            </label>

            <button
              className="btn btn-secondary"
              onClick={handlePollOnce}
              disabled={busy || unsupported}
              title="Run exactly one collection poll"
            >
              <RefreshCw size={14} /> Poll once
            </button>

            {running ? (
              <button className="btn btn-secondary" onClick={handleStop} disabled={busy}>
                <Square size={14} /> Stop collection
              </button>
            ) : (
              <button
                className="btn btn-primary"
                onClick={handleStart}
                disabled={busy || unsupported}
              >
                <Play size={14} /> Start collection
              </button>
            )}
          </div>
        </div>

        {unsupported && (
          <div
            className="badge badge-warning"
            style={{ marginTop: "1rem", display: "block", padding: "0.75rem" }}
          >
            <AlertTriangle size={14} /> Live collection is unavailable on{" "}
            {status?.platform_name}. This source requires Windows.
          </div>
        )}

        {error && (
          <div
            className="badge badge-attack"
            style={{ marginTop: "1rem", display: "block", padding: "0.75rem" }}
          >
            <XCircle size={14} /> {error}
          </div>
        )}

        {status?.last_error && (
          <div
            className="badge badge-attack"
            style={{ marginTop: "1rem", display: "block", padding: "0.75rem" }}
          >
            <AlertTriangle size={14} /> Last collection error: {status.last_error}
          </div>
        )}
      </div>

      {/* ── Collection state ────────────────────────────────── */}
      <div className="stat-grid">
        <div className="glass-panel stat-card">
          <div className="stat-header">
            <span className="stat-label">Events Persisted</span>
            <Database className="stat-icon" size={18} />
          </div>
          <div className="stat-value">{fmtInt(status?.events_persisted_total, "0")}</div>
          <div className="stat-subtext">
            new rows this run · {fmtInt(eventTotal, "0")} stored all-time
          </div>
        </div>

        <div className="glass-panel stat-card blue">
          <div className="stat-header">
            <span className="stat-label">Last Successful Poll</span>
            <Activity className="stat-icon" size={18} style={{ color: "var(--accent-blue)" }} />
          </div>
          <div className="stat-value" style={{ fontSize: "var(--text-lg)" }}>
            {relativeSeconds(status?.last_success_at ?? null)}
          </div>
          <div className="stat-subtext">
            {status?.polls_succeeded ?? 0}/{status?.polls_attempted ?? 0} polls succeeded
          </div>
        </div>

        <div className="glass-panel stat-card emerald">
          <div className="stat-header">
            <span className="stat-label">Latest Observation</span>
            <CheckCircle
              className="stat-icon"
              size={18}
              style={{ color: "var(--accent-emerald)" }}
            />
          </div>
          <div className="stat-value" style={{ fontSize: "var(--text-lg)" }}>
            {relativeSeconds(status?.latest_event_observed_at ?? null)}
          </div>
          <div className="stat-subtext">Newest connection start time seen</div>
        </div>

        <div className="glass-panel stat-card rose">
          <div className="stat-header">
            <span className="stat-label">Collection Failures</span>
            <AlertTriangle
              className="stat-icon"
              size={18}
              style={{ color: "var(--accent-rose)" }}
            />
          </div>
          <div className="stat-value">{status?.polls_failed ?? 0}</div>
          <div className="stat-subtext">
            {status?.collection_gaps.length ?? 0} collection gap(s) recorded
          </div>
        </div>
      </div>

      {/* ── Ingestion accounting ────────────────────────────── */}
      <div className="glass-panel" style={{ padding: "1.25rem 1.5rem" }}>
        <h3 style={{ marginTop: 0 }}>
          Ingestion Accounting{" "}
          <span style={{ fontSize: "var(--text-2xs)", fontWeight: 400, color: "var(--text-dim)" }}>
            (this collector process)
          </span>
        </h3>
        <div style={{ color: "var(--text-dim)", fontSize: "var(--text-xs)", marginBottom: "0.75rem" }}>
          Every observed record falls into exactly one outcome, so{" "}
          <strong>observed = accepted + repeats + filtered + rejected</strong>.
        </div>
        {/* These counters and the stored-event total have different scopes,
            which previously looked like a discrepancy. */}
        <div
          style={{
            color: "var(--text-dim)",
            fontSize: "var(--text-2xs)",
            lineHeight: 1.7,
            marginBottom: "1rem",
            paddingLeft: "0.75rem",
            borderLeft: "2px solid var(--border-subtle)",
          }}
        >
          <strong>Scope:</strong> these totals accumulate since the server started and
          reset when it restarts. The <em>Events Persisted</em> card and{" "}
          <em>Source Health</em> count rows in the database across all time, so they
          are normally larger. A connection already stored from an earlier run is
          re-observed and re-accepted, but adds no new row — which is why{" "}
          <em>accepted</em> can exceed newly persisted events.
        </div>
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(150px, 1fr))",
            gap: "1rem",
          }}
        >
          {[
            ["Observed", status?.records_observed_total ?? 0, "var(--text-bright)",
              "Connection rows read from the Windows connection table across all polls."],
            ["Accepted", status?.events_accepted_total ?? 0, "#10b981",
              "Normalized into canonical events by this process."],
            ["Repeats suppressed", status?.duplicates_suppressed_total ?? 0, "#06b6d4",
              "Same still-open connection seen again on a later poll; not a new event."],
            ["Filtered (out of scope)", status?.records_filtered_by_policy_total ?? 0, "#94a3b8",
              "Excluded by collector policy (e.g. loopback-only). Not a defect."],
            ["Rejected (unusable)", status?.records_rejected_total ?? 0, "#f43f5e",
              "Failed validation — genuinely unusable data."],
          ].map(([label, value, color, help]) => (
            <div key={label as string} title={help as string}>
              <div style={{ fontSize: "var(--text-xl)", fontWeight: 600, color: color as string }}>
                {value as number}
              </div>
              <div style={{ fontSize: "var(--text-2xs)", color: "var(--text-dim)" }}>
                {label as string}
              </div>
            </div>
          ))}
        </div>

        {status && Object.keys(status.rejection_reasons).length > 0 && (
          <div style={{ marginTop: "1rem" }}>
            <div style={{ fontSize: "var(--text-2xs)", color: "var(--text-dim)", marginBottom: "0.4rem" }}>
              Rejection reasons
            </div>
            {Object.entries(status.rejection_reasons).map(([reason, count]) => (
              <div key={reason} style={{ fontSize: "var(--text-xs)" }}>
                <span className="badge badge-warning">{count}</span> {humanise(reason)}
              </div>
            ))}
          </div>
        )}

        {lastPoll && (
          <div
            style={{
              marginTop: "1rem",
              paddingTop: "1rem",
              borderTop: "1px solid var(--border-subtle)",
              fontSize: "var(--text-xs)",
            }}
          >
            <strong>Most recent manual poll</strong> ({fmtTime(lastPoll.polled_at)}): observed{" "}
            {lastPoll.records_observed}, accepted {lastPoll.events_accepted}, persisted{" "}
            {lastPoll.events_persisted}, repeats {lastPoll.duplicates_suppressed}, filtered{" "}
            {lastPoll.records_filtered_by_policy}, rejected {lastPoll.records_rejected}
          </div>
        )}
      </div>

      {/* ── Source health ───────────────────────────────────── */}
      {source && (
        <div className="glass-panel" style={{ padding: "1.25rem 1.5rem" }}>
          <h3 style={{ marginTop: 0 }}>Source Health</h3>
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fit, minmax(190px, 1fr))",
              gap: "0.9rem",
              fontSize: "var(--text-xs)",
            }}
          >
            <div>
              <div style={{ color: "var(--text-dim)" }}>Source ID</div>
              <div><code>{source.source_id}</code></div>
            </div>
            <div>
              <div style={{ color: "var(--text-dim)" }}>Collection method</div>
              <div><code>{source.source_type}</code></div>
            </div>
            <div>
              <div style={{ color: "var(--text-dim)" }}>Status</div>
              <div>{source.status}</div>
            </div>
            <div>
              <div style={{ color: "var(--text-dim)" }}>Events stored</div>
              <div>{source.event_count}</div>
            </div>
            <div>
              <div style={{ color: "var(--text-dim)" }}>Last event observed</div>
              <div>{fmtTime(source.last_event_at ?? null)}</div>
            </div>
            <div>
              <div style={{ color: "var(--text-dim)" }}>Poll interval</div>
              <div>{status?.interval_seconds}s</div>
            </div>
          </div>
        </div>
      )}

      {/* ── Collection gaps ─────────────────────────────────── */}
      {status && status.collection_gaps.length > 0 && (
        <div className="glass-panel" style={{ padding: "1.25rem 1.5rem" }}>
          <h3 style={{ marginTop: 0 }}>Collection Gaps</h3>
          <div style={{ color: "var(--text-dim)", fontSize: "var(--text-xs)", marginBottom: "0.75rem" }}>
            Periods with no successful collection. Connections that opened and closed
            inside a gap were never observed.
          </div>
          <div className="table-container">
            <table style={{ width: "100%", fontSize: "var(--text-xs)" }}>
              <thead>
                <tr>
                  <th style={{ textAlign: "left" }}>From</th>
                  <th style={{ textAlign: "left" }}>To</th>
                  <th style={{ textAlign: "right" }}>Duration</th>
                  <th style={{ textAlign: "left" }}>Reason</th>
                </tr>
              </thead>
              <tbody>
                {status.collection_gaps.slice(-10).reverse().map((g, i) => (
                  <tr key={i}>
                    <td>{fmtTime(g.gap_start)}</td>
                    <td>{fmtTime(g.gap_end)}</td>
                    <td style={{ textAlign: "right" }}>{fmtFixed(g.gap_seconds, 1)}s</td>
                    <td>{g.reason}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ── Domain enrichment status ────────────────────────── */}
      {enrichment && (
        <div className="glass-panel" style={{ padding: "1.25rem 1.5rem" }}>
          <h3 style={{ marginTop: 0 }}>Domain Attribution</h3>
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fit, minmax(170px, 1fr))",
              gap: "0.9rem",
              fontSize: "var(--text-xs)",
            }}
          >
            <div>
              <div style={{ color: "var(--text-dim)" }}>DNS observations stored</div>
              <div>{enrichment.total_observations_stored}</div>
            </div>
            <div>
              <div style={{ color: "var(--text-dim)" }}>Addresses with evidence</div>
              <div>{enrichment.distinct_ips_with_evidence}</div>
            </div>
            <div>
              <div style={{ color: "var(--text-dim)" }}>Last DNS snapshot</div>
              <div>{fmtTime(enrichment.last_refresh_at)}</div>
            </div>
            <div>
              <div style={{ color: "var(--text-dim)" }}>Evidence considered stale after</div>
              <div>{Math.round(enrichment.stale_after_seconds / 60)} min</div>
            </div>
          </div>

          {enrichment.cache_appears_unavailable && enrichment.diagnosis && (
            <div
              className="badge badge-warning"
              style={{ marginTop: "1rem", display: "block", padding: "0.75rem", lineHeight: 1.6 }}
            >
              <AlertTriangle size={14} /> {enrichment.diagnosis}
            </div>
          )}

          {/* Evidence-based explanation of WHY no DNS evidence exists here,
              gathered read-only from this host's resolver configuration. */}
          {dnsDiag && (
            <div
              style={{
                marginTop: "1rem",
                padding: "0.85rem 1rem",
                background: "rgba(0,0,0,0.2)",
                border: "1px solid var(--border-subtle)",
                borderRadius: "6px",
                fontSize: "var(--text-2xs)",
                lineHeight: 1.7,
              }}
            >
              <div style={{ fontWeight: 600, marginBottom: "0.4rem" }}>
                Why no DNS evidence is available here
              </div>
              <div style={{ color: "var(--text-dim)" }}>
                Cached DNS records visible: <strong>{String(dnsDiag.cache_entries ?? "—")}</strong>
                {" · "}DNS client service: <strong>{String(dnsDiag.dnscache_service ?? "—")}</strong>
                {Array.isArray(dnsDiag.active_resolvers) && dnsDiag.active_resolvers.length > 0 && (
                  <>
                    <br />
                    Configured resolvers: <strong>{dnsDiag.active_resolvers.join(", ")}</strong>
                  </>
                )}
                {Array.isArray(dnsDiag.resolvers_with_doh_auto_upgrade) &&
                  dnsDiag.resolvers_with_doh_auto_upgrade.length > 0 && (
                    <>
                      <br />
                      Set to auto-upgrade to DoH:{" "}
                      <strong style={{ color: "#f59e0b" }}>
                        {dnsDiag.resolvers_with_doh_auto_upgrade.join(", ")}
                      </strong>
                    </>
                  )}
                {/* Listed in Windows' well-known DoH table is NOT evidence of
                    DoH use; label it as such rather than implying a cause. */}
                {Array.isArray(dnsDiag.resolvers_in_known_doh_table) &&
                  dnsDiag.resolvers_in_known_doh_table.length > 0 &&
                  !dnsDiag.doh_auto_upgrade_enabled && (
                    <>
                      <br />
                      In Windows&apos; known-DoH-server table (auto-upgrade off, so
                      this does <em>not</em> indicate DoH was used):{" "}
                      <strong>{dnsDiag.resolvers_in_known_doh_table.join(", ")}</strong>
                    </>
                  )}
              </div>
              {Array.isArray(dnsDiag.likely_causes) && dnsDiag.likely_causes.length > 0 && (
                <ul style={{ margin: "0.6rem 0 0", paddingLeft: "1.1rem", color: "var(--text-dim)" }}>
                  {dnsDiag.likely_causes.map((c: string, i: number) => (
                    <li key={i}>{c}</li>
                  ))}
                </ul>
              )}
              {dnsDiag.conclusion && (
                <div style={{ marginTop: "0.6rem" }}>{String(dnsDiag.conclusion)}</div>
              )}
              <div style={{ marginTop: "0.5rem", color: "var(--text-dim)", fontStyle: "italic" }}>
                This check is read-only: no DNS setting was changed, no cache
                flushed, and no query sent.
              </div>
            </div>
          )}

          <ul
            style={{
              margin: "0.9rem 0 0",
              paddingLeft: "1.1rem",
              fontSize: "var(--text-2xs)",
              color: "var(--text-dim)",
              lineHeight: 1.7,
            }}
          >
            {enrichment.limitations.map((l, i) => (
              <li key={i}>{l}</li>
            ))}
          </ul>
        </div>
      )}

      {/* ── Observed connections ────────────────────────────── */}
      <div className="glass-panel" style={{ padding: "1.25rem 1.5rem" }}>
        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "baseline",
            flexWrap: "wrap",
            gap: "0.75rem",
          }}
        >
          <h3 style={{ marginTop: 0, marginBottom: 0 }}>
            Observed Connections{" "}
            <span style={{ fontSize: "var(--text-2xs)", color: "var(--text-dim)", fontWeight: 400 }}>
              (showing {returnedCount} of {eventTotal} stored)
            </span>
          </h3>
          <label
            style={{
              fontSize: "var(--text-2xs)",
              color: "var(--text-dim)",
              display: "flex",
              alignItems: "center",
              gap: "0.4rem",
            }}
            title="Reverse DNS names the owner of the IP address — often a CDN edge — not the site that was requested. It also sends DNS queries."
          >
            <input
              type="checkbox"
              checked={allowReverseDns}
              onChange={(e) => setAllowReverseDns(e.target.checked)}
            />
            Reverse DNS fallback (names IP owner only)
          </label>
        </div>

        {/* Filters */}
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(140px, 1fr))",
            gap: "0.6rem",
            margin: "1rem 0",
          }}
        >
          {[
            ["Host contains", filterHostname, setFilterHostname, "example.com"],
            ["Process contains", filterProcess, setFilterProcess, "msedge"],
            ["Destination IP", filterDstIp, setFilterDstIp, "93.184."],
            ["Port", filterPort, setFilterPort, "443"],
            ["State", filterState, setFilterState, "Established"],
          ].map(([label, value, setter, placeholder]) => (
            <label key={label as string} style={{ fontSize: "var(--text-2xs)", color: "var(--text-dim)" }}>
              {label as string}
              <input
                value={value as string}
                placeholder={placeholder as string}
                onChange={(e) => (setter as (v: string) => void)(e.target.value)}
                style={{
                  width: "100%",
                  marginTop: "0.25rem",
                  padding: "0.35rem 0.45rem",
                  background: "rgba(255,255,255,0.05)",
                  border: "1px solid var(--border-subtle)",
                  borderRadius: "4px",
                  color: "inherit",
                  fontSize: "var(--text-2xs)",
                }}
              />
            </label>
          ))}
        </div>

        {connections.length === 0 ? (
          <div
            style={{
              padding: "2rem",
              textAlign: "center",
              color: "var(--text-dim)",
              fontSize: "var(--text-xs)",
            }}
          >
            {eventTotal === 0
              ? unsupported
                ? "Live collection is not available on this platform."
                : 'No live telemetry collected yet. Use "Poll once" or "Start collection".'
              : "No connections match the current filters."}
          </div>
        ) : (
          <ConnectionTable connections={connections} />
        )}

        <div style={{ marginTop: "0.9rem", fontSize: "var(--text-2xs)", color: "var(--text-dim)", lineHeight: 1.7 }}>
          Click a row for full detail and evidence. <strong>TCP</strong> is the
          transport; a destination port does not establish which application
          protocol was used, and HTTP status codes are application-layer values
          that this source cannot observe.
        </div>
      </div>

      {/* ── Application-layer telemetry (separate from connections) ── */}
      <AppLayerPanel />

      {/* ── Honest capability limits ────────────────────────── */}
      <div className="glass-panel" style={{ padding: "1.25rem 1.5rem" }}>
        <h3 style={{ marginTop: 0, display: "flex", alignItems: "center", gap: "0.5rem" }}>
          <Info size={16} /> What This Source Can and Cannot See
        </h3>
        <div style={{ color: "var(--text-dim)", fontSize: "var(--text-xs)", marginBottom: "0.75rem" }}>
          These limits are reported by the collector itself. Fields this source cannot
          provide are stored as null and flagged, never estimated.
        </div>
        <ul style={{ margin: 0, paddingLeft: "1.2rem", fontSize: "var(--text-xs)", lineHeight: 1.75 }}>
          {(status?.capability_notes ?? []).map((note, i) => (
            <li key={i}>{note}</li>
          ))}
        </ul>
        {status && (
          <div
            style={{
              marginTop: "1rem",
              paddingTop: "0.9rem",
              borderTop: "1px solid var(--border-subtle)",
              fontSize: "var(--text-2xs)",
              color: "var(--text-dim)",
            }}
          >
            Collected TCP states: {status.collected_tcp_states.join(", ")}
            <br />
            Loopback-only connections:{" "}
            {status.include_loopback ? "included" : "excluded from collection scope"}
            <br />
            Data category: <strong>{humanise(status.data_category)}</strong> — kept distinct from
            historical imports, replays and test fixtures.
          </div>
        )}
      </div>
    </div>
  );
};
