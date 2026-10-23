// DNS activity — the resolutions PraHari has recorded (§11, ADR-122).
//
// The data this surfaces has existed since ADR-120 and had nowhere to
// be seen. Three rules shape the page:
//
//   * **Every row carries its evidence source.** A hostname without
//     the address it resolved to and the method that produced it is not
//     evidence of anything, so none of the three is omitted.
//   * **An empty result is explained, not left blank.** "Nothing
//     collected" and "this host resolved nothing" are opposite claims
//     and look identical on screen.
//   * **The two evidence sources are never merged.** Cache and event
//     log are different kinds of evidence; they are filterable apart.

import React, { useCallback, useEffect, useRef, useState } from "react";
import { AlertTriangle, Download, Globe, Pause, Play, RefreshCw } from "lucide-react";
import { api } from "../services/api";
import { DnsCollectorStatus, DnsObservationsPage } from "../types";
import { Explain } from "../components/GuidedMode";
import { fmtTime, humanise } from "../utils/format";

const METHODS = [
  { value: "", label: "Any evidence source" },
  { value: "dns_query_log", label: "DNS event log" },
  { value: "dns_cache_observation", label: "DNS cache" },
];

export const DnsPage: React.FC = () => {
  const [page, setPage] = useState<DnsObservationsPage | null>(null);
  const [method, setMethod] = useState("");
  const [loading, setLoading] = useState(false);
  const [collecting, setCollecting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [collector, setCollector] = useState<DnsCollectorStatus | null>(null);
  const [busy, setBusy] = useState(false);
  const [updatedAt, setUpdatedAt] = useState<string | null>(null);
  /**
   * Guards against overlapping loads (ADR-127).
   *
   * The auto-refresh fires on a timer while collection runs. A slow
   * request must not have a second stacked behind it, and an in-flight
   * response arriving after a newer one would show stale rows.
   */
  const inFlight = useRef(false);
  const timer = useRef<number | null>(null);

  /**
   * Fetch observations.
   *
   * `quiet` is the auto-refresh path: it must not flip the page into a
   * loading state, because a spinner every few seconds over a table the
   * operator is reading is worse than no refresh at all.
   */
  const load = useCallback(
    async (quiet = false) => {
      if (inFlight.current) return;
      inFlight.current = true;
      if (!quiet) setLoading(true);
      try {
        const next = await api.getDnsObservations({
          method: method || undefined,
          limit: 200,
        });
        setPage(next);
        setUpdatedAt(new Date().toISOString());
        // A refresh that succeeds clears a stale failure banner; one
        // that fails below leaves the last good rows on screen.
        setError(null);
      } catch (e) {
        setError(e instanceof Error ? e.message : String(e));
      } finally {
        inFlight.current = false;
        if (!quiet) setLoading(false);
      }
    },
    [method],
  );

  const refreshStatus = useCallback(async () => {
    try {
      setCollector(await api.getDnsCollectorStatus());
    } catch {
      // The collector endpoint failing is not the page failing: the
      // stored observations are still worth showing.
      setCollector(null);
    }
  }, []);

  useEffect(() => {
    load();
    refreshStatus();
  }, [load, refreshStatus]);

  // Poll only while collection is actually running. A stopped collector
  // produces nothing new, so refreshing against it would be traffic
  // that cannot change the answer.
  useEffect(() => {
    if (timer.current) {
      window.clearInterval(timer.current);
      timer.current = null;
    }
    if (collector?.state === "running") {
      const ms = Math.max(2000, (collector.interval_seconds || 8) * 1000);
      timer.current = window.setInterval(() => {
        load(true);
        refreshStatus();
      }, ms);
    }
    return () => {
      if (timer.current) window.clearInterval(timer.current);
    };
  }, [collector?.state, collector?.interval_seconds, load, refreshStatus]);

  const toggleCollector = useCallback(async () => {
    setBusy(true);
    setError(null);
    try {
      const next =
        collector?.state === "running"
          ? await api.stopDnsCollector()
          : await api.startDnsCollector();
      setCollector(next);
      if (next.state !== "running" && next.last_error) setError(next.last_error);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }, [collector?.state]);

  const collect = useCallback(async () => {
    setCollecting(true);
    setError(null);
    setNotice(null);
    try {
      const res = (await api.collectDnsEvents()) as Record<string, unknown>;
      if (res.succeeded) {
        // Report what was read AND what was skipped. A count of stored
        // rows alone presents a partial read as a complete one.
        setNotice(
          `Read ${res.records_read} record(s); stored ${res.observations_recorded} ` +
            `new observation(s).` +
            (Number(res.skipped_failed_query) > 0
              ? ` ${res.skipped_failed_query} query/queries did not resolve.`
              : ""),
        );
        // Only reload on success: a refused collection changed nothing,
        // and `load()` clears the error banner, which would wipe the
        // reason the refusal exists to communicate.
        await load();
      } else {
        setError(String(res.error ?? "Collection did not succeed."));
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setCollecting(false);
    }
  }, [load]);

  const rows = page?.observations ?? [];

  return (
    <div className="page-container">
      <div className="page-header">
        <div>
          <h1 className="page-title">
            <Globe size={20} /> DNS Activity
          </h1>
          <p className="page-subtitle">
            Locally observed name resolutions, each with the evidence source
            that produced it.
          </p>
          <Explain>
            When a program on this machine looks up a name like{" "}
            <code>example.com</code>, the answer can sometimes be observed
            locally. These are the ones PraHari saw. It never sends a DNS query
            of its own.
          </Explain>
        </div>
        <div style={{ display: "flex", gap: "0.75rem", alignItems: "center" }}>
          {collector && (
            <button
              className={`btn ${collector.state === "running" ? "" : "btn-primary"}`}
              onClick={toggleCollector}
              disabled={busy || !collector.platform_supported}
              title={
                collector.platform_supported
                  ? "Poll the Windows DNS-Client channel continuously"
                  : `The DNS-Client channel is a Windows facility; this backend runs on ${collector.platform_name}.`
              }
            >
              {collector.state === "running" ? (
                <>
                  <Pause size={14} /> Stop collecting
                </>
              ) : (
                <>
                  <Play size={14} /> Collect continuously
                </>
              )}
            </button>
          )}
          <button className="btn" onClick={collect} disabled={collecting}>
            <Download size={14} /> {collecting ? "Collecting…" : "Collect once"}
          </button>
          {/* Manual refresh stays, as the fallback when nothing is
              polling — and as the way to re-read after a failure. */}
          <button className="btn" onClick={() => load()} disabled={loading}>
            <RefreshCw size={14} className={loading ? "spin" : ""} /> Refresh
          </button>
        </div>
      </div>

      {/* Collection state and when the view last changed. Without this
          a live page and a stuck one look identical. */}
      <div className="collector-bar">
        <span className={`pill ${collector?.state === "running" ? "pill-ok" : "pill-idle"}`}>
          <span
            className="status-dot"
            style={{
              backgroundColor:
                collector?.state === "running"
                  ? "#10b981"
                  : collector?.state === "error"
                  ? "#f43f5e"
                  : "#64748b",
            }}
          />
          {collector?.state === "running"
            ? `Collecting every ${collector.interval_seconds}s`
            : collector?.state === "unsupported"
            ? "Continuous collection unavailable on this platform"
            : collector?.state === "error"
            ? "Collection stopped after repeated failures"
            : "Not collecting"}
        </span>
        {updatedAt && (
          <span className="panel-meta">Observations updated {fmtTime(updatedAt)}</span>
        )}
        {collector?.last_success_at && (
          <span className="panel-meta">
            Last successful poll {fmtTime(collector.last_success_at)}
          </span>
        )}
        {collector && collector.bookmark > 0 && (
          <span
            className="panel-meta"
            title="The event-log RecordId last safely processed. It survives a restart, so collection resumes where it stopped."
          >
            bookmark #{collector.bookmark}
          </span>
        )}
      </div>

      {error && (
        <div className="status-banner status-error" role="alert">
          <AlertTriangle size={16} />
          <div>
            {error}
            {/* A failure to collect is not an empty host. Saying so
                stops a broken reader reading as a quiet network. */}
            <div className="banner-note">
              This is a collection failure, not a statement that this host
              resolved nothing.
            </div>
          </div>
        </div>
      )}

      {collector?.state === "unsupported" && (
        <div className="status-banner status-warn" role="status">
          <AlertTriangle size={16} />
          <div>
            <strong>Continuous collection needs Windows.</strong>
            <div className="banner-note">
              The DNS-Client Operational channel is readable only by a process
              on the Windows host itself, and this backend runs on{" "}
              {collector.platform_name}. Run PraHari on that machine, or give
              it a sensor agent — a remote backend cannot read another
              machine&apos;s event log.
            </div>
          </div>
        </div>
      )}
      {notice && (
        <div className="status-banner status-ok" role="status">
          {notice}
        </div>
      )}

      <section className="panel">
        <div className="form-row">
          <label>
            Evidence source
            <select
              className="form-select"
              value={method}
              onChange={(e) => setMethod(e.target.value)}
            >
              {METHODS.map((m) => (
                <option key={m.value} value={m.value}>
                  {m.label}
                </option>
              ))}
            </select>
          </label>
        </div>
        <p className="panel-note">
          The cache and the event log are different kinds of evidence and are
          never merged into one figure.
        </p>
      </section>

      {page && (
        <section className="panel">
          <div className="panel-header">
            <h3>
              {page.returned} of {page.total_stored} recorded resolution
              {page.total_stored === 1 ? "" : "s"}
            </h3>
          </div>

          {rows.length === 0 ? (
            // An empty store and a host that resolved nothing are
            // opposite claims. The backend's note distinguishes them.
            <p className="host-devices-empty">{page.note}</p>
          ) : (
            <>
              <div className="table-container">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Observed</th>
                      <th>Name</th>
                      <th>Resolved to</th>
                      <th>Evidence source</th>
                      <th>TTL</th>
                      <th>Collected by</th>
                    </tr>
                  </thead>
                  <tbody>
                    {rows.map((r) => (
                      <tr key={`${r.ip_address}|${r.hostname}|${r.observed_at}`}>
                        <td>{fmtTime(r.observed_at)}</td>
                        <td>{r.hostname}</td>
                        <td>
                          <code>{r.ip_address}</code>
                        </td>
                        <td>{humanise(r.method)}</td>
                        <td>
                          {r.ttl_seconds === null ? (
                            <span className="metric-unavailable">not reported</span>
                          ) : (
                            `${r.ttl_seconds}s`
                          )}
                        </td>
                        <td>
                          {r.source_id ? (
                            <code>{r.source_id}</code>
                          ) : (
                            <span className="metric-unavailable">unknown</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <p className="panel-note">{page.note}</p>
            </>
          )}
        </section>
      )}
    </div>
  );
};
