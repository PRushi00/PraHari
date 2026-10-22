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

import React, { useCallback, useEffect, useState } from "react";
import { AlertTriangle, Download, Globe, RefreshCw } from "lucide-react";
import { api } from "../services/api";
import { DnsObservationsPage } from "../types";
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

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      setPage(await api.getDnsObservations({ method: method || undefined, limit: 200 }));
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, [method]);

  useEffect(() => {
    load();
  }, [load]);

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
        <div style={{ display: "flex", gap: "0.75rem" }}>
          <button className="btn btn-primary" onClick={collect} disabled={collecting}>
            <Download size={14} /> {collecting ? "Collecting…" : "Collect from event log"}
          </button>
          <button className="btn" onClick={load} disabled={loading}>
            <RefreshCw size={14} className={loading ? "spin" : ""} /> Refresh
          </button>
        </div>
      </div>

      {error && (
        <div className="status-banner status-error" role="alert">
          <AlertTriangle size={16} /> {error}
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
