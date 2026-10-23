// Connections — the Traffic Explorer (§11, ADR-122, ADR-124).
//
// What this page is careful about, and why:
//
//   * **Direction is an inference and says so.** The connection table
//     does not report who opened the socket. A column reading
//     "Outbound" is read as fact, so every value carries its method and
//     an `unknown` is rendered as a real answer rather than a blank.
//   * **`unknown` is filterable.** It is the set PraHari declined to
//     call, which is the set worth auditing — hiding it behind "no
//     filter" would make the declines invisible.
//   * **No bytes, no packets, no bandwidth** unless the record actually
//     carries them. The Windows connection table measures none of it,
//     and a column of blanks invites someone to fill it (ADR-118).
//   * **An empty table states which emptiness it is** (ADR-124). "No
//     row matches your filters", "nothing has ever been collected" and
//     "the source failed" are three different situations with three
//     different next actions, and they used to render identically.

import React, { useCallback, useEffect, useMemo, useState } from "react";
import {
  AlertTriangle,
  ChevronDown,
  ChevronRight,
  Filter,
  RefreshCw,
  SlidersHorizontal,
  X,
} from "lucide-react";
import { api } from "../services/api";
import {
  ConnectionDetail,
  PaginatedConnectionsResponse,
  TrafficDirection,
} from "../types";
import { Explain } from "../components/GuidedMode";
import { fmtTime, humanise } from "../utils/format";

const DIRECTIONS: { value: "" | TrafficDirection; label: string }[] = [
  { value: "", label: "Any direction" },
  { value: "outbound", label: "Outbound" },
  { value: "inbound", label: "Inbound" },
  { value: "local", label: "Local (loopback)" },
  { value: "unknown", label: "Unknown — not inferable" },
];

const DIRECTION_COLOUR: Record<TrafficDirection, string> = {
  outbound: "#38bdf8",
  inbound: "#f59e0b",
  local: "#a78bfa",
  unknown: "#94a3b8",
};

interface Filters {
  direction: string;
  dstIp: string;
  dstPort: string;
  protocol: string;
  process: string;
  hostname: string;
}

/** Rows per request. The API takes limit and offset; this uses both. */
const PAGE_SIZE = 50;

const EMPTY: Filters = {
  direction: "",
  dstIp: "",
  dstPort: "",
  protocol: "",
  process: "",
  hostname: "",
};

/** The direction cell: the verdict, and how it was reached. */
const DirectionCell: React.FC<{ record: ConnectionDetail }> = ({ record }) => {
  const assessment = record.direction;
  if (!assessment) {
    return <span className="metric-unavailable">not assessed</span>;
  }
  return (
    <span
      className="direction-cell"
      style={{ color: DIRECTION_COLOUR[assessment.direction] }}
      // The method and reason are the difference between a verdict and
      // a claim. They travel with the cell rather than a legend.
      title={`${assessment.reason}\n\nMethod: ${assessment.method}${
        assessment.limitations.length
          ? `\n\n${assessment.limitations.join("\n")}`
          : ""
      }`}
    >
      {humanise(assessment.direction)}
      {assessment.confidence === "inferred" && (
        <span className="cell-note">inferred</span>
      )}
      {assessment.confidence === "observed" && (
        <span className="cell-note">observed</span>
      )}
    </span>
  );
};

/** One connection, expanded: the fields that do not fit the row. */
const DetailRow: React.FC<{ record: ConnectionDetail; columns: number }> = ({
  record,
  columns,
}) => (
  <tr className="detail-row">
    <td colSpan={columns}>
      <dl className="detail-grid">
        <div>
          <dt>Event id</dt>
          <dd>
            <code>{record.event.event_id}</code>
          </dd>
        </div>
        <div>
          <dt>Evidence source</dt>
          <dd>{humanise(record.source_type)}</dd>
        </div>
        <div>
          <dt>Collected by</dt>
          <dd>
            <code>{record.event.source_id}</code>
          </dd>
        </div>
        <div>
          <dt>Connection state</dt>
          <dd>
            {record.connection_state ?? (
              <span className="metric-unavailable">not reported</span>
            )}
          </dd>
        </div>
        <div>
          <dt>Process id</dt>
          <dd>
            {record.process_id ?? (
              <span className="metric-unavailable">not reported</span>
            )}
          </dd>
        </div>
        <div>
          <dt>Direction method</dt>
          <dd>
            {record.direction ? (
              <>
                {humanise(record.direction.method)}
                {record.direction.confidence !== "none" && (
                  <> · {record.direction.confidence}</>
                )}
              </>
            ) : (
              <span className="metric-unavailable">not assessed</span>
            )}
          </dd>
        </div>
      </dl>

      {record.direction?.limitations?.length ? (
        <p className="detail-note">
          {record.direction.limitations.join(" · ")}
        </p>
      ) : null}
      {record.unsupported_fields?.length ? (
        <p className="detail-note">
          Not carried by this source: {record.unsupported_fields.join(", ")}.
        </p>
      ) : null}
      {record.source_limitations?.length ? (
        <p className="detail-note">{record.source_limitations.join(" · ")}</p>
      ) : null}
    </td>
  </tr>
);

export const TrafficPage: React.FC = () => {
  const [page, setPage] = useState<PaginatedConnectionsResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [filters, setFilters] = useState<Filters>(EMPTY);
  const [advancedOpen, setAdvancedOpen] = useState(false);
  const [offset, setOffset] = useState(0);
  const [expanded, setExpanded] = useState<string | null>(null);

  const active = useMemo(
    () =>
      (Object.keys(EMPTY) as (keyof Filters)[]).filter(
        (k) => filters[k] !== "",
      ),
    [filters],
  );

  const set = useCallback(
    (key: keyof Filters, value: string) =>
      setFilters((f) => ({ ...f, [key]: value })),
    [],
  );

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const result = await api.getConnections({
        direction: filters.direction || undefined,
        dst_ip: filters.dstIp || undefined,
        dst_port: filters.dstPort ? Number(filters.dstPort) : undefined,
        protocol: filters.protocol || undefined,
        process: filters.process || undefined,
        hostname: filters.hostname || undefined,
        limit: PAGE_SIZE,
        offset,
      });
      setPage(result);
    } catch (e) {
      // A failure is not an absence. Clearing the table here would
      // render a broken source as a quiet network.
      setPage(null);
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, [filters, offset]);

  // A filter change re-asks the question, so page 3 of the old answer
  // is not page 3 of the new one.
  useEffect(() => {
    setOffset(0);
  }, [filters]);

  useEffect(() => {
    load();
  }, [load]);

  const rows = page?.connections ?? [];
  const COLUMNS = 9;

  return (
    <div className="page-container">
      <div className="page-header compact">
        <div>
          <h1 className="page-title">
            <Filter size={18} /> Connections
          </h1>
          <p className="page-subtitle">
            Every stored connection, with the direction PraHari inferred and
            how it was decided.
          </p>
        </div>
        <button
          className="btn"
          onClick={load}
          disabled={loading}
          aria-label="Refresh connections"
        >
          <RefreshCw size={14} className={loading ? "spin" : ""} />{" "}
          {loading ? "Loading…" : "Refresh"}
        </button>
      </div>

      <Explain>
        One row per network connection PraHari has recorded. Direction is
        worked out from the port numbers rather than observed directly, so
        each value says how it was decided — hover it to see.
      </Explain>

      {/* A toolbar, not a form. The filters people reach for most sit on
          one line; the rest are behind a disclosure, because six empty
          boxes above an empty table made the filters look like the page. */}
      <div className="filter-bar">
        <label className="filter-field">
          <span className="filter-label">Direction</span>
          <select
            className="form-select"
            value={filters.direction}
            onChange={(e) => set("direction", e.target.value)}
          >
            {DIRECTIONS.map((d) => (
              <option key={d.value} value={d.value}>
                {d.label}
              </option>
            ))}
          </select>
        </label>

        <label className="filter-field grow">
          <span className="filter-label">Destination address</span>
          <input
            className="form-input"
            value={filters.dstIp}
            onChange={(e) => set("dstIp", e.target.value)}
            // No example address: a greyed-out 93.184.x reads as an
            // applied filter and sends people looking for a reset.
            placeholder="Any"
          />
        </label>

        <label className="filter-field">
          <span className="filter-label">Port</span>
          <input
            className="form-input"
            value={filters.dstPort}
            onChange={(e) => set("dstPort", e.target.value)}
            placeholder="Any"
            inputMode="numeric"
          />
        </label>

        <button
          className="btn btn-sm"
          onClick={() => setAdvancedOpen((v) => !v)}
          aria-expanded={advancedOpen}
        >
          <SlidersHorizontal size={14} /> More filters
          {active.length > 0 && <span className="filter-count">{active.length}</span>}
        </button>

        {active.length > 0 && (
          <button
            className="btn btn-sm"
            onClick={() => setFilters(EMPTY)}
            aria-label="Clear all filters"
          >
            <X size={14} /> Clear
          </button>
        )}
      </div>

      {advancedOpen && (
        <div className="filter-bar secondary">
          <label className="filter-field">
            <span className="filter-label">Protocol</span>
            <input
              className="form-input"
              value={filters.protocol}
              onChange={(e) => set("protocol", e.target.value)}
              placeholder="Any"
            />
          </label>
          <label className="filter-field">
            <span className="filter-label">Process</span>
            <input
              className="form-input"
              value={filters.process}
              onChange={(e) => set("process", e.target.value)}
              placeholder="Any"
            />
          </label>
          <label className="filter-field grow">
            <span className="filter-label">Attributed hostname</span>
            <input
              className="form-input"
              value={filters.hostname}
              onChange={(e) => set("hostname", e.target.value)}
              placeholder="Any"
            />
          </label>
          <p className="filter-note">
            <strong>Unknown is a direction value, not an absence.</strong> It
            selects the connections PraHari declined to call.
          </p>
        </div>
      )}

      {error && (
        <div className="status-banner status-error" role="alert">
          <AlertTriangle size={16} />
          <div>
            <strong>Could not load connections.</strong> {error}
            <div className="banner-note">
              This is a failure to read, not an empty network. Nothing can be
              concluded about traffic from this screen until it succeeds.
            </div>
          </div>
        </div>
      )}

      {loading && !page && (
        <div className="panel panel-state" role="status">
          Loading connections…
        </div>
      )}

      {page && (
        <section className="panel">
          <div className="panel-header tight">
            <h3>
              {page.total === 0
                ? "No connections stored"
                : active.length > 0
                ? `${page.returned} match${
                    page.returned === 1 ? "" : "es"
                  } on this page`
                : `${page.returned} of ${page.total} connection${
                    page.total === 1 ? "" : "s"
                  }`}
            </h3>
            {page.total > 0 && (
              <span className="panel-meta">
                {page.total} stored · page{" "}
                {Math.floor(offset / PAGE_SIZE) + 1} of{" "}
                {Math.max(1, Math.ceil(page.total / PAGE_SIZE))}
              </span>
            )}
          </div>

          {/* The backend applies these filters to the page it fetched,
              not to the whole store, and says so rather than reporting a
              match count it never computed. A match further down the
              store therefore appears on a later page, so the UI must not
              present this page's misses as the store's. */}
          {active.length > 0 && page.total > PAGE_SIZE && (
            <p className="panel-note">
              Filters apply to the {PAGE_SIZE} connections on this page.
              Matches elsewhere in the {page.total} stored appear on other
              pages.
            </p>
          )}

          {rows.length === 0 ? (
            // Three different emptinesses, three different next actions.
            <div className="empty-state">
              {active.length > 0 && page.total > 0 ? (
                <>
                  <p className="empty-title">
                    No connection on this page matches these filters.
                  </p>
                  <p className="empty-body">
                    {page.total} connection{page.total === 1 ? " is" : "s are"}{" "}
                    stored
                    {page.total > PAGE_SIZE
                      ? `; this page holds ${PAGE_SIZE} of them. Try the next page, or clear the filters.`
                      : ". None of them matches what you asked for."}
                  </p>
                  <button className="btn btn-primary btn-sm" onClick={() => setFilters(EMPTY)}>
                    <X size={14} /> Clear filters
                  </button>
                </>
              ) : (
                <>
                  <p className="empty-title">No telemetry has been collected yet.</p>
                  <p className="empty-body">
                    Nothing is stored, with or without filters. Start the
                    collector from <strong>Live Telemetry</strong> to record
                    this machine's own connections, or import a CSV.
                  </p>
                </>
              )}
            </div>
          ) : (
            <div className="table-container">
              <table className="data-table compact">
                <thead>
                  <tr>
                    <th aria-label="Expand" />
                    <th>Time</th>
                    <th>Direction</th>
                    <th>Source</th>
                    <th>Destination</th>
                    <th>Port</th>
                    <th>Protocol</th>
                    <th>Process</th>
                    <th>Hostname</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((r) => {
                    const open = expanded === r.event.event_id;
                    return (
                      <React.Fragment key={r.event.event_id}>
                        <tr>
                          <td>
                            <button
                              className="row-toggle"
                              aria-expanded={open}
                              aria-label={`Details for connection ${r.event.event_id}`}
                              onClick={() =>
                                setExpanded(open ? null : r.event.event_id)
                              }
                            >
                              {open ? (
                                <ChevronDown size={14} />
                              ) : (
                                <ChevronRight size={14} />
                              )}
                            </button>
                          </td>
                          <td>{fmtTime(r.event.observed_at)}</td>
                          <td>
                            <DirectionCell record={r} />
                          </td>
                          <td>
                            <code>{r.event.src_ip ?? "—"}</code>
                            {r.event.src_port ? `:${r.event.src_port}` : ""}
                          </td>
                          <td>
                            <code>{r.event.dst_ip ?? "—"}</code>
                          </td>
                          <td>{r.event.dst_port ?? "—"}</td>
                          <td>{r.event.protocol ?? "—"}</td>
                          <td>
                            {r.process_name ?? (
                              <span className="metric-unavailable">
                                not reported
                              </span>
                            )}
                          </td>
                          <td>
                            {r.domain_attribution?.hostname ? (
                              <>
                                {r.domain_attribution.hostname}
                                <div className="cell-note">
                                  {humanise(r.domain_attribution.method)} ·{" "}
                                  {r.domain_attribution.confidence}
                                </div>
                              </>
                            ) : (
                              <span className="metric-unavailable">unknown</span>
                            )}
                          </td>
                        </tr>
                        {open && <DetailRow record={r} columns={COLUMNS} />}
                      </React.Fragment>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}

          {page.total > PAGE_SIZE && (
            <div className="pager">
              <button
                className="btn btn-sm"
                onClick={() => setOffset((o) => Math.max(0, o - PAGE_SIZE))}
                disabled={offset === 0 || loading}
              >
                Previous
              </button>
              <span className="panel-meta">
                Page {Math.floor(offset / PAGE_SIZE) + 1} of{" "}
                {Math.ceil(page.total / PAGE_SIZE)} of stored connections
              </span>
              <button
                className="btn btn-sm"
                onClick={() => setOffset((o) => o + PAGE_SIZE)}
                // Paged over the store, so a page that filtered down to
                // nothing still has a next page to look at.
                disabled={offset + PAGE_SIZE >= page.total || loading}
              >
                Next
              </button>
            </div>
          )}

          {/* No bytes, packets or bandwidth columns. The Windows
              connection table measures none of them, and a column of
              blanks invites someone to fill it (ADR-118). */}
          <p className="panel-note">{page.enrichment_note}</p>
        </section>
      )}
    </div>
  );
};
