// Network activity — connections per minute (ADR-125).
//
// Every point is counted from the `observed_at` of stored connections.
// Nothing is interpolated, smoothed or extrapolated: a minute with no
// record is plotted as zero because zero is what was recorded for it,
// and the axis only spans minutes the store actually covers.
//
// The window is the data's, not the clock's. "Last 30 minutes" over a
// store whose newest record is three days old would draw an empty chart
// and imply a quiet network, so the chart follows the records and says
// which window it drew.

import React, { useMemo } from "react";
import ReactECharts from "echarts-for-react";
import { Activity } from "lucide-react";
import { ConnectionDetail, TrafficDirection } from "../types";
import { fmtTime } from "../utils/format";

interface Props {
  connections: ConnectionDetail[];
  /** Records the store holds in total, to say what the chart covers. */
  totalStored: number;
  loading: boolean;
}

const MINUTE = 60_000;
/** Buckets drawn at most. Beyond this the line stops being readable. */
const MAX_BUCKETS = 40;

const SERIES_COLOUR: Record<string, string> = {
  outbound: "#38bdf8",
  inbound: "#f59e0b",
  local: "#a78bfa",
  unknown: "#64748b",
};

interface Bucket {
  minute: number;
  byDirection: Record<string, number>;
  total: number;
}

function bucketByMinute(connections: ConnectionDetail[]): Bucket[] {
  const times: { minute: number; direction: string }[] = [];
  for (const c of connections) {
    const t = new Date(c.event.observed_at).getTime();
    if (Number.isNaN(t)) continue; // an unparseable time is not a zero
    times.push({
      minute: Math.floor(t / MINUTE) * MINUTE,
      direction: (c.direction?.direction as TrafficDirection) ?? "unknown",
    });
  }
  if (times.length === 0) return [];

  const newest = Math.max(...times.map((x) => x.minute));
  const oldest = Math.min(...times.map((x) => x.minute));
  // Follow the records. Where they span more than the chart can show,
  // keep the most recent window rather than compressing the whole range.
  const start = Math.max(oldest, newest - (MAX_BUCKETS - 1) * MINUTE);

  const buckets = new Map<number, Bucket>();
  for (let m = start; m <= newest; m += MINUTE) {
    buckets.set(m, { minute: m, byDirection: {}, total: 0 });
  }
  for (const { minute, direction } of times) {
    const bucket = buckets.get(minute);
    if (!bucket) continue; // outside the drawn window
    bucket.byDirection[direction] = (bucket.byDirection[direction] ?? 0) + 1;
    bucket.total += 1;
  }
  return [...buckets.values()].sort((a, b) => a.minute - b.minute);
}

export const ActivityChart: React.FC<Props> = ({
  connections,
  totalStored,
  loading,
}) => {
  const buckets = useMemo(() => bucketByMinute(connections), [connections]);

  // Only directions actually present get a series. A flat zero line for
  // "inbound" on a store with none would read as a measurement.
  const directions = useMemo(() => {
    const seen = new Set<string>();
    for (const b of buckets) {
      for (const d of Object.keys(b.byDirection)) seen.add(d);
    }
    return [...seen].sort();
  }, [buckets]);

  const option = useMemo(
    () => ({
      backgroundColor: "transparent",
      tooltip: { trigger: "axis" },
      legend: {
        bottom: 0,
        textStyle: { color: "#94a3b8", fontSize: 12 },
        data: directions.map((d) => d[0].toUpperCase() + d.slice(1)),
      },
      grid: { left: "8%", right: "4%", top: "8%", bottom: "18%" },
      xAxis: {
        type: "category",
        boundaryGap: false,
        data: buckets.map((b) =>
          new Date(b.minute).toLocaleTimeString(undefined, {
            hour: "2-digit",
            minute: "2-digit",
          }),
        ),
        axisLabel: { color: "#94a3b8", fontSize: 11 },
        axisLine: { lineStyle: { color: "#334155" } },
      },
      yAxis: {
        type: "value",
        minInterval: 1, // connections are whole things
        axisLabel: { color: "#94a3b8", fontSize: 11 },
        splitLine: { lineStyle: { color: "rgba(51, 65, 85, 0.4)" } },
      },
      series: directions.map((d) => ({
        name: d[0].toUpperCase() + d.slice(1),
        type: "line",
        stack: "total",
        areaStyle: { opacity: 0.18 },
        smooth: false, // a smoothed line invents values between points
        symbol: "none",
        lineStyle: { width: 2 },
        itemStyle: { color: SERIES_COLOUR[d] ?? "#64748b" },
        data: buckets.map((b) => b.byDirection[d] ?? 0),
      })),
    }),
    [buckets, directions],
  );

  const covered = buckets.length;
  const counted = connections.length;

  return (
    <section className="panel">
      <div className="panel-header tight">
        <h3>
          <Activity size={16} /> Network activity
        </h3>
        {covered > 0 && (
          <span className="panel-meta">
            {/* fmtTime takes an ISO string; these are epoch millis. */}
            {fmtTime(new Date(buckets[0].minute).toISOString())} –{" "}
            {fmtTime(new Date(buckets[covered - 1].minute).toISOString())}
          </span>
        )}
      </div>

      {loading && buckets.length === 0 ? (
        <p className="panel-state">Counting connections…</p>
      ) : buckets.length === 0 ? (
        <div className="empty-state">
          <p className="empty-title">Nothing to plot.</p>
          <p className="empty-body">
            No stored connection carries a readable timestamp. This is a
            statement about the store, not about the network.
          </p>
        </div>
      ) : (
        <>
          <ReactECharts option={option} style={{ height: 240 }} notMerge />
          <p className="panel-note">
            Connections per minute, counted from {counted} stored record
            {counted === 1 ? "" : "s"}
            {totalStored > counted
              ? ` of ${totalStored} — the most recent are charted`
              : ""}
            . A minute with no record is plotted as zero because that is what
            was recorded for it. Direction is inferred, never observed.
          </p>
        </>
      )}
    </section>
  );
};
