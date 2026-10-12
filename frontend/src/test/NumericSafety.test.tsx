import { describe, expect, it } from "vitest";
import {
  UNAVAILABLE,
  fmtElapsed,
  fmtFixed,
  fmtInt,
  fmtPercent,
  fmtRelative,
  fmtTime,
  isNum,
  safeSeries,
} from "../utils/format";

/**
 * Regression tests for the two render-crash outages.
 *
 * Both were the same mistake: calling a numeric method directly on an API
 * field the backend does not return. `undefined.toFixed(2)` throws during
 * render, which blanked the page (and, before the error boundary existed,
 * the whole application).
 *
 * The central requirement is that these helpers never throw AND never
 * disguise a missing measurement as zero — "no bytes transferred" and
 * "this source cannot count bytes" are different facts.
 */

const ABSENT = [undefined, null, NaN, Infinity, -Infinity, "abc", {}, [], true];

describe("numeric formatting safety", () => {
  it("isNum accepts only finite numbers, including zero", () => {
    expect(isNum(0)).toBe(true);
    expect(isNum(-1.5)).toBe(true);
    for (const v of ABSENT) expect(isNum(v)).toBe(false);
  });

  it("fmtFixed never throws on absent or invalid input", () => {
    for (const v of ABSENT) {
      expect(() => fmtFixed(v, 2)).not.toThrow();
      expect(fmtFixed(v, 2)).toBe(UNAVAILABLE);
    }
  });

  it("fmtFixed renders a real zero as 0, not as unavailable", () => {
    // The distinction that matters: 0 is a measurement.
    expect(fmtFixed(0, 2)).toBe("0.00");
    expect(fmtFixed(0, 0)).toBe("0");
    expect(fmtInt(0)).toBe("0");
    expect(fmtPercent(0)).toBe("0.0%");
  });

  it("fmtInt and fmtPercent never throw", () => {
    for (const v of ABSENT) {
      expect(() => fmtInt(v)).not.toThrow();
      expect(() => fmtPercent(v)).not.toThrow();
      expect(fmtInt(v)).toBe(UNAVAILABLE);
      expect(fmtPercent(v)).toBe(UNAVAILABLE);
    }
  });

  it("fmtPercent converts ratios and respects alreadyPercent", () => {
    expect(fmtPercent(0.525)).toBe("52.5%");
    expect(fmtPercent(52.5, 1, { alreadyPercent: true })).toBe("52.5%");
  });

  it("fmtTime handles missing and unparseable timestamps", () => {
    expect(fmtTime(undefined)).toBe(UNAVAILABLE);
    expect(fmtTime(null)).toBe(UNAVAILABLE);
    expect(fmtTime("")).toBe(UNAVAILABLE);
    expect(fmtTime("not-a-date")).toBe(UNAVAILABLE);
    expect(fmtTime("2026-10-12T08:00:00Z", "—")).not.toBe("—");
  });

  it("fmtRelative handles missing timestamps", () => {
    expect(fmtRelative(undefined)).toBe(UNAVAILABLE);
    expect(fmtRelative("garbage")).toBe(UNAVAILABLE);
    expect(fmtRelative(new Date().toISOString())).toMatch(/ago|just now/);
  });

  it("fmtElapsed derives duration and refuses invalid ranges", () => {
    const start = "2026-10-12T08:00:00.000Z";
    const end = "2026-10-12T08:00:02.500Z";
    expect(fmtElapsed(start, end)).toBe("2.50s");
    // Missing either end -> unavailable, never a fabricated 0.
    expect(fmtElapsed(start, undefined)).toBe(UNAVAILABLE);
    expect(fmtElapsed(undefined, end)).toBe(UNAVAILABLE);
    expect(fmtElapsed("bad", end)).toBe(UNAVAILABLE);
    // End before start is not a real elapsed time.
    expect(fmtElapsed(end, start)).toBe(UNAVAILABLE);
  });

  it("safeSeries drops non-finite values so charts never receive NaN", () => {
    expect(safeSeries([1, NaN, 2, undefined, 3, null, Infinity])).toEqual([1, 2, 3]);
    expect(safeSeries([])).toEqual([]);
    // A single-point dataset stays usable.
    expect(safeSeries([5])).toEqual([5]);
  });

  it("reproduces the exact Stream & Replay failure shape safely", () => {
    // The endpoint returns an ImportSummary; the page previously read
    // duration_seconds and simulated_attack_ratio, which do not exist.
    const importSummary: Record<string, unknown> = {
      import_id: "abc",
      source_id: "synthetic_replay_engine",
      total_records: 200,
      accepted_records: 200,
      rejected_records: 0,
      started_at: "2026-10-12T08:00:00.000Z",
      completed_at: "2026-10-12T08:00:00.120Z",
    };

    // Old code: (undefined).toFixed(2) -> TypeError
    expect(() =>
      (importSummary.duration_seconds as number).toFixed(2)
    ).toThrow(TypeError);

    // New code: derived from real timestamps, never throws.
    expect(() =>
      fmtElapsed(importSummary.started_at, importSummary.completed_at)
    ).not.toThrow();
    expect(fmtElapsed(importSummary.started_at, importSummary.completed_at)).toBe("120ms");
    expect(fmtInt(importSummary.total_records)).toBe("200");
    expect(fmtInt(importSummary.rejected_records)).toBe("0");
  });

  it("reproduces the exact Feasibility failure shape safely", () => {
    const report: Record<string, unknown> = { overall_score: 0.525 };
    // Old code read overall_feasibility_score, which does not exist.
    expect(() =>
      (report.overall_feasibility_score as number).toFixed(1)
    ).toThrow(TypeError);
    expect(fmtPercent(report.overall_score)).toBe("52.5%");
    expect(fmtPercent(report.overall_feasibility_score)).toBe(UNAVAILABLE);
  });
});
