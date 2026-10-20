// The Events and Audit tables are headed "(UTC)" but rendered times with
// toLocaleString(): in India every row was 5 h 30 m off its own header
// (ADR-079). Found in a real browser during Windows validation.
import { describe, expect, it } from "vitest";

import { fmtTimeUtc } from "../utils/format";
import auditSrc from "../pages/AuditPage.tsx?raw";
import eventsSrc from "../pages/EventsPage.tsx?raw";

describe("fmtTimeUtc", () => {
  it("renders the instant in UTC, labelled", () => {
    expect(fmtTimeUtc("2026-10-17T08:20:09.468555Z")).toBe("2026-10-17 08:20:09 UTC");
  });

  it("normalises an offset timestamp to the same UTC instant", () => {
    expect(fmtTimeUtc("2026-10-17T13:50:09+05:30")).toBe("2026-10-17 08:20:09 UTC");
  });

  it("returns the fallback for missing or invalid input", () => {
    expect(fmtTimeUtc(null, "—")).toBe("—");
    expect(fmtTimeUtc("", "—")).toBe("—");
    expect(fmtTimeUtc("not a time", "—")).toBe("—");
  });
});

describe("a column headed UTC renders UTC", () => {
  it.each([
    ["EventsPage", eventsSrc],
    ["AuditPage", auditSrc],
  ])("%s does not format a (UTC) column with local time", (_name, src) => {
    expect(src).toContain("(UTC)");
    expect(src).not.toMatch(/\bfmtTime\(/);
    expect(src).toMatch(/\bfmtTimeUtc\(/);
  });
});
