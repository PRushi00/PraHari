import { describe, expect, it } from "vitest";
import { humanise, UNAVAILABLE } from "../utils/format";

/**
 * Labels versus identifiers (ADR-114).
 *
 * The rule this pins is a judgement, not a style preference: a value
 * that DESCRIBES a condition is prose and should read as prose, while
 * an identifier is a key the system matches on exactly and must keep
 * its spelling. Prettifying `windows_local_host` would put a second
 * spelling of one thing on screen, and an operator comparing the
 * dashboard with a config file or an API response would find no match.
 *
 * `humanise` is therefore applied only at call sites that render the
 * first kind. These tests pin its behaviour; the call sites are where
 * the judgement is exercised.
 */

describe("humanise", () => {
  it("turns an underscored condition into sentence case", () => {
    expect(humanise("timestamp_uncertainty")).toBe("Timestamp uncertainty");
    expect(humanise("live_telemetry")).toBe("Live telemetry");
    expect(humanise("historical_import")).toBe("Historical import");
    expect(humanise("never_reported")).toBe("Never reported");
  });

  it("uses sentence case, not Title Case", () => {
    // Title Case Reads As A Heading And Is Harder To Scan In A Table.
    expect(humanise("loopback_only_connection_out_of_scope")).toBe(
      "Loopback only connection out of scope",
    );
  });

  it("keeps the project's acronyms upper case", () => {
    expect(humanise("src_ip_missing")).toBe("Src IP missing");
    expect(humanise("dns_cache_empty")).toBe("DNS cache empty");
    expect(humanise("pr_auc")).toBe("PR AUC");
    expect(humanise("ddos")).toBe("DDOS");
  });

  it("handles hyphens and stray whitespace", () => {
    expect(humanise("source-limited")).toBe("Source limited");
    expect(humanise("  spaced   out  ")).toBe("Spaced out");
  });

  it("leaves an already-readable value alone apart from its case", () => {
    expect(humanise("Benign")).toBe("Benign");
    expect(humanise("reporting")).toBe("Reporting");
  });

  it("reports absence rather than rendering 'undefined'", () => {
    expect(humanise(undefined)).toBe(UNAVAILABLE);
    expect(humanise(null)).toBe(UNAVAILABLE);
    expect(humanise("")).toBe(UNAVAILABLE);
    expect(humanise("   ")).toBe(UNAVAILABLE);
    expect(humanise(42)).toBe(UNAVAILABLE);
    expect(humanise(undefined, "—")).toBe("—");
  });

  it("never throws on hostile input", () => {
    for (const v of [{}, [], true, Symbol("x"), () => 1]) {
      expect(() => humanise(v as unknown)).not.toThrow();
    }
  });
});
