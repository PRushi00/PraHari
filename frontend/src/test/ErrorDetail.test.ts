import { describe, expect, it, vi, afterEach } from "vitest";
import { api } from "../services/api";

/**
 * A refusal must arrive as words, not as JSON (ADR-124).
 *
 * The backend refuses some requests on purpose — importing a research
 * corpus into the operational database, for one — and says why and what
 * to do instead. That body was passed through `JSON.stringify`, so the
 * remedy reached the screen buried in braces and escaped quotes, which
 * is how a deliberate, explained refusal came to look like a glitch.
 */

function mockFetch(status: number, body: unknown) {
  vi.stubGlobal(
    "fetch",
    vi.fn().mockResolvedValue({
      ok: false,
      status,
      statusText: "Conflict",
      json: async () => body,
    }),
  );
}

afterEach(() => vi.unstubAllGlobals());

describe("backend refusals", () => {
  it("reads out the message and the remedy, not the JSON", async () => {
    mockFetch(409, {
      detail: {
        error: "research_import_into_operational_database",
        message: "Refusing to import data_category='historical_import'.",
        remedy: "Use POST /api/v1/research/import/csv instead.",
      },
    });

    await expect(api.getEventStats()).rejects.toThrow(
      /Refusing to import .* Use POST \/api\/v1\/research\/import\/csv instead\./,
    );
    await expect(api.getEventStats()).rejects.not.toThrow(/[{}"]/);
  });

  it("passes a plain string refusal through unchanged", async () => {
    mockFetch(404, { detail: "No such source." });
    await expect(api.getEventStats()).rejects.toThrow("No such source.");
  });

  it("joins the per-field messages of a validation error", async () => {
    mockFetch(422, {
      detail: [
        { loc: ["body", "limit"], msg: "must be positive", type: "value_error" },
        { loc: ["body", "source_id"], msg: "field required", type: "missing" },
      ],
    });
    await expect(api.getEventStats()).rejects.toThrow(
      "must be positive; field required",
    );
  });

  it("falls back to the status when the body explains nothing", async () => {
    mockFetch(500, { detail: { error: "boom" } });
    await expect(api.getEventStats()).rejects.toThrow("HTTP 500: Conflict");
  });
});
