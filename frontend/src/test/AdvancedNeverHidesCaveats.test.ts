import { describe, expect, it } from "vitest";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

/**
 * `<Advanced>` may defer dense diagnostics and nothing else (ADR-115).
 *
 * `GuidedMode.test.tsx` pins the two panels that matter today by
 * rendering them in both modes. That catches a regression in those two
 * and says nothing about the next panel someone wraps. This is the
 * general rule, enforced on the source: if a marker of a caveat appears
 * anywhere inside an `<Advanced>` block, the test names the file, the
 * marker and the panel.
 *
 * It is a text scan, so it is blunt in both directions: it cannot read
 * a caveat written in prose with none of these markers, and it will
 * object to a marker used innocently. The second is the better failure
 * — it forces the author to say why, here, in a comment or by moving
 * the panel out.
 */

const SRC = join(dirname(fileURLToPath(import.meta.url)), "..");

/**
 * Things that only ever appear where PraHari is reporting a limit, a
 * refusal, or an absence it will not paper over.
 */
const CAVEAT_MARKERS: { marker: string; why: string }[] = [
  { marker: "refusal_reason", why: "a refusal the backend issued" },
  { marker: "capability_notes", why: "what a source cannot see" },
  { marker: "collection_gaps", why: "periods where nothing was observed" },
  { marker: "not measured", why: "a reading that was never taken" },
  { marker: "badge-warning", why: "a warning badge" },
  { marker: "status-warn", why: "a warning banner" },
  { marker: "status-error", why: "an error banner" },
  { marker: 'role="alert"', why: "an element announced as an alert" },
  { marker: "metric-unavailable", why: "an unavailable measurement" },
  { marker: "not ground truth", why: "a label-provenance caveat" },
  { marker: "never estimated", why: "a statement about what is not inferred" },
];

function tsxFiles(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    const path = join(dir, entry);
    if (statSync(path).isDirectory()) {
      if (entry === "test") continue;
      out.push(...tsxFiles(path));
    } else if (entry.endsWith(".tsx")) {
      out.push(path);
    }
  }
  return out;
}

/**
 * The text inside each `<Advanced>…</Advanced>`, by nesting depth, so a
 * panel that itself contains one is handled rather than mis-sliced.
 */
function advancedBlocks(text: string): string[] {
  const blocks: string[] = [];
  const open = /<Advanced[\s>]/g;
  let match: RegExpExecArray | null;
  while ((match = open.exec(text)) !== null) {
    let depth = 0;
    let i = match.index;
    const start = i;
    while (i < text.length) {
      if (text.startsWith("</Advanced>", i)) {
        depth -= 1;
        if (depth === 0) {
          blocks.push(text.slice(start, i));
          break;
        }
        i += "</Advanced>".length;
        continue;
      }
      if (/<Advanced[\s>]/.test(text.slice(i, i + 10))) {
        depth += 1;
        i += "<Advanced".length;
        continue;
      }
      i += 1;
    }
  }
  return blocks;
}

describe("Advanced never hides a caveat", () => {
  it("contains no refusal, warning, limit or unavailability", () => {
    const offences: string[] = [];

    for (const file of tsxFiles(SRC)) {
      const text = readFileSync(file, "utf8");
      if (!text.includes("<Advanced")) continue;

      for (const block of advancedBlocks(text)) {
        // The opening tag's own title/summary is the beginner-facing
        // label, not deferred content.
        const body = block.slice(block.indexOf(">") + 1);
        for (const { marker, why } of CAVEAT_MARKERS) {
          if (body.includes(marker)) {
            offences.push(
              `${relative(SRC, file)}: <Advanced> defers ${marker} (${why})`,
            );
          }
        }
      }
    }

    expect(
      offences,
      `guided mode must not defer a caveat (ADR-115):\n  ${offences.join("\n  ")}`,
    ).toEqual([]);
  });

  it("actually found the Advanced panels, so an empty scan cannot pass", () => {
    // Without this, a walk that finds nothing — or a rename of the
    // component — makes the assertion above vacuous.
    const blocks = tsxFiles(SRC).flatMap((f) =>
      advancedBlocks(readFileSync(f, "utf8")),
    );
    expect(blocks.length).toBeGreaterThanOrEqual(2);
  });
});
