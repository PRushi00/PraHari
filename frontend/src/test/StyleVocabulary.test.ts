import { describe, expect, it } from "vitest";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

/**
 * Every class the pages name must exist in the stylesheet (ADR-114).
 *
 * Thirty-six did not, used 190 times, and every other test passed
 * throughout: jsdom computes no cascade, so a missing rule is invisible
 * to `getByText`, and the real-browser session verifier asserts that a
 * page renders, not that it is legible. `System Health` rendered every
 * label/value pair as one run of text — "Deploymentlocal", "Uptime305s"
 * — for days.
 *
 * The stylesheet is read from disk rather than imported: vitest runs
 * with CSS processing off, so `import "../index.css?raw"` returns an
 * empty string and this check would pass against nothing.
 *
 * It is mechanical and claims nothing about appearance. It catches one
 * failure mode: a class that resolves to no rule at all.
 */

const SRC = join(dirname(fileURLToPath(import.meta.url)), "..");

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
 * Class names written as a literal `className`. A template literal has
 * its `${...}` holes blanked first: `badge-${state}` contributes the
 * dead stem `badge-`, which is not a class anyone wrote, so a trailing
 * hyphen is dropped rather than asserted on.
 */
function classesUsed(): Set<string> {
  const used = new Set<string>();
  for (const file of tsxFiles(SRC)) {
    const text = readFileSync(file, "utf8");
    const pattern = /className=(?:"([^"]*)"|\{`([^`]*)`\})/g;
    for (const match of text.matchAll(pattern)) {
      const raw = (match[1] ?? match[2] ?? "").replace(/\$\{[^}]*\}/g, " ");
      for (const name of raw.split(/\s+/)) {
        if (!name || name.endsWith("-")) continue;
        used.add(name);
      }
    }
  }
  return used;
}

describe("stylesheet vocabulary", () => {
  it("defines every class the application names", () => {
    const css = readFileSync(join(SRC, "index.css"), "utf8");
    const defined = new Set(
      [...css.matchAll(/\.([a-zA-Z][\w-]*)/g)].map((m) => m[1]),
    );

    const missing = [...classesUsed()]
      .filter((name) => !defined.has(name))
      .sort();

    expect(missing, `undefined in index.css: ${missing.join(", ")}`).toEqual([]);
  });

  it("reads a stylesheet and a set of pages, so an empty scan cannot pass", () => {
    // Without this, a file walk or a read that silently returns nothing
    // makes the assertion above vacuous — which is how it would fail open.
    expect(readFileSync(join(SRC, "index.css"), "utf8").length).toBeGreaterThan(5000);
    expect(classesUsed().size).toBeGreaterThan(40);
  });
});
