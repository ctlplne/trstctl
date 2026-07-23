import { describe, it, expect } from "vitest";
import { readFileSync, existsSync } from "node:fs";
import path from "node:path";

/** S-R2: the user-facing docs must describe the shipped IA. The old S-A1-era
 * group labels must not appear in customer docs (historical audit files under
 * docs-internal/ are exempt). Vitest runs from web/, so docs live one level up. */

// Resolve docs whether tests run from web/ or the repo root.
function docsDir(): string {
  for (const candidate of ["../docs", "docs"]) {
    const abs = path.resolve(process.cwd(), candidate);
    if (existsSync(abs)) return abs;
  }
  throw new Error("could not locate docs/ directory");
}

const OLD_LABELS = ["Issue & renew", "Discover & inventory", "Monitor posture", "Approve & respond"];

const FILES = ["demo-click-through.html", "web-console.md", "features/platform-and-api.md"];

describe("docs IA parity (S-R2)", () => {
  const dir = docsDir();

  for (const file of FILES) {
    it(`${file} names no retired nav-group labels`, () => {
      const full = path.join(dir, file);
      if (!existsSync(full)) return; // doc optional in some checkouts
      const src = readFileSync(full, "utf8");
      const found = OLD_LABELS.filter((label) => src.includes(label) || src.includes(label.replace(/&/g, "&amp;")));
      expect(found, `${file} still references retired group labels: ${found.join(", ")}`).toEqual([]);
    });
  }

  for (const file of FILES.concat(["journeys/manage-secrets.md"])) {
    it(`${file} routes admin traffic to /admin/* and keeps no console dead-end copy (C-R1)`, () => {
      const full = path.join(dir, file);
      if (!existsSync(full)) return;
      const src = readFileSync(full, "utf8");
      // C-A1: the /platform tab query params are redirect legacy, not doc targets.
      expect(src.includes("/platform?tab="), `${file} still targets /platform?tab=`).toBe(false);
      // C-S4: the DA-02 dead-end phrasing may not reappear in operator docs.
      expect(src.includes("isn't in the console yet"), `${file} resurrects the console dead-end`).toBe(false);
    });
  }

  it("the demo click-through names the spaces shell and its groups", () => {
    const full = path.join(dir, "demo-click-through.html");
    if (!existsSync(full)) return;
    const src = readFileSync(full, "utf8");
    expect(src).toMatch(/Certificates &amp; PKI/);
    expect(src).toMatch(/Detect &amp; respond/);
    expect(src).toMatch(/Editions &amp; license/);
  });
});
