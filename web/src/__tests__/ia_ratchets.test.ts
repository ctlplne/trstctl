import { describe, it, expect } from "vitest";
import { readdirSync, readFileSync, existsSync } from "node:fs";
import path from "node:path";

/** S-R1: permanent ratchets that keep the defect classes this IA train fixed
 * from silently returning. These are source-level guards (they read the shipped
 * tree) plus a meta-check that the behavioural guards stay in CI. */

const SRC = path.resolve(process.cwd(), "src");

function walk(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) out.push(...walk(full));
    else if (/\.tsx?$/.test(entry.name)) out.push(full);
  }
  return out;
}

describe("IA ratchets (S-R1)", () => {
  it("keeps demo data out of every page except the demo-gated Dashboard (DA-01)", () => {
    const pages = walk(path.join(SRC, "pages"));
    const offenders: string[] = [];
    for (const file of pages) {
      if (path.basename(file) === "Dashboard.tsx") continue; // the only demo showcase, and it is useDemo-gated
      const src = readFileSync(file, "utf8");
      if (/from\s+["']@\/lib\/demoData["']/.test(src) || /\bdemoDashboard\b/.test(src)) {
        offenders.push(path.relative(SRC, file));
      }
    }
    expect(offenders, `these pages import demo data (real tenants must see served data only): ${offenders.join(", ")}`).toEqual([]);
  });

  it("keeps Dashboard's demo data strictly behind useDemo (DA-01/DA-12)", () => {
    const src = readFileSync(path.join(SRC, "pages", "Dashboard.tsx"), "utf8");
    // The demo dataset is referenced only via the `d` alias, and every render of
    // it is gated: the file must contain the useDemo gate and must not render
    // the demo trend/activity unconditionally.
    expect(src).toMatch(/const useDemo = preview/);
    // The demo dataset feeds KPIs only through the useDemo gate.
    expect(src).toMatch(/useDemo[\s\n]*\?[\s\n]*d\.kpis/);
    // The demo-only cards render behind {useDemo && …}.
    expect(src).toMatch(/\{useDemo && \(/);
    // Served readers exist (KPIs are wired, not stubbed zeros).
    expect(src).toMatch(/readOpenIncidents|openIncidents\.data/);
    expect(src).toMatch(/expiresWithinDays|servedAlgoMix/);
  });

  it("keeps the behavioural IA guards present in the test suite", () => {
    const tests = path.join(SRC, "__tests__");
    for (const guard of ["naming_parity.test.tsx", "nav_completeness.test.ts", "module_map.test.ts", "module_switcher.test.tsx"]) {
      expect(existsSync(path.join(tests, guard)), `${guard} guard is missing`).toBe(true);
    }
  });

  it("keeps every rail nav item pointing at a registered route (no orphan chrome)", async () => {
    const { navGroups, primaryNavItems, appRoutePaths } = await import("@/lib/navigation");
    const registered = new Set<string>(appRoutePaths);
    for (const item of [...primaryNavItems, ...navGroups.flatMap((g) => g.items)]) {
      const base = item.to.split("?")[0] || "/";
      expect(registered.has(base), `${item.to} is not a registered route`).toBe(true);
    }
  });
});
