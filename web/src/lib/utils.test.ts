import { describe, expect, it } from "vitest";
import { cn } from "@/lib/utils";

/** S-C9 follow-up: the automated guard for the cn()/tailwind-merge contract.
 *
 * Stock tailwind-merge does not know the design-token font sizes, so before
 * the extendTailwindMerge fix it classified `text-caption` (and every other
 * token size) as an unknown text-COLOR utility and silently dropped it when a
 * real color utility followed through cn(). This suite pins the fix for every
 * token rung so a tailwind-merge upgrade or a config regression fails here —
 * not in a design review. Pixel-level rendering drift is separately checked by
 * the Playwright visual suite (web/e2e/visual.spec.ts), which is local-only:
 * baselines are recorded per machine and are never committed, so that suite is a
 * review aid rather than a CI guard. This one is the CI guard. */

const tokenSizes = ["text-2xs", "text-caption", "text-body", "text-title", "text-heading", "text-display"] as const;

const colorUtilities = ["text-muted-foreground", "text-brand-accent", "text-risk-critical", "text-sidebar-foreground/60", "text-status-success"] as const;

describe("cn() token-size merge contract (S-C9)", () => {
  for (const size of tokenSizes) {
    it(`keeps ${size} when a color utility follows`, () => {
      for (const color of colorUtilities) {
        const merged = cn(size, color);
        expect(merged, `${size} + ${color}`).toContain(size);
        expect(merged, `${size} + ${color}`).toContain(color);
      }
    });
  }

  it("keeps the size when base and extension both carry colors (the Eyebrow case)", () => {
    const merged = cn("text-caption font-semibold uppercase tracking-wide text-muted-foreground", "text-sidebar-foreground/60");
    expect(merged).toContain("text-caption");
    // The extension color wins the color conflict…
    expect(merged).toContain("text-sidebar-foreground/60");
    // …and the base color is correctly replaced, not duplicated.
    expect(merged).not.toContain("text-muted-foreground");
  });

  it("still resolves real font-size conflicts (last size wins)", () => {
    const merged = cn("text-caption", "text-body");
    expect(merged).toContain("text-body");
    expect(merged).not.toContain("text-caption");
  });

  it("still resolves stock-scale sizes against token sizes", () => {
    const merged = cn("text-sm", "text-caption");
    expect(merged).toContain("text-caption");
    expect(merged).not.toContain("text-sm");
  });
});
