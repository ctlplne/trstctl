import { describe, expect, it } from "vitest";
import { appRoutePaths, navGroups, realGuiSurfaces, type RealGuiSurface } from "@/lib/navigation";
import { featureCoverageItems } from "@/lib/featureCoverage";

const servedFeatureIds = featureCoverageItems.filter((item) => item.servedState === "served" || item.servedState === "conditional").map((item) => item.id);

function surfacesFor(featureId: string): RealGuiSurface[] {
  return realGuiSurfaces.filter((surface) => surface.featureId === featureId);
}

describe("route-level served-feature parity", () => {
  it("requires every feature-map row to declare explicit served maturity metadata", () => {
	expect(featureCoverageItems).toHaveLength(78);
	expect(featureCoverageItems.filter((item) => item.servedState === "served")).toHaveLength(31);
	expect(featureCoverageItems.filter((item) => item.servedState === "conditional")).toHaveLength(20);
	expect(featureCoverageItems.filter((item) => item.servedState === "partial")).toHaveLength(17);
	expect(featureCoverageItems.filter((item) => item.servedState === "library")).toHaveLength(10);
	expect(featureCoverageItems.filter((item) => item.servedState === "roadmap")).toHaveLength(0);

    const absentServedRows = featureCoverageItems
      .filter((item) => item.servedState === "library" || item.servedState === "roadmap")
      .filter((item) => !/(roadmap-disclosure|^disclosure:)/i.test(item.currentMapping));
    expect(absentServedRows).toEqual([]);
  });

  it("keeps /coverage as the ledger, not the replacement GUI workflow", () => {
    const coverageOnlyRows = featureCoverageItems
      .filter((item) => surfacesFor(item.id).length > 0)
      .filter((item) => /roadmap-disclosure:\s*\/coverage/i.test(item.currentMapping));
    expect(coverageOnlyRows.map((item) => item.id)).toEqual([]);
  });

  it("keeps every served feature ID tied to a non-ledger GUI route", () => {
    const backlogIds = new Set(featureCoverageItems.map((item) => item.id));
    const missingFromBacklog = servedFeatureIds.filter((featureId) => !backlogIds.has(featureId));
    expect(missingFromBacklog).toEqual([]);

    const missingSurface = servedFeatureIds.filter((featureId) => surfacesFor(featureId).length === 0);
    expect(missingSurface).toEqual([]);

    for (const featureId of servedFeatureIds) {
      const surfaces = surfacesFor(featureId);
      expect(surfaces.some((surface) => surface.routes.some((route) => route !== "/coverage"))).toBe(true);
      for (const surface of surfaces) {
        for (const route of surface.routes.filter((r) => !r.startsWith("/coverage"))) {
          expect(appRoutePaths).toContain(route as (typeof appRoutePaths)[number]);
        }
      }
    }
  });

  it("keeps grouped navigation attached to registered routes or explicit roadmap links", () => {
    const allItems = navGroups.flatMap((group) => group.items.map((item) => ({ ...item, group: group.labelKey })));
    expect(allItems.length).toBeGreaterThan(20);

    for (const item of allItems) {
      if (item.mode === "real") {
        expect(appRoutePaths).toContain(item.to as (typeof appRoutePaths)[number]);
      } else {
        expect(item.to).toMatch(/^\/coverage\?/);
      }
      expect(item.featureIds.length).toBeGreaterThan(0);
    }
  });
});
