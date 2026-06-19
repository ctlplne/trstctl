import { describe, expect, it } from "vitest";
import {
  appRoutePaths,
  navGroups,
  realGuiSurfaces,
  type RealGuiSurface,
} from "@/lib/navigation";
import { featureCoverageItems } from "@/lib/featureCoverage";

const servedFeatureIds = [
  "F1",
  "F3",
  "F4",
  "F8",
  "F9",
  "F12",
  "F15",
  "F19",
  "F21",
  "F40",
  "F47",
  "F53",
  "F59",
];

function surfacesFor(featureId: string): RealGuiSurface[] {
  return realGuiSurfaces.filter((surface) => surface.featureId === featureId);
}

describe("route-level served-feature parity", () => {
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
    const allItems = navGroups.flatMap((group) => group.items.map((item) => ({ ...item, group: group.label })));
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
