import { describe, expect, it } from "vitest";
import { canonicalCapabilities, canonicalCapabilityIDs } from "@/lib/feature-contracts.gen";
import { appRoutePaths, realGuiSurfaces } from "@/lib/navigation";

function basePath(route: string): string {
  return route.split("?")[0] || "/";
}

describe("bidirectional capability parity", () => {
  const contracts = new Map(canonicalCapabilities.map((capability) => [capability.featureId, capability]));
  const surfaces = new Map(realGuiSurfaces.map((surface) => [surface.featureId, surface]));
  const routes = new Set<string>(appRoutePaths);

  it("keeps every canonical console destination on a registered route", () => {
    for (const capability of canonicalCapabilities) {
      expect(routes.has(basePath(capability.contract.consoleRoute)), `${capability.featureId} points to an absent console route`).toBe(true);
    }
  });

  it("gives every primary capability one truthful real GUI surface", () => {
    const routeMismatches: string[] = [];
    for (const capability of canonicalCapabilities) {
      if (capability.contract.classification !== "primary") continue;
      const surface = surfaces.get(capability.featureId);
      expect(surface, `${capability.featureId} is primary but has no real GUI surface`).toBeDefined();
      if (!surface?.routes.map(basePath).includes(basePath(capability.contract.consoleRoute))) {
        routeMismatches.push(`${capability.featureId}: contract ${capability.contract.consoleRoute}; surface ${surface?.routes.join(", ")}`);
      }
    }
    expect(routeMismatches, `canonical routes disagree with their real GUI surfaces:\n${routeMismatches.join("\n")}`).toEqual([]);
  });

  it("rejects ghost UI: every visible surface belongs to the canonical backend catalog", () => {
    const canonicalIDs = new Set<string>(canonicalCapabilityIDs);
    for (const surface of realGuiSurfaces) {
      expect(canonicalIDs.has(surface.featureId), `${surface.featureId} is visible but has no canonical capability contract`).toBe(true);
      expect(contracts.has(surface.featureId)).toBe(true);
    }
  });

  it("proves the ghost-UI guard detects an injected unknown feature", () => {
    const canonicalIDs = new Set<string>(canonicalCapabilityIDs);
    const injected = [...realGuiSurfaces, { featureId: "F999", routes: ["/"], component: "Ghost", kind: "observe", evidence: "none" }];
    expect(injected.filter((surface) => !canonicalIDs.has(surface.featureId))).toHaveLength(1);
  });
});
