import { describe, it, expect } from "vitest";
import { appRoutePaths, contextualRouteItems, navGroups, taskNavItems } from "@/lib/navigation";

const basePath = (to: string) => to.split("?")[0] || "/";

describe("U8-6 navigation & IA refresh", () => {
  it("renders task-based groups where every command resolves to one registered route and is RBAC-gated", () => {
    // S-C1: space-scoped groups across the five spaces (the S-A1 four-band
    // era ended when the unified shell landed); S-C2 added the two Secrets
    // workspace groups.
    expect(navGroups.length).toBe(12);

    const registered = new Set<string>(appRoutePaths);
    const sidebarItems = navGroups.flatMap((group) => group.items);
    const allItems = [...taskNavItems, ...sidebarItems, ...contextualRouteItems];

    for (const item of allItems) {
      expect(registered.has(basePath(item.to))).toBe(true); // route resolves
      expect(item.featureIds.length).toBeGreaterThan(0); // RBAC-gated by feature
    }
    for (const item of sidebarItems) {
      expect(item.mode).toBe("real");
    }

    // one label per route: no sidebar route is registered twice
    const sidebarRoutes = sidebarItems.map((item) => basePath(item.to));
    expect(new Set(sidebarRoutes).size).toBe(sidebarRoutes.length);

    expect(sidebarRoutes).toContain("/approvals");
    // Every product surface is now in the rail (no contextual-only routes), so
    // the budget grew from the old task-nav ceiling to the full IA.
    // C-A1 split the /platform grab-bag into three question-shaped admin
    // rows (Access / System / Editions), consciously spending two more rows
    // of rail budget to kill the DA-13 grab-bag. New ceiling: 34.
    // S-C2 spent five rows to give each Secrets workspace a route. Ceiling: 38.
    expect(sidebarRoutes.length + taskNavItems.length).toBeLessThanOrEqual(38);

    // S-A1 promoted the formerly-hidden surfaces into the rail; they are no
    // longer contextual-only.
    expect(contextualRouteItems).toEqual([]);
    for (const route of ["/privacy", "/integrate", "/operations", "/notifications", "/ca-hierarchy", "/ssh", "/codesign", "/profiles"]) {
      expect(sidebarRoutes).toContain(route);
    }
  });
});
