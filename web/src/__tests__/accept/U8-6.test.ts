import { describe, it, expect } from "vitest";
import { appRoutePaths, contextualRouteItems, navGroups, taskNavItems } from "@/lib/navigation";

const basePath = (to: string) => to.split("?")[0] || "/";

describe("U8-6 navigation & IA refresh", () => {
  it("renders task-based groups where every command resolves to one registered route and is RBAC-gated", () => {
    // S-C1: tool-scoped groups across the six focused tools (the S-A1 four-band
    // era ended when the unified shell landed); S-C2 added the two Secrets
    // workspace groups. The certctl-informed carve adds a Machine
    // infrastructure group plus one overview each for Software Trust and Trust
    // Operations; route ownership remains unique.
    expect(navGroups.length).toBe(16);

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
    // H2 spent one row for the migration workspace. The product carve adds the
    // real Trust Operations overview and no duplicate destination. Ceiling: 40.
    // F64 adds one explicit application-secret workspace instead of mixing its
    // review/run contract into machine-login administration. Ceiling: 41.
    expect(sidebarRoutes.length + taskNavItems.length).toBeLessThanOrEqual(41);

    // S-A1 promoted the formerly-hidden surfaces into the rail; they are no
    // longer contextual-only.
    expect(contextualRouteItems).toEqual([]);
    for (const route of ["/privacy", "/integrate", "/operations", "/notifications", "/ca-hierarchy", "/ssh", "/codesign", "/profiles"]) {
      expect(sidebarRoutes).toContain(route);
    }
  });
});
