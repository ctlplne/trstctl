import { describe, it, expect } from "vitest";
import { appRoutePaths, contextualRouteItems, navGroups, taskNavItems } from "@/lib/navigation";

const basePath = (to: string) => to.split("?")[0] || "/";

describe("U8-6 navigation & IA refresh", () => {
  it("renders task-based groups where every command resolves to one registered route and is RBAC-gated", () => {
    // S-A1: four question-shaped bands (Inventory / Issue & automate /
    // Detect & respond / Govern & administer).
    expect(navGroups.length).toBe(4);

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
    expect(sidebarRoutes.length + taskNavItems.length).toBeLessThanOrEqual(32);

    // S-A1 promoted the formerly-hidden surfaces into the rail; they are no
    // longer contextual-only.
    expect(contextualRouteItems).toEqual([]);
    for (const route of ["/privacy", "/integrate", "/operations", "/notifications", "/ca-hierarchy", "/ssh", "/codesign", "/profiles"]) {
      expect(sidebarRoutes).toContain(route);
    }
  });
});
