import { describe, it, expect } from "vitest";
import { navGroups, taskNavItems, appRoutePaths } from "@/lib/navigation";

const basePath = (to: string) => to.split("?")[0] || "/";

describe("U8-6 navigation & IA refresh", () => {
  it("renders task-based groups where every command resolves to one registered route and is RBAC-gated", () => {
    expect(navGroups.length).toBeGreaterThanOrEqual(5); // task-oriented groups

    const registered = new Set<string>(appRoutePaths);
    const sidebarItems = navGroups.flatMap((group) => group.items);
    const allItems = [...taskNavItems, ...sidebarItems];

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

    // the new command-center surfaces are present in the IA
    expect(sidebarRoutes).toContain("/privacy");
    expect(sidebarRoutes).toContain("/integrate");
  });
});
