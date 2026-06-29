import { describe, it, expect } from "vitest";
import { appRoutePaths, contextualRouteItems, navGroups, taskNavItems } from "@/lib/navigation";

const basePath = (to: string) => to.split("?")[0] || "/";

describe("U8-6 navigation & IA refresh", () => {
  it("renders task-based groups where every command resolves to one registered route and is RBAC-gated", () => {
    expect(navGroups.length).toBeGreaterThanOrEqual(5); // task-oriented groups

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
    expect(sidebarRoutes.length + taskNavItems.length).toBeLessThanOrEqual(24);

    // secondary command-center surfaces remain registered, labeled, and reachable
    // from page-local actions instead of taking permanent rail rows.
    const contextualRoutes = contextualRouteItems.map((item) => basePath(item.to));
    expect(contextualRoutes).toEqual(expect.arrayContaining(["/privacy", "/integrate", "/operations", "/notifications"]));
    for (const route of contextualRoutes) {
      expect(sidebarRoutes).not.toContain(route);
    }
  });
});
