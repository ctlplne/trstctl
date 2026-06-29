import { describe, expect, it } from "vitest";
import { appRoutePaths, contextualRouteItems, navGroups, realGuiSurfaces, taskNavItems } from "@/lib/navigation";

function basePath(to: string): string {
  return to.split("?")[0] || "/";
}

describe("route-level product surface parity", () => {
  it("does not register the internal coverage ledger as a customer route", () => {
    expect(appRoutePaths).not.toContain("/coverage");
    expect(realGuiSurfaces.some((surface) => surface.featureId === "F12")).toBe(false);

    const groupedRoutes = navGroups.flatMap((group) => group.items.map((item) => item.to));
    const taskRoutes = taskNavItems.map((item) => item.to);
    const contextualRoutes = contextualRouteItems.map((item) => item.to);
    const surfaceRoutes = realGuiSurfaces.flatMap((surface) => surface.routes);

    for (const route of [...groupedRoutes, ...taskRoutes, ...contextualRoutes, ...surfaceRoutes]) {
      expect(route).not.toMatch(/^\/coverage(?:\?|$)/);
    }
  });

  it("keeps every navigation command attached to a registered app route", () => {
    const registered = new Set<string>(appRoutePaths);
    const sidebarItems = navGroups.flatMap((group) => group.items);
    const allItems = [...taskNavItems, ...sidebarItems];

    expect(allItems.length).toBeGreaterThan(20);

    for (const item of allItems) {
      expect(registered.has(basePath(item.to))).toBe(true);
      expect(item.featureIds.length).toBeGreaterThan(0);
    }
    for (const item of sidebarItems) {
      expect(item.mode).toBe("real");
    }
  });

  it("keeps every contextual destination attached to a registered app route", () => {
    const registered = new Set<string>(appRoutePaths);

    for (const item of contextualRouteItems) {
      expect(registered.has(basePath(item.to))).toBe(true);
      expect(item.featureIds.length).toBeGreaterThan(0);
    }
  });

  it("keeps real GUI surface evidence on registered routes", () => {
    const registered = new Set<string>(appRoutePaths);

    for (const surface of realGuiSurfaces) {
      expect(surface.routes.length).toBeGreaterThan(0);
      for (const route of surface.routes) {
        expect(registered.has(basePath(route))).toBe(true);
      }
      expect(surface.evidence).toBeTruthy();
    }
  });
});
