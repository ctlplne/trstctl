import { describe, expect, it } from "vitest";
import { appRoutePaths, contextualRouteItems, navGroups, taskNavItems } from "@/lib/navigation";
import { messages } from "@/i18n/messages";

function basePath(to: string): string {
  return to.split("?")[0] || "/";
}

describe("UX-03 task-based navigation", () => {
  it("keeps the sidebar compact and gives each grouped destination one row", () => {
    const groupedItems = navGroups.flatMap((group) => group.items.map((item) => ({ ...item, group: group.labelKey })));
    const allSidebarItems = [...taskNavItems, ...groupedItems];

    // S-A1: the rail now shows every product surface (no contextual-only
    // routes), grouped into four question-shaped bands. Budget tracks the
    // served IA: three urgency shortcuts plus the grouped destinations.
    // C-A1 split the /platform grab-bag into three question-shaped admin
    // rows (Access / System / Editions), consciously spending two more rows
    // of rail budget to kill the DA-13 grab-bag. New ceiling: 34.
    expect(allSidebarItems.length).toBeLessThanOrEqual(34);
    expect(navGroups.map((group) => messages[group.labelKey].defaultMessage)).toEqual([
      "Inventory",
      "Issue & automate",
      "Detect & respond",
      "Govern & administer",
    ]);

    const registered = new Set<string>(appRoutePaths);
    const groupedRouteCounts = new Map<string, string[]>();
    for (const item of groupedItems) {
      const route = basePath(item.to);
      if (!registered.has(route)) continue;
      groupedRouteCounts.set(route, [...(groupedRouteCounts.get(route) ?? []), messages[item.labelKey].defaultMessage]);
    }

    for (const [route, labels] of groupedRouteCounts) {
      expect(labels, `${route} should only have one grouped nav row`).toHaveLength(1);
    }

    // S-A1 promoted every former contextual route into the rail, so the
    // contextual list is now empty by design.
    expect(contextualRouteItems).toEqual([]);
  });
});
