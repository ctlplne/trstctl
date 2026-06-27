import { describe, expect, it } from "vitest";
import { appRoutePaths, navGroups, taskNavItems } from "@/lib/navigation";
import { messages } from "@/i18n/messages";

function basePath(to: string): string {
  return to.split("?")[0] || "/";
}

describe("UX-03 task-based navigation", () => {
  it("keeps the sidebar compact and gives each grouped destination one row", () => {
    const groupedItems = navGroups.flatMap((group) => group.items.map((item) => ({ ...item, group: group.labelKey })));
    const allSidebarItems = [...taskNavItems, ...groupedItems];

    // Budget grew from 22 to 24 with the uplift's two new command-center surfaces
    // (Privacy/GDPR console — U6-3, and the Integrate hub — U8-5/U8-6).
    expect(allSidebarItems.length).toBeLessThanOrEqual(24);
    expect(navGroups.map((group) => messages[group.labelKey].defaultMessage)).toEqual([
      "Issue & renew",
      "Discover & inventory",
      "Approve & respond",
      "Monitor posture",
      "Administer",
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
  });
});
