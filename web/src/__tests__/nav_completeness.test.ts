import { describe, expect, it } from "vitest";
import { appRoutePaths, contextualRouteItems, navGroups, primaryNavItems, realGuiSurfaces, taskNavItems } from "@/lib/navigation";

/** nav_completeness (S-A1, guards DA-04): every product surface a customer can
 * reach must be visible in the rail — no route may hide behind Cmd+K or an
 * in-page link only. This is the permanent regression guard that keeps whole
 * sub-products (CA hierarchy, Profiles, SSH trust, Code signing) from slipping
 * back out of navigation.
 *
 * Exemptions are the surfaces that are intentionally NOT permanent rail rows:
 *   /login    — pre-auth.
 *   /wizard   — onboarding flow, reached from the Dashboard empty-state CTA and
 *               Journeys (S-A1 removed its permanent "Set up" row).
 *   /styleguide — dev-only, never customer nav. */
const EXEMPT_ROUTES = new Set<string>(["/login", "/wizard", "/styleguide"]);

function basePath(to: string): string {
  return to.split("?")[0] || "/";
}

function railRoutes(): Set<string> {
  const routes = new Set<string>();
  for (const item of primaryNavItems) routes.add(basePath(item.to));
  for (const item of taskNavItems) routes.add(basePath(item.to));
  for (const group of navGroups) for (const item of group.items) routes.add(basePath(item.to));
  // contextualRouteItems is empty after S-A1, but include it so this guard keeps
  // holding if a future change reintroduces a contextual destination.
  for (const item of contextualRouteItems) routes.add(basePath(item.to));
  return routes;
}

describe("nav completeness (S-A1)", () => {
  it("makes every realGuiSurface route reachable from the rail", () => {
    const reachable = railRoutes();
    const missing: string[] = [];
    for (const surface of realGuiSurfaces) {
      for (const route of surface.routes) {
        const base = basePath(route);
        if (EXEMPT_ROUTES.has(base)) continue;
        if (!reachable.has(base)) missing.push(`${surface.featureId} → ${base}`);
      }
    }
    expect(missing, `these product surfaces are not visible in the rail: ${missing.join(", ")}`).toEqual([]);
  });

  it("keeps the space-scoped groups as the canonical structure (S-C1)", () => {
    expect(navGroups.map((group) => group.labelKey)).toEqual([
      // Certificates & PKI
      "nav.group.inventory",
      "nav.group.issueAutomate",
      // Secrets (S-C2: the workspaces are routes, grouped in the sidebar)
      "nav.group.secretsEngines",
      "nav.group.secretsAccess",
      "nav.group.secretsDelivery",
      // Workload & SSH
      "nav.group.workloadIdentity",
      "nav.group.sshTrust",
      // Posture & response
      "nav.group.detectRespond",
      // Platform
      "nav.group.governAdminister",
      "nav.group.infrastructure",
      "nav.group.integrations",
      "nav.group.adminConsole",
    ]);
  });

  it("no longer hides any customer route as contextual-only", () => {
    expect(contextualRouteItems).toEqual([]);
  });

  it("does not keep /wizard as a permanent rail row (onboarding is CTA-driven)", () => {
    const inRail = navGroups.some((group) => group.items.some((item) => basePath(item.to) === "/wizard"));
    expect(inRail).toBe(false);
    // But it stays a registered, navigable route.
    expect(appRoutePaths).toContain("/wizard");
  });
});
