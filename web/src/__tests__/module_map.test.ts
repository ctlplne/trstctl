import { describe, it, expect } from "vitest";
import {
  appRoutePaths,
  globalBandRoutes,
  moduleForRoute,
  moduleLabelKey,
  navModules,
  navSpaces,
  permissionAnyForPath,
  realGuiSurfaces,
  spaceForRoute,
  surfaceModule,
  type ModuleId,
} from "@/lib/navigation";

/** module_map (S-B1, carried into the S-C1 spaces era): the space registry must
 * partition every customer route into exactly one place — a global plane OR a
 * single space — with no gaps and no overlaps. This is the guarantee the space
 * rail depends on and the permanent guard that keeps a route from silently
 * belonging to two spaces or none. */

// Routes that are neither global planes nor module-scoped (pre-auth, onboarding
// flow, dev-only styleguide).
const EXEMPT = new Set<string>(["/login", "/wizard", "/styleguide"]);

function basePath(to: string): string {
  return to.split("?")[0] || "/";
}

describe("module map (S-B1)", () => {
  it("assigns every customer route to exactly one of {global, one module}", () => {
    const global = new Set(globalBandRoutes);
    const problems: string[] = [];
    for (const route of appRoutePaths) {
      if (EXEMPT.has(route)) continue;
      const owningModules = navModules.filter((m) => m.routes.includes(route)).map((m) => m.id);
      const inGlobal = global.has(route);
      const placements = owningModules.length + (inGlobal ? 1 : 0);
      if (placements !== 1) {
        problems.push(`${route}: ${inGlobal ? "global" : ""}${owningModules.length ? ` modules[${owningModules.join(",")}]` : ""} (placements=${placements})`);
      }
    }
    expect(problems, `each route must be global XOR one module: ${problems.join("; ")}`).toEqual([]);
  });

  it("never lists the same route under two modules", () => {
    const seen = new Map<string, ModuleId>();
    for (const module of navModules) {
      for (const route of module.routes) {
        expect(seen.has(route), `${route} is claimed by both ${seen.get(route)} and ${module.id}`).toBe(false);
        seen.set(route, module.id);
      }
    }
  });

  it("keeps global and module route sets disjoint", () => {
    const global = new Set(globalBandRoutes);
    for (const module of navModules) {
      for (const route of module.routes) {
        expect(global.has(route), `${route} is both global and in module ${module.id}`).toBe(false);
      }
    }
  });

  it("resolves module ownership consistently through the helpers", () => {
    for (const module of navModules) {
      for (const route of module.routes) {
        expect(moduleForRoute(route)).toBe(module.id);
      }
    }
    for (const route of globalBandRoutes) {
      expect(moduleForRoute(route)).toBeUndefined();
    }
  });

  it("classifies every realGuiSurface route to a real module or global", () => {
    const validModules = new Set<string>(navModules.map((m) => m.id));
    for (const surface of realGuiSurfaces) {
      const resolved = surfaceModule(surface);
      expect(resolved === "global" || validModules.has(resolved), `${surface.featureId} → ${resolved}`).toBe(true);
      // Every route on the surface must be registered (no typos in the map).
      for (const route of surface.routes) {
        expect(appRoutePaths).toContain(basePath(route) as (typeof appRoutePaths)[number]);
      }
    }
  });

  it("pins the six focused tools without turning support configuration into a seventh product", () => {
    // Five existing persistence ids remain stable; Discover is the deliberate
    // addition because it is the front door to every credential domain.
    expect(navModules.length).toBe(6);
    expect(navModules.map((m) => m.id)).toEqual(["discovery", "certificates", "workload", "secrets", "posture", "platform"]);
    expect(navSpaces.map((space) => space.labelKey)).toEqual([
      "nav.space.discovery",
      "nav.module.certificates",
      "nav.space.workload",
      "nav.module.secrets",
      "nav.space.posture",
      "nav.space.platform",
    ]);
  });

  it("maps the stable routes into the six certctl-informed operator domains", () => {
    expect(moduleForRoute("/discovery")).toBe("discovery");
    expect(moduleForRoute("/certificates")).toBe("certificates");
    expect(moduleForRoute("/workloads")).toBe("workload");
    expect(moduleForRoute("/agents")).toBe("workload");
    expect(moduleForRoute("/secrets")).toBe("secrets");
    expect(moduleForRoute("/codesign")).toBe("posture");

    // Cross-domain risk, people, alerts, evidence, and system readiness have
    // one canonical home in Operations; discovery no longer hides there.
    for (const route of ["/trust-operations", "/risk", "/posture", "/incidents", "/operations", "/owners", "/notifications", "/audit", "/admin/system"]) {
      expect(moduleForRoute(route), route).toBe("platform");
    }
  });

  it("normalizes query links and fails closed for exempt or unknown routes", () => {
    expect(spaceForRoute("")).toBe("home");
    expect(spaceForRoute("/journeys?step=first")).toBe("home");
    expect(spaceForRoute("/certificates?expiry=30d")).toBe("certificates");
    expect(spaceForRoute("/login")).toBeUndefined();
    expect(spaceForRoute("/not-registered")).toBeUndefined();

    expect(moduleForRoute("/secrets/sync?status=failed")).toBe("secrets");
    expect(moduleForRoute("/not-registered")).toBeUndefined();
    expect(moduleLabelKey("discovery")).toBe("nav.space.discovery");
    expect(moduleLabelKey("workload")).toBe("nav.space.workload");
    expect(moduleLabelKey("not-a-space")).toBeUndefined();

    expect(permissionAnyForPath("/notifications?status=unread")).toContain("notifications:read");
    expect(permissionAnyForPath("")).toEqual(["certs:read", "identities:read", "risk:read"]);
    expect(permissionAnyForPath("/not-registered")).toBeUndefined();
  });

  it("honors an explicit surface owner before route-derived and global fallbacks", () => {
    expect(surfaceModule({ featureId: "F1", routes: [], component: "x", kind: "observe", evidence: "x", module: "platform" })).toBe("platform");
    expect(surfaceModule({ featureId: "F2", routes: ["/not-registered", "/ssh"], component: "x", kind: "observe", evidence: "x" })).toBe("workload");
    expect(surfaceModule({ featureId: "F3", routes: ["/not-registered"], component: "x", kind: "observe", evidence: "x" })).toBe("global");
  });
});
