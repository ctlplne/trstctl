import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { buildOperations, type OpenAPIDocument } from "@/pages/ApiExplorer";
import { apiWorkflowCoverage } from "@/lib/apiWorkflowCoverage";
import { appRoutePaths, contextualRouteItems, navGroups, realGuiSurfaces, taskNavItems } from "@/lib/navigation";

function basePath(to: string): string {
  return to.split("?")[0] || "/";
}

function normalizeOpenAPIPath(path: string): string {
  return path.replace(/\{[^}]+\}/g, "{param}");
}

function servedOpenAPI(): OpenAPIDocument {
  for (const candidate of ["internal/api/testdata/openapi.golden.json", "../internal/api/testdata/openapi.golden.json"]) {
    try {
      return JSON.parse(readFileSync(candidate, "utf8")) as OpenAPIDocument;
    } catch (err) {
      const code = typeof err === "object" && err !== null && "code" in err ? (err as { code?: string }).code : undefined;
      if (code !== "ENOENT") throw err;
    }
  }
  throw new Error("missing internal/api/testdata/openapi.golden.json");
}

const auditedUnwrappedPaths = [
  "/api/v1/access/sessions",
  "/api/v1/access/sessions/{id}",
  "/api/v1/agents/{id}/cert-revocations",
  "/api/v1/ca/authorities",
  "/api/v1/ca/authorities/intermediates",
  "/api/v1/ca/authorities/roots",
  "/api/v1/ca/authorities/{id}/intermediates/csr",
  "/api/v1/ca/authorities/{id}/issue",
  "/api/v1/ca/authorities/{id}/rekey",
  "/api/v1/ca/ceremonies/{id}",
  "/api/v1/certificates/bulk-revoke",
  "/api/v1/certificates/{id}",
  "/api/v1/connectors/catalog",
  "/api/v1/connectors/deliveries",
  "/api/v1/connectors/deliveries/{id}",
  "/api/v1/connectors/outbox-circuits",
  "/api/v1/connectors/targets/{id}",
  "/api/v1/discovery/findings",
  "/api/v1/ephemeral",
  "/api/v1/ephemeral/{id}/approvals",
  "/api/v1/external-cas/{id}/issue",
  "/api/v1/identities/bulk-revoke",
  "/api/v1/identities/{id}",
  "/api/v1/identities/{id}/transitions",
  "/api/v1/issuers/{id}",
  "/api/v1/lifecycle/rotation-runs",
  "/api/v1/lifecycle/rotation-runs/{id}",
  "/api/v1/notifications/{id}",
  "/api/v1/owners/{id}",
  "/api/v1/privacy/subject-exports",
  "/api/v1/remediation/playbook-runs",
  "/api/v1/secrets/rotations",
  "/api/v1/secrets/scans/repositories",
  "/api/v1/secrets/scans/third-party",
] as const;

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

  it("rejects feature-map UI and a11y evidence for absent app routes", () => {
    execFileSync(process.execPath, [path.resolve(process.cwd(), "scripts/check-feature-map-route-evidence.mjs")], {
      cwd: process.cwd(),
      stdio: "pipe",
    });
  });

  it("keeps every served OpenAPI operation reachable from the API Explorer workflow", () => {
    const spec = servedOpenAPI();
    const expectedOperationKeys = Object.entries(spec.paths).flatMap(([path, pathItem]) =>
      Object.entries(pathItem)
        .filter(([, operation]) => Boolean(operation?.operationId))
        .map(([method]) => `${method}:${path}`),
    );
    const operationKeys = new Set(buildOperations(spec).map((operation) => operation.key));

    expect(operationKeys.size).toBe(expectedOperationKeys.length);
    for (const key of expectedOperationKeys) {
      expect(operationKeys.has(key)).toBe(true);
    }
    expect(appRoutePaths).toContain("/integrate/api");
  });

  it("documents every served path without a domain wrapper as a workflow or explicit exception", () => {
    const spec = servedOpenAPI();
    const servedPaths = new Set(
      Object.keys(spec.paths)
        .filter((path) => path.startsWith("/api/v1/"))
        .map(normalizeOpenAPIPath),
    );
    const coveragePaths = apiWorkflowCoverage.map((entry) => normalizeOpenAPIPath(entry.path));

    expect(new Set(coveragePaths).size).toBe(coveragePaths.length);
    for (const path of auditedUnwrappedPaths) {
      expect(coveragePaths).toContain(normalizeOpenAPIPath(path));
    }

    for (const entry of apiWorkflowCoverage) {
      expect(servedPaths.has(normalizeOpenAPIPath(entry.path))).toBe(true);
      expect(appRoutePaths).toContain(entry.route);
      expect(entry.owner).toMatch(/^SURFACE\//);
      expect(entry.workflow.length).toBeGreaterThan(8);
      expect(entry.rationale.length).toBeGreaterThan(40);
      if (entry.kind === "api-cli-exception") {
        expect(entry.route).toBe("/integrate/api");
      }
    }
  });
});
