import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { buildInitialRequestDraft, buildOperations, type OpenAPIDocument } from "@/pages/ApiExplorer";
import { apiWorkflowCoverage, type ApiWorkflowCoverage } from "@/lib/apiWorkflowCoverage";
import { appRoutePaths, contextualRouteItems, navGroups, realGuiSurfaces, taskNavItems } from "@/lib/navigation";

interface FeatureMapBacklog {
  items: Array<{
    feature_id: string;
    feature: string;
    current_frontend_mapping?: string;
    target_gui_mapping?: string;
    facet_evidence?: {
      ui?: {
        evidence?: string[];
        na?: string;
      };
    };
  }>;
}

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

const cover004FeatureIds = [
  "F5",
  "F13",
  "F22",
  "F23",
  "F24",
  "F25",
  "F30",
  "F43",
  "F44",
  "F45",
  "F51",
  "F55",
  "F61",
  "F63",
  "F65",
  "F67",
  "F68",
  "F75",
  "F76",
  "F77",
  "F78",
  "F79",
] as const;

const partialUiEvidencePattern =
  /\b(?:observe|basic|passive|thin|disclosure)\s*:|\b(?:api\/cli(?:\s+served)?|cli\/api|hand-?off|handoff|fixture|unavailable state|backend-gap|gap disclosure)\b/i;

function servedFeatureMap(): FeatureMapBacklog {
  for (const candidate of ["internal/featureparity/feature-map-backlog.json", "../internal/featureparity/feature-map-backlog.json"]) {
    try {
      return JSON.parse(readFileSync(candidate, "utf8")) as FeatureMapBacklog;
    } catch (err) {
      const code = typeof err === "object" && err !== null && "code" in err ? (err as { code?: string }).code : undefined;
      if (code !== "ENOENT") throw err;
    }
  }
  throw new Error("missing internal/featureparity/feature-map-backlog.json");
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

  it("keeps COVER-004 UI cells workflow-backed or explicitly non-UI", () => {
    const featureMap = new Map(servedFeatureMap().items.map((item) => [item.feature_id, item]));
    const surfaces = new Map(realGuiSurfaces.map((surface) => [surface.featureId, surface]));

    for (const featureId of cover004FeatureIds) {
      const item = featureMap.get(featureId);
      expect(item, `${featureId} must stay in feature-map-backlog`).toBeDefined();

      const ui = item?.facet_evidence?.ui;
      if (ui?.na) {
        expect(ui.na, `${featureId} UI N/A reason must be explicit`).toMatch(/^N\/A:/);
        expect(ui.evidence ?? [], `${featureId} UI N/A must not also claim route evidence`).toHaveLength(0);
        continue;
      }

      const surface = surfaces.get(featureId);
      expect(surface, `${featureId} must have a real GUI surface entry`).toBeDefined();
      expect(surface?.kind, `${featureId} GUI surface must be an operator workflow`).toBe("operate");
      expect(surface?.evidence ?? "", `${featureId} GUI surface evidence must not be partial`).not.toMatch(partialUiEvidencePattern);

      const evidence = [item?.current_frontend_mapping ?? "", item?.target_gui_mapping ?? "", ...(ui?.evidence ?? [])].filter(Boolean);
      expect(evidence.length, `${featureId} UI cell must cite concrete route evidence`).toBeGreaterThan(0);
      for (const value of evidence) {
        expect(value, `${featureId} UI evidence must not use partial labels`).not.toMatch(partialUiEvidencePattern);
      }
    }
  });

  it("rejects feature-map UI and a11y evidence for absent app routes", () => {
    execFileSync(process.execPath, [path.resolve(process.cwd(), "scripts/check-feature-map-route-evidence.mjs")], {
      cwd: process.cwd(),
      stdio: "pipe",
    });
  });

  it("keeps every served OpenAPI operation reachable from the API playground workflow", () => {
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

  it("builds an operator-owned draft for every served OpenAPI parameter and JSON body", () => {
    const spec = servedOpenAPI();
    const operations = buildOperations(spec);

    for (const operation of operations) {
      const draft = buildInitialRequestDraft(operation, spec);
      const parameters = (operation.operation.parameters ?? []).filter((parameter) => parameter.in !== "cookie");
      expect(Object.keys(draft.parameterValues), operation.key).toHaveLength(parameters.length);
      for (const parameter of parameters) {
        const value = draft.parameterValues[`${parameter.in}:${parameter.name}`];
        expect(value, `${operation.key} must expose ${parameter.in}:${parameter.name}`).toBeDefined();
        if (parameter.required || parameter.in === "path") expect(value, `${operation.key} must initialize required ${parameter.name}`).not.toBe("");
        if (!parameter.required && parameter.in === "query")
          expect(value, `${operation.key} must leave optional ${parameter.name} operator-controlled`).toBe("");
      }
      if (operation.operation.requestBody?.content?.["application/json"]) {
        expect(draft.bodyText, `${operation.key} must expose editable JSON`).not.toBe("");
      }
    }
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

    for (const entry of apiWorkflowCoverage as readonly ApiWorkflowCoverage[]) {
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
