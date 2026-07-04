import { cleanup, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { AppRoutes } from "@/App";
import { AuthProvider } from "@/auth/AuthProvider";
import { ThemeProvider } from "@/components/ThemeProvider";
import { journeySmokeMatrix, journeySmokePersonas, journeySmokeSteps, journeySmokeUiRoutes, type JourneySmokeCell } from "@/lib/journeyMatrix";
import { appRoutePaths } from "@/lib/navigation";

const { apiMock, clearApiCalls } = vi.hoisted(() => {
  const calls: Record<string, ReturnType<typeof vi.fn>> = {};
  const page = { items: [] };
  const generatedAt = "2026-07-03T00:00:00Z";

  function defaultResponse(name: string): unknown {
    if (name === "me") {
      return {
        subject: "journey-operator",
        tenant_id: "tenant-journey",
        email: "journey@example.test",
        roles: ["admin"],
        permissions: ["*"],
      };
    }
    if (["agents", "certificates", "externalCAs", "identities", "issuers", "owners", "profiles", "risk"].includes(name)) return [];
    if (
      [
        "accessChangeRequests",
        "apiTokens",
        "certificatePage",
        "complianceReportSchedules",
        "connectorDeliveries",
        "connectorTargets",
        "discoveryFindings",
        "discoveryRuns",
        "discoverySchedules",
        "discoverySources",
        "fleetReissuanceRuns",
        "incidentExecutions",
        "members",
        "notifications",
        "notificationChannels",
        "notificationRoutingPolicies",
        "nhiReviewCampaigns",
        "policyVersions",
        "privacyRetentionRuns",
        "privacySubjectErasures",
        "remediationPlaybookRuns",
        "rotationRuns",
        "secretPage",
      ].includes(name)
    ) {
      return page;
    }
    if (name === "nhiInventory") return { generated_at: generatedAt, items: [], summary: {}, coverage: [] };
    if (name === "ownershipAttribution") return { generated_at: generatedAt, items: [], summary: {}, coverage: [] };
    if (name === "nhiShadowPosture")
      return { capability: "CAP-NHI-05", generated_at: generatedAt, coverage: [], summary: {}, findings: [], recommended_actions: [] };
    if (name === "nhiPolicyCompliance") return { generated_at: generatedAt, coverage: [], summary: {}, items: [] };
    if (name === "nhiOverPrivilegePosture") return { generated_at: generatedAt, coverage: [], summary: {}, findings: [] };
    if (name === "nhiStalePosture") return { generated_at: generatedAt, coverage: [], summary: {}, findings: [] };
    if (name === "nhiStaticPosture") return { generated_at: generatedAt, coverage: [], summary: {}, findings: [] };
    if (name === "nhiExposurePosture") return { generated_at: generatedAt, coverage: [], summary: {}, findings: [] };
    if (name === "protocolStatuses") return { checked_at: generatedAt, items: [] };
    if (name === "acmeDNS01Providers") return page;
    if (name === "acmeDNS01ProviderConfigs") return page;
    if (name === "mdmSCEPStatus") return { served: true, policies: [] };
    if (name === "discoveryMonitoring") return { generated_at: generatedAt, summary: {}, sources: [] };
    if (name === "driftRemediation") return { generated_at: generatedAt, findings: [], summary: {} };
    if (name === "ctMonitoring") return { enabled: false, logs: [] };
    if (name === "listCBOMAssets") return { generated_at: generatedAt, items: [], summary: {}, migration_progress: {} };
    if (name === "graph") return { nodes: [], edges: [] };
    if (name === "graphBlastRadius") return { root: "", nodes: [], edges: [], summary: {} };
    if (name === "graphReachable") return { root: "", nodes: [], edges: [] };
    if (name === "connectorCatalog") return { items: [], capabilities: [] };
    if (name === "caDiscoveryInventory") return { generated_at: generatedAt, authorities: [], summary: {} };
    if (name === "complianceInventoryReport") return { generated_at: generatedAt, frameworks: [], evidence_refs: [] };
    if (name === "nhiComplianceReport") return { generated_at: generatedAt, summary: {}, controls: [] };
    if (name === "privacyCatalog") return { generated_at: generatedAt, items: [] };
    if (name === "editions") {
      return {
        tier: "community",
        state: "active",
        features: [],
        fips: { module_active: false, required: false, self_test_passed: true },
        packaging: {
          category_label: "self-hosted non-human identity management / Machine IAM control plane",
          billable_unit: "control_plane_deployment",
          provider_billing_unit: "managed_tenant_band",
          no_per_certificate_billing: true,
          no_ephemeral_identity_billing: true,
          editions: [],
          meters: [],
        },
      };
    }
    if (name === "enterpriseSupportStatus") return { served: true, capability: "CAP-MODEL-04", support_tiers: [], sla_targets: [] };
    if (name === "managedOfferingStatus") return { served: true, deployment_model: "self_hosted", tier: "community" };
    if (name === "scaleOrchestration") return { served: true, capability: "CAP-SCALE-01", target_credential_bands: [], release_gates: [] };
    if (name === "activeActiveIssuance") return { served: true, capability: "CAP-SCALE-02", topology: [], release_gates: [] };
    if (name === "kubernetesCSRSupport") return { capability: "CAP-K8S-04", served: true, rbac_rules: [], status_fields: [], evidence_refs: [] };
    if (name === "kubernetesTrustBundles") return { capability: "CAP-K8S-07", served: true, distribution_targets: [], rbac_rules: [], status_fields: [] };
    if (name === "workloadAttesterTrustSources") return page;
    if (name === "remediationPlaybooks") return { items: [] };
    if (name === "ownerRemediationActions") return { items: [], summary: { open: 0, accepted: 0 } };
    if (name === "auditEvents") return [];
    if (name === "logout") return undefined;
    return undefined;
  }

  const apiMock = new Proxy(calls, {
    get(target, prop) {
      if (typeof prop !== "string") return Reflect.get(target, prop);
      target[prop] ??= vi.fn(async () => defaultResponse(prop));
      return target[prop];
    },
  });

  return {
    apiMock,
    clearApiCalls: () => {
      for (const mock of Object.values(calls)) mock.mockClear();
    },
  };
});

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: apiMock };
});

function renderAt(path: string) {
  return render(
    <ThemeProvider>
      <AuthProvider>
        <MemoryRouter initialEntries={[path]}>
          <AppRoutes />
        </MemoryRouter>
      </AuthProvider>
    </ThemeProvider>,
  );
}

function keyFor(cell: Pick<JourneySmokeCell, "persona" | "step">): string {
  return `${cell.persona}:${cell.step}`;
}

describe("JOURNEY-004 full persona journey smoke", () => {
  beforeEach(() => {
    cleanup();
    clearApiCalls();
  });

  it("keeps a complete persona x lifecycle matrix with UI, API, CLI, docs, and acceptance evidence", () => {
    const byKey = new Map(journeySmokeMatrix.map((cell) => [keyFor(cell), cell]));
    const applicable = journeySmokeMatrix.filter((cell) => cell.status !== "not_applicable");

    expect(journeySmokePersonas).toHaveLength(6);
    expect(journeySmokeSteps).toEqual(["onboard", "discover", "issue", "rotate", "revoke", "offboard"]);
    expect(journeySmokeMatrix).toHaveLength(journeySmokePersonas.length * journeySmokeSteps.length);
    expect(applicable).toHaveLength(33);
    expect(byKey.get("ra_officer_requester:rotate")?.status).toBe("functional");
    expect(byKey.get("ra_officer_requester:rotate")?.cliCommands).toContain("trstctl-cli identities approve rotate");

    for (const persona of journeySmokePersonas) {
      for (const step of journeySmokeSteps) {
        const cell = byKey.get(`${persona.id}:${step}`);
        expect(cell, `${persona.id} ${step}`).toBeDefined();
        if (!cell || cell.status === "not_applicable") continue;
        expect(appRoutePaths).toContain(cell.uiRoute.split("?")[0] as (typeof appRoutePaths)[number]);
        expect(cell.apiPaths.length, `${persona.id} ${step} API coverage`).toBeGreaterThan(0);
        expect(cell.cliCommands.length, `${persona.id} ${step} CLI coverage`).toBeGreaterThan(0);
        expect(cell.docs.length, `${persona.id} ${step} docs coverage`).toBeGreaterThan(0);
        expect(cell.acceptance.length, `${persona.id} ${step} acceptance coverage`).toBeGreaterThan(0);
      }
    }
    expect(new Set(applicable.flatMap((cell) => cell.acceptance))).toEqual(new Set(["JOURNEY-001", "JOURNEY-002", "JOURNEY-003", "JOURNEY-004"]));
  });

  it("browser-drives every UI route named by the matrix through the authenticated shell", async () => {
    for (const route of journeySmokeUiRoutes) {
      cleanup();
      clearApiCalls();
      renderAt(route.path);
      expect(await screen.findByRole("heading", { name: route.heading })).toBeInTheDocument();
      expect(apiMock.me).toHaveBeenCalled();
    }
  });
});
