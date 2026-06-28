import { readFileSync } from "node:fs";
import path from "node:path";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { AuthProvider } from "@/auth/AuthProvider";
import { Platform } from "@/pages/Platform";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    me: vi.fn(),
    accessRoles: vi.fn(),
    oidcMappingStatus: vi.fn(),
    members: vi.fn(),
    editions: vi.fn(),
    enterpriseSupportStatus: vi.fn(),
    managedOfferingStatus: vi.fn(),
    provisionManagedTenant: vi.fn(),
    upsertMember: vi.fn(),
    offboardMember: vi.fn(),
    apiTokens: vi.fn(),
    createAPIToken: vi.fn(),
    logout: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});

function renderPlatform() {
  return render(
    <AuthProvider>
      <MemoryRouter>
        <Platform />
      </MemoryRouter>
    </AuthProvider>,
  );
}

describe("SIMP-01 Platform served-data reduction", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    for (const mock of Object.values(apiMock)) mock.mockReset();
    apiMock.me.mockResolvedValue({ subject: "access-admin", tenant_id: "tenant-admin", email: "access-admin@example.test" });
    apiMock.accessRoles.mockResolvedValue({
      items: [{ name: "access-admin", permissions: ["access:read", "access:write"] }],
    });
    apiMock.oidcMappingStatus.mockResolvedValue({
      enabled: true,
      tenant_claim: "tenant",
      groups_claim: "groups",
      claim_is_tenant: false,
      allow_default_tenant: false,
      tenant_mappings: [{ group: "access-admins", tenant_id: "tenant-admin", roles: ["access-admin"] }],
    });
    apiMock.members.mockResolvedValue({
      items: [
        {
          tenant_id: "tenant-admin",
          subject: "access-admin@example.test",
          roles: ["access-admin"],
          source: "oidc",
          status: "active",
          created_at: "2026-06-26T14:00:00Z",
          updated_at: "2026-06-26T14:01:00Z",
        },
      ],
    });
    apiMock.apiTokens.mockResolvedValue({
      items: [
        {
          id: "tok-admin",
          tenant_id: "tenant-admin",
          subject: "ops-automation",
          scopes: ["access:read"],
          created_at: "2026-06-26T14:02:00Z",
        },
      ],
    });
    apiMock.editions.mockResolvedValue({
      tier: "community",
      state: "community",
      features: [{ name: "fips", tier: "enterprise", licensed: false, mode: "off" }],
      fips: { module_active: false, required: false, self_test_passed: true },
    });
    apiMock.enterpriseSupportStatus.mockResolvedValue({
      served: true,
      capability: "CAP-MODEL-04",
      tier: "community",
      license_state: "community",
      support_mode: "off",
      license_feature: "ha_support",
      contract_boundary: "Commercial support terms control legal SLA credits and named contacts.",
      support_tiers: [
        {
          id: "business-hours",
          name: "Enterprise business-hours support",
          coverage: "Monday-Friday regional business hours",
          initial_response_sla: "P1: 4 hours",
          update_cadence_sla: "P1: every business day",
          escalation: "Named support engineer",
          license_mode: "off",
          contract_boundary: "Requires ha_support.",
        },
      ],
      sla_targets: [
        {
          severity: "P1",
          applies_to: "Production outage",
          initial_response_sla: "1 hour",
          update_cadence_sla: "Every 4 hours",
          target_restore: "Mitigation path",
          escalation: "Incident commander",
        },
      ],
      professional_services: [
        {
          id: "deployment-architecture",
          name: "Deployment architecture review",
          engagement_model: "Fixed-scope design review",
          deliverables: ["Topology review", "Readiness report", "Residual-risk backlog"],
        },
      ],
      evidence_refs: ["internal/api/enterprise_support.go"],
    });
    apiMock.managedOfferingStatus.mockResolvedValue({
      served: true,
      deployment_model: "managed_provider",
      tier: "community",
      license_state: "community",
      provider_plane_mode: "off",
      idempotency_required: true,
      event_type: "tenant.registered",
      mutation_path: "/api/v1/managed-offering/tenants",
    });
    apiMock.logout.mockResolvedValue(undefined);
  });

  it("keeps only served access-admin data plus session posture on Platform", async () => {
    renderPlatform();

    expect(await screen.findByRole("heading", { name: "Platform" })).toBeInTheDocument();
    await waitFor(() => expect(apiMock.accessRoles).toHaveBeenCalledTimes(1));
    expect(apiMock.oidcMappingStatus).toHaveBeenCalledTimes(1);
    expect(apiMock.members).toHaveBeenCalledWith({ includeOffboarded: true, limit: 50 });
    expect(apiMock.apiTokens).toHaveBeenCalledWith({ includeRevoked: true, limit: 50 });
    expect(apiMock.enterpriseSupportStatus).toHaveBeenCalledTimes(1);
    expect(apiMock.managedOfferingStatus).toHaveBeenCalledTimes(1);

    expect(screen.getByRole("heading", { name: "Tenant boundary" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Transport" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Auth session" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Managed offering" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Enterprise support" })).toBeInTheDocument();
    expect(screen.getByText("CAP-MODEL-04")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Access administration" })).toBeInTheDocument();
    expect(screen.getAllByText("access-admin").length).toBeGreaterThan(0);
    expect(screen.getByText("access-admins")).toBeInTheDocument();
    expect(screen.getAllByText("access-admin@example.test").length).toBeGreaterThan(0);
    expect(screen.getByText("ops-automation")).toBeInTheDocument();

    expect(screen.queryByRole("heading", { name: "API capability view" })).not.toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "CLI companion" })).not.toBeInTheDocument();
    expect(screen.queryByText("Required permission scopes by feature")).not.toBeInTheDocument();
    expect(document.body.textContent).not.toMatch(/trstctl-cli|OpenAPI|Capability view|API capability groups|Token-safe command/i);
    expect(document.body.textContent).not.toMatch(/certs:issue|graph:read|secrets:write|static capability|fixture|coming soon|not served yet/i);
  });

  it("removes the static Platform API, CLI, and scope-map fixtures from the module", () => {
    const source = readFileSync(path.join(process.cwd(), "src/pages/Platform.tsx"), "utf8");
    expect(source).not.toMatch(/const\s+requiredScopes|const\s+apiCapabilities|const\s+cliCommands/);
    expect(source).not.toMatch(/interface\s+ScopeRequirement|interface\s+APICapability/);
    expect(source).not.toMatch(/API capability view|CLI companion|Required permission scopes by feature|trstctl-cli/);
  });
});
