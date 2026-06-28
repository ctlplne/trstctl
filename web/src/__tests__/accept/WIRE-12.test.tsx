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

describe("WIRE-12 Platform served admin surface", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    for (const mock of Object.values(apiMock)) mock.mockReset();
    apiMock.me.mockResolvedValue({ subject: "platform-admin", tenant_id: "tenant-platform", email: "admin@example.test" });
    apiMock.accessRoles.mockResolvedValue({
      items: [{ name: "platform-owner", permissions: ["access:read", "access:write"] }],
    });
    apiMock.oidcMappingStatus.mockResolvedValue({
      enabled: true,
      tenant_claim: "tenant",
      groups_claim: "groups",
      claim_is_tenant: false,
      allow_default_tenant: false,
      tenant_mappings: [{ group: "platform-admins", tenant_id: "tenant-platform", roles: ["platform-owner"] }],
    });
    apiMock.members.mockResolvedValue({
      items: [
        {
          tenant_id: "tenant-platform",
          subject: "admin@example.test",
          roles: ["platform-owner"],
          source: "oidc",
          status: "active",
          created_at: "2026-06-26T13:00:00Z",
          updated_at: "2026-06-26T13:01:00Z",
        },
      ],
    });
    apiMock.apiTokens.mockResolvedValue({
      items: [
        {
          id: "tok-platform",
          tenant_id: "tenant-platform",
          subject: "automation-client",
          scopes: ["access:read"],
          created_at: "2026-06-26T13:02:00Z",
        },
      ],
    });
    apiMock.editions.mockResolvedValue({
      tier: "enterprise",
      state: "active",
      customer: "Acme Robotics",
      license_id: "lic_test_editions",
      expires_at: "2026-12-31T00:00:00Z",
      features: [{ name: "fips", tier: "enterprise", licensed: true, mode: "enabled" }],
      fips: { module_active: false, required: false, self_test_passed: true },
    });
    apiMock.managedOfferingStatus.mockResolvedValue({
      served: true,
      deployment_model: "managed_provider",
      tier: "provider",
      license_state: "active",
      provider_plane_mode: "enabled",
      tenant_band: 100,
      idempotency_required: true,
      event_type: "tenant.registered",
      mutation_path: "/api/v1/managed-offering/tenants",
    });
    apiMock.logout.mockResolvedValue(undefined);
  });

  it("renders remaining Platform admin data from served access endpoints and hides unbacked status panels", async () => {
    renderPlatform();

    expect(await screen.findByRole("heading", { name: "Platform" })).toBeInTheDocument();
    await waitFor(() => expect(apiMock.accessRoles).toHaveBeenCalledTimes(1));
    expect(apiMock.oidcMappingStatus).toHaveBeenCalledTimes(1);
    expect(apiMock.members).toHaveBeenCalledWith({ includeOffboarded: true, limit: 50 });
    expect(apiMock.apiTokens).toHaveBeenCalledWith({ includeRevoked: true, limit: 50 });
    expect(apiMock.editions).toHaveBeenCalledTimes(1);
    expect(apiMock.managedOfferingStatus).toHaveBeenCalledTimes(1);

    expect(screen.getByText("tenant-platform")).toBeInTheDocument();
    expect(screen.getAllByText("platform-owner").length).toBeGreaterThan(0);
    expect(screen.getByText("platform-admins")).toBeInTheDocument();
    expect(screen.getAllByText("admin@example.test").length).toBeGreaterThan(0);
    expect(screen.getByText("automation-client")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Editions" })).toBeInTheDocument();
    expect(screen.getByText("ENTERPRISE")).toBeInTheDocument();
    expect(screen.getByText("Acme Robotics")).toBeInTheDocument();
    expect(screen.getByRole("row", { name: /fips enterprise Enabled/i })).toBeInTheDocument();
    expect(screen.getByText(/FIPS module inactive/i)).toBeInTheDocument();
    expect(screen.getByText(/self-test passed/i)).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Managed offering" })).toBeInTheDocument();
    expect(screen.getByText("managed_provider")).toBeInTheDocument();
    expect(screen.getByText("provider plane enabled")).toBeInTheDocument();

    expect(screen.queryByRole("heading", { name: "Single-binary runtime" })).not.toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Plugin SDK and capability sandbox" })).not.toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Cross-cluster federation" })).not.toBeInTheDocument();
    expect(document.body.textContent).not.toMatch(/Runtime status view|Plugin administration|Platform status view|Tenant switching|Live schema publication/i);
    expect(document.body.textContent).not.toMatch(/connector-f5\.wasm|unsigned plugin|replication worker|fixture|coming soon|not served yet/i);
  });

  it("removes the unserved Platform fixture arrays and unavailable-state disclosures", () => {
    const source = readFileSync(path.join(process.cwd(), "src/pages/Platform.tsx"), "utf8");
    expect(source).not.toMatch(/runtimeRows|pluginAdminRows|federationRows/);
    expect(source).not.toMatch(/UnavailableState/);
    expect(source).not.toMatch(/Upgrade to Enterprise|Contact sales|unlock/i);
    expect(source).not.toMatch(/Single-binary runtime|Plugin SDK and capability sandbox|Cross-cluster federation/);
    expect(source).not.toMatch(/Runtime status view coming soon|Plugin administration coming soon|Platform status view coming soon/);
  });
});
