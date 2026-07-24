import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { ThemeProvider } from "@/components/ThemeProvider";
import { AuthProvider } from "@/auth/AuthProvider";
import { AppRoutes } from "@/App";

/* C-A1 (07-closeout plan): /platform's tab grab-bag became three real routes.
 * This suite is the card's permanent guard: the redirects must keep every
 * historical /platform?tab= deep link working forever, and each route must
 * carry its own H1 (naming parity is asserted separately by naming_parity). */

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    me: vi.fn(),
    logout: vi.fn(),
    accessRoles: vi.fn(),
    oidcMappingStatus: vi.fn(),
    members: vi.fn(),
    apiTokens: vi.fn(),
    editions: vi.fn(),
    enterpriseSupportStatus: vi.fn(),
    managedOfferingStatus: vi.fn(),
    scaleOrchestration: vi.fn(),
    activeActiveIssuance: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
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

describe("C-A1 /admin split + permanent /platform redirects", () => {
  beforeEach(() => {
    for (const mock of Object.values(apiMock)) mock.mockReset();
    apiMock.me.mockResolvedValue({
      subject: "admin-1",
      tenant_id: "t1",
      email: "admin@example.test",
      permissions: ["access:read", "access:write", "certs:read", "identities:read", "risk:read"],
    });
    apiMock.accessRoles.mockResolvedValue({ items: [{ name: "operator", permissions: ["access:read"] }] });
    apiMock.oidcMappingStatus.mockResolvedValue({ enabled: false, tenant_mappings: [] });
    apiMock.members.mockResolvedValue({ items: [] });
    apiMock.apiTokens.mockResolvedValue({ items: [] });
    apiMock.editions.mockResolvedValue({
      tier: "community",
      state: "community",
      features: [{ name: "fips", tier: "enterprise", licensed: false, mode: "off" }],
      fips: { module_active: false, required: false, self_test_passed: true },
    });
    apiMock.enterpriseSupportStatus.mockResolvedValue({ served: true, support_mode: "off", support_tiers: [], sla_targets: [], professional_services: [] });
    apiMock.managedOfferingStatus.mockResolvedValue({ served: true, provider_plane_mode: "off" });
    apiMock.scaleOrchestration.mockResolvedValue({ served: false, execution_lanes: [], release_gates: [], target_credential_bands: [], residuals: [] });
    apiMock.activeActiveIssuance.mockResolvedValue({
      served: false,
      regions: [],
      tenant_write_fences: [],
      failover_runbook: [],
      release_gates: [],
      residuals: [],
    });
  });

  it("serves each /admin route under its own H1", async () => {
    const access = renderAt("/admin/access");
    expect(await screen.findByRole("heading", { level: 1, name: "Access administration" })).toBeInTheDocument();
    access.unmount();

    const system = renderAt("/admin/system");
    expect(await screen.findByRole("heading", { level: 1, name: "System posture" })).toBeInTheDocument();
    system.unmount();

    renderAt("/admin/editions");
    expect(await screen.findByRole("heading", { level: 1, name: "Editions & license" })).toBeInTheDocument();
  });

  it("redirects bare /platform to /admin/access", async () => {
    renderAt("/platform");
    expect(await screen.findByRole("heading", { level: 1, name: "Access administration" })).toBeInTheDocument();
  });

  it("redirects /platform?tab=posture to /admin/system", async () => {
    renderAt("/platform?tab=posture");
    expect(await screen.findByRole("heading", { level: 1, name: "System posture" })).toBeInTheDocument();
  });

  it("redirects /platform?tab=editions to /admin/editions", async () => {
    renderAt("/platform?tab=editions");
    expect(await screen.findByRole("heading", { level: 1, name: "Editions & license" })).toBeInTheDocument();
  });

  it("redirects an unknown /platform tab to /admin/access", async () => {
    renderAt("/platform?tab=nonsense");
    expect(await screen.findByRole("heading", { level: 1, name: "Access administration" })).toBeInTheDocument();
  });

  it("keeps editions and commercial framing off Access and System (S-A3 re-asserted per route)", async () => {
    const access = renderAt("/admin/access");
    await screen.findByRole("heading", { level: 1, name: "Access administration" });
    expect(screen.queryByRole("heading", { name: "Editions" })).not.toBeInTheDocument();
    expect(document.body.textContent).not.toMatch(/Upgrade to Enterprise|Contact sales/i);
    access.unmount();

    renderAt("/admin/system");
    await screen.findByRole("heading", { level: 1, name: "System posture" });
    expect(screen.queryByRole("heading", { name: "Editions" })).not.toBeInTheDocument();
    expect(document.body.textContent).not.toMatch(/Upgrade to Enterprise|Contact sales/i);
  });
});
