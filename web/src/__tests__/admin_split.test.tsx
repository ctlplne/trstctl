import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { axe } from "vitest-axe";
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
    authMethods: vi.fn().mockResolvedValue({ oidc: true, saml: false, ldap: false }),
    logout: vi.fn(),
    accessRoles: vi.fn(),
    oidcMappingStatus: vi.fn(),
    members: vi.fn(),
    apiTokens: vi.fn(),
    editions: vi.fn(),
    enterpriseSupportStatus: vi.fn(),
    managedOfferingStatus: vi.fn(),
    scaleOrchestration: vi.fn(),
    platformSystem: vi.fn(),
    tenantKeyDomain: vi.fn(),
    migrateTenantKeyDomain: vi.fn(),
    sealTenantKeyDomain: vi.fn(),
    unsealTenantKeyDomain: vi.fn(),
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
    apiMock.authMethods.mockResolvedValue({ oidc: true, saml: false, ldap: false });
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
    apiMock.platformSystem.mockResolvedValue({
      version: "test",
      commit: "test",
      build_date: "2026-07-31T00:00:00Z",
      go_version: "go1.26",
      started_at: "2026-07-31T00:00:00Z",
      uptime_seconds: 1,
      signer_mode: "child",
      fips_module_active: false,
      dependencies: [],
      idempotency_results: {
        state: "empty",
        fleet_ready: false,
        sealed_only_floor: false,
        raw_v0_remaining: 0,
        legacy_dynamic_remaining: 0,
        sealed_results: 0,
        pending_results: 0,
        indeterminate_results: 0,
        recovery: "upgrade the fleet",
      },
    });
    apiMock.tenantKeyDomain.mockResolvedValue({
      served: true,
      protection_mode: "legacy_deployment_kek",
      state: "legacy",
      progress_completed: 0,
      progress_total: 0,
      retryable: false,
      legacy_history_exposure: "hot_history_pending",
      last_transition_evidence_refs: [],
      local_wrapper_zero_egress: true,
      remote_wrapper_state: "disabled_in_core_local_custody",
      recovery: "Configure a local wrapper and migrate.",
    });
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

  it("operates tenant migration, confirmed seal, and unseal from the system console", async () => {
    apiMock.me.mockResolvedValue({
      subject: "custody-operator",
      tenant_id: "t1",
      email: "custody@example.test",
      permissions: ["access:read", "keys:read", "keys:write"],
    });
    const legacy = {
      served: true,
      protection_mode: "legacy_deployment_kek",
      state: "legacy",
      progress_completed: 0,
      progress_total: 0,
      retryable: false,
      legacy_history_exposure: "hot_history_pending",
      last_transition_evidence_refs: [],
      local_wrapper_zero_egress: true,
      remote_wrapper_state: "disabled_in_core_local_custody",
      recovery: "Configure a local wrapper and migrate.",
    };
    const partial = {
      ...legacy,
      protection_mode: "tenant_domain",
      state: "partial",
      wrapper_id: "tenant-a-custody",
      wrapper_kind: "local_file",
      operation_kind: "migrate",
      operation_status: "completed",
      progress_completed: 10,
      progress_total: 10,
      legacy_history_exposure: "external_archives_possible",
      last_transition_type: "tenant.key_domain.migration_completed",
      last_transition_evidence_refs: ["tenant-history://signed-continuity"],
      recovery: "Retire pre-migration archives.",
    };
    const sealed = {
      ...partial,
      state: "sealed",
      operation_kind: "seal",
      operation_status: "completed",
      recovery: "Use the configured wrapper to unseal.",
    };
    const unsealed = {
      ...sealed,
      state: "unsealed",
      operation_kind: "unseal",
      recovery: "Tenant-domain protection is available.",
    };
    apiMock.tenantKeyDomain.mockReset();
    apiMock.tenantKeyDomain.mockResolvedValueOnce(legacy).mockResolvedValueOnce(sealed);
    apiMock.migrateTenantKeyDomain.mockResolvedValue(partial);
    apiMock.sealTenantKeyDomain.mockResolvedValue({
      accepted: true,
      operation_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
      state: "seal_queued",
      status_url: "/api/v1/platform/tenant-key-domain",
    });
    apiMock.unsealTenantKeyDomain.mockResolvedValue(unsealed);

    const user = userEvent.setup();
    const view = renderAt("/admin/system");
    expect(await screen.findByRole("heading", { name: "Tenant cryptographic custody" })).toBeInTheDocument();
    expect(await screen.findByText("Deployment-key protected")).toBeInTheDocument();
    await user.type(screen.getByRole("textbox", { name: /Configured local wrapper ID/ }), "tenant-a-custody");
    await user.click(screen.getByRole("button", { name: "Start or resume migration" }));
    await waitFor(() => expect(apiMock.migrateTenantKeyDomain).toHaveBeenCalledWith({ wrapper_kind: "local_file", wrapper_id: "tenant-a-custody" }));
    expect(await screen.findByText("Hot state migrated")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Seal tenant crypto" }));
    const dialog = await screen.findByRole("alertdialog", { name: "Seal this tenant's cryptographic domain?" });
    expect(dialog).toContainElement(document.activeElement as HTMLElement);
    await user.keyboard("{Escape}");
    expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Seal tenant crypto" }));
    await user.click(within(screen.getByRole("alertdialog")).getByRole("button", { name: "Confirm seal" }));
    await waitFor(() => expect(apiMock.sealTenantKeyDomain).toHaveBeenCalledTimes(1));
    expect(await screen.findByText("Cryptographically sealed")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Unseal tenant crypto" }));
    await waitFor(() => expect(apiMock.unsealTenantKeyDomain).toHaveBeenCalledTimes(1));
    expect(await screen.findByText("Tenant domain available")).toBeInTheDocument();
    expect(await axe(view.container)).toHaveNoViolations();
  });

  it("renders a terminal seal failure as available, retryable custody truth", async () => {
    apiMock.me.mockResolvedValue({
      subject: "custody-operator",
      tenant_id: "t1",
      email: "custody@example.test",
      permissions: ["keys:read", "keys:write"],
    });
    apiMock.tenantKeyDomain.mockResolvedValue({
      served: true,
      protection_mode: "tenant_domain",
      state: "partial",
      wrapper_id: "tenant-a-custody",
      wrapper_kind: "local_file",
      progress_completed: 10,
      progress_total: 10,
      retryable: true,
      operation_kind: "seal",
      operation_status: "failed",
      failure: "Tenant seal worker exhausted its retry budget before the seal committed.",
      failure_code: "seal_delivery_exhausted",
      legacy_history_exposure: "external_archives_possible",
      last_transition_type: "tenant.key_domain.seal_failed",
      last_transition_evidence_refs: ["tenant-domain://crypto-remains-available"],
      local_wrapper_zero_egress: true,
      remote_wrapper_state: "disabled_in_core_local_custody",
      recovery: "Retry with a new Idempotency-Key; the exhausted key keeps replaying its receipt.",
    });
    const view = renderAt("/admin/system");
    expect(await screen.findByText("Tenant seal worker exhausted its retry budget before the seal committed.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Retry seal with a new request" })).toBeInTheDocument();
    expect(screen.getAllByText(/Retry with a new Idempotency-Key/)).toHaveLength(2);
    expect(await axe(view.container)).toHaveNoViolations();
  });
});
