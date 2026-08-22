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
    usageEvidence: vi.fn(),
    migrateTenantKeyDomain: vi.fn(),
    sealTenantKeyDomain: vi.fn(),
    unsealTenantKeyDomain: vi.fn(),
    activeActiveIssuance: vi.fn(),
    platformDistribution: vi.fn(),
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
    apiMock.platformDistribution.mockResolvedValue({
      production_mode: "self_hosted",
      control_plane_lineage: "one binary lineage",
      offline_license_verifier: true,
      core_audit_and_export: true,
      run_modes: [],
      supported_host_archives: [],
      air_gap: {},
    });
  });

  it("serves each /admin route under its own H1", async () => {
    const access = renderAt("/admin/access");
    expect(await screen.findByRole("heading", { level: 1, name: "People and roles" })).toBeInTheDocument();
    access.unmount();

    const system = renderAt("/admin/system");
    expect(await screen.findByRole("heading", { level: 1, name: "System health" })).toBeInTheDocument();
    system.unmount();

    renderAt("/admin/editions");
    expect(await screen.findByRole("heading", { level: 1, name: "Plan and license" })).toBeInTheDocument();
  });

  it("redirects bare /platform to /admin/access", async () => {
    renderAt("/platform");
    expect(await screen.findByRole("heading", { level: 1, name: "People and roles" })).toBeInTheDocument();
  });

  it("redirects /platform?tab=posture to /admin/system", async () => {
    renderAt("/platform?tab=posture");
    expect(await screen.findByRole("heading", { level: 1, name: "System health" })).toBeInTheDocument();
  });

  it("redirects /platform?tab=editions to /admin/editions", async () => {
    renderAt("/platform?tab=editions");
    expect(await screen.findByRole("heading", { level: 1, name: "Plan and license" })).toBeInTheDocument();
  });

  it("answers plan and license first, guides safe installation, and defers expert evidence", async () => {
    apiMock.editions.mockResolvedValue({
      tier: "enterprise",
      state: "active",
      customer: "Acme Robotics",
      license_id: "lic_acme_01",
      expires_at: "2035-12-31T23:59:59Z",
      read_only_at: "2036-01-31T23:59:59Z",
      rights: ["self_host"],
      features: [
        { name: "governance", tier: "enterprise", licensed: true, mode: "enabled" },
        { name: "provider_plane", tier: "provider", licensed: false, mode: "off" },
      ],
      deployment_entitlement: {
        deployment_id: "acme-prod",
        environment: "production",
        production_units_consumed: 1,
        bundled_non_production_deployments: 3,
        registered_non_production_deployments: 1,
        non_production_slots_remaining: 2,
        legacy_unbound: false,
      },
      fips: { module_active: false, required: false, self_test_passed: true },
    });
    apiMock.activeActiveIssuance.mockResolvedValue({
      served: true,
      topology: "active-active",
      write_model: "tenant fenced",
      regions: [{ id: "region-a", region: "us-east", role: "primary", writable_scope: "tenant-a", health_signal: "healthy" }],
      tenant_write_fences: [],
      failover_runbook: [],
      release_gates: [],
      residuals: [],
    });
    const user = userEvent.setup();
    const view = renderAt("/admin/editions");

    expect(await screen.findByRole("heading", { level: 1, name: "Plan and license" })).toBeInTheDocument();
    expect(screen.getByText("Which features are enabled and when the signed license expires.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Add license" })).toBeInTheDocument();
    expect(await screen.findByRole("heading", { name: "Enterprise plan is active" })).toBeInTheDocument();
    expect(screen.getByText("Signed license verified at startup")).toBeInTheDocument();
    expect(screen.getByText("Signature verification", { exact: true })).toBeInTheDocument();
    expect(screen.getByText("Feature table", { exact: true })).toBeInTheDocument();
    expect(screen.getByText("Entitlement evidence", { exact: true })).toBeInTheDocument();
    expect(screen.queryByRole("table")).not.toBeInTheDocument();
    await waitFor(() => expect(apiMock.editions).toHaveBeenCalledTimes(1));
    expect(apiMock.activeActiveIssuance).not.toHaveBeenCalled();
    expect(apiMock.platformDistribution).not.toHaveBeenCalled();

    await user.click(screen.getByText("Signature verification", { exact: true }));
    expect(screen.getByText(/The UI cannot bypass it/i)).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Add license" }));
    const guide = await screen.findByRole("dialog", { name: "Add license" });
    expect(within(guide).getByText(/trstctl verifies the Ed25519 signature before startup completes/i)).toBeInTheDocument();
    expect(within(guide).getByText(/The browser never uploads or stores the license file/i)).toBeInTheDocument();
    expect(within(guide).getByText("TRSTCTL_LICENSE_FILE", { exact: true })).toBeInTheDocument();
    await user.keyboard("{Escape}");
    expect(screen.queryByRole("dialog", { name: "Add license" })).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Add license" })).toHaveFocus();

    const featureSummary = screen.getByText("Feature table", { exact: true });
    expect(featureSummary.closest("details")).toHaveClass("min-w-0");
    await user.click(featureSummary);
    const featureTable = await screen.findByRole("table", { name: "Feature table" });
    expect(featureTable).toBeInTheDocument();
    expect(featureTable.closest("[role='region']")).toHaveClass("min-w-0", "max-w-full");
    expect(screen.getByRole("row", { name: /Governance.*Enabled/i })).toBeInTheDocument();
    expect(apiMock.activeActiveIssuance).not.toHaveBeenCalled();
    expect(apiMock.platformDistribution).not.toHaveBeenCalled();

    const entitlementSummary = screen.getByText("Entitlement evidence", { exact: true });
    expect(entitlementSummary.closest("details")).toHaveClass("min-w-0");
    await user.click(entitlementSummary);
    expect(await screen.findByText("acme-prod")).toBeInTheDocument();
    expect(apiMock.activeActiveIssuance).not.toHaveBeenCalled();
    expect(apiMock.platformDistribution).not.toHaveBeenCalled();

    const architectureSummary = screen.getByText("Deployment architecture evidence", { exact: true });
    expect(architectureSummary.closest("details")).toHaveClass("min-w-0");
    await user.click(architectureSummary);
    await waitFor(() => expect(apiMock.activeActiveIssuance).toHaveBeenCalledTimes(1));
    expect(apiMock.platformDistribution).toHaveBeenCalledTimes(1);
    const regionalHeading = await screen.findByRole("heading", { name: "Regional issuance HA" });
    expect(regionalHeading.closest("section")).toHaveClass("min-w-0");
    expect(screen.getByRole("table", { name: "Regional issuance ingress table" }).closest("[role='region']")).toHaveClass("min-w-0", "max-w-full");
    expect(await axe(view.container)).toHaveNoViolations();
  });

  it("fails closed with sanitized recovery when license truth cannot be read", async () => {
    apiMock.editions.mockRejectedValue(new Error("/etc/trstctl/license.json signature bytes=secret"));
    renderAt("/admin/editions");

    expect(await screen.findByRole("heading", { name: "License status unavailable" })).toBeInTheDocument();
    expect(screen.getByRole("alert")).toHaveTextContent("Plan and license could not be read. No license state was assumed.");
    expect(screen.getByRole("button", { name: "Try again" })).toBeInTheDocument();
    expect(document.body.textContent).not.toMatch(/\/etc\/trstctl|signature bytes|secret/i);
    expect(screen.queryByText(/Community plan is active/i)).not.toBeInTheDocument();
  });

  it("keeps backend details out of lazy deployment-architecture failures", async () => {
    const user = userEvent.setup();
    apiMock.platformDistribution.mockRejectedValue(new Error("postgresql://operator:password@db/internal trace=secret"));
    renderAt("/admin/editions");

    await user.click(await screen.findByText("Entitlement evidence", { exact: true }));
    await user.click(screen.getByText("Deployment architecture evidence", { exact: true }));

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Some deployment architecture evidence could not be read. The license answer above is unchanged.",
    );
    expect(screen.getByRole("button", { name: "Try again" })).toBeInTheDocument();
    expect(document.body.textContent).not.toMatch(/postgresql|operator:password|trace=secret|\/internal/i);
    expect(apiMock.activeActiveIssuance).toHaveBeenCalledTimes(1);
    expect(apiMock.platformDistribution).toHaveBeenCalledTimes(1);
  });

  it.each([
    {
      state: "community" as const,
      tier: "community" as const,
      answer: "Community plan is active",
      signature: "No signed license installed",
      expiry: "No expiry — Community",
    },
    {
      state: "grace" as const,
      tier: "enterprise" as const,
      answer: "Enterprise plan has expired and is in grace",
      signature: "Signed license verified at startup",
      expiry: "Dec 31, 2035, 11:59 PM",
    },
    {
      state: "read_only" as const,
      tier: "provider" as const,
      answer: "Provider plan is read-only",
      signature: "Signed license verified at startup",
      expiry: "Dec 31, 2035, 11:59 PM",
    },
  ])("states license truth plainly for $state", async ({ state, tier, answer, signature, expiry }) => {
    apiMock.editions.mockResolvedValue({
      tier,
      state,
      customer: state === "community" ? undefined : "State fixture",
      license_id: state === "community" ? undefined : `lic_${state}`,
      expires_at: state === "community" ? undefined : "2035-12-31T23:59:59Z",
      rights: ["self_host"],
      features: [],
      fips: { module_active: false, required: false, self_test_passed: true },
    });

    renderAt("/admin/editions");
    expect(await screen.findByRole("heading", { name: answer })).toBeInTheDocument();
    expect(screen.getByText(signature)).toBeInTheDocument();
    expect(screen.getByText(expiry)).toBeInTheDocument();
    expect(apiMock.activeActiveIssuance).not.toHaveBeenCalled();
    expect(apiMock.platformDistribution).not.toHaveBeenCalled();
  });

  it("redirects an unknown /platform tab to /admin/access", async () => {
    renderAt("/platform?tab=nonsense");
    expect(await screen.findByRole("heading", { level: 1, name: "People and roles" })).toBeInTheDocument();
  });

  it("answers system health first and loads exact evidence only when the operator asks", async () => {
    const user = userEvent.setup();
    const view = renderAt("/admin/system");

    expect(await screen.findByRole("heading", { level: 1, name: "System health" })).toBeInTheDocument();
    expect(screen.getByText("Whether the control plane is securely configured for this environment.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Fix first issue" })).toBeInTheDocument();
    expect(screen.getByText("Checks")).toBeInTheDocument();
    expect(screen.getByText("Configuration evidence")).toBeInTheDocument();
    expect(screen.getByText("Dependency health")).toBeInTheDocument();
    expect(screen.getByText("Exceptions")).toBeInTheDocument();

    await waitFor(() => expect(apiMock.platformSystem).toHaveBeenCalledTimes(1));
    expect(apiMock.tenantKeyDomain).not.toHaveBeenCalled();
    expect(apiMock.editions).not.toHaveBeenCalled();
    expect(apiMock.enterpriseSupportStatus).not.toHaveBeenCalled();
    expect(apiMock.managedOfferingStatus).not.toHaveBeenCalled();
    expect(apiMock.scaleOrchestration).not.toHaveBeenCalled();
    expect(screen.queryByRole("heading", { name: "Tenant cryptographic custody" })).not.toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Managed offering" })).not.toBeInTheDocument();
    expect(screen.queryByRole("textbox")).not.toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Fix first issue" }));
    expect(await screen.findByRole("heading", { name: "Tenant cryptographic custody" })).toBeInTheDocument();
    await waitFor(() => expect(apiMock.tenantKeyDomain).toHaveBeenCalledTimes(1));
    expect(apiMock.enterpriseSupportStatus).not.toHaveBeenCalled();
    expect(apiMock.managedOfferingStatus).not.toHaveBeenCalled();

    expect(await axe(view.container)).toHaveNoViolations();
  });

  it("keeps backend request details out of lazy custody evidence failures", async () => {
    const user = userEvent.setup();
    apiMock.tenantKeyDomain.mockRejectedValue(new Error("secret /var/lib/trstctl trace=deadbeef"));
    apiMock.usageEvidence.mockRejectedValue(new Error("postgresql://operator:password@db/internal"));

    renderAt("/admin/system");
    await user.click(await screen.findByText("Configuration evidence", { exact: true }));

    expect(await screen.findByText("Tenant custody status is unavailable")).toBeInTheDocument();
    expect(screen.getByText("Check your access and connection, then refresh the status.")).toBeInTheDocument();
    expect(document.body.textContent).not.toMatch(/secret|\/var\/lib\/trstctl|deadbeef/i);

    await user.click(screen.getByRole("button", { name: "Pull evidence" }));
    expect(
      await screen.findByText("Usage evidence could not be loaded. Check the dates, your access, and the connection, then try again."),
    ).toBeInTheDocument();
    expect(document.body.textContent).not.toMatch(/postgresql|operator:password|\/internal/i);
  });

  it("keeps editions and commercial framing off Access and System (S-A3 re-asserted per route)", async () => {
    const access = renderAt("/admin/access");
    await screen.findByRole("heading", { level: 1, name: "People and roles" });
    expect(screen.queryByRole("heading", { name: "Editions" })).not.toBeInTheDocument();
    expect(document.body.textContent).not.toMatch(/Upgrade to Enterprise|Contact sales/i);
    access.unmount();

    renderAt("/admin/system");
    await screen.findByRole("heading", { level: 1, name: "System health" });
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
    await user.click(await screen.findByRole("button", { name: "Fix first issue" }));
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
    const user = userEvent.setup();
    const view = renderAt("/admin/system");
    await user.click(await screen.findByRole("button", { name: "Fix first issue" }));
    expect(await screen.findByText("Tenant seal worker exhausted its retry budget before the seal committed.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Retry seal with a new request" })).toBeInTheDocument();
    expect(screen.getAllByText(/Retry with a new Idempotency-Key/)).toHaveLength(2);
    expect(await axe(view.container)).toHaveNoViolations();
  });
});
