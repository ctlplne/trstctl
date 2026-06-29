import { describe, it, expect, vi, beforeEach } from "vitest";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { axe } from "vitest-axe";
import { ThemeProvider } from "@/components/ThemeProvider";
import { AuthProvider } from "@/auth/AuthProvider";
import { AppShell } from "@/components/AppShell";
import { Platform } from "@/pages/Platform";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    me: vi.fn(),
    certificates: vi.fn(),
    certificatePage: vi.fn(),
    identities: vi.fn(),
    owners: vi.fn(),
    risk: vi.fn(),
    secretPage: vi.fn(),
    accessRoles: vi.fn(),
    oidcMappingStatus: vi.fn(),
    members: vi.fn(),
    editions: vi.fn(),
    enterpriseSupportStatus: vi.fn(),
    managedOfferingStatus: vi.fn(),
    scaleOrchestration: vi.fn(),
    activeActiveIssuance: vi.fn(),
    provisionManagedTenant: vi.fn(),
    upsertMember: vi.fn(),
    offboardMember: vi.fn(),
    apiTokens: vi.fn(),
    createAPIToken: vi.fn(),
    revokeAPIToken: vi.fn(),
    logout: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: apiMock };
});

function renderShell(initialEntries = ["/"]) {
  return render(
    <ThemeProvider>
      <AuthProvider>
        <MemoryRouter initialEntries={initialEntries}>
          <Routes>
            <Route element={<AppShell />}>
              <Route index element={<h1>Overview</h1>} />
              <Route path="certificates" element={<h1>Certificates</h1>} />
              <Route path="identities" element={<h1>Identities</h1>} />
              <Route path="platform" element={<Platform />} />
              <Route path="secrets" element={<h1>Secrets</h1>} />
            </Route>
          </Routes>
        </MemoryRouter>
      </AuthProvider>
    </ThemeProvider>,
  );
}

function resizeViewport(width: number) {
  Object.defineProperty(window, "innerWidth", {
    configurable: true,
    value: width,
    writable: true,
  });
  window.dispatchEvent(new Event("resize"));
}

describe("app shell accessibility and theme", () => {
  beforeEach(() => {
    apiMock.me.mockResolvedValue({ subject: "user-1", tenant_id: "t1", email: "u@example.test" });
    apiMock.certificatePage.mockResolvedValue({
      items: [
        {
          id: "cert-1",
          subject: "payments-api",
          fingerprint: "SHA256:abc123",
          status: "active",
          tenant_id: "t1",
        },
      ],
    });
    apiMock.identities.mockResolvedValue([
      {
        id: "id-1",
        kind: "workload_identity",
        name: "payments-worker",
        owner_id: "owner-1",
        status: "issued",
        tenant_id: "t1",
      },
    ]);
    apiMock.secretPage.mockResolvedValue({ items: [{ name: "payments/db/password", version: 3 }] });
    apiMock.accessRoles.mockResolvedValue({
      items: [
        { name: "operator", permissions: ["access:read", "access:write", "certs:issue"] },
        { name: "ra-officer", permissions: ["profiles:read", "profiles:write", "certs:request"] },
      ],
    });
    apiMock.oidcMappingStatus.mockResolvedValue({
      enabled: true,
      tenant_claim: "org",
      groups_claim: "groups",
      claim_is_tenant: false,
      allow_default_tenant: false,
      tenant_mappings: [{ group: "pki-approvers", tenant_id: "t1", roles: ["operator"] }],
    });
    apiMock.members.mockResolvedValue({
      items: [
        {
          tenant_id: "t1",
          subject: "issuer",
          roles: ["operator"],
          source: "manual",
          status: "active",
          created_at: "2026-01-01T00:00:00Z",
          updated_at: "2026-01-01T00:00:00Z",
        },
        {
          tenant_id: "t1",
          subject: "approver-one",
          roles: ["operator"],
          source: "manual",
          status: "offboarded",
          created_at: "2026-01-01T00:00:00Z",
          updated_at: "2026-01-02T00:00:00Z",
          offboarded_at: "2026-01-02T00:00:00Z",
        },
      ],
    });
    apiMock.apiTokens.mockResolvedValue({
      items: [
        { id: "tok-1", tenant_id: "t1", subject: "issuer", scopes: ["identities:write", "certs:issue"], created_at: "2026-01-01T00:00:00Z" },
        {
          id: "tok-2",
          tenant_id: "t1",
          subject: "approver-one",
          scopes: ["certs:issue"],
          created_at: "2026-01-01T00:00:00Z",
          revoked_at: "2026-01-02T00:00:00Z",
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
    apiMock.scaleOrchestration.mockResolvedValue({
      capability: "CAP-SCALE-01",
      served: true,
      generated_at: "2026-06-29T00:00:00Z",
      target_credential_bands: [
        { id: "SCALE-100K", managed_credential: "100,000 managed credentials", capacity_tier: "CAP-MEDIUM", topology: "external datastore production" },
        { id: "SCALE-1M", managed_credential: "1,000,000 managed credentials", capacity_tier: "CAP-LARGE", topology: "multi-replica enterprise" },
      ],
      selected_capacity_tier: {
        id: "CAP-LARGE",
        name: "multi-replica enterprise",
        tenants: 250,
        managed_credentials: 1000000,
        events_per_day: 10000000,
        postgres_gib_30_day: 700,
        jetstream_gib_30_day: 1200,
        control_plane_cpu: "16 vCPU",
        control_plane_memory_gib: 32,
        signer_cpu: "6 vCPU",
        signer_memory_gib: 8,
        estimated_monthly_cost_usd: 14500,
        estimated_cost_per_credential_usd: 0.0145,
        notes: "External HA PostgreSQL and JetStream.",
      },
      hot_path_slos: [],
      execution_lanes: [
        {
          id: "scale-signer",
          subsystem: "signer",
          worker_pool: "isolated signer process pool",
          queue: "signer RPC backlog",
          bulkhead_env: ["TRSTCTL_SIGNER_WORKERS", "TRSTCTL_SIGNER_QUEUE"],
          failure_mode: "signer saturation does not import SQL or HTTP",
          external_side_effect: "signature only",
          replay_source: "orchestrator idempotency and events",
          scale_trigger: "signer p95",
          hot_path_slo: "PERF-SLO-007",
          operator_control: "scale signer separately",
          backpressure_signal: "signer queue saturation",
          measurement: "perf live signer.rpc",
          architecture_invariant: "AN-3/AN-4/AN-7/AN-8",
        },
      ],
      shard_plan: [],
      backpressure_policy: [],
      release_gates: [
        { id: "perf-live", command: "scripts/perf/run-local.sh --profile live", artifact: "scripts/perf/artifacts/live-load-baseline.json", required: true },
      ],
      operator_actions: ["run perf-live"],
      residuals: ["customer infrastructure pricing is operator-specific"],
      evidence_refs: ["internal/perf/contract.go"],
      measurement_artifacts: ["scripts/perf/artifacts/smoke-baseline.json", "scripts/perf/artifacts/live-load-baseline.json"],
      estimated_daily_event_load: 10000000,
      estimated_monthly_cost_usd: 14500,
      unit_economics: { estimated_cost_per_credential_usd: 0.0145, postgres_gib_30_day: 700, jetstream_gib_30_day: 1200, events_per_day: 10000000 },
      tenant_isolation: { storage_enforcement: "RLS", query_rule: "tenant_id filter", evidence_refs: ["CLAUDE.md: AN-1"] },
      datastore: { postgres: "external HA PostgreSQL", jetstream: "external JetStream", rls: "tenant_id", outbox: "transactional outbox" },
      signer: { process_model: "separate signer process", transport: "gRPC over UDS", scaling: "scale signer separately" },
      projection_replay: { replay_floor_events_per_second: 500, max_lag_events: 50, rebuild_source: "append-only event log" },
    });
    apiMock.activeActiveIssuance.mockResolvedValue({
      capability: "CAP-SCALE-02",
      served: true,
      generated_at: "2026-06-29T00:00:00Z",
      topology: "multi-region active ingress on a shared writer plane",
      write_model: "active regional API acceptance with idempotency and event append fencing",
      regions: [
        {
          id: "region-a",
          region: "primary-us-east",
          role: "active issuance ingress",
          writable_scope: "tenant issuance requests that commit in the shared writer plane",
          datastore: "external PostgreSQL",
          event_stream: "replicated JetStream",
          signer: "isolated signer",
          health_signal: "readyz and synthetic issue smoke",
        },
        {
          id: "region-b",
          region: "secondary-us-west",
          role: "active issuance ingress",
          writable_scope: "same idempotent writer plane",
          datastore: "external PostgreSQL",
          event_stream: "replicated JetStream",
          signer: "isolated signer",
          health_signal: "readyz and projection lag",
        },
      ],
      tenant_write_fences: [
        {
          id: "idempotency",
          scope: "every issuance mutation",
          mechanism: "Idempotency-Key recorded before execution",
          conflict_outcome: "retry returns original result",
          evidence: "AN-5",
        },
        { id: "event-log", scope: "issued certificate state", mechanism: "append event first", conflict_outcome: "one ordered event stream", evidence: "AN-2" },
        { id: "outbox", scope: "external calls", mechanism: "transactional intent", conflict_outcome: "leader delivers side effects", evidence: "AN-6" },
      ],
      issuance_lanes: [],
      failover_runbook: [
        { id: "verify", trigger: "traffic moved", action: "run synthetic issue and compare audit evidence", gate: "same result from every region" },
      ],
      release_gates: [
        { id: "regional-smoke", command: "regional smoke", artifact: "regional-issuance-smoke.json", required: true },
        { id: "failover-drill", command: "failover drill", artifact: "ha-failover-drill.json", required: true },
      ],
      rpo_seconds: 5,
      rto_seconds: 30,
      operator_actions: ["route only healthy regional ingress"],
      residuals: ["customer DNS and datastore promotion determine real RTO"],
      evidence_refs: ["internal/perf/contract.go"],
      architecture_invariants: ["AN-1", "AN-2", "AN-4", "AN-5", "AN-6", "AN-7", "AN-8"],
    });
    apiMock.upsertMember.mockResolvedValue({
      tenant_id: "t1",
      subject: "new-approver",
      roles: ["operator"],
      source: "manual",
      status: "active",
      created_at: "2026-01-01T00:00:00Z",
      updated_at: "2026-01-01T00:00:00Z",
    });
    apiMock.offboardMember.mockResolvedValue({
      member: {
        tenant_id: "t1",
        subject: "approver-one",
        roles: ["operator"],
        source: "manual",
        status: "offboarded",
        created_at: "2026-01-01T00:00:00Z",
        updated_at: "2026-01-02T00:00:00Z",
      },
      revoked_token_count: 1,
      rotation_evidence: "active API tokens for the offboarded subject were revoked",
    });
    apiMock.createAPIToken.mockResolvedValue({
      id: "tok-new",
      tenant_id: "t1",
      subject: "new-approver",
      scopes: ["certs:issue"],
      created_at: "2026-01-01T00:00:00Z",
      token: "trst_test_token",
    });
    apiMock.logout.mockReset();
    apiMock.logout.mockResolvedValue(undefined);
    document.documentElement.classList.remove("dark");
    localStorage.clear();
    resizeViewport(1024);
  });

  it("has no axe accessibility violations", async () => {
    const { container } = renderShell();
    await waitFor(() => screen.getByText("u@example.test"));
    const results = await axe(container);
    expect(results).toHaveNoViolations();
  });

  it("exposes navigation and main landmarks and a skip link", async () => {
    renderShell();
    await screen.findByText("u@example.test");
    expect(screen.getByRole("navigation", { name: /Primary/i })).toBeInTheDocument();
    expect(screen.getByRole("main")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Skip to main content/i })).toBeInTheDocument();
  });

  it("navigation links are keyboard reachable", async () => {
    const user = userEvent.setup();
    renderShell();
    await screen.findByText("u@example.test");
    await user.tab(); // skip link
    await user.tab(); // theme toggle
    const dashboardLink = screen.getByRole("link", { name: /Dashboard/i });
    dashboardLink.focus();
    expect(dashboardLink).toHaveFocus();
  });

  it("collapses primary navigation into a labeled mobile drawer", async () => {
    const user = userEvent.setup();
    resizeViewport(380);
    const { container } = renderShell();
    await screen.findByText("u@example.test");

    expect(screen.queryByRole("navigation", { name: /Primary/i })).not.toBeInTheDocument();
    expect(screen.getByRole("main")).toHaveClass("min-w-0");
    const toggle = screen.getByRole("button", { name: "Open primary navigation" });
    expect(toggle).toHaveAttribute("aria-expanded", "false");

    await user.click(toggle);

    expect(toggle).toHaveAttribute("aria-expanded", "true");
    const drawer = screen.getByRole("dialog", { name: "Primary navigation" });
    expect(within(drawer).getByRole("navigation", { name: /Primary/i })).toBeInTheDocument();
    expect(within(drawer).getByRole("link", { name: /Dashboard/i })).toBeInTheDocument();
    expect(within(drawer).getByRole("button", { name: "Close primary navigation" })).toBeInTheDocument();
    expect(document.documentElement.scrollWidth).toBeLessThanOrEqual(380);

    const results = await axe(container);
    expect(results).toHaveNoViolations();

    await user.click(within(drawer).getByRole("button", { name: "Close primary navigation" }));
    expect(screen.queryByRole("dialog", { name: "Primary navigation" })).not.toBeInTheDocument();
  });

  it("shows tenant context without a fake tenant switch", async () => {
    renderShell();
    await screen.findByText("u@example.test");

    const tenant = screen.getByLabelText("Tenant context");
    expect(tenant).toHaveTextContent("t1");
    expect(tenant).not.toHaveTextContent(/Tenant switching isn't available yet|Switch unavailable/i);
    expect(screen.queryByRole("button", { name: /Tenant switching isn't available yet|Switch unavailable/i })).not.toBeInTheDocument();
  });

  it("keeps operators in the shell and announces served logout failures", async () => {
    const user = userEvent.setup();
    apiMock.logout.mockRejectedValueOnce(new Error("network down"));
    renderShell();
    await screen.findByText("u@example.test");

    const signOut = screen.getByRole("button", { name: "Sign out" });
    await user.click(signOut);

    expect(apiMock.logout).toHaveBeenCalledTimes(1);
    expect(await screen.findByRole("alert")).toHaveTextContent("Sign-out failed");
    expect(screen.getByRole("button", { name: "Sign out" })).toBeEnabled();
    expect(screen.getByText("u@example.test")).toBeInTheDocument();
  });

  it("opens the command palette from Cmd-K, searches inventory, and navigates on Enter", async () => {
    const user = userEvent.setup();
    const { container } = renderShell();
    await screen.findByText("u@example.test");

    fireEvent.keyDown(document, { key: "k", metaKey: true });

    let palette = await screen.findByRole("dialog", { name: "Command palette" });
    let search = within(palette).getByRole("searchbox", { name: "Search routes and inventory" });
    expect(search).toHaveFocus();
    await user.type(search, "payments");

    await waitFor(() => expect(apiMock.certificatePage).toHaveBeenCalled());
    expect(within(palette).getByRole("button", { name: /payments-api.*Certificate/i })).toBeInTheDocument();
    expect(within(palette).getByRole("button", { name: /payments-worker.*Identity/i })).toBeInTheDocument();
    expect(within(palette).getByRole("button", { name: /payments\/db\/password.*Secret/i })).toBeInTheDocument();

    const close = within(palette).getByRole("button", { name: "Close command palette" });
    close.focus();
    await user.tab({ shift: true });
    const focusableButtons = within(palette).getAllByRole("button");
    expect(focusableButtons[focusableButtons.length - 1]).toHaveFocus();

    await user.tab();
    expect(close).toHaveFocus();

    expect(await axe(container)).toHaveNoViolations();

    await user.keyboard("{Escape}");
    expect(screen.queryByRole("dialog", { name: "Command palette" })).not.toBeInTheDocument();

    const opener = screen.getByRole("button", { name: "Open command palette" });
    await user.click(opener);
    palette = await screen.findByRole("dialog", { name: "Command palette" });
    search = within(palette).getByRole("searchbox", { name: "Search routes and inventory" });
    expect(search).toHaveFocus();
    await user.keyboard("{Escape}");
    expect(screen.queryByRole("dialog", { name: "Command palette" })).not.toBeInTheDocument();
    expect(opener).toHaveFocus();

    await user.click(opener);
    palette = await screen.findByRole("dialog", { name: "Command palette" });
    search = within(palette).getByRole("searchbox", { name: "Search routes and inventory" });
    await user.type(search, "platform");
    await user.keyboard("{Enter}");

    expect(await screen.findByRole("heading", { name: "Platform" })).toBeInTheDocument();
  });

  it("opens the keyboard shortcuts overlay from ? and the help button", async () => {
    const user = userEvent.setup();
    const { container } = renderShell();
    await screen.findByText("u@example.test");

    await user.keyboard("?");

    let overlay = screen.getByRole("dialog", { name: "Keyboard shortcuts" });
    expect(within(overlay).getByText("Open command palette")).toBeInTheDocument();
    expect(within(overlay).getByText("Show keyboard shortcuts")).toBeInTheDocument();
    expect(await axe(container)).toHaveNoViolations();

    await user.keyboard("{Escape}");
    expect(screen.queryByRole("dialog", { name: "Keyboard shortcuts" })).not.toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Open keyboard shortcuts" }));
    overlay = screen.getByRole("dialog", { name: "Keyboard shortcuts" });
    expect(within(overlay).getByText("Close open overlay")).toBeInTheDocument();
  });

  it("exposes grouped non-certificate navigation domains", async () => {
    renderShell();
    await screen.findByText("u@example.test");
    const nav = screen.getByRole("navigation", { name: /Primary/i });

    for (const group of ["Issue & renew", "Discover & inventory", "Approve & respond", "Monitor posture", "Administer"]) {
      expect(within(nav).getAllByText(group).length).toBeGreaterThan(0);
    }

    for (const link of ["Set up", "Request credential", "Protocols", "Secrets", "Discovery", "Incidents", "Deployment connectors", "Platform"]) {
      expect(within(nav).getByRole("link", { name: new RegExp(link) })).toBeInTheDocument();
    }
    expect(within(nav).queryByRole("link", { name: /Coverage roadmap|RBAC/i })).not.toBeInTheDocument();
  });

  it("exposes task worklists without internal nav metadata", async () => {
    renderShell();
    await screen.findByText("u@example.test");
    const nav = screen.getByRole("navigation", { name: /Primary/i });
    const taskList = within(nav).getByRole("list", { name: "Needs action worklists" });

    expect(within(nav).getByText("Needs action")).toBeInTheDocument();
    expect(within(taskList).getByRole("link", { name: /Expiring soon.*30-day certificate worklist/i })).toHaveAttribute("href", "/certificates?expiry=30d");
    expect(within(taskList).getByRole("link", { name: /Pending approvals.*dual-control issue and revoke inbox/i })).toHaveAttribute(
      "href",
      "/approvals?status=pending",
    );
    expect(within(taskList).getByRole("link", { name: /Highest risk.*risk-prioritized rotation list/i })).toHaveAttribute("href", "/risk?sort=score");

    expect(within(nav).queryByText("Operate")).not.toBeInTheDocument();
    expect(within(nav).queryByText("Observe")).not.toBeInTheDocument();
    expect(within(nav).queryByText("Disclose")).not.toBeInTheDocument();
    expect(within(nav).queryByText(/^map$/i)).not.toBeInTheDocument();
  });

  it("routes to the platform posture page from grouped navigation", async () => {
    const user = userEvent.setup();
    renderShell();
    await screen.findByText("u@example.test");

    await user.click(screen.getByRole("link", { name: /^Platform$/i }));

    expect(await screen.findByRole("heading", { name: "Platform" })).toBeInTheDocument();
    expect(screen.getByText(/Tenant boundary/i)).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Access administration" })).toBeInTheDocument();
  });

  it("renders tenant context from the served session without an editable tenant input", async () => {
    renderShell(["/platform"]);
    await screen.findByRole("heading", { name: "Platform" });

    expect(screen.getByText("Tenant ID from session")).toBeInTheDocument();
    expect(within(screen.getByRole("main")).getByText("t1")).toBeInTheDocument();
    expect(screen.getByText(/browser never chooses a tenant id/i)).toBeInTheDocument();
    expect(screen.queryByRole("textbox", { name: /tenant/i })).not.toBeInTheDocument();
  });

  it("shows access administration from served data", async () => {
    renderShell(["/platform"]);
    await screen.findByRole("heading", { name: "Platform" });

    expect((await screen.findAllByText("operator")).length).toBeGreaterThan(0);
    expect(screen.getByText("ra-officer")).toBeInTheDocument();
    expect(screen.getByText("pki-approvers")).toBeInTheDocument();
    expect(screen.getAllByText("approver-one").length).toBeGreaterThan(0);
    expect(screen.getAllByText("offboarded").length).toBeGreaterThan(0);
    expect(screen.getAllByText("revoked").length).toBeGreaterThan(0);
    expect(screen.getByRole("button", { name: "Offboard" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Mint" })).toBeInTheDocument();
    expect(screen.getByRole("main")).toHaveTextContent("access:write");
    expect(screen.getByRole("main")).toHaveTextContent("certs:issue");
    expect(screen.queryByText("graph:read")).not.toBeInTheDocument();
    expect(screen.queryByText("secrets:write")).not.toBeInTheDocument();
    expect(screen.queryByText(/without tenant existence details/i)).not.toBeInTheDocument();
  });

  it("hides the static API capability table", async () => {
    renderShell(["/platform"]);
    await screen.findByRole("heading", { name: "Platform" });

    expect(screen.queryByRole("heading", { name: "API capability view" })).not.toBeInTheDocument();
    expect(screen.queryByText(/capability groups/i)).not.toBeInTheDocument();
    expect(screen.queryByText("Capability view")).not.toBeInTheDocument();
    expect(screen.queryByText(/Native store, PKI secrets, shares, leases, rotation, sync, and machine login/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/\/api\/v1/)).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /copy curl/i })).not.toBeInTheDocument();
  });

  it("shows honest auth and transport status without exposing key material", async () => {
    renderShell(["/platform"]);
    await screen.findByRole("heading", { name: "Platform" });

    expect(screen.getByText(/Plaintext local preview/i)).toBeInTheDocument();
    expect(screen.getByText(/No private cert\/key bytes are exposed/i)).toBeInTheDocument();
    expect(screen.getByText(/OIDC mapping status and API-token administration/i)).toBeInTheDocument();
    expect(screen.getByText(/browser session and CSRF posture/i)).toBeInTheDocument();
    expect(screen.queryByText(/BEGIN PRIVATE KEY/)).not.toBeInTheDocument();
    expect(screen.queryByText(/BEGIN CERTIFICATE/)).not.toBeInTheDocument();
  });

  it("hides static CLI companion commands", async () => {
    renderShell(["/platform"]);
    await screen.findByRole("heading", { name: "Platform" });

    expect(screen.queryByRole("heading", { name: "CLI companion" })).not.toBeInTheDocument();
    expect(document.body.textContent).not.toMatch(/trstctl-cli|Authorization: Bearer|trst_[A-Za-z0-9]/);
  });

  it("hides unbacked runtime, plugin, and passive federation disclosures", async () => {
    renderShell(["/platform"]);
    await screen.findByRole("heading", { name: "Platform" });

    expect(screen.queryByRole("heading", { name: "Single-binary runtime" })).not.toBeInTheDocument();
    expect(screen.queryByText("Runtime status view coming soon")).not.toBeInTheDocument();
    expect(screen.queryByText("Signer supervision")).not.toBeInTheDocument();

    expect(screen.queryByRole("heading", { name: "Plugin SDK and capability sandbox" })).not.toBeInTheDocument();
    expect(screen.queryByText("connector-f5.wasm")).not.toBeInTheDocument();
    expect(screen.queryByText("net.dial:f5.example.test")).not.toBeInTheDocument();

    expect(screen.queryByRole("heading", { name: "Cross-cluster federation" })).not.toBeInTheDocument();
    expect(screen.queryByText("Passive-read-state model")).not.toBeInTheDocument();
    expect(screen.queryByText("replication worker")).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /activate|enable plugin|install plugin|join cluster|federate/i })).not.toBeInTheDocument();
  });

  it("toggles between exactly two modes — light and dark", async () => {
    const user = userEvent.setup();
    renderShell();
    await screen.findByText("u@example.test");
    // First load resolves the OS default (light here) — not dark.
    expect(document.documentElement.classList.contains("dark")).toBe(false);
    const toggle = screen.getByRole("button", { name: /Theme:/i });
    await user.click(toggle); // light -> dark
    expect(document.documentElement.classList.contains("dark")).toBe(true);
    expect(localStorage.getItem("trstctl-theme")).toBe("dark");
    await user.click(toggle); // dark -> light (no third "system" stop)
    expect(document.documentElement.classList.contains("dark")).toBe(false);
    expect(localStorage.getItem("trstctl-theme")).toBe("light");
  });

  it("collapses and restores the desktop sidebar via the header hamburger", async () => {
    const user = userEvent.setup();
    resizeViewport(1280); // desktop
    renderShell();
    await screen.findByText("u@example.test");
    // Sidebar visible on first load.
    expect(document.getElementById("desktop-primary-nav")).not.toBeNull();
    // Hamburger collapses it.
    await user.click(screen.getByRole("button", { name: /hide navigation sidebar/i }));
    expect(document.getElementById("desktop-primary-nav")).toBeNull();
    // And restores it.
    await user.click(screen.getByRole("button", { name: /show navigation sidebar/i }));
    expect(document.getElementById("desktop-primary-nav")).not.toBeNull();
  });
});
