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
    scaleOrchestration: vi.fn(),
    activeActiveIssuance: vi.fn(),
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
    apiMock.enterpriseSupportStatus.mockResolvedValue({
      served: true,
      capability: "CAP-MODEL-04",
      tier: "enterprise",
      license_state: "active",
      support_mode: "enabled",
      license_feature: "ha_support",
      contract_boundary: "Commercial support terms control legal SLA credits and named contacts.",
      support_tiers: [
        {
          id: "24x7-production",
          name: "Enterprise 24x7 production support",
          coverage: "24x7 for production outages and credential-security incidents",
          initial_response_sla: "P1: 1 hour",
          update_cadence_sla: "P1: every 4 hours",
          escalation: "On-call support engineer",
          license_mode: "enabled",
          contract_boundary: "Requires ha_support and a production-support order form.",
        },
      ],
      sla_targets: [
        {
          severity: "P1",
          applies_to: "Production outage or active credential compromise",
          initial_response_sla: "1 hour",
          update_cadence_sla: "Every 4 hours",
          target_restore: "Mitigation path",
          escalation: "Incident commander plus security engineering",
        },
      ],
      professional_services: [
        {
          id: "incident-retainer",
          name: "Credential incident retainer",
          engagement_model: "Pre-arranged response support",
          deliverables: ["Escalation runbook", "Compromise-response tabletop", "Evidence pack"],
        },
      ],
      evidence_refs: ["internal/api/enterprise_support.go"],
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
          id: "scale-issue",
          subsystem: "issuance",
          worker_pool: "lifecycle issue/deploy workers",
          queue: "bounded lifecycle queue",
          bulkhead_env: ["TRSTCTL_BULKHEAD_LIFECYCLE_WORKERS", "TRSTCTL_BULKHEAD_LIFECYCLE_QUEUE"],
          failure_mode: "full queue rejects before signer work starts",
          external_side_effect: "connector intent through outbox",
          replay_source: "events log",
          scale_trigger: "issuance p95",
          hot_path_slo: "PERF-SLO-001",
          operator_control: "increase lifecycle workers",
          backpressure_signal: "queue saturation",
          measurement: "perf live api.issuance",
          architecture_invariant: "AN-2/AN-5/AN-6/AN-7",
        },
      ],
      shard_plan: [],
      backpressure_policy: [],
      release_gates: [
        { id: "perf-live", command: "scripts/perf/run-local.sh --profile live", artifact: "scripts/perf/artifacts/live-load-baseline.json", required: true },
        { id: "soak", command: "scripts/perf/soak.sh --in <series.json>", artifact: "soak-trend.json", required: true },
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
    expect(apiMock.enterpriseSupportStatus).toHaveBeenCalledTimes(1);
    expect(apiMock.managedOfferingStatus).toHaveBeenCalledTimes(1);
    expect(apiMock.scaleOrchestration).toHaveBeenCalledTimes(1);
    expect(apiMock.activeActiveIssuance).toHaveBeenCalledTimes(1);

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
    expect(screen.getByRole("heading", { name: "Enterprise support" })).toBeInTheDocument();
    expect(screen.getByText("support enabled")).toBeInTheDocument();
    expect(screen.getByText("Enterprise 24x7 production support")).toBeInTheDocument();
    expect(screen.getByText("Credential incident retainer")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Managed offering" })).toBeInTheDocument();
    expect(screen.getByText("managed_provider")).toBeInTheDocument();
    expect(screen.getByText("provider plane enabled")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Scale orchestration" })).toBeInTheDocument();
    expect(screen.getByText("CAP-SCALE-01 active")).toBeInTheDocument();
    expect(screen.getByText("perf-live")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Regional issuance HA" })).toBeInTheDocument();
    expect(screen.getByText("CAP-SCALE-02 active")).toBeInTheDocument();
    expect(screen.getByText("regional-smoke")).toBeInTheDocument();

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
