import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { AuthProvider } from "@/auth/AuthProvider";
import { ThemeProvider } from "@/components/ThemeProvider";
import { AppRoutes } from "@/App";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    authMethods: vi.fn(),
    me: vi.fn(),
    capabilities: vi.fn(),
    contextualRiskPriorities: vi.fn(),
    incidentExecutions: vi.fn(),
    notifications: vi.fn(),
    notificationChannels: vi.fn(),
    notificationRoutingPolicies: vi.fn(),
    ownershipAttribution: vi.fn(),
    bulkheadStats: vi.fn(),
    auditEvents: vi.fn(),
    connectorDeliveries: vi.fn(),
    agentJobPosture: vi.fn(),
    platformSystem: vi.fn(),
  },
}));

vi.mock("@/lib/bootstrapApi", async (original) => {
  const actual = await original<typeof import("@/lib/bootstrapApi")>();
  return { ...actual, bootstrapApi: { ...actual.bootstrapApi, ...apiMock } };
});

vi.mock("@/lib/api", async (original) => {
  const actual = await original<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});

function renderPage() {
  return render(
    <ThemeProvider>
      <AuthProvider>
        <MemoryRouter initialEntries={["/trust-operations"]}>
          <AppRoutes />
        </MemoryRouter>
      </AuthProvider>
    </ThemeProvider>,
  );
}

describe("Trust Operations overview", () => {
  beforeEach(() => {
    for (const mock of Object.values(apiMock)) mock.mockReset();
    apiMock.authMethods.mockResolvedValue({ oidc: true, saml: false, ldap: false });
    apiMock.me.mockResolvedValue({ permissions: ["*"], subject: "operator", tenant_id: "tenant-1" });
    apiMock.capabilities.mockResolvedValue({
      schema_version: 2,
      contract_schema_version: 3,
      enforcement_note: "The server checks every operation again when it executes.",
      license: { tier: "community", state: "community" },
      operations: [],
      items: [
        {
          capability_id: "F31",
          name: "Credential compromise workflow",
          purpose: "Contain and repair compromised credentials.",
          tool: "operations",
          classification: "primary",
          console_route: "/incidents",
          maturity: "partial_workflow",
          release_blocking: true,
          edition: "core",
          runtime_state: "available",
          authorization_state: "full",
          dependency_state: "none",
          dependencies: [],
          stages: [{ name: "observe", completion: "complete" }],
          actions: { allowed: ["listIncidentExecutions"], scoped: [], denied: [], unavailable: [] },
        },
      ],
    });
    apiMock.contextualRiskPriorities.mockResolvedValue({
      generated_at: "2026-08-24T12:00:00Z",
      capability: "contextual-risk",
      coverage: ["certificate", "secret"],
      summary: { critical: 1, high: 0, medium: 0, low: 0, priorities: 1, total_analyzed: 1 },
      urgent_summary: { status: "complete", urgent: 1 },
      priorities: [
        {
          credential_id: "cert-1",
          subject: "payments.example.test",
          kind: "certificate",
          severity: "critical",
          contextual_score: 96,
          expires_at: new Date(Date.now() + 86_400_000).toISOString(),
          owner_active: false,
          priority_reasons: ["near_expiry", "orphaned_owner"],
          recommended_action: "Assign the Payments team, verify the alert route, then renew and confirm the served endpoint.",
          base_score: 90,
          blast_radius: 8,
          credential_blast_radius: 3,
          crypto_asset_blast_radius: 0,
          resource_blast_radius: 5,
          workload_blast_radius: 0,
          components: {},
          evidence_refs: [],
          privilege: 2,
          rank: 1,
          sensitivity: 4,
          weak_crypto_context: 0,
        },
      ],
    });
    apiMock.incidentExecutions.mockResolvedValue({
      items: [{ id: "incident-1", status: "running", phase: "contain", created_at: "2026-08-24T11:00:00Z", updated_at: "2026-08-24T11:00:00Z" }],
    });
    apiMock.notifications.mockResolvedValue({
      items: [{ id: "delivery-1", tenant_id: "tenant-1", destination: "notification.slack", status: "dead", attempts: 10, created_at: "2026-08-24T10:00:00Z" }],
    });
    apiMock.notificationChannels.mockResolvedValue({
      items: [{ id: "slack", label: "Slack", category: "chat", configured: true, enabled: true, delivery: "outbox" }],
    });
    apiMock.notificationRoutingPolicies.mockResolvedValue({
      items: [
        {
          id: "route-1",
          name: "Critical",
          tenant_id: "tenant-1",
          default_channels: ["slack"],
          channels_by_severity: {},
          digest_interval_seconds: 3600,
          digest_timezone: "UTC",
          digest_preview: { interval_seconds: 3600, timezone: "UTC", next_run_at: "2026-08-24T13:00:00Z" },
          created_at: "2026-08-24T10:00:00Z",
          updated_at: "2026-08-24T10:00:00Z",
        },
      ],
    });
    apiMock.ownershipAttribution.mockResolvedValue({
      generated_at: "2026-08-24T12:00:00Z",
      coverage: [],
      summary: { total: 8, attributed: 6, orphaned: 2 },
      items: [
        {
          id: "cert-1",
          tenant_id: "tenant-1",
          kind: "certificate",
          source: "inventory",
          display_name: "payments.example.test",
          attribution_status: "attributed",
          attribution_source: "asset_override",
          attribution_evidence: ["assignment:owner-payments"],
          created_at: "2026-08-24T10:00:00Z",
          owner: { id: "owner-payments", tenant_id: "tenant-1", kind: "team", name: "Payments team" },
        },
      ],
    });
    apiMock.bulkheadStats.mockResolvedValue({
      served: true,
      pools: [{ name: "notifications", workers: 2, capacity: 10, queued: 0, submitted: 4, completed: 4, rejected: 0, panicked: 0, saturation_percent: 0 }],
    });
    apiMock.auditEvents.mockResolvedValue([{ sequence: 42, tenant_id: "tenant-1", time: "2026-08-24T11:59:00Z", type: "notification.delivered" }]);
    apiMock.connectorDeliveries.mockResolvedValue({
      items: [
        {
          id: "connector-1",
          tenant_id: "tenant-1",
          connector: "kubernetes",
          target: "cluster-a",
          destination: "connector.deploy",
          status: "verify_failed",
          attempts: 3,
          created_at: "2026-08-24T11:00:00Z",
          updated_at: "2026-08-24T11:03:00Z",
        },
      ],
    });
    apiMock.agentJobPosture.mockResolvedValue({
      served: true,
      generated_at: "2026-08-24T12:00:00Z",
      claimable_kinds: ["discovery"],
      queues: [{ kind: "discovery", enabled: true, pending: 2, claimed: 0, oldest_unclaimed_seconds: 120 }],
      receipts: { rejected: 0, verified: 4 },
      redemptions: { live: 1, total: 4 },
    });
    apiMock.platformSystem.mockResolvedValue({
      version: "0.1.0",
      commit: "abc123",
      build_date: "2026-08-24T10:00:00Z",
      go_version: "go1.26",
      started_at: "2026-08-24T10:00:00Z",
      uptime_seconds: 7200,
      fips_module_active: false,
      signer_mode: "child",
      idempotency_results: { protected: true },
      dependencies: [
        { name: "postgres", ready: true },
        { name: "jetstream", ready: true },
        { name: "signer", ready: true },
      ],
    });
  });

  it("answers cross-product urgency before exposing control-plane machinery", async () => {
    renderPage();

    expect(await screen.findByRole("heading", { level: 1, name: "Operations" })).toBeInTheDocument();
    expect(screen.getByText("What needs attention across every trust domain.", { exact: true })).toBeInTheDocument();

    const attention = await screen.findByRole("list", { name: "Cross-product attention queue" });
    expect(within(attention).getByText("payments.example.test")).toBeInTheDocument();
    expect(within(attention).getByText("Certificates")).toBeInTheDocument();
    expect(within(attention).getByText(/expires in 1 day/i)).toBeInTheDocument();
    expect(within(attention).getByText("Owned by Payments team")).toBeInTheDocument();
    expect(within(attention).getByRole("link", { name: "Review and remediate" })).toHaveAttribute("href", "/risk?sort=score");

    const health = screen.getByRole("list", { name: "Trust Operations health" });
    expect(within(health).getByRole("link", { name: /1 open incident/i })).toHaveAttribute("href", "/incidents");
    expect(within(health).getByRole("link", { name: /2 ownership gaps/i })).toHaveAttribute("href", "/owners?status=orphaned");
    expect(within(health).getByRole("link", { name: /1 failed alert delivery/i })).toHaveAttribute("href", "/notifications?status=dead");
    expect(within(health).getByRole("link", { name: /background workers healthy/i })).toHaveAttribute("href", "/operations");
    expect(within(health).getByRole("link", { name: /1 connector delivery failed/i })).toHaveAttribute("href", "/connectors");
    expect(within(health).getByRole("link", { name: /2 agent jobs waiting/i })).toHaveAttribute("href", "/agents");
    expect(within(health).getByRole("link", { name: /audit evidence is readable/i })).toHaveAttribute("href", "/audit");
    expect(within(health).getByRole("link", { name: /core dependencies ready/i })).toHaveAttribute("href", "/platform");
  });

  it("labels failed evidence sources as unavailable instead of reporting green zeroes", async () => {
    apiMock.contextualRiskPriorities.mockRejectedValue(new Error("risk unavailable"));
    apiMock.incidentExecutions.mockRejectedValue(new Error("incidents unavailable"));
    apiMock.auditEvents.mockRejectedValue(new Error("audit unavailable"));
    apiMock.platformSystem.mockRejectedValue(new Error("system unavailable"));
    renderPage();

    expect(await screen.findByRole("heading", { name: "Trust Operations urgency is not fully known" }, { timeout: 3_000 })).toBeInTheDocument();
    expect(screen.getByText("Risk priorities are unavailable")).toBeInTheDocument();
    const health = screen.getByRole("list", { name: "Trust Operations health" });
    expect(within(health).getByRole("link", { name: "Incident evidence unavailable" })).toBeInTheDocument();
    expect(within(health).getByRole("link", { name: "Audit evidence unavailable" })).toBeInTheDocument();
    expect(within(health).getByRole("link", { name: "System readiness unavailable" })).toBeInTheDocument();
    expect(screen.queryByText("No urgent conditions are projected")).not.toBeInTheDocument();
  });
});
