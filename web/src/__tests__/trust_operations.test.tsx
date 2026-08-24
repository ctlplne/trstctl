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
    contextualRiskPriorities: vi.fn(),
    incidentExecutions: vi.fn(),
    notifications: vi.fn(),
    notificationChannels: vi.fn(),
    notificationRoutingPolicies: vi.fn(),
    ownershipAttribution: vi.fn(),
    bulkheadStats: vi.fn(),
  },
}));

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
      items: [],
    });
    apiMock.bulkheadStats.mockResolvedValue({
      served: true,
      pools: [{ name: "notifications", workers: 2, capacity: 10, queued: 0, submitted: 4, completed: 4, rejected: 0, panicked: 0, saturation_percent: 0 }],
    });
  });

  it("answers cross-product urgency before exposing control-plane machinery", async () => {
    renderPage();

    expect(await screen.findByRole("heading", { level: 1, name: "Trust Operations" })).toBeInTheDocument();
    expect(screen.getByText("What needs attention across every trust domain.", { exact: true })).toBeInTheDocument();

    const attention = await screen.findByRole("list", { name: "Cross-product attention queue" });
    expect(within(attention).getByText("payments.example.test")).toBeInTheDocument();
    expect(within(attention).getByText("Certificate Lifecycle")).toBeInTheDocument();
    expect(within(attention).getByText(/expires in 1 day/i)).toBeInTheDocument();
    expect(within(attention).getByText("No accountable owner")).toBeInTheDocument();
    expect(within(attention).getByRole("link", { name: "Review and remediate" })).toHaveAttribute("href", "/risk?sort=score");

    const health = screen.getByRole("list", { name: "Trust Operations health" });
    expect(within(health).getByRole("link", { name: /1 open incident/i })).toHaveAttribute("href", "/incidents");
    expect(within(health).getByRole("link", { name: /2 ownership gaps/i })).toHaveAttribute("href", "/owners?status=orphaned");
    expect(within(health).getByRole("link", { name: /1 failed alert delivery/i })).toHaveAttribute("href", "/notifications?status=dead");
    expect(within(health).getByRole("link", { name: /background workers healthy/i })).toHaveAttribute("href", "/operations");
  });
});
