import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { ThemeProvider } from "@/components/ThemeProvider";
import { AuthProvider } from "@/auth/AuthProvider";
import { AppRoutes } from "@/App";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    me: vi.fn(),
    risk: vi.fn(),
    contextualRiskPriorities: vi.fn(),
    nhiPolicyCompliance: vi.fn(),
    nhiOverPrivilegePosture: vi.fn(),
    nhiStalePosture: vi.fn(),
    nhiStaticPosture: vi.fn(),
    identities: vi.fn(),
    profiles: vi.fn(),
    createIdentity: vi.fn(),
    approveIdentityAction: vi.fn(),
  },
}));

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

describe("POL-03 polish fixes", () => {
  beforeEach(() => {
    for (const mock of Object.values(apiMock)) mock.mockReset();
    apiMock.me.mockResolvedValue({ subject: "dev-1", tenant_id: "t1", email: "dev@example.test" });
    apiMock.nhiPolicyCompliance.mockResolvedValue({
      capability: "CAP-GOV-03",
      generated_at: "2026-06-29T00:00:00Z",
      coverage: ["managed_identities", "discovery_findings", "rotation_cadence", "allowed_scopes", "allowed_geographies", "expiry_policy", "business_purpose"],
      summary: {
        total_analyzed: 0,
        compliant: 0,
        violations: 0,
        rotation_violations: 0,
        scope_violations: 0,
        geo_violations: 0,
        expiry_violations: 0,
        business_purpose_missing: 0,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
      },
      findings: [],
      recommended_actions: [],
      evidence_refs: ["projection:nhi_inventory"],
    });
    apiMock.nhiOverPrivilegePosture.mockResolvedValue({
      capability: "CAP-POST-01",
      generated_at: "2026-06-29T00:00:00Z",
      coverage: ["managed_identities", "discovery_findings", "usage_driven_scope_delta", "least_privilege_recommendations"],
      summary: { total_analyzed: 0, overprivileged: 0, critical: 0, high: 0, medium: 0, low: 0, least_privilege_plans: 0, unused_grants: 0, wildcard_grants: 0 },
      findings: [],
    });
    apiMock.nhiStalePosture.mockResolvedValue({
      capability: "CAP-POST-02",
      generated_at: "2026-06-29T00:00:00Z",
      coverage: ["managed_identities", "discovery_findings", "stale_activity", "unused_no_activity", "orphaned_detection", "dormant_detection"],
      thresholds: { stale_activity_days: 90, dormant_activity_days: 365, unused_no_activity_days: 90 },
      summary: { total_analyzed: 0, findings: 0, stale: 0, dormant: 0, unused: 0, orphaned: 0, critical: 0, high: 0, medium: 0, low: 0, recommendations: 0 },
      findings: [],
    });
    apiMock.nhiStaticPosture.mockResolvedValue({
      capability: "CAP-POST-03",
      generated_at: "2026-06-29T00:00:00Z",
      coverage: ["managed_identities", "discovery_findings", "long_lived_credentials", "static_credential_detection", "no_expiry_detection", "rotation_age"],
      thresholds: { long_lived_credential_days: 365, rotation_overdue_days: 180, no_expiry_minimum_age_days: 90 },
      summary: { total_analyzed: 0, findings: 0, long_lived: 0, static_credentials: 0, no_expiry: 0, rotation_overdue: 0, critical: 0, high: 0, medium: 0, low: 0, recommendations: 0 },
      findings: [],
    });
    apiMock.contextualRiskPriorities.mockResolvedValue({
      capability: "CAP-POST-05",
      generated_at: "2026-06-29T00:00:00Z",
      coverage: ["credential_risk_scores", "graph_blast_radius", "resource_reachability", "cbom_crypto_context", "owner_and_rotation_context"],
      summary: { total_analyzed: 0, priorities: 0, critical: 0, high: 0, medium: 0, low: 0, high_blast_radius: 0, weak_crypto_context: 0, orphaned: 0, near_expiry: 0, recommendations: 0 },
      priorities: [],
    });
    apiMock.approveIdentityAction.mockResolvedValue({ resource: "jit-1", action: "issue", approver: "ra", approvals: 2 });
    apiMock.profiles.mockResolvedValue([{ id: "prof-1", name: "web-server", version: 2, active: true }]);
  });

  it("keeps the risk band thresholds in a tooltip instead of a visible legend", async () => {
    apiMock.risk.mockResolvedValue([
      {
        credential_id: "cert-root",
        subject: "root-ca.example.test",
        kind: "certificate",
        privilege: 2,
        sensitivity: 1,
        exposure: 3,
        owner_active: false,
        expires_at: "2026-07-01T00:00:00Z",
        score: 91,
        components: { age: 0.2, rotation: 0.4, privilege: 0.9, exposure: 0.95, owner: 1, sensitivity: 0.7 },
      },
    ]);
    renderAt("/risk");

    expect(await screen.findByText("root-ca.example.test")).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Risk band legend" })).not.toBeInTheDocument();
    const trigger = screen.getByRole("button", { name: "Risk bands" });
    expect(trigger).toHaveAccessibleDescription(/Critical 90-100/);
    expect(trigger).toHaveAccessibleDescription(/High 70-89/);
  });

  it("labels the approval count column in user language with a tooltip", async () => {
    apiMock.identities.mockResolvedValue([
      {
        id: "jit-1",
        name: "jit-db",
        kind: "x509_certificate",
        owner_id: "owner-1",
        status: "requested",
        attributes: { requester: "ops@example.test", approvals: "1/2", grant_expires_at: "2026-06-19T18:00:00Z" },
      },
    ]);
    renderAt("/approvals");

    const row = await screen.findByRole("row", { name: /jit-db/i });
    expect(screen.getByRole("columnheader", { name: "Approvals" })).toBeInTheDocument();
    expect(screen.queryByRole("columnheader", { name: "Quorum" })).not.toBeInTheDocument();
    expect(screen.getByTitle(/Recorded approvals and required approvals/i)).toBeInTheDocument();
    expect(within(row).getByText("1/2")).toBeInTheDocument();
  });

  it("renders missing request profile data as an em dash, not a not-served cell value", async () => {
    apiMock.identities.mockResolvedValue([
      {
        id: "mine-1",
        tenant_id: "t1",
        name: "checkout-api",
        kind: "x509_certificate",
        owner_id: "dev-1",
        status: "requested",
        attributes: { requester: "dev@example.test", profile_name: "not served", approvals: "1/2" },
      },
    ]);
    renderAt("/request");

    const row = await screen.findByRole("row", { name: /checkout-api/i });
    expect(within(row).getByText("—")).toBeInTheDocument();
    expect(within(row).queryByText(/not served/i)).not.toBeInTheDocument();
  });
});
