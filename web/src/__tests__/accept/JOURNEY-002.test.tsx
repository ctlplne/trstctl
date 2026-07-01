import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { Discovery } from "@/pages/Discovery";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    discoverySources: vi.fn(),
    discoverySchedules: vi.fn(),
    discoveryRuns: vi.fn(),
    discoveryMonitoring: vi.fn(),
    nhiShadowPosture: vi.fn(),
    discoveryFindings: vi.fn(),
    claimDiscoveryFinding: vi.fn(),
    dismissDiscoveryFinding: vi.fn(),
    createDiscoverySource: vi.fn(),
    createDiscoverySchedule: vi.fn(),
    startDiscoveryRun: vi.fn(),
    transitionIdentity: vi.fn(),
    decommissionNHI: vi.fn(),
    runRemediationPlaybook: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});

function renderDiscovery() {
  return render(
    <MemoryRouter initialEntries={["/discovery"]}>
      <Discovery />
    </MemoryRouter>,
  );
}

describe("JOURNEY-002 discovery-to-action handoff", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    for (const mock of Object.values(apiMock)) mock.mockReset();
    seedDiscoveryMocks();
  });

  it("runs revoke, decommission, and remediation from a finding row with IDs prefilled", async () => {
    const user = userEvent.setup();
    renderDiscovery();

    const findingRow = (await screen.findByText("github:user/payments-ci/pat")).closest("tr");
    expect(findingRow).toBeTruthy();

    await user.click(within(findingRow as HTMLTableRowElement).getByRole("button", { name: "Revoke" }));
    await waitFor(() =>
      expect(apiMock.transitionIdentity).toHaveBeenCalledWith(
        "identity-api-key-1",
        "revoked",
        "Discovery finding finding-api-key: github:user/payments-ci/pat",
      ),
    );

    await user.click(within(findingRow as HTMLTableRowElement).getByRole("button", { name: "Decommission" }));
    await waitFor(() =>
      expect(apiMock.decommissionNHI).toHaveBeenCalledWith({
        reason: "Discovery finding finding-api-key: github:user/payments-ci/pat",
        revocation_reason: "keyCompromise",
        signals: [
          {
            type: "inactivity",
            identity_id: "identity-api-key-1",
            subject: "github:user/payments-ci/pat",
            evidence_refs: ["discovery.finding:finding-api-key", "discovery.run:run-1"],
          },
        ],
      }),
    );

    await user.click(within(findingRow as HTMLTableRowElement).getByRole("button", { name: "Remediate" }));
    await waitFor(() =>
      expect(apiMock.runRemediationPlaybook).toHaveBeenCalledWith("identity-revoke", {
        inventory_id: "identity/identity-api-key-1",
        reason: "Discovery finding finding-api-key: github:user/payments-ci/pat",
        target: "github:user/payments-ci/pat",
        target_identity_id: "identity-api-key-1",
      }),
    );
  });
});

function seedDiscoveryMocks() {
  apiMock.discoverySources.mockResolvedValue({
    items: [
      {
        id: "source-1",
        tenant_id: "tenant-1",
        kind: "api_key",
        name: "github-audit",
        config: { observations: [] },
        created_at: "2026-06-20T10:00:00Z",
        updated_at: "2026-06-20T10:00:00Z",
      },
    ],
  });
  apiMock.discoverySchedules.mockResolvedValue({ items: [] });
  apiMock.discoveryRuns.mockResolvedValue({
    items: [
      {
        id: "run-1",
        tenant_id: "tenant-1",
        source_id: "source-1",
        status: "succeeded",
        dry_run: false,
        targets: 1,
        discovered: 1,
        failed: 0,
        rejected: 0,
        created_at: "2026-06-20T10:02:00Z",
        completed_at: "2026-06-20T10:02:05Z",
      },
    ],
  });
  apiMock.discoveryMonitoring.mockResolvedValue({
    repository_path: "/api/v1/certificates",
    findings_path: "/api/v1/discovery/findings",
    sources_path: "/api/v1/discovery/sources",
    schedules_path: "/api/v1/discovery/schedules",
    runs_path: "/api/v1/discovery/runs",
    summary: {
      source_count: 1,
      scheduled_source_count: 0,
      active_monitoring_count: 0,
      run_count: 1,
      completed_run_count: 1,
      failed_run_count: 0,
      finding_count: 1,
      open_finding_count: 1,
      certificate_inventory_count: 0,
    },
    sources: [],
  });
  apiMock.nhiShadowPosture.mockResolvedValue({
    capability: "CAP-NHI-05",
    generated_at: "2026-06-20T10:04:00Z",
    coverage: ["discovery_findings"],
    summary: {
      total_analyzed: 1,
      findings: 1,
      unmanaged: 1,
      investigating: 0,
      unregistered: 1,
      ownerless: 0,
      critical: 0,
      high: 1,
      medium: 0,
      low: 0,
      kind_counts: { api_key: 1 },
      surface_counts: { ci: 1 },
    },
    findings: [],
    recommended_actions: ["Use row actions to revoke or decommission unauthorized findings."],
    evidence_refs: ["projection:discovery_findings"],
  });
  apiMock.discoveryFindings.mockResolvedValue({
    items: [
      {
        id: "finding-api-key",
        tenant_id: "tenant-1",
        run_id: "run-1",
        source_id: "source-1",
        kind: "api_key",
        ref: "github:user/payments-ci/pat",
        provenance: "github:audit/pat-1",
        fingerprint: "1234567890abcdef1234567890abcdef",
        risk_score: 90,
        metadata: { owner: "payments", team: "platform", tags: ["orphaned", "static"] },
        discovered_at: "2026-06-20T10:02:06Z",
        triage_status: "unmanaged",
        managed_identity_id: "identity-api-key-1",
      },
    ],
  });
  apiMock.transitionIdentity.mockResolvedValue({
    id: "identity-api-key-1",
    state: "revoked",
  });
  apiMock.decommissionNHI.mockResolvedValue({
    capability: "CAP-NHI-DECOMMISSION",
    coverage: ["managed_identities", "discovery_findings"],
    reason: "Discovery finding finding-api-key: github:user/payments-ci/pat",
    summary: { matched: 1, revoked: 1, retired: 1, failed: 0 },
    items: [],
  });
  apiMock.runRemediationPlaybook.mockResolvedValue({
    id: "remediation-run-1",
    tenant_id: "tenant-1",
    playbook_id: "identity-revoke",
    action: "remediate",
    status: "queued",
    phase: "queued",
    inventory_id: "finding-api-key",
    target_identity_id: "identity-api-key-1",
    scope_delta: {},
    evidence_refs: ["discovery.finding:finding-api-key"],
    rollback_refs: [],
    created_at: "2026-06-20T10:10:00Z",
    updated_at: "2026-06-20T10:10:00Z",
  });
}
