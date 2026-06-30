import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { Policy } from "@/pages/Policy";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    accessChangeRequests: vi.fn(),
    complianceEvidencePack: vi.fn(),
    complianceInventoryReport: vi.fn(),
    complianceReportSchedules: vi.fn(),
    createAccessChangeRequest: vi.fn(),
    createComplianceReportSchedule: vi.fn(),
    decideAccessChangeRequest: vi.fn(),
    decideNHIReviewItem: vi.fn(),
    exportAudit: vi.fn(),
    getAccessChangeRequest: vi.fn(),
    getNHIReviewCampaign: vi.fn(),
    nhiReviewCampaigns: vi.fn(),
    startNHIReviewCampaign: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});

beforeEach(() => {
  apiMock.accessChangeRequests.mockReset().mockResolvedValue({ items: [accessChangeRequest()] });
  apiMock.complianceEvidencePack.mockReset().mockResolvedValue({
    framework: "soc2",
    format: "application/json",
    public_key_der: "BASE64DER",
    signed_export: { controls: 12, posture: "pass" },
  });
  apiMock.complianceInventoryReport.mockReset().mockResolvedValue(complianceInventoryReport());
  apiMock.complianceReportSchedules.mockReset().mockResolvedValue({ items: [complianceSchedule()] });
  apiMock.createAccessChangeRequest.mockReset().mockResolvedValue(accessChangeRequest());
  apiMock.createComplianceReportSchedule.mockReset().mockResolvedValue(complianceSchedule());
  apiMock.decideAccessChangeRequest.mockReset().mockResolvedValue(accessChangeRequest("approved"));
  apiMock.exportAudit.mockReset().mockResolvedValue({ format: "json", bundle: "BASE64BUNDLE" });
  apiMock.getAccessChangeRequest.mockReset().mockResolvedValue(accessChangeRequest());
  apiMock.nhiReviewCampaigns.mockReset().mockResolvedValue({ items: [nhiReviewCampaign()] });
  apiMock.getNHIReviewCampaign.mockReset().mockResolvedValue(nhiReviewCampaign());
  apiMock.startNHIReviewCampaign.mockReset().mockResolvedValue(nhiReviewCampaign());
  apiMock.decideNHIReviewItem.mockReset().mockResolvedValue(nhiReviewCampaign("certified"));
});

function nhiReviewCampaign(status: "pending" | "certified" = "pending") {
  return {
    id: "11111111-1111-4111-8111-111111111111",
    tenant_id: "tenant-1",
    name: "Quarterly NHI access certification",
    scope: "quarterly_access",
    reviewer_subject: "ra@example.test",
    requested_by: "ra@example.test",
    status: status === "pending" ? "open" : "completed",
    item_count: 1,
    pending_count: status === "pending" ? 1 : 0,
    certified_count: status === "certified" ? 1 : 0,
    revoked_count: 0,
    exception_count: 0,
    created_at: "2026-06-28T12:00:00Z",
    updated_at: "2026-06-28T12:00:00Z",
    items: [
      {
        item_id: "22222222-2222-4222-8222-222222222222",
        nhi_id: "svc-payments-api",
        nhi_kind: "workload",
        display_name: "Payments API workload",
        resource: "k8s://prod/payments",
        entitlement: "secret:payments/db/read",
        risk: "medium",
        evidence_refs: ["audit:nhi-discovery/latest"],
        status,
        created_at: "2026-06-28T12:00:00Z",
        updated_at: "2026-06-28T12:00:00Z",
      },
    ],
  };
}

function accessChangeRequest(status: "pending" | "approved" | "denied" = "pending") {
  return {
    id: "77777777-7777-4777-8777-777777777777",
    tenant_id: "tenant-1",
    requested_action: "grant",
    requester_subject: "platform-dev@example.test",
    nhi_id: "github-app:prod-deployer",
    nhi_kind: "oauth_app",
    display_name: "Prod deployer GitHub App",
    resource: "github:org/prod-infra",
    entitlement: "repo:contents:write",
    change_ref: "github:org/prod-infra#4821",
    change_system: "github",
    change_url: "https://github.com/org/prod-infra/pull/4821",
    risk: "high",
    reason: "Scoped deployment automation access",
    evidence_refs: ["pull:4821/checks"],
    status,
    required_approvals: 2,
    approval_count: status === "approved" ? 2 : 0,
    created_at: "2026-06-28T12:00:00Z",
    updated_at: "2026-06-28T12:00:00Z",
    decisions: [],
  };
}

function complianceSchedule() {
  return {
    id: "33333333-3333-4333-8333-333333333333",
    tenant_id: "tenant-1",
    framework: "soc2",
    name: "Quarterly SOC 2 inventory",
    report_type: "inventory_snapshot",
    interval_seconds: 90 * 24 * 60 * 60,
    enabled: true,
    delivery: "audit_export",
    recipient_ref: "audit-vault",
    next_run_at: "2026-09-26T12:00:00Z",
    created_at: "2026-06-28T12:00:00Z",
    updated_at: "2026-06-28T12:00:00Z",
  };
}

function complianceInventoryReport() {
  return {
    capability: "CAP-OBS-02",
    generated_at: "2026-06-28T12:00:00Z",
    frameworks: ["pci-dss", "hipaa", "soc2", "nist-800-53", "nist-csf-2.0", "fedramp", "cmmc-2.0", "cnsa-2.0", "fips-140", "common-criteria", "cabf-br", "webtrust", "etsi", "eidas", "nis2"],
    report_types: ["framework_evidence_pack", "inventory_snapshot", "cbom_posture", "audit_summary"],
    routes: ["GET /api/v1/compliance/inventory-report", "POST /api/v1/compliance/report-schedules", "GET /api/v1/compliance/report-schedules"],
    evidence_refs: ["event:compliance.report_schedule.upserted"],
    schedules: [complianceSchedule()],
    summary: {
      certificates: 8,
      crypto_assets: 4,
      discovery_schedules: 2,
      report_schedules: 1,
      enabled_report_schedules: 1,
      frameworks_supported: 15,
      report_types_supported: 4,
      inventory_rows: 15,
    },
  };
}

describe("U6-1 compliance evidence-pack dashboard", () => {
  it("renders a framework's signed evidence pack and exports audit evidence from served endpoints", async () => {
    const user = userEvent.setup();
    render(
      <MemoryRouter>
        <Policy />
      </MemoryRouter>,
    );
    await waitFor(() => expect(apiMock.complianceEvidencePack).toHaveBeenCalledWith("soc2"));
    expect(await screen.findByText("SOC 2 evidence pack")).toBeInTheDocument();
    expect(screen.getByText("Download signed bundle")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "PCI DSS" }));
    await waitFor(() => expect(apiMock.complianceEvidencePack).toHaveBeenCalledWith("pci-dss"));

    await user.click(screen.getByRole("button", { name: "Export audit evidence" }));
    await waitFor(() => expect(apiMock.exportAudit).toHaveBeenCalledWith({ limit: 500 }));
  });
});
