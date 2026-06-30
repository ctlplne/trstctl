import { readFileSync } from "node:fs";
import path from "node:path";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { Audit } from "@/pages/Audit";
import { Policy } from "@/pages/Policy";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    auditEvents: vi.fn(),
    complianceEvidencePack: vi.fn(),
    complianceInventoryReport: vi.fn(),
    nhiComplianceReport: vi.fn(),
    complianceReportSchedules: vi.fn(),
    createComplianceReportSchedule: vi.fn(),
    decideNHIReviewItem: vi.fn(),
    exportAudit: vi.fn(),
    getNHIReviewCampaign: vi.fn(),
    nhiReviewCampaigns: vi.fn(),
    startNHIReviewCampaign: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});

function renderPolicy() {
  return render(
    <MemoryRouter>
      <Policy />
    </MemoryRouter>,
  );
}

function renderAudit(initialEntry = "/audit") {
  return render(
    <MemoryRouter initialEntries={[initialEntry]}>
      <Audit />
    </MemoryRouter>,
  );
}

function evidencePack(framework: "soc2" | "cnsa-2.0") {
  return {
    format: "trstctl.compliance.evidence-pack.v1",
    framework,
    public_key_der: "BASE64PUBLICKEY",
    signed_export: {
      manifest: {
        framework,
        controls: [
          { id: `${framework}-crypto-inventory`, title: "Cryptographic inventory maintained", status: "evidenced", evidence: ["CBOM"] },
          { id: `${framework}-audit-trail`, title: "Tamper-evident audit trail", status: "evidenced", evidence: ["signed audit evidence log"] },
          { id: `${framework}-operator-attest`, title: "Operator attestation needed", status: "gap", evidence: ["operator attestation"] },
        ],
        posture: { total_crypto_assets: 4, quantum_vulnerable: framework === "cnsa-2.0" ? 1 : 0, post_quantum: framework === "cnsa-2.0" ? 3 : 1 },
        product_evidences: ["FIPS 203/204/205 migration posture from the CBOM"],
        operator_attests: ["organizational policies & governance"],
      },
      signature: "signed-by-export-key",
    },
  };
}

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
    report_types: ["framework_evidence_pack", "inventory_snapshot", "cbom_posture", "audit_summary", "nhi_compliance_mapping"],
    routes: [
      "GET /api/v1/compliance/inventory-report",
      "GET /api/v1/compliance/nhi-report",
      "POST /api/v1/compliance/report-schedules",
      "GET /api/v1/compliance/report-schedules",
    ],
    evidence_refs: ["event:compliance.report_schedule.upserted"],
    schedules: [complianceSchedule()],
    summary: {
      certificates: 8,
      crypto_assets: 4,
      discovery_schedules: 2,
      report_schedules: 1,
      enabled_report_schedules: 1,
      frameworks_supported: 15,
      report_types_supported: 5,
      inventory_rows: 15,
    },
  };
}

function nhiComplianceReport() {
  return {
    format: "trstctl.nhi.compliance-report.v1",
    capability: "CAP-CMP-06",
    generated_at: "2026-06-28T12:00:00Z",
    audit_ready: true,
    summary: {
      total_nhis: 12,
      inventory_kinds: 5,
      frameworks_supported: 9,
      controls_mapped: 37,
      overprivileged_findings: 2,
      stale_findings: 1,
      static_credential_findings: 1,
      audit_evidence_refs: 8,
      operator_attestation_needed: 3,
    },
    frameworks: [
      { id: "nist-800-53", name: "NIST SP 800-53", version: "Rev. 5", mapping_status: "served", evidence_sources: ["api:GET /api/v1/compliance/nhi-report"] },
      { id: "nist-csf-2.0", name: "NIST Cybersecurity Framework", version: "2.0", mapping_status: "served", evidence_sources: ["api:GET /api/v1/compliance/nhi-report"] },
      { id: "pci-dss-4.0", name: "PCI DSS", version: "4.0", mapping_status: "served", evidence_sources: ["api:GET /api/v1/compliance/nhi-report"] },
      { id: "dora", name: "Digital Operational Resilience Act", version: "Regulation (EU) 2022/2554", mapping_status: "served", evidence_sources: ["api:GET /api/v1/compliance/nhi-report"] },
      { id: "iso-27001", name: "ISO/IEC 27001", version: "2022 Annex A", mapping_status: "served", evidence_sources: ["api:GET /api/v1/compliance/nhi-report"] },
      { id: "fedramp", name: "FedRAMP", version: "Rev. 5 baselines", mapping_status: "served", evidence_sources: ["api:GET /api/v1/compliance/nhi-report"] },
      { id: "cmmc-2.0", name: "CMMC", version: "2.0", mapping_status: "served", evidence_sources: ["api:GET /api/v1/compliance/nhi-report"] },
      { id: "eidas", name: "eIDAS", version: "Regulation (EU) No 910/2014 and eIDAS 2.0", mapping_status: "served", evidence_sources: ["api:GET /api/v1/compliance/nhi-report"] },
      { id: "nis2", name: "NIS2", version: "Directive (EU) 2022/2555", mapping_status: "served", evidence_sources: ["api:GET /api/v1/compliance/nhi-report"] },
    ],
    controls: [
      {
        framework: "pci-dss-4.0",
        control_id: "8.6",
        title: "Application and system account credential controls",
        status: "evidenced",
        evidence_refs: ["api:GET /api/v1/nhi/posture/static-credentials"],
        posture_signals: ["static_rotation"],
        finding_count: 1,
      },
      {
        framework: "dora",
        control_id: "Article 8",
        title: "ICT asset identification and classification",
        status: "evidenced",
        evidence_refs: ["api:GET /api/v1/nhi/inventory"],
        posture_signals: ["inventory"],
        finding_count: 12,
      },
    ],
    report_types: ["framework_evidence_pack", "inventory_snapshot", "cbom_posture", "audit_summary", "nhi_compliance_mapping"],
    routes: ["GET /api/v1/compliance/nhi-report", "GET /api/v1/nhi/inventory", "GET /api/v1/nhi/posture/static-credentials"],
    evidence_refs: ["api:GET /api/v1/compliance/nhi-report"],
    residuals: ["trstctl maps tenant evidence to controls but does not certify compliance."],
  };
}

describe("SIMP-03 policy, audit, and compliance remediation", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    apiMock.auditEvents.mockReset();
    apiMock.complianceEvidencePack.mockReset();
    apiMock.complianceInventoryReport.mockReset().mockResolvedValue(complianceInventoryReport());
    apiMock.nhiComplianceReport.mockReset().mockResolvedValue(nhiComplianceReport());
    apiMock.complianceReportSchedules.mockReset().mockResolvedValue({ items: [complianceSchedule()] });
    apiMock.createComplianceReportSchedule.mockReset().mockResolvedValue(complianceSchedule());
    apiMock.decideNHIReviewItem.mockReset().mockResolvedValue(nhiReviewCampaign("certified"));
    apiMock.exportAudit.mockReset();
    apiMock.getNHIReviewCampaign.mockReset().mockResolvedValue(nhiReviewCampaign());
    apiMock.nhiReviewCampaigns.mockReset().mockResolvedValue({ items: [nhiReviewCampaign()] });
    apiMock.startNHIReviewCampaign.mockReset().mockResolvedValue(nhiReviewCampaign());
    apiMock.complianceEvidencePack.mockImplementation((framework: "soc2" | "cnsa-2.0") => Promise.resolve(evidencePack(framework)));
  });

  it("renders framework compliance evidence packs from the served client with a signed-bundle download", async () => {
    const user = userEvent.setup();
    renderPolicy();

    await waitFor(() => expect(apiMock.complianceEvidencePack).toHaveBeenCalledWith("soc2"));
    expect(await screen.findByRole("heading", { name: "SOC 2 evidence pack" })).toBeInTheDocument();
    expect(screen.getByText("trstctl.compliance.evidence-pack.v1")).toBeInTheDocument();
    expect(screen.getByText("3 controls")).toBeInTheDocument();
    expect(screen.getByText("2 evidenced")).toBeInTheDocument();
    expect(screen.getByText("1 gap")).toBeInTheDocument();
    expect(screen.getAllByText("4").length).toBeGreaterThan(0);
    expect(screen.getByText("FIPS 203/204/205 migration posture from the CBOM")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Download signed bundle" })).toHaveAttribute("download", "soc2-evidence-pack.json");
    expect(await screen.findByRole("heading", { name: "NHI compliance mapping" })).toBeInTheDocument();
    expect(screen.getByText("CAP-CMP-06 generated Jun 28, 2026 · audit-ready")).toBeInTheDocument();
    expect(screen.getByText("PCI DSS 4.0")).toBeInTheDocument();
    expect(screen.getByText("Application and system account credential controls")).toBeInTheDocument();
    expect(screen.getAllByText("NHI compliance mapping").length).toBeGreaterThan(0);

    await user.click(screen.getByRole("button", { name: "CNSA 2.0" }));

    await waitFor(() => expect(apiMock.complianceEvidencePack).toHaveBeenLastCalledWith("cnsa-2.0"));
    expect(await screen.findByRole("heading", { name: "CNSA 2.0 evidence pack" })).toBeInTheDocument();
    expect(screen.getByText("1 quantum vulnerable")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Download signed bundle" })).toHaveAttribute("download", "cnsa-2.0-evidence-pack.json");
    expect(screen.getByRole("heading", { name: "NHI access certification" })).toBeInTheDocument();
    expect(await screen.findByText("Payments API workload")).toBeInTheDocument();
  });

  it("views policy decisions from Audit filters instead of a static Policy table", async () => {
    const user = userEvent.setup();
    apiMock.auditEvents
      .mockResolvedValueOnce([{ sequence: 1, id: "evt-1", type: "identity.issued", tenant_id: "tenant-1", time: "2026-06-26T12:00:00Z" }])
      .mockResolvedValueOnce([
        {
          sequence: 42,
          id: "evt-42",
          type: "policy.decision",
          tenant_id: "tenant-1",
          time: "2026-06-26T12:30:00Z",
          hash: "sha256:policy",
          actor: { email: "ra@example.test" },
          data: { decision: "deny", resource_id: "cert/payments", reason: "profile rejected SAN" },
        },
      ]);
    renderAudit();

    await screen.findByText("identity.issued");
    await user.click(screen.getByRole("button", { name: "Policy decisions" }));

    await waitFor(() => expect(apiMock.auditEvents).toHaveBeenLastCalledWith({ type: "policy.decision", limit: 50 }));
    expect(await screen.findByText("policy.decision")).toBeInTheDocument();
    expect(screen.getByDisplayValue("policy.decision")).toBeInTheDocument();
    expect(screen.getByText("cert/payments")).toBeInTheDocument();
    expect(screen.getByText("ra@example.test")).toBeInTheDocument();
  });

  it("removes notification-channel fixtures from Policy", async () => {
    renderPolicy();
    await waitFor(() => expect(apiMock.complianceEvidencePack).toHaveBeenCalled());

    expect(screen.queryByRole("heading", { name: "Notification integrations" })).not.toBeInTheDocument();
    expect(document.body.textContent).not.toMatch(/Slack|Microsoft Teams|PagerDuty|OpsGenie|secret:\/\/notify|channel fixture|test delivery/i);

    const source = readFileSync(path.join(process.cwd(), "src/pages/Policy.tsx"), "utf8");
    expect(source).not.toMatch(
      /notificationChannels|notificationFailures|secret:\/\/notify|Slack|Microsoft Teams|PagerDuty|OpsGenie|channel fixture|test delivery/i,
    );
  });
});
