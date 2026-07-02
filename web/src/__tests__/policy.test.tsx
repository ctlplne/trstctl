import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { Policy } from "@/pages/Policy";
import type { AccessChangeRequest, ComplianceEvidencePack, PolicyVersion } from "@/lib/api";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    accessChangeRequests: vi.fn(),
    complianceEvidencePack: vi.fn(),
    complianceInventoryReport: vi.fn(),
    createAccessChangeRequest: vi.fn(),
    nhiComplianceReport: vi.fn(),
    complianceReportSchedules: vi.fn(),
    createComplianceReportSchedule: vi.fn(),
    decideAccessChangeRequest: vi.fn(),
    decideNHIReviewItem: vi.fn(),
    exportAudit: vi.fn(),
    getAccessChangeRequest: vi.fn(),
    getNHIReviewCampaign: vi.fn(),
    nhiReviewCampaigns: vi.fn(),
    policyVersions: vi.fn(),
    createPolicyVersion: vi.fn(),
    activatePolicyVersion: vi.fn(),
    rollbackPolicyVersion: vi.fn(),
    policyDryRun: vi.fn(),
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

function nhiReviewCampaign(status: "pending" | "certified" = "pending") {
  const completed = status !== "pending";
  return {
    id: "11111111-1111-4111-8111-111111111111",
    tenant_id: "tenant-1",
    name: "Quarterly NHI access certification",
    scope: "quarterly_access",
    reviewer_subject: "ra@example.test",
    requested_by: "ra@example.test",
    status: completed ? "completed" : "open",
    item_count: 1,
    pending_count: completed ? 0 : 1,
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
        decision_by: completed ? "ra@example.test" : undefined,
        decision_reason: completed ? "Recorded" : undefined,
        created_at: "2026-06-28T12:00:00Z",
        updated_at: "2026-06-28T12:00:00Z",
      },
    ],
  };
}

function accessChangeRequest(status: "pending" | "approved" | "denied" = "pending", overrides: Partial<AccessChangeRequest> = {}): AccessChangeRequest {
  const terminal = status !== "pending";
  return {
    id: "77777777-7777-4777-8777-777777777777",
    tenant_id: "tenant-1",
    requested_action: "grant",
    requester_subject: "platform-dev@example.test",
    nhi_id: "github-app:prod-deployer",
    nhi_kind: "oauth_app",
    display_name: "Prod deployer GitHub App",
    owner_ref: "team:platform",
    resource: "github:org/prod-infra",
    entitlement: "repo:contents:write",
    change_ref: "github:org/prod-infra#4821",
    change_system: "github",
    change_url: "https://github.com/org/prod-infra/pull/4821",
    risk: "high",
    reason: "Scoped deployment automation access",
    evidence_refs: ["pull:4821/checks", "ticket:CAB-4821"],
    status,
    required_approvals: 2,
    approval_count: status === "approved" ? 2 : 0,
    created_at: "2026-06-28T12:00:00Z",
    updated_at: "2026-06-28T12:00:00Z",
    completed_at: terminal ? "2026-06-28T12:10:00Z" : undefined,
    decisions: terminal
      ? [
          {
            request_id: "77777777-7777-4777-8777-777777777777",
            approver_subject: "security-reviewer@example.test",
            decision: status === "approved" ? "approved" : "denied",
            reason: "PR evidence reviewed",
            decision_evidence_refs: ["github-review:security-reviewer"],
            decided_at: "2026-06-28T12:10:00Z",
          },
        ]
      : [],
    ...overrides,
  };
}

function policyVersion(status: PolicyVersion["status"] = "draft", overrides: Partial<PolicyVersion> = {}): PolicyVersion {
  return {
    id: status === "active" ? "11111111-1111-4111-8111-111111111111" : "22222222-2222-4222-8222-222222222222",
    tenant_id: "tenant-1",
    kind: "lifecycle",
    module: "package trstctl.policy\n\ndefault allow := false\n",
    module_sha256: status === "active" ? "sha256-active-policy-module" : "sha256-draft-policy-module",
    package: "trstctl.policy",
    query: "data.trstctl.policy",
    description: status === "active" ? "Default lifecycle gate" : "Emergency issuance guard",
    change_ref: "github:security/policy#42",
    evidence_refs: ["pr:policy-42"],
    status,
    active: status === "active",
    created_at: "2026-07-02T12:00:00Z",
    activated_at: status === "active" ? "2026-07-02T12:05:00Z" : undefined,
    ...overrides,
  };
}

function complianceSchedule(name = "Quarterly SOC 2 inventory") {
  return {
    id: "33333333-3333-4333-8333-333333333333",
    tenant_id: "tenant-1",
    framework: "soc2",
    name,
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

function policyDryRunResult() {
  return {
    kind: "lifecycle",
    valid: true,
    module_sha256: "sha256-policy-module",
    package: "trstctl.policy",
    query: "data.trstctl.policy",
    allow: true,
    deny: false,
    reason: "",
    trace: [
      {
        op: "Enter",
        query_id: 1,
        location: "trstctl.policy.rego:6",
        node: 'input.action == "issue"',
      },
    ],
    input_summary: {
      action: "issue",
      profile: "server-tls",
      subject: "svc-payments-api",
      actor: "policy-author@example.test",
      tenant_id: "tenant-1",
    },
    audit_event: "policy.dry_run.evaluated",
    idempotency_key: "idem-policy-dry-run",
  };
}

function complianceInventoryReport() {
  return {
    capability: "CAP-OBS-02",
    generated_at: "2026-06-28T12:00:00Z",
    frameworks: [
      "pci-dss",
      "hipaa",
      "soc2",
      "nist-800-53",
      "nist-csf-2.0",
      "fedramp",
      "cmmc-2.0",
      "cnsa-2.0",
      "fips-140",
      "common-criteria",
      "cabf-br",
      "webtrust",
      "etsi",
      "eidas",
      "nis2",
    ],
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
      {
        id: "nist-csf-2.0",
        name: "NIST Cybersecurity Framework",
        version: "2.0",
        mapping_status: "served",
        evidence_sources: ["api:GET /api/v1/compliance/nhi-report"],
      },
      { id: "pci-dss-4.0", name: "PCI DSS", version: "4.0", mapping_status: "served", evidence_sources: ["api:GET /api/v1/compliance/nhi-report"] },
      {
        id: "dora",
        name: "Digital Operational Resilience Act",
        version: "Regulation (EU) 2022/2554",
        mapping_status: "served",
        evidence_sources: ["api:GET /api/v1/compliance/nhi-report"],
      },
      {
        id: "iso-27001",
        name: "ISO/IEC 27001",
        version: "2022 Annex A",
        mapping_status: "served",
        evidence_sources: ["api:GET /api/v1/compliance/nhi-report"],
      },
      { id: "fedramp", name: "FedRAMP", version: "Rev. 5 baselines", mapping_status: "served", evidence_sources: ["api:GET /api/v1/compliance/nhi-report"] },
      { id: "cmmc-2.0", name: "CMMC", version: "2.0", mapping_status: "served", evidence_sources: ["api:GET /api/v1/compliance/nhi-report"] },
      {
        id: "eidas",
        name: "eIDAS",
        version: "Regulation (EU) No 910/2014 and eIDAS 2.0",
        mapping_status: "served",
        evidence_sources: ["api:GET /api/v1/compliance/nhi-report"],
      },
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

describe("policy governance surface", () => {
  beforeEach(() => {
    apiMock.accessChangeRequests.mockReset().mockResolvedValue({ items: [accessChangeRequest()] });
    apiMock.complianceEvidencePack.mockReset();
    apiMock.complianceInventoryReport.mockReset().mockResolvedValue(complianceInventoryReport());
    apiMock.createAccessChangeRequest.mockReset().mockResolvedValue(accessChangeRequest());
    apiMock.nhiComplianceReport.mockReset().mockResolvedValue(nhiComplianceReport());
    apiMock.complianceReportSchedules.mockReset().mockResolvedValue({ items: [complianceSchedule()] });
    apiMock.createComplianceReportSchedule.mockReset().mockResolvedValue(complianceSchedule("Quarterly SOC 2 inventory"));
    apiMock.decideAccessChangeRequest.mockReset().mockResolvedValue(accessChangeRequest("approved"));
    apiMock.decideNHIReviewItem.mockReset().mockResolvedValue(nhiReviewCampaign("certified"));
    apiMock.exportAudit.mockReset();
    apiMock.getAccessChangeRequest.mockReset().mockResolvedValue(accessChangeRequest());
    apiMock.getNHIReviewCampaign.mockReset().mockResolvedValue(nhiReviewCampaign());
    apiMock.nhiReviewCampaigns.mockReset().mockResolvedValue({ items: [nhiReviewCampaign()] });
    apiMock.policyVersions.mockReset().mockResolvedValue({
      items: [policyVersion("active"), policyVersion("draft")],
      active: policyVersion("active"),
      counts: { total: 2, active: 1, draft: 1, inactive: 0, rolled_back: 0 },
    });
    apiMock.createPolicyVersion.mockReset().mockResolvedValue(policyVersion("draft"));
    apiMock.activatePolicyVersion.mockReset().mockResolvedValue(policyVersion("active", { id: "22222222-2222-4222-8222-222222222222" }));
    apiMock.rollbackPolicyVersion.mockReset().mockResolvedValue(
      policyVersion("rolled_back", {
        id: "11111111-1111-4111-8111-111111111111",
        active: false,
        rollback_to_id: "33333333-3333-4333-8333-333333333333",
      }),
    );
    apiMock.policyDryRun.mockReset().mockResolvedValue(policyDryRunResult());
    apiMock.startNHIReviewCampaign.mockReset().mockResolvedValue(nhiReviewCampaign());
    apiMock.complianceEvidencePack.mockImplementation((framework: ComplianceEvidencePack["framework"]) =>
      Promise.resolve({
        format: "trstctl.compliance.evidence-pack.v1",
        framework,
        public_key_der: "BASE64PUBLICKEY",
        signed_export: {
          manifest: {
            controls: [
              { id: `${framework}-crypto-inventory`, title: "Cryptographic inventory maintained", status: "evidenced", evidence: ["CBOM"] },
              { id: `${framework}-audit-trail`, title: "Tamper-evident audit trail", status: "evidenced", evidence: ["signed audit evidence log"] },
              ...(framework === "cabf-br"
                ? [
                    {
                      id: "cabf-br-profile-lint",
                      title: "TLS server-certificate profiles are linted against CA/Browser Forum Baseline Requirements",
                      status: "evidenced",
                      evidence: ["profilelint structural CA/B checks", "external zlint corpus gate"],
                    },
                    {
                      id: "cabf-br-public-trust-residual",
                      title: "Public-trust policy operation remains an operator responsibility",
                      status: "gap",
                      evidence: ["external practitioner report"],
                    },
                  ]
                : []),
              ...(framework === "soc2"
                ? [
                    {
                      id: "soc2-cc6-access-control",
                      title: "Logical access controls for NHI credentials are evidenced",
                      status: "evidenced",
                      evidence: ["tenant RBAC", "NHI inventory and posture evidence mappings"],
                    },
                    {
                      id: "soc2-attestation-residual",
                      title: "CPA examination and trust-service scope remain operator responsibilities",
                      status: "gap",
                      evidence: ["independent CPA SOC 2 examination report"],
                    },
                  ]
                : []),
              ...(framework === "fips-140"
                ? [
                    {
                      id: "fips-140-module-post",
                      title: "FIPS-capable build path and fail-closed power-on self-test are evidenced",
                      status: "evidenced",
                      evidence: ["make fips-build artifact gate", "--fips fail-closed POST"],
                    },
                    {
                      id: "fips-140-cmvp-certificate-residual",
                      title: "NIST CMVP validation certificate remains an external artifact",
                      status: "gap",
                      evidence: ["NIST CMVP certificate"],
                    },
                  ]
                : []),
              ...(framework === "common-criteria"
                ? [
                    {
                      id: "common-criteria-security-target-evidence",
                      title: "Security-target evidence map covers the served TOE controls",
                      status: "evidenced",
                      evidence: ["security-target evidence map"],
                    },
                    {
                      id: "common-criteria-evaluation-residual",
                      title: "External lab evaluation and certificate remain operator responsibilities",
                      status: "gap",
                      evidence: ["Common Criteria certificate"],
                    },
                  ]
                : []),
              ...(framework === "webtrust" || framework === "etsi"
                ? [
                    {
                      id: `${framework}-ca-audit-posture`,
                      title: framework === "webtrust" ? "CA lifecycle evidence supports WebTrust review" : "CA operations evidence supports ETSI review",
                      status: "evidenced",
                      evidence: ["CA issuance and revocation audit evidence"],
                    },
                  ]
                : []),
              ...((["nist-800-53", "nist-csf-2.0", "fedramp", "cmmc-2.0", "eidas", "nis2"] as Array<ComplianceEvidencePack["framework"]>).includes(framework)
                ? [
                    {
                      id: `${framework}-regulatory-mapping`,
                      title: "Regulatory control mapping from NHI posture and audit evidence",
                      status: "evidenced",
                      evidence: ["NHI inventory and posture evidence mappings", "signed audit evidence mapped to framework controls"],
                    },
                  ]
                : []),
              { id: `${framework}-operator-attest`, title: "Operator attestation needed", status: "gap", evidence: ["operator attestation"] },
            ],
            posture: { total_crypto_assets: 4, quantum_vulnerable: framework === "cnsa-2.0" ? 1 : 0, post_quantum: 2 },
            product_evidences:
              framework === "cabf-br"
                ? ["CA/Browser Forum profile lint evidence", "external zlint corpus gate", "served CA issuance and revocation audit evidence"]
                : framework === "soc2"
                  ? ["SOC 2 security-event and change-control evidence mapping", "tenant RBAC and NHI access-review evidence"]
                  : framework === "fips-140"
                    ? ["FIPS-capable build and fail-closed POST evidence"]
                    : framework === "common-criteria"
                      ? ["security-target evidence map over served controls"]
                      : framework === "webtrust" || framework === "etsi"
                        ? ["CA issuance and revocation audit evidence", "isolated signer and HSM-capable key-management posture"]
                        : (["nist-800-53", "nist-csf-2.0", "fedramp", "cmmc-2.0", "eidas", "nis2"] as Array<ComplianceEvidencePack["framework"]>).includes(
                              framework,
                            )
                          ? ["NHI inventory and posture evidence mappings", "signed audit evidence mapped to framework controls"]
                          : ["FIPS 203/204/205 migration posture from the CBOM"],
            operator_attests:
              framework === "cabf-br"
                ? ["independent WebTrust practitioner opinion for public-trust issuance", "CA/Browser Forum policy program operation"]
                : framework === "soc2"
                  ? ["SOC 2 trust-services category scope", "independent CPA SOC 2 examination report"]
                  : framework === "fips-140"
                    ? ["NIST CMVP certificate number for the deployed validated module"]
                    : framework === "common-criteria"
                      ? ["Common Criteria certificate and evaluation report"]
                      : framework === "webtrust"
                        ? ["WebTrust practitioner audit opinion"]
                        : framework === "etsi"
                          ? ["ETSI conformity assessment"]
                          : framework === "eidas"
                            ? ["eIDAS conformity assessment"]
                            : framework === "nis2"
                              ? ["NIS2 entity scope and national transposition obligations"]
                              : framework === "fedramp"
                                ? ["FedRAMP authorization package"]
                                : framework === "cmmc-2.0"
                                  ? ["CMMC scope and CUI boundary"]
                                  : framework === "nist-800-53"
                                    ? ["NIST SP 800-53 control tailoring"]
                                    : framework === "nist-csf-2.0"
                                      ? ["NIST CSF organizational profile"]
                                      : ["organizational policies & governance"],
          },
          signature: "signed-by-export-key",
        },
      }),
    );
  });

  it("routes policy decisions to Audit and serves policy dry-run traces", async () => {
    const user = userEvent.setup();
    renderPolicy();
    await screen.findByRole("heading", { name: "SOC 2 evidence pack" });

    expect(screen.getByRole("heading", { name: "Policy" })).toBeInTheDocument();
    expect(screen.getByText(/Decisions are evidence events/i)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Open policy decisions in Audit/i })).toHaveAttribute("href", "/audit?type=policy.decision");
    expect(screen.getByRole("link", { name: /Open profile evaluations in Audit/i })).toHaveAttribute("href", "/audit?type=issuance.profile_evaluated");
    expect(screen.getByRole("link", { name: /Open dry-run audit events/i })).toHaveAttribute("href", "/audit?type=policy.dry_run.evaluated");
    expect(screen.queryByRole("table", { name: "Policy decision outcomes" })).not.toBeInTheDocument();
    expect(screen.queryByText("Policy authoring and dry-run aren't in the console yet")).not.toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Run dry run" }));

    await waitFor(() =>
      expect(apiMock.policyDryRun).toHaveBeenCalledWith(
        expect.objectContaining({
          kind: "lifecycle",
          trace_limit: 80,
          input: expect.objectContaining({ action: "issue", profile: "server-tls", subject: "svc-payments-api" }),
        }),
      ),
    );
    expect(await screen.findByRole("heading", { name: "Dry-run result" })).toBeInTheDocument();
    expect(screen.getByText("policy.dry_run.evaluated")).toBeInTheDocument();
    expect(screen.getByText("sha256-policy-module")).toBeInTheDocument();
    expect(screen.getByRole("table", { name: "Policy dry-run trace" })).toBeInTheDocument();
  });

  it("serves policy version authoring, activation, and rollback controls", async () => {
    const user = userEvent.setup();
    renderPolicy();
    await screen.findByRole("heading", { name: "Active policy" });

    expect(screen.getByRole("table", { name: "Policy versions" })).toBeInTheDocument();
    expect(screen.getByText("Emergency issuance guard")).toBeInTheDocument();
    expect(screen.getByText("sha256-active-policy-module")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Author version" }));
    await waitFor(() =>
      expect(apiMock.createPolicyVersion).toHaveBeenCalledWith(
        expect.objectContaining({
          kind: "lifecycle",
          change_ref: "github:security/policy#42",
          evidence_refs: ["pr:policy-42", "cab:2026-07-02"],
        }),
      ),
    );

    const activateButtons = screen.getAllByRole("button", { name: "Activate" });
    await user.click(activateButtons[1]);
    await waitFor(() => expect(apiMock.activatePolicyVersion).toHaveBeenCalledWith("22222222-2222-4222-8222-222222222222", expect.any(Object)));

    const rollbackButtons = screen.getAllByRole("button", { name: "Rollback" });
    await user.click(rollbackButtons[0]);
    await waitFor(() => expect(apiMock.rollbackPolicyVersion).toHaveBeenCalledWith("11111111-1111-4111-8111-111111111111", expect.any(Object)));
  });

  it("removes notification-channel fixtures and live channel controls", async () => {
    renderPolicy();
    await screen.findByRole("heading", { name: "SOC 2 evidence pack" });

    expect(screen.queryByRole("heading", { name: "Notification integrations" })).not.toBeInTheDocument();
    for (const channel of ["Slack", "Microsoft Teams", "Email", "PagerDuty", "OpsGenie", "Webhook"]) {
      expect(screen.queryByText(channel)).not.toBeInTheDocument();
    }
    expect(screen.queryByText(/secret:\/\/notify/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/Notification channel controls coming soon/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/xoxb-|pagerduty_api_key|webhook-token-/i)).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /test delivery|configure channel|send notification/i })).not.toBeInTheDocument();
  });

  it("renders served compliance evidence packs and still exports audit evidence", async () => {
    apiMock.exportAudit.mockResolvedValue({ format: "jws", bundle: "signed.audit.bundle" });
    const user = userEvent.setup();
    renderPolicy();

    expect(screen.getByRole("heading", { name: "Compliance posture and reports" })).toBeInTheDocument();
    await waitFor(() => expect(apiMock.complianceEvidencePack).toHaveBeenCalledWith("soc2"));
    await waitFor(() => expect(apiMock.complianceInventoryReport).toHaveBeenCalled());
    await waitFor(() => expect(apiMock.nhiComplianceReport).toHaveBeenCalled());
    expect(await screen.findByRole("heading", { name: "SOC 2 evidence pack" })).toBeInTheDocument();
    expect(await screen.findByRole("heading", { name: "Compliance inventory report" })).toBeInTheDocument();
    expect(await screen.findByRole("heading", { name: "NHI compliance mapping" })).toBeInTheDocument();
    expect(screen.getByText(/CAP-CMP-06/i)).toBeInTheDocument();
    expect(screen.getByText("Application and system account credential controls")).toBeInTheDocument();
    expect(screen.getByText(/CAP-OBS-02/i)).toBeInTheDocument();
    expect(screen.getByText("Quarterly SOC 2 inventory")).toBeInTheDocument();
    expect(screen.getByText("GET /api/v1/compliance/inventory-report")).toBeInTheDocument();
    expect(screen.getByText("trstctl.compliance.evidence-pack.v1")).toBeInTheDocument();
    expect(screen.getByText("5 controls")).toBeInTheDocument();
    expect(screen.getByText("3 evidenced")).toBeInTheDocument();
    expect(screen.getByText("2 gaps")).toBeInTheDocument();
    expect(screen.getByText("SOC 2 security-event and change-control evidence mapping")).toBeInTheDocument();
    expect(screen.getAllByText("independent CPA SOC 2 examination report").length).toBeGreaterThan(0);
    expect(screen.getAllByText(/evidence, not certification/i).length).toBeGreaterThan(0);
    expect(screen.getByRole("link", { name: "Download signed bundle" })).toHaveAttribute("download", "soc2-evidence-pack.json");

    await user.click(screen.getByRole("button", { name: "CNSA 2.0" }));
    await waitFor(() => expect(apiMock.complianceEvidencePack).toHaveBeenLastCalledWith("cnsa-2.0"));
    expect(await screen.findByRole("heading", { name: "CNSA 2.0 evidence pack" })).toBeInTheDocument();
    expect(screen.getByText("1 quantum vulnerable")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "FIPS 140" }));
    await waitFor(() => expect(apiMock.complianceEvidencePack).toHaveBeenLastCalledWith("fips-140"));
    expect(await screen.findByRole("heading", { name: "FIPS 140 evidence pack" })).toBeInTheDocument();
    expect(screen.getByText("FIPS-capable build and fail-closed POST evidence")).toBeInTheDocument();
    expect(screen.getByText("NIST CMVP certificate number for the deployed validated module")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Common Criteria" }));
    await waitFor(() => expect(apiMock.complianceEvidencePack).toHaveBeenLastCalledWith("common-criteria"));
    expect(await screen.findByRole("heading", { name: "Common Criteria evidence pack" })).toBeInTheDocument();
    expect(screen.getByText("security-target evidence map over served controls")).toBeInTheDocument();
    expect(screen.getByText("Common Criteria certificate and evaluation report")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "CA/B Forum BR" }));
    await waitFor(() => expect(apiMock.complianceEvidencePack).toHaveBeenLastCalledWith("cabf-br"));
    expect(await screen.findByRole("heading", { name: "CA/B Forum BR evidence pack" })).toBeInTheDocument();
    expect(screen.getByText("CA/Browser Forum profile lint evidence")).toBeInTheDocument();
    expect(screen.getByText("independent WebTrust practitioner opinion for public-trust issuance")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "WebTrust" }));
    await waitFor(() => expect(apiMock.complianceEvidencePack).toHaveBeenLastCalledWith("webtrust"));
    expect(await screen.findByRole("heading", { name: "WebTrust evidence pack" })).toBeInTheDocument();
    expect(screen.getAllByText("CA issuance and revocation audit evidence").length).toBeGreaterThan(0);
    expect(screen.getByText("WebTrust practitioner audit opinion")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "ETSI" }));
    await waitFor(() => expect(apiMock.complianceEvidencePack).toHaveBeenLastCalledWith("etsi"));
    expect(await screen.findByRole("heading", { name: "ETSI evidence pack" })).toBeInTheDocument();
    expect(screen.getByText("ETSI conformity assessment")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "NIST 800-53" }));
    await waitFor(() => expect(apiMock.complianceEvidencePack).toHaveBeenLastCalledWith("nist-800-53"));
    expect(await screen.findByRole("heading", { name: "NIST 800-53 evidence pack" })).toBeInTheDocument();
    expect(screen.getByText("NIST SP 800-53 control tailoring")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "FedRAMP" }));
    await waitFor(() => expect(apiMock.complianceEvidencePack).toHaveBeenLastCalledWith("fedramp"));
    expect(await screen.findByRole("heading", { name: "FedRAMP evidence pack" })).toBeInTheDocument();
    expect(screen.getByText("FedRAMP authorization package")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "CMMC 2.0" }));
    await waitFor(() => expect(apiMock.complianceEvidencePack).toHaveBeenLastCalledWith("cmmc-2.0"));
    expect(await screen.findByRole("heading", { name: "CMMC 2.0 evidence pack" })).toBeInTheDocument();
    expect(screen.getByText("CMMC scope and CUI boundary")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "eIDAS" }));
    await waitFor(() => expect(apiMock.complianceEvidencePack).toHaveBeenLastCalledWith("eidas"));
    expect(await screen.findByRole("heading", { name: "eIDAS evidence pack" })).toBeInTheDocument();
    expect(screen.getByText("eIDAS conformity assessment")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "NIS2" }));
    await waitFor(() => expect(apiMock.complianceEvidencePack).toHaveBeenLastCalledWith("nis2"));
    expect(await screen.findByRole("heading", { name: "NIS2 evidence pack" })).toBeInTheDocument();
    expect(screen.getByText("NIS2 entity scope and national transposition obligations")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Export audit evidence" }));

    await waitFor(() => expect(apiMock.exportAudit).toHaveBeenCalledWith({ limit: 500 }));
    expect(await screen.findByText("jws: signed.audit.bundle")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Create schedule" }));
    await waitFor(() =>
      expect(apiMock.createComplianceReportSchedule).toHaveBeenCalledWith(
        expect.objectContaining({
          framework: "soc2",
          report_type: "inventory_snapshot",
          interval_seconds: 90 * 24 * 60 * 60,
          delivery: "audit_export",
        }),
      ),
    );
    expect(screen.queryByRole("button", { name: /generate report|attest compliance/i })).not.toBeInTheDocument();
  });

  it("serves NHI access certification campaigns from the Policy surface", async () => {
    const user = userEvent.setup();
    renderPolicy();

    expect(await screen.findByRole("heading", { name: "NHI access certification" })).toBeInTheDocument();
    expect(await screen.findByText("Payments API workload")).toBeInTheDocument();
    expect(screen.getByText("secret:payments/db/read")).toBeInTheDocument();

    expect(screen.getByRole("button", { name: "Certify" })).toBeEnabled();
    expect(screen.getByRole("button", { name: "Revoke" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Exception" })).toBeDisabled();

    await user.click(screen.getByRole("button", { name: "Start campaign" }));
    await waitFor(() =>
      expect(apiMock.startNHIReviewCampaign).toHaveBeenCalledWith(
        expect.objectContaining({
          name: "Quarterly NHI access certification",
          items: [expect.objectContaining({ nhi_id: "svc-payments-api", resource: "k8s://prod/payments" })],
        }),
      ),
    );
  });

  it("serves access-change approval requests from the Policy surface", async () => {
    const user = userEvent.setup();
    renderPolicy();

    expect(await screen.findByRole("heading", { name: "Access-change approvals" })).toBeInTheDocument();
    expect((await screen.findAllByText("Prod deployer GitHub App")).length).toBeGreaterThan(0);
    expect(screen.getByText("repo:contents:write")).toBeInTheDocument();
    expect(screen.getByText("github:org/prod-infra#4821")).toBeInTheDocument();

    await waitFor(() => expect(screen.getByRole("button", { name: "Approve" })).toBeEnabled());
    expect(screen.getByRole("button", { name: "Deny" })).toBeDisabled();

    await user.click(screen.getByRole("button", { name: "Open request" }));
    await waitFor(() =>
      expect(apiMock.createAccessChangeRequest).toHaveBeenCalledWith(
        expect.objectContaining({
          requested_action: "grant",
          nhi_id: "github-app:prod-deployer",
          change_ref: "github:org/prod-infra#4821",
          required_approvals: 2,
          evidence_refs: ["pull:4821/checks", "ticket:CAB-4821"],
        }),
      ),
    );
    expect(await screen.findByText("Prod deployer GitHub App grant request opened from github:org/prod-infra#4821.")).toBeInTheDocument();
  });

  it("renders access-change links only when the URL is safe", async () => {
    renderPolicy();

    const link = await screen.findByRole("link", { name: "https://github.com/org/prod-infra/pull/4821" });
    expect(link).toHaveAttribute("href", "https://github.com/org/prod-infra/pull/4821");
    expect(link).toHaveAttribute("target", "_blank");
    expect(link).toHaveAttribute("rel", "noopener noreferrer");
  });

  it("omits unsafe access-change links from API data", async () => {
    const unsafeRequest = accessChangeRequest("pending", { change_url: "javascript:alert(1)" });
    apiMock.accessChangeRequests.mockResolvedValue({ items: [unsafeRequest] });
    apiMock.getAccessChangeRequest.mockResolvedValue(unsafeRequest);

    renderPolicy();

    expect(await screen.findByText("Scoped deployment automation access")).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "javascript:alert(1)" })).not.toBeInTheDocument();
    expect(screen.queryByText("javascript:alert(1)")).not.toBeInTheDocument();
  });
});
