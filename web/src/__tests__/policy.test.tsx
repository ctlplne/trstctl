import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { Policy } from "@/pages/Policy";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    complianceEvidencePack: vi.fn(),
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

describe("policy governance surface", () => {
  beforeEach(() => {
    apiMock.complianceEvidencePack.mockReset();
    apiMock.decideNHIReviewItem.mockReset().mockResolvedValue(nhiReviewCampaign("certified"));
    apiMock.exportAudit.mockReset();
    apiMock.getNHIReviewCampaign.mockReset().mockResolvedValue(nhiReviewCampaign());
    apiMock.nhiReviewCampaigns.mockReset().mockResolvedValue({ items: [nhiReviewCampaign()] });
    apiMock.startNHIReviewCampaign.mockReset().mockResolvedValue(nhiReviewCampaign());
    apiMock.complianceEvidencePack.mockImplementation((framework: "soc2" | "cnsa-2.0" | "cabf-br" | "webtrust" | "etsi") =>
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
              { id: `${framework}-operator-attest`, title: "Operator attestation needed", status: "gap", evidence: ["operator attestation"] },
            ],
            posture: { total_crypto_assets: 4, quantum_vulnerable: framework === "cnsa-2.0" ? 1 : 0, post_quantum: 2 },
            product_evidences:
              framework === "cabf-br"
                ? ["CA/Browser Forum profile lint evidence", "external zlint corpus gate", "served CA issuance and revocation audit evidence"]
                : framework === "webtrust" || framework === "etsi"
                ? ["CA issuance and revocation audit evidence", "isolated signer and HSM-capable key-management posture"]
                : ["FIPS 203/204/205 migration posture from the CBOM"],
            operator_attests:
              framework === "cabf-br"
                ? ["independent WebTrust practitioner opinion for public-trust issuance", "CA/Browser Forum policy program operation"]
                : framework === "webtrust"
                ? ["WebTrust practitioner audit opinion"]
                : framework === "etsi"
                  ? ["ETSI conformity assessment"]
                  : ["organizational policies & governance"],
          },
          signature: "signed-by-export-key",
        },
      }),
    );
  });

  it("routes policy decisions to Audit and keeps authoring/dry-run honestly blocked", async () => {
    renderPolicy();
    await screen.findByRole("heading", { name: "SOC 2 evidence pack" });

    expect(screen.getByRole("heading", { name: "Policy" })).toBeInTheDocument();
    expect(screen.getByText(/Decisions are evidence events/i)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Open policy decisions in Audit/i })).toHaveAttribute("href", "/audit?type=policy.decision");
    expect(screen.getByRole("link", { name: /Open profile evaluations in Audit/i })).toHaveAttribute("href", "/audit?type=issuance.profile_evaluated");
    expect(screen.queryByRole("table", { name: "Policy decision outcomes" })).not.toBeInTheDocument();
    expect(screen.getByText("Policy authoring and dry-run aren't in the console yet")).toBeInTheDocument();
    expect(screen.getByText(/lifecycle mutations remain the real enforcement path/i)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /dry run/i })).not.toBeInTheDocument();
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
    expect(await screen.findByRole("heading", { name: "SOC 2 evidence pack" })).toBeInTheDocument();
    expect(screen.getByText("trstctl.compliance.evidence-pack.v1")).toBeInTheDocument();
    expect(screen.getByText("3 controls")).toBeInTheDocument();
    expect(screen.getByText("2 evidenced")).toBeInTheDocument();
    expect(screen.getByText("1 gap")).toBeInTheDocument();
    expect(screen.getByText("FIPS 203/204/205 migration posture from the CBOM")).toBeInTheDocument();
    expect(screen.getAllByText(/evidence, not certification/i).length).toBeGreaterThan(0);
    expect(screen.getByRole("link", { name: "Download signed bundle" })).toHaveAttribute("download", "soc2-evidence-pack.json");

    await user.click(screen.getByRole("button", { name: "CNSA 2.0" }));
    await waitFor(() => expect(apiMock.complianceEvidencePack).toHaveBeenLastCalledWith("cnsa-2.0"));
    expect(await screen.findByRole("heading", { name: "CNSA 2.0 evidence pack" })).toBeInTheDocument();
    expect(screen.getByText("1 quantum vulnerable")).toBeInTheDocument();

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

    await user.click(screen.getByRole("button", { name: "Export audit evidence" }));

    await waitFor(() => expect(apiMock.exportAudit).toHaveBeenCalledWith({ limit: 500 }));
    expect(await screen.findByText("jws: signed.audit.bundle")).toBeInTheDocument();
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
});
