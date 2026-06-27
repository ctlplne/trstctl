import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { Policy } from "@/pages/Policy";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    complianceEvidencePack: vi.fn(),
    exportAudit: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, complianceEvidencePack: apiMock.complianceEvidencePack, exportAudit: apiMock.exportAudit } };
});

function renderPolicy() {
  return render(
    <MemoryRouter>
      <Policy />
    </MemoryRouter>,
  );
}

describe("policy governance surface", () => {
  beforeEach(() => {
    apiMock.complianceEvidencePack.mockReset();
    apiMock.exportAudit.mockReset();
    apiMock.complianceEvidencePack.mockImplementation((framework: "soc2" | "cnsa-2.0") =>
      Promise.resolve({
        format: "trstctl.compliance.evidence-pack.v1",
        framework,
        public_key_der: "BASE64PUBLICKEY",
        signed_export: {
          manifest: {
            controls: [
              { id: `${framework}-crypto-inventory`, title: "Cryptographic inventory maintained", status: "evidenced", evidence: ["CBOM"] },
              { id: `${framework}-audit-trail`, title: "Tamper-evident audit trail", status: "evidenced", evidence: ["signed audit evidence log"] },
              { id: `${framework}-operator-attest`, title: "Operator attestation needed", status: "gap", evidence: ["operator attestation"] },
            ],
            posture: { total_crypto_assets: 4, quantum_vulnerable: framework === "cnsa-2.0" ? 1 : 0, post_quantum: 2 },
            product_evidences: ["FIPS 203/204/205 migration posture from the CBOM"],
            operator_attests: ["organizational policies & governance"],
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

    await user.click(screen.getByRole("button", { name: "Export audit evidence" }));

    await waitFor(() => expect(apiMock.exportAudit).toHaveBeenCalledWith({ limit: 500 }));
    expect(await screen.findByText("jws: signed.audit.bundle")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /generate report|certify|attest compliance/i })).not.toBeInTheDocument();
  });
});
