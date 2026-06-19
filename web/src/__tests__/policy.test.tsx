import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { Policy } from "@/pages/Policy";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    exportAudit: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, exportAudit: apiMock.exportAudit } };
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
    apiMock.exportAudit.mockReset();
  });

  it("explains served policy outcomes and keeps authoring/dry-run honestly blocked", () => {
    renderPolicy();

    expect(screen.getByRole("heading", { name: "Policy" })).toBeInTheDocument();
    expect(screen.getByText("Allowed")).toBeInTheDocument();
    expect(screen.getByText("Denied")).toBeInTheDocument();
    expect(screen.getByText("Policy error")).toBeInTheDocument();
    expect(screen.getByText("Overload 503")).toBeInTheDocument();
    expect(screen.getByText(/default-deny wins/i)).toBeInTheDocument();
    expect(screen.getByText(/policy.decision deny/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Audit policy decisions/i })).toHaveAttribute(
      "href",
      "/audit?type=policy.decision",
    );
    expect(screen.getByRole("link", { name: /profile evaluation evidence/i })).toHaveAttribute(
      "href",
      "/audit?type=issuance.profile_evaluated",
    );
    expect(screen.getByText("Policy authoring and dry-run API not served yet")).toBeInTheDocument();
    expect(screen.getByText(/BACKEND-POLICY-AUTHOR/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /dry run/i })).not.toBeInTheDocument();
  });

  it("renders notification integrations with masked secret references and no live channel controls", () => {
    renderPolicy();

    expect(screen.getByRole("heading", { name: "Notification integrations" })).toBeInTheDocument();
    for (const channel of ["Slack", "Microsoft Teams", "Email", "PagerDuty", "OpsGenie", "Webhook"]) {
      expect(screen.getByText(channel)).toBeInTheDocument();
    }
    expect(screen.getByText("secret://notify/slack/prod:****")).toBeInTheDocument();
    expect(screen.getByText("secret://notify/webhook/prod:****")).toBeInTheDocument();
    expect(screen.getByText(/response body redacted/i)).toBeInTheDocument();
    expect(screen.getAllByText(/BACKEND-NOTIFY|BACKEND-OUTBOX-STATUS/).length).toBeGreaterThan(0);
    expect(screen.queryByText(/xoxb-|pagerduty_api_key|webhook-token-/i)).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /test delivery|configure channel|send notification/i })).not.toBeInTheDocument();
  });

  it("exports served audit evidence while keeping compliance reports library-only", async () => {
    apiMock.exportAudit.mockResolvedValue({ format: "jws", bundle: "signed.audit.bundle" });
    const user = userEvent.setup();
    renderPolicy();

    expect(screen.getByRole("heading", { name: "Compliance posture and reports" })).toBeInTheDocument();
    expect(screen.getByText("PCI DSS")).toBeInTheDocument();
    expect(screen.getByText("HIPAA")).toBeInTheDocument();
    expect(screen.getByText("SOC 2")).toBeInTheDocument();
    expect(screen.getByText("FedRAMP")).toBeInTheDocument();
    expect(screen.getByText("CNSA 2.0")).toBeInTheDocument();
    expect(screen.getAllByText(/evidence, not certification/i).length).toBeGreaterThan(0);
    expect(screen.getByText("Framework-mapped compliance posture is not served yet")).toBeInTheDocument();
    expect(screen.getAllByText(/BACKEND-COMPLIANCE/).length).toBeGreaterThan(0);

    await user.click(screen.getByRole("button", { name: "Export audit evidence" }));

    await waitFor(() => expect(apiMock.exportAudit).toHaveBeenCalledWith({ limit: 500 }));
    expect(await screen.findByText("jws: signed.audit.bundle")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /generate report|certify|attest compliance/i })).not.toBeInTheDocument();
  });
});
