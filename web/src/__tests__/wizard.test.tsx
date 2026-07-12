import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { Wizard } from "@/pages/Wizard";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    createIssuer: vi.fn(),
    issuers: vi.fn(),
    createEnrollmentToken: vi.fn(),
    agents: vi.fn(),
    issueCertificate: vi.fn(),
    protocolProfileStatus: vi.fn(),
    activateProtocolProfile: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: apiMock };
});

function renderWizard() {
  return render(
    <MemoryRouter>
      <Wizard pollMs={50} />
    </MemoryRouter>,
  );
}

describe("first-run wizard", () => {
  beforeEach(() => {
    apiMock.createIssuer.mockReset();
    apiMock.issuers.mockReset().mockResolvedValue([{ id: "iss-1", name: "Internal CA", internal: true }]);
    apiMock.createEnrollmentToken.mockReset().mockResolvedValue({ token: "BOOT-TOKEN-XYZ" });
    apiMock.agents.mockReset().mockResolvedValue([{ id: "ag-1", name: "edge-01", status: "online" }]);
    apiMock.issueCertificate.mockReset().mockResolvedValue({ id: "id-1", name: "payments", status: "issued" });
    apiMock.protocolProfileStatus.mockReset().mockResolvedValue({
      profile: "eval",
      active: false,
      protocols: ["acme", "est", "scep", "cmp", "ssh", "tsa", "spiffe"],
    });
    apiMock.activateProtocolProfile.mockReset().mockResolvedValue({
      profile: "eval",
      active: true,
      protocols: ["acme", "est", "scep", "cmp", "ssh", "tsa", "spiffe"],
    });
  });

  it("walks internal-CA → issue-first-cert → install-agent and completes setup", async () => {
    const user = userEvent.setup();
    renderWizard();

    // Step 1 — use the already-provisioned internal signer-backed CA. The wizard
    // must not post a name-only x509_ca issuer, because the served API rejects X.509
    // issuers without a certificate chain.
    expect(screen.getByRole("heading", { name: /connect an issuer/i })).toBeInTheDocument();
    expect(screen.getByText(/signer-backed internal x\.509 ca/i)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /use internal ca/i }));
    await waitFor(() => expect(apiMock.issuers).toHaveBeenCalled());
    await waitFor(() => expect(screen.getByText(/internal ca is ready/i)).toBeInTheDocument());
    expect(apiMock.createIssuer).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: /next: enable protocols/i }));

    // Step 2 — the wizard makes a real authenticated activation call. The
    // server appends durable tenant state before opening the responders.
    expect(await screen.findByRole("heading", { name: /enable enrollment protocols/i })).toBeInTheDocument();
    await waitFor(() => expect(apiMock.protocolProfileStatus).toHaveBeenCalledTimes(1));
    await user.click(screen.getByRole("button", { name: /activate eval protocol profile/i }));
    await waitFor(() => expect(apiMock.activateProtocolProfile).toHaveBeenCalledTimes(1));
    expect(await screen.findByText(/eval protocol profile is active/i)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /next: issue certificate/i }));

    // Step 3 — issue the first certificate.
    expect(await screen.findByRole("heading", { name: /issue your first certificate/i })).toBeInTheDocument();
    await user.type(screen.getByLabelText(/service name/i), "payments");
    await user.click(screen.getByRole("button", { name: /issue certificate/i }));
    await waitFor(() => expect(apiMock.issueCertificate).toHaveBeenCalledWith({ name: "payments" }));
    await user.click(screen.getByRole("button", { name: /next: enroll agent/i }));

    // Step 4 — install an agent: a one-time token is minted and shown in the
    // install command, then the wizard detects the agent's registration.
    await user.type(await screen.findByLabelText(/agent identity/i), "edge-01");
    await user.click(screen.getByRole("button", { name: /mint enrollment token/i }));
    await waitFor(() => expect(apiMock.createEnrollmentToken).toHaveBeenCalledWith({ allowed_identity: "edge-01" }));
    expect(await screen.findByText(/BOOT-TOKEN-XYZ/)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /check (for agent|now)/i }));
    expect(await screen.findByText(/Agent edge-01 registered/i)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /next: complete setup/i }));

    expect(await screen.findByText(/ready for certificate operations/i)).toBeInTheDocument();
  });

  it("does not promise automatic renewal after setup and links to the track/renew worklist", async () => {
    const user = userEvent.setup();
    renderWizard();

    await user.click(screen.getByRole("button", { name: /use internal ca/i }));
    await waitFor(() => expect(screen.getByText(/internal ca is ready/i)).toBeInTheDocument());
    await user.click(screen.getByRole("button", { name: /next: enable protocols/i }));
    await screen.findByRole("heading", { name: /enable enrollment protocols/i });
    await user.click(screen.getByRole("button", { name: /activate eval protocol profile/i }));
    await screen.findByText(/eval protocol profile is active/i);
    await user.click(screen.getByRole("button", { name: /next: issue certificate/i }));
    await user.type(await screen.findByLabelText(/service name/i), "payments");
    await user.click(screen.getByRole("button", { name: /issue certificate/i }));
    await user.click(await screen.findByRole("button", { name: /next: enroll agent/i }));
    await user.click(await screen.findByRole("button", { name: /check (for agent|now)/i }));
    await waitFor(() => expect(screen.getByText(/edge-01/)).toBeInTheDocument());
    await user.click(screen.getByRole("button", { name: /next: complete setup/i }));
    await user.click(screen.getByRole("button", { name: /complete setup/i }));

    expect(await screen.findByText(/alert before expiry/i)).toBeInTheDocument();
    expect(screen.getByText(/manual, one-click action/i)).toBeInTheDocument();
    expect(document.body.textContent).not.toMatch(/rotate.*automatically|renew.*automatically/i);
    expect(screen.getByRole("link", { name: /track and renew certificates/i })).toHaveAttribute("href", "/certificates");
  });

  it("surfaces a failure to issue without creating an issuer", async () => {
    apiMock.issueCertificate.mockRejectedValueOnce(new Error("boom"));
    const user = userEvent.setup();
    renderWizard();

    await user.click(screen.getByRole("button", { name: /use internal ca/i }));
    await waitFor(() => expect(screen.getByText(/internal ca is ready/i)).toBeInTheDocument());
    await user.click(screen.getByRole("button", { name: /next: enable protocols/i }));
    await screen.findByRole("heading", { name: /enable enrollment protocols/i });
    await user.click(screen.getByRole("button", { name: /activate eval protocol profile/i }));
    await screen.findByText(/eval protocol profile is active/i);
    await user.click(screen.getByRole("button", { name: /next: issue certificate/i }));
    await user.type(await screen.findByLabelText(/service name/i), "payments");
    await user.click(screen.getByRole("button", { name: /issue certificate/i }));

    expect(await screen.findByRole("alert")).toHaveTextContent(/boom|could not|failed/i);
    expect(apiMock.createIssuer).not.toHaveBeenCalled();
  });
});
