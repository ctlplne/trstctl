import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { Wizard } from "@/pages/Wizard";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    createIssuer: vi.fn(),
    issuers: vi.fn(),
    platformSystem: vi.fn(),
    createEnrollmentToken: vi.fn(),
    agents: vi.fn(),
    createOwner: vi.fn(),
    attestOwner: vi.fn(),
    issueCertificate: vi.fn(),
    protocolProfileStatus: vi.fn(),
    activateProtocolProfile: vi.fn(),
    connectorCatalog: vi.fn(),
    externalCAs: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});

function renderWizard() {
  return render(
    <MemoryRouter>
      <Wizard pollMs={10} />
    </MemoryRouter>,
  );
}

describe("DESIGN-001 first-certificate onboarding cues", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    for (const mock of Object.values(apiMock)) mock.mockReset();
    apiMock.issuers.mockResolvedValue([{ id: "iss-1", tenant_id: "t1", name: "Internal CA", kind: "x509_ca", internal: true }]);
    apiMock.platformSystem.mockResolvedValue({ signer_mode: "external", dependencies: [{ name: "signer", ready: true }] });
    apiMock.createEnrollmentToken.mockResolvedValue({ token: "BOOT-TOKEN-DESIGN-001" });
    apiMock.agents.mockResolvedValue([{ id: "agent-1", tenant_id: "t1", name: "edge-01", status: "online" }]);
    apiMock.createOwner.mockResolvedValue({ id: "owner-1", ownership_complete: true, ownership_current: false });
    apiMock.attestOwner.mockResolvedValue({ id: "owner-1", ownership_complete: true, ownership_current: true });
    apiMock.issueCertificate.mockResolvedValue({ id: "id-1", tenant_id: "t1", name: "payments", kind: "x509_certificate", status: "issued" });
    apiMock.protocolProfileStatus.mockResolvedValue({
      profile: "eval",
      active: false,
      protocols: ["acme", "est", "scep", "cmp", "ssh", "tsa", "spiffe"],
    });
    apiMock.activateProtocolProfile.mockResolvedValue({
      profile: "eval",
      active: true,
      protocols: ["acme", "est", "scep", "cmp", "ssh", "tsa", "spiffe"],
    });
    apiMock.connectorCatalog.mockResolvedValue({ items: [] });
    apiMock.externalCAs.mockResolvedValue([]);
  });

  it("keeps the wizard order aligned with docs and names the issuance credential boundary", async () => {
    const user = userEvent.setup();
    renderWizard();

    expect(screen.getByRole("heading", { name: "Confirm certificate signing" })).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Check signing health" }));
    await waitFor(() => expect(apiMock.issuers).toHaveBeenCalledTimes(1));
    await user.click(screen.getByRole("button", { name: "Next: enable protocols" }));

    expect(await screen.findByRole("heading", { name: "Enable enrollment protocols" })).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Activate eval protocol profile" }));
    await waitFor(() => expect(apiMock.activateProtocolProfile).toHaveBeenCalledTimes(1));
    await user.click(screen.getByRole("button", { name: "Next: issue certificate" }));

    expect(await screen.findByRole("heading", { name: "Issue your first certificate" })).toBeInTheDocument();
    expect(screen.getByText(/operator credential with certificate issuance authority/i)).toBeInTheDocument();
    await user.type(screen.getByLabelText("Service name"), "payments");
    await user.type(screen.getByLabelText("Application ID"), "APP-PAYMENTS");
    await user.type(screen.getByLabelText("Environment"), "production");
    await user.type(screen.getByLabelText("Alert contact"), "web-team@example.test");
    await user.click(screen.getByLabelText("I confirm this application owns the certificate"));
    await user.click(screen.getByRole("button", { name: "Issue certificate" }));
    await waitFor(() => expect(apiMock.issueCertificate).toHaveBeenCalledWith({ name: "payments", ownerId: "owner-1" }));
    await user.click(screen.getByRole("button", { name: "Next: prove integrations" }));
    expect(await screen.findByRole("heading", { name: "Verify configured integrations" })).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Skip integration proof for now" }));
    await user.click(screen.getByRole("button", { name: "Next: optional agent" }));

    expect(await screen.findByRole("heading", { name: "Connect an agent (optional)", level: 3 })).toBeInTheDocument();
    await user.type(screen.getByLabelText("Agent identity"), "edge-01");
    await user.click(screen.getByRole("button", { name: "Mint enrollment token" }));
    await waitFor(() => expect(apiMock.createEnrollmentToken).toHaveBeenCalledWith({ allowed_identity: "edge-01" }));
    expect(await screen.findByText("BOOT-TOKEN-DESIGN-001")).toBeInTheDocument();
    expect(screen.getByText(/enrollment token.*cannot issue certificates/i)).toBeInTheDocument();
  });
});
