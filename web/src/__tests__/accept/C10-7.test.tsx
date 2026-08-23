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

function mockMatchMedia(reducedMotion: boolean) {
  Object.defineProperty(window, "matchMedia", {
    configurable: true,
    writable: true,
    value: (query: string) => ({
      matches: reducedMotion && query.includes("prefers-reduced-motion"),
      media: query,
      onchange: null,
      addListener: () => undefined,
      removeListener: () => undefined,
      addEventListener: () => undefined,
      removeEventListener: () => undefined,
      dispatchEvent: () => false,
    }),
  });
}

function renderWizard() {
  return render(
    <MemoryRouter>
      <Wizard pollMs={10} />
    </MemoryRouter>,
  );
}

describe("C10-7 carousel onboarding wizard", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    mockMatchMedia(false);
    for (const mock of Object.values(apiMock)) mock.mockReset();
    apiMock.issuers.mockResolvedValue([{ id: "iss-1", tenant_id: "t1", name: "Internal CA", kind: "x509_ca", internal: true }]);
    apiMock.platformSystem.mockResolvedValue({ signer_mode: "external", dependencies: [{ name: "signer", ready: true }] });
    apiMock.createEnrollmentToken.mockResolvedValue({ token: "BOOT-TOKEN-C10" });
    apiMock.agents.mockResolvedValue([{ id: "agent-1", tenant_id: "t1", name: "edge-01", status: "online" }]);
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

  it("advances through served issuer, certificate, and agent actions, then latches closed and reopens", async () => {
    const user = userEvent.setup();
    renderWizard();

    expect(screen.getByRole("region", { name: "Onboarding carousel" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Confirm certificate signing" })).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Check signing health" }));
    await waitFor(() => expect(apiMock.issuers).toHaveBeenCalledTimes(1));
    expect(apiMock.createIssuer).not.toHaveBeenCalled();
    expect(await screen.findByText("Internal CA is listed, and the signer health check passed.")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Next: enable protocols" }));

    expect(await screen.findByRole("heading", { name: "Enable enrollment protocols" })).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Activate eval protocol profile" }));
    await waitFor(() => expect(apiMock.activateProtocolProfile).toHaveBeenCalledTimes(1));
    await user.click(screen.getByRole("button", { name: "Next: issue certificate" }));

    await user.type(await screen.findByLabelText("Service name"), "payments");
    await user.click(screen.getByRole("button", { name: "Issue certificate" }));
    await waitFor(() => expect(apiMock.issueCertificate).toHaveBeenCalledWith({ name: "payments" }));
    await user.click(screen.getByRole("button", { name: "Next: prove integrations" }));
    expect(await screen.findByRole("heading", { name: "Verify configured integrations" })).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Skip integration proof for now" }));
    await user.click(screen.getByRole("button", { name: "Next: optional agent" }));

    await user.type(await screen.findByLabelText("Agent identity"), "edge-01");
    await user.click(screen.getByRole("button", { name: "Mint enrollment token" }));
    await waitFor(() => expect(apiMock.createEnrollmentToken).toHaveBeenCalledWith({ allowed_identity: "edge-01" }));
    expect(await screen.findByText("BOOT-TOKEN-C10")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Check for agent" }));
    await waitFor(() => expect(apiMock.agents).toHaveBeenCalled());
    expect(await screen.findByText(/Agent edge-01 registered/i)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Next: review setup" }));

    expect(await screen.findByRole("heading", { name: "Ready for certificate operations" })).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Complete setup" }));

    expect(screen.queryByRole("region", { name: "Onboarding carousel" })).not.toBeInTheDocument();
    expect(await screen.findByRole("heading", { name: "Setup complete" })).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Reopen setup guide" }));
    expect(await screen.findByRole("region", { name: "Onboarding carousel" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Confirm certificate signing" })).toBeInTheDocument();
  });

  it("renders the reduced-motion carousel path without animation", () => {
    mockMatchMedia(true);
    renderWizard();

    expect(screen.getByTestId("onboarding-slide")).toHaveAttribute("data-motion", "reduced");
  });
});
