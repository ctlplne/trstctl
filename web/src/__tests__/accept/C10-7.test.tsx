import { AppQueryProvider } from "@/lib/query";
import { installWizardWireFixture, wizardFixtureCSR } from "@/test/wizardWireFixture";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { Wizard } from "@/pages/Wizard";
import { ApiError } from "@/lib/api";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    createIssuer: vi.fn(),
    issuers: vi.fn(),
    platformSystem: vi.fn(),
    createEnrollmentToken: vi.fn(),
    agents: vi.fn(),
    createOwner: vi.fn(),
    attestOwner: vi.fn(),
    transitionIdentity: vi.fn(),
    protocolProfileStatus: vi.fn(),
    activateProtocolProfile: vi.fn(),
    connectorCatalog: vi.fn(),
    externalCAs: vi.fn(),
  },
}));

vi.mock("@/auth/AuthProvider", async (orig) => ({
  ...(await orig<typeof import("@/auth/AuthProvider")>()),
  useAuth: () => ({ user: { tenant_id: "t1", subject: "operator-1" }, preview: false }),
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
      <AppQueryProvider>
        <Wizard pollMs={10} />
      </AppQueryProvider>
    </MemoryRouter>,
  );
}

async function completeOwnerFields(user: ReturnType<typeof userEvent.setup>) {
  await user.type(screen.getByLabelText("Application ID"), "APP-PAYMENTS");
  await user.type(screen.getByLabelText("Environment"), "production");
  await user.type(screen.getByLabelText("Alert contact"), "web-team@example.test");
  await user.click(screen.getByLabelText("I confirm this application owns the certificate"));
  await user.type(screen.getByLabelText("Public certificate request (CSR)"), wizardFixtureCSR);
}

async function openIntegrationStep() {
  const user = userEvent.setup();
  renderWizard();
  await user.click(screen.getByRole("button", { name: "Check signing health" }));
  await user.click(await screen.findByRole("button", { name: "Next: enable protocols" }));
  await user.click(await screen.findByRole("button", { name: "Activate eval protocol profile" }));
  await user.click(await screen.findByRole("button", { name: "Next: issue certificate" }));
  await user.type(await screen.findByLabelText("Service name"), "catalog-proof");
  await completeOwnerFields(user);
  await user.click(screen.getByRole("button", { name: "Issue certificate" }));
  await screen.findByRole("button", { name: "Download leaf certificate" });
  await user.click(await screen.findByRole("button", { name: "Next: prove integrations" }));
  return user;
}

describe("C10-7 carousel onboarding wizard", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    mockMatchMedia(false);
    for (const mock of Object.values(apiMock)) mock.mockReset();
    installWizardWireFixture(apiMock);
    apiMock.issuers.mockResolvedValue([{ id: "iss-1", tenant_id: "t1", name: "Internal CA", kind: "x509_ca", internal: true }]);
    apiMock.platformSystem.mockResolvedValue({ signer_mode: "external", dependencies: [{ name: "signer", ready: true }] });
    apiMock.createEnrollmentToken.mockResolvedValue({ token: "BOOT-TOKEN-C10" });
    apiMock.agents.mockResolvedValue([{ id: "agent-1", tenant_id: "t1", name: "edge-01", status: "online" }]);
    apiMock.createOwner.mockResolvedValue({ id: "owner-1", ownership_complete: true, ownership_current: false });
    apiMock.attestOwner.mockResolvedValue({ id: "owner-1", ownership_complete: true, ownership_current: true });
    apiMock.transitionIdentity.mockResolvedValue({ id: "id-1", tenant_id: "t1", name: "payments", kind: "x509_certificate", status: "issued" });
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
    await waitFor(() => expect(apiMock.platformSystem).toHaveBeenCalledTimes(1));
    expect(apiMock.createIssuer).not.toHaveBeenCalled();
    expect(await screen.findByText("The separate signer health check passed. This does not select or verify a certificate authority.")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Next: enable protocols" }));

    expect(await screen.findByRole("heading", { name: "Enable enrollment protocols" })).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Activate eval protocol profile" }));
    await waitFor(() => expect(apiMock.activateProtocolProfile).toHaveBeenCalledTimes(1));
    await user.click(screen.getByRole("button", { name: "Next: issue certificate" }));

    await user.type(await screen.findByLabelText("Service name"), "payments");
    await completeOwnerFields(user);
    await user.click(screen.getByRole("button", { name: "Issue certificate" }));
    await waitFor(() => expect(apiMock.transitionIdentity).toHaveBeenCalledWith(expect.objectContaining({ to: "issued", subject_csr_pem: wizardFixtureCSR })));
    await screen.findByRole("button", { name: "Download leaf certificate" });
    await screen.findByRole("button", { name: "Download leaf certificate" });
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

    expect(await screen.findByRole("heading", { name: "Review recorded setup" })).toBeInTheDocument();
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

  it("treats intentionally unavailable optional catalogs as a calm core-only state", async () => {
    apiMock.connectorCatalog.mockRejectedValue(new ApiError(503, "connector subsystem is not enabled"));
    apiMock.externalCAs.mockRejectedValue(new ApiError(404, "external CA catalog is not mounted"));

    await openIntegrationStep();

    expect(await screen.findByText(/No optional integrations are configured.*Your certificate works/)).toBeInTheDocument();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Deploy the issued identity through a connector" })).not.toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Issue with a configured upstream CA" })).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Skip integration proof for now" })).toBeEnabled();
  });

  it("keeps an unexpected catalog failure visible and retryable", async () => {
    apiMock.connectorCatalog.mockRejectedValue(new ApiError(500, "catalog database failed"));
    apiMock.externalCAs.mockResolvedValue([]);
    const user = await openIntegrationStep();

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("trstctl could not verify the optional integration catalogs");
    expect(alert).not.toHaveTextContent("catalog database failed");
    await user.click(screen.getByRole("button", { name: "Try again" }));
    await waitFor(() => expect(apiMock.connectorCatalog).toHaveBeenCalledTimes(2));
  });
});
