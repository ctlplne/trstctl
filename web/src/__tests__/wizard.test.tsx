import { AppQueryProvider } from "@/lib/query";
import { installWizardWireFixture, wizardFixtureCSR } from "@/test/wizardWireFixture";
import { describe, it, expect, vi, beforeEach } from "vitest";
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
    transitionIdentity: vi.fn(),
    getIdentity: vi.fn(),
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
  return { ...actual, api: apiMock };
});

function renderWizard() {
  return render(
    <MemoryRouter>
      <AppQueryProvider>
        <Wizard pollMs={50} />
      </AppQueryProvider>
    </MemoryRouter>,
  );
}

async function issueFirstCertificate(user: ReturnType<typeof userEvent.setup>, name = "payments") {
  const serviceName = await screen.findByLabelText(/service name/i);
  await user.clear(serviceName);
  await user.type(serviceName, name);
  await user.type(screen.getByLabelText("Application ID"), "APP-PAYMENTS");
  await user.type(screen.getByLabelText("Environment"), "production");
  await user.type(screen.getByLabelText(/alert contact/i), "web-team@example.test");
  await user.click(screen.getByLabelText("I confirm this application owns the certificate"));
  await user.type(screen.getByLabelText("Public certificate request (CSR)"), wizardFixtureCSR);
  await user.click(screen.getByRole("button", { name: /issue certificate/i }));
}

describe("first-run wizard", () => {
  beforeEach(() => {
    installWizardWireFixture(apiMock);
    apiMock.createIssuer.mockReset();
    apiMock.issuers.mockReset().mockResolvedValue([{ id: "iss-1", name: "Internal CA", internal: true }]);
    apiMock.platformSystem.mockReset().mockResolvedValue({
      signer_mode: "external",
      dependencies: [{ name: "signer", ready: true }],
    });
    apiMock.createEnrollmentToken.mockReset().mockResolvedValue({
      token: "BOOT-TOKEN-XYZ",
      enroll_path: "/enroll/bootstrap",
      agent_server: "localhost:19443",
      agent_server_name: "localhost",
      roles: ["host"],
    });
    apiMock.agents.mockReset().mockResolvedValue([{ id: "ag-1", name: "edge-01", status: "online" }]);
    apiMock.createOwner.mockReset().mockResolvedValue({
      id: "owner-1",
      kind: "workload",
      name: "payments",
      application_id: "APP-PAYMENTS",
      environment: "production",
      ownership_complete: true,
      ownership_attested: false,
      ownership_current: false,
    });
    apiMock.attestOwner.mockReset().mockResolvedValue({
      id: "owner-1",
      kind: "workload",
      name: "payments",
      application_id: "APP-PAYMENTS",
      environment: "production",
      ownership_complete: true,
      ownership_attested: true,
      ownership_current: true,
    });
    apiMock.transitionIdentity.mockReset().mockResolvedValue({ id: "id-1", name: "payments", status: "issued" });
    apiMock.getIdentity.mockReset().mockRejectedValue(new Error("not found"));
    localStorage.removeItem("trstctl:onboarding-issued-identity");
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
    apiMock.connectorCatalog.mockReset().mockResolvedValue({ items: [] });
    apiMock.externalCAs.mockReset().mockResolvedValue([]);
  });

  it("walks internal-CA → issue-first-cert → install-agent and completes setup", async () => {
    const user = userEvent.setup();
    renderWizard();

    // Step 1 — use the already-provisioned internal signer-backed CA. The wizard
    // must not post a name-only x509_ca issuer, because the served API rejects X.509
    // issuers without a certificate chain.
    expect(screen.getByRole("heading", { name: /confirm certificate signing/i })).toBeInTheDocument();
    expect(screen.getByText(/completed certificate result names the actual issuer/i)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /check signing health/i }));
    await waitFor(() => expect(apiMock.platformSystem).toHaveBeenCalled());
    await waitFor(() => expect(screen.getByText(/separate signer health check passed/i)).toBeInTheDocument());
    expect(apiMock.platformSystem).toHaveBeenCalledTimes(1);
    expect(apiMock.createIssuer).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: /next: enable protocols/i }));

    // Step 2 — the wizard makes a real authenticated activation call. The
    // server appends durable tenant state before opening the responders.
    expect(await screen.findByRole("heading", { name: /enable enrollment protocols/i })).toBeInTheDocument();
    await waitFor(() => expect(apiMock.protocolProfileStatus).toHaveBeenCalledTimes(1));
    await user.click(screen.getByRole("button", { name: /activate eval protocol profile/i }));
    await waitFor(() => expect(apiMock.activateProtocolProfile).toHaveBeenCalledTimes(1));
    expect(await screen.findByText(/eval protocol profile is active/i)).toBeInTheDocument();
    expect(screen.getByText(/enabled means the tenant may use these responders/i)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /next: issue certificate/i }));

    // Step 3 — issue the first certificate.
    expect(await screen.findByRole("heading", { name: /issue your first certificate/i })).toBeInTheDocument();
    await issueFirstCertificate(user);
    await waitFor(() =>
      expect(apiMock.createOwner).toHaveBeenCalledWith({
        kind: "workload",
        name: "payments",
        service: "payments",
        application_id: "APP-PAYMENTS",
        environment: "production",
        email: "web-team@example.test",
      }),
    );
    expect(apiMock.attestOwner).toHaveBeenCalledWith("owner-1");
    expect(apiMock.transitionIdentity).toHaveBeenCalledWith(expect.objectContaining({ to: "issued", subject_csr_pem: wizardFixtureCSR }));
    await screen.findByRole("button", { name: "Download leaf certificate" });
    expect(screen.getByRole("link", { name: /open certificate inventory/i })).toHaveAttribute("href", "/certificates");
    await screen.findByRole("button", { name: "Download leaf certificate" });
    await user.click(screen.getByRole("button", { name: /next: prove integrations/i }));

    // Step 4 — configured integration proof is optional on a core-only install.
    expect(await screen.findByRole("heading", { name: /verify configured integrations/i })).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /skip integration proof/i }));
    await user.click(screen.getByRole("button", { name: /next: optional agent/i }));

    // Step 5 — install an agent: a one-time token is minted and shown in the
    // install command, then the wizard detects the agent's registration.
    expect(await screen.findByText(/mint a one-time enrollment token to reveal the exact server-verified install command/i)).toBeInTheDocument();
    expect(screen.queryByText(/did not publish its agent endpoint/i)).not.toBeInTheDocument();
    expect(screen.queryByLabelText("Runnable Linux agent command")).not.toBeInTheDocument();
    await user.type(await screen.findByLabelText(/agent identity/i), "edge-01");
    await user.click(screen.getByRole("button", { name: /mint enrollment token/i }));
    await waitFor(() => expect(apiMock.createEnrollmentToken).toHaveBeenCalledWith({ allowed_identity: "edge-01" }));
    expect(await screen.findByText(/BOOT-TOKEN-XYZ/)).toBeInTheDocument();
    const command = screen.getByLabelText("Runnable Linux agent command").textContent ?? "";
    expect(command).toContain("--enroll-url http://localhost");
    expect(command).toContain("--allow-insecure-loopback-enrollment");
    expect(command).toContain("--server localhost:19443");
    expect(command).toContain("--server-name localhost");
    expect(command).toContain("--name edge-01");
    expect(command).toContain("--inventory-cert-roots /etc/ssl,/etc/pki/tls/certs");
    expect(command).not.toContain("/enroll/bootstrap");
    expect(command).not.toContain("<");
    await user.click(screen.getByRole("button", { name: /check (for agent|now)/i }));
    expect(await screen.findByText(/Agent edge-01 registered/i)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /next: review setup/i }));

    expect(await screen.findByText(/review recorded setup/i)).toBeInTheDocument();
  });

  it("does not promise automatic renewal after setup and links to the track/renew worklist", async () => {
    const user = userEvent.setup();
    renderWizard();

    await user.click(screen.getByRole("button", { name: /check signing health/i }));
    await waitFor(() => expect(screen.getByText(/separate signer health check passed/i)).toBeInTheDocument());
    await user.click(screen.getByRole("button", { name: /next: enable protocols/i }));
    await screen.findByRole("heading", { name: /enable enrollment protocols/i });
    await user.click(screen.getByRole("button", { name: /activate eval protocol profile/i }));
    await screen.findByText(/eval protocol profile is active/i);
    await user.click(screen.getByRole("button", { name: /next: issue certificate/i }));
    await issueFirstCertificate(user);
    await screen.findByRole("button", { name: "Download leaf certificate" });
    await screen.findByRole("button", { name: "Download leaf certificate" });
    await user.click(await screen.findByRole("button", { name: /next: prove integrations/i }));
    await screen.findByRole("heading", { name: /verify configured integrations/i });
    await user.click(screen.getByRole("button", { name: /skip integration proof/i }));
    await user.click(screen.getByRole("button", { name: /next: optional agent/i }));
    await user.click(await screen.findByRole("button", { name: /check (for agent|now)/i }));
    await waitFor(() => expect(screen.getByText(/edge-01/)).toBeInTheDocument());
    await user.click(screen.getByRole("button", { name: /next: review setup/i }));
    await user.click(screen.getByRole("button", { name: /complete setup/i }));

    expect(await screen.findByText(/Deployment, TLS checks and renewal are separate lifecycle operations/)).toBeInTheDocument();
    expect(screen.queryByText(/manual, one-click action/i)).not.toBeInTheDocument();
    expect(document.body.textContent).not.toMatch(/rotate.*automatically|renew.*automatically/i);
    expect(screen.getByRole("link", { name: /track and renew certificates/i })).toHaveAttribute("href", "/certificates");
  });

  it("surfaces a failure to issue without creating an issuer", async () => {
    apiMock.transitionIdentity.mockRejectedValueOnce(new Error("boom"));
    const user = userEvent.setup();
    renderWizard();

    await user.click(screen.getByRole("button", { name: /check signing health/i }));
    await waitFor(() => expect(screen.getByText(/separate signer health check passed/i)).toBeInTheDocument());
    await user.click(screen.getByRole("button", { name: /next: enable protocols/i }));
    await screen.findByRole("heading", { name: /enable enrollment protocols/i });
    await user.click(screen.getByRole("button", { name: /activate eval protocol profile/i }));
    await screen.findByText(/eval protocol profile is active/i);
    await user.click(screen.getByRole("button", { name: /next: issue certificate/i }));
    await issueFirstCertificate(user);

    expect(await screen.findByRole("alert")).toHaveTextContent(/uncertain|interrupted/i);
    expect(apiMock.createIssuer).not.toHaveBeenCalled();

    await user.click(screen.getByRole("button", { name: /retry the same issuance attempt/i }));
    await waitFor(() => expect(apiMock.transitionIdentity).toHaveBeenCalledTimes(2));
    expect(apiMock.createOwner).toHaveBeenCalledTimes(1);
    expect(apiMock.attestOwner).toHaveBeenCalledTimes(1);
  });

  it("does not invent an issuer row and explains exactly what an empty catalog proves", async () => {
    apiMock.issuers.mockResolvedValueOnce([]);
    const user = userEvent.setup();
    renderWizard();

    await user.click(screen.getByRole("button", { name: /check signing health/i }));

    expect(await screen.findByText(/does not select or verify a certificate authority/i)).toBeInTheDocument();
    expect(apiMock.issuers).not.toHaveBeenCalled();
    expect(screen.queryByText(/internal ca is ready/i)).not.toBeInTheDocument();
  });

  it("fails closed when the separate signer is not healthy", async () => {
    apiMock.platformSystem.mockResolvedValueOnce({
      signer_mode: "external",
      dependencies: [{ name: "signer", ready: false, error: "unreachable" }],
    });
    const user = userEvent.setup();
    renderWizard();

    await user.click(screen.getByRole("button", { name: /check signing health/i }));

    expect(await screen.findByRole("alert")).toHaveTextContent(/signer.*not healthy|could not prove signing/i);
    expect(screen.getByRole("button", { name: /next: enable protocols/i })).toBeDisabled();
  });

  it("lets a blank install defer the optional agent without pretending one registered", async () => {
    const user = userEvent.setup();
    renderWizard();

    await user.click(screen.getByRole("button", { name: /check signing health/i }));
    await screen.findByText(/signer health check passed/i);
    await user.click(screen.getByRole("button", { name: /next: enable protocols/i }));
    await user.click(await screen.findByRole("button", { name: /activate eval protocol profile/i }));
    await screen.findByText(/eval protocol profile is active/i);
    await user.click(screen.getByRole("button", { name: /next: issue certificate/i }));
    await issueFirstCertificate(user, "first-service");
    await screen.findByRole("button", { name: "Download leaf certificate" });
    await screen.findByRole("button", { name: "Download leaf certificate" });
    await user.click(await screen.findByRole("button", { name: /next: prove integrations/i }));
    await user.click(await screen.findByRole("button", { name: /skip integration proof/i }));
    await user.click(screen.getByRole("button", { name: /next: optional agent/i }));

    await user.click(await screen.findByRole("button", { name: /skip agent for now/i }));
    expect(screen.getByText(/no agent was enrolled/i)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /next: review setup/i }));

    expect(await screen.findByText(/optional step deferred/i)).toBeInTheDocument();
    expect(apiMock.createEnrollmentToken).not.toHaveBeenCalled();
  });

  it("reports a missing public agent endpoint only after the server returns an unusable token response", async () => {
    apiMock.createEnrollmentToken.mockResolvedValueOnce({
      token: "BOOT-TOKEN-NO-ENDPOINT",
      enroll_path: "/enroll/bootstrap",
      agent_server: "",
      agent_server_name: "",
      roles: ["host"],
    });
    const user = userEvent.setup();
    renderWizard();

    await user.click(screen.getByRole("button", { name: /check signing health/i }));
    await screen.findByText(/signer health check passed/i);
    await user.click(screen.getByRole("button", { name: /next: enable protocols/i }));
    await user.click(await screen.findByRole("button", { name: /activate eval protocol profile/i }));
    await screen.findByText(/eval protocol profile is active/i);
    await user.click(screen.getByRole("button", { name: /next: issue certificate/i }));
    await issueFirstCertificate(user, "agent-endpoint-control");
    await screen.findByRole("button", { name: "Download leaf certificate" });
    await screen.findByRole("button", { name: "Download leaf certificate" });
    await user.click(await screen.findByRole("button", { name: /next: prove integrations/i }));
    await user.click(await screen.findByRole("button", { name: /skip integration proof/i }));
    await user.click(screen.getByRole("button", { name: /next: optional agent/i }));

    expect(await screen.findByText(/mint a one-time enrollment token to reveal the exact server-verified install command/i)).toBeInTheDocument();
    expect(screen.queryByText(/did not publish its agent endpoint/i)).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /mint enrollment token/i }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/did not publish its agent endpoint/i);
    expect(screen.queryByText(/reveal the exact server-verified install command/i)).not.toBeInTheDocument();
  });
});

describe("legacy unbound reload hint", () => {
  beforeEach(() => {
    installWizardWireFixture(apiMock);
  });
  it("does not use an old issued identity ID as exact certificate delivery", async () => {
    localStorage.setItem("trstctl:onboarding-issued-identity", "id-1");
    apiMock.getIdentity.mockClear().mockResolvedValue({ id: "id-1", name: "payments", status: "issued" });
    renderWizard();
    await waitFor(() => expect(localStorage.getItem("trstctl:onboarding-issued-identity")).toBeNull());
    expect(apiMock.getIdentity).not.toHaveBeenCalled();
    expect(screen.queryByText(/payments was issued/)).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: /next: enable protocols/i })).toBeDisabled();
  });
  it("does not create or issue anything merely because a prior identity hint is stale", async () => {
    localStorage.setItem("trstctl:onboarding-issued-identity", "id-stale");
    apiMock.createOwner.mockClear();
    apiMock.transitionIdentity.mockClear();
    renderWizard();
    await waitFor(() => expect(localStorage.getItem("trstctl:onboarding-issued-identity")).toBeNull());
    expect(apiMock.createOwner).not.toHaveBeenCalled();
    expect(apiMock.transitionIdentity).not.toHaveBeenCalled();
  });
});
