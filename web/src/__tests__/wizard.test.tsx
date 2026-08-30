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
    issueCertificate: vi.fn(),
    protocolProfileStatus: vi.fn(),
    activateProtocolProfile: vi.fn(),
    connectorCatalog: vi.fn(),
    externalCAs: vi.fn(),
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

async function issueFirstCertificate(user: ReturnType<typeof userEvent.setup>, name = "payments") {
  const serviceName = await screen.findByLabelText(/service name/i);
  await user.clear(serviceName);
  await user.type(serviceName, name);
  await user.type(screen.getByLabelText("Application ID"), "APP-PAYMENTS");
  await user.type(screen.getByLabelText("Environment"), "production");
  await user.click(screen.getByLabelText("I confirm this application owns the certificate"));
  await user.click(screen.getByRole("button", { name: /issue certificate/i }));
}

describe("first-run wizard", () => {
  beforeEach(() => {
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
    expect(screen.getByText(/built-in setup issuer/i)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /check signing health/i }));
    await waitFor(() => expect(apiMock.issuers).toHaveBeenCalled());
    await waitFor(() => expect(screen.getByText(/internal ca.*signer health check passed/i)).toBeInTheDocument());
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
      }),
    );
    expect(apiMock.attestOwner).toHaveBeenCalledWith("owner-1");
    expect(apiMock.issueCertificate).toHaveBeenCalledWith({ name: "payments", ownerId: "owner-1" });
    expect(screen.getByRole("link", { name: /open certificate inventory/i })).toHaveAttribute("href", "/certificates");
    await user.click(screen.getByRole("button", { name: /next: prove integrations/i }));

    // Step 4 — configured integration proof is optional on a core-only install.
    expect(await screen.findByRole("heading", { name: /verify configured integrations/i })).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /skip integration proof/i }));
    await user.click(screen.getByRole("button", { name: /next: optional agent/i }));

    // Step 5 — install an agent: a one-time token is minted and shown in the
    // install command, then the wizard detects the agent's registration.
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

    expect(await screen.findByText(/ready for certificate operations/i)).toBeInTheDocument();
  });

  it("does not promise automatic renewal after setup and links to the track/renew worklist", async () => {
    const user = userEvent.setup();
    renderWizard();

    await user.click(screen.getByRole("button", { name: /check signing health/i }));
    await waitFor(() => expect(screen.getByText(/internal ca.*signer health check passed/i)).toBeInTheDocument());
    await user.click(screen.getByRole("button", { name: /next: enable protocols/i }));
    await screen.findByRole("heading", { name: /enable enrollment protocols/i });
    await user.click(screen.getByRole("button", { name: /activate eval protocol profile/i }));
    await screen.findByText(/eval protocol profile is active/i);
    await user.click(screen.getByRole("button", { name: /next: issue certificate/i }));
    await issueFirstCertificate(user);
    await user.click(await screen.findByRole("button", { name: /next: prove integrations/i }));
    await screen.findByRole("heading", { name: /verify configured integrations/i });
    await user.click(screen.getByRole("button", { name: /skip integration proof/i }));
    await user.click(screen.getByRole("button", { name: /next: optional agent/i }));
    await user.click(await screen.findByRole("button", { name: /check (for agent|now)/i }));
    await waitFor(() => expect(screen.getByText(/edge-01/)).toBeInTheDocument());
    await user.click(screen.getByRole("button", { name: /next: review setup/i }));
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

    await user.click(screen.getByRole("button", { name: /check signing health/i }));
    await waitFor(() => expect(screen.getByText(/internal ca.*signer health check passed/i)).toBeInTheDocument());
    await user.click(screen.getByRole("button", { name: /next: enable protocols/i }));
    await screen.findByRole("heading", { name: /enable enrollment protocols/i });
    await user.click(screen.getByRole("button", { name: /activate eval protocol profile/i }));
    await screen.findByText(/eval protocol profile is active/i);
    await user.click(screen.getByRole("button", { name: /next: issue certificate/i }));
    await issueFirstCertificate(user);

    expect(await screen.findByRole("alert")).toHaveTextContent(/boom|could not|failed/i);
    expect(apiMock.createIssuer).not.toHaveBeenCalled();

    await user.click(screen.getByRole("button", { name: /issue certificate/i }));
    await waitFor(() => expect(apiMock.issueCertificate).toHaveBeenCalledTimes(2));
    expect(apiMock.createOwner).toHaveBeenCalledTimes(1);
    expect(apiMock.attestOwner).toHaveBeenCalledTimes(1);
  });

  it("does not invent an issuer row and explains exactly what an empty catalog proves", async () => {
    apiMock.issuers.mockResolvedValueOnce([]);
    const user = userEvent.setup();
    renderWizard();

    await user.click(screen.getByRole("button", { name: /check signing health/i }));

    expect(await screen.findByText(/built-in setup issuer is selected/i)).toBeInTheDocument();
    expect(screen.getByText(/next certificate step proves end-to-end signing/i)).toBeInTheDocument();
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
    await user.click(await screen.findByRole("button", { name: /next: prove integrations/i }));
    await user.click(await screen.findByRole("button", { name: /skip integration proof/i }));
    await user.click(screen.getByRole("button", { name: /next: optional agent/i }));

    await user.click(await screen.findByRole("button", { name: /skip agent for now/i }));
    expect(screen.getByText(/no agent was enrolled/i)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /next: review setup/i }));

    expect(await screen.findByText(/optional step deferred/i)).toBeInTheDocument();
    expect(apiMock.createEnrollmentToken).not.toHaveBeenCalled();
  });
});
