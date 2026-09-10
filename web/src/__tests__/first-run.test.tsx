import { AppQueryProvider } from "@/lib/query";
import { installWizardWireFixture, wizardFixtureCSR } from "@/test/wizardWireFixture";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { Wizard } from "@/pages/Wizard";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    issuers: vi.fn(),
    platformSystem: vi.fn(),
    protocolProfileStatus: vi.fn(),
    activateProtocolProfile: vi.fn(),
    createOwner: vi.fn(),
    attestOwner: vi.fn(),
    transitionIdentity: vi.fn(),
    connectorCatalog: vi.fn(),
    createConnectorTarget: vi.fn(),
    deployConnectorTarget: vi.fn(),
    externalCAs: vi.fn(),
    issueExternalCA: vi.fn(),
    issueDynamicLease: vi.fn(),
    createEnrollmentToken: vi.fn(),
    agents: vi.fn(),
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

describe("first-run served capability journey", () => {
  beforeEach(() => {
    for (const mock of Object.values(apiMock)) mock.mockReset();
    installWizardWireFixture(apiMock, "identity-1");
    apiMock.issuers.mockResolvedValue([{ id: "issuer-1", name: "Internal CA", internal: true }]);
    apiMock.platformSystem.mockResolvedValue({ signer_mode: "external", dependencies: [{ name: "signer", ready: true }] });
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
    apiMock.createOwner.mockResolvedValue({ id: "owner-1", ownership_complete: true, ownership_current: false });
    apiMock.attestOwner.mockResolvedValue({ id: "owner-1", ownership_complete: true, ownership_current: true });
    apiMock.transitionIdentity.mockResolvedValue({
      id: "identity-1",
      name: "payments",
      owner_id: "owner-1",
      kind: "x509_certificate",
      status: "issued",
    });
    apiMock.connectorCatalog.mockResolvedValue({
      items: [{ kind: "nginx", name: "NGINX", delivery_mode: "native", rollback: "verified" }],
    });
    apiMock.createConnectorTarget.mockResolvedValue({
      id: "target-1",
      tenant_id: "tenant-1",
      name: "first-nginx",
      connector: "nginx",
      config: { base_url: "https://nginx.example" },
      created_at: "2026-07-12T00:00:00Z",
    });
    apiMock.deployConnectorTarget.mockResolvedValue({
      id: "identity-1",
      name: "payments",
      owner_id: "owner-1",
      kind: "x509_certificate",
      status: "issued",
    });
    apiMock.externalCAs.mockResolvedValue([{ id: "step-ca", name: "Step CA", type: "step", status: "ready" }]);
    apiMock.issueExternalCA.mockResolvedValue({
      certificate_pem: "-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----",
      issuer: "Step CA",
      not_after: "2026-07-13T00:00:00Z",
      serial: "01",
    });
    apiMock.issueDynamicLease.mockResolvedValue({
      id: "lease-1",
      provider: "postgres",
      role: "readonly",
      state: "active",
      issued_at: "2026-07-12T00:00:00Z",
      expires_at: "2026-07-12T00:15:00Z",
      credential: "must-not-be-rendered",
    });
    apiMock.createEnrollmentToken.mockResolvedValue({
      token: "BOOT-TOKEN-XYZ",
      enroll_path: "/enroll/bootstrap",
      agent_server: "localhost:19443",
      agent_server_name: "localhost",
      roles: ["host"],
    });
    apiMock.agents.mockResolvedValue([{ id: "agent-1", name: "edge-01", status: "online" }]);
  });

  it("issues, deploys, exercises an upstream CA and lease backend, then enrolls", async () => {
    const user = userEvent.setup();
    render(
      <MemoryRouter>
        <AppQueryProvider>
          <Wizard pollMs={50} />
        </AppQueryProvider>
      </MemoryRouter>,
    );

    await user.click(screen.getByRole("button", { name: /check signing health/i }));
    await screen.findByText(/separate signer health check passed/i);
    await user.click(screen.getByRole("button", { name: /next: enable protocols/i }));
    await user.click(await screen.findByRole("button", { name: /activate eval protocol profile/i }));
    await screen.findByText(/eval protocol profile is active/i);
    await user.click(screen.getByRole("button", { name: /next: issue certificate/i }));
    await user.type(await screen.findByLabelText(/service name/i), "payments");
    await user.type(screen.getByLabelText("Application ID"), "APP-PAYMENTS");
    await user.type(screen.getByLabelText("Environment"), "production");
    await user.type(screen.getByLabelText("Alert contact"), "web-team@example.test");
    await user.click(screen.getByLabelText("I confirm this application owns the certificate"));
    await user.type(screen.getByLabelText("Public certificate request (CSR)"), wizardFixtureCSR);
    await user.click(screen.getByRole("button", { name: /^issue certificate$/i }));
    await waitFor(() => expect(apiMock.transitionIdentity).toHaveBeenCalledWith(expect.objectContaining({ to: "issued", subject_csr_pem: wizardFixtureCSR })));
    await screen.findByRole("button", { name: "Download leaf certificate" });
    await screen.findByRole("button", { name: "Download leaf certificate" });
    await user.click(await screen.findByRole("button", { name: /next: prove integrations/i }));

    expect(await screen.findByRole("heading", { name: /verify configured integrations/i })).toBeInTheDocument();
    await waitFor(() => expect(apiMock.connectorCatalog).toHaveBeenCalledTimes(1));
    await waitFor(() => expect(apiMock.externalCAs).toHaveBeenCalledTimes(1));

    expect(screen.getByLabelText(/connector target config/i)).toHaveValue('{"base_url":"https://nginx.example"}');
    await user.click(screen.getByRole("button", { name: /deploy through connector/i }));
    await waitFor(() =>
      expect(apiMock.createConnectorTarget).toHaveBeenCalledWith({
        name: "first-nginx",
        connector: "nginx",
        config: { base_url: "https://nginx.example" },
      }),
    );
    await waitFor(() =>
      expect(apiMock.deployConnectorTarget).toHaveBeenCalledWith("target-1", {
        identity_id: "identity-1",
        reason: "first-run connector verification",
      }),
    );

    await user.type(screen.getByLabelText(/external ca csr/i), "-----BEGIN CERTIFICATE REQUEST-----\nrequest\n-----END CERTIFICATE REQUEST-----");
    await user.type(screen.getByLabelText(/external ca dns names/i), "payments.example.com");
    await user.click(screen.getByRole("button", { name: /issue through external ca/i }));
    await waitFor(() =>
      expect(apiMock.issueExternalCA).toHaveBeenCalledWith("step-ca", {
        csr_pem: "-----BEGIN CERTIFICATE REQUEST-----\nrequest\n-----END CERTIFICATE REQUEST-----",
        dns_names: ["payments.example.com"],
        ttl_seconds: 900,
      }),
    );

    await user.click(screen.getByRole("button", { name: /issue dynamic lease/i }));
    await waitFor(() => expect(apiMock.issueDynamicLease).toHaveBeenCalledWith({ provider: "postgres", role: "readonly", ttl_seconds: 900 }));
    expect(screen.queryByText("must-not-be-rendered")).not.toBeInTheDocument();

    await user.click(await screen.findByRole("button", { name: /next: optional agent/i }));
    await user.type(await screen.findByLabelText(/agent identity/i), "edge-01");
    await user.click(screen.getByRole("button", { name: /mint enrollment token/i }));
    await user.click(screen.getByRole("button", { name: /check (for agent|now)/i }));
    await screen.findByText(/agent edge-01 registered/i);

    expect(apiMock.deployConnectorTarget).toHaveBeenCalledTimes(1);
    expect(apiMock.issueExternalCA).toHaveBeenCalledTimes(1);
    expect(apiMock.issueDynamicLease).toHaveBeenCalledTimes(1);
  });
});
