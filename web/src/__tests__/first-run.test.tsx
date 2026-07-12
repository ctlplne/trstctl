import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { Wizard } from "@/pages/Wizard";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    issuers: vi.fn(),
    protocolProfileStatus: vi.fn(),
    activateProtocolProfile: vi.fn(),
    issueCertificate: vi.fn(),
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

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: apiMock };
});

describe("first-run served capability journey", () => {
  beforeEach(() => {
    for (const mock of Object.values(apiMock)) mock.mockReset();
    apiMock.issuers.mockResolvedValue([{ id: "issuer-1", name: "Internal CA", internal: true }]);
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
    apiMock.issueCertificate.mockResolvedValue({
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
    apiMock.createEnrollmentToken.mockResolvedValue({ token: "BOOT-TOKEN-XYZ" });
    apiMock.agents.mockResolvedValue([{ id: "agent-1", name: "edge-01", status: "online" }]);
  });

  it("issues, deploys, exercises an upstream CA and lease backend, then enrolls", async () => {
    const user = userEvent.setup();
    render(
      <MemoryRouter>
        <Wizard pollMs={50} />
      </MemoryRouter>,
    );

    await user.click(screen.getByRole("button", { name: /use internal ca/i }));
    await screen.findByText(/internal ca is ready/i);
    await user.click(screen.getByRole("button", { name: /next: enable protocols/i }));
    await user.click(await screen.findByRole("button", { name: /activate eval protocol profile/i }));
    await screen.findByText(/eval protocol profile is active/i);
    await user.click(screen.getByRole("button", { name: /next: issue certificate/i }));
    await user.type(await screen.findByLabelText(/service name/i), "payments");
    await user.click(screen.getByRole("button", { name: /^issue certificate$/i }));
    await waitFor(() => expect(apiMock.issueCertificate).toHaveBeenCalledWith({ name: "payments" }));
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

    await user.click(await screen.findByRole("button", { name: /next: enroll agent/i }));
    await user.type(await screen.findByLabelText(/agent identity/i), "edge-01");
    await user.click(screen.getByRole("button", { name: /mint enrollment token/i }));
    await user.click(screen.getByRole("button", { name: /check (for agent|now)/i }));
    await screen.findByText(/agent edge-01 registered/i);

    expect(apiMock.deployConnectorTarget).toHaveBeenCalledTimes(1);
    expect(apiMock.issueExternalCA).toHaveBeenCalledTimes(1);
    expect(apiMock.issueDynamicLease).toHaveBeenCalledTimes(1);
  });
});
