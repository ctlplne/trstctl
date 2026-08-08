import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { ToastProvider } from "@/components/ToastProvider";
import { ApiError, type Issuer } from "@/lib/api";
import { CAHierarchy } from "@/pages/CAHierarchy";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    issuers: vi.fn(),
    createIssuer: vi.fn(),
    externalCAs: vi.fn(),
    caDiscoveryInventory: vi.fn(),
    profiles: vi.fn(),
    createCACeremony: vi.fn(),
    approveCACeremony: vi.fn(),
    generateManagedKey: vi.fn(),
    rotateManagedKey: vi.fn(),
    revokeManagedKey: vi.fn(),
    zeroizeManagedKey: vi.fn(),
    caAuthorities: vi.fn(),
    edgeSegmentPolicies: vi.fn(),
    edgeDelegations: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: apiMock };
});

const caChain = "-----BEGIN CERTIFICATE-----\nMIIBexample\n-----END CERTIFICATE-----";

function issuer(partial: Partial<Issuer>): Issuer {
  return {
    id: "iss-1",
    name: "Issuer",
    kind: "x509_ca",
    internal: false,
    chain: [caChain],
    ...partial,
  };
}

function renderCAHierarchy() {
  return render(
    <MemoryRouter>
      <ToastProvider>
        <CAHierarchy />
      </ToastProvider>
    </MemoryRouter>,
  );
}

describe("C10-1 issuer catalog and connection tests", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    for (const mock of Object.values(apiMock)) mock.mockReset();
    apiMock.caAuthorities.mockResolvedValue({ items: [] });
    apiMock.edgeSegmentPolicies.mockResolvedValue({ items: [], guidance: "" });
    apiMock.edgeDelegations.mockResolvedValue({ items: [], guidance: "" });
    apiMock.issuers.mockResolvedValue([
      issuer({ id: "acme-prod", name: "Production ACME" }),
      issuer({ id: "missing-upstream", name: "Unregistered External" }),
    ]);
    apiMock.profiles.mockResolvedValue([]);
    apiMock.caDiscoveryInventory.mockResolvedValue({
      items: [],
      summary: {
        public_count: 0,
        private_count: 0,
        external_registry_count: 0,
        authority_count: 0,
      },
    });
    apiMock.externalCAs.mockResolvedValue([{ id: "acme-prod", name: "ACME", type: "ACME", status: "available" }]);
    apiMock.createIssuer.mockResolvedValue(issuer({ id: "created-acme", name: "Created ACME" }));
    apiMock.createCACeremony.mockResolvedValue({
      id: "ceremony-root-1",
      tenant_id: "tenant-1",
      purpose: "create_root:Trust Root CA",
      threshold: 2,
      status: "pending",
      approvals: 1,
      opener: "ra@example.test",
      created_at: "2026-06-26T14:00:00Z",
    });
    apiMock.approveCACeremony.mockResolvedValue({
      id: "ceremony-root-1",
      tenant_id: "tenant-1",
      purpose: "create_root:Trust Root CA",
      threshold: 2,
      status: "approved",
      approvals: 2,
      opener: "ra@example.test",
      created_at: "2026-06-26T14:00:00Z",
    });
    apiMock.generateManagedKey.mockResolvedValue({ key_id: "kms/root-1", algorithm: "ECDSA-P256", version: 1, state: "active", public_der: "BASE64PUBLICDER" });
    apiMock.rotateManagedKey.mockResolvedValue({ key_id: "kms/root-1", algorithm: "ECDSA-P256", version: 2, state: "active", public_der: "ROTATEDDER" });
    apiMock.revokeManagedKey.mockResolvedValue({ key_id: "kms/root-1", algorithm: "ECDSA-P256", version: 2, state: "revoked", public_der: "ROTATEDDER" });
    apiMock.zeroizeManagedKey.mockResolvedValue({ key_id: "kms/root-1", algorithm: "ECDSA-P256", version: 2, state: "zeroized" });
  });

  it("renders the CA catalog, creates from a schema form, masks sensitive fields, and probes upstream status", async () => {
    const user = userEvent.setup();
    renderCAHierarchy();

    const catalog = await screen.findByRole("region", { name: "Issuer catalog" });
    expect(within(catalog).getByText("ACME")).toBeInTheDocument();
    expect(within(catalog).getByText("Vault PKI")).toBeInTheDocument();
    expect(within(catalog).getByText("DigiCert CertCentral")).toBeInTheDocument();

    await user.click(within(catalog).getByRole("button", { name: "Configure ACME" }));

    const dialog = await screen.findByRole("dialog", { name: "Configure ACME issuer" });
    await user.type(within(dialog).getByLabelText("Issuer name"), "Created ACME");
    await user.type(within(dialog).getByLabelText("CA chain PEM"), caChain);
    await user.type(within(dialog).getByLabelText("Directory URL"), "https://acme.example/directory");
    await user.type(within(dialog).getByLabelText("Email"), "ops@example.test");
    const hmacInput = within(dialog).getByLabelText("EAB HMAC Key");
    expect(hmacInput).toHaveAttribute("type", "password");
    await user.type(hmacInput, "super-secret-hmac");

    await user.click(within(dialog).getByRole("button", { name: "Create issuer" }));

    await waitFor(() =>
      expect(apiMock.createIssuer).toHaveBeenCalledWith({
        name: "Created ACME",
        kind: "x509_ca",
        internal: false,
        chain: [caChain],
      }),
    );
    expect(JSON.stringify(apiMock.createIssuer.mock.calls[0][0])).not.toContain("super-secret-hmac");

    await user.click(await screen.findByRole("button", { name: "Test connection Production ACME" }));
    expect(await screen.findByText("Production ACME: connection passed")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Test connection Unregistered External" }));
    expect(await screen.findByText("Unregistered External: connection failed")).toBeInTheDocument();

    apiMock.externalCAs.mockRejectedValueOnce(new ApiError(503, JSON.stringify({ detail: "external CA registry is not enabled" })));
    await user.click(screen.getByRole("button", { name: "Test connection Production ACME" }));
    expect(await screen.findByText(/external CA registry is not enabled/)).toBeInTheDocument();
  });
});
