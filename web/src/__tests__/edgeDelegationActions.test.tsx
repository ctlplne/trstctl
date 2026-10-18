import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { EdgeDelegationsPanel } from "@/components/EdgeDelegationsPanel";
import { AppQueryProvider } from "@/lib/query";

const { apiMock, principal } = vi.hoisted(() => ({
  apiMock: {
    edgeSegmentPolicies: vi.fn(),
    edgeDelegations: vi.fn(),
    edgeDelegation: vi.fn(),
    setEdgeSegmentPolicy: vi.fn(),
    createDiscoverySegment: vi.fn(),
    mintEdgeDelegation: vi.fn(),
    revokeEdgeDelegation: vi.fn(),
    reconcileEdgeDelegation: vi.fn(),
  },
  principal: { permissions: ["issuers:read", "issuers:write"] as string[] },
}));

vi.mock("@/lib/api", async (orig) => ({
  ...(await orig<typeof import("@/lib/api")>()),
  api: apiMock,
}));
vi.mock("@/auth/AuthProvider", async (orig) => ({
  ...(await orig<typeof import("@/auth/AuthProvider")>()),
  useAuth: () => ({ user: principal }),
}));

describe("delegated Edge CA console lifecycle", () => {
  const segmentID = "278f7f74-7ad6-5d5d-b8fb-400b5eb67b11";
  const caID = "63cf5ef4-4c23-4b98-97cc-5418e557ae14";
  const delegation = {
    id: "49d2051c-8d27-41b3-af96-485316273352",
    segment_id: segmentID,
    ca_id: caID,
    host: "edge-host.qa.invalid",
    common_name: "edge-host.qa.invalid",
    serial: "21",
    status: "active",
    csr_key_sha256: "f".repeat(64),
    certificate_pem: "-----BEGIN CERTIFICATE-----\nUUFURURHRQ==\n-----END CERTIFICATE-----\n",
    custody_assurance: "hardware_key_attested",
    key_provider: "tpm2",
    key_storage: "device_bound",
    key_exportable: false,
    permitted_dns_domains: ["edge.qa.invalid"],
    not_after: "2026-10-19T10:00:00Z",
    not_before: "2026-10-18T10:00:00Z",
  };

  beforeEach(() => {
    vi.clearAllMocks();
    apiMock.edgeSegmentPolicies.mockResolvedValue({
      items: [
        {
          segment_id: "278f7f74-7ad6-5d5d-b8fb-400b5eb67b11",
          segment_name: "edge-lab",
          enabled: true,
          attestation_roots: 1,
          permitted_dns_domains: ["edge.qa.invalid"],
          allowed_key_providers: ["tpm2"],
          updated_at: "2026-10-18T10:00:00Z",
        },
      ],
      guidance: "",
    });
    apiMock.edgeDelegations.mockResolvedValue({ items: [], guidance: "" });
    apiMock.edgeDelegation.mockResolvedValue({ delegation });
  });

  it("lets an issuer start a reviewed mint from the actual Edge panel", async () => {
    render(
      <AppQueryProvider>
        <EdgeDelegationsPanel />
      </AppQueryProvider>,
    );
    expect(await screen.findByRole("button", { name: "Mint delegated edge CA" })).toBeInTheDocument();
  });

  it("rejects an unseen segment and keeps the reviewed mint key after a lost response", async () => {
    apiMock.mintEdgeDelegation.mockRejectedValueOnce(new Error("response lost")).mockResolvedValue(delegation);
    const user = userEvent.setup();
    render(
      <AppQueryProvider>
        <EdgeDelegationsPanel />
      </AppQueryProvider>,
    );
    await user.click(await screen.findByRole("button", { name: "Mint delegated edge CA" }));
    const input = await screen.findByLabelText("Mint request JSON");
    const request = { segment_id: segmentID, ca_id: caID, host: delegation.host, key_provider: "tpm2", csr_der: "Y3Ny", attestation_credential_json: "e30=" };
    fireEvent.change(input, { target: { value: JSON.stringify({ ...request, segment_id: caID }) } });
    await user.click(screen.getByRole("button", { name: "Review mint request" }));
    expect(screen.getByRole("alert")).toHaveTextContent("Enable this segment");
    expect(apiMock.mintEdgeDelegation).not.toHaveBeenCalled();
    fireEvent.change(input, { target: { value: JSON.stringify(request) } });
    await user.click(screen.getByRole("button", { name: "Review mint request" }));
    expect(screen.getByText(delegation.host)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Mint reviewed delegated CA" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("response lost");
    await user.click(screen.getByRole("button", { name: "Mint reviewed delegated CA" }));
    await waitFor(() => expect(apiMock.edgeDelegation).toHaveBeenCalledWith(delegation.id));
    expect(apiMock.mintEdgeDelegation).toHaveBeenCalledTimes(2);
    expect(apiMock.mintEdgeDelegation.mock.calls[0][1]).toBe(apiMock.mintEdgeDelegation.mock.calls[1][1]);
    expect(screen.getByRole("status")).toHaveTextContent("Minted and read back");
    expect(screen.getByLabelText("Public delegated CA certificate chain")).toHaveValue(delegation.certificate_pem);
  });

  it("reviews the exact CA serial before revocation and verifies readback", async () => {
    apiMock.edgeDelegations.mockResolvedValue({ items: [delegation], guidance: "" });
    apiMock.revokeEdgeDelegation.mockResolvedValue({ ...delegation, status: "revoked" });
    apiMock.edgeDelegation.mockResolvedValue({ delegation: { ...delegation, status: "revoked" } });
    const user = userEvent.setup();
    render(
      <AppQueryProvider>
        <EdgeDelegationsPanel />
      </AppQueryProvider>,
    );
    await user.click(await screen.findByRole("button", { name: "Mint delegated edge CA" }));
    await user.click(screen.getByRole("button", { name: "Revoke delegated edge CA" }));
    await user.selectOptions(screen.getByLabelText("Delegated CA"), delegation.id);
    await user.type(screen.getByLabelText("Revocation reason"), "Host custody lost");
    await user.click(screen.getByRole("button", { name: "Review revocation" }));
    expect(screen.getByText(delegation.serial)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Revoke reviewed delegated CA" }));
    await waitFor(() => expect(apiMock.revokeEdgeDelegation).toHaveBeenCalledWith(delegation.id, { reason: "Host custody lost" }, expect.any(String)));
    expect(screen.getByRole("status")).toHaveTextContent("Revoked and read back");
  });

  it("binds a host journal to the selected delegation before reconciliation", async () => {
    apiMock.edgeDelegations.mockResolvedValue({ items: [delegation], guidance: "" });
    apiMock.reconcileEdgeDelegation.mockResolvedValue({ reconciled: 1, already: 0, violations: 0, rejected: 0 });
    apiMock.edgeDelegation
      .mockResolvedValueOnce({ delegation, issuances: [] })
      .mockResolvedValueOnce({ delegation, issuances: [{ serial: "31", subject: "db.edge.qa.invalid", within_constraints: true }] });
    const user = userEvent.setup();
    render(
      <AppQueryProvider>
        <EdgeDelegationsPanel />
      </AppQueryProvider>,
    );
    await user.click(await screen.findByRole("button", { name: "Mint delegated edge CA" }));
    await user.click(screen.getByRole("button", { name: "Reconcile host journal" }));
    await user.selectOptions(screen.getByLabelText("Delegated CA"), delegation.id);
    const journal = screen.getByLabelText("Issuance journal JSON");
    fireEvent.change(journal, { target: { value: JSON.stringify({ host: "wrong-host", certificates_pem: [delegation.certificate_pem] }) } });
    await user.click(screen.getByRole("button", { name: "Review journal" }));
    expect(screen.getByRole("alert")).toHaveTextContent("must match the selected delegation");
    expect(apiMock.reconcileEdgeDelegation).not.toHaveBeenCalled();
    fireEvent.change(journal, { target: { value: JSON.stringify({ host: delegation.host, certificates_pem: [delegation.certificate_pem] }) } });
    await user.click(screen.getByRole("button", { name: "Review journal" }));
    await user.click(screen.getByRole("button", { name: "Reconcile reviewed journal" }));
    await waitFor(() =>
      expect(apiMock.reconcileEdgeDelegation).toHaveBeenCalledWith(
        delegation.id,
        { host: delegation.host, certificates_pem: [delegation.certificate_pem] },
        expect.any(String),
      ),
    );
    expect(screen.getByRole("status")).toHaveTextContent("Reconciled 1");
  });
});
