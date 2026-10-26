import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { RbacProvider } from "@/components/rbac";
import { AppQueryProvider } from "@/lib/query";
import { TSACertificatesPanel } from "@/pages/protocols/TSACertificatesPanel";

const { apiMock } = vi.hoisted(() => ({
  apiMock: { tsaCertificates: vi.fn(), rotateTSACertificate: vi.fn(), revokeTSACertificate: vi.fn() },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});

const certificate = (serial: string, state: "active" | "retired" | "revoked", extra: Record<string, string> = {}) => ({
  serial,
  state,
  not_before: "2026-10-01T00:00:00Z",
  not_after: "2027-10-01T00:00:00Z",
  cert_sha256: "a".repeat(64),
  cert_pem: "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n",
  ...extra,
});

const list = {
  items: [
    certificate("0c3", "active"),
    certificate("0b2", "retired"),
    certificate("0a1", "revoked", { revoked_at: "2026-10-20T00:00:00Z", reason: "keyCompromise" }),
  ],
  crl: "/crl/t1.crl",
  ocsp: "/ocsp/t1",
};

function renderPanel(permissions: string[] | null) {
  return render(
    <AppQueryProvider>
      <RbacProvider permissions={permissions}>
        <TSACertificatesPanel />
      </RbacProvider>
    </AppQueryProvider>,
  );
}

describe("TSA certificates (A145)", () => {
  beforeEach(() => {
    apiMock.tsaCertificates.mockReset().mockResolvedValue(list);
    apiMock.rotateTSACertificate.mockReset().mockResolvedValue({ current: certificate("0d4", "active"), previous: certificate("0c3", "revoked") });
    apiMock.revokeTSACertificate.mockReset().mockResolvedValue(certificate("0b2", "revoked"));
  });

  it("lists each certificate's state and where relying parties check it", async () => {
    renderPanel(["certs:read"]);
    const region = await screen.findByRole("region", { name: "TSA certificates" });
    const items = await within(region).findAllByRole("listitem");
    expect(items).toHaveLength(3);
    expect(within(items[0]).getByText("Active")).toBeInTheDocument();
    expect(within(items[1]).getByText("Retired")).toBeInTheDocument();
    expect(within(items[2]).getByText("Revoked")).toBeInTheDocument();
    expect(within(items[2]).getByText(/keyCompromise/)).toBeInTheDocument();
    expect(within(region).getByText(/\/crl\/t1\.crl/)).toBeInTheDocument();
    // Read-only operators see no rotation or revocation controls.
    expect(within(region).queryByRole("button")).not.toBeInTheDocument();
  });

  it("rotates with a revocation reason and revokes a retired certificate", async () => {
    const user = userEvent.setup();
    renderPanel(["certs:read", "issuers:write"]);
    const region = await screen.findByRole("region", { name: "TSA certificates" });
    await user.selectOptions(await within(region).findByLabelText("Revoke the outgoing certificate"), "keyCompromise");
    await user.click(within(region).getByRole("button", { name: "Rotate the TSA certificate" }));
    await waitFor(() => expect(apiMock.rotateTSACertificate).toHaveBeenCalledWith("keyCompromise"));
    expect(await within(region).findByText("The TSA now signs under a new certificate.")).toBeInTheDocument();

    await user.selectOptions(within(region).getByLabelText("Reason to revoke a retired certificate"), "cessationOfOperation");
    await user.click(within(region).getByRole("button", { name: "Revoke" }));
    await waitFor(() => expect(apiMock.revokeTSACertificate).toHaveBeenCalledWith("0b2", "cessationOfOperation"));
  });

  it("stays out of the way where this tenant does not run the TSA", async () => {
    apiMock.tsaCertificates.mockReset().mockRejectedValue(new Error("not served"));
    const view = renderPanel(null);
    await waitFor(() => expect(apiMock.tsaCertificates).toHaveBeenCalled());
    await waitFor(() => expect(view.container).toBeEmptyDOMElement());
  });
});
