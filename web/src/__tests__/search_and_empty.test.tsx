import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { Certificates } from "@/pages/Certificates";
import { ApiError, UnauthorizedError } from "@/lib/api";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    certificatePage: vi.fn(),
    getCertificate: vi.fn(),
    ingestCertificate: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: apiMock };
});

function renderCerts() {
  return render(
    <MemoryRouter>
      <Certificates />
    </MemoryRouter>,
  );
}

function primitive(container: HTMLElement, name: string) {
  return container.querySelector(`[data-state-primitive="${name}"]`);
}

describe("inventory search", () => {
  beforeEach(() => {
    apiMock.certificatePage.mockReset();
    apiMock.getCertificate.mockReset();
    apiMock.ingestCertificate.mockReset();
  });

  it("filters the certificate inventory as you type", async () => {
    apiMock.certificatePage.mockResolvedValue({
      items: [
        { id: "c1", subject: "CN=payments.example.com", issuer: "CN=CA", status: "active", fingerprint: "fp1" },
        { id: "c2", subject: "CN=web.example.com", issuer: "CN=CA", status: "active", fingerprint: "fp2" },
      ],
    });
    const user = userEvent.setup();
    renderCerts();

    expect(await screen.findByText("CN=payments.example.com")).toBeInTheDocument();
    expect(screen.getByText("CN=web.example.com")).toBeInTheDocument();

    await user.type(screen.getByRole("searchbox", { name: /search/i }), "payments");

    await waitFor(() => expect(screen.queryByText("CN=web.example.com")).not.toBeInTheDocument());
    expect(screen.getByText("CN=payments.example.com")).toBeInTheDocument();
  });

  it("reports when a search matches nothing", async () => {
    apiMock.certificatePage.mockResolvedValue({
      items: [{ id: "c1", subject: "CN=payments.example.com", status: "active", fingerprint: "fp1" }],
    });
    const user = userEvent.setup();
    renderCerts();

    await screen.findByText("CN=payments.example.com");
    await user.type(screen.getByRole("searchbox", { name: /search/i }), "nomatch");
    expect(await screen.findByText(/no (certificates )?match/i)).toBeInTheDocument();
  });
});

describe("guiding empty states", () => {
  beforeEach(() => {
    apiMock.certificatePage.mockReset();
    apiMock.getCertificate.mockReset();
    apiMock.ingestCertificate.mockReset();
  });

  it("guides a fresh install to the setup wizard when the inventory is empty", async () => {
    apiMock.certificatePage.mockResolvedValue({ items: [] });
    const { container } = renderCerts();

    const cta = await screen.findByRole("link", { name: /set up|get started|first certificate|wizard/i });
    expect(cta).toHaveAttribute("href", expect.stringContaining("/wizard"));
    expect(primitive(container, "empty")).toBeInTheDocument();
  });

  it("shows permission denial when the tenant session cannot read inventory", async () => {
    apiMock.certificatePage.mockRejectedValue(new UnauthorizedError());
    const { container } = renderCerts();

    expect(await screen.findByRole("alert")).toHaveTextContent(/permission denied/i);
    expect(primitive(container, "permission-denied")).toBeInTheDocument();
  });

  it("uses shared loading and error primitives on the representative certificate page", async () => {
    apiMock.certificatePage.mockReturnValueOnce(new Promise(() => undefined));
    const loading = renderCerts();
    expect(await screen.findByRole("status")).toHaveTextContent(/loading certificates/i);
    expect(primitive(loading.container, "loading")).toBeInTheDocument();
    loading.unmount();

    apiMock.certificatePage.mockRejectedValue(new ApiError(500, "database unavailable"));
    const error = renderCerts();
    expect(await screen.findByRole("alert")).toHaveTextContent(/database unavailable/i);
    expect(primitive(error.container, "error")).toBeInTheDocument();
  });
});

describe("certificate inventory gap closure", () => {
  beforeEach(() => {
    apiMock.certificatePage.mockReset();
    apiMock.getCertificate.mockReset();
    apiMock.ingestCertificate.mockReset();
  });

  it("loads server-side pages, applies expiring_before, and reaches the no-more-pages state", async () => {
    apiMock.certificatePage
      .mockResolvedValueOnce({
        items: [{ id: "c1", subject: "CN=page-one", issuer: "CN=CA", status: "active", fingerprint: "fp1" }],
        next_cursor: "cursor-two",
      })
      .mockResolvedValueOnce({
        items: [{ id: "c2", subject: "CN=page-two", issuer: "CN=CA", status: "active", fingerprint: "fp2" }],
      })
      .mockResolvedValueOnce({ items: [] });
    const user = userEvent.setup();
    renderCerts();

    expect(await screen.findByText("CN=page-one")).toBeInTheDocument();
    expect(apiMock.certificatePage).toHaveBeenCalledWith({ limit: 20, expiringBefore: undefined });

    await user.click(screen.getByRole("button", { name: /load next page/i }));
    await waitFor(() =>
      expect(apiMock.certificatePage).toHaveBeenCalledWith({
        limit: 20,
        cursor: "cursor-two",
        expiringBefore: undefined,
      }),
    );
    expect(await screen.findByText("CN=page-two")).toBeInTheDocument();
    expect(screen.getByText(/no more certificate pages/i)).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "<7d" }));
    await waitFor(() =>
      expect(apiMock.certificatePage).toHaveBeenLastCalledWith({
        limit: 20,
        expiringBefore: expect.any(String),
      }),
    );
  });

  it("renders expiry bands and revoked metadata from served certificate fields", async () => {
    const soon = new Date(Date.now() + 3 * 24 * 60 * 60 * 1000).toISOString();
    apiMock.certificatePage.mockResolvedValue({
      items: [
        {
          id: "c1",
          subject: "CN=revoked.example.com",
          issuer: "CN=CA",
          not_after: soon,
          status: "revoked",
          revocation_reason: "keyCompromise",
          fingerprint: "fp1",
        },
      ],
    });

    renderCerts();

    expect(await screen.findByText("<7d critical")).toBeInTheDocument();
    expect(screen.getByText("revoked")).toBeInTheDocument();
    expect(screen.getByText("keyCompromise")).toBeInTheDocument();
    expect(screen.queryByText(/^active$/i)).not.toBeInTheDocument();
  });

  it("opens a served detail panel with SANs, fingerprint, issuer, and owner link", async () => {
    apiMock.certificatePage.mockResolvedValue({
      items: [{ id: "c1", subject: "CN=api.example.com", issuer: "CN=CA", status: "active", fingerprint: "fp-list" }],
    });
    apiMock.getCertificate.mockResolvedValue({
      id: "c1",
      tenant_id: "tenant-1",
      subject: "CN=api.example.com",
      sans: ["api.example.com", "10.0.0.10"],
      issuer: "CN=Issuing CA",
      key_algorithm: "ECDSA-P256",
      serial: "01",
      fingerprint: "sha256:detail",
      not_before: "2026-06-01T00:00:00Z",
      not_after: "2026-09-01T00:00:00Z",
      source: "agent",
      deployment_location: "cluster-a/api",
      owner_id: "owner-1",
      status: "active",
    });
    const user = userEvent.setup();
    renderCerts();

    await user.click(await screen.findByRole("button", { name: /view details/i }));

    expect(apiMock.getCertificate).toHaveBeenCalledWith("c1");
    const dialog = await screen.findByRole("dialog", { name: /certificate details/i });
    expect(dialog).toHaveTextContent("api.example.com");
    expect(dialog).toHaveTextContent("sha256:detail");
    expect(dialog).toHaveTextContent("CN=Issuing CA");
    expect(screen.getByRole("link", { name: "owner-1" })).toHaveAttribute("href", "/owners?owner=owner-1");
    expect(dialog).toHaveTextContent(/certificate chain not served yet/i);
    expect(document.querySelector('[data-state-primitive="unavailable"]')).toBeInTheDocument();
  });

  it("ingests a PEM through the served mutation and prepends the returned row", async () => {
    apiMock.certificatePage.mockResolvedValue({ items: [] });
    apiMock.ingestCertificate.mockResolvedValue({
      id: "c-new",
      tenant_id: "tenant-1",
      subject: "CN=new.example.com",
      issuer: "CN=CA",
      fingerprint: "fp-new",
      status: "active",
    });
    const user = userEvent.setup();
    renderCerts();

    await user.click(screen.getByRole("button", { name: /add certificate/i }));
    await user.type(screen.getByLabelText(/certificate pem/i), "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----");
    await user.type(screen.getByLabelText(/owner id/i), "owner-1");
    await user.type(screen.getByLabelText(/deployment location/i), "cluster-a/api");
    await user.click(screen.getByRole("button", { name: /ingest certificate/i }));

    await waitFor(() =>
      expect(apiMock.ingestCertificate).toHaveBeenCalledWith({
        pem: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----",
        owner_id: "owner-1",
        source: "manual-ui",
        deployment_location: "cluster-a/api",
      }),
    );
    expect(await screen.findByText("CN=new.example.com")).toBeInTheDocument();
    expect(screen.getByRole("status")).toHaveTextContent(/ingested CN=new.example.com/i);
  });

  it("surfaces problem+json detail when ingest rejects invalid PEM", async () => {
    apiMock.certificatePage.mockResolvedValue({ items: [] });
    apiMock.ingestCertificate.mockRejectedValue(
      new ApiError(422, JSON.stringify({ detail: "could not parse certificate: bad PEM" })),
    );
    const user = userEvent.setup();
    renderCerts();

    await user.click(screen.getByRole("button", { name: /add certificate/i }));
    await user.type(screen.getByLabelText(/certificate pem/i), "not a certificate");
    await user.click(screen.getByRole("button", { name: /ingest certificate/i }));

    expect(await screen.findByRole("alert")).toHaveTextContent(/could not parse certificate/i);
  });
});
