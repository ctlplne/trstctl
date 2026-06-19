import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { ApiError } from "@/lib/api";
import { Discovery } from "@/pages/Discovery";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    identities: vi.fn(),
    secretPage: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: apiMock };
});

function renderDiscovery() {
  return render(
    <MemoryRouter>
      <Discovery />
    </MemoryRouter>,
  );
}

describe("discovery and inventory surface", () => {
  beforeEach(() => {
    localStorage.clear();
    sessionStorage.clear();
    vi.restoreAllMocks();
    apiMock.identities.mockReset().mockResolvedValue([
      {
        id: "ssh-1",
        kind: "ssh_key",
        name: "prod-host-key",
        owner_id: "owner-ssh",
        status: "deployed",
        not_after: "2026-07-01T00:00:00Z",
        attributes: { fingerprint: "sha256:sshkey1234567890", public_key: "ssh-ed25519 AAAA..." },
      },
      {
        id: "ssh-cert-1",
        kind: "ssh_certificate",
        name: "ci-user-cert",
        owner_id: "owner-ci",
        status: "issued",
        attributes: { fingerprint: "sha256:sshcert1234567890" },
      },
      {
        id: "api-1",
        kind: "api_key",
        name: "billing-api-token",
        owner_id: "owner-api",
        status: "issued",
        not_after: "2026-08-01T00:00:00Z",
        attributes: {
          fingerprint: "sha256:api1234567890abcdef",
          scopes: ["billing:read", "billing:write"],
          token: "RAW-TOKEN-VALUE",
        },
      },
      {
        id: "cert-1",
        kind: "x509_certificate",
        name: "web-cert",
        owner_id: "owner-web",
        status: "issued",
      },
    ]);
    apiMock.secretPage.mockReset().mockResolvedValue({
      items: [
        {
          name: "app/db/password",
          version: 4,
          updated_at: "2026-06-19T10:00:00Z",
          created_at: "2026-06-18T10:00:00Z",
          value: "SECRET-VALUE",
        },
      ],
    });
  });

  it("renders scanner disclosures with links but no enabled scan controls or raw cloud credential field", async () => {
    renderDiscovery();

    expect(await screen.findByRole("heading", { name: "Discovery" })).toBeInTheDocument();
    expect(screen.getByText("Discovery scan API not served yet")).toBeInTheDocument();
    expect(screen.getAllByText(/BACKEND-DISCOVERY-SCAN/).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/BACKEND-SECRETSCAN/).length).toBeGreaterThan(0);
    expect(screen.getByRole("link", { name: "Open certificate ingest" })).toHaveAttribute("href", "/certificates");
    expect(screen.getByRole("link", { name: "Open agent enrollment" })).toHaveAttribute("href", "/agents");
    expect(screen.getByText(/Cloud credentials must be sealed references/)).toBeInTheDocument();
    expect(screen.queryByLabelText(/cloud credential/i)).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /start scan|run scan|schedule scan/i })).not.toBeInTheDocument();
  });

  it("shows served SSH identities, API-key fingerprints, and secret metadata without rendering values", async () => {
    const storageSpy = vi.spyOn(Storage.prototype, "setItem");
    renderDiscovery();

    expect(await screen.findByText("prod-host-key")).toBeInTheDocument();
    expect(screen.getByText("ci-user-cert")).toBeInTheDocument();
    expect(screen.getByText("ssh_key")).toBeInTheDocument();
    expect(screen.getByText("ssh_certificate")).toBeInTheDocument();
    expect(screen.getByText(/Trust mutation and host-key remediation controls are intentionally absent/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /install trust|remove trust|rewrite sshd/i })).not.toBeInTheDocument();

    expect(screen.getByText("billing-api-token")).toBeInTheDocument();
    expect(screen.getByText("billing:read, billing:write")).toBeInTheDocument();
    expect(screen.getByText("sha256:api...abcdef")).toBeInTheDocument();
    expect(screen.queryByText("RAW-TOKEN-VALUE")).not.toBeInTheDocument();

    expect(screen.getByText("app/db/password")).toBeInTheDocument();
    expect(screen.getByText("v4")).toBeInTheDocument();
    expect(screen.queryByText("SECRET-VALUE")).not.toBeInTheDocument();
    expect(storageSpy).not.toHaveBeenCalled();
    expect(localStorage.length).toBe(0);
    expect(sessionStorage.length).toBe(0);
  });

  it("uses permission and empty states when served metadata is unavailable or absent", async () => {
    apiMock.identities.mockRejectedValueOnce(
      new ApiError(403, JSON.stringify({ detail: "missing identities:read" })),
    );
    apiMock.secretPage.mockResolvedValueOnce({ items: [] });
    renderDiscovery();

    expect((await screen.findAllByText("Permission denied")).length).toBeGreaterThan(0);
    expect(screen.getAllByText("missing identities:read").length).toBeGreaterThan(0);
    expect(screen.getByText("No native secrets in served store")).toBeInTheDocument();
  });
});
