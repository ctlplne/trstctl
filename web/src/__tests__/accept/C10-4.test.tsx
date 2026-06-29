import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, useLocation } from "react-router-dom";
import { Certificates } from "@/pages/Certificates";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    certificatePage: vi.fn(),
    getCertificate: vi.fn(),
    ingestCertificate: vi.fn(),
    certificateHealth: vi.fn(),
    crlDistributions: vi.fn(),
    owners: vi.fn(),
    risk: vi.fn(),
    rotationRuns: vi.fn(),
    connectorDeliveries: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});

function LocationProbe() {
  const location = useLocation();
  return <output aria-label="location search">{location.search}</output>;
}

function renderCerts(initialEntry = "/certificates") {
  return render(
    <MemoryRouter initialEntries={[initialEntry]}>
      <LocationProbe />
      <Certificates />
    </MemoryRouter>,
  );
}

describe("C10-4 certificate inventory filters", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    for (const mock of Object.values(apiMock)) mock.mockReset();
    apiMock.certificatePage.mockResolvedValue({
      items: [
        {
          id: "cert-pay",
          tenant_id: "t1",
          owner_id: "team-platform",
          subject: "CN=payments.example.test",
          issuer: "CN=Platform CA",
          fingerprint: "sha256:pay",
          status: "active",
          profile_name: "prod-web",
          environment: "prod",
          deployment_location: "prod/payments",
        },
        {
          id: "cert-admin",
          tenant_id: "t1",
          owner_id: "team-platform",
          subject: "CN=admin.example.test",
          issuer: "CN=Platform CA",
          fingerprint: "sha256:admin",
          status: "active",
          profile_name: "stage-web",
          environment: "staging",
          deployment_location: "staging/admin",
        },
        {
          id: "cert-dev",
          tenant_id: "t1",
          owner_id: "team-dev",
          subject: "CN=dev.example.test",
          issuer: "CN=Developer CA",
          fingerprint: "sha256:dev",
          status: "active",
          profile_name: "dev-web",
          environment: "dev",
          deployment_location: "dev/service",
        },
      ],
    });
    apiMock.owners.mockResolvedValue([
      { id: "team-platform", tenant_id: "t1", kind: "team", name: "Platform Team" },
      { id: "team-dev", tenant_id: "t1", kind: "team", name: "Developer Team" },
    ]);
    apiMock.certificateHealth.mockResolvedValue(undefined);
    apiMock.crlDistributions.mockResolvedValue({
      items: [
        {
          tenant_id: "t1",
          ca_id: "ca-prod",
          full_number: 42,
          full_url: "/crl/t1",
          shard_count: 4,
          shards: [
            { index: 0, revoked_count: 125000, url: "/crl/t1/shards/0" },
            { index: 1, revoked_count: 125000, url: "/crl/t1/shards/1" },
          ],
          delta_base_number: 41,
          delta_url: "/crl/t1/delta/41",
          revoked_count: 250000,
          this_update: "2026-06-29T00:00:00Z",
          next_update: "2026-06-30T00:00:00Z",
        },
      ],
    });
    apiMock.risk.mockResolvedValue([]);
    apiMock.rotationRuns.mockResolvedValue({ items: [] });
    apiMock.connectorDeliveries.mockResolvedValue({ items: [] });
  });

  it("filters by issuer, profile, team, and environment while rendering the Team column", async () => {
    const user = userEvent.setup();
    renderCerts();

    expect(await screen.findByText("CN=payments.example.test")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "CRL distribution" })).toBeInTheDocument();
    expect(screen.getByText("ca-prod")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "#42" })).toHaveAttribute("href", "/crl/t1");
    expect(screen.getByRole("link", { name: "base #41" })).toHaveAttribute("href", "/crl/t1/delta/41");
    expect(screen.getByRole("columnheader", { name: "Team" })).toBeInTheDocument();
    expect(screen.getAllByText("Platform Team").length).toBeGreaterThan(0);

    await user.selectOptions(screen.getByLabelText("Issuer filter"), "CN=Platform CA");
    await user.selectOptions(screen.getByLabelText("Profile filter"), "prod-web");
    await user.selectOptions(screen.getByLabelText("Team filter"), "team-platform");
    await user.selectOptions(screen.getByLabelText("Environment filter"), "prod");

    expect(screen.getByText("CN=payments.example.test")).toBeInTheDocument();
    expect(screen.queryByText("CN=admin.example.test")).not.toBeInTheDocument();
    expect(screen.queryByText("CN=dev.example.test")).not.toBeInTheDocument();

    const params = new URLSearchParams(screen.getByLabelText("location search").textContent ?? "");
    expect(params.get("issuer")).toBe("CN=Platform CA");
    expect(params.get("profile")).toBe("prod-web");
    expect(params.get("team")).toBe("team-platform");
    expect(params.get("environment")).toBe("prod");
    await waitFor(() => expect(apiMock.certificatePage).toHaveBeenCalledWith({ limit: 20, expiringBefore: undefined }));
  });
});
