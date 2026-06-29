import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { Certificates } from "@/pages/Certificates";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    certificatePage: vi.fn(),
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

function renderEmptyCertificates() {
  return render(
    <MemoryRouter initialEntries={["/certificates"]}>
      <Routes>
        <Route path="/certificates" element={<Certificates />} />
        <Route path="/request" element={<h1>Credential request destination</h1>} />
        <Route path="/ca-hierarchy" element={<h1>Issuer connection destination</h1>} />
      </Routes>
    </MemoryRouter>,
  );
}

describe("C10-6 first-run empty states", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    for (const mock of Object.values(apiMock)) mock.mockReset();
    apiMock.certificatePage.mockResolvedValue({ items: [] });
    apiMock.certificateHealth.mockResolvedValue(undefined);
    apiMock.crlDistributions.mockResolvedValue({ items: [] });
    apiMock.owners.mockResolvedValue([]);
    apiMock.risk.mockResolvedValue([]);
    apiMock.rotationRuns.mockResolvedValue({ items: [] });
    apiMock.connectorDeliveries.mockResolvedValue({ items: [] });
  });

  it("renders certificate empty-state CTAs with working primary and secondary actions", async () => {
    const user = userEvent.setup();
    const first = renderEmptyCertificates();

    expect(await screen.findByRole("heading", { name: "No certificates yet" })).toBeInTheDocument();
    expect(screen.getByText("Start with a profile-bound request, or connect an issuer before the first certificate is minted.")).toBeInTheDocument();

    await user.click(screen.getByRole("link", { name: "Issue first certificate" }));
    expect(await screen.findByRole("heading", { name: "Credential request destination" })).toBeInTheDocument();

    first.unmount();
    renderEmptyCertificates();
    expect(await screen.findByRole("heading", { name: "No certificates yet" })).toBeInTheDocument();

    await user.click(screen.getByRole("link", { name: "Connect an issuer" }));
    expect(await screen.findByRole("heading", { name: "Issuer connection destination" })).toBeInTheDocument();
  });
});
