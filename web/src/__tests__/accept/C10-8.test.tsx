import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { CommandPalette } from "@/components/CommandPalette";

// CommandPalette filters its commands by the caller's permissions, and this test
// exercises a permission-gated quick action. It used to pass no user at all and
// relied on hasPermission failing open; auth_and_dashboards.test.tsx asserts the
// opposite direction (an unpermitted operator must NOT see this action), so the
// gating is deliberate and the operator here is stated explicitly.
const fullyPermittedOperator = {
  subject: "test-operator",
  tenant_id: "t1",
  email: "operator@example.test",
  roles: ["admin"],
  permissions: ["*"],
};

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    agents: vi.fn(),
    certificatePage: vi.fn(),
    discoverySources: vi.fn(),
    identities: vi.fn(),
    issuers: vi.fn(),
    secretPage: vi.fn(),
    startDiscoveryRun: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});

function renderPalette(onClose = vi.fn()) {
  return render(
    <MemoryRouter initialEntries={["/"]}>
      <Routes>
        <Route path="/" element={<CommandPalette open onClose={onClose} user={fullyPermittedOperator} />} />
        <Route path="/discovery" element={<h1>Discovery destination</h1>} />
        <Route path="/request" element={<h1>Request destination</h1>} />
      </Routes>
    </MemoryRouter>,
  );
}

describe("C10-8 command palette search and actions", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    for (const mock of Object.values(apiMock)) mock.mockReset();
    apiMock.certificatePage.mockResolvedValue({
      items: [{ id: "cert-1", tenant_id: "t1", subject: "payments-api", fingerprint: "SHA256:pay", status: "active" }],
    });
    apiMock.issuers.mockResolvedValue([{ id: "iss-1", tenant_id: "t1", name: "Payments CA", kind: "x509_ca", internal: true }]);
    apiMock.identities.mockResolvedValue([{ id: "id-1", tenant_id: "t1", name: "payments-worker", kind: "workload_identity", status: "issued" }]);
    apiMock.secretPage.mockResolvedValue({ items: [] });
    apiMock.agents.mockResolvedValue([]);
    apiMock.discoverySources.mockResolvedValue({ items: [{ id: "source-1", tenant_id: "t1", name: "edge network", kind: "network" }] });
    apiMock.startDiscoveryRun.mockResolvedValue({ id: "run-1", tenant_id: "t1", source_id: "source-1", status: "queued" });
  });

  it("debounces served record search and invokes a served quick action", async () => {
    const user = userEvent.setup();
    renderPalette();

    const palette = screen.getByRole("dialog", { name: "Command palette" });
    const search = within(palette).getByRole("searchbox", { name: "Search routes and inventory" });

    await user.type(search, "payments");
    expect(apiMock.certificatePage).not.toHaveBeenCalled();

    await waitFor(() => expect(apiMock.certificatePage).toHaveBeenCalledWith({ limit: 25 }));
    expect(apiMock.issuers).toHaveBeenCalledTimes(1);
    expect(apiMock.identities).toHaveBeenCalledTimes(1);
    expect(within(palette).getByRole("button", { name: /payments-api.*Certificate/i })).toBeInTheDocument();
    expect(within(palette).getByRole("button", { name: /Payments CA.*Issuer/i })).toBeInTheDocument();
    expect(within(palette).getByRole("button", { name: /payments-worker.*Identity/i })).toBeInTheDocument();

    await user.clear(search);
    await user.type(search, "run");
    await user.click(within(palette).getByRole("button", { name: /Run discovery scan/i }));

    await waitFor(() => expect(apiMock.discoverySources).toHaveBeenCalledWith({ limit: 1 }));
    expect(apiMock.startDiscoveryRun).toHaveBeenCalledWith({ source_id: "source-1", dry_run: false });
    expect(await screen.findByRole("heading", { name: "Discovery destination" })).toBeInTheDocument();
  });
});
