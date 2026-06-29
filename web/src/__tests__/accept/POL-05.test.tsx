import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { ThemeProvider } from "@/components/ThemeProvider";
import { AuthProvider } from "@/auth/AuthProvider";
import { AppRoutes } from "@/App";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    me: vi.fn(),
    owners: vi.fn(),
    ownershipAttribution: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: apiMock };
});

function renderAt(path: string) {
  return render(
    <ThemeProvider>
      <AuthProvider>
        <MemoryRouter initialEntries={[path]}>
          <AppRoutes />
        </MemoryRouter>
      </AuthProvider>
    </ThemeProvider>,
  );
}

describe("POL-05 Owners route polish", () => {
  beforeEach(() => {
    for (const mock of Object.values(apiMock)) mock.mockReset();
    apiMock.me.mockResolvedValue({ subject: "user-1", tenant_id: "t1", email: "u@example.test" });
    apiMock.owners.mockResolvedValue([
      { id: "owner-payments", name: "Payments team", kind: "team", email: "payments@example.test" },
      { id: "owner-platform", name: "Platform service", kind: "workload", email: "platform@example.test" },
    ]);
    apiMock.ownershipAttribution.mockResolvedValue({
      generated_at: "2026-06-29T00:00:00Z",
      summary: { total: 2, attributed: 1, orphaned: 1, team: 1 },
      coverage: ["human_owner", "team_owner", "vendor_owner", "orphaned"],
      items: [
        {
          id: "identity/id-1",
          tenant_id: "t1",
          kind: "api_key",
          source: "identity",
          display_name: "payments-api-key",
          owner: { id: "owner-payments", tenant_id: "t1", kind: "team", name: "Payments team", email: "payments@example.test" },
          attribution_status: "attributed",
          attribution_source: "owner_id",
          attribution_evidence: ["owner_id:owner-payments"],
          created_at: "2026-06-29T00:00:00Z",
        },
        {
          id: "finding/find-1",
          tenant_id: "t1",
          kind: "token",
          source: "discovery_finding",
          display_name: "orphaned-ci-token",
          attribution_status: "orphaned",
          attribution_source: "unattributed",
          attribution_evidence: [],
          created_at: "2026-06-29T00:00:00Z",
        },
      ],
    });
  });

  it("keeps Owners as a standalone served route with interactive search and filtering", async () => {
    const user = userEvent.setup();
    renderAt("/owners");

    expect(await screen.findByRole("heading", { name: "Owners" })).toBeInTheDocument();

    const search = await screen.findByRole("searchbox", { name: "Search owners" });
    expect(apiMock.owners).toHaveBeenCalledTimes(1);
    expect(apiMock.ownershipAttribution).toHaveBeenCalledTimes(1);
    const attributionTable = screen.getByRole("table", { name: "NHI ownership attribution" });
    expect(await within(attributionTable).findByRole("row", { name: /payments-api-key/ })).toBeInTheDocument();
    expect(within(attributionTable).getByRole("row", { name: /orphaned-ci-token/ })).toBeInTheDocument();
    await user.type(search, "payments");
    const ownersTable = screen.getByRole("table", { name: "Credential owners" });
    expect(within(ownersTable).getByRole("row", { name: /Payments team/ })).toBeInTheDocument();
    expect(within(ownersTable).queryByRole("row", { name: /Platform service/ })).not.toBeInTheDocument();

    await user.clear(search);
    await user.selectOptions(screen.getByLabelText("Owner kind"), "workload");
    expect(within(ownersTable).getByRole("row", { name: /Platform service/ })).toBeInTheDocument();
    expect(within(ownersTable).queryByRole("row", { name: /Payments team/ })).not.toBeInTheDocument();
  });
});
