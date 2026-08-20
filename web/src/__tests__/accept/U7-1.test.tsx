import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { Incidents } from "@/pages/Incidents";

const impact = {
  node: { id: "id:11111111-1111-1111-1111-111111111111", kind: "credential", name: "payments-api identity" },
  affected: [
    { id: "wl:payments", kind: "workload", name: "payments service" },
    { id: "res:ledger", kind: "resource", name: "ledger database" },
  ],
  by_kind: { workload: [{ id: "wl:payments", kind: "workload", name: "payments service" }], resource: [] },
};

const { apiMock } = vi.hoisted(() => ({
  apiMock: { incidentExecutions: vi.fn(), executeIncident: vi.fn(), graphBlastRadius: vi.fn() },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});

beforeEach(() => {
  apiMock.incidentExecutions.mockReset().mockResolvedValue({ items: [] });
  apiMock.graphBlastRadius.mockReset().mockResolvedValue(impact);
  apiMock.executeIncident.mockReset();
});

describe("U7-1 incident response console", () => {
  it("previews a served blast radius for the compromised identity", async () => {
    const user = userEvent.setup();
    render(
      <MemoryRouter>
        <Incidents />
      </MemoryRouter>,
    );
    expect(screen.getByRole("heading", { name: "Security incidents" })).toBeInTheDocument();
    await user.type(screen.getByLabelText("Affected identity"), "11111111-1111-1111-1111-111111111111");
    await user.click(screen.getByRole("button", { name: "Preview blast radius" }));

    await waitFor(() => expect(apiMock.graphBlastRadius).toHaveBeenCalled());
    expect(await screen.findByRole("heading", { name: "Blast-radius snapshot" })).toBeInTheDocument();
    expect(screen.getByText("payments service")).toBeInTheDocument();
  });
});
