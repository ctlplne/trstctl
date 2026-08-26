import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { ToastProvider } from "@/components/ToastProvider";
import { Agents } from "@/pages/Agents";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    agents: vi.fn(),
    createEnrollmentToken: vi.fn(),
    offboardAgent: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});

function renderAgents() {
  return render(
    <MemoryRouter initialEntries={["/agents"]}>
      <ToastProvider>
        <Agents />
      </ToastProvider>
    </MemoryRouter>,
  );
}

describe("JOURNEY-003 agent offboarding", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    apiMock.createEnrollmentToken.mockReset().mockResolvedValue({
      token: "BOOT-TOKEN-JOURNEY-003",
      enroll_path: "/enroll/bootstrap",
      agent_server: "localhost:19443",
      agent_server_name: "localhost",
      roles: ["host"],
    });
    apiMock.agents.mockReset().mockResolvedValue([
      {
        id: "ag-journey-003",
        name: "edge-journey-003",
        status: "active",
        version: "1.0.0",
        last_seen_at: "2999-01-01T00:00:00Z",
        inventory_report_path: "agent.mtls.ReportInventory",
        discovery_capabilities: [],
      },
    ]);
    apiMock.offboardAgent.mockReset().mockResolvedValue({
      agent: {
        id: "ag-journey-003",
        name: "edge-journey-003",
        status: "offboarded",
        version: "1.0.0",
        last_seen_at: "2999-01-01T00:00:00Z",
        offboarded_at: "2026-07-01T12:00:00Z",
        offboarded_by: "ops@example.test",
        offboard_reason: "host decommissioned",
        inventory_report_path: "agent.mtls.ReportInventory",
        discovery_capabilities: [],
      },
      revocation_evidence: "offboarded agent certificates are rejected by the served mTLS channel",
    });
  });

  it("retires a displayed agent from the console and leaves tombstoned evidence in the row", async () => {
    const user = userEvent.setup();
    renderAgents();

    await user.click(await screen.findByText("Fleet status and safe actions"));
    const row = (await screen.findAllByText("edge-journey-003"))[0].closest("tr");
    expect(row).toBeTruthy();
    await user.click(within(row as HTMLTableRowElement).getByRole("button", { name: "Offboard" }));

    const dialog = await screen.findByRole("alertdialog", { name: "Offboard edge-journey-003" });
    await user.clear(within(dialog).getByLabelText("Reason"));
    await user.type(within(dialog).getByLabelText("Reason"), "host decommissioned");
    await user.click(within(dialog).getByRole("button", { name: "Offboard agent" }));

    await waitFor(() => expect(apiMock.offboardAgent).toHaveBeenCalledWith("ag-journey-003", { reason: "host decommissioned" }));
    expect((await screen.findAllByText("offboarded")).length).toBeGreaterThan(0);
    expect(screen.getByText("Offboarded Jul 1, 2026")).toBeInTheDocument();
    expect(screen.getAllByText("host decommissioned").length).toBeGreaterThan(0);
    expect(screen.getByText(/served mTLS channel/i)).toBeInTheDocument();
  });
});
