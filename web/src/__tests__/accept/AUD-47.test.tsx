import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { IssuanceRequestsPanel } from "@/components/IssuanceRequestsPanel";
import { AppQueryProvider } from "@/lib/query";

const { issuanceRequests, ticketIntakeSchedule, ticketIntakeSchedules } = vi.hoisted(() => ({
  issuanceRequests: vi.fn(),
  ticketIntakeSchedule: vi.fn(),
  ticketIntakeSchedules: vi.fn(),
}));

vi.mock("@/lib/api", async (original) => {
  const actual = await original<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, issuanceRequests, ticketIntakeSchedule, ticketIntakeSchedules } };
});

function renderPanel() {
  return render(
    <AppQueryProvider>
      <IssuanceRequestsPanel />
    </AppQueryProvider>,
  );
}

describe("AUD-47 bounded ServiceNow and Jira ticket intake", () => {
  beforeEach(() => {
    issuanceRequests.mockReset();
    ticketIntakeSchedule.mockReset();
    ticketIntakeSchedules.mockReset();
    issuanceRequests.mockResolvedValue({ items: [], open: 0, guidance: "" });
  });

  it("shows page 100 as incomplete with the exact retained ServiceNow cursor", async () => {
    ticketIntakeSchedules.mockResolvedValue({
      items: [
        {
          configured: true,
          system: "servicenow",
          name: "default",
          enabled: true,
          sweep_id: "11111111-1111-4111-8111-111111111147",
          next_cursor: "sn-100",
          read_count: 100,
          expected_count: 101,
          pages_completed: 1,
          coverage_complete: false,
          eligible_count: 100,
          skipped_count: 0,
          guidance: "Durable network-relay pages.",
        },
      ],
    });
    renderPanel();

    await screen.findByText("servicenow: 100 of 101 tickets read across 1 pages.");
    const status = screen.getByRole("status");
    expect(status).toHaveTextContent("servicenow: 100 of 101 tickets read across 1 pages");
    expect(status).toHaveTextContent("Coverage incomplete. The committed cursor sn-100");
    expect(screen.queryByText(/Terminal coverage complete/)).not.toBeInTheDocument();
    expect(ticketIntakeSchedules).toHaveBeenCalledWith();
    expect(ticketIntakeSchedule).not.toHaveBeenCalled();
  });

  it("renders provider failures separately and calls only terminal Jira coverage complete", async () => {
    ticketIntakeSchedules.mockResolvedValue({
      items: (["servicenow", "jira"] as const).map((system) => ({
        configured: true,
        system,
        name: "default",
        enabled: true,
        sweep_id: system === "jira" ? "22222222-2222-4222-8222-222222222247" : "33333333-3333-4333-8333-333333333347",
        next_cursor: system === "jira" ? "" : "sn-100",
        read_count: system === "jira" ? 101 : 100,
        expected_count: 101,
        pages_completed: system === "jira" ? 2 : 1,
        coverage_complete: system === "jira",
        eligible_count: system === "jira" ? 100 : 99,
        skipped_count: 1,
        last_error: system === "servicenow" ? "ServiceNow relay timed out" : "",
        guidance: "Durable network-relay pages.",
      })),
    });
    renderPanel();

    await screen.findByText(/Terminal coverage complete: 100 eligible and 1 skipped/);
    const statuses = screen.getAllByRole("status");
    expect(statuses).toHaveLength(2);
    expect(screen.getByText(/Terminal coverage complete: 100 eligible and 1 skipped/)).toBeInTheDocument();
    expect(screen.getByText("ServiceNow relay timed out")).toBeInTheDocument();
    expect(screen.getByText(/The committed cursor sn-100/)).toBeInTheDocument();
  });
});
