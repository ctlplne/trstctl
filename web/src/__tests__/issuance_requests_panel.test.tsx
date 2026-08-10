import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { IssuanceRequestsPanel } from "@/components/IssuanceRequestsPanel";
import { AppQueryProvider } from "@/lib/query";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    issuanceRequests: vi.fn(),
    ticketIntakeSchedule: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});

describe("ticket-intake relay visibility", () => {
  beforeEach(() => {
    apiMock.issuanceRequests.mockReset().mockResolvedValue({ items: [], open: 0, guidance: "" });
    apiMock.ticketIntakeSchedule.mockReset().mockResolvedValue({
      configured: true,
      enabled: true,
      system: "servicenow",
      last_error: "a dispatched ticket.sync job is still waiting",
      guidance: "A network relay executes the durable read; the control plane never dials ServiceNow.",
    });
  });

  it("shows the durable relay outcome even before a ticket opens a request", async () => {
    render(
      <AppQueryProvider>
        <IssuanceRequestsPanel />
      </AppQueryProvider>,
    );

    expect(await screen.findByRole("heading", { name: "Network relay" })).toBeInTheDocument();
    expect(screen.getByText((_, node) => node?.tagName === "P" && node.textContent === "servicenow · Enabled · Last run: —")).toBeInTheDocument();
    expect(screen.getByText("a dispatched ticket.sync job is still waiting")).toBeInTheDocument();
    expect(screen.getByText(/control plane never dials ServiceNow/)).toBeInTheDocument();
  });
});
