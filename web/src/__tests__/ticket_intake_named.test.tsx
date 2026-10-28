import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, expect, it, vi } from "vitest";
import { MemoryRouter } from "react-router-dom";
import { IssuanceRequestsPanel } from "@/components/IssuanceRequestsPanel";
import { AppQueryProvider } from "@/lib/query";

const { methods } = vi.hoisted(() => ({
  methods: {
    issuanceRequests: vi.fn(),
    ticketIntakeSchedule: vi.fn(),
    ticketIntakeSchedules: vi.fn(),
    putTicketIntakeSchedule: vi.fn(),
    deleteTicketIntakeSchedule: vi.fn(),
  },
}));
vi.mock("@/lib/api", async (original) => {
  const actual = await original<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...methods } };
});
const base = {
  configured: true,
  system: "servicenow",
  enabled: false,
  interval_seconds: 3600,
  instance_url: "https://tickets.example.test",
  token_ref: "secret://tickets/reader",
  subject_field: "u_subject",
  profile_field: "u_profile",
  read_count: 0,
  pages_completed: 0,
  coverage_complete: false,
  eligible_count: 0,
  skipped_count: 0,
  guidance: "No provider read has completed.",
};

beforeEach(() => {
  vi.clearAllMocks();
  methods.issuanceRequests.mockResolvedValue({ items: [], open: 0, guidance: "" });
  methods.ticketIntakeSchedule.mockResolvedValue({ configured: false, enabled: false, guidance: "" });
  methods.ticketIntakeSchedules.mockResolvedValue({
    items: [
      { ...base, name: "incidents", sn_table: "incident" },
      { ...base, name: "requests", sn_table: "sc_req_item", owner_field: "assigned_to.email" },
    ],
  });
  methods.deleteTicketIntakeSchedule.mockResolvedValue(undefined);
});

function mount() {
  render(
    <MemoryRouter>
      <AppQueryProvider>
        <IssuanceRequestsPanel currentPrincipal={{ permissions: ["certs:read", "certs:write"] }} />
      </AppQueryProvider>
    </MemoryRouter>,
  );
}

it("lists two sources of one provider and removes only the reviewed named schedule", async () => {
  const user = userEvent.setup();
  mount();
  const table = await screen.findByRole("table", { name: "Ticket intake schedules" });
  expect(within(table).getByText("incidents")).toBeInTheDocument();
  expect(within(table).getByText("requests")).toBeInTheDocument();
  const row = within(table).getByText("requests").closest("tr")!;
  await user.click(within(row).getByRole("button", { name: "Remove schedule" }));
  expect(methods.deleteTicketIntakeSchedule).not.toHaveBeenCalled();
  expect(await screen.findByText(/requests.*servicenow/)).toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "Remove reviewed schedule" }));
  await waitFor(() => expect(methods.deleteTicketIntakeSchedule).toHaveBeenCalledWith("servicenow", "requests", expect.any(String)));
});

it("requires a valid distinct name before advancing to owner mapping", async () => {
  const user = userEvent.setup();
  mount();
  await user.click(await screen.findByRole("button", { name: "Configure ticket intake" }));
  await user.type(screen.getByLabelText("Schedule name"), "../bad");
  await user.click(screen.getByRole("button", { name: "Next" }));
  expect(await screen.findByText(/1–40 lowercase/)).toBeInTheDocument();
  expect(methods.putTicketIntakeSchedule).not.toHaveBeenCalled();
});
