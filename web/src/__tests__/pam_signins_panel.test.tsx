import { beforeEach, expect, it, vi } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { axe } from "vitest-axe";
import { AppQueryProvider } from "@/lib/query";
import { IntlProvider } from "@/i18n/I18nProvider";
import { PAMSignInsPanel } from "@/pages/PAMSignInsPanel";

// A274: the console lists the sign-ins bypass detection recorded, newest
// first, each with what explained it; an unexplained one is marked and links
// to its finding's list. The provider and unexplained-only filters are sent
// to the server.

const { apiMock } = vi.hoisted(() => ({
  apiMock: { pamSignIns: vi.fn() },
}));
vi.mock("@/lib/api", async (original) => {
  const actual = await original<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});

const direct = {
  provider_id: "lab-host",
  fingerprint: "sha256:direct",
  account: "orders-single",
  at: "2026-11-07T18:00:01Z",
  source: "203.0.113.5",
  method: "password",
  ref: "sshd[101]:51234",
  collector: "sshd",
  last_seen_at: "2026-11-07T18:01:00Z",
};
const rotation = {
  provider_id: "lab-host",
  fingerprint: "sha256:rotation",
  account: "orders-single",
  at: "2026-11-07T17:59:00Z",
  source: "172.17.0.1",
  method: "publickey",
  key_id: "trstctl-admin",
  collector: "sshd",
  last_seen_at: "2026-11-07T18:01:00Z",
  explained_by: { kind: "rotation_check", ref: "rotation-7" },
};
const database = {
  provider_id: "orders-mysql",
  fingerprint: "sha256:db",
  account: "app_reader",
  at: "2026-11-07T17:58:00Z",
  earliest: "2026-11-07T17:53:00Z",
  method: "database",
  collector: "performance_schema_threads",
  last_seen_at: "2026-11-07T18:01:00Z",
  explained_by: { kind: "checkout" },
};

beforeEach(() => {
  apiMock.pamSignIns.mockReset();
  apiMock.pamSignIns.mockResolvedValue({ items: [direct, rotation, database] });
});

function mount() {
  return render(
    <MemoryRouter>
      <AppQueryProvider>
        <IntlProvider initialLocale="en-US" initialTimeZone="UTC">
          <PAMSignInsPanel />
        </IntlProvider>
      </AppQueryProvider>
    </MemoryRouter>,
  );
}

it("lists recorded sign-ins with what explained each and marks the unexplained (A274)", async () => {
  const { container } = mount();
  const table = await screen.findByRole("table", { name: "Recorded sign-ins" });
  const rows = within(table).getAllByRole("row");
  expect(rows).toHaveLength(4);
  expect(within(rows[1]).getByText("orders-single")).toBeInTheDocument();
  expect(within(rows[1]).getByText("203.0.113.5")).toBeInTheDocument();
  expect(within(rows[1]).getByText("Unexplained")).toHaveClass("text-status-danger");
  expect(within(rows[2]).getByText("Rotation rotation-7")).toBeInTheDocument();
  expect(within(rows[2]).getByText("publickey (trstctl-admin)")).toBeInTheDocument();
  expect(within(rows[3]).getByText("Check-out")).toBeInTheDocument();
  expect(within(rows[3]).getByText("Not recorded")).toBeInTheDocument();
  expect(within(rows[3]).getByText(/^Between .+ and .+$/)).toBeInTheDocument();
  expect(screen.getByRole("link", { name: "Review the findings" })).toHaveAttribute("href", "/discovery?tab=findings");
  expect(apiMock.pamSignIns).toHaveBeenLastCalledWith(expect.objectContaining({ providerId: undefined, unexplained: false }));
  expect(await axe(container)).toHaveNoViolations();
});

it("sends the provider and unexplained-only filters to the server (A274)", async () => {
  const user = userEvent.setup();
  mount();
  await screen.findByRole("table", { name: "Recorded sign-ins" });
  apiMock.pamSignIns.mockResolvedValue({ items: [direct] });
  await user.type(screen.getByLabelText("Provider"), " lab-host ");
  await user.click(screen.getByLabelText("Only unexplained sign-ins"));
  await user.click(screen.getByRole("button", { name: "Show" }));
  await waitFor(() => expect(apiMock.pamSignIns).toHaveBeenLastCalledWith(expect.objectContaining({ providerId: "lab-host", unexplained: true })));
  await waitFor(() => expect(within(screen.getByRole("table", { name: "Recorded sign-ins" })).getAllByRole("row")).toHaveLength(2));
});

it("says when nothing is recorded (A274)", async () => {
  apiMock.pamSignIns.mockResolvedValue({ items: [] });
  mount();
  expect(await screen.findByText("No sign-ins recorded.")).toBeInTheDocument();
});
