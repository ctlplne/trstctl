import { beforeEach, expect, it, vi } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { axe } from "vitest-axe";
import { AppQueryProvider } from "@/lib/query";
import { IntlProvider } from "@/i18n/I18nProvider";
import { PAMRecordingSearchPanel } from "@/pages/PAMRecordingSearchPanel";

// A275: the console searches every recorded session at once; each hit names
// its session (a link that opens it), target and person, where it was found
// and the masked line; a refusal is shown, not hidden.

const { apiMock } = vi.hoisted(() => ({ apiMock: { searchPAMRecordings: vi.fn() } }));
vi.mock("@/lib/api", async (original) => {
  const actual = await original<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});

const hit = {
  session_id: "a2750000-0000-4000-8000-000000000001",
  target_type: "postgres",
  target_id: "orders-db",
  subject: "alice",
  session_started_at: "2026-11-07T20:00:00Z",
  at_millis: 61500,
  conn: 1,
  source: "sql",
  kind: "query",
  text: "SELECT 'needle', '[masked:aws-access-key-id]'",
};

beforeEach(() => {
  apiMock.searchPAMRecordings.mockReset();
});

function mount() {
  return render(
    <MemoryRouter>
      <AppQueryProvider>
        <IntlProvider initialLocale="en-US" initialTimeZone="UTC">
          <PAMRecordingSearchPanel />
        </IntlProvider>
      </AppQueryProvider>
    </MemoryRouter>,
  );
}

it("searches every recording and links each masked hit to its session (A275)", async () => {
  const user = userEvent.setup();
  apiMock.searchPAMRecordings.mockResolvedValue({
    items: [hit, { ...hit, source: "output", kind: "out", text: "needle-ssh" }],
    sessions_searched: 7,
    truncated: false,
  });
  const { container } = mount();
  const search = screen.getByRole("button", { name: "Search" });
  expect(search).toBeDisabled();
  await user.type(screen.getByLabelText("Text to find (at least 3 characters)"), "needle");
  await user.type(screen.getByLabelText("Target ID (optional)"), "orders-db");
  await user.click(search);
  await waitFor(() => expect(apiMock.searchPAMRecordings).toHaveBeenCalledWith({ q: "needle", targetID: "orders-db" }));
  expect(await screen.findByRole("status")).toHaveTextContent("2 matches in 7 recordings searched.");
  const table = screen.getByRole("table", { name: "Matching recorded lines" });
  const rows = within(table).getAllByRole("row");
  expect(rows).toHaveLength(3);
  expect(within(rows[1]).getByRole("link")).toHaveAttribute("href", `/admin/access?session=${hit.session_id}`);
  expect(within(rows[1]).getByRole("link")).toHaveTextContent("at 1:01");
  expect(within(rows[1]).getByText("SQL statement")).toBeInTheDocument();
  expect(within(rows[1]).getByText(/\[masked:aws-access-key-id\]/)).toBeInTheDocument();
  expect(within(rows[2]).getByText("Terminal output")).toBeInTheDocument();
  expect(await axe(container)).toHaveNoViolations();
});

it("says when nothing matches, when a limit stopped the search, and when it was refused (A275)", async () => {
  const user = userEvent.setup();
  apiMock.searchPAMRecordings.mockResolvedValueOnce({ items: [], sessions_searched: 200, truncated: true });
  mount();
  await user.type(screen.getByLabelText("Text to find (at least 3 characters)"), "absent");
  await user.click(screen.getByRole("button", { name: "Search" }));
  expect(await screen.findByText("Nothing in the recordings matches.")).toBeInTheDocument();
  expect(screen.getByRole("status")).toHaveTextContent(/stopped the search early/);
  apiMock.searchPAMRecordings.mockRejectedValueOnce(new Error("forbidden"));
  await user.click(screen.getByRole("button", { name: "Search" }));
  expect(await screen.findByText("The recordings could not be searched")).toBeInTheDocument();
});
