import { beforeEach, expect, it, vi } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { axe } from "vitest-axe";
import { AppQueryProvider } from "@/lib/query";
import { IntlProvider } from "@/i18n/I18nProvider";
import { PAMAccountFlagsPanel } from "@/pages/PAMAccountFlagsPanel";

// A276: flagged accounts show why; an action is proposed (reassign to an
// owner, or rotate and disable naming the account in use), its review is
// linked, and once approved it is applied with the approval's exact
// identifiers; without access:targets.write nothing is offered.

const { apiMock } = vi.hoisted(() => ({
  apiMock: { pamAccountFlags: vi.fn(), owners: vi.fn(), scanPAMAccountFlags: vi.fn(), requestPAMAccountAction: vi.fn(), applyPAMAccountAction: vi.fn() },
}));
vi.mock("@/lib/api", async (original) => {
  const actual = await original<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});

const owner = { id: "a2760000-0000-4000-8000-000000000001", name: "Dana", kind: "user" };
const flag = {
  target_type: "postgres",
  target_id: "orders-vault",
  reasons: ["orphaned", "unused"],
  detail: "it has no owner; unused since 2026-08-01T00:00:00Z",
  flagged_at: "2026-11-07T20:00:00Z",
  status: "open",
};
const review = {
  request_id: "r",
  approval_request_id: "a2760000-0000-4000-8000-0000000000aa",
  intent_digest: "digest",
  status: "pending",
  approval_count: 0,
  required_approvals: 2,
  expires_at: "2026-11-07T21:00:00Z",
};

beforeEach(() => {
  for (const mock of Object.values(apiMock)) mock.mockReset();
  apiMock.pamAccountFlags.mockResolvedValue({ items: [flag] });
  apiMock.owners.mockResolvedValue([owner]);
  apiMock.scanPAMAccountFlags.mockResolvedValue({ items: [flag] });
  apiMock.requestPAMAccountAction.mockResolvedValue(review);
  apiMock.applyPAMAccountAction.mockResolvedValue({ ...flag, status: "actioned", action: "reassign", action_owner_id: owner.id });
});

function mount(canAct: boolean) {
  return render(
    <MemoryRouter>
      <AppQueryProvider>
        <IntlProvider initialLocale="en-US" initialTimeZone="UTC">
          <PAMAccountFlagsPanel canAct={canAct} />
        </IntlProvider>
      </AppQueryProvider>
    </MemoryRouter>,
  );
}

it("proposes a reassignment, links its review and applies it with the approval (A276)", async () => {
  const user = userEvent.setup();
  const { container } = mount(true);
  const table = await screen.findByRole("table", { name: "Flagged accounts" });
  expect(within(table).getByText("Orphaned, Unused")).toBeInTheDocument();
  expect(within(table).getByText(/it has no owner/)).toBeInTheDocument();
  await user.click(within(table).getByRole("button", { name: "Propose an action for orders-vault" }));
  const form = screen.getByRole("form", { name: "Propose an action for orders-vault" });
  await user.selectOptions(within(form).getByLabelText("New owner"), owner.id);
  await user.type(within(form).getByLabelText("Reason"), "Dana runs the orders ledger");
  await user.click(within(form).getByRole("button", { name: "Request approval" }));
  await waitFor(() =>
    expect(apiMock.requestPAMAccountAction).toHaveBeenCalledWith(
      "postgres",
      "orders-vault",
      expect.objectContaining({ action: "reassign", owner_id: owner.id, reason: "Dana runs the orders ledger" }),
      expect.any(String),
    ),
  );
  expect(await screen.findByRole("link", { name: "Open the review (2 approvals needed)" })).toHaveAttribute(
    "href",
    `/approvals?request=${review.approval_request_id}`,
  );
  expect(await axe(container)).toHaveNoViolations();
  await user.click(screen.getByRole("button", { name: "Apply the approved action" }));
  await waitFor(() =>
    expect(apiMock.applyPAMAccountAction).toHaveBeenCalledWith(
      "postgres",
      "orders-vault",
      expect.objectContaining({ action: "reassign", owner_id: owner.id, approval_request_id: review.approval_request_id, intent_digest: "digest" }),
      expect.any(String),
    ),
  );
  expect(await screen.findByRole("status")).toHaveTextContent("orders-vault has its new owner.");
});

it("proposes rotate-and-disable with the account in use, and offers nothing without the permission (A276)", async () => {
  const user = userEvent.setup();
  const first = mount(true);
  await user.click(await screen.findByRole("button", { name: "Propose an action for orders-vault" }));
  const form = screen.getByRole("form", { name: "Propose an action for orders-vault" });
  await user.selectOptions(within(form).getByLabelText("Action"), "rotate_disable");
  await user.type(within(form).getByLabelText("Account in use now (for an account rotated between two)"), "orders_app_a");
  await user.type(within(form).getByLabelText("Reason"), "retire it");
  await user.click(within(form).getByRole("button", { name: "Request approval" }));
  await waitFor(() =>
    expect(apiMock.requestPAMAccountAction).toHaveBeenCalledWith(
      "postgres",
      "orders-vault",
      { request_id: expect.any(String), action: "rotate_disable", rotation_old_ref: "orders_app_a", reason: "retire it" },
      expect.any(String),
    ),
  );
  first.unmount();
  mount(false);
  await screen.findByRole("table", { name: "Flagged accounts" });
  expect(screen.queryByRole("button", { name: /Propose an action/ })).not.toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Check accounts now" })).not.toBeInTheDocument();
});
