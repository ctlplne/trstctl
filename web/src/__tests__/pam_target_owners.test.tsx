import { beforeEach, expect, it, vi } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import { AppQueryProvider } from "@/lib/query";
import { IntlProvider } from "@/i18n/I18nProvider";
import { PAMTargetsPanel } from "@/pages/PAMTargetsPanel";

// A276: every brokered account shows its owner, or that it has none; an
// owners:write holder assigns one to the account's inventory record with a
// reason. Without owners:write there is no assignment control.

const { apiMock } = vi.hoisted(() => ({ apiMock: { pamTargets: vi.fn(), owners: vi.fn(), assignOwnership: vi.fn() } }));
vi.mock("@/lib/api", async (original) => {
  const actual = await original<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});

const owner = { id: "a2760000-0000-4000-8000-000000000001", name: "Orders platform", kind: "team" };

beforeEach(() => {
  for (const mock of Object.values(apiMock)) mock.mockReset();
  apiMock.pamTargets.mockResolvedValue({
    items: [
      { id: "orders-pg", target_type: "postgres", provider_id: "pam-pg", allowed_roles: ["readonly"], enabled: true, source: "tenant" },
      { id: "billing-pg", target_type: "postgres", provider_id: "pam-pg", allowed_roles: ["readonly"], enabled: true, source: "tenant", owner_id: owner.id },
    ],
  });
  apiMock.owners.mockResolvedValue([owner]);
  apiMock.assignOwnership.mockResolvedValue({ owner_id: owner.id, inventory_ids: ["pam-account/postgres/orders-pg"] });
});

function mount(canAssignOwner: boolean) {
  return render(
    <AppQueryProvider>
      <IntlProvider initialLocale="en-US" initialTimeZone="UTC">
        <PAMTargetsPanel canManage={false} canAssignOwner={canAssignOwner} />
      </IntlProvider>
    </AppQueryProvider>,
  );
}

it("shows each brokered account's owner and assigns one with a reason (A276)", async () => {
  const user = userEvent.setup();
  const { container } = mount(true);
  const table = await screen.findByRole("table");
  const rows = within(table).getAllByRole("row");
  expect(within(rows[1]).getByText("No owner")).toBeInTheDocument();
  expect(await within(rows[2]).findByText("Orders platform")).toBeInTheDocument();
  await user.click(within(rows[1]).getByRole("button", { name: "Assign the owner of orders-pg" }));
  const dialog = await screen.findByRole("dialog");
  await user.selectOptions(within(dialog).getByRole("combobox", { name: "Owner" }), owner.id);
  const assign = within(dialog).getByRole("button", { name: "Assign owner" });
  expect(assign).toBeDisabled();
  await user.type(within(dialog).getByRole("textbox", { name: "Why this owner" }), "orders platform runs this database");
  await user.click(assign);
  await waitFor(() =>
    expect(apiMock.assignOwnership).toHaveBeenCalledWith({
      owner_id: owner.id,
      inventory_ids: ["pam-account/postgres/orders-pg"],
      reason: "orders platform runs this database",
    }),
  );
  expect(await screen.findByRole("status")).toHaveTextContent("Orders platform now owns orders-pg.");
  expect(await axe(container)).toHaveNoViolations();
});

it("offers no assignment without owners:write (A276)", async () => {
  mount(false);
  await screen.findByRole("table");
  expect(screen.queryByRole("button", { name: /Assign the owner/ })).not.toBeInTheDocument();
});
