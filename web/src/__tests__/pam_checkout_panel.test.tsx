import { beforeEach, expect, it, vi } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import { AppQueryProvider } from "@/lib/query";
import { IntlProvider } from "@/i18n/I18nProvider";
import { PAMCheckoutPanel } from "@/pages/PAMCheckoutPanel";

// A261: the check-out panel offers only vaulted accounts, requests a review,
// reveals the approved credential once in a dialog that forgets it when
// closed, and checks in the caller's own revealed check-outs.

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    pamCheckouts: vi.fn(),
    pamTargets: vi.fn(),
    requestPAMCheckout: vi.fn(),
    revealPAMCheckout: vi.fn(),
    checkInPAMCheckout: vi.fn(),
  },
}));
vi.mock("@/lib/api", async (original) => {
  const actual = await original<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});

const checkout = (requestID: string, requestedBy: string, status = "revealed") => ({
  request_id: requestID,
  target_type: "postgres",
  target_id: "orders-vault",
  provider_id: "pam-pg-vault",
  account_secret: "db/orders",
  secret_version: 1,
  requested_by: requestedBy,
  reason: "INC-4471",
  approval_request_id: "appr-0",
  revealed_at: "2026-11-05T01:00:00Z",
  expires_at: "2999-01-01T00:00:00Z",
  status,
});

beforeEach(() => {
  for (const mock of Object.values(apiMock)) mock.mockReset();
  apiMock.pamCheckouts.mockResolvedValue({ items: [checkout("c-1", "op"), checkout("c-2", "someone-else")] });
  apiMock.pamTargets.mockResolvedValue({
    items: [
      { id: "orders-vault", target_type: "postgres", provider_id: "pam-pg-vault", allowed_roles: ["db/orders"], account_secret: "db/orders", enabled: true },
      { id: "pg-main", target_type: "postgres", provider_id: "pam-pg", allowed_roles: ["readonly"], enabled: true },
    ],
  });
});

function mount(canRequest: boolean) {
  return render(
    <AppQueryProvider>
      <IntlProvider initialLocale="en-US" initialTimeZone="UTC">
        <PAMCheckoutPanel subject="op" canRequest={canRequest} canCheckInAny={false} />
      </IntlProvider>
    </AppQueryProvider>,
  );
}

it("requests a check-out, reveals the credential once and checks in the caller's own", async () => {
  const user = userEvent.setup();
  apiMock.requestPAMCheckout.mockResolvedValue({
    request_id: "req-1",
    approval_request_id: "appr-1",
    intent_digest: "digest-1",
    status: "pending",
    approval_count: 0,
    required_approvals: 2,
    expires_at: "2026-11-05T02:00:00Z",
  });
  apiMock.revealPAMCheckout.mockResolvedValue({ checkout: checkout("req-1", "op"), credential: "postgres://orders_app_a:s3cret@db/orders" });
  apiMock.checkInPAMCheckout.mockResolvedValue({ ...checkout("c-1", "op", "checked_in"), ended_by: "op", rotation_command_id: "cmd-1" });
  const view = mount(true);

  const table = await screen.findByRole("table", { name: "Check-outs" });
  expect(within(table).getAllByText(/Revealed; rotates at/)).toHaveLength(2);
  // Only the caller's own revealed check-out can be checked in here.
  expect(within(table).getAllByRole("button", { name: "Check in orders-vault" })).toHaveLength(1);
  // Only vaulted accounts are offered.
  const account = await screen.findByRole("combobox", { name: "Account" });
  expect(within(account).getByRole("option", { name: "orders-vault (postgres, db/orders)" })).toBeInTheDocument();
  expect(within(account).queryByRole("option", { name: /pg-main/ })).not.toBeInTheDocument();
  expect(await axe(view.container)).toHaveNoViolations();

  await user.selectOptions(account, "postgres/orders-vault");
  await user.type(screen.getByRole("textbox", { name: "Reason" }), "INC-4471 reconcile the ledger");
  await user.selectOptions(screen.getByRole("combobox", { name: "Lifetime" }), "1800");
  await user.click(screen.getByRole("button", { name: "Request review" }));
  await waitFor(() =>
    expect(apiMock.requestPAMCheckout).toHaveBeenCalledWith(
      expect.objectContaining({ target_type: "postgres", target_id: "orders-vault", reason: "INC-4471 reconcile the ledger", ttl_seconds: 1800 }),
      expect.any(String),
    ),
  );
  expect(await screen.findByText(/Waiting for 2 approvals from reviewers other than you/)).toBeInTheDocument();

  await user.click(screen.getByRole("button", { name: "Reveal credential" }));
  const request = apiMock.requestPAMCheckout.mock.calls[0][0];
  await waitFor(() =>
    expect(apiMock.revealPAMCheckout).toHaveBeenCalledWith(
      request.request_id,
      { approval_request_id: "appr-1", intent_digest: "digest-1" },
      expect.any(String),
    ),
  );
  const dialog = await screen.findByRole("dialog", { name: "Credential for orders-vault" });
  expect(within(dialog).getByText("postgres://orders_app_a:s3cret@db/orders")).toBeInTheDocument();
  expect(within(dialog).getByText(/Shown once/)).toBeInTheDocument();
  expect(await axe(view.container)).toHaveNoViolations();
  await user.click(within(dialog).getByRole("button", { name: "Close" }));
  expect(screen.queryByText("postgres://orders_app_a:s3cret@db/orders")).not.toBeInTheDocument();

  await user.click(screen.getByRole("button", { name: "Check in orders-vault" }));
  await waitFor(() => expect(apiMock.checkInPAMCheckout).toHaveBeenCalledWith("c-1", expect.any(String)));
  await waitFor(() => expect(screen.getByRole("status")).toHaveTextContent("Checked in orders-vault: the account is being rotated"));
});

it("shows a reader the check-outs without the request form", async () => {
  apiMock.pamCheckouts.mockResolvedValue({ items: [checkout("c-3", "someone-else", "expired")] });
  const view = mount(false);
  const table = await screen.findByRole("table", { name: "Check-outs" });
  expect(within(table).getByText("Reached its deadline; account rotated")).toBeInTheDocument();
  expect(screen.queryByRole("form", { name: "Check out a vaulted account" })).not.toBeInTheDocument();
  expect(screen.queryByRole("button", { name: /Check in/ })).not.toBeInTheDocument();
  expect(apiMock.pamTargets).not.toHaveBeenCalled();
  expect(await axe(view.container)).toHaveNoViolations();
});
