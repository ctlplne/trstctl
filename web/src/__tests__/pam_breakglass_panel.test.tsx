import { beforeEach, expect, it, vi } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import { AppQueryProvider } from "@/lib/query";
import { IntlProvider } from "@/i18n/I18nProvider";
import { PAMBreakGlassPanel } from "@/pages/PAMBreakGlassPanel";
import { PAMCheckoutPanel } from "@/pages/PAMCheckoutPanel";

// A272: a named responder releases a break-glass account once, after a
// confirmation that every approver is notified; the dialog shows the
// password, the current one-time code and the hardware key holders, and
// checks it in. Another approver records the post-incident review; the
// responder is never offered their own. Reviewed check-outs never offer a
// break-glass or web console account.

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    pamTargets: vi.fn(),
    pamEmergencyGrants: vi.fn(),
    openPAMEmergencyCheckout: vi.fn(),
    checkInPAMCheckout: vi.fn(),
    reviewPAMEmergencyGrant: vi.fn(),
    pamCheckouts: vi.fn(),
  },
}));
vi.mock("@/lib/api", async (original) => {
  const actual = await original<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});

const grant = (sessionID: string, responder: string, status = "pending") => ({
  session_id: sessionID,
  responder,
  reason: "IdP outage",
  target_type: "breakglass",
  target_id: "okta-bg",
  role: "bg/okta",
  opened_at: "2026-11-07T18:00:00Z",
  expires_at: "2026-11-07T18:05:00Z",
  review: { status },
});

beforeEach(() => {
  for (const mock of Object.values(apiMock)) mock.mockReset();
  apiMock.pamTargets.mockResolvedValue({
    items: [
      { id: "okta-bg", target_type: "breakglass", provider_id: "okta-org", allowed_roles: ["bg/okta"], account_secret: "bg/okta", enabled: true },
      { id: "grafana-admin", target_type: "webconsole", allowed_roles: ["consoles/grafana"], account_secret: "consoles/grafana", enabled: true },
      { id: "orders-vault", target_type: "postgres", provider_id: "pam-pg-vault", allowed_roles: ["db/orders"], account_secret: "db/orders", enabled: true },
    ],
  });
  apiMock.pamEmergencyGrants.mockResolvedValue({ items: [] });
  apiMock.pamCheckouts.mockResolvedValue({ items: [] });
});

function mount(subject: string, canRelease: boolean, canReview: boolean) {
  return render(
    <AppQueryProvider>
      <IntlProvider initialLocale="en-US" initialTimeZone="UTC">
        <PAMBreakGlassPanel subject={subject} canRelease={canRelease} canReview={canReview} />
      </IntlProvider>
    </AppQueryProvider>,
  );
}

it("releases a break-glass account once after confirming every approver is notified, shows its code and key holders, and checks it in (A272)", async () => {
  const user = userEvent.setup();
  apiMock.openPAMEmergencyCheckout.mockResolvedValue({
    checkout: { request_id: "release-1", target_type: "breakglass", target_id: "okta-bg", expires_at: "2026-11-07T18:05:00Z", status: "revealed" },
    credential: JSON.stringify({
      username: "breakglass@corp.example",
      password: "Bg-Released-Password-1",
      totp_code: "492039",
      totp_valid_until: "2026-11-07T18:00:30Z",
    }),
    hardware_key_holders: ["alice", "bob"],
    emergency: grant("release-1", "carol"),
  });
  apiMock.checkInPAMCheckout.mockResolvedValue({ request_id: "release-1", status: "checked_in" });
  const view = mount("carol", true, false);
  const account = await screen.findByRole("combobox", { name: "Break-glass account" });
  expect(within(account).queryByRole("option", { name: "grafana-admin" })).not.toBeInTheDocument();
  await user.selectOptions(account, "okta-bg");
  await user.type(screen.getByRole("textbox", { name: "Reason" }), "IdP outage");
  await user.click(screen.getByRole("button", { name: "Release now" }));
  expect(apiMock.openPAMEmergencyCheckout).not.toHaveBeenCalled();
  expect(screen.getByRole("alert")).toHaveTextContent("Every approver is notified now");
  await user.click(screen.getByRole("button", { name: "Release" }));
  await waitFor(() =>
    expect(apiMock.openPAMEmergencyCheckout).toHaveBeenCalledWith(
      { request_id: expect.any(String), target_type: "breakglass", target_id: "okta-bg", reason: "IdP outage", ttl_seconds: 300 },
      expect.any(String),
    ),
  );
  const dialog = await screen.findByRole("dialog", { name: "Break-glass credential for okta-bg" });
  expect(dialog).toHaveTextContent("breakglass@corp.example");
  expect(dialog).toHaveTextContent("492039");
  expect(dialog).toHaveTextContent("alice, bob");
  expect(await axe(view.container)).toHaveNoViolations();
  await user.click(within(dialog).getByRole("button", { name: "Check in now (rotates the password)" }));
  await waitFor(() => expect(apiMock.checkInPAMCheckout).toHaveBeenCalledWith("release-1", expect.any(String)));
  await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
  expect(screen.getByRole("status")).toHaveTextContent("okta-bg was checked in");
});

it("records another approver's post-incident review and never offers responders their own (A258)", async () => {
  const user = userEvent.setup();
  apiMock.pamEmergencyGrants.mockResolvedValue({ items: [grant("g-1", "carol"), grant("g-2", "dave")] });
  apiMock.reviewPAMEmergencyGrant.mockResolvedValue({ ...grant("g-1", "carol", "reviewed") });
  mount("dave", false, true);
  const table = await screen.findByRole("table", { name: "Emergency grants" });
  const rows = within(table).getAllByRole("row");
  expect(within(rows[2]).queryByRole("button")).not.toBeInTheDocument();
  expect(rows[2]).toHaveTextContent("Review pending");
  expect(screen.queryByRole("button", { name: "Release now" })).not.toBeInTheDocument();
  await user.click(within(rows[1]).getByRole("button", { name: "Review okta-bg" }));
  const form = screen.getByRole("form", { name: "Post-incident review of okta-bg" });
  await user.selectOptions(within(form).getByRole("combobox", { name: "Outcome" }), "unjustified");
  await user.type(within(form).getByRole("textbox", { name: "Notes" }), "No outage on record");
  await user.click(within(form).getByRole("button", { name: "Save review" }));
  await waitFor(() =>
    expect(apiMock.reviewPAMEmergencyGrant).toHaveBeenCalledWith("g-1", { outcome: "unjustified", notes: "No outage on record" }, expect.any(String)),
  );
});

it("never offers a break-glass or web console account for a reviewed check-out (A272, A273)", async () => {
  render(
    <AppQueryProvider>
      <IntlProvider initialLocale="en-US" initialTimeZone="UTC">
        <PAMCheckoutPanel subject="op" canRequest canCheckInAny={false} />
      </IntlProvider>
    </AppQueryProvider>,
  );
  const options = await screen.findAllByRole("option");
  const labels = options.map((option) => option.textContent ?? "");
  expect(labels.some((label) => label.includes("orders-vault"))).toBe(true);
  expect(labels.some((label) => label.includes("okta-bg") || label.includes("grafana-admin"))).toBe(false);
});
