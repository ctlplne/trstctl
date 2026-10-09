import { beforeEach, expect, it, vi } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { AppQueryProvider } from "@/lib/query";
import { IntlProvider } from "@/i18n/I18nProvider";
import { PAMTargetsPanel } from "@/pages/PAMTargetsPanel";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    pamTargets: vi.fn(),
    registerPAMTarget: vi.fn(),
    disablePAMTarget: vi.fn(),
  },
}));
vi.mock("@/lib/api", async (original) => {
  const actual = await original<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});

beforeEach(() => {
  for (const mock of Object.values(apiMock)) mock.mockReset();
});
function mount(canManage: boolean) {
  render(
    <AppQueryProvider>
      <IntlProvider initialLocale="en-US" initialTimeZone="UTC">
        <PAMTargetsPanel canManage={canManage} />
      </IntlProvider>
    </AppQueryProvider>,
  );
}

it("lets a target registrar create, read back, and disable a tenant target", async () => {
  const user = userEvent.setup();
  let items: Array<Record<string, unknown>> = [];
  apiMock.pamTargets.mockImplementation(async () => ({ items }));
  apiMock.registerPAMTarget.mockImplementation(async () => {
    const created = { id: "incident-db", target_type: "postgres", provider_id: "tenant-pg", allowed_roles: ["readonly"], source: "tenant", enabled: true };
    items = [created];
    return created;
  });
  apiMock.disablePAMTarget.mockImplementation(async () => {
    items = [{ ...items[0], enabled: false }];
    return items[0];
  });
  mount(true);
  expect(await screen.findByText("No privileged access targets are registered.")).toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "Register target" }));
  const form = screen.getByRole("dialog", { name: "Register target" });
  await user.type(within(form).getByRole("textbox", { name: "Target ID" }), "incident-db");
  await user.type(within(form).getByRole("combobox", { name: "PostgreSQL provider ID" }), "tenant-pg");
  await user.click(within(form).getByRole("button", { name: "Register target" }));
  await waitFor(() =>
    expect(apiMock.registerPAMTarget).toHaveBeenCalledWith(
      { id: "incident-db", target_type: "postgres", provider_id: "tenant-pg", allowed_roles: ["readonly"] },
      expect.any(String),
    ),
  );
  expect(await screen.findByText("postgres/incident-db")).toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "Disable target" }));
  const disableDialog = screen.getByRole("dialog", { name: "Disable target" });
  await user.type(within(disableDialog).getByRole("textbox", { name: "Reason for disabling" }), "retired");
  await user.click(within(disableDialog).getByRole("button", { name: "Disable target" }));
  await waitFor(() => expect(apiMock.disablePAMTarget).toHaveBeenCalledWith("postgres", "incident-db", "retired", expect.any(String)));
  expect(await screen.findByText("Target incident-db disabled for new requests.")).toBeInTheDocument();
});

it("shows target inventory but no registration controls to a session requester", async () => {
  apiMock.pamTargets.mockResolvedValue({
    items: [{ id: "incident-db", target_type: "postgres", provider_id: "tenant-pg", allowed_roles: ["readonly"], source: "tenant", enabled: true }],
  });
  mount(false);
  expect(await screen.findByText("postgres/incident-db")).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Register target" })).not.toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Disable target" })).not.toBeInTheDocument();
});
