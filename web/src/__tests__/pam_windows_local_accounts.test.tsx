import { beforeEach, expect, it, vi } from "vitest";
import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, useLocation } from "react-router-dom";
import { axe } from "vitest-axe";
import { AppQueryProvider } from "@/lib/query";
import { IntlProvider } from "@/i18n/I18nProvider";
import { ApiError } from "@/lib/apiTransport";
import { PAMWindowsLocalAccounts } from "@/pages/PAMWindowsLocalAccounts";
const host = "11111111-1111-4111-8111-111111111111";
const run = "22222222-2222-4222-8222-222222222222";
const { calls } = vi.hoisted(() => ({
  calls: {
    pamWindowsLocalAccountHosts: vi.fn(),
    pamWindowsLocalAccountScans: vi.fn(),
    pamWindowsLocalAccountScan: vi.fn(),
    runPAMWindowsLocalAccountInventory: vi.fn(),
  },
}));
vi.mock("@/lib/api", async (original) => {
  const actual = await original<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...calls } };
});
const complete = () => ({
  id: run,
  intent: { run_id: run, tenant_id: "33333333-3333-4333-8333-333333333333", agent_id: host, binding_digest: "a".repeat(64) },
  status: "complete",
  delivery_status: "delivered",
  queued_by: "operator",
  queued_at: "2026-11-07T00:00:00Z",
  queued_event_id: run,
  report_digest: "b".repeat(64),
  signer_fingerprint: "c".repeat(64),
  receipt_job_id: 15,
  attempt: 1,
  report: {
    run_id: run,
    binding_digest: "a".repeat(64),
    observed_at: "2026-11-07T00:01:00Z",
    status: "complete",
    inventory: {
      machine: { name: "OWNED-WIN", sid: "S-1-5-21-1-2-3", role: 3 },
      accounts: [{ name: "OwnedAdmin", sid: "S-1-5-21-1-2-3-1001", enabled: true, locked: false, password_required: true }],
      external_members: 2,
      group_members: 1,
      deleted_members: 0,
    },
  },
});
beforeEach(() => {
  for (const call of Object.values(calls)) call.mockReset();
  calls.pamWindowsLocalAccountHosts.mockResolvedValue({ items: [{ id: host, name: "owned-win", status: "active", last_seen_at: "2026-11-07T00:00:00Z" }] });
  calls.pamWindowsLocalAccountScans.mockResolvedValue({ items: [] });
  calls.pamWindowsLocalAccountScan.mockResolvedValue(complete());
});
function Location() {
  return <output data-testid="native-location">{useLocation().search}</output>;
}
function mount(canManage = true, query = "") {
  return render(
    <AppQueryProvider>
      <IntlProvider initialLocale="en-US" initialTimeZone="UTC">
        <MemoryRouter initialEntries={["/admin/access?tab=discovery" + query]}>
          <PAMWindowsLocalAccounts canManage={canManage} />
          <Location />
        </MemoryRouter>
      </IntlProvider>
    </AppQueryProvider>,
  );
}
it("selects an enrolled host and retries a lost queue reply with the same request key", async () => {
  const user = userEvent.setup();
  calls.runPAMWindowsLocalAccountInventory
    .mockRejectedValueOnce(new Error("owned lost reply"))
    .mockResolvedValueOnce({ ...complete(), status: "queued", report: undefined });
  mount();
  const hosts = await screen.findByRole("table", { name: "Enrolled hosts for local account discovery" });
  await user.click(within(hosts).getByRole("button", { name: "Inspect owned-win" }));
  await user.click(await screen.findByRole("button", { name: "Scan local administrators" }));
  expect(await screen.findByText("owned lost reply")).toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "Scan local administrators" }));
  await waitFor(() => expect(calls.runPAMWindowsLocalAccountInventory).toHaveBeenCalledTimes(2));
  expect(calls.runPAMWindowsLocalAccountInventory.mock.calls[0]).toEqual([host, expect.any(String)]);
  expect(calls.runPAMWindowsLocalAccountInventory.mock.calls[1]).toEqual(calls.runPAMWindowsLocalAccountInventory.mock.calls[0]);
  await waitFor(() => expect(screen.getByTestId("native-location")).toHaveTextContent("windows_run=" + run));
});
it("reopens exact signed metadata read-only, including flags and coverage limits", async () => {
  const view = mount(false, "&windows_host=" + host + "&windows_run=" + run);
  const accounts = await screen.findByRole("table", { name: "Observed local administrators" });
  expect(within(accounts).getByText("OwnedAdmin")).toBeInTheDocument();
  expect(within(accounts).getByText("S-1-5-21-1-2-3-1001")).toBeInTheDocument();
  expect(screen.getByText("OWNED-WIN")).toBeInTheDocument();
  expect(screen.getByText("b".repeat(64))).toBeInTheDocument();
  expect(screen.getByText(/2 foreign members; 1 groups; 0 deleted references/)).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Scan local administrators" })).not.toBeInTheDocument();
  expect(calls.runPAMWindowsLocalAccountInventory).not.toHaveBeenCalled();
  expect(await axe(view.container)).toHaveNoViolations();
});
it("keeps unavailable native coverage separate from a completed empty inventory", async () => {
  const value = complete();
  calls.pamWindowsLocalAccountScan.mockResolvedValue({
    ...value,
    status: "failed",
    failure: "unsupported_os",
    report: { ...value.report, status: "unavailable", failure: "unsupported_os", inventory: undefined },
  });
  mount(false, "&windows_host=" + host + "&windows_run=" + run);
  expect(await screen.findByText("Native inventory unavailable")).toBeInTheDocument();
  expect(screen.getByText("unsupported_os")).toBeInTheDocument();
  expect(screen.queryByText("OwnedAdmin")).not.toBeInTheDocument();
  expect(screen.queryByText("No direct local administrator accounts found")).not.toBeInTheDocument();
});
it("refuses a response for another host instead of rendering its account data", async () => {
  const value = complete();
  calls.pamWindowsLocalAccountScan.mockResolvedValue({ ...value, intent: { ...value.intent, agent_id: "44444444-4444-4444-8444-444444444444" } });
  mount(false, "&windows_host=" + host + "&windows_run=" + run);
  expect(await screen.findByText("The returned scan does not match this host and run.")).toBeInTheDocument();
  expect(screen.queryByText("OwnedAdmin")).not.toBeInTheDocument();
});
it("pages hosts without collecting previous response bodies", async () => {
  const next = "44444444-4444-4444-8444-444444444444";
  calls.pamWindowsLocalAccountHosts.mockImplementation((after?: string) =>
    Promise.resolve(
      after ? { items: [{ id: next, name: "next-win", status: "active" }] } : { items: [{ id: host, name: "owned-win", status: "active" }], next_cursor: host },
    ),
  );
  const user = userEvent.setup();
  mount(false);
  await screen.findByText("owned-win");
  await user.click(screen.getByRole("button", { name: "Next host page" }));
  expect(await screen.findByText("next-win")).toBeInTheDocument();
  expect(screen.queryByText("owned-win")).not.toBeInTheDocument();
  expect(calls.pamWindowsLocalAccountHosts).toHaveBeenLastCalledWith(host);
});

it("refuses an incomplete response that has no host authority", async () => {
  calls.pamWindowsLocalAccountScan.mockResolvedValue({ ...complete(), intent: undefined });
  mount(false, "&windows_host=" + host + "&windows_run=" + run);
  expect(await screen.findByText("The returned scan does not match this host and run.")).toBeInTheDocument();
  expect(screen.queryByText("OwnedAdmin")).not.toBeInTheDocument();
});
it("shows a permission refusal without presenting a cached account list", async () => {
  calls.pamWindowsLocalAccountScan.mockRejectedValue(new ApiError(403, "owned permission refusal"));
  mount(false, "&windows_host=" + host + "&windows_run=" + run);
  expect(await screen.findByText("Scan read permission required")).toBeInTheDocument();
  expect(screen.queryByText("OwnedAdmin")).not.toBeInTheDocument();
});
it("distinguishes a completed empty inventory from unobserved coverage", async () => {
  const value = complete();
  calls.pamWindowsLocalAccountScan.mockResolvedValue({ ...value, report: { ...value.report, inventory: { ...value.report.inventory, accounts: [] } } });
  mount(false, "&windows_host=" + host + "&windows_run=" + run);
  expect(await screen.findByText("No direct local administrator accounts found")).toBeInTheDocument();
  expect(screen.queryByText("Native inventory unavailable")).not.toBeInTheDocument();
});
it("does not navigate back to an old host when its queue reply arrives late", async () => {
  const other = "44444444-4444-4444-8444-444444444444";
  calls.pamWindowsLocalAccountHosts.mockResolvedValue({
    items: [
      { id: host, name: "owned-win", status: "active" },
      { id: other, name: "other-win", status: "active" },
    ],
  });
  let release!: (value: ReturnType<typeof complete>) => void;
  calls.runPAMWindowsLocalAccountInventory.mockImplementation(
    () =>
      new Promise((resolve) => {
        release = resolve;
      }),
  );
  const user = userEvent.setup();
  mount();
  await user.click(await screen.findByRole("button", { name: "Inspect owned-win" }));
  await user.click(await screen.findByRole("button", { name: "Scan local administrators" }));
  await waitFor(() => expect(calls.runPAMWindowsLocalAccountInventory).toHaveBeenCalledTimes(1));
  await user.click(screen.getByRole("button", { name: "Inspect other-win" }));
  await act(async () => {
    release(complete());
  });
  expect(screen.getByTestId("native-location")).toHaveTextContent("windows_host=" + other);
  expect(screen.getByTestId("native-location")).not.toHaveTextContent("windows_run=" + run);
});
