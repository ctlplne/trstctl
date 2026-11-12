import { beforeEach, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { AppQueryProvider } from "@/lib/query";
import { IntlProvider } from "@/i18n/I18nProvider";
import { PAMServiceDependentsDialog } from "@/pages/PAMServiceDependentsDialog";

const { mock } = vi.hoisted(() => ({
  mock: {
    pamServiceDependentHosts: vi.fn(),
    savePAMServiceDependentHost: vi.fn(),
    runPAMServiceDependentInventory: vi.fn(),
    pamServiceDependentScan: vi.fn(),
  },
}));
vi.mock("@/lib/api", async (original) => {
  const actual = await original<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...mock } };
});
const agentID = "56900000-0000-4000-8000-000000000001";
const account = {
  id: "56900000-0000-4000-8000-000000000002",
  provider_id: "ad",
  key: "ad:svc",
  name: "svc-web",
  kind: "directory_service_account" as const,
  privileges: [],
  disabled: false,
  status: "staged" as const,
  first_seen_at: "2026-11-06T00:00:00Z",
  last_seen_at: "2026-11-06T00:00:00Z",
  details: { native_sid: "S-1-5-21-1-2-3-1001" },
};
const host = {
  binding: {
    account: { account_id: account.id, provider_id: "ad", name: "svc-web", dn: "CN=svc-web,DC=test", sid: account.details.native_sid, guid: "1".repeat(32) },
    agent_id: agentID,
    revision: 7,
    enabled: true,
  },
  binding_digest: "a".repeat(64),
  saved_by: "owner",
  updated_at: "2026-11-06T00:00:00Z",
};
const scan = {
  id: "56900000-0000-4000-8000-000000000003",
  intent: { run_id: "56900000-0000-4000-8000-000000000003", binding: host.binding, binding_digest: host.binding_digest },
  status: "partial",
  service_count: 1,
  task_count: 0,
  pool_count: 0,
  report: {
    observed_at: "2026-11-06T00:01:00Z",
    coverage: [
      { family: "services", status: "complete" },
      { family: "tasks", status: "unavailable", failure: "native_read_failed" },
      { family: "iis", status: "complete" },
    ],
    services: [{ name: "owned-web", account_sid: host.binding.account.sid, config_sha256: "b".repeat(64), was_running: true }],
  },
};
beforeEach(() => {
  for (const m of Object.values(mock)) m.mockReset();
  mock.pamServiceDependentHosts.mockResolvedValue({ items: [] });
  mock.savePAMServiceDependentHost.mockImplementation(async () => {
    mock.pamServiceDependentHosts.mockResolvedValue({ items: [host] });
    return host;
  });
  mock.runPAMServiceDependentInventory.mockResolvedValue({ ...scan, status: "queued", report: undefined });
  mock.pamServiceDependentScan.mockResolvedValue(scan);
});
function mount(canManage = true) {
  return render(
    <AppQueryProvider>
      <IntlProvider initialLocale="en-US" initialTimeZone="UTC">
        <PAMServiceDependentsDialog account={account} canManage={canManage} onClose={() => {}} />
      </IntlProvider>
    </AppQueryProvider>,
  );
}
it("binds an exact host, queues a read and preserves unavailable coverage", async () => {
  mount();
  const user = userEvent.setup();
  const input = await screen.findByLabelText("Enrolled host ID");
  await user.type(input, agentID);
  await user.click(screen.getByRole("button", { name: "Add host" }));
  await waitFor(() => expect(mock.savePAMServiceDependentHost).toHaveBeenCalledWith(account.id, agentID, true, expect.any(String)));
  await user.click(await screen.findByRole("button", { name: "Scan host" }));
  await screen.findByText("owned-web");
  expect(screen.getByText(/native_read_failed/)).toBeInTheDocument();
  expect(screen.getByText(/Coverage is incomplete/)).toBeInTheDocument();
  expect(mock.runPAMServiceDependentInventory).toHaveBeenCalledWith(account.id, agentID, expect.any(String));
});
it("reopens a retained scan and labels stale binding evidence without granting writes", async () => {
  mock.pamServiceDependentHosts.mockResolvedValue({
    items: [{ ...host, latest_scan: { id: scan.id, status: "complete", current: false, service_count: 1, task_count: 0, pool_count: 0 } }],
  });
  mount(false);
  const user = userEvent.setup();
  await screen.findByText(/Earlier host binding/);
  await user.click(screen.getByRole("button", { name: "View scan" }));
  await screen.findByText("owned-web");
  expect(screen.queryByRole("button", { name: "Scan host" })).not.toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Add host" })).not.toBeInTheDocument();
});

it("says each AD discovery scan also queues the read on enabled hosts (A267-O1)", async () => {
  mount();
  expect(await screen.findByText(/Each AD discovery scan of this account's source also queues this read on every enabled host/)).toBeInTheDocument();
});
it("shows stopped delivery with the retained failed attempt", async () => {
  mock.pamServiceDependentHosts.mockResolvedValue({
    items: [{ ...host, latest_scan: { id: scan.id, status: "retrying", current: true, service_count: 0, task_count: 0, pool_count: 0 } }],
  });
  mock.pamServiceDependentScan.mockResolvedValue({
    ...scan,
    status: "retrying",
    delivery_status: "failed",
    failure: "agent_execution_failed",
    report: undefined,
  });
  mount();
  const user = userEvent.setup();
  await user.click(await screen.findByRole("button", { name: "View scan" }));
  await screen.findByText(/Delivery stopped/);
  expect(screen.getByText("Delivery: failed")).toBeInTheDocument();
});
it("pages selected hosts with the returned cursor", async () => {
  const other = { ...host, binding: { ...host.binding, agent_id: "56900000-0000-4000-8000-000000000009" } };
  mock.pamServiceDependentHosts.mockImplementation(async (_id, after) => (after ? { items: [other] } : { items: [host], next_cursor: agentID }));
  mount(false);
  const user = userEvent.setup();
  await user.click(await screen.findByRole("button", { name: "Next hosts" }));
  await screen.findByText(other.binding.agent_id);
  expect(mock.pamServiceDependentHosts).toHaveBeenCalledWith(account.id, agentID);
  await user.click(screen.getByRole("button", { name: "Previous hosts" }));
  await screen.findByText(agentID);
});
