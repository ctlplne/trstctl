import { beforeEach, expect, it, vi } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import { AppQueryProvider } from "@/lib/query";
import { IntlProvider } from "@/i18n/I18nProvider";
import { PAMDiscoveryPanel } from "@/pages/PAMDiscoveryPanel";

// A260: the discovery panel scans a source, lists its staged privileged
// accounts, imports selected ones into a folder after review (the requester
// applies the exact approval), dismisses one with a reason, and lists the
// imported accounts. Importing grants nothing.

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    pamDiscoverySources: vi.fn(),
    pamDiscoveredAccounts: vi.fn(),
    pamImportedAccounts: vi.fn(),
    pamServiceDependentHosts: vi.fn(),
    dynamicSecretProviders: vi.fn(),
    savePAMDiscoverySource: vi.fn(),
    runPAMDiscovery: vi.fn(),
    requestPAMDiscoveryImport: vi.fn(),
    applyPAMDiscoveryImport: vi.fn(),
    dismissPAMDiscoveredAccount: vi.fn(),
  },
}));
vi.mock("@/lib/api", async (original) => {
  const actual = await original<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});

const account = (id: string, name: string, privileges: string[]) => ({
  id,
  provider_id: "orders-pg",
  key: `role:${name}`,
  name,
  kind: "database_role",
  privileges,
  disabled: false,
  first_seen_at: "2026-11-05T01:00:00Z",
  last_seen_at: "2026-11-05T01:00:00Z",
  status: "staged",
});

beforeEach(() => {
  for (const mock of Object.values(apiMock)) mock.mockReset();
  apiMock.pamDiscoverySources.mockResolvedValue({
    items: [
      {
        provider_id: "orders-pg",
        provider_type: "postgresql",
        interval_seconds: 86400,
        saved_at: "2026-11-05T01:00:00Z",
        last_run: {
          id: "r1",
          provider_id: "orders-pg",
          status: "completed",
          requested_by: "op",
          started_at: "",
          finished_at: "",
          accounts: 2,
          added: 2,
          removed: 0,
          changed: 0,
        },
      },
    ],
  });
  apiMock.pamDiscoveredAccounts.mockResolvedValue({
    items: [account("a-1", "app_admin", ["superuser"]), account("a-2", "etl", ["member:pg_read_all_data"])],
  });
  apiMock.pamImportedAccounts.mockResolvedValue({ items: [] });
  apiMock.pamServiceDependentHosts.mockResolvedValue({ items: [] });
  apiMock.dynamicSecretProviders.mockResolvedValue({
    configured_providers: [
      { id: "orders-pg", type: "postgresql" },
      { id: "openai", type: "openai" },
    ],
  });
});

function mount(canManage: boolean) {
  return render(
    <AppQueryProvider>
      <IntlProvider initialLocale="en-US" initialTimeZone="UTC">
        <PAMDiscoveryPanel canManage={canManage} />
      </IntlProvider>
    </AppQueryProvider>,
  );
}

it("scans a source, imports selected accounts after review and dismisses one", async () => {
  const user = userEvent.setup();
  apiMock.runPAMDiscovery.mockResolvedValue({ id: "r2", provider_id: "orders-pg", status: "completed", accounts: 2, added: 0, removed: 1, changed: 1 });
  apiMock.requestPAMDiscoveryImport.mockResolvedValue({
    request_id: "req-1",
    approval_request_id: "appr-1",
    intent_digest: "digest-1",
    status: "pending",
    approval_count: 0,
    required_approvals: 2,
    expires_at: "2026-11-05T02:00:00Z",
    accounts: 2,
  });
  apiMock.applyPAMDiscoveryImport.mockResolvedValue({ items: [{ name: "app_admin" }, { name: "etl" }] });
  apiMock.dismissPAMDiscoveredAccount.mockResolvedValue({ ...account("a-2", "etl", []), status: "dismissed" });
  const view = mount(true);

  const sources = await screen.findByRole("table", { name: "Discovery sources" });
  expect(within(sources).getByText(/2 privileged accounts; 2 added, 0 removed/)).toBeInTheDocument();
  // Only providers of a type discovery reads are offered.
  const provider = screen.getByRole("combobox", { name: "Provider" });
  expect(within(provider).queryByRole("option", { name: /openai/ })).not.toBeInTheDocument();
  expect(await axe(view.container)).toHaveNoViolations();

  await user.click(screen.getByRole("button", { name: "Scan orders-pg now" }));
  await waitFor(() => expect(screen.getByRole("status")).toHaveTextContent("Scan of orders-pg: 2 privileged accounts, 0 added, 1 removed, 1 changed."));

  await user.click(await screen.findByRole("checkbox", { name: "Select app_admin for import" }));
  await user.click(screen.getByRole("checkbox", { name: "Select etl for import" }));
  await user.click(screen.getByRole("button", { name: "Import 2 selected accounts" }));
  const dialog = screen.getByRole("dialog", { name: "Import 2 accounts into a folder" });
  await user.type(within(dialog).getByRole("textbox", { name: "Folder" }), "db-admins");
  await user.type(within(dialog).getByRole("textbox", { name: "Reason" }), "bring the DBAs under review");
  await user.click(within(dialog).getByRole("button", { name: "Request review" }));
  await waitFor(() =>
    expect(apiMock.requestPAMDiscoveryImport).toHaveBeenCalledWith(
      expect.objectContaining({ account_ids: ["a-1", "a-2"], folder: "db-admins", reason: "bring the DBAs under review" }),
      expect.any(String),
    ),
  );
  expect(await within(dialog).findByText(/Waiting for 2 approvals from reviewers other than you/)).toBeInTheDocument();
  await user.click(within(dialog).getByRole("button", { name: "Apply approved import" }));
  await waitFor(() =>
    expect(apiMock.applyPAMDiscoveryImport).toHaveBeenCalledWith(
      expect.objectContaining({ account_ids: ["a-1", "a-2"], folder: "db-admins", approval_request_id: "appr-1", intent_digest: "digest-1" }),
      expect.any(String),
    ),
  );
  const request = apiMock.requestPAMDiscoveryImport.mock.calls[0][0];
  expect(apiMock.applyPAMDiscoveryImport.mock.calls[0][0].request_id).toBe(request.request_id);
  await waitFor(() => expect(screen.getByRole("status")).toHaveTextContent("Imported 2 accounts into db-admins."));

  await user.click(screen.getByRole("button", { name: "Dismiss etl" }));
  const dismiss = screen.getByRole("dialog", { name: "Dismiss etl" });
  await user.type(within(dismiss).getByRole("textbox", { name: "Reason" }), "a break-glass role kept outside");
  await user.click(within(dismiss).getByRole("button", { name: "Dismiss account" }));
  await waitFor(() => expect(apiMock.dismissPAMDiscoveredAccount).toHaveBeenCalledWith("a-2", "a break-glass role kept outside", expect.any(String)));
});

it("shows a reader the staged and imported accounts without actions", async () => {
  apiMock.pamImportedAccounts.mockResolvedValue({
    items: [{ provider_id: "orders-pg", key: "role:app_admin", name: "app_admin", privileges: ["superuser"], folder: "db-admins", imported_by: "op" }],
  });
  const view = mount(false);
  const importedTable = await screen.findByRole("table", { name: "Imported accounts" });
  expect(within(importedTable).getByText("db-admins")).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: /Scan .* now/ })).not.toBeInTheDocument();
  expect(screen.queryByRole("checkbox")).not.toBeInTheDocument();
  expect(apiMock.dynamicSecretProviders).not.toHaveBeenCalled();
  expect(await axe(view.container)).toHaveNoViolations();
});

it("shows a native AD service identity without inventing administrator rights", async () => {
  apiMock.pamDiscoveredAccounts.mockResolvedValue({
    items: [
      {
        ...account("ad-service", "orders-service", []),
        key: "user:orders-service",
        kind: "directory_service_account",
        provider_id: "ad-services",
        details: {
          service_account: "true",
          native_sid: "S-1-5-21-1-2-3-1001",
          native_guid: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          configured_rotation_account: "true",
        },
      },
    ],
  });
  mount(false);
  expect(await screen.findByText("AD service account")).toBeVisible();
  expect(screen.getByText("No administrator privileges inferred")).toBeVisible();
  expect(screen.getByText("S-1-5-21-1-2-3-1001")).toBeVisible();
  expect(screen.getByText("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")).toBeVisible();
});

it("keeps native host inventory reachable after an AD account is imported", async () => {
  const native = {
    ...account("native-imported", "svc-web", []),
    kind: "directory_service_account",
    status: "imported",
    details: { native_sid: "S-1-5-21-1-2-3-1001", native_guid: "a".repeat(32) },
  };
  apiMock.pamImportedAccounts.mockResolvedValue({ items: [{ ...native, folder: "service-accounts", imported_by: "owner" }] });
  apiMock.pamDiscoveredAccounts.mockImplementation(async (options) => ({ items: options?.status === "imported" ? [native] : [] }));
  mount(false);
  const user = userEvent.setup();
  await user.click(await screen.findByRole("button", { name: "Dependent hosts" }));
  await screen.findByRole("dialog");
  expect(apiMock.pamServiceDependentHosts).toHaveBeenCalledWith(native.id, "");
  expect(screen.queryByRole("button", { name: "Add host" })).not.toBeInTheDocument();
});
