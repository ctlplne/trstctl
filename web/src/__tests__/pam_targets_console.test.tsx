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

it("lists a gateway-served Redis target by its provider and roles", async () => {
  apiMock.pamTargets.mockResolvedValue({
    items: [{ id: "cache", target_type: "redis", provider_id: "tenant-redis", allowed_roles: ["redis-writer"], source: "operator", enabled: true }],
  });
  mount(false);
  expect(await screen.findByText("redis/cache")).toBeInTheDocument();
  expect(screen.getByText("tenant-redis")).toBeInTheDocument();
  expect(screen.getByText("redis-writer")).toBeInTheDocument();
});

it("tells the registrar a PostgreSQL target's private CA travels with each gateway session (A256-L1)", async () => {
  const user = userEvent.setup();
  apiMock.pamTargets.mockResolvedValue({ items: [] });
  mount(true);
  await user.click(await screen.findByRole("button", { name: "Register target" }));
  const form = screen.getByRole("dialog", { name: "Register target" });
  expect(within(form).getByRole("combobox", { name: "Target type" })).toHaveValue("postgres");
  expect(within(form).getByText(/a private CA needs no copy on the gateway's host/)).toBeInTheDocument();
  await user.selectOptions(within(form).getByRole("combobox", { name: "Target type" }), "ssh");
  expect(within(form).queryByText(/a private CA needs no copy on the gateway's host/)).not.toBeInTheDocument();
});

it("requires a gateway for a Snowflake stand-in account and submits only references", async () => {
  const user = userEvent.setup();
  apiMock.pamTargets.mockResolvedValue({ items: [] });
  apiMock.registerPAMTarget.mockImplementation(async (input) => ({ ...input, source: "tenant", enabled: true }));
  mount(true);
  await user.click(await screen.findByRole("button", { name: "Register target" }));
  const form = screen.getByRole("dialog", { name: "Register target" });
  await user.type(within(form).getByRole("textbox", { name: "Target ID" }), "warehouse");
  await user.selectOptions(within(form).getByRole("combobox", { name: "Target type" }), "snowflake");
  await user.type(within(form).getByRole("combobox", { name: "Account provider ID" }), "tenant-snowflake");
  const roles = within(form).getByRole("textbox", { name: "Allowed roles or principals" });
  await user.clear(roles);
  await user.type(roles, "analyst");
  expect(within(form).getByText(/proven against a stand-in/)).toBeInTheDocument();
  await user.click(within(form).getByRole("button", { name: "Register target" }));
  expect(apiMock.registerPAMTarget).not.toHaveBeenCalled();
  await user.type(within(form).getByRole("textbox", { name: "Gateway agent ID" }), "gateway-agent");
  await user.type(within(form).getByRole("textbox", { name: "Gateway address (host:port)" }), "gateway.example:8443");
  await user.click(within(form).getByRole("button", { name: "Register target" }));
  await waitFor(() =>
    expect(apiMock.registerPAMTarget).toHaveBeenCalledWith(
      {
        id: "warehouse",
        target_type: "snowflake",
        provider_id: "tenant-snowflake",
        allowed_roles: ["analyst"],
        gateway_agent_id: "gateway-agent",
        gateway_address: "gateway.example:8443",
      },
      expect.any(String),
    ),
  );
});

it("registers an AWS API account using a provider and required gateway references", async () => {
  const user = userEvent.setup();
  apiMock.pamTargets.mockResolvedValue({ items: [] });
  apiMock.registerPAMTarget.mockImplementation(async (input) => ({ ...input, source: "tenant", enabled: true }));
  mount(true);
  await user.click(await screen.findByRole("button", { name: "Register target" }));
  const form = screen.getByRole("dialog", { name: "Register target" });
  await user.type(within(form).getByRole("textbox", { name: "Target ID" }), "cloud-reader");
  await user.selectOptions(within(form).getByRole("combobox", { name: "Target type" }), "aws");
  await user.type(within(form).getByRole("combobox", { name: "Account provider ID" }), "tenant-sts");
  const roles = within(form).getByRole("textbox", { name: "Allowed roles or principals" });
  await user.clear(roles);
  await user.type(roles, "reader");
  expect(within(form).getByText(/authorization uses a stand-in/)).toBeInTheDocument();
  await user.type(within(form).getByRole("textbox", { name: "Gateway agent ID" }), "gateway-agent");
  await user.type(within(form).getByRole("textbox", { name: "Gateway address (host:port)" }), "gateway.example:8443");
  await user.click(within(form).getByRole("button", { name: "Register target" }));
  await waitFor(() =>
    expect(apiMock.registerPAMTarget).toHaveBeenCalledWith(
      {
        id: "cloud-reader",
        target_type: "aws",
        provider_id: "tenant-sts",
        allowed_roles: ["reader"],
        gateway_agent_id: "gateway-agent",
        gateway_address: "gateway.example:8443",
      },
      expect.any(String),
    ),
  );
});

it("registers a Google Cloud API account using a provider and required gateway references", async () => {
  const user = userEvent.setup();
  apiMock.pamTargets.mockResolvedValue({ items: [] });
  apiMock.registerPAMTarget.mockImplementation(async (input) => ({ ...input, source: "tenant", enabled: true }));
  mount(true);
  await user.click(await screen.findByRole("button", { name: "Register target" }));
  const form = screen.getByRole("dialog", { name: "Register target" });
  await user.type(within(form).getByRole("textbox", { name: "Target ID" }), "cloud-reader");
  await user.selectOptions(within(form).getByRole("combobox", { name: "Target type" }), "gcp");
  await user.type(within(form).getByRole("combobox", { name: "Account provider ID" }), "tenant-gcp");
  const roles = within(form).getByRole("textbox", { name: "Allowed roles or principals" });
  await user.clear(roles);
  await user.type(roles, "reader");
  expect(within(form).getByText(/existing tokens keep their native expiry/)).toBeInTheDocument();
  await user.type(within(form).getByRole("textbox", { name: "Gateway agent ID" }), "gateway-agent");
  await user.type(within(form).getByRole("textbox", { name: "Gateway address (host:port)" }), "gateway.example:8443");
  await user.click(within(form).getByRole("button", { name: "Register target" }));
  await waitFor(() =>
    expect(apiMock.registerPAMTarget).toHaveBeenCalledWith(
      {
        id: "cloud-reader",
        target_type: "gcp",
        provider_id: "tenant-gcp",
        allowed_roles: ["reader"],
        gateway_agent_id: "gateway-agent",
        gateway_address: "gateway.example:8443",
      },
      expect.any(String),
    ),
  );
});

it("registers a Azure application API account using a provider and required gateway references", async () => {
  const user = userEvent.setup();
  apiMock.pamTargets.mockResolvedValue({ items: [] });
  apiMock.registerPAMTarget.mockImplementation(async (input) => ({ ...input, source: "tenant", enabled: true }));
  mount(true);
  await user.click(await screen.findByRole("button", { name: "Register target" }));
  const form = screen.getByRole("dialog", { name: "Register target" });
  await user.type(within(form).getByRole("textbox", { name: "Target ID" }), "cloud-reader");
  await user.selectOptions(within(form).getByRole("combobox", { name: "Target type" }), "azure");
  await user.type(within(form).getByRole("combobox", { name: "Account provider ID" }), "tenant-entra");
  const roles = within(form).getByRole("textbox", { name: "Allowed roles or principals" });
  await user.clear(roles);
  await user.type(roles, "reader");
  expect(within(form).getByText(/issued tokens keep their native expiry/)).toBeInTheDocument();
  await user.type(within(form).getByRole("textbox", { name: "Gateway agent ID" }), "gateway-agent");
  await user.type(within(form).getByRole("textbox", { name: "Gateway address (host:port)" }), "gateway.example:8443");
  await user.click(within(form).getByRole("button", { name: "Register target" }));
  await waitFor(() =>
    expect(apiMock.registerPAMTarget).toHaveBeenCalledWith(
      {
        id: "cloud-reader",
        target_type: "azure",
        provider_id: "tenant-entra",
        allowed_roles: ["reader"],
        gateway_agent_id: "gateway-agent",
        gateway_address: "gateway.example:8443",
      },
      expect.any(String),
    ),
  );
});

it("registers an AWS native console handoff using a provider and required gateway references", async () => {
  const user = userEvent.setup();
  apiMock.pamTargets.mockResolvedValue({ items: [] });
  apiMock.registerPAMTarget.mockImplementation(async (input) => ({ ...input, source: "tenant", enabled: true }));
  mount(true);
  await user.click(await screen.findByRole("button", { name: "Register target" }));
  const form = screen.getByRole("dialog", { name: "Register target" });
  await user.type(within(form).getByRole("textbox", { name: "Target ID" }), "cloud-reader");
  await user.selectOptions(within(form).getByRole("combobox", { name: "Target type" }), "aws-console");
  await user.type(within(form).getByRole("combobox", { name: "Account provider ID" }), "tenant-sts");
  const roles = within(form).getByRole("textbox", { name: "Allowed roles or principals" });
  await user.clear(roles);
  await user.type(roles, "reader");
  expect(within(form).getByText(/native console activity and cookies remain outside gateway capture/)).toBeInTheDocument();
  await user.type(within(form).getByRole("textbox", { name: "Gateway agent ID" }), "gateway-agent");
  await user.type(within(form).getByRole("textbox", { name: "Gateway address (host:port)" }), "gateway.example:8443");
  await user.click(within(form).getByRole("button", { name: "Register target" }));
  await waitFor(() =>
    expect(apiMock.registerPAMTarget).toHaveBeenCalledWith(
      {
        id: "cloud-reader",
        target_type: "aws-console",
        provider_id: "tenant-sts",
        allowed_roles: ["reader"],
        gateway_agent_id: "gateway-agent",
        gateway_address: "gateway.example:8443",
      },
      expect.any(String),
    ),
  );
});

it("registers a vaulted desktop with one account secret and explicit gateway references", async () => {
  const user = userEvent.setup();
  apiMock.pamTargets.mockResolvedValue({ items: [] });
  apiMock.registerPAMTarget.mockImplementation(async (input) => ({ ...input, source: "tenant", enabled: true }));
  mount(true);
  await user.click(await screen.findByRole("button", { name: "Register target" }));
  const form = screen.getByRole("dialog", { name: "Register target" });
  await user.type(within(form).getByRole("textbox", { name: "Target ID" }), "desktop-lab");
  await user.selectOptions(within(form).getByRole("combobox", { name: "Target type" }), "rdp");
  await user.type(within(form).getByRole("combobox", { name: "Account provider ID" }), "desktop-provider");
  const role = within(form).getByRole("combobox", { name: "Account secret" });
  await user.clear(role);
  await user.type(role, "desktop/account");
  expect(within(form).getByText(/pixel masking is not automatic/)).toBeInTheDocument();
  await user.type(within(form).getByRole("textbox", { name: "Gateway agent ID" }), "gateway-agent");
  await user.type(within(form).getByRole("textbox", { name: "Gateway address (host:port)" }), "gateway.example:8443");
  await user.click(within(form).getByRole("button", { name: "Register target" }));
  await waitFor(() =>
    expect(apiMock.registerPAMTarget).toHaveBeenCalledWith(
      {
        id: "desktop-lab",
        target_type: "rdp",
        provider_id: "desktop-provider",
        allowed_roles: ["desktop/account"],
        account_secret: "desktop/account",
        gateway_agent_id: "gateway-agent",
        gateway_address: "gateway.example:8443",
      },
      expect.any(String),
    ),
  );
});

it("registers a vaulted network device with one account secret and explicit gateway references", async () => {
  const user = userEvent.setup();
  apiMock.pamTargets.mockResolvedValue({ items: [] });
  apiMock.registerPAMTarget.mockImplementation(async (input) => ({ ...input, source: "tenant", enabled: true }));
  mount(true);
  await user.click(await screen.findByRole("button", { name: "Register target" }));
  const form = screen.getByRole("dialog", { name: "Register target" });
  await user.type(within(form).getByRole("textbox", { name: "Target ID" }), "core-ops");
  await user.selectOptions(within(form).getByRole("combobox", { name: "Target type" }), "netdevice");
  await user.type(within(form).getByRole("combobox", { name: "Account provider ID" }), "core-device");
  const role = within(form).getByRole("combobox", { name: "Account secret" });
  await user.clear(role);
  await user.type(role, "net/core");
  expect(within(form).getByText(/no real device yet/)).toBeInTheDocument();
  await user.type(within(form).getByRole("textbox", { name: "Gateway agent ID" }), "gateway-agent");
  await user.type(within(form).getByRole("textbox", { name: "Gateway address (host:port)" }), "gateway.example:8443");
  await user.click(within(form).getByRole("button", { name: "Register target" }));
  await waitFor(() =>
    expect(apiMock.registerPAMTarget).toHaveBeenCalledWith(
      {
        id: "core-ops",
        target_type: "netdevice",
        provider_id: "core-device",
        allowed_roles: ["net/core"],
        account_secret: "net/core",
        gateway_agent_id: "gateway-agent",
        gateway_address: "gateway.example:8443",
      },
      expect.any(String),
    ),
  );
});

it("registers a web admin console with its vaulted account, its https origin and explicit gateway references (A273)", async () => {
  const user = userEvent.setup();
  apiMock.pamTargets.mockResolvedValue({ items: [] });
  apiMock.registerPAMTarget.mockImplementation(async (input) => ({ ...input, source: "tenant", enabled: true }));
  mount(true);
  await user.click(await screen.findByRole("button", { name: "Register target" }));
  const form = screen.getByRole("dialog", { name: "Register target" });
  await user.type(within(form).getByRole("textbox", { name: "Target ID" }), "grafana-admin");
  await user.selectOptions(within(form).getByRole("combobox", { name: "Target type" }), "webconsole");
  expect(within(form).queryByRole("combobox", { name: "Account provider ID" })).not.toBeInTheDocument();
  const secret = within(form).getByRole("textbox", { name: "Account secret" });
  await user.clear(secret);
  await user.type(secret, "consoles/grafana-admin");
  const address = within(form).getByRole("textbox", { name: "Console address" });
  await user.type(address, "http://grafana.internal.example/admin");
  expect(within(form).getByText(/the browser never receives the password/)).toBeInTheDocument();
  await user.type(within(form).getByRole("textbox", { name: "Gateway agent ID" }), "gateway-agent");
  await user.type(within(form).getByRole("textbox", { name: "Gateway address (host:port)" }), "gateway.example:8443");
  await user.click(within(form).getByRole("button", { name: "Register target" }));
  expect(await within(form).findByText(/origin over https/)).toBeInTheDocument();
  expect(apiMock.registerPAMTarget).not.toHaveBeenCalled();
  await user.clear(address);
  await user.type(address, "https://grafana.internal.example");
  await user.click(within(form).getByRole("button", { name: "Register target" }));
  await waitFor(() =>
    expect(apiMock.registerPAMTarget).toHaveBeenCalledWith(
      {
        id: "grafana-admin",
        target_type: "webconsole",
        allowed_roles: ["consoles/grafana-admin"],
        account_secret: "consoles/grafana-admin",
        web: { url: "https://grafana.internal.example" },
        gateway_agent_id: "gateway-agent",
        gateway_address: "gateway.example:8443",
      },
      expect.any(String),
    ),
  );
});

it("registers a Windows local administrator account for check-out with its native provider and no gateway (A268)", async () => {
  const user = userEvent.setup();
  apiMock.pamTargets.mockResolvedValue({ items: [] });
  apiMock.registerPAMTarget.mockImplementation(async (input) => ({ ...input, source: "tenant", enabled: true }));
  mount(true);
  await user.click(await screen.findByRole("button", { name: "Register target" }));
  const form = screen.getByRole("dialog", { name: "Register target" });
  await user.type(within(form).getByRole("textbox", { name: "Target ID" }), "host-admin");
  await user.type(within(form).getByRole("textbox", { name: "Gateway agent ID" }), "typed-before-the-type");
  await user.selectOptions(within(form).getByRole("combobox", { name: "Target type" }), "windows_local");
  expect(within(form).queryByRole("textbox", { name: "Gateway agent ID" })).not.toBeInTheDocument();
  expect(within(form).getByText(/never opened as a session/)).toBeInTheDocument();
  await user.type(within(form).getByRole("combobox", { name: "Account provider ID" }), "host-sam");
  const secret = within(form).getByRole("combobox", { name: "Account secret" });
  await user.clear(secret);
  await user.type(secret, "hosts/local-admin");
  await user.click(within(form).getByRole("button", { name: "Register target" }));
  await waitFor(() =>
    expect(apiMock.registerPAMTarget).toHaveBeenCalledWith(
      {
        id: "host-admin",
        target_type: "windows_local",
        provider_id: "host-sam",
        allowed_roles: ["hosts/local-admin"],
        account_secret: "hosts/local-admin",
      },
      expect.any(String),
    ),
  );
});

it("registers an account its provider rotates in place for check-out, with no gateway (A271)", async () => {
  const user = userEvent.setup();
  apiMock.pamTargets.mockResolvedValue({ items: [] });
  apiMock.registerPAMTarget.mockImplementation(async (input) => ({ ...input, source: "tenant", enabled: true }));
  mount(true);
  await user.click(await screen.findByRole("button", { name: "Register target" }));
  const form = screen.getByRole("dialog", { name: "Register target" });
  await user.type(within(form).getByRole("textbox", { name: "Target ID" }), "esxi-root");
  await user.selectOptions(within(form).getByRole("combobox", { name: "Target type" }), "account");
  expect(within(form).queryByRole("textbox", { name: "Gateway address (host:port)" })).not.toBeInTheDocument();
  expect(within(form).getByText(/a Redfish controller or a network device/)).toBeInTheDocument();
  await user.type(within(form).getByRole("combobox", { name: "Account provider ID" }), "esxi-host");
  const secret = within(form).getByRole("combobox", { name: "Account secret" });
  await user.clear(secret);
  await user.type(secret, "infra/esxi-root");
  await user.click(within(form).getByRole("button", { name: "Register target" }));
  await waitFor(() =>
    expect(apiMock.registerPAMTarget).toHaveBeenCalledWith(
      { id: "esxi-root", target_type: "account", provider_id: "esxi-host", allowed_roles: ["infra/esxi-root"], account_secret: "infra/esxi-root" },
      expect.any(String),
    ),
  );
});

it("registers a break-glass identity provider administrator with its provider and no gateway (A272)", async () => {
  const user = userEvent.setup();
  apiMock.pamTargets.mockResolvedValue({ items: [] });
  apiMock.registerPAMTarget.mockImplementation(async (input) => ({ ...input, source: "tenant", enabled: true }));
  mount(true);
  await user.click(await screen.findByRole("button", { name: "Register target" }));
  const form = screen.getByRole("dialog", { name: "Register target" });
  await user.type(within(form).getByRole("textbox", { name: "Target ID" }), "okta-bg");
  await user.selectOptions(within(form).getByRole("combobox", { name: "Target type" }), "breakglass");
  expect(within(form).queryByRole("textbox", { name: "Gateway agent ID" })).not.toBeInTheDocument();
  expect(within(form).getByText(/released only through emergency access/)).toBeInTheDocument();
  await user.type(within(form).getByRole("combobox", { name: "Account provider ID" }), "okta-org");
  const secret = within(form).getByRole("combobox", { name: "Account secret" });
  await user.clear(secret);
  await user.type(secret, "bg/okta");
  await user.click(within(form).getByRole("button", { name: "Register target" }));
  await waitFor(() =>
    expect(apiMock.registerPAMTarget).toHaveBeenCalledWith(
      { id: "okta-bg", target_type: "breakglass", provider_id: "okta-org", allowed_roles: ["bg/okta"], account_secret: "bg/okta" },
      expect.any(String),
    ),
  );
});
