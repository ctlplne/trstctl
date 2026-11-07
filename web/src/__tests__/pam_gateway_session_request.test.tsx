import { beforeEach, expect, it, vi } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { ThemeProvider } from "@/components/ThemeProvider";
import { AppQueryProvider } from "@/lib/query";
import { IntlProvider } from "@/i18n/I18nProvider";
import { AdminAccess } from "@/pages/AdminAccess";

// A273 (and every gateway type): the privileged session dialog requests a
// session to a web admin console like any other — reviewed, then activated —
// and the opened session shows how to connect through its gateway and its
// one-time ticket, never a credential.

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    accessRoles: vi.fn(),
    oidcMappingStatus: vi.fn(),
    members: vi.fn(),
    apiTokens: vi.fn(),
    pamSessions: vi.fn(),
    requestPAMSession: vi.fn(),
    pamRequestProgress: vi.fn(),
    openPAMSession: vi.fn(),
  },
}));
vi.mock("@/lib/bootstrapApi", async (original) => {
  const actual = await original<typeof import("@/lib/bootstrapApi")>();
  return { ...actual, bootstrapApi: { ...actual.bootstrapApi, ...apiMock } };
});
vi.mock("@/lib/api", async (original) => {
  const actual = await original<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});

const pending = {
  request_id: "66666666-6666-4666-8666-666666666666",
  approval_request_id: "77777777-7777-4777-8777-777777777777",
  intent_digest: "reviewed-web-console",
  status: "approved",
  approval_count: 2,
  required_approvals: 2,
  expires_at: "2999-01-01T00:00:00Z",
  target_type: "webconsole",
  target_id: "grafana-admin",
  role: "consoles/grafana-admin",
};

beforeEach(() => {
  for (const mock of Object.values(apiMock)) mock.mockReset();
  apiMock.accessRoles.mockResolvedValue({ items: [{ name: "operator", permissions: ["access:read", "access:write"] }] });
  apiMock.members.mockResolvedValue({ items: [] });
  apiMock.oidcMappingStatus.mockResolvedValue({ configured: false, mappings: [] });
  apiMock.apiTokens.mockResolvedValue({ items: [] });
  apiMock.pamSessions.mockResolvedValue({ items: [] });
  apiMock.requestPAMSession.mockResolvedValue({ ...pending, status: "pending", approval_count: 0 });
  apiMock.pamRequestProgress.mockResolvedValue(pending);
  apiMock.openPAMSession.mockResolvedValue({
    id: "88888888-8888-4888-8888-888888888888",
    target_type: "webconsole",
    target_id: "grafana-admin",
    role: "consoles/grafana-admin",
    status: "active",
    subject: "operator",
    requested_by: "operator",
    started_at: "2026-11-07T18:30:00Z",
    expires_at: "2026-11-07T18:45:00Z",
    delivery: "gateway",
    gateway: { address: "gateway.example:8443", agent_id: "agent-1", spiffe_id: "spiffe://trstctl/agent-1", ticket: "one-time-gateway-ticket" },
  });
});

it("requests a reviewed web console session and shows how to connect, with its ticket only on request (A273)", async () => {
  const user = userEvent.setup();
  render(
    <AppQueryProvider>
      <ThemeProvider>
        <IntlProvider initialLocale="en-US" initialTimeZone="UTC">
          <MemoryRouter>
            <AdminAccess />
          </MemoryRouter>
        </IntlProvider>
      </ThemeProvider>
    </AppQueryProvider>,
  );
  await screen.findByRole("heading", { level: 1, name: "People and roles" });
  await user.click(screen.getByText("Sessions and access keys", { exact: true }));
  await user.click(await screen.findByRole("button", { name: "Request privileged session" }));
  const dialog = screen.getByRole("dialog", { name: "Request privileged session" });
  await user.selectOptions(within(dialog).getByRole("combobox", { name: "Target type" }), "webconsole");
  expect(within(dialog).queryByRole("checkbox")).not.toBeInTheDocument();
  await user.type(within(dialog).getByRole("textbox", { name: "Target ID" }), "grafana-admin");
  await user.type(within(dialog).getByRole("textbox", { name: "Role" }), "consoles/grafana-admin");
  await user.type(within(dialog).getByRole("textbox", { name: "Method" }), "oidc");
  await user.type(within(dialog).getByRole("textbox", { name: "Payload (base64)" }), "Z2VudWluZQ==");
  await user.click(within(dialog).getByRole("button", { name: "Request review" }));
  await waitFor(() => expect(apiMock.requestPAMSession).toHaveBeenCalledTimes(1));
  expect(apiMock.requestPAMSession.mock.calls[0][0]).toMatchObject({ target_type: "webconsole", target_id: "grafana-admin", role: "consoles/grafana-admin" });
  await user.click(await within(dialog).findByRole("button", { name: "Refresh approval status" }));
  await user.click(await within(dialog).findByRole("button", { name: "Activate approved session" }));
  expect(await within(dialog).findByText("Session opened")).toBeInTheDocument();
  expect(apiMock.openPAMSession.mock.calls[0][0]).not.toHaveProperty("browser");
  expect(within(dialog).getByText("trstctl access sessions connect 88888888-8888-4888-8888-888888888888 --ticket-file ticket.txt")).toBeInTheDocument();
  expect(within(dialog).getByText(/open the address it prints in your browser/)).toBeInTheDocument();
  expect(within(dialog).queryByText("one-time-gateway-ticket")).not.toBeInTheDocument();
  await user.click(within(dialog).getByRole("button", { name: "Reveal one-time credential" }));
  expect(within(dialog).getByText("one-time-gateway-ticket")).toBeInTheDocument();
});
