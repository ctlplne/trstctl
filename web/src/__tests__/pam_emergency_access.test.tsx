import { beforeEach, expect, it, vi } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import { MemoryRouter } from "react-router-dom";
import { AppQueryProvider } from "@/lib/query";
import { IntlProvider } from "@/i18n/I18nProvider";
import { ThemeProvider } from "@/components/ThemeProvider";
import { AdminAccess } from "@/pages/AdminAccess";
import { PAMEmergencyRespondersPanel } from "@/pages/PAMEmergencyRespondersPanel";

// A258: the console names the emergency responders, and a responder opens a
// session at once from the session dialog — only after confirming that every
// approver is notified and that it needs a post-incident review — without a
// review request.

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
    openPAMEmergencySession: vi.fn(),
    pamEmergencyResponders: vi.fn(),
    setPAMEmergencyResponders: vi.fn(),
  },
}));
vi.mock("@/auth/AuthProvider", async (orig) => ({
  ...(await orig<typeof import("@/auth/AuthProvider")>()),
  useAuth: () => ({
    user: { tenant_id: "t1", subject: "responder@example.test", permissions: ["access:read", "access:write", "access:sessions.open"] },
    preview: false,
  }),
}));
vi.mock("@/lib/bootstrapApi", async (original) => {
  const actual = await original<typeof import("@/lib/bootstrapApi")>();
  return { ...actual, bootstrapApi: { ...actual.bootstrapApi, ...apiMock } };
});
vi.mock("@/lib/api", async (original) => {
  const actual = await original<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});

beforeEach(() => {
  for (const mock of Object.values(apiMock)) mock.mockReset();
  apiMock.accessRoles.mockResolvedValue({ items: [{ name: "operator", permissions: ["access:read", "access:write"] }] });
  apiMock.members.mockResolvedValue({ items: [] });
  apiMock.oidcMappingStatus.mockResolvedValue({ configured: false, mappings: [] });
  apiMock.apiTokens.mockResolvedValue({ items: [] });
  apiMock.pamSessions.mockResolvedValue({ items: [] });
  apiMock.pamEmergencyResponders.mockResolvedValue({ subjects: ["carol@example.test"] });
  apiMock.setPAMEmergencyResponders.mockImplementation(async (input) => input);
  apiMock.openPAMEmergencySession.mockResolvedValue({
    id: "55555555-5555-4555-8555-555555555555",
    target_type: "postgres",
    target_id: "incident-db",
    role: "readonly",
    status: "active",
    subject: "responder@example.test",
    requested_by: "responder@example.test",
    started_at: "2026-11-07T18:00:00Z",
    expires_at: "2026-11-07T18:15:00Z",
  });
});

it("opens a session at once as a named responder only after confirming every approver is notified (A258)", async () => {
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
  await user.type(within(dialog).getByRole("textbox", { name: "Target ID" }), "incident-db");
  await user.type(within(dialog).getByRole("textbox", { name: "Role" }), "readonly");
  await user.type(within(dialog).getByRole("textbox", { name: "Method" }), "oidc");
  await user.type(within(dialog).getByRole("textbox", { name: "Payload (base64)" }), "Z2VudWluZQ==");
  await user.click(within(dialog).getByRole("button", { name: "Open now in an emergency" }));
  expect(within(dialog).getByRole("alert")).toHaveTextContent("Every approver is notified now");
  await user.click(within(dialog).getByRole("button", { name: "Open now" }));
  expect(await within(dialog).findByText("Emergency access needs a reason.")).toBeInTheDocument();
  expect(apiMock.openPAMEmergencySession).not.toHaveBeenCalled();
  const reason = within(dialog)
    .getAllByRole("textbox")
    .find((box) => box.getAttribute("name") === "reason");
  if (!reason) throw new Error("no reason field");
  await user.type(reason, "INC-9001 database down");
  await user.click(within(dialog).getByRole("button", { name: "Open now in an emergency" }));
  await user.click(within(dialog).getByRole("button", { name: "Open now" }));
  await waitFor(() =>
    expect(apiMock.openPAMEmergencySession).toHaveBeenCalledWith(
      {
        target_type: "postgres",
        target_id: "incident-db",
        role: "readonly",
        reason: "INC-9001 database down",
        method: "oidc",
        payload_base64: "Z2VudWluZQ==",
      },
      expect.any(String),
    ),
  );
  expect(apiMock.requestPAMSession).not.toHaveBeenCalled();
  expect(await within(dialog).findByText("Session opened")).toBeInTheDocument();
});

it("names the emergency responders, one per line (A258)", async () => {
  const user = userEvent.setup();
  const view = render(
    <AppQueryProvider>
      <IntlProvider initialLocale="en-US" initialTimeZone="UTC">
        <PAMEmergencyRespondersPanel canManage />
      </IntlProvider>
    </AppQueryProvider>,
  );
  expect(await screen.findByText("carol@example.test")).toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "Edit responders" }));
  const editor = screen.getByRole("textbox", { name: "Responders (one per line)" });
  await user.type(editor, "{enter}dave@example.test{enter}");
  await user.click(screen.getByRole("button", { name: "Save responders" }));
  await waitFor(() =>
    expect(apiMock.setPAMEmergencyResponders).toHaveBeenCalledWith({ subjects: ["carol@example.test", "dave@example.test"] }, expect.any(String)),
  );
  expect(await screen.findByRole("status")).toHaveTextContent("2 responders saved");
  expect(await axe(view.container)).toHaveNoViolations();
});
