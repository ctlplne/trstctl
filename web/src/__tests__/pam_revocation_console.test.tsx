import { beforeEach, expect, it, vi } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { ThemeProvider } from "@/components/ThemeProvider";
import { IntlProvider } from "@/i18n/I18nProvider";
import { AppQueryProvider } from "@/lib/query";
import { AdminAccess } from "@/pages/AdminAccess";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    accessRoles: vi.fn(),
    members: vi.fn(),
    apiTokens: vi.fn(),
    pamSessions: vi.fn(),
    pamSession: vi.fn(),
    revokePAMSession: vi.fn(),
  },
}));

vi.mock("@/auth/AuthProvider", () => ({ useAuth: () => ({ user: { subject: "incident-operator", permissions: ["access:write"] } }) }));
vi.mock("@/lib/api", async (original) => {
  const actual = await original<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});

const session = {
  id: "44444444-4444-4444-8444-444444444444",
  target_type: "postgres",
  target_id: "incident-db",
  role: "readonly",
  status: "active",
  subject: "workload",
  requested_by: "operator",
  started_at: "2026-10-08T10:00:00Z",
  expires_at: "2026-10-08T10:10:00Z",
};

beforeEach(() => {
  for (const mock of Object.values(apiMock)) mock.mockReset();
  apiMock.accessRoles.mockResolvedValue({ items: [] });
  apiMock.members.mockResolvedValue({ items: [] });
  apiMock.apiTokens.mockResolvedValue({ items: [] });
  apiMock.pamSessions.mockResolvedValue({ items: [session] });
  apiMock.pamSession.mockResolvedValue(session);
});

it("requests a reasoned PAM revocation and distinguishes pending from confirmed removal", async () => {
  const user = userEvent.setup();
  apiMock.revokePAMSession.mockResolvedValue({
    ...session,
    status: "revoking",
    revocation_reason: "incident containment",
    revocation_requested_by: "incident-operator",
  });
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
  await user.click(await screen.findByRole("button", { name: "Details" }));
  const dialog = screen.getByRole("dialog", { name: /Privileged session/ });
  const button = within(dialog).getByRole("button", { name: "Revoke this session" });
  expect(button).toBeDisabled();
  await user.type(within(dialog).getByRole("textbox", { name: "Revocation reason" }), "incident containment");
  await user.click(button);
  await waitFor(() => expect(apiMock.revokePAMSession).toHaveBeenCalledWith(session.id, "incident containment", `pam-revoke:${session.id}`));
  expect(await within(dialog).findByText(/Waiting for target confirmation/)).toBeInTheDocument();
  expect(within(dialog).queryByText(/Target removal confirmed/)).not.toBeInTheDocument();
  apiMock.pamSession.mockResolvedValue({
    ...session,
    status: "revoked",
    ended_at: "2026-10-08T10:01:00Z",
    revocation_reason: "incident containment",
    revocation_requested_by: "incident-operator",
  });
  await user.click(within(dialog).getByRole("button", { name: "Refresh session status" }));
  expect(await within(dialog).findByText(/Target removal confirmed/)).toBeInTheDocument();
});
