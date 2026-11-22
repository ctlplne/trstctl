import { beforeEach, expect, it, vi } from "vitest";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { AppQueryProvider } from "@/lib/query";
import { IntlProvider } from "@/i18n/I18nProvider";
import { ThemeProvider } from "@/components/ThemeProvider";
import { AdminAccess } from "@/pages/AdminAccess";

// CR-001: an automatic approval rule approves in reviewers' place, so the
// server lets only a principal that may approve access (access:approve as
// well as access:write) change one. The console offers rule changes to
// exactly those principals: the requester persona, which holds access:write
// but not access:approve, sees the rules and cannot edit or delete them.

const { apiMock, auth } = vi.hoisted(() => ({
  apiMock: {
    accessRoles: vi.fn(),
    oidcMappingStatus: vi.fn(),
    members: vi.fn(),
    apiTokens: vi.fn(),
    pamSessions: vi.fn(),
    pamAutoApprovalRules: vi.fn(),
  },
  auth: { permissions: [] as string[] },
}));
vi.mock("@/auth/AuthProvider", async (orig) => ({
  ...(await orig<typeof import("@/auth/AuthProvider")>()),
  useAuth: () => ({
    user: { tenant_id: "t1", subject: "person@example.test", permissions: auth.permissions },
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
  apiMock.accessRoles.mockResolvedValue({ items: [{ name: "operator", permissions: ["access:read", "access:write", "access:approve"] }] });
  apiMock.members.mockResolvedValue({ items: [] });
  apiMock.oidcMappingStatus.mockResolvedValue({ configured: false, mappings: [] });
  apiMock.apiTokens.mockResolvedValue({ items: [] });
  apiMock.pamSessions.mockResolvedValue({ items: [] });
  apiMock.pamAutoApprovalRules.mockResolvedValue({
    items: [
      {
        id: "11111111-1111-4111-8111-111111111111",
        name: "Routine incidents",
        applies_to: ["session"],
        target_ids: ["orders"],
        max_ttl_seconds: 120,
        enabled: true,
        revision: 1,
        saved_by: "approver@example.test",
        saved_at: "2026-11-01T00:00:00Z",
      },
    ],
  });
});

async function rulesPanel(permissions: string[]) {
  auth.permissions = permissions;
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
  const heading = await screen.findByRole("heading", { name: "Automatic access approvals" });
  const panel = heading.closest("section");
  if (!panel) throw new Error("no automatic approvals section");
  await within(panel).findByText("Routine incidents");
  return within(panel);
}

it("does not offer rule changes to the requester persona, which may not approve access (CR-001)", async () => {
  const panel = await rulesPanel(["access:read", "access:write", "access:sessions.open"]);
  expect(panel.queryByRole("button", { name: "Edit rule" })).not.toBeInTheDocument();
  expect(panel.queryByRole("button", { name: "Delete rule" })).not.toBeInTheDocument();
  expect(panel.queryByRole("button", { name: "Review rule" })).not.toBeInTheDocument();
});

it("does not offer rule changes to a reviewer that may not change access (CR-001)", async () => {
  const panel = await rulesPanel(["access:read", "access:approve"]);
  expect(panel.queryByRole("button", { name: "Edit rule" })).not.toBeInTheDocument();
  expect(panel.queryByRole("button", { name: "Review rule" })).not.toBeInTheDocument();
});

it("offers rule changes to a principal that may approve and change access (CR-001)", async () => {
  const panel = await rulesPanel(["access:read", "access:write", "access:approve"]);
  expect(panel.getByRole("button", { name: "Edit rule" })).toBeInTheDocument();
  expect(panel.getByRole("button", { name: "Delete rule" })).toBeInTheDocument();
  expect(panel.getByRole("button", { name: "Review rule" })).toBeInTheDocument();
});

it("offers rule changes to an administrator (CR-001)", async () => {
  const panel = await rulesPanel(["*"]);
  expect(panel.getByRole("button", { name: "Edit rule" })).toBeInTheDocument();
});
