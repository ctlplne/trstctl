import { beforeEach, expect, it, vi } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, useLocation } from "react-router-dom";
import { ThemeProvider } from "@/components/ThemeProvider";
import { AppQueryProvider } from "@/lib/query";
import { IntlProvider } from "@/i18n/I18nProvider";
import { AdminAccess } from "@/pages/AdminAccess";

// A275: a session risk alert links the session's recording as
// /admin/access?session=<id>. The page opens that session's detail, with its
// recording; closing it drops the link; a session this person cannot read
// says so instead.

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    accessRoles: vi.fn(),
    oidcMappingStatus: vi.fn(),
    members: vi.fn(),
    apiTokens: vi.fn(),
    pamSessions: vi.fn(),
    pamSession: vi.fn(),
    pamCommandActions: vi.fn(),
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

const sessionID = "a2750000-0000-4000-8000-000000000001";

beforeEach(() => {
  for (const mock of Object.values(apiMock)) mock.mockReset();
  apiMock.accessRoles.mockResolvedValue({ items: [{ name: "operator", permissions: ["access:read", "access:write"] }] });
  apiMock.members.mockResolvedValue({ items: [] });
  apiMock.oidcMappingStatus.mockResolvedValue({ configured: false, mappings: [] });
  apiMock.apiTokens.mockResolvedValue({ items: [] });
  apiMock.pamSessions.mockResolvedValue({ items: [] });
  apiMock.pamCommandActions.mockResolvedValue({ items: [] });
  apiMock.pamSession.mockResolvedValue({
    id: sessionID,
    target_type: "postgres",
    target_id: "orders-db",
    role: "readonly",
    status: "active",
    subject: "alice",
    requested_by: "alice",
    started_at: "2026-11-07T20:00:00Z",
    expires_at: "2026-11-07T20:15:00Z",
    delivery: "gateway",
  });
});

function Where() {
  const location = useLocation();
  return <output aria-label="location">{location.pathname + location.search}</output>;
}

function mount(entry: string) {
  return render(
    <AppQueryProvider>
      <ThemeProvider>
        <IntlProvider initialLocale="en-US" initialTimeZone="UTC">
          <MemoryRouter initialEntries={[entry]}>
            <AdminAccess />
            <Where />
          </MemoryRouter>
        </IntlProvider>
      </ThemeProvider>
    </AppQueryProvider>,
  );
}

it("opens the session an alert links and drops the link when closed (A275)", async () => {
  const user = userEvent.setup();
  mount(`/admin/access?session=${sessionID}`);
  const dialog = await screen.findByRole("dialog");
  expect(within(dialog).getByRole("heading", { level: 2 })).toHaveTextContent(sessionID);
  expect(apiMock.pamSession).toHaveBeenCalledWith(sessionID);
  await user.keyboard("{Escape}");
  await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
  expect(screen.getByRole("status", { name: "location" })).toHaveTextContent(/^\/admin\/access$/);
});

it("says when the linked session cannot be opened (A275)", async () => {
  apiMock.pamSession.mockRejectedValue(new Error("not found"));
  mount(`/admin/access?session=${sessionID}`);
  expect(await screen.findByText("The linked session could not be opened")).toBeInTheDocument();
  expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
});

it("says a session's pooled gateway was lost and how long it may still serve (A278)", async () => {
  apiMock.pamSession.mockResolvedValue({
    id: sessionID,
    target_type: "postgres",
    target_id: "orders-db",
    role: "readonly",
    status: "revoked",
    subject: "alice",
    requested_by: "alice",
    started_at: "2026-11-07T20:00:00Z",
    expires_at: "2026-11-07T20:15:00Z",
    delivery: "gateway",
    revocation_requested_by: "trstctl:gateway-health",
    revocation_reason: "gateway lost: 9f0c stopped reporting",
    gateway_lost: true,
    uncertain_until: "2026-11-07T20:15:00Z",
  });
  mount(`/admin/access?session=${sessionID}`);
  const dialog = await screen.findByRole("dialog");
  expect(await within(dialog).findByText("Gateway lost")).toBeInTheDocument();
  expect(
    within(dialog).getByText(/This session's gateway stopped reporting, so the session was revoked\. It may still serve connections until/),
  ).toBeInTheDocument();
  expect(within(dialog).queryByText("May still serve until")).not.toBeInTheDocument();
});
