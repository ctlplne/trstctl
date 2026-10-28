import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { ThemeProvider } from "@/components/ThemeProvider";
import { IntlProvider } from "@/i18n/I18nProvider";
import { AppQueryProvider } from "@/lib/query";
import { AdminAccess } from "@/pages/AdminAccess";
import { customRoleVocabulary } from "@/pages/access/CustomRoleDialog";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    accessRoles: vi.fn(),
    members: vi.fn(),
    defineTenantCustomRole: vi.fn(),
    deleteTenantCustomRole: vi.fn(),
  },
}));

vi.mock("@/auth/AuthProvider", () => ({
  useAuth: () => ({ user: { tenant_id: "tenant-a", subject: "admin@example.test", permissions: ["access:read", "access:write", "certs:read"] } }),
}));

vi.mock("@/lib/bootstrapApi", async (original) => {
  const actual = await original<typeof import("@/lib/bootstrapApi")>();
  return { ...actual, bootstrapApi: { ...actual.bootstrapApi, ...apiMock } };
});

vi.mock("@/lib/api", async (original) => {
  const actual = await original<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});

const builtins = [
  { name: "operator", permissions: ["access:read", "access:write", "certs:read", "certs:request", "agents:heartbeat"] },
  { name: "auditor", permissions: ["audit:read"] },
  { name: "admin", permissions: ["*"] },
];
const custom = { name: "payments-operator", description: "payments certificate operations", permissions: ["certs:read", "certs:request"], custom: true };

function renderPage() {
  return render(
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
}

// A207: an access administrator defines a custom role from a checklist of the
// permissions built-in roles grant, sees it marked in the role catalog, and
// deletes it; machine permissions and the wildcard are never offered.
describe("A207 tenant custom roles", () => {
  beforeEach(() => {
    for (const mock of Object.values(apiMock)) mock.mockReset();
    apiMock.accessRoles.mockResolvedValueOnce({ items: builtins }).mockResolvedValue({ items: [...builtins, custom] });
    apiMock.members.mockResolvedValue({ items: [] });
    apiMock.defineTenantCustomRole.mockResolvedValue(custom);
    apiMock.deleteTenantCustomRole.mockResolvedValue(undefined);
  });

  it("offers only grantable permissions", () => {
    expect(customRoleVocabulary([...builtins, custom])).toEqual(["access:read", "access:write", "audit:read", "certs:read", "certs:request"]);
  });

  it("defines a custom role, shows it in the catalog and deletes it", async () => {
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByRole("button", { name: "Define custom role" }));
    const dialog = await screen.findByRole("dialog", { name: "Define custom role" });
    expect(within(dialog).queryByText("agents:heartbeat")).not.toBeInTheDocument();
    expect(within(dialog).queryByText("*")).not.toBeInTheDocument();
    const submit = within(dialog).getByRole("button", { name: "Define custom role" });
    expect(submit).toBeDisabled();
    await user.type(within(dialog).getByLabelText(/Role name/), "payments-operator");
    await user.type(within(dialog).getByLabelText("Description"), "payments certificate operations");
    await user.click(within(dialog).getByRole("checkbox", { name: "certs:read" }));
    await user.click(within(dialog).getByRole("checkbox", { name: "certs:request" }));
    await user.click(submit);
    await waitFor(() =>
      expect(apiMock.defineTenantCustomRole).toHaveBeenCalledWith("payments-operator", {
        description: "payments certificate operations",
        permissions: ["certs:read", "certs:request"],
      }),
    );
    expect(await screen.findByText("Custom role payments-operator saved.")).toBeInTheDocument();
    expect(await screen.findByText("payments certificate operations")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Delete payments-operator" }));
    await waitFor(() => expect(apiMock.deleteTenantCustomRole).toHaveBeenCalledWith("payments-operator"));
    expect(await screen.findByText("Custom role payments-operator deleted.")).toBeInTheDocument();
  });
});
