import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { axe } from "vitest-axe";
import { ThemeProvider } from "@/components/ThemeProvider";
import { IntlProvider } from "@/i18n/I18nProvider";
import { ApiError } from "@/lib/api";
import { AdminAccess } from "@/pages/AdminAccess";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    accessRoles: vi.fn(),
    oidcMappingStatus: vi.fn(),
    members: vi.fn(),
    apiTokens: vi.fn(),
    pamSessions: vi.fn(),
    upsertMember: vi.fn(),
    offboardMember: vi.fn(),
    createAPIToken: vi.fn(),
    openPAMSession: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (original) => {
  const actual = await original<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});

function renderPage() {
  return render(
    <ThemeProvider>
      <IntlProvider initialLocale="en-US" initialTimeZone="UTC">
        <MemoryRouter>
          <AdminAccess />
        </MemoryRouter>
      </IntlProvider>
    </ThemeProvider>,
  );
}

const member = {
  tenant_id: "tenant-a",
  subject: "operator@example.test",
  display_name: "Example operator",
  email: "operator@example.test",
  roles: ["operator"],
  source: "manual",
  status: "active",
  created_at: "2026-08-20T10:00:00Z",
  updated_at: "2026-08-20T10:00:00Z",
};

describe("DESIGN-ROUTE-040 People and roles", () => {
  beforeEach(() => {
    for (const mock of Object.values(apiMock)) mock.mockReset();
    apiMock.accessRoles.mockResolvedValue({
      items: [
        { name: "operator", permissions: ["access:read", "access:write", "access:role.assign"] },
        { name: "auditor", permissions: ["audit:read"] },
      ],
    });
    apiMock.members.mockResolvedValue({ items: [member] });
    apiMock.oidcMappingStatus.mockResolvedValue({
      enabled: true,
      tenant_claim: "tenant",
      groups_claim: "groups",
      tenant_mappings: [{ group: "platform-operators", tenant_id: "tenant-a", roles: ["operator"] }],
    });
    apiMock.apiTokens.mockResolvedValue({
      items: [
        {
          id: "token-1",
          tenant_id: "tenant-a",
          subject: member.subject,
          scopes: ["access:read"],
          created_at: "2026-08-20T10:00:00Z",
        },
      ],
    });
    apiMock.pamSessions.mockResolvedValue({ items: [] });
    apiMock.upsertMember.mockResolvedValue(member);
    apiMock.offboardMember.mockResolvedValue({ member: { ...member, status: "offboarded" }, revoked_token_count: 1 });
    apiMock.createAPIToken.mockResolvedValue({
      id: "token-2",
      tenant_id: "tenant-a",
      subject: member.subject,
      scopes: ["access:read"],
      token: "reveal-once-value",
      created_at: "2026-08-20T11:00:00Z",
    });
  });

  it("answers first with one Add person action and no eager administrative form or optional read", async () => {
    renderPage();

    expect(await screen.findByRole("heading", { level: 1, name: "People and roles" })).toBeInTheDocument();
    expect(screen.getByText("Who can use the control plane and what each role permits.", { exact: true })).toBeInTheDocument();
    expect(screen.getAllByRole("button", { name: "Add person" })).toHaveLength(1);
    expect(document.querySelectorAll("form")).toHaveLength(0);
    expect(document.querySelectorAll("input, select, textarea")).toHaveLength(0);
    expect(screen.queryByRole("heading", { name: "Mint API token" })).not.toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Offboard member" })).not.toBeInTheDocument();

    await waitFor(() => expect(apiMock.accessRoles).toHaveBeenCalledTimes(1));
    expect(apiMock.members).toHaveBeenCalledWith({ includeOffboarded: true, limit: 50 });
    expect(apiMock.oidcMappingStatus).not.toHaveBeenCalled();
    expect(apiMock.apiTokens).not.toHaveBeenCalled();
    expect(apiMock.pamSessions).not.toHaveBeenCalled();
  });

  it("keeps every expert disclosure visually hidden until its summary is opened", async () => {
    renderPage();
    await screen.findByRole("heading", { level: 1, name: "People and roles" });

    for (const title of ["SSO groups and role bindings", "Sessions and access keys", "Certification history"]) {
      const details = screen.getByText(title, { exact: true }).closest("details");
      expect(details).not.toHaveAttribute("open");
      expect(details?.querySelector(":scope > div")).toHaveClass("hidden", "group-open:grid");
    }
  });

  it("does not render private backend details from denied or unavailable access reads", async () => {
    const user = userEvent.setup();
    apiMock.oidcMappingStatus.mockRejectedValue(new ApiError(403, JSON.stringify({ detail: "tenant t2 has a confidential admin group" })));
    apiMock.apiTokens.mockRejectedValue(new ApiError(403, JSON.stringify({ detail: "token prefix qa-secret-prefix exists" })));
    apiMock.pamSessions.mockRejectedValue(new ApiError(503, JSON.stringify({ detail: "broker internal host pam.private.local" })));
    renderPage();
    await screen.findByRole("heading", { level: 1, name: "People and roles" });

    await user.click(screen.getByText("SSO groups and role bindings", { exact: true }));
    expect(await screen.findByText("SSO group mappings are unavailable", { exact: true })).toBeInTheDocument();
    expect(screen.queryByText(/tenant t2|confidential admin group/i)).not.toBeInTheDocument();

    await user.click(screen.getByText("Sessions and access keys", { exact: true }));
    expect(await screen.findByText("Access-key metadata is unavailable", { exact: true })).toBeInTheDocument();
    expect(await screen.findByText("Privileged access sessions are unavailable", { exact: true })).toBeInTheDocument();
    expect(screen.queryByText(/qa-secret-prefix|pam\.private\.local/i)).not.toBeInTheDocument();
  });

  it("loads exact SSO, role, session, key, and certification evidence only when requested", async () => {
    const user = userEvent.setup();
    const view = renderPage();
    await screen.findByRole("heading", { level: 1, name: "People and roles" });

    await user.click(screen.getByText("SSO groups and role bindings", { exact: true }));
    await waitFor(() => expect(apiMock.oidcMappingStatus).toHaveBeenCalledTimes(1));
    expect(screen.getByText("platform-operators")).toBeInTheDocument();
    expect(screen.getByText("access:role.assign")).toBeInTheDocument();

    await user.click(screen.getByText("Sessions and access keys", { exact: true }));
    await waitFor(() => expect(apiMock.apiTokens).toHaveBeenCalledWith({ includeRevoked: true, limit: 50 }));
    expect(apiMock.pamSessions).toHaveBeenCalledWith({ limit: 20 });
    expect(screen.getByText("token-1")).toBeInTheDocument();

    await user.click(screen.getByText("Certification history", { exact: true }));
    expect(screen.getByRole("link", { name: "Open access reviews" })).toHaveAttribute("href", "/policy");
    expect(screen.getByRole("link", { name: "Open change history" })).toHaveAttribute("href", "/audit");
    expect(await axe(view.container)).toHaveNoViolations();
  });

  it("adds a person in a focused dialog and reads the roster back", async () => {
    const user = userEvent.setup();
    renderPage();
    const trigger = await screen.findByRole("button", { name: "Add person" });
    await user.click(trigger);

    const dialog = screen.getByRole("dialog", { name: "Add person" });
    expect(dialog).toContainElement(document.activeElement as HTMLElement);
    await user.type(within(dialog).getByRole("textbox", { name: "Subject" }), member.subject);
    await user.type(within(dialog).getByRole("textbox", { name: "Display name" }), member.display_name);
    await user.type(within(dialog).getByRole("textbox", { name: "Email" }), member.email);
    expect(within(dialog).getByRole("checkbox", { name: "operator" })).toBeChecked();
    expect(within(dialog).getByRole("checkbox", { name: "auditor" })).not.toBeChecked();
    await user.click(within(dialog).getByRole("checkbox", { name: "auditor" }));
    await user.click(within(dialog).getByRole("button", { name: "Add person" }));

    await waitFor(() =>
      expect(apiMock.upsertMember).toHaveBeenCalledWith(member.subject, {
        display_name: member.display_name,
        email: member.email,
        roles: ["operator", "auditor"],
        source: "manual",
      }),
    );
    await waitFor(() => expect(apiMock.members).toHaveBeenCalledTimes(2));
    expect(screen.queryByRole("dialog", { name: "Add person" })).not.toBeInTheDocument();
    expect(trigger).toHaveFocus();
  });

  it("uses the full foreground token for small Add person labels and role guidance", async () => {
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByRole("button", { name: "Add person" }));

    const dialog = screen.getByRole("dialog", { name: "Add person" });
    for (const label of ["Subject", "Display name", "Email"]) {
      const labelText = within(dialog).getByText(label, { exact: true });
      expect(labelText).toHaveClass("text-foreground");
      expect(labelText).not.toHaveClass("text-muted-foreground");
    }
    const fieldset = dialog.querySelector("fieldset");
    expect(fieldset).not.toBeNull();
    expect(fieldset?.querySelector("legend")).toHaveClass("text-foreground");
    expect(fieldset?.querySelector(":scope > p")).toHaveClass("text-foreground");
  });

  it("requires an explicit confirmation before offboarding and durably reloads membership", async () => {
    const user = userEvent.setup();
    renderPage();
    await screen.findByRole("heading", { level: 1, name: "People and roles" });
    await user.click(screen.getByText("SSO groups and role bindings", { exact: true }));
    await user.click(screen.getByRole("button", { name: "Offboard person" }));

    const dialog = screen.getByRole("alertdialog", { name: "Offboard a person?" });
    await user.selectOptions(within(dialog).getByRole("combobox", { name: "Person" }), member.subject);
    await user.type(within(dialog).getByRole("textbox", { name: "Reason" }), "Role ended");
    const confirm = within(dialog).getByRole("checkbox", { name: /I understand this revokes active access keys/i });
    const offboard = within(dialog).getByRole("button", { name: "Offboard person" });
    expect(offboard).toBeDisabled();
    expect(apiMock.offboardMember).not.toHaveBeenCalled();

    await user.click(confirm);
    await user.click(offboard);
    await waitFor(() => expect(apiMock.offboardMember).toHaveBeenCalledWith(member.subject, { reason: "Role ended" }));
    await waitFor(() => expect(apiMock.members).toHaveBeenCalledTimes(2));
    expect(screen.queryByRole("alertdialog", { name: "Offboard a person?" })).not.toBeInTheDocument();
  });

  it("keeps reveal-once access-key creation behind the sessions detail layer", async () => {
    const user = userEvent.setup();
    renderPage();
    await screen.findByRole("heading", { level: 1, name: "People and roles" });
    await user.click(screen.getByText("Sessions and access keys", { exact: true }));
    await user.click(await screen.findByRole("button", { name: "Create access key" }));

    const dialog = screen.getByRole("dialog", { name: "Create access key" });
    await user.type(within(dialog).getByRole("textbox", { name: "Subject" }), member.subject);
    await user.click(within(dialog).getByRole("button", { name: "Create access key" }));
    await waitFor(() => expect(apiMock.createAPIToken).toHaveBeenCalledWith({ subject: member.subject, scopes: ["access:read"] }));
    expect(await within(dialog).findByText("Copy this key now. It will not be shown again.")).toBeInTheDocument();
    expect(within(dialog).getByText("reveal-once-value")).toBeInTheDocument();
  });
});
