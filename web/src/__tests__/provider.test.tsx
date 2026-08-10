// SPDX-License-Identifier: MPL-2.0

import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen, waitFor, fireEvent, within } from "@testing-library/react";
import { IntlProvider } from "@/i18n/I18nProvider";

const { providerMock } = vi.hoisted(() => ({
  providerMock: {
    listTenants: vi.fn(),
    listActivity: vi.fn(),
    provisionTenant: vi.fn(),
    suspendTenant: vi.fn(),
    offboardTenant: vi.fn(),
    getQuota: vi.fn(),
    setQuota: vi.fn(),
    setBrand: vi.fn(),
    runIsolationDrill: vi.fn(),
  },
}));

vi.mock("@/lib/providerApi", async (orig) => {
  const actual = await orig<typeof import("@/lib/providerApi")>();
  return { ...actual, providerApi: providerMock };
});

import { Provider } from "@/pages/Provider";
import { setProviderToken, clearProviderToken } from "@/lib/providerApi";

function renderProvider() {
  return render(
    <IntlProvider initialLocale="en-US" initialTimeZone="UTC">
      <Provider />
    </IntlProvider>,
  );
}

describe("provider console (L3)", () => {
  beforeEach(() => {
    clearProviderToken();
    for (const fn of Object.values(providerMock)) fn.mockReset();
    providerMock.listActivity.mockResolvedValue([]);
  });

  it("gates on an operator token before touching the provider plane", () => {
    renderProvider();
    // No token: the login gate shows and the API is never called.
    expect(screen.getByLabelText("Operator bearer token")).toBeInTheDocument();
    expect(providerMock.listTenants).not.toHaveBeenCalled();
  });

  it("lists customer tenants once an operator signs in", async () => {
    providerMock.listTenants.mockResolvedValue([
      { id: "t-1", slug: "acme", name: "Acme Corp", status: "active", created_at: "2026-01-01T00:00:00Z", updated_at: "2026-01-01T00:00:00Z" },
      { id: "t-2", slug: "globex", name: "Globex", status: "suspended", created_at: "2026-02-01T00:00:00Z", updated_at: "2026-02-01T00:00:00Z" },
    ]);
    setProviderToken("operator-bearer");
    renderProvider();
    expect(await screen.findByText("Acme Corp")).toBeInTheDocument();
    expect(screen.getByText("Globex")).toBeInTheDocument();
    // The suspended customer shows its status; the active one offers suspend.
    expect(screen.getByText("suspended")).toBeInTheDocument();
  });

  it("suspends a customer through the plane after confirmation", async () => {
    providerMock.listTenants
      .mockResolvedValueOnce([
        { id: "t-1", slug: "acme", name: "Acme Corp", status: "active", created_at: "2026-01-01T00:00:00Z", updated_at: "2026-01-01T00:00:00Z" },
      ])
      .mockResolvedValueOnce([
        { id: "t-1", slug: "acme", name: "Acme Corp", status: "suspended", created_at: "2026-01-01T00:00:00Z", updated_at: "2026-01-03T00:00:00Z" },
      ]);
    providerMock.suspendTenant.mockResolvedValue(undefined);
    vi.spyOn(window, "confirm").mockReturnValue(true);
    setProviderToken("operator-bearer");
    renderProvider();

    const row = (await screen.findByText("Acme Corp")).closest("tr")!;
    fireEvent.click(within(row).getByRole("button", { name: "Suspend" }));
    await waitFor(() => expect(providerMock.suspendTenant).toHaveBeenCalledWith("t-1"));
    // The list reloads and reflects the new status.
    expect(await screen.findByText("suspended")).toBeInTheDocument();
  });

  it("shows a customer's quota, rendering an unset limit as unlimited", async () => {
    providerMock.listTenants.mockResolvedValue([
      { id: "t-1", slug: "acme", name: "Acme Corp", status: "active", created_at: "2026-01-01T00:00:00Z", updated_at: "2026-01-01T00:00:00Z" },
    ]);
    // max_agents capped, the rest unset -> "unlimited", never zero.
    providerMock.getQuota.mockResolvedValue({ tenant_id: "t-1", max_agents: 50 });
    setProviderToken("operator-bearer");
    renderProvider();

    const row = (await screen.findByText("Acme Corp")).closest("tr")!;
    fireEvent.click(within(row).getByRole("button", { name: "Quota" }));
    await waitFor(() => expect(providerMock.getQuota).toHaveBeenCalledWith("t-1"));
    // max_agents is 50 in its field; the unset limits are blank (unlimited).
    expect(await screen.findByLabelText("Max agents")).toHaveValue(50);
    expect(screen.getByLabelText("Max certificates")).toHaveValue(null);
  });

  it("edits a quota, sending a blank field as unlimited (never zero)", async () => {
    providerMock.listTenants.mockResolvedValue([
      { id: "t-1", slug: "acme", name: "Acme Corp", status: "active", created_at: "2026-01-01T00:00:00Z", updated_at: "2026-01-01T00:00:00Z" },
    ]);
    providerMock.getQuota.mockResolvedValue({ tenant_id: "t-1", max_agents: 50 });
    providerMock.setQuota.mockResolvedValue(undefined);
    setProviderToken("operator-bearer");
    renderProvider();

    const row = (await screen.findByText("Acme Corp")).closest("tr")!;
    fireEvent.click(within(row).getByRole("button", { name: "Quota" }));
    const agents = await screen.findByLabelText("Max agents");
    fireEvent.change(agents, { target: { value: "10" } });
    // Leave certificates blank -> must be sent as undefined (unlimited), NOT 0.
    fireEvent.click(screen.getByRole("button", { name: "Save quota" }));
    await waitFor(() => expect(providerMock.setQuota).toHaveBeenCalled());
    const [, sent] = providerMock.setQuota.mock.calls[0];
    expect(sent.max_agents).toBe(10);
    expect(sent.max_certificates_stored).toBeUndefined();
    expect(sent.max_secrets_stored).toBeUndefined();
  });

  it("sets a customer's white-label brand through the plane", async () => {
    providerMock.listTenants.mockResolvedValue([
      { id: "t-1", slug: "acme", name: "Acme Corp", status: "active", created_at: "2026-01-01T00:00:00Z", updated_at: "2026-01-01T00:00:00Z" },
    ]);
    providerMock.setBrand.mockResolvedValue(undefined);
    setProviderToken("operator-bearer");
    renderProvider();

    const row = (await screen.findByText("Acme Corp")).closest("tr")!;
    fireEvent.click(within(row).getByRole("button", { name: "Brand" }));
    fireEvent.change(await screen.findByLabelText("Product name"), { target: { value: "Acme PKI" } });
    fireEvent.change(screen.getByLabelText("Custom domain"), { target: { value: "certs.acme.example" } });
    fireEvent.click(screen.getByRole("button", { name: "Save brand" }));
    await waitFor(() =>
      expect(providerMock.setBrand).toHaveBeenCalledWith(
        "t-1",
        expect.objectContaining({
          product_name: "Acme PKI",
          custom_domain: "certs.acme.example",
        }),
      ),
    );
  });

  it("drops the operator back to the gate when the plane refuses the token", async () => {
    const { ProviderAuthError } = await import("@/lib/providerApi");
    providerMock.listTenants.mockRejectedValue(new ProviderAuthError("expired"));
    setProviderToken("stale-bearer");
    renderProvider();
    // An auth refusal is "not signed in", not an error banner: the gate returns.
    expect(await screen.findByLabelText("Operator bearer token")).toBeInTheDocument();
  });

  it("runs the isolation drill and surfaces a failing result with its checks", async () => {
    providerMock.listTenants.mockResolvedValue([]);
    providerMock.runIsolationDrill.mockResolvedValue({
      passed: false,
      ran_at: "2026-06-27T12:00:00Z",
      checks: [{ name: "cross_tenant_write_refused", passed: false, detail: "hijack accepted" }],
    });
    setProviderToken("operator-bearer");
    renderProvider();

    fireEvent.click(await screen.findByRole("button", { name: "Run isolation drill" }));
    await waitFor(() => expect(providerMock.runIsolationDrill).toHaveBeenCalled());
    // A failed drill reads as a danger result, and the failing check is shown so
    // the operator sees what broke, not just that something did.
    expect(await screen.findByText(/Isolation drill FAILED/)).toBeInTheDocument();
    expect(screen.getByText(/hijack accepted/)).toBeInTheDocument();
  });

  it("shows immutable provider authority evidence with actor, customer, and sequence", async () => {
    providerMock.listTenants.mockResolvedValue([]);
    providerMock.listActivity.mockResolvedValue([
      {
        sequence: 42,
        event_id: "evt-42",
        type: "provider.tenant.quota.set",
        tenant_id: "tenant-acme",
        operator_id: "op-1",
        operator_email: "operator@example.test",
        at: "2026-08-09T21:00:00Z",
      },
    ]);
    setProviderToken("operator-bearer");
    renderProvider();

    expect(await screen.findByRole("heading", { name: "Recent activity" })).toBeInTheDocument();
    expect(screen.getByText("provider.tenant.quota.set")).toBeInTheDocument();
    expect(screen.getByText("operator@example.test")).toBeInTheDocument();
    expect(screen.getByText("tenant-acme")).toBeInTheDocument();
    expect(screen.getByText("#42")).toBeInTheDocument();
  });
});
