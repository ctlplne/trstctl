// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it, vi, beforeEach } from "vitest";
import { act, render, screen, waitFor, fireEvent, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { IntlProvider } from "@/i18n/I18nProvider";
import { AppQueryProvider } from "@/lib/query";

const { providerMock } = vi.hoisted(() => ({
  providerMock: {
    listTenants: vi.fn(),
    listActivity: vi.fn(),
    provisionTenant: vi.fn(),
    suspendTenant: vi.fn(),
    resumeTenant: vi.fn(),
    offboardTenant: vi.fn(),
    getQuota: vi.fn(),
    setQuota: vi.fn(),
    getBrand: vi.fn(),
    setBrand: vi.fn(),
    runIsolationDrill: vi.fn(),
    availability: vi.fn(),
    authMethods: vi.fn(),
    session: vi.fn(),
    listOperatorAccess: vi.fn(),
    listAccessCustomers: vi.fn(),
    grantOperatorAccess: vi.fn(),
    revokeOperatorAccess: vi.fn(),
    setOperatorRole: vi.fn(),
    customerHealth: vi.fn(),
    usageEvidence: vi.fn(),
    verifyUsageEvidence: vi.fn(),
    downloadUsageEvidence: vi.fn(),
    signOut: vi.fn(),
  },
}));

vi.mock("@/lib/providerApi", async (orig) => {
  const actual = await orig<typeof import("@/lib/providerApi")>();
  return { ...actual, providerApi: providerMock };
});

import { Provider } from "@/pages/Provider";
import { setProviderToken, clearProviderToken, providerToken } from "@/lib/providerApi";

function renderProvider() {
  return render(
    <IntlProvider initialLocale="en-US" initialTimeZone="UTC">
      <AppQueryProvider>
        <MemoryRouter>
          <Provider />
        </MemoryRouter>
      </AppQueryProvider>
    </IntlProvider>,
  );
}

describe("provider console (L3)", () => {
  beforeEach(() => {
    clearProviderToken();
    for (const fn of Object.values(providerMock)) fn.mockReset();
    providerMock.listActivity.mockResolvedValue([]);
    providerMock.availability.mockResolvedValue(true);
    providerMock.authMethods.mockResolvedValue([]);
    // Existing action tests exercise a fully authorized administrator. The new
    // authority regression suite separately covers limited and unknown grants.
    providerMock.session.mockImplementation(async () => {
      if (!providerToken()) throw new Error("no provider session");
      return {
        id: "test-admin",
        role: "admin",
        mfa: true,
        authority: {
          available: true,
          access_read: true,
          access_write: true,
          provision: true,
          isolation_drill: true,
          customers: Object.fromEntries(
            ["t-1", "t-2", "tenant-alpha", "tenant-bravo", "tenant-acme", "4054b878-56cb-5591-ba98-71aa09012048"].map((id) => [
              id,
              { read_quota: true, write_quota: true, write_brand: true, suspend: true, resume: true, offboard: true },
            ]),
          ),
        },
      };
    });
    providerMock.listOperatorAccess.mockResolvedValue([]);
    providerMock.listAccessCustomers.mockResolvedValue([]);
    providerMock.customerHealth.mockResolvedValue({ tenant_id: "", health: "unknown", active_certificates: 0 });
    providerMock.verifyUsageEvidence.mockResolvedValue({ verified: false });
    providerMock.downloadUsageEvidence.mockResolvedValue(undefined);
    providerMock.signOut.mockResolvedValue(undefined);
  });

  it("gates on an operator token before touching customer data", async () => {
    renderProvider();
    expect(await screen.findByLabelText("Operator bearer token")).toBeInTheDocument();
    expect(providerMock.listTenants).not.toHaveBeenCalled();
  });

  it("shows customer access setup separately from an active service and verifies refresh", async () => {
    const tenant = {
      id: "4054b878-56cb-5591-ba98-71aa09012048",
      slug: "setup-pending",
      name: "Setup customer",
      status: "active",
      created_at: "2026-09-28T00:00:00Z",
      updated_at: "2026-09-28T00:00:00Z",
    };
    providerMock.listTenants.mockResolvedValue([tenant]);
    providerMock.customerHealth.mockResolvedValue({ tenant_id: tenant.id, health: "setup_required", active_certificates: 0, workspace_initialized: false });
    setProviderToken("operator-bearer");
    renderProvider();
    fireEvent.click(await screen.findByRole("button", { name: "View setup" }));
    expect(await screen.findByText("Initialize customer workspace")).toBeInTheDocument();
    expect(screen.getByText(/trstctl token create/)).toHaveTextContent(`--tenant '${tenant.id}'`);
    expect(screen.getByText(/Metering starts after the customer workspace is initialized/)).toBeInTheDocument();
    expect(screen.queryByText("Customer workspace is initialized")).not.toBeInTheDocument();

    providerMock.customerHealth.mockResolvedValue({ tenant_id: tenant.id, health: "no_certificates", active_certificates: 0, workspace_initialized: true });
    fireEvent.click(screen.getByRole("button", { name: "Check setup again" }));
    expect(await screen.findByText("Customer workspace is initialized")).toBeInTheDocument();
    expect(screen.queryByText(/trstctl token create/)).not.toBeInTheDocument();
    expect(providerMock.customerHealth).toHaveBeenCalledWith(tenant.id);
  });

  it("does not infer customer access from healthy inventory when setup evidence is absent", async () => {
    providerMock.listTenants.mockResolvedValue([
      {
        id: "4054b878-56cb-5591-ba98-71aa09012048",
        slug: "unknown",
        name: "Unknown setup",
        status: "active",
        created_at: "2026-09-28T00:00:00Z",
        updated_at: "2026-09-28T00:00:00Z",
      },
    ]);
    providerMock.customerHealth.mockResolvedValue({ tenant_id: "4054b878-56cb-5591-ba98-71aa09012048", health: "healthy", active_certificates: 4 });
    setProviderToken("operator-bearer");
    renderProvider();
    fireEvent.click(await screen.findByRole("button", { name: "View setup" }));
    expect(await screen.findByText("Workspace setup could not be verified")).toBeInTheDocument();
    expect(screen.queryByText("Customer workspace is initialized")).not.toBeInTheDocument();
    expect(screen.queryByText(/trstctl token create/)).not.toBeInTheDocument();
  });

  it("carries a provisioned customer into setup without asking the operator to retype its ID", async () => {
    const tenant = {
      id: "4054b878-56cb-5591-ba98-71aa09012048",
      slug: "new-customer",
      name: "O'Brian",
      status: "active",
      created_at: "2026-09-28T00:00:00Z",
      updated_at: "2026-09-28T00:00:00Z",
    };
    providerMock.listTenants.mockResolvedValue([]);
    providerMock.provisionTenant.mockImplementation(async () => {
      providerMock.listTenants.mockResolvedValue([tenant]);
      return tenant;
    });
    providerMock.customerHealth.mockResolvedValue({ tenant_id: tenant.id, health: "setup_required", active_certificates: 0, workspace_initialized: false });
    setProviderToken("operator-bearer");
    renderProvider();
    fireEvent.change(await screen.findByLabelText("Slug"), { target: { value: " new-customer " } });
    fireEvent.change(screen.getByLabelText("Name"), { target: { value: " O'Brian " } });
    fireEvent.click(screen.getByRole("button", { name: "Provision" }));
    expect(await screen.findByText("Initialize customer workspace")).toBeInTheDocument();
    expect(providerMock.provisionTenant).toHaveBeenCalledWith({ slug: "new-customer", name: "O'Brian" });
    expect(screen.getByText(/trstctl token create/)).toHaveTextContent("--tenant-name 'O'\\''Brian'");
    expect(screen.getByRole("region", { name: "Customer setup: O'Brian" })).toHaveFocus();
  });

  it("discards a customer setup verdict when refresh fails", async () => {
    const tenant = {
      id: "4054b878-56cb-5591-ba98-71aa09012048",
      slug: "refresh",
      name: "Refresh customer",
      status: "active",
      created_at: "2026-09-28T00:00:00Z",
      updated_at: "2026-09-28T00:00:00Z",
    };
    providerMock.listTenants.mockResolvedValue([tenant]);
    providerMock.customerHealth.mockResolvedValue({ tenant_id: tenant.id, health: "no_certificates", active_certificates: 0, workspace_initialized: true });
    setProviderToken("operator-bearer");
    renderProvider();
    fireEvent.click(await screen.findByRole("button", { name: "View setup" }));
    await screen.findByText("Customer workspace is initialized");
    providerMock.customerHealth.mockRejectedValue(new Error("Unavailable"));
    fireEvent.click(screen.getByRole("button", { name: "Check setup again" }));
    expect(await screen.findByText("Workspace setup could not be verified")).toBeInTheDocument();
    expect(screen.queryByText("Customer workspace is initialized")).not.toBeInTheDocument();
    expect(screen.queryByText(/trstctl token create/)).not.toBeInTheDocument();
  });

  it("does not display a late customer setup response under a different customer", async () => {
    const alpha = {
      id: "4054b878-56cb-5591-ba98-71aa09012048",
      slug: "alpha",
      name: "Alpha setup",
      status: "active",
      created_at: "2026-09-28T00:00:00Z",
      updated_at: "2026-09-28T00:00:00Z",
    };
    const beta = { ...alpha, id: "t-2", slug: "beta", name: "Beta setup" };
    let resolveAlpha!: (value: unknown) => void;
    const delayed = new Promise((resolve) => {
      resolveAlpha = resolve;
    });
    providerMock.listTenants.mockResolvedValue([alpha, beta]);
    providerMock.customerHealth.mockImplementation((id: string) =>
      id === alpha.id ? delayed : Promise.resolve({ tenant_id: beta.id, health: "no_certificates", active_certificates: 0, workspace_initialized: true }),
    );
    setProviderToken("operator-bearer");
    renderProvider();
    const alphaRow = (await screen.findByRole("cell", { name: alpha.name })).closest("tr")!;
    fireEvent.click(within(alphaRow).getByRole("button", { name: "View setup" }));
    await waitFor(() => expect(providerMock.customerHealth).toHaveBeenCalledWith(alpha.id));
    const betaRow = screen.getByRole("cell", { name: beta.name }).closest("tr")!;
    fireEvent.click(within(betaRow).getByRole("button", { name: "View setup" }));
    await screen.findByText("Customer workspace is initialized");
    await act(async () => {
      resolveAlpha({ tenant_id: alpha.id, health: "setup_required", active_certificates: 0, workspace_initialized: false });
      await delayed;
    });
    expect(screen.getByRole("region", { name: "Customer setup: Beta setup" })).toHaveTextContent("Customer workspace is initialized");
    expect(screen.queryByText("Initialize customer workspace")).not.toBeInTheDocument();
    expect(screen.queryByText(/trstctl token create/)).not.toBeInTheDocument();
  });

  it("does not probe the dark Provider API when the plane is unattached", async () => {
    providerMock.availability.mockResolvedValue(false);
    renderProvider();

    expect(await screen.findByText(/does not include the Provider plane/i)).toBeInTheDocument();
    expect(providerMock.authMethods).not.toHaveBeenCalled();
    expect(providerMock.session).not.toHaveBeenCalled();
    expect(providerMock.listTenants).not.toHaveBeenCalled();
  });

  it("fails closed without probing the Provider API when attachment truth is unknown", async () => {
    providerMock.availability.mockResolvedValue(null);
    renderProvider();

    expect(await screen.findByText(/could not verify whether the Provider plane is attached/i)).toBeInTheDocument();
    expect(providerMock.authMethods).not.toHaveBeenCalled();
    expect(providerMock.session).not.toHaveBeenCalled();
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

  it("revokes the separate Provider session before returning to the login gate", async () => {
    providerMock.listTenants.mockResolvedValue([]);
    setProviderToken("operator-bearer");
    renderProvider();
    fireEvent.click(await screen.findByRole("button", { name: "Sign out" }));
    await waitFor(() => expect(providerMock.signOut).toHaveBeenCalledOnce());
    expect(await screen.findByLabelText("Operator bearer token")).toBeInTheDocument();
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

  it("resumes a suspended customer through its own confirmed action", async () => {
    const tenant = { id: "t-1", slug: "acme", name: "Acme Corp", status: "suspended", created_at: "2026-01-01T00:00:00Z", updated_at: "2026-01-03T00:00:00Z" };
    providerMock.listTenants.mockResolvedValueOnce([tenant]).mockResolvedValue([{ ...tenant, status: "active" }]);
    providerMock.resumeTenant.mockResolvedValue(undefined);
    vi.spyOn(window, "confirm").mockReturnValue(false);
    setProviderToken("operator-bearer");
    renderProvider();
    const row = (await screen.findByText("Acme Corp")).closest("tr")!;
    fireEvent.click(within(row).getByRole("button", { name: "Resume" }));
    expect(providerMock.resumeTenant).not.toHaveBeenCalled();
    vi.mocked(window.confirm).mockReturnValue(true);
    fireEvent.click(within(row).getByRole("button", { name: "Resume" }));
    await waitFor(() => expect(providerMock.resumeTenant).toHaveBeenCalledWith("t-1"));
    expect(await screen.findByText("active")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Resume" })).not.toBeInTheDocument();
  });

  it("shows pending offboarding without offering another deletion or resume", async () => {
    providerMock.listTenants.mockResolvedValue([
      { id: "t-1", slug: "acme", name: "Acme Corp", status: "offboarding", created_at: "2026-01-01T00:00:00Z", updated_at: "2026-01-03T00:00:00Z" },
    ]);
    setProviderToken("operator-bearer");
    renderProvider();
    const row = (await screen.findByText("Acme Corp")).closest("tr")!;
    expect(within(row).getByText("Offboarding pending")).toBeInTheDocument();
    expect(within(row).getByText(/Customer access remains blocked/)).toBeInTheDocument();
    expect(within(row).queryByRole("button", { name: /Offboard|Resume/ })).not.toBeInTheDocument();
  });

  it("continues an original offboarding request from activity after its customer leaves the roster", async () => {
    const request = {
      sequence: 10,
      event_id: "ec39388f-d4d4-51f3-af5c-e768cae9047c",
      type: "provider.tenant_erasure.requested",
      request_event_id: "ec39388f-d4d4-51f3-af5c-e768cae9047c",
      tenant_id: "t-1",
      operator_id: "test-admin",
      at: "2026-01-03T00:00:00Z",
      offboard_state: "pending",
      can_continue_offboard: true,
    };
    providerMock.listTenants.mockResolvedValue([]);
    providerMock.listActivity.mockResolvedValueOnce([request]).mockResolvedValue([{ ...request, offboard_state: "completed", can_continue_offboard: false }]);
    providerMock.offboardTenant.mockResolvedValue(undefined);
    vi.spyOn(window, "confirm").mockReturnValue(false);
    setProviderToken("operator-bearer");
    renderProvider();
    const button = await screen.findByRole("button", { name: "Continue offboarding" });
    fireEvent.click(button);
    expect(providerMock.offboardTenant).not.toHaveBeenCalled();
    vi.mocked(window.confirm).mockReturnValue(true);
    fireEvent.click(button);
    await waitFor(() => expect(providerMock.offboardTenant).toHaveBeenCalledWith("t-1", request.request_event_id));
    expect(await screen.findByText("Deletion verified")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Continue offboarding" })).not.toBeInTheDocument();
  });

  it("does not offer continuation without current server authority", async () => {
    providerMock.listTenants.mockResolvedValue([]);
    providerMock.listActivity.mockResolvedValue([
      {
        sequence: 10,
        event_id: "request",
        type: "provider.tenant_erasure.requested",
        request_event_id: "request",
        tenant_id: "t-1",
        operator_id: "another-operator",
        at: "2026-01-03T00:00:00Z",
        offboard_state: "pending",
        can_continue_offboard: false,
      },
    ]);
    setProviderToken("operator-bearer");
    renderProvider();
    expect(within(await screen.findByRole("table", { name: "Offboarding needs attention" })).getByText("Offboarding pending")).toBeInTheDocument();
    expect(within(await screen.findByRole("table", { name: "Recent activity" })).getByText("Offboarding pending")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Continue offboarding" })).not.toBeInTheDocument();
  });

  it("requires a new confirmation to retry refused offboarding and refreshes after a refusal", async () => {
    const tenant = { id: "t-1", slug: "acme", name: "Acme Corp", status: "active", created_at: "2026-01-01T00:00:00Z", updated_at: "2026-01-03T00:00:00Z" };
    providerMock.listTenants.mockResolvedValueOnce([tenant]).mockResolvedValue([{ ...tenant, status: "offboard_failed" }]);
    providerMock.offboardTenant.mockRejectedValueOnce(new Error("customer state changed"));
    vi.spyOn(window, "confirm").mockReturnValue(true);
    setProviderToken("operator-bearer");
    renderProvider();
    const row = (await screen.findByText("Acme Corp")).closest("tr")!;
    fireEvent.click(within(row).getByRole("button", { name: "Offboard" }));
    expect(await screen.findByText("Offboarding needs review")).toBeInTheDocument();
    expect(screen.getByText(/Review the customer before submitting a new deletion request/)).toBeInTheDocument();
    const retry = screen.getByRole("button", { name: "Review offboarding" });
    expect(screen.queryByRole("button", { name: "Resume" })).not.toBeInTheDocument();
    vi.mocked(window.confirm).mockReturnValue(false);
    fireEvent.click(retry);
    expect(providerMock.offboardTenant).toHaveBeenCalledTimes(1);
    providerMock.offboardTenant.mockResolvedValue(undefined);
    vi.mocked(window.confirm).mockReturnValue(true);
    fireEvent.click(retry);
    await waitFor(() => expect(providerMock.offboardTenant).toHaveBeenCalledTimes(2));
    expect(window.confirm).toHaveBeenLastCalledWith(expect.stringContaining("new deletion request"));
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
    providerMock.getBrand
      .mockResolvedValueOnce({
        tenant_id: "t-1",
        revision: "event-1",
        product_name: "Original",
        custom_domain: "old.acme.example",
        login_message: "Welcome",
        logo_data_uri: "data:image/png;base64,abc",
        email_footer: "Trusted",
      })
      .mockResolvedValueOnce({
        tenant_id: "t-1",
        revision: "event-2",
        product_name: "Acme PKI",
        custom_domain: "certs.acme.example",
        login_message: "Welcome",
        logo_data_uri: "data:image/png;base64,abc",
        email_footer: "Trusted",
      });
    setProviderToken("operator-bearer");
    renderProvider();

    const row = (await screen.findByText("Acme Corp")).closest("tr")!;
    fireEvent.click(within(row).getByRole("button", { name: "Brand" }));
    expect(await screen.findByDisplayValue("old.acme.example")).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Product name"), { target: { value: "Acme PKI" } });
    fireEvent.change(screen.getByLabelText("Custom domain"), { target: { value: "certs.acme.example" } });
    fireEvent.click(screen.getByRole("button", { name: "Save brand" }));
    await waitFor(() =>
      expect(providerMock.setBrand).toHaveBeenCalledWith(
        "t-1",
        expect.objectContaining({
          product_name: "Acme PKI",
          custom_domain: "certs.acme.example",
          login_message: "Welcome",
          logo_data_uri: "data:image/png;base64,abc",
          email_footer: "Trusted",
        }),
        "event-1",
      ),
    );
    await waitFor(() => expect(screen.queryByLabelText("Product name")).not.toBeInTheDocument());
    fireEvent.click(within(row).getByRole("button", { name: "Brand" }));
    expect(await screen.findByDisplayValue("certs.acme.example")).toBeInTheDocument();
    expect(providerMock.getBrand).toHaveBeenCalledTimes(2);
  });

  it("refuses a blind brand write when current customer readback fails", async () => {
    providerMock.listTenants.mockResolvedValue([
      { id: "t-1", slug: "acme", name: "Acme Corp", status: "active", created_at: "2026-01-01T00:00:00Z", updated_at: "2026-01-01T00:00:00Z" },
    ]);
    providerMock.getBrand.mockRejectedValue(new Error("readback unavailable"));
    setProviderToken("operator-bearer");
    renderProvider();
    const row = (await screen.findByText("Acme Corp")).closest("tr")!;
    fireEvent.click(within(row).getByRole("button", { name: "Brand" }));
    expect(await screen.findByText("The current brand could not be read. Reload it before editing this customer.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Save brand" })).toBeDisabled();
    expect(providerMock.setBrand).not.toHaveBeenCalled();
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
    expect(await screen.findByText("provider.tenant.quota.set")).toBeInTheDocument();
    expect(screen.getByText("operator@example.test")).toBeInTheDocument();
    expect(screen.getByText("tenant-acme")).toBeInTheDocument();
    expect(screen.getByText("#42")).toBeInTheDocument();
  });

  it("manages SCIM operators, exact customer grants, and revocation evidence", async () => {
    providerMock.listTenants.mockResolvedValue([
      { id: "tenant-acme", slug: "acme", name: "Acme Corp", status: "active", created_at: "2026-01-01T00:00:00Z", updated_at: "2026-01-01T00:00:00Z" },
    ]);
    providerMock.listOperatorAccess.mockResolvedValue([
      {
        identity: {
          id: "op-2",
          external_id: "entra-2",
          user_name: "casey@example.test",
          email: "casey@example.test",
          display_name: "Casey",
          role: "operator",
          active: true,
          source: "scim:entra",
          created_at: "2026-08-13T12:00:00Z",
          updated_at: "2026-08-13T12:00:00Z",
        },
        delegations: [
          {
            operator_id: "op-2",
            customer_id: "tenant-acme",
            operation: "read",
            source: "console",
            granted_by: "admin-1",
            granted_at: "2026-08-13T12:01:00Z",
            last_used_at: "2026-08-13T12:02:00Z",
          },
        ],
      },
    ]);
    providerMock.listAccessCustomers.mockResolvedValue([
      { id: "tenant-acme", slug: "acme", name: "Acme Corp", status: "active", created_at: "2026-01-01T00:00:00Z", updated_at: "2026-01-01T00:00:00Z" },
    ]);
    providerMock.revokeOperatorAccess.mockResolvedValue({
      identity: {
        id: "op-2",
        external_id: "entra-2",
        user_name: "casey@example.test",
        email: "casey@example.test",
        display_name: "Casey",
        role: "operator",
        active: true,
        source: "scim:entra",
        created_at: "2026-08-13T12:00:00Z",
        updated_at: "2026-08-13T12:03:00Z",
      },
      delegations: [],
    });
    setProviderToken("operator-bearer");
    renderProvider();

    expect(await screen.findByRole("heading", { name: "Operator access" })).toBeInTheDocument();
    const operatorRow = (await screen.findByText("Casey")).closest("tr")!;
    expect(screen.getByText("scim:entra")).toBeInTheDocument();
    fireEvent.click(within(operatorRow).getByRole("button", { name: /View delegations/i }));
    await screen.findByRole("dialog", { name: /Casey/ });
    expect(screen.getByText("tenant-acme")).toBeInTheDocument();
    expect(screen.getByText(/Last used/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Revoke" }));
    await waitFor(() =>
      expect(providerMock.revokeOperatorAccess).toHaveBeenCalledWith("op-2", {
        customer_id: "tenant-acme",
        operations: ["read"],
        reason: "Revoked in Provider access console",
      }),
    );
  });

  // These are the exact delegation wire values from ee/provider/delegation.go.
  // The console previously sent break_glass, which the served API rejects.
  it.each(["read", "provision", "suspend", "resume", "offboard", "break-glass"])(
    "grants the server's %s operation through the access form",
    async (operation) => {
      const operator = {
        identity: {
          id: "op-2",
          user_name: "casey",
          display_name: "Casey",
          email: "casey@example.test",
          role: "operator",
          active: true,
          source: "scim:test",
          created_at: "2026-09-16T00:00:00Z",
          updated_at: "2026-09-16T00:00:00Z",
        },
        delegations: [],
      };
      providerMock.listTenants.mockResolvedValue([]);
      providerMock.listOperatorAccess.mockResolvedValue([operator]);
      providerMock.listAccessCustomers.mockResolvedValue([{ id: "tenant-acme", name: "Acme Corp", slug: "acme", status: "active" }]);
      providerMock.grantOperatorAccess.mockResolvedValue(operator);
      setProviderToken("admin-mfa");
      renderProvider();
      await screen.findByRole("option", { name: "Casey — casey" });
      await screen.findByRole("option", { name: "Acme Corp — acme" });
      fireEvent.change(screen.getByRole("combobox", { name: "Operator" }), { target: { value: "op-2" } });
      fireEvent.change(screen.getByRole("combobox", { name: "Customer" }), { target: { value: "tenant-acme" } });
      const operationSelect = screen.getByRole("combobox", { name: "Operation" });
      expect(within(operationSelect).getByRole("option", { name: operation })).toHaveValue(operation);
      fireEvent.change(operationSelect, { target: { value: operation } });
      fireEvent.click(screen.getByRole("button", { name: "Grant access" }));
      await waitFor(() =>
        expect(providerMock.grantOperatorAccess).toHaveBeenCalledWith("op-2", { customer_id: "tenant-acme", operations: [operation], expires_at: undefined }),
      );
    },
  );

  it("pulls, verifies, and downloads a selected customer's invoice evidence", async () => {
    providerMock.listTenants.mockResolvedValue([
      { id: "tenant-alpha", slug: "alpha", name: "Alpha Bank", status: "active", created_at: "2026-01-01T00:00:00Z", updated_at: "2026-01-01T00:00:00Z" },
      { id: "tenant-bravo", slug: "bravo", name: "Bravo Health", status: "active", created_at: "2026-02-01T00:00:00Z", updated_at: "2026-02-01T00:00:00Z" },
    ]);
    providerMock.usageEvidence.mockResolvedValue({
      customer_id: "tenant-bravo",
      period_start: "2026-07-01T00:00:00Z",
      period_end: "2026-08-01T00:00:00Z",
      lines: [{ meter: "certificates_issued", kind: "counter", value: 7 }],
      signable: true,
      reason: "complete and reconciled",
      reconciliation: [
        { meter: "certificates_issued", metered: 7, event_history: 7, checked: true, matches: true },
        { meter: "tenants", metered: 1, event_history: 0, checked: false, matches: false },
      ],
      digest: "abc123",
      signature: { alg: "RS256", key_id: "audit-1", jws: "header.payload.signature" },
      guidance: "verify before invoicing",
    });
    providerMock.verifyUsageEvidence.mockResolvedValue({ verified: true, keyId: "audit-1" });
    setProviderToken("operator-bearer");
    renderProvider();

    await screen.findByRole("option", { name: "Bravo Health · bravo" });
    const customer = screen.getByLabelText("Billing customer");
    fireEvent.change(customer, { target: { value: "tenant-bravo" } });
    fireEvent.change(screen.getByLabelText("Billing period start (UTC)"), { target: { value: "2026-07-01T00:00" } });
    fireEvent.change(screen.getByLabelText("Billing period end (UTC)"), { target: { value: "2026-08-01T00:00" } });
    fireEvent.click(screen.getByRole("button", { name: "Pull invoice evidence" }));

    await waitFor(() => expect(providerMock.usageEvidence).toHaveBeenCalledWith("tenant-bravo", "2026-07-01T00:00:00Z", "2026-08-01T00:00:00Z"));
    expect(await screen.findByText("Signature verified")).toBeInTheDocument();
    expect(screen.getByText("7")).toBeInTheDocument();
    expect(screen.getByText("abc123")).toBeInTheDocument();
    expect(screen.getByText("certificates_issued: reconciled to 7 event-history records.")).toBeInTheDocument();
    expect(
      screen.getByText("tenants: no independent event-history comparison exists; this metered value stands alone. Use the billability verdict above."),
    ).toBeInTheDocument();
    expect(screen.queryByText(/tenants: not reconciled; do not invoice/)).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Download signed JSON" }));
    fireEvent.click(screen.getByRole("button", { name: "Download finance CSV" }));
    await waitFor(() => expect(providerMock.downloadUsageEvidence).toHaveBeenCalledTimes(2));
    expect(providerMock.downloadUsageEvidence).toHaveBeenNthCalledWith(1, "tenant-bravo", "2026-07-01T00:00:00Z", "2026-08-01T00:00:00Z", "json");
    expect(providerMock.downloadUsageEvidence).toHaveBeenNthCalledWith(2, "tenant-bravo", "2026-07-01T00:00:00Z", "2026-08-01T00:00:00Z", "csv");
  });

  it("pulls the exact closed UTC hour and refuses a reversed period", async () => {
    providerMock.listTenants.mockResolvedValue([
      { id: "tenant-alpha", slug: "alpha", name: "Alpha Bank", status: "active", created_at: "2026-01-01T00:00:00Z", updated_at: "2026-01-01T00:00:00Z" },
    ]);
    providerMock.usageEvidence.mockResolvedValue({
      customer_id: "tenant-alpha",
      period_start: "2026-10-03T19:00:00Z",
      period_end: "2026-10-03T20:00:00Z",
      lines: [],
      signable: false,
      reason: "meter coverage is incomplete",
      digest: "hour-fixture",
      guidance: "do not invoice",
    });
    setProviderToken("operator-bearer");
    renderProvider();
    await screen.findByRole("option", { name: "Alpha Bank · alpha" });
    const start = screen.getByLabelText("Billing period start (UTC)");
    const end = screen.getByLabelText("Billing period end (UTC)");
    expect(start).toHaveAttribute("type", "datetime-local");
    fireEvent.change(start, { target: { value: "2026-10-03T20:00" } });
    fireEvent.change(end, { target: { value: "2026-10-03T19:00" } });
    expect(screen.getByRole("button", { name: "Pull invoice evidence" })).toBeDisabled();
    expect(providerMock.usageEvidence).not.toHaveBeenCalled();
    fireEvent.change(start, { target: { value: "2026-10-03T19:00" } });
    fireEvent.change(end, { target: { value: "2026-10-03T20:00" } });
    fireEvent.click(screen.getByRole("button", { name: "Pull invoice evidence" }));
    await waitFor(() => expect(providerMock.usageEvidence).toHaveBeenCalledWith("tenant-alpha", "2026-10-03T19:00:00Z", "2026-10-03T20:00:00Z"));
  });

  it("renders delegated customer health beside the selected usage evidence", async () => {
    providerMock.listTenants.mockResolvedValue([
      { id: "tenant-alpha", slug: "alpha", name: "Alpha Bank", status: "active", created_at: "2026-01-01T00:00:00Z", updated_at: "2026-01-01T00:00:00Z" },
      { id: "tenant-bravo", slug: "bravo", name: "Bravo Health", status: "suspended", created_at: "2026-02-01T00:00:00Z", updated_at: "2026-02-01T00:00:00Z" },
    ]);
    providerMock.customerHealth.mockResolvedValue({ tenant_id: "tenant-bravo", health: "suspended", active_certificates: 4 });
    providerMock.usageEvidence.mockResolvedValue({
      customer_id: "tenant-bravo",
      period_start: "2026-07-01T00:00:00Z",
      period_end: "2026-08-01T00:00:00Z",
      lines: [],
      signable: false,
      reason: "meter coverage is incomplete",
      digest: "health-fixture",
      guidance: "do not invoice",
    });
    setProviderToken("operator-bearer");
    renderProvider();

    expect(await screen.findByText("Health unknown")).toBeInTheDocument();
    await screen.findByRole("option", { name: "Bravo Health · bravo" });
    fireEvent.change(screen.getByLabelText("Billing customer"), { target: { value: "tenant-bravo" } });
    fireEvent.click(screen.getByRole("button", { name: "Pull invoice evidence" }));

    await waitFor(() => expect(providerMock.customerHealth).toHaveBeenCalledWith("tenant-bravo"));
    expect(await screen.findByText("Customer health")).toBeInTheDocument();
    expect(screen.getByText("Suspended")).toBeInTheDocument();
    expect(screen.getByText("Active certificates")).toBeInTheDocument();
    expect(screen.getByText("4")).toBeInTheDocument();
    expect(screen.getByText("Not billable")).toBeInTheDocument();
  });

  it("keeps invoice truth visible when customer health is explicitly unavailable", async () => {
    providerMock.listTenants.mockResolvedValue([
      { id: "tenant-alpha", slug: "alpha", name: "Alpha Bank", status: "active", created_at: "2026-01-01T00:00:00Z", updated_at: "2026-01-01T00:00:00Z" },
    ]);
    providerMock.customerHealth.mockRejectedValue(new Error("customer health is unavailable"));
    providerMock.usageEvidence.mockResolvedValue({
      customer_id: "tenant-alpha",
      period_start: "2026-07-01T00:00:00Z",
      period_end: "2026-08-01T00:00:00Z",
      lines: [],
      signable: false,
      reason: "meter coverage is incomplete",
      digest: "unavailable-fixture",
      guidance: "do not invoice",
    });
    setProviderToken("operator-bearer");
    renderProvider();

    await screen.findByRole("option", { name: "Alpha Bank · alpha" });
    await waitFor(() => expect(screen.getByRole("button", { name: "Pull invoice evidence" })).toBeEnabled());
    fireEvent.click(screen.getByRole("button", { name: "Pull invoice evidence" }));

    expect(await screen.findByText(/Health unavailable: customer health is unavailable/)).toBeInTheDocument();
    expect(screen.getByText("Not billable")).toBeInTheDocument();
    expect(screen.queryByText(/^0$/)).not.toBeInTheDocument();
  });

  it("keeps routine customer work before access history, billing, provisioning and activity", async () => {
    providerMock.listTenants.mockResolvedValue([
      { id: "t-1", slug: "acme", name: "Acme Corp", status: "active", created_at: "2026-01-01T00:00:00Z", updated_at: "2026-01-01T00:00:00Z" },
    ]);
    setProviderToken("operator-bearer");
    renderProvider();
    await screen.findByText("Acme Corp");
    const customers = screen.getByRole("heading", { name: /^Customers$/ });
    const main = screen.getByRole("main");
    const headings = within(main).getAllByRole("heading", { level: 2 });
    expect(headings[0]).toBe(customers);
    for (const heading of headings.slice(1)) {
      expect(customers.compareDocumentPosition(heading) & Node.DOCUMENT_POSITION_FOLLOWING).not.toBe(0);
    }
    expect(within(screen.getByRole("table", { name: "Customers" })).getByRole("button", { name: "Suspend" })).toBeVisible();
  });

  it("keeps interrupted offboarding recovery visible outside bounded historical activity", async () => {
    const request = {
      sequence: 101,
      event_id: "pending-erasure",
      type: "provider.tenant_erasure.requested",
      request_event_id: "pending-erasure",
      tenant_id: "removed-customer",
      operator_id: "test-admin",
      at: "2026-01-03T00:00:00Z",
      offboard_state: "pending",
      can_continue_offboard: true,
    };
    providerMock.listTenants.mockResolvedValue([]);
    providerMock.listActivity.mockResolvedValue([
      request,
      ...Array.from({ length: 60 }, (_, index) => ({
        sequence: index + 1,
        event_id: `older-event-${index}`,
        type: "provider.operator.role.set",
        operator_id: "test-admin",
        at: "2026-01-01T00:00:00Z",
      })),
    ]);
    providerMock.offboardTenant.mockResolvedValue(undefined);
    vi.spyOn(window, "confirm").mockReturnValue(false);
    setProviderToken("operator-bearer");
    renderProvider();
    const continuation = await screen.findByRole("button", { name: "Continue offboarding" });
    expect(continuation).toBeVisible();
    expect(continuation.closest("details:not([open])")).toBeNull();
    fireEvent.click(continuation);
    expect(providerMock.offboardTenant).not.toHaveBeenCalled();
    vi.mocked(window.confirm).mockReturnValue(true);
    fireEvent.click(continuation);
    await waitFor(() => expect(providerMock.offboardTenant).toHaveBeenCalledWith("removed-customer", "pending-erasure"));
    expect(screen.getAllByRole("button", { name: "Continue offboarding" })).toHaveLength(1);
  });

  it("opens every retained delegation without expanding the operator roster and restores keyboard focus", async () => {
    const delegations = Array.from({ length: 30 }, (_, index) => ({
      operator_id: "op-retained",
      customer_id: `retained-customer-${index}`,
      operation: "read",
      source: "console",
      granted_by: "test-admin",
      granted_at: "2020-01-01T00:00:00Z",
      ...(index % 3 === 1 ? { expires_at: "2020-02-01T00:00:00Z" } : {}),
      ...(index % 3 === 2 ? { revoked_at: "2020-03-01T00:00:00Z", revoked_by: "test-admin" } : {}),
    }));
    providerMock.listTenants.mockResolvedValue([]);
    providerMock.listOperatorAccess.mockResolvedValue([
      {
        identity: {
          id: "op-retained",
          user_name: "retained",
          email: "retained@example.test",
          display_name: "Retained Operator",
          role: "operator",
          active: true,
          source: "scim:test",
          created_at: "2020-01-01T00:00:00Z",
          updated_at: "2020-01-01T00:00:00Z",
        },
        delegations,
      },
    ]);
    setProviderToken("operator-bearer");
    renderProvider();
    const operatorRow = (await screen.findByText("Retained Operator")).closest("tr")!;
    expect(within(operatorRow).queryByText("retained-customer-29")).not.toBeInTheDocument();
    const opener = within(operatorRow).getByRole("button", { name: /View delegations/i });
    opener.focus();
    fireEvent.click(opener);
    const drawer = await screen.findByRole("dialog", { name: /Retained Operator/ });
    let activeActions = 0;
    for (let page = 0; page < 3; page += 1) {
      for (const grant of delegations.slice(page * 10, (page + 1) * 10)) expect(within(drawer).getByText(grant.customer_id)).toBeVisible();
      activeActions += within(drawer).getAllByRole("button", { name: /^Revoke$/ }).length;
      const next = within(drawer).getByRole("button", { name: "Next delegations" });
      if (page < 2) fireEvent.click(next);
      else expect(next).toBeDisabled();
    }
    expect(activeActions).toBe(10);
    fireEvent.click(within(drawer).getByRole("button", { name: "Previous delegations" }));
    expect(within(drawer).getByText("retained-customer-10")).toBeVisible();
    fireEvent.keyDown(drawer, { key: "Escape" });
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    expect(opener).toHaveFocus();
  });

  it("shows both grant episodes when the same customer scope is reissued after revocation", async () => {
    providerMock.listTenants.mockResolvedValue([]);
    providerMock.listOperatorAccess.mockResolvedValue([
      {
        identity: {
          id: "op-regranted",
          user_name: "regranted",
          email: "regranted@example.test",
          display_name: "Regranted Operator",
          role: "admin",
          active: true,
          source: "scim:test",
          created_at: "2026-10-04T00:00:00Z",
          updated_at: "2026-10-04T00:04:00Z",
        },
        delegations: [
          {
            grant_event_id: "event-old",
            operator_id: "op-regranted",
            customer_id: "same-customer",
            operation: "read",
            source: "scim",
            granted_at: "2026-10-04T00:01:00Z",
            revoked_at: "2026-10-04T00:02:00Z",
          },
          {
            grant_event_id: "event-new",
            operator_id: "op-regranted",
            customer_id: "same-customer",
            operation: "read",
            source: "scim",
            granted_at: "2026-10-04T00:04:00Z",
          },
        ],
      },
    ]);
    setProviderToken("operator-bearer");
    renderProvider();
    const operatorRow = (await screen.findByText("Regranted Operator")).closest("tr")!;
    fireEvent.click(within(operatorRow).getByRole("button", { name: /View delegations/i }));
    const drawer = await screen.findByRole("dialog", { name: /Regranted Operator/ });
    expect(within(drawer).getAllByText("same-customer")).toHaveLength(2);
    expect(within(drawer).getAllByRole("button", { name: "Revoke" })).toHaveLength(1);
  });

  it("keeps all returned delegations visible when refresh shrinks an anchored page", async () => {
    const delegations = Array.from({ length: 21 }, (_, index) => ({
      operator_id: "op-shrink",
      customer_id: `shrink-customer-${index}`,
      operation: "read",
      source: "console",
      granted_by: "test-admin",
      granted_at: "2020-01-01T00:00:00Z",
    }));
    const row = {
      identity: {
        id: "op-shrink",
        user_name: "shrink",
        email: "shrink@example.test",
        display_name: "Shrink Operator",
        role: "operator",
        active: true,
        source: "scim:test",
        created_at: "2020-01-01T00:00:00Z",
        updated_at: "2020-01-01T00:00:00Z",
      },
      delegations,
    };
    providerMock.listOperatorAccess.mockResolvedValue([row]);
    const visibility = vi.spyOn(document, "visibilityState", "get").mockReturnValue("visible");
    try {
      setProviderToken("operator-bearer");
      renderProvider();
      const operatorRow = (await screen.findByText("Shrink Operator")).closest("tr")!;
      fireEvent.click(within(operatorRow).getByRole("button", { name: /View delegations/i }));
      const drawer = await screen.findByRole("dialog", { name: /Shrink Operator/ });
      fireEvent.click(within(drawer).getByRole("button", { name: "Next delegations" }));
      expect(within(drawer).getByText("shrink-customer-10")).toBeVisible();
      const remaining = [delegations[0], delegations[10], delegations[20]];
      providerMock.listOperatorAccess.mockResolvedValue([{ ...row, delegations: remaining }]);
      fireEvent(document, new Event("visibilitychange"));
      await waitFor(() => expect(within(drawer).getByText("shrink-customer-0")).toBeVisible());
      for (const grant of remaining) expect(within(drawer).getByText(grant.customer_id)).toBeVisible();
      expect(within(drawer).queryByRole("button", { name: "Previous delegations" })).not.toBeInTheDocument();
      providerMock.listOperatorAccess.mockResolvedValue([row]);
      fireEvent(document, new Event("visibilitychange"));
      await within(drawer).findByRole("button", { name: "Next delegations" });
      expect(within(drawer).getByText("shrink-customer-0")).toBeVisible();
      expect(within(drawer).queryByText("shrink-customer-10")).not.toBeInTheDocument();
      expect(providerMock.revokeOperatorAccess).not.toHaveBeenCalled();
    } finally {
      visibility.mockRestore();
    }
  });

  it("refreshes an open delegation drawer from current authority and closes it when the operator disappears", async () => {
    const grant = {
      operator_id: "op-live",
      customer_id: "customer-live",
      operation: "read",
      source: "console",
      granted_by: "test-admin",
      granted_at: "2020-01-01T00:00:00Z",
    };
    const row = {
      identity: {
        id: "op-live",
        user_name: "live",
        email: "live@example.test",
        display_name: "Live Operator",
        role: "operator",
        active: true,
        source: "scim:test",
        created_at: "2020-01-01T00:00:00Z",
        updated_at: "2020-01-01T00:00:00Z",
      },
      delegations: [grant],
    };
    providerMock.listTenants.mockResolvedValue([]);
    providerMock.listOperatorAccess.mockResolvedValue([row]);
    const visibility = vi.spyOn(document, "visibilityState", "get").mockReturnValue("visible");
    try {
      setProviderToken("operator-bearer");
      renderProvider();
      const operatorRow = (await screen.findByText("Live Operator")).closest("tr")!;
      fireEvent.click(within(operatorRow).getByRole("button", { name: /View delegations/i }));
      const drawer = await screen.findByRole("dialog", { name: /Live Operator/ });
      expect(within(drawer).getByRole("button", { name: /^Revoke$/ })).toBeVisible();
      providerMock.listOperatorAccess.mockResolvedValue([
        { ...row, delegations: [{ ...grant, revoked_at: "2020-02-01T00:00:00Z", revoked_by: "another-admin" }] },
      ]);
      fireEvent(document, new Event("visibilitychange"));
      await waitFor(() => expect(within(drawer).queryByRole("button", { name: /^Revoke$/ })).not.toBeInTheDocument());
      expect(within(drawer).getByText("customer-live")).toBeVisible();
      expect(within(drawer).getByText(/Revoked/)).toBeVisible();
      providerMock.listOperatorAccess.mockResolvedValue([]);
      fireEvent(document, new Event("visibilitychange"));
      await waitFor(() => expect(screen.queryByRole("dialog", { name: /Live Operator/ })).not.toBeInTheDocument());
      providerMock.listOperatorAccess.mockResolvedValue([row]);
      fireEvent(document, new Event("visibilitychange"));
      await screen.findByText("Live Operator");
      expect(screen.queryByRole("dialog", { name: /Live Operator/ })).not.toBeInTheDocument();
      expect(providerMock.revokeOperatorAccess).not.toHaveBeenCalled();
    } finally {
      visibility.mockRestore();
    }
  });

  it("removes delegation actions when authority changes and closes unreadable details without reopening them", async () => {
    const row = {
      identity: {
        id: "op-current",
        user_name: "current",
        email: "current@example.test",
        display_name: "Current Operator",
        role: "operator",
        active: true,
        source: "scim:test",
        created_at: "2020-01-01T00:00:00Z",
        updated_at: "2020-01-01T00:00:00Z",
      },
      delegations: [
        {
          operator_id: "op-current",
          customer_id: "current-customer",
          operation: "read",
          source: "console",
          granted_by: "test-admin",
          granted_at: "2020-01-01T00:00:00Z",
        },
      ],
    };
    providerMock.listOperatorAccess.mockResolvedValue([row]);
    const visibility = vi.spyOn(document, "visibilityState", "get").mockReturnValue("visible");
    try {
      setProviderToken("operator-bearer");
      renderProvider();
      const operatorRow = (await screen.findByText("Current Operator")).closest("tr")!;
      fireEvent.click(within(operatorRow).getByRole("button", { name: /View delegations/i }));
      const drawer = await screen.findByRole("dialog", { name: /Current Operator/ });
      expect(within(drawer).getByRole("button", { name: /^Revoke$/ })).toBeVisible();
      // The unchanged admin label does not authorize writes after the served
      // capability is withdrawn. Keep the readable evidence available.
      providerMock.session.mockResolvedValue({
        id: "test-admin",
        role: "admin",
        mfa: true,
        authority: {
          available: true,
          access_read: true,
          access_write: false,
          provision: false,
          isolation_drill: false,
          customers: {},
        },
      });
      fireEvent(document, new Event("visibilitychange"));
      await waitFor(() => expect(within(drawer).queryByRole("button", { name: /^Revoke$/ })).not.toBeInTheDocument());
      expect(within(drawer).getByText("current-customer")).toBeVisible();
      providerMock.listOperatorAccess.mockRejectedValue(new Error("Current delegation evidence unavailable"));
      fireEvent(document, new Event("visibilitychange"));
      // Allow the query layer's existing one retry; do not change its policy.
      await screen.findByText("Current delegation evidence unavailable", {}, { timeout: 3000 });
      expect(screen.queryByRole("dialog", { name: /Current Operator/ })).not.toBeInTheDocument();
      providerMock.listOperatorAccess.mockResolvedValue([row]);
      fireEvent(document, new Event("visibilitychange"));
      await screen.findByText("Current Operator");
      expect(screen.queryByRole("dialog", { name: /Current Operator/ })).not.toBeInTheDocument();
      expect(providerMock.revokeOperatorAccess).not.toHaveBeenCalled();
      expect(providerMock.grantOperatorAccess).not.toHaveBeenCalled();
      expect(providerMock.setOperatorRole).not.toHaveBeenCalled();
    } finally {
      visibility.mockRestore();
    }
  });

  it("keeps every returned activity row reachable and preserves the viewed event through live refresh", async () => {
    const rows = Array.from({ length: 23 }, (_, index) => ({
      sequence: 100 - index,
      event_id: `recent-${index}`,
      type: "provider.operator.role.set",
      operator_id: "test-admin",
      reason: `unique-reason-${index} ` + "long explanation ".repeat(20).trimEnd(),
      at: "2026-01-03T00:00:00Z",
    }));
    providerMock.listActivity.mockResolvedValue(rows);
    const visibility = vi.spyOn(document, "visibilityState", "get").mockReturnValue("visible");
    try {
      setProviderToken("operator-bearer");
      renderProvider();
      const table = await screen.findByRole("table", { name: "Recent activity" });
      expect(within(table).getByText(rows[0].reason)).toBeVisible();
      expect(within(table).queryByText(rows[10].reason)).not.toBeInTheDocument();
      fireEvent.click(screen.getByRole("button", { name: "Older activity" }));
      for (const row of rows.slice(10, 20)) expect(within(table).getByText(row.reason)).toBeVisible();
      providerMock.listActivity.mockResolvedValue([{ ...rows[0], sequence: 101, event_id: "new-live-event", reason: "Newly received event" }, ...rows]);
      fireEvent(document, new Event("visibilitychange"));
      await screen.findByText("12–21 of 24 recent events");
      for (const row of rows.slice(10, 20)) expect(within(table).getByText(row.reason)).toBeVisible();
      fireEvent.click(screen.getByRole("button", { name: "Older activity" }));
      for (const row of rows.slice(20)) expect(within(table).getByText(row.reason)).toBeVisible();
      expect(screen.getByRole("button", { name: "Older activity" })).toBeDisabled();
      fireEvent.click(screen.getByRole("button", { name: "Newer activity" }));
      expect(within(table).getByText(rows[10].reason)).toBeVisible();
      // Keep the current anchor but shrink below a page: no earlier row may
      // become hidden behind pagination that is no longer rendered.
      providerMock.listActivity.mockResolvedValue([rows[0], rows[10], rows[20]]);
      fireEvent(document, new Event("visibilitychange"));
      await waitFor(() => expect(within(table).getByText(rows[0].reason)).toBeVisible());
      for (const row of [rows[10], rows[20]]) expect(within(table).getByText(row.reason)).toBeVisible();
      expect(screen.queryByRole("button", { name: "Newer activity" })).not.toBeInTheDocument();
      providerMock.listActivity.mockResolvedValue(rows);
      fireEvent(document, new Event("visibilitychange"));
      await screen.findByText("1–10 of 23 recent events");
      expect(within(table).getByText(rows[0].reason)).toBeVisible();
      fireEvent.click(screen.getByRole("button", { name: "Older activity" }));
      providerMock.listActivity.mockResolvedValue(rows.slice(0, 2));
      fireEvent(document, new Event("visibilitychange"));
      await waitFor(() => expect(within(table).queryByText(rows[10].reason)).not.toBeInTheDocument());
      expect(within(table).getByText(rows[0].reason)).toBeVisible();
      providerMock.listActivity.mockResolvedValue(rows);
      fireEvent(document, new Event("visibilitychange"));
      await screen.findByText("1–10 of 23 recent events");
      expect(within(table).getByText(rows[0].reason)).toBeVisible();
      expect(within(table).queryByText(rows[10].reason)).not.toBeInTheDocument();
    } finally {
      visibility.mockRestore();
    }
  });
});
