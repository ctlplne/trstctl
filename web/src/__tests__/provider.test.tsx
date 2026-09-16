// SPDX-License-Identifier: MPL-2.0

import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen, waitFor, fireEvent, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { IntlProvider } from "@/i18n/I18nProvider";
import { AppQueryProvider } from "@/lib/query";

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
          customers: { "t-1": { read_quota: true, write_quota: true, write_brand: true, suspend: true, offboard: true } },
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
    expect(await screen.findByText("Casey")).toBeInTheDocument();
    expect(screen.getByText("scim:entra")).toBeInTheDocument();
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
      reconciliation: [{ meter: "certificates_issued", metered: 7, event_history: 7, checked: true, matches: true }],
      digest: "abc123",
      signature: { alg: "RS256", key_id: "audit-1", jws: "header.payload.signature" },
      guidance: "verify before invoicing",
    });
    providerMock.verifyUsageEvidence.mockResolvedValue({ verified: true, keyId: "audit-1" });
    setProviderToken("operator-bearer");
    renderProvider();

    const customer = await screen.findByLabelText("Billing customer");
    fireEvent.change(customer, { target: { value: "tenant-bravo" } });
    fireEvent.change(screen.getByLabelText("Billing period start"), { target: { value: "2026-07-01" } });
    fireEvent.change(screen.getByLabelText("Billing period end"), { target: { value: "2026-08-01" } });
    fireEvent.click(screen.getByRole("button", { name: "Pull invoice evidence" }));

    await waitFor(() => expect(providerMock.usageEvidence).toHaveBeenCalledWith("tenant-bravo", "2026-07-01T00:00:00Z", "2026-08-01T00:00:00Z"));
    expect(await screen.findByText("Signature verified")).toBeInTheDocument();
    expect(screen.getByText("7")).toBeInTheDocument();
    expect(screen.getByText("abc123")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Download signed JSON" }));
    fireEvent.click(screen.getByRole("button", { name: "Download finance CSV" }));
    await waitFor(() => expect(providerMock.downloadUsageEvidence).toHaveBeenCalledTimes(2));
    expect(providerMock.downloadUsageEvidence).toHaveBeenNthCalledWith(1, "tenant-bravo", "2026-07-01T00:00:00Z", "2026-08-01T00:00:00Z", "json");
    expect(providerMock.downloadUsageEvidence).toHaveBeenNthCalledWith(2, "tenant-bravo", "2026-07-01T00:00:00Z", "2026-08-01T00:00:00Z", "csv");
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
    fireEvent.change(await screen.findByLabelText("Billing customer"), { target: { value: "tenant-bravo" } });
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

    fireEvent.click(await screen.findByRole("button", { name: "Pull invoice evidence" }));

    expect(await screen.findByText(/Health unavailable: customer health is unavailable/)).toBeInTheDocument();
    expect(screen.getByText("Not billable")).toBeInTheDocument();
    expect(screen.queryByText(/^0$/)).not.toBeInTheDocument();
  });
});
