// SPDX-License-Identifier: MPL-2.0

import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen, waitFor, fireEvent, within } from "@testing-library/react";
import { IntlProvider } from "@/i18n/I18nProvider";

const { providerMock } = vi.hoisted(() => ({
  providerMock: {
    listTenants: vi.fn(),
    provisionTenant: vi.fn(),
    suspendTenant: vi.fn(),
    offboardTenant: vi.fn(),
    getQuota: vi.fn(),
    setQuota: vi.fn(),
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

  it("drops the operator back to the gate when the plane refuses the token", async () => {
    const { ProviderAuthError } = await import("@/lib/providerApi");
    providerMock.listTenants.mockRejectedValue(new ProviderAuthError("expired"));
    setProviderToken("stale-bearer");
    renderProvider();
    // An auth refusal is "not signed in", not an error banner: the gate returns.
    expect(await screen.findByLabelText("Operator bearer token")).toBeInTheDocument();
  });
});
