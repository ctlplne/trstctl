// SPDX-License-Identifier: MPL-2.0

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { IntlProvider } from "@/i18n/I18nProvider";
import { AppQueryProvider } from "@/lib/query";
import { Provider } from "@/pages/Provider";
import { clearProviderToken, providerToken, setProviderToken } from "@/lib/providerApi";

const alpha = { id: "alpha", slug: "alpha", name: "Alpha customer", status: "active", created_at: "2026-09-16T00:00:00Z", updated_at: "2026-09-16T00:00:00Z" };
const json = (body: unknown) => new Response(JSON.stringify(body), { headers: { "Content-Type": "application/json" } });
const readOnlyAuthority = {
  available: true,
  access_read: false,
  access_write: false,
  provision: false,
  isolation_drill: false,
  customers: { alpha: { read_quota: true, write_quota: false, write_brand: false, suspend: false, offboard: false } },
};
let authority: typeof readOnlyAuthority;
let delayedSession: Promise<Response> | undefined;
let requests: string[];

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

describe("Provider controls follow effective server authority", () => {
  beforeEach(() => {
    setProviderToken("limited");
    requests = [];
    delayedSession = undefined;
    authority = structuredClone(readOnlyAuthority);
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string) => {
        requests.push(url);
        if (url === "/auth/methods") return json({ provider_plane: true });
        if (url === "/provider/v1/auth/session") return delayedSession ?? json({ id: "op-1", role: "operator", mfa: true, authority });
        if (url === "/provider/v1/tenants") return json({ tenants: [alpha] });
        if (url.startsWith("/provider/v1/activity")) return json({ items: [] });
        if (url === "/provider/v1/tenants/alpha/quota") return json({ tenant_id: "alpha", max_agents: 3 });
        if (url === "/provider/v1/operators" || url === "/provider/v1/access/customers")
          return new Response(JSON.stringify({ detail: "administrator required" }), { status: 403 });
        throw new Error("Unexpected Provider request " + url);
      }),
    );
  });
  afterEach(() => {
    clearProviderToken();
    vi.unstubAllGlobals();
  });

  it("shows a delegated read-only customer without administrative calls or write controls", async () => {
    renderProvider();
    await screen.findByRole("cell", { name: "Alpha customer" });
    for (const name of ["Provision", "Suspend", "Offboard", "Brand", "Run isolation drill"]) {
      expect(screen.queryByRole("button", { name })).not.toBeInTheDocument();
    }
    expect(requests).not.toContain("/provider/v1/operators");
    expect(requests).not.toContain("/provider/v1/access/customers");
    fireEvent.click(screen.getByRole("button", { name: "Quota" }));
    await waitFor(() => expect(requests).toContain("/provider/v1/tenants/alpha/quota"));
    await act(async () => {
      await Promise.resolve();
    });
    expect(screen.queryByRole("spinbutton")).not.toBeInTheDocument();
    expect(providerToken()).toBe("limited");
  });

  it("does not expose controls while authority is pending or unavailable", async () => {
    let release!: (value: Response) => void;
    delayedSession = new Promise((resolve) => {
      release = resolve;
    });
    renderProvider();
    await screen.findByRole("heading", { name: "Provider console" });
    expect(screen.queryByRole("button", { name: "Provision" })).not.toBeInTheDocument();
    await act(async () => {
      release(json({ id: "op-1", role: "admin", mfa: true, authority: { ...readOnlyAuthority, available: false, customers: {} } }));
      await delayedSession;
    });
    expect(screen.queryByRole("button", { name: "Suspend" })).not.toBeInTheDocument();
    expect(requests).not.toContain("/provider/v1/operators");
    expect(providerToken()).toBe("limited");
  });

  it("shows only the exact allowed customer operation, without inferring offboard from suspend", async () => {
    authority.customers.alpha.suspend = true;
    renderProvider();
    expect(await screen.findByRole("button", { name: "Suspend" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Offboard" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Brand" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Provision" })).not.toBeInTheDocument();
  });
});
