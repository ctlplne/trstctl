// SPDX-License-Identifier: BUSL-1.1

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { IntlProvider } from "@/i18n/I18nProvider";
import { AppQueryProvider } from "@/lib/query";
import { Provider } from "@/pages/Provider";
import { clearProviderToken, providerToken, setProviderToken } from "@/lib/providerApi";

const alpha = { id: "alpha", slug: "alpha", name: "Alpha customer", status: "active", created_at: "2026-09-16T00:00:00Z", updated_at: "2026-09-16T00:00:00Z" };
const beta = { ...alpha, id: "beta", slug: "beta", name: "Beta customer" };
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
let delayAdminRoster: (() => Promise<Response>) | undefined;
let rejectProvision = false;

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

async function switchToLimitedOperator() {
  fireEvent.click(screen.getByRole("button", { name: "Sign out" }));
  fireEvent.change(await screen.findByLabelText("Operator bearer token"), { target: { value: "limited" } });
  fireEvent.click(screen.getByRole("button", { name: "Sign in" }));
  await screen.findByRole("cell", { name: "Alpha customer" });
}

describe("Provider authentication boundaries with the real transport client", () => {
  beforeEach(() => {
    clearProviderToken();
    delayAdminRoster = undefined;
    rejectProvision = false;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string, init?: RequestInit) => {
        const token = new Headers(init?.headers).get("Authorization");
        const admin = token === "Bearer admin";
        if (url === "/auth/methods") return json({ provider_plane: true });
        if (url === "/provider/v1/auth/methods") return json({ methods: ["oidc"] });
        if (url === "/provider/v1/auth/logout") return new Response(null, { status: 204 });
        if (!token) return json({ detail: "Sign in again" }, 401);
        if (url === "/provider/v1/auth/session")
          return json({
            id: admin ? "admin" : "limited",
            role: admin ? "admin" : "operator",
            mfa: true,
            authority: {
              available: true,
              access_read: admin,
              access_write: admin,
              provision: admin,
              isolation_drill: admin,
              customers: {
                alpha: { read_quota: true, write_quota: admin, write_brand: admin, suspend: admin, offboard: admin },
                ...(admin ? { beta: { read_quota: true, write_quota: true, write_brand: true, suspend: true, offboard: true } } : {}),
              },
            },
          });
        if (url === "/provider/v1/operators") return admin ? json({ operators: [] }) : json({ detail: "Provider administrator required" }, 403);
        if (url === "/provider/v1/access/customers") {
          if (admin && delayAdminRoster) return delayAdminRoster();
          return admin ? json({ tenants: [alpha, beta] }) : json({ detail: "Provider administrator required" }, 403);
        }
        if (url === "/provider/v1/tenants" && init?.method === "POST" && rejectProvision) return json({ detail: "Customer delegation is required" }, 403);
        if (url === "/provider/v1/tenants") return json({ tenants: admin ? [alpha, beta] : [alpha] });
        if (url.startsWith("/provider/v1/activity")) return json({ items: [] });
        throw new Error("Unexpected Provider request " + url);
      }),
    );
  });
  afterEach(() => {
    clearProviderToken();
    vi.unstubAllGlobals();
  });

  it("does not show the previous operator's cached customer roster after sign-out and sign-in", async () => {
    setProviderToken("admin");
    renderProvider();
    await screen.findByRole("option", { name: "Beta customer — beta" });
    await switchToLimitedOperator();
    expect(screen.queryByRole("option", { name: "Beta customer — beta" })).not.toBeInTheDocument();
    expect(providerToken()).toBe("limited");
  });

  it("discards a previous operator's roster that finishes after the next operator signs in", async () => {
    let resolveRoster!: (response: Response) => void;
    const delayed = new Promise<Response>((resolve) => {
      resolveRoster = resolve;
    });
    delayAdminRoster = () => delayed;
    setProviderToken("admin");
    renderProvider();
    await screen.findByRole("cell", { name: "Beta customer" });
    await switchToLimitedOperator();
    await act(async () => {
      resolveRoster(json({ tenants: [alpha, beta] }));
      await delayed;
    });
    await waitFor(() => expect(screen.queryByRole("option", { name: "Beta customer — beta" })).not.toBeInTheDocument());
    expect(providerToken()).toBe("limited");
  });

  it("keeps a valid operator and the form when customer delegation refuses a mutation", async () => {
    rejectProvision = true;
    setProviderToken("admin");
    renderProvider();
    fireEvent.change(await screen.findByLabelText("Slug"), { target: { value: "new-customer" } });
    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "New customer" } });
    fireEvent.click(screen.getByRole("button", { name: "Provision" }));
    expect(await screen.findByText(/Customer delegation is required/)).toBeInTheDocument();
    expect(providerToken()).toBe("admin");
    expect(screen.getByLabelText("Slug")).toHaveValue("new-customer");
    expect(screen.getByLabelText("Name")).toHaveValue("New customer");
    expect(screen.queryByLabelText("Operator bearer token")).not.toBeInTheDocument();
  });
});
