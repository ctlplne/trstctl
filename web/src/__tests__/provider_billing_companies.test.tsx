// SPDX-License-Identifier: BUSL-1.1

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { IntlProvider } from "@/i18n/I18nProvider";
import { AppQueryProvider } from "@/lib/query";
import { clearProviderToken, setProviderToken } from "@/lib/providerApi";
import { ProviderBillingCompanies } from "@/pages/provider/ProviderBillingCompaniesPanel";

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
const targets = [{ id: "psa", name: "Main PSA", type: "json", cadence: "monthly" }];

function renderPanel(canWrite: boolean) {
  return render(
    <IntlProvider initialLocale="en-US" initialTimeZone="UTC">
      <AppQueryProvider>
        <ProviderBillingCompanies customerId="alpha" canWrite={canWrite} onAuthError={vi.fn()} />
      </AppQueryProvider>
    </IntlProvider>,
  );
}

describe("Provider billing systems (MSP-2)", () => {
  beforeEach(() => setProviderToken("signed-lab-operator"));
  afterEach(() => {
    clearProviderToken();
    vi.unstubAllGlobals();
  });

  it("maps a customer to its company with an idempotent PUT and shows the server's conflict", async () => {
    let mapped: string | null = null;
    const fetcher = vi.fn(async (url: string, init?: RequestInit) => {
      if (url === "/provider/v1/tenants/alpha/billing-companies" && (!init?.method || init.method === "GET"))
        return json({ targets, companies: mapped ? [{ tenant_id: "alpha", target_id: "psa", external_company_id: mapped }] : [] });
      if (url === "/provider/v1/tenants/alpha/billing-sync") return json({ pushes: [] });
      if (url === "/provider/v1/tenants/alpha/billing-companies/psa" && init?.method === "PUT") {
        const body = JSON.parse(String(init.body)) as { external_company_id: string };
        if (body.external_company_id === "TAKEN") return json({ title: "conflict", detail: "already mapped" }, 409);
        mapped = body.external_company_id;
        return new Response(null, { status: 204 });
      }
      throw new Error("unexpected path " + url);
    });
    vi.stubGlobal("fetch", fetcher);
    renderPanel(true);
    const list = await screen.findByRole("list", { name: "Configured billing systems" });
    expect(within(list).getByText("Not mapped: nothing is pushed to this system for this customer.")).toBeInTheDocument();
    const input = within(list).getByRole("textbox", { name: "Company ID in Main PSA" });
    fireEvent.change(input, { target: { value: "TAKEN" } });
    fireEvent.click(within(list).getByRole("button", { name: "Save company" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("already mapped to another customer");
    fireEvent.change(input, { target: { value: "COMPANY-7" } });
    fireEvent.click(within(list).getByRole("button", { name: "Save company" }));
    expect(await screen.findByText("Mapped to company COMPANY-7")).toBeInTheDocument();
    const put = fetcher.mock.calls.filter(([url, init]) => url === "/provider/v1/tenants/alpha/billing-companies/psa" && init?.method === "PUT");
    expect(put).toHaveLength(2);
    expect((put[1][1]?.headers as Record<string, string>)["Idempotency-Key"]).toBeTruthy();
    expect(JSON.parse(String(put[1][1]?.body))).toEqual({ external_company_id: "COMPANY-7" });
    await waitFor(() => expect(screen.getByRole("button", { name: "Remove mapping" })).toBeInTheDocument());
  });

  it("shows the mapping and its push history read-only without billing:write, and says when no system is configured", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string) => {
        if (url === "/provider/v1/tenants/alpha/billing-companies")
          return json({ targets, companies: [{ tenant_id: "alpha", target_id: "psa", external_company_id: "COMPANY-1" }] });
        if (url === "/provider/v1/tenants/alpha/billing-sync")
          return json({
            pushes: [
              {
                target_id: "psa",
                period_start: "2026-10-01T00:00:00Z",
                period_end: "2026-11-01T00:00:00Z",
                status: "held",
                reason: "metering coverage has a gap in this period",
                updated_at: "2026-11-13T00:00:00Z",
              },
              {
                target_id: "psa",
                period_start: "2026-09-01T00:00:00Z",
                period_end: "2026-10-01T00:00:00Z",
                status: "delivered",
                external_company_id: "COMPANY-1",
                updated_at: "2026-10-01T03:00:00Z",
              },
            ],
          });
        throw new Error("unexpected path " + url);
      }),
    );
    const view = renderPanel(false);
    expect(await screen.findByText("Mapped to company COMPANY-1")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Save company" })).not.toBeInTheDocument();
    const history = screen.getByRole("table", { name: "Usage pushes" });
    expect(within(history).getByText("Held: not signable")).toBeInTheDocument();
    expect(within(history).getByText("metering coverage has a gap in this period")).toBeInTheDocument();
    expect(within(history).getByText("Delivered")).toBeInTheDocument();
    expect(within(history).getByText("To company COMPANY-1")).toBeInTheDocument();
    view.unmount();
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string) => (url.endsWith("/billing-sync") ? json({ pushes: [] }) : json({ targets: [], companies: [] }))),
    );
    renderPanel(true);
    expect(await screen.findByText(/No billing system is configured/)).toBeInTheDocument();
  });
});
