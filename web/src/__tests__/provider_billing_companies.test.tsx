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

  it("names each target's kind and tells the operator what a ConnectWise company is (MSP-3)", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string) => {
        if (url === "/provider/v1/tenants/alpha/billing-companies")
          return json({
            targets: [
              { id: "at", name: "Autotask", type: "autotask", cadence: "monthly" },
              { id: "cw", name: "ConnectWise", type: "connectwise", cadence: "monthly" },
              { id: "gradient", name: "Gradient", type: "gradient", cadence: "monthly" },
              { id: "halo", name: "HaloPSA", type: "halopsa", cadence: "monthly" },
              { id: "psa", name: "Main PSA", type: "json", cadence: "daily" },
              { id: "syncro", name: "Syncro", type: "syncro", cadence: "monthly" },
            ],
            companies: [],
          });
        if (url === "/provider/v1/tenants/alpha/billing-sync") return json({ pushes: [] });
        throw new Error("unexpected path " + url);
      }),
    );
    renderPanel(true);
    const list = await screen.findByRole("list", { name: "Configured billing systems" });
    const [autotaskItem, connectwise, gradientItem, haloItem, generic, syncroItem] = within(list).getAllByRole("listitem");
    expect(within(gradientItem).getByText("Gradient Synthesize, service counts")).toBeInTheDocument();
    expect(within(gradientItem).getByRole("textbox", { name: "Company ID in Gradient" })).toHaveAccessibleDescription(
      "The Gradient account ID trstctl reports this customer under. Map it to the customer's PSA company in Gradient.",
    );
    expect(within(haloItem).getByText("HaloPSA, recurring invoice lines")).toBeInTheDocument();
    expect(within(haloItem).getByRole("textbox", { name: "Company ID in HaloPSA" })).toHaveAccessibleDescription(
      "The HaloPSA client ID, a number. Usage sets the line quantities of that client's recurring invoice.",
    );
    expect(within(syncroItem).getByText("Syncro, recurring invoice lines")).toBeInTheDocument();
    expect(within(syncroItem).getByRole("textbox", { name: "Company ID in Syncro" })).toHaveAccessibleDescription(
      "The Syncro customer ID, a number. Usage sets the line quantities of that customer's one active recurring invoice schedule.",
    );
    expect(within(autotaskItem).getByText("Autotask PSA, contract services")).toBeInTheDocument();
    expect(within(autotaskItem).getByRole("textbox", { name: "Company ID in Autotask" })).toHaveAccessibleDescription(
      "The Autotask company ID, a number. Usage sets the units of that company's Recurring Service contract services.",
    );
    expect(within(connectwise).getByText("ConnectWise PSA, agreement additions")).toBeInTheDocument();
    expect(within(generic).getByText("Signed JSON push")).toBeInTheDocument();
    expect(within(connectwise).getByRole("textbox", { name: "Company ID in ConnectWise" })).toHaveAccessibleDescription(
      "The ConnectWise company record ID or its identifier. Usage lands on that company's one active agreement of the configured type.",
    );
    expect(within(generic).getByRole("textbox", { name: "Company ID in Main PSA" })).not.toHaveAccessibleDescription();
  });

  it("lists the PSA tickets the customer's alerts opened when a system opens tickets (MSP-3)", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string) => {
        if (url === "/provider/v1/tenants/alpha/billing-companies")
          return json({
            targets: [{ id: "cw", name: "ConnectWise", type: "connectwise", cadence: "monthly", tickets: true }],
            companies: [{ tenant_id: "alpha", target_id: "cw", external_company_id: "ALPHA" }],
          });
        if (url === "/provider/v1/tenants/alpha/billing-sync") return json({ pushes: [] });
        if (url === "/provider/v1/tenants/alpha/psa-tickets")
          return json({
            tickets: [
              {
                target_id: "cw",
                alert_kind: "certificate.expiry",
                subject: "c-1",
                generation: 1,
                status: "open",
                external_company_id: "ALPHA",
                external_ticket_id: "502",
                notes: 2,
                updated_at: "2026-11-13T00:00:00Z",
              },
              {
                target_id: "cw",
                alert_kind: "identity.renewal_failed",
                subject: "orders-api",
                generation: 1,
                status: "closed",
                external_company_id: "ALPHA",
                external_ticket_id: "501",
                notes: 0,
                reason: "a renewal succeeded",
                updated_at: "2026-11-12T00:00:00Z",
              },
            ],
          });
        throw new Error("unexpected path " + url);
      }),
    );
    renderPanel(false);
    const table = await screen.findByRole("table", { name: "Tickets opened in the PSA for this customer's alerts" });
    const rows = within(table).getAllByRole("row");
    expect(rows).toHaveLength(3);
    expect(within(rows[1]).getByText("Certificate expiry")).toBeInTheDocument();
    expect(within(rows[1]).getByText("#502 (company ALPHA)")).toBeInTheDocument();
    expect(within(rows[1]).getByText("Notes from later alerts: 2")).toBeInTheDocument();
    expect(within(rows[2]).getByText("Renewal failed")).toBeInTheDocument();
    expect(within(rows[2]).getByText("Closed")).toBeInTheDocument();
    expect(within(rows[2]).getByText("a renewal succeeded")).toBeInTheDocument();
  });
});
