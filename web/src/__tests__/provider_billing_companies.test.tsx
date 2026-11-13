// SPDX-License-Identifier: BUSL-1.1

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { IntlProvider } from "@/i18n/I18nProvider";
import { AppQueryProvider } from "@/lib/query";
import { clearProviderToken, setProviderToken } from "@/lib/providerApi";
import { ProviderBillingCompanies } from "@/pages/provider/ProviderBillingCompaniesPanel";

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
const targets = [{ id: "psa", name: "Main PSA", type: "json", cadence: "monthly" }];

function renderPanel(canWrite: boolean, canWriteRMM = false) {
  return render(
    <IntlProvider initialLocale="en-US" initialTimeZone="UTC">
      <AppQueryProvider>
        <ProviderBillingCompanies customerId="alpha" canWrite={canWrite} canWriteRMM={canWriteRMM} onAuthError={vi.fn()} />
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
              { id: "pax8", name: "Pax8", type: "pax8", cadence: "monthly" },
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
    const [autotaskItem, connectwise, gradientItem, haloItem, pax8Item, generic, syncroItem] = within(list).getAllByRole("listitem");
    expect(within(pax8Item).getByText("Pax8, usage lines")).toBeInTheDocument();
    expect(within(pax8Item).getByRole("textbox", { name: "Company ID in Pax8" })).toHaveAccessibleDescription(
      "The customer's Pax8 subscription ID (a UUID). Usage is uploaded as lines of that subscription.",
    );
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

  it("lists the customer's RMM devices with their agent and health (MSP-9)", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string) => {
        if (url === "/provider/v1/tenants/alpha/billing-companies")
          return json({
            targets: [{ id: "ninja", name: "NinjaOne", type: "ninjaone", cadence: "monthly", rmm: true }],
            companies: [{ tenant_id: "alpha", target_id: "ninja", external_company_id: "11" }],
          });
        if (url === "/provider/v1/tenants/alpha/billing-sync") return json({ pushes: [] });
        if (url === "/provider/v1/tenants/alpha/rmm-devices")
          return json({
            devices: [
              {
                target_id: "ninja",
                device_id: "1001",
                device_name: "ALPHA-DC01",
                present: true,
                agent_id: "a1",
                agent_match: "hostname",
                health: "trstctl agent healthy (version 1.4.2)",
                updated_at: "2026-11-13T00:00:00Z",
              },
              { target_id: "ninja", device_id: "1003", device_name: "ALPHA-OLD01", present: false, updated_at: "2026-11-12T00:00:00Z" },
            ],
          });
        throw new Error("unexpected path " + url);
      }),
    );
    renderPanel(false);
    expect(await screen.findByText("NinjaOne RMM, devices and agents")).toBeInTheDocument();
    const table = await screen.findByRole("table", { name: "Devices in the RMM and the customer's agents on them" });
    const rows = within(table).getAllByRole("row");
    expect(rows).toHaveLength(3);
    expect(within(rows[1]).getByText("Matched by host name")).toBeInTheDocument();
    expect(within(rows[1]).getByText("trstctl agent healthy (version 1.4.2)")).toBeInTheDocument();
    expect(within(rows[2]).getByText("no longer in the RMM")).toBeInTheDocument();
    expect(within(rows[2]).getByText("No agent")).toBeInTheDocument();
    expect(within(table).queryByRole("button")).toBeNull();
  });

  it("names a Datto RMM target and what its company is (MSP-10)", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string) => {
        if (url === "/provider/v1/tenants/alpha/billing-companies")
          return json({ targets: [{ id: "datto", name: "Datto", type: "datto", cadence: "monthly", rmm: true }], companies: [] });
        if (url === "/provider/v1/tenants/alpha/billing-sync") return json({ pushes: [] });
        if (url === "/provider/v1/tenants/alpha/rmm-devices") return json({ devices: [] });
        throw new Error("unexpected path " + url);
      }),
    );
    renderPanel(true);
    expect(await screen.findByText("Datto RMM, devices and agents")).toBeInTheDocument();
    expect(screen.getByText("The Datto RMM site UID. The site's devices are listed and matched to this customer's agents.")).toBeInTheDocument();
  });

  it("names an N-central target and what its company is (MSP-12)", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string) => {
        if (url === "/provider/v1/tenants/alpha/billing-companies")
          return json({ targets: [{ id: "ncentral", name: "N-central", type: "ncentral", cadence: "monthly", rmm: true }], companies: [] });
        if (url === "/provider/v1/tenants/alpha/billing-sync") return json({ pushes: [] });
        if (url === "/provider/v1/tenants/alpha/rmm-devices") return json({ devices: [] });
        throw new Error("unexpected path " + url);
      }),
    );
    renderPanel(true);
    expect(await screen.findByText("N-able N-central, devices and agents")).toBeInTheDocument();
    expect(
      screen.getByText("The N-central customer ID, a number. The customer's devices are listed and matched to this customer's agents."),
    ).toBeInTheDocument();
  });

  it("names a Kaseya VSA target and what its company is (MSP-13)", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string) => {
        if (url === "/provider/v1/tenants/alpha/billing-companies")
          return json({ targets: [{ id: "vsa", name: "VSA", type: "kaseya", cadence: "monthly", rmm: true }], companies: [] });
        if (url === "/provider/v1/tenants/alpha/billing-sync") return json({ pushes: [] });
        if (url === "/provider/v1/tenants/alpha/rmm-devices") return json({ devices: [] });
        throw new Error("unexpected path " + url);
      }),
    );
    renderPanel(true);
    expect(await screen.findByText("Kaseya VSA, devices and agents")).toBeInTheDocument();
    expect(
      screen.getByText("The VSA organization ID, a number. The organization's agents are listed and matched to this customer's trstctl agents."),
    ).toBeInTheDocument();
  });

  it("names a ConnectWise Automate target and what its company is (MSP-11)", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string) => {
        if (url === "/provider/v1/tenants/alpha/billing-companies")
          return json({ targets: [{ id: "automate", name: "Automate", type: "automate", cadence: "monthly", rmm: true }], companies: [] });
        if (url === "/provider/v1/tenants/alpha/billing-sync") return json({ pushes: [] });
        if (url === "/provider/v1/tenants/alpha/rmm-devices") return json({ devices: [] });
        throw new Error("unexpected path " + url);
      }),
    );
    renderPanel(true);
    expect(await screen.findByText("ConnectWise Automate, devices and agents")).toBeInTheDocument();
    expect(screen.getByText("The Automate client ID, a number. The client's computers are listed and matched to this customer's agents.")).toBeInTheDocument();
  });

  it("lists the customer's certificate records in IT Glue with their state (MSP-14)", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string) => {
        if (url === "/provider/v1/tenants/alpha/billing-companies")
          return json({
            targets: [
              { id: "itglue", name: "IT Glue", type: "itglue", cadence: "monthly", documentation: true },
              { id: "itglue-eu", name: "IT Glue EU", type: "itglue", cadence: "monthly", documentation: true },
            ],
            companies: [{ tenant_id: "alpha", target_id: "itglue", external_company_id: "11" }],
          });
        if (url === "/provider/v1/tenants/alpha/billing-sync") return json({ pushes: [] });
        if (url === "/provider/v1/tenants/alpha/doc-records")
          return json({
            records: [
              {
                target_id: "itglue",
                org_id: "11",
                record_id: "9001",
                certificates: 2,
                next_expiry: "2026-12-03T00:00:00Z",
                status: "synced",
                synced_at: "2026-11-13T09:40:00Z",
                updated_at: "2026-11-13T09:40:00Z",
              },
              {
                target_id: "itglue-eu",
                certificates: 0,
                status: "failed",
                reason: "itglue: POST /flexible_assets answered 422",
                updated_at: "2026-11-13T09:41:00Z",
              },
            ],
          });
        throw new Error("unexpected path " + url);
      }),
    );
    renderPanel(true);
    expect(await screen.findAllByText("IT Glue, certificate records")).toHaveLength(2);
    const table = await screen.findByRole("table", { name: "Certificate records in documentation systems" });
    const rows = within(table).getAllByRole("row");
    expect(rows).toHaveLength(3);
    expect(within(rows[1]).getByText("Record 9001 in organization 11")).toBeInTheDocument();
    expect(within(rows[1]).getByText("2026-12-03")).toBeInTheDocument();
    expect(within(rows[2]).getByText("Not written: itglue: POST /flexible_assets answered 422")).toBeInTheDocument();
  });

  it("installs, upgrades and removes the agent through the RMM with rmm:write (MSP-9)", async () => {
    const actions: { url: string; body: unknown; key: string }[] = [];
    let busy = false;
    const fetcher = vi.fn(async (url: string, init?: RequestInit) => {
      if (url === "/provider/v1/tenants/alpha/billing-companies")
        return json({
          targets: [{ id: "ninja", name: "NinjaOne", type: "ninjaone", cadence: "monthly", rmm: true }],
          companies: [{ tenant_id: "alpha", target_id: "ninja", external_company_id: "11" }],
        });
      if (url === "/provider/v1/tenants/alpha/billing-sync") return json({ pushes: [] });
      if (url === "/provider/v1/tenants/alpha/rmm-devices")
        return json({
          devices: [
            {
              target_id: "ninja",
              device_id: "1001",
              device_name: "ALPHA-DC01",
              present: true,
              agent_id: "a1",
              agent_match: "hostname",
              updated_at: "2026-11-13T00:00:00Z",
            },
            {
              target_id: "ninja",
              device_id: "1003",
              device_name: "ALPHA-NEW01",
              present: true,
              ...(actions.length > 0 ? { action: "install", action_status: "requested" } : {}),
              updated_at: "2026-11-13T00:00:00Z",
            },
            { target_id: "ninja", device_id: "1004", device_name: "ALPHA-OLD01", present: false, updated_at: "2026-11-12T00:00:00Z" },
          ],
        });
      if (url.startsWith("/provider/v1/tenants/alpha/rmm-devices/ninja/") && init?.method === "POST") {
        actions.push({ url, body: JSON.parse(String(init.body)), key: (init.headers as Record<string, string>)["Idempotency-Key"] });
        if (busy) return json({ title: "conflict", detail: "an agent action is still running" }, 409);
        return json(
          { request_event_id: "ev-" + actions.length, action: (JSON.parse(String(init.body)) as { action: string }).action, status: "requested" },
          202,
        );
      }
      throw new Error("unexpected path " + url);
    });
    vi.stubGlobal("fetch", fetcher);
    renderPanel(false, true);
    const table = await screen.findByRole("table", { name: "Devices in the RMM and the customer's agents on them" });
    let rows = within(table).getAllByRole("row");
    expect(within(rows[3]).queryByRole("button")).toBeNull();
    fireEvent.click(within(rows[2]).getByRole("button", { name: "Install agent" }));
    expect(await screen.findByRole("status")).toHaveTextContent("Install requested on ALPHA-NEW01");
    expect(actions[0]).toMatchObject({ url: "/provider/v1/tenants/alpha/rmm-devices/ninja/1003/actions", body: { action: "install" } });
    expect(actions[0].key).toBeTruthy();
    rows = within(table).getAllByRole("row");
    await waitFor(() => expect(within(within(table).getAllByRole("row")[2]).getByRole("button", { name: "Install agent" })).toBeDisabled());

    fireEvent.click(within(rows[1]).getByRole("button", { name: "Remove agent" }));
    expect(within(table).getByText("Remove the trstctl agent from ALPHA-DC01?")).toBeInTheDocument();
    expect(actions).toHaveLength(1);
    fireEvent.click(within(table).getByRole("button", { name: "Cancel" }));
    expect(within(table).queryByText("Remove the trstctl agent from ALPHA-DC01?")).toBeNull();
    busy = true;
    fireEvent.click(within(within(table).getAllByRole("row")[1]).getByRole("button", { name: "Upgrade agent" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("An agent action is still running on ALPHA-DC01");
    busy = false;
    fireEvent.click(within(within(table).getAllByRole("row")[1]).getByRole("button", { name: "Remove agent" }));
    fireEvent.click(within(table).getByRole("button", { name: "Remove agent" }));
    expect(await screen.findByRole("status")).toHaveTextContent("Removal requested on ALPHA-DC01");
    expect(actions.map((a) => (a.body as { action: string }).action)).toEqual(["install", "upgrade", "remove"]);
    expect(new Set(actions.map((a) => a.key)).size).toBe(3);
  });
});
