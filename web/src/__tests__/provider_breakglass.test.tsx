// SPDX-License-Identifier: BUSL-1.1

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { IntlProvider } from "@/i18n/I18nProvider";
import { AppQueryProvider } from "@/lib/query";
import { clearProviderToken, setProviderToken } from "@/lib/providerApi";
import { ProviderBreakGlassPanel } from "@/pages/provider/ProviderBreakGlassPanel";

const customer = "alpha";
const grant = {
  id: "grant-1",
  tenant_id: customer,
  operator_id: "requester",
  operator_email: "requester@local.qa",
  reason: "Incident diagnosis for Alpha",
  requested_at: "2026-10-05T14:00:00Z",
  expires_at: "2026-10-05T14:15:00Z",
  use_count: 0,
  state: "pending",
};
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });

function renderPanel(operatorId: string, canWrite = true) {
  return render(
    <IntlProvider initialLocale="en-US" initialTimeZone="UTC">
      <AppQueryProvider>
        <ProviderBreakGlassPanel
          customerId={customer}
          customerName="Alpha customer"
          operatorId={operatorId}
          canWrite={canWrite}
          onAuthError={vi.fn()}
          onClose={vi.fn()}
        />
      </AppQueryProvider>
    </IntlProvider>,
  );
}

describe("Provider exact-customer emergency console", () => {
  beforeEach(() => setProviderToken("signed-lab-operator"));
  afterEach(() => {
    clearProviderToken();
    vi.unstubAllGlobals();
  });

  it("lets a requester create a bounded request without offering self-approval", async () => {
    const fetcher = vi.fn(async (url: string, init?: RequestInit) => {
      if (url.startsWith("/provider/v1/tenants/alpha/breakglass?")) return json({ items: [grant] });
      if (url === "/provider/v1/breakglass" && init?.method === "POST") return json(grant, 201);
      throw new Error("unexpected path " + url);
    });
    vi.stubGlobal("fetch", fetcher);
    renderPanel("requester");
    const row = await screen.findByRole("article", { name: "grant-1" });
    expect(within(row).queryByRole("button", { name: "Approve" })).not.toBeInTheDocument();
    expect(within(row).getByRole("button", { name: "Withdraw request" })).toBeInTheDocument();
    fireEvent.change(screen.getByRole("textbox", { name: "Incident reason" }), { target: { value: "Incident diagnosis for Alpha" } });
    fireEvent.change(screen.getByRole("combobox", { name: "Access duration" }), { target: { value: "30m" } });
    fireEvent.click(screen.getByRole("button", { name: "Request emergency access" }));
    await waitFor(() => expect(fetcher).toHaveBeenCalledWith("/provider/v1/breakglass", expect.objectContaining({ method: "POST" })));
    const call = fetcher.mock.calls.find(([url]) => url === "/provider/v1/breakglass")!;
    expect(JSON.parse(String(call[1]?.body))).toEqual({ tenant_id: customer, reason: "Incident diagnosis for Alpha", ttl: "30m" });
    expect((call[1]?.headers as Record<string, string>)["Idempotency-Key"]).toBeTruthy();
  });

  it("offers consent only to a distinct approver and uses the selected customer", async () => {
    const awaiting = { ...grant, state: "awaiting_co_consent", consented_by: "approver-a", consented_at: "2026-10-05T14:01:00Z" };
    const fetcher = vi.fn(async (url: string, init?: RequestInit) => {
      if (url.startsWith("/provider/v1/tenants/alpha/breakglass?")) return json({ items: [awaiting] });
      if (url === "/provider/v1/breakglass/grant-1/consent" && init?.method === "POST") return json({ ...awaiting, second_consented_by: "approver-b" });
      throw new Error("unexpected path " + url);
    });
    vi.stubGlobal("fetch", fetcher);
    const first = renderPanel("approver-a");
    const ownRow = await screen.findByRole("article", { name: "grant-1" });
    expect(within(ownRow).queryByRole("button", { name: "Approve" })).not.toBeInTheDocument();
    first.unmount();
    renderPanel("approver-b");
    const row = await screen.findByRole("article", { name: "grant-1" });
    fireEvent.click(within(row).getByRole("button", { name: "Approve" }));
    await waitFor(() => expect(fetcher).toHaveBeenCalledWith("/provider/v1/breakglass/grant-1/consent", expect.objectContaining({ method: "POST" })));
    const call = fetcher.mock.calls.find(([url, init]) => url === "/provider/v1/breakglass/grant-1/consent" && init?.method === "POST")!;
    expect(JSON.parse(String(call[1]?.body))).toEqual({ tenant_id: customer, approve: true });
  });

  it("shows the narrow result only to the requester after two approvals", async () => {
    const active = { ...grant, state: "active", consented_by: "approver-a", second_consented_by: "approver-b" };
    const fetcher = vi.fn(async (url: string, init?: RequestInit) => {
      if (url.startsWith("/provider/v1/tenants/alpha/breakglass?")) return json({ items: [active] });
      if (url === "/provider/v1/breakglass/grant-1/results" && init?.method === "POST")
        return json({ tenant_id: customer, health: "healthy", active_certificates: 2, workspace_initialized: true });
      throw new Error("unexpected path " + url);
    });
    vi.stubGlobal("fetch", fetcher);
    const approver = renderPanel("approver-a");
    await screen.findByRole("article", { name: "grant-1" });
    expect(screen.queryByRole("button", { name: "View authorized result" })).not.toBeInTheDocument();
    approver.unmount();
    renderPanel("requester");
    const row = await screen.findByRole("article", { name: "grant-1" });
    fireEvent.click(within(row).getByRole("button", { name: "View authorized result" }));
    expect(await screen.findByText("Active certificates: 2")).toBeInTheDocument();
    expect(screen.getByText("Health: healthy")).toBeInTheDocument();
  });

  it("shows the queue but no emergency mutation in license read-only mode", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string) => {
        if (url.startsWith("/provider/v1/tenants/alpha/breakglass?")) return json({ items: [grant] });
        throw new Error("unexpected path " + url);
      }),
    );
    renderPanel("requester", false);
    expect(await screen.findByRole("article", { name: "grant-1" })).toBeInTheDocument();
    for (const name of ["Request emergency access", "Withdraw request", "View authorized result", "Approve", "Deny"]) {
      expect(screen.queryByRole("button", { name })).not.toBeInTheDocument();
    }
  });
});
