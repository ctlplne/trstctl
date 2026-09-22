import { act, cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { I18nProvider } from "@/i18n/I18nProvider";
import { ManagedTenantProvisioning } from "@/pages/platform/ManagedTenantProvisioning";
import { api, type ManagedTenant, type Me } from "@/lib/api";
import { ApiError } from "@/lib/apiTransport";
import {
  completeManagedTenantAttempt,
  listManagedTenantAttempts,
  ManagedTenantRecoveryError,
  prepareManagedTenantAttempt,
  type ManagedTenantAttempt,
} from "@/lib/managedTenantAttempts";

const auth = vi.hoisted(() => ({ user: null as Me | null, preview: false }));
vi.mock("@/auth/AuthProvider", () => ({ useAuth: () => auth }));
vi.mock("@/lib/api", () => ({ api: { provisionManagedTenant: vi.fn() } }));
vi.mock("@/lib/managedTenantAttempts", async (original) => ({
  ...(await original<typeof import("@/lib/managedTenantAttempts")>()),
  prepareManagedTenantAttempt: vi.fn(),
  listManagedTenantAttempts: vi.fn(),
  completeManagedTenantAttempt: vi.fn(),
}));

const alpha: Me = {
  tenant_id: "11111111-1111-4111-8111-111111111111",
  subject: "alpha-admin",
  email: "alpha@example.test",
  roles: ["admin"],
  permissions: ["*"],
};
const request = { tenant_id: "33333333-3333-4333-8333-333333333333", name: "Saved customer", region: "US" };
const principal = { tenantId: alpha.tenant_id, subject: alpha.subject };
const saved: ManagedTenantAttempt = {
  version: 1,
  principal: JSON.stringify([alpha.tenant_id, alpha.subject]),
  scope: JSON.stringify([JSON.stringify([alpha.tenant_id, alpha.subject]), request.tenant_id]),
  key: "44444444-4444-4444-8444-444444444444",
  createdAt: "2026-09-22T02:00:00Z",
  request,
};
const receipt: ManagedTenant = {
  tenant_id: request.tenant_id,
  name: request.name,
  managed: true,
  deployment_model: "managed_provider",
  provider_tenant_id: alpha.tenant_id,
  region: "US",
  provisioned_by: alpha.subject,
  created_at: saved.createdAt,
  event_sequence: 42,
};
let retained: ManagedTenantAttempt[];
function view(enabled = true) {
  return (
    <I18nProvider>
      <ManagedTenantProvisioning enabled={enabled} />
    </I18nProvider>
  );
}
async function openSaved() {
  await userEvent.click(await screen.findByRole("button", { name: "Review request for Saved customer" }));
  return screen.getByRole("button", { name: "Retry unchanged request" });
}
function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}
beforeEach(() => {
  vi.resetAllMocks();
  auth.user = alpha;
  auth.preview = false;
  retained = [saved];
  vi.mocked(listManagedTenantAttempts).mockImplementation(async (owner) =>
    owner.tenantId === alpha.tenant_id && owner.subject === alpha.subject ? retained : [],
  );
  vi.mocked(prepareManagedTenantAttempt).mockResolvedValue(saved);
  vi.mocked(completeManagedTenantAttempt).mockImplementation(async () => {
    retained = [];
  });
  vi.mocked(api.provisionManagedTenant).mockResolvedValue(receipt);
});
afterEach(cleanup);

describe("managed customer provisioning recovery", () => {
  it("reviews a saved request without mutation and reuses its original key on retry", async () => {
    render(view());
    const retry = await openSaved();
    expect(screen.getByText(request.tenant_id)).toBeInTheDocument();
    expect(api.provisionManagedTenant).not.toHaveBeenCalled();
    await userEvent.click(retry);
    expect(await screen.findByText("Created customer tenant Saved customer.")).toBeInTheDocument();
    expect(prepareManagedTenantAttempt).toHaveBeenCalledWith(principal, request);
    expect(api.provisionManagedTenant).toHaveBeenCalledWith(request, saved.key, { tenant_id: alpha.tenant_id, subject: alpha.subject });
    expect(completeManagedTenantAttempt).toHaveBeenCalledWith(principal, saved);
  });

  it("retains the request after a lost response and recovers after remount", async () => {
    vi.mocked(api.provisionManagedTenant).mockRejectedValueOnce(new TypeError("response lost"));
    const mounted = render(view());
    await userEvent.click(await openSaved());
    expect(await screen.findByRole("alert")).toHaveTextContent("The result could not be confirmed");
    expect(completeManagedTenantAttempt).not.toHaveBeenCalled();
    mounted.unmount();
    render(view());
    await userEvent.click(await openSaved());
    expect(await screen.findByText("Created customer tenant Saved customer.")).toBeInTheDocument();
    expect(vi.mocked(api.provisionManagedTenant).mock.calls).toEqual([
      [request, saved.key, { tenant_id: alpha.tenant_id, subject: alpha.subject }],
      [request, saved.key, { tenant_id: alpha.tenant_id, subject: alpha.subject }],
    ]);
  });

  it("refuses network mutation if the recovery intent cannot be stored", async () => {
    vi.mocked(prepareManagedTenantAttempt).mockRejectedValue(new ManagedTenantRecoveryError("storage_unavailable"));
    render(view());
    await userEvent.click(await openSaved());
    expect(await screen.findByRole("alert")).toHaveTextContent("Allow site storage");
    expect(api.provisionManagedTenant).not.toHaveBeenCalled();
  });

  it("keeps the record if the server receipt belongs to another customer", async () => {
    vi.mocked(api.provisionManagedTenant).mockResolvedValue({ ...receipt, tenant_id: "55555555-5555-4555-8555-555555555555" });
    render(view());
    await userEvent.click(await openSaved());
    expect(await screen.findByRole("alert")).toHaveTextContent("did not match the saved customer request");
    expect(completeManagedTenantAttempt).not.toHaveBeenCalled();
    expect(screen.queryByText("Created customer tenant Saved customer.")).not.toBeInTheDocument();
  });

  it("preserves the server refusal and its recovery guidance", async () => {
    vi.mocked(api.provisionManagedTenant).mockRejectedValue(new ApiError(403, JSON.stringify({ detail: "Provider license required" })));
    render(view());
    await userEvent.click(await openSaved());
    expect(await screen.findByRole("alert")).toHaveTextContent("Provider license required");
    expect(screen.getByRole("alert")).toHaveTextContent("retry it unchanged");
    expect(completeManagedTenantAttempt).not.toHaveBeenCalled();
  });

  it("keeps verified success visible when local cleanup fails", async () => {
    vi.mocked(completeManagedTenantAttempt).mockRejectedValue(new ManagedTenantRecoveryError("storage_unavailable"));
    render(view());
    await userEvent.click(await openSaved());
    expect(await screen.findByText("Created customer tenant Saved customer.")).toBeInTheDocument();
    expect(await screen.findByRole("alert")).toHaveTextContent("could not clear its recovery record");
    expect(await screen.findByRole("button", { name: "Review request for Saved customer" })).toBeInTheDocument();
  });

  it("does not send a prepared request after the authenticated account changes", async () => {
    const preparing = deferred<ManagedTenantAttempt>();
    vi.mocked(prepareManagedTenantAttempt).mockReturnValue(preparing.promise);
    const mounted = render(view());
    await userEvent.click(await openSaved());
    await waitFor(() => expect(prepareManagedTenantAttempt).toHaveBeenCalledOnce());
    auth.user = { ...alpha, subject: "beta-admin" };
    mounted.rerender(view());
    await act(async () => {
      preparing.resolve(saved);
      await preparing.promise;
    });
    expect(api.provisionManagedTenant).not.toHaveBeenCalled();
    expect(screen.queryByText("Saved customer")).not.toBeInTheDocument();
  });

  it("does not show an old account's late success or remove its saved record", async () => {
    const sending = deferred<ManagedTenant>();
    vi.mocked(api.provisionManagedTenant).mockReturnValue(sending.promise);
    const mounted = render(view());
    await userEvent.click(await openSaved());
    await waitFor(() => expect(api.provisionManagedTenant).toHaveBeenCalledOnce());
    auth.user = { ...alpha, tenant_id: "22222222-2222-4222-8222-222222222222", subject: "beta-admin" };
    mounted.rerender(view());
    await act(async () => {
      sending.resolve(receipt);
      await sending.promise;
    });
    expect(screen.queryByText("Created customer tenant Saved customer.")).not.toBeInTheDocument();
    expect(completeManagedTenantAttempt).not.toHaveBeenCalled();
    expect(retained).toEqual([saved]);
  });

  it("disables retry without the licensed capability", async () => {
    render(view(false));
    expect(await openSaved()).toBeDisabled();
    expect(api.provisionManagedTenant).not.toHaveBeenCalled();
  });

  it("does not access live recovery records or mutations in preview", async () => {
    auth.preview = true;
    render(view());
    expect(await screen.findByText("Sign in to provision a customer tenant.")).toBeInTheDocument();
    expect(listManagedTenantAttempts).not.toHaveBeenCalled();
    expect(api.provisionManagedTenant).not.toHaveBeenCalled();
  });
});
