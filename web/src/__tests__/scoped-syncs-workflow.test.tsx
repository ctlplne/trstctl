import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ScopedSyncsWorkflow } from "@/pages/secrets/ScopedSyncsWorkflow";

const { apiMock, can } = vi.hoisted(() => ({
  apiMock: {
    listSecretScopedSyncs: vi.fn(),
    getSecretScopedSync: vi.fn(),
    defineSecretScopedSync: vi.fn(),
    setSecretScopedSyncMode: vi.fn(),
    previewSecretScopedSync: vi.fn(),
    applySecretScopedSync: vi.fn(),
  },
  can: { value: true },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});
vi.mock("@/components/rbac", () => ({ useCan: () => can.value }));

const sync = {
  id: "s1",
  name: "payments-prod",
  source_prefix: "payments/prod/",
  target: "vault",
  destination_prefix: "payments",
  key_transform: "path",
  delete_scope: "managed",
  adopt_existing: false,
  mode: "manual",
  created_at: "2026-11-02T00:00:00Z",
  updated_at: "2026-11-02T00:00:00Z",
  keys: [{ key: "payments/db/password", state: "synced", job_status: "delivered" }],
};

const plan = {
  sync_id: "s1",
  name: "payments-prod",
  target: "vault",
  plan_digest: "d".repeat(64),
  items: [
    { key: "payments/api/token", source_name: "payments/prod/api/token", source_version: 1, action: "create" },
    { key: "payments/legacy", action: "unmanaged", reason: "not written by this sync; never touched" },
  ],
  changes: 1,
  blocked: 0,
};

describe("A237 scoped syncs", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    can.value = true;
    apiMock.listSecretScopedSyncs.mockResolvedValue({ items: [sync] });
    apiMock.getSecretScopedSync.mockResolvedValue(sync);
  });

  it("previews a value-free plan and applies it by its digest", async () => {
    apiMock.previewSecretScopedSync.mockResolvedValue(plan);
    apiMock.applySecretScopedSync.mockResolvedValue({ sync_id: "s1", plan_digest: plan.plan_digest, writes: [{ key: "payments/api/token" }], deletes: [] });
    const user = userEvent.setup();
    render(<ScopedSyncsWorkflow targets={["vault"]} />);
    await user.click(within(await screen.findByRole("list", { name: "Scoped syncs" })).getByRole("button", { name: "Open" }));
    expect(await screen.findByText("payments/db/password")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Preview the plan" }));
    const items = await screen.findByRole("list", { name: "Plan" });
    expect(within(items).getByText("Not ours — left alone")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Apply this plan" }));
    expect(apiMock.applySecretScopedSync).toHaveBeenCalledWith("s1", { plan_digest: plan.plan_digest });
    expect(await screen.findByText("1 writes and 0 deletes queued.")).toBeInTheDocument();
  });

  it("will not apply a blocked plan", async () => {
    apiMock.previewSecretScopedSync.mockResolvedValue({
      ...plan,
      items: [{ key: "payments/db", action: "blocked", reason: "the destination would hold both payments/db and payments/db/password" }],
      changes: 0,
      blocked: 1,
    });
    const user = userEvent.setup();
    render(<ScopedSyncsWorkflow targets={["vault"]} />);
    await user.click(await screen.findByRole("button", { name: "Open" }));
    await user.click(await screen.findByRole("button", { name: "Preview the plan" }));
    expect(await screen.findByText(/would hold both/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Apply this plan" })).toBeDisabled();
  });

  it("defines an auto sync and switches its mode", async () => {
    apiMock.defineSecretScopedSync.mockResolvedValue({ ...sync, mode: "auto" });
    apiMock.setSecretScopedSyncMode.mockResolvedValue(sync);
    const user = userEvent.setup();
    render(<ScopedSyncsWorkflow targets={["vault"]} />);
    await user.type(await screen.findByRole("textbox", { name: "Name" }), "payments-prod");
    await user.type(screen.getByRole("textbox", { name: "Source prefix" }), "payments/prod/");
    await user.click(screen.getByRole("checkbox"));
    await user.click(screen.getByRole("button", { name: "Define scoped sync" }));
    expect(apiMock.defineSecretScopedSync).toHaveBeenCalledWith({
      name: "payments-prod",
      source_prefix: "payments/prod/",
      target: "vault",
      destination_prefix: undefined,
      delete_scope: "none",
      mode: "auto",
    });
    await user.click(await screen.findByRole("button", { name: "Switch to manual" }));
    expect(apiMock.setSecretScopedSyncMode).toHaveBeenCalledWith("s1", { mode: "manual" });
  });

  it("offers no define, apply or mode switch without secrets:write", async () => {
    can.value = false;
    apiMock.previewSecretScopedSync.mockResolvedValue(plan);
    const user = userEvent.setup();
    render(<ScopedSyncsWorkflow targets={["vault"]} />);
    await user.click(await screen.findByRole("button", { name: "Open" }));
    await user.click(await screen.findByRole("button", { name: "Preview the plan" }));
    await screen.findByRole("list", { name: "Plan" });
    expect(screen.queryByRole("button", { name: "Apply this plan" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Switch to auto" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Define scoped sync" })).not.toBeInTheDocument();
  });
});
