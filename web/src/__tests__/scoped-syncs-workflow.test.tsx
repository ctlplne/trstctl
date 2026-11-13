import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { ScopedSyncsWorkflow } from "@/pages/secrets/ScopedSyncsWorkflow";

const { apiMock, can } = vi.hoisted(() => ({
  apiMock: {
    listSecretScopedSyncs: vi.fn(),
    getSecretScopedSync: vi.fn(),
    defineSecretScopedSync: vi.fn(),
    setSecretScopedSyncMode: vi.fn(),
    replaceSecretScopedSync: vi.fn(),
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
    await user.selectOptions(screen.getByLabelText("Mode"), "auto");
    await user.click(screen.getByRole("button", { name: "Define scoped sync" }));
    expect(apiMock.defineSecretScopedSync).toHaveBeenCalledWith({
      name: "payments-prod",
      source_prefix: "payments/prod/",
      target: "vault",
      destination_prefix: undefined,
      delete_scope: "none",
      mode: "auto",
    });
    await user.selectOptions(await screen.findByLabelText("Change mode"), "manual");
    await user.click(screen.getByRole("button", { name: "Set mode" }));
    expect(apiMock.setSecretScopedSyncMode).toHaveBeenCalledWith("s1", { mode: "manual" });
  });

  // A237-L2: a target that can't list its keys takes a scoped sync only with
  // adopt existing; the define form sends it.
  it("defines a sync that adopts existing keys", async () => {
    apiMock.defineSecretScopedSync.mockResolvedValue({ ...sync, adopt_existing: true });
    const user = userEvent.setup();
    render(<ScopedSyncsWorkflow targets={["ci-hook"]} />);
    await user.type(await screen.findByRole("textbox", { name: "Name" }), "ci-prod");
    await user.type(screen.getByRole("textbox", { name: "Source prefix" }), "ci/prod/");
    await user.click(screen.getByRole("checkbox", { name: /Adopt existing keys/ }));
    await user.click(screen.getByRole("button", { name: "Define scoped sync" }));
    expect(apiMock.defineSecretScopedSync).toHaveBeenCalledWith(expect.objectContaining({ target: "ci-hook", adopt_existing: true, delete_scope: "none" }));
    expect(screen.getByRole("checkbox", { name: /Adopt existing keys/ })).not.toBeChecked();
  });

  // A237-L1: an approval-gated sync names the request its plan waits for,
  // from the reconciler's reason and from a refused apply, and links the
  // approval queue.
  it("names the approval an approval-gated plan waits for", async () => {
    const waiting = {
      ...sync,
      mode: "approved",
      reconcile_status: "awaiting_approval",
      reconcile_reason: "1 changes await approval request 11111111-2222-4333-8444-555555555555",
      last_reconcile_at: "2026-11-12T00:00:00Z",
    };
    apiMock.getSecretScopedSync.mockResolvedValue(waiting);
    apiMock.previewSecretScopedSync.mockResolvedValue(plan);
    apiMock.applySecretScopedSync.mockRejectedValue(
      new Error(
        "dual control: approval_required:s1 request_id=66666666-7777-4888-8999-000000000000 intent_digest=sha256:" +
          "b".repeat(64) +
          ": approval request awaits 2 distinct approval(s)",
      ),
    );
    const user = userEvent.setup();
    render(
      <MemoryRouter>
        <ScopedSyncsWorkflow targets={["vault"]} />
      </MemoryRouter>,
    );
    await user.click(await screen.findByRole("button", { name: "Open" }));
    expect(await screen.findByText("Mode: Approval-gated")).toBeInTheDocument();
    const fromReconcile = await screen.findByText(/waits for its approvers: request 11111111-2222-4333-8444-555555555555/);
    expect(within(fromReconcile).getByRole("link", { name: "Open Approvals" })).toHaveAttribute("href", "/approvals");
    await user.click(screen.getByRole("button", { name: "Preview the plan" }));
    await user.click(await screen.findByRole("button", { name: "Apply this plan" }));
    expect(await screen.findByText(/waits for its approvers: request 66666666-7777-4888-8999-000000000000/)).toBeInTheDocument();
    expect(apiMock.previewSecretScopedSync).toHaveBeenCalledTimes(1);
  });

  // A237-L3: a definition is replaced in place from the edit form, which
  // says what moving the destination does to the keys it manages.
  it("replaces a definition in place", async () => {
    apiMock.replaceSecretScopedSync.mockResolvedValue({ ...sync, destination_prefix: "pay" });
    const user = userEvent.setup();
    render(<ScopedSyncsWorkflow targets={["vault"]} />);
    await user.click(await screen.findByRole("button", { name: "Open" }));
    await user.click(await screen.findByRole("button", { name: "Edit definition" }));
    const form = within(screen.getByRole("form", { name: "Replace this definition" }));
    expect(form.getByText("Moving the destination releases the keys this sync manages there; they stay where they are.")).toBeInTheDocument();
    const destination = form.getByRole("textbox", { name: "Destination prefix (optional)" });
    await user.clear(destination);
    await user.type(destination, "pay");
    await user.click(form.getByRole("button", { name: "Save definition" }));
    expect(apiMock.replaceSecretScopedSync).toHaveBeenCalledWith("s1", {
      name: "payments-prod",
      source_prefix: "payments/prod/",
      target: "vault",
      destination_prefix: "pay",
      key_transform: "path",
      delete_scope: "managed",
      adopt_existing: false,
      reconcile_interval: "0s",
    });
    expect(screen.queryByRole("form", { name: "Replace this definition" })).not.toBeInTheDocument();
  });

  // A237-L7: a sync sets its own drift-check interval at definition, and its
  // view names it.
  it("defines a sync with its own drift-check interval and shows it", async () => {
    apiMock.defineSecretScopedSync.mockResolvedValue({ ...sync, mode: "auto", reconcile_interval: "1h0m0s" });
    const user = userEvent.setup();
    render(<ScopedSyncsWorkflow targets={["vault"]} />);
    await user.type(await screen.findByRole("textbox", { name: "Name" }), "payments-prod");
    await user.type(screen.getByRole("textbox", { name: "Source prefix" }), "payments/prod/");
    await user.selectOptions(screen.getByLabelText("Mode"), "auto");
    await user.selectOptions(screen.getAllByLabelText("Drift check")[0], "1h0m0s");
    await user.click(screen.getByRole("button", { name: "Define scoped sync" }));
    expect(apiMock.defineSecretScopedSync).toHaveBeenCalledWith(expect.objectContaining({ mode: "auto", reconcile_interval: "1h0m0s" }));
    expect(await screen.findByText("Drift check: Every hour.")).toBeInTheDocument();
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
    expect(screen.queryByRole("button", { name: "Set mode" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Edit definition" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Define scoped sync" })).not.toBeInTheDocument();
  });
});
