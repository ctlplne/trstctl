import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { SecretProjectTransfers } from "@/pages/secrets/SecretProjectTransfers";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    previewSecretPromotion: vi.fn(),
    applySecretPromotion: vi.fn(),
    previewSecretRestore: vi.fn(),
    applySecretRestore: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});

const project = {
  slug: "orders",
  name: "Orders",
  owner: "unknown",
  created_at: "2026-11-01T00:00:00Z",
  environments: [
    { slug: "dev", restricted: false, access: "open", secrets: [] },
    { slug: "stage", restricted: false, access: "open", secrets: [] },
  ],
};

const promotionPlan = {
  project: "orders",
  from: "dev",
  to: "stage",
  plan_digest: "d".repeat(64),
  items: [
    {
      key: "db/password",
      source_name: "orders/dev/db/password",
      source_version: 2,
      target_name: "orders/stage/db/password",
      target_version: 1,
      action: "update",
    },
    { key: "db/url", source_name: "orders/dev/db/url", source_version: 1, target_name: "orders/stage/db/url", target_version: 0, action: "create" },
  ],
  kept: ["orders/stage/only-in-stage"],
  changes: 2,
  blocked: 0,
};

describe("A236 promote and restore", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("previews a value-free promotion and applies it by its digest", async () => {
    apiMock.previewSecretPromotion.mockResolvedValue(promotionPlan);
    apiMock.applySecretPromotion.mockResolvedValue({ batch_id: "b1", operation: "promotion", plan_digest: promotionPlan.plan_digest, items: [{}, {}] });
    const onApplied = vi.fn();
    const user = userEvent.setup();
    render(<SecretProjectTransfers project={project} onApplied={onApplied} />);
    await user.click(screen.getByRole("button", { name: "Preview the plan" }));
    const plan = await screen.findByRole("list", { name: "Plan" });
    expect(within(plan).getByText("db/url")).toBeInTheDocument();
    expect(within(plan).getByText("Create")).toBeInTheDocument();
    expect(screen.getByText("Left alone in the target: orders/stage/only-in-stage")).toBeInTheDocument();
    expect(apiMock.previewSecretPromotion).toHaveBeenCalledWith("orders", { from: "dev", to: "stage", folder: undefined });
    await user.click(screen.getByRole("button", { name: "Promote these secrets" }));
    expect(apiMock.applySecretPromotion).toHaveBeenCalledWith("orders", {
      from: "dev",
      to: "stage",
      folder: undefined,
      plan_digest: promotionPlan.plan_digest,
    });
    expect(await screen.findByText("2 secrets got a new version.")).toBeInTheDocument();
    expect(onApplied).toHaveBeenCalled();
  });

  it("will not apply a plan with a blocked item and shows why", async () => {
    apiMock.previewSecretPromotion.mockResolvedValue({
      ...promotionPlan,
      items: [{ ...promotionPlan.items[1], action: "blocked", reason: "reference cycle: orders/stage/a → orders/stage/b → orders/stage/a" }],
      changes: 0,
      blocked: 1,
    });
    const user = userEvent.setup();
    render(<SecretProjectTransfers project={project} onApplied={vi.fn()} />);
    await user.click(screen.getByRole("button", { name: "Preview the plan" }));
    expect(await screen.findByText(/reference cycle/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Promote these secrets" })).toBeDisabled();
  });

  it("previews again when the plan went stale", async () => {
    apiMock.previewSecretPromotion.mockResolvedValue(promotionPlan);
    apiMock.applySecretPromotion.mockRejectedValue(new Error("the plan changed since the preview"));
    const user = userEvent.setup();
    render(<SecretProjectTransfers project={project} onApplied={vi.fn()} />);
    await user.click(screen.getByRole("button", { name: "Preview the plan" }));
    await user.click(await screen.findByRole("button", { name: "Promote these secrets" }));
    await screen.findByText("Promote or restore failed");
    expect(apiMock.previewSecretPromotion).toHaveBeenCalledTimes(2);
  });

  it("restores a folder to a point in time", async () => {
    apiMock.previewSecretRestore.mockResolvedValue({
      project: "orders",
      environment: "dev",
      folder: "db",
      at: "2026-11-01T10:00:00Z",
      plan_digest: "e".repeat(64),
      items: [
        { name: "orders/dev/db/password", current_version: 3, restore_version: 1, action: "restore" },
        { name: "orders/dev/db/new", current_version: 1, action: "created_since" },
      ],
      changes: 1,
      blocked: 0,
    });
    apiMock.applySecretRestore.mockResolvedValue({ batch_id: "b2", operation: "restore", plan_digest: "e".repeat(64), items: [{}] });
    const user = userEvent.setup();
    render(<SecretProjectTransfers project={project} onApplied={vi.fn()} />);
    await user.click(screen.getByRole("button", { name: "Restore" }));
    // jsdom sanitizes a datetime-local value typed key by key; set it whole.
    fireEvent.change(screen.getByLabelText("Restore to"), { target: { value: "2026-11-01T10:00:00" } });
    await user.type(screen.getByLabelText("Folder (optional)"), "db");
    await user.click(screen.getByRole("button", { name: "Preview the plan" }));
    expect(await screen.findByText("Created since — kept")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Restore these secrets" }));
    expect(apiMock.applySecretRestore).toHaveBeenCalledWith(
      "orders",
      expect.objectContaining({ environment: "dev", folder: "db", plan_digest: "e".repeat(64) }),
    );
  });
});
