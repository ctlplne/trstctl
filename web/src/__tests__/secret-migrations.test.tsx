import { describe, expect, it, vi } from "vitest";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { SecretProjectMigrations } from "@/pages/secrets/SecretProjectMigrations";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    listSecretMigrations: vi.fn(),
    getSecretMigration: vi.fn(),
    assessSecretMigration: vi.fn(),
    stageSecretMigration: vi.fn(),
    applySecretMigrationPermissions: vi.fn(),
    cutOverSecretMigration: vi.fn(),
    reissueSecretMigrationCredentials: vi.fn(),
    rollBackSecretMigration: vi.fn(),
  },
}));
vi.mock("@/lib/api", () => ({ api: apiMock }));

const plan = {
  project: "payments",
  counts: { import: 2, reissue: 1, blocked: 1, unsupported: 0, permissions_translated: 1, permissions_held: 1 },
  environments: [{ name: "production", open: false, open_accepted: false }],
  objects: [
    { name: "payments/production/api/DB_HOST", action: "import", existing_version: 1 },
    { name: "payments/production/api/DB_URL", action: "import", existing_version: 0, references: ["payments/production/api/DB_HOST"] },
    { name: "payments/production/api/SIGNING_KEY", action: "reissue", existing_version: 0, reason: "the export could not carry this credential" },
    { name: "payments/production/api/GREETING", action: "blocked", existing_version: 0, reason: "a reference in its value names a secret that is not there" },
  ],
  unsupported: [],
  permissions: [
    { subject: "orders-api", access: "read", environment: "production", status: "translated", role: "viewer" },
    { subject: "billing", access: "read", environment: "production", folder: "api", status: "held", reason: "the store grants whole environments" },
  ],
  consumers: [],
};

function run(state: string, objects: object[] = []) {
  return {
    id: "run-1",
    project: "payments",
    state,
    digest: "d".repeat(64),
    plan,
    accepted_open: [],
    created_at: "2026-11-03T00:00:00Z",
    permissions_applied: [],
    objects,
    consumers: [{ name: "orders", subject: "orders-api", secrets: ["payments/production/api/DB_URL"], read: [], pending: ["payments/production/api/DB_URL"] }],
  };
}

describe("secret migration panel (A243)", () => {
  it("assesses without values, stages by the digest and offers cutover, reissue and rollback", async () => {
    apiMock.listSecretMigrations.mockResolvedValue({ items: [] });
    apiMock.assessSecretMigration.mockResolvedValue(run("assessed"));
    apiMock.stageSecretMigration.mockResolvedValue(
      run("staged", [{ name: "payments/production/api/DB_HOST", outcome: "migrated", prior_version: 1, version: 2, writer: "source" }]),
    );
    const user = userEvent.setup();
    render(
      <SecretProjectMigrations
        project={{ slug: "payments", environments: [{ slug: "production", restricted: true, access: "member", secrets: [] }] } as never}
      />,
    );

    await user.type(screen.getByRole("textbox", { name: "Exported file" }), "DB_HOST=db.prod.internal");
    await user.click(screen.getByRole("button", { name: "Assess" }));
    expect(apiMock.assessSecretMigration).toHaveBeenCalledWith(
      expect.objectContaining({
        project: "payments",
        sources: [{ environment: "production", folder: undefined, format: "dotenv", content: "DB_HOST=db.prod.internal" }],
      }),
    );
    expect(await screen.findByText("assessed: 2 to import, 1 to reissue, 1 blocked, 0 unsupported, 1 permissions held for review")).toBeInTheDocument();
    expect(screen.getByText("a reference in its value names a secret that is not there")).toBeInTheDocument();
    expect(screen.getByText("orders-api · read · production → translated")).toBeInTheDocument();
    expect(screen.getByText("billing · read · production/api → held")).toBeInTheDocument();
    // The export stays in its own field; the plan never shows a value.
    expect(within(screen.getByLabelText("Migration plan")).queryByText(/db\.prod\.internal/)).not.toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Stage" }));
    expect(apiMock.stageSecretMigration).toHaveBeenCalledWith("run-1", expect.objectContaining({ plan_digest: "d".repeat(64) }));
    const table = await screen.findByRole("table");
    expect(within(table).getByText("source · v2")).toBeInTheDocument();
    expect(screen.getByText("orders: read 0 of 1")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Cut over" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Reissue 1 credentials" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Roll back" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Apply translated permissions" })).toBeInTheDocument();
  });
});
