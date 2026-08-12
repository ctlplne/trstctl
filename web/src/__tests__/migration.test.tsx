import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import { AppQueryProvider } from "@/lib/query";
import { Migration } from "@/pages/Migration";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    assessMigration: vi.fn(),
    startMigrationRun: vi.fn(),
    migrationRuns: vi.fn(),
    pauseMigrationRun: vi.fn(),
    resumeMigrationRun: vi.fn(),
    rollbackMigrationRun: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});

const existingRun = {
  id: "40400000-0000-4000-8000-000000000040",
  plan_id: "existing-rollover",
  status: "running" as const,
  waves: [
    {
      id: "canary",
      ordinal: 1,
      phase: "verifying_live",
      started: true,
      members: [
        { identity_id: "identity-a", binding: {}, trust_verdict: "verified", successor_verdict: "verified" },
        { identity_id: "identity-b", binding: {}, trust_verdict: "verified" },
      ],
    },
  ],
};

const manifest = {
  plan_id: "new-rollover",
  new_authority_id: "40400000-0000-4000-8000-000000000042",
  waves: [
    {
      id: "canary",
      ordinal: 1,
      members: [
        {
          identity_id: "identity-1",
          agent_id: "40400000-0000-4000-8000-000000000041",
          trust_anchor_path: "/etc/trstctl/next-root.pem",
        },
      ],
    },
  ],
};

function renderMigration() {
  return render(
    <AppQueryProvider>
      <Migration />
    </AppQueryProvider>,
  );
}

describe("executable CA migration console (AUD-40)", () => {
  beforeEach(() => {
    for (const mock of Object.values(apiMock)) mock.mockReset();
    apiMock.migrationRuns.mockResolvedValue({ items: [existingRun] });
    apiMock.assessMigration.mockResolvedValue({
      plan_id: manifest.plan_id,
      members: 1,
      migratable: 1,
      guidance: "All members have the required observed facts.",
      unknowns: [],
      waves: [{ id: "canary", ordinal: 1, members: ["identity-1"] }],
    });
    apiMock.startMigrationRun.mockResolvedValue({ ...existingRun, id: "run-new", plan_id: manifest.plan_id });
    apiMock.pauseMigrationRun.mockResolvedValue({ ...existingRun, status: "paused" });
    apiMock.resumeMigrationRun.mockResolvedValue(existingRun);
    apiMock.rollbackMigrationRun.mockResolvedValue({ ...existingRun, status: "rolling_back" });
  });

  it("assesses, reviews, and starts only the validated manifest", async () => {
    const user = userEvent.setup();
    const { container } = renderMigration();
    expect(await screen.findByText("existing-rollover")).toBeInTheDocument();
    expect(screen.getByText("canary").closest("li")).toHaveTextContent("verifying_live · 2 · 75% (3/4)");
    expect(screen.getByText("identity-a, identity-b")).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText("Migration plan"), { target: { value: JSON.stringify(manifest) } });
    await user.click(screen.getByRole("button", { name: "Assess plan" }));
    expect(await screen.findByText("Migratable: 1/1 members.")).toBeInTheDocument();
    expect(screen.getByText(manifest.new_authority_id)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Start migration" }));

    await waitFor(() => expect(apiMock.startMigrationRun).toHaveBeenCalledWith(manifest));
    expect(await axe(container)).toHaveNoViolations();
  });

  it("wires pause and rollback controls to the durable run", async () => {
    const user = userEvent.setup();
    renderMigration();
    expect(await screen.findByText("existing-rollover")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: `Pause fleet run ${existingRun.plan_id}` }));
    await waitFor(() => expect(apiMock.pauseMigrationRun).toHaveBeenCalledWith(existingRun.id));
    await user.click(screen.getByRole("button", { name: "Rollback" }));
    await waitFor(() => expect(apiMock.rollbackMigrationRun).toHaveBeenCalledWith(existingRun.id));
  });
});
