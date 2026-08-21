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
        {
          identity_id: "identity-a",
          binding: {
            connector: "kubernetes",
            target: "payments/api",
            predecessor_fingerprint: "SHA256:CURRENT-A",
            successor_fingerprint: "SHA256:NEXT-A",
          },
          trust_verdict: "verified",
          successor_verdict: "verified",
          rollback_trust_verdict: "verified",
          rollback_successor_verdict: "verified",
        },
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
    expect(await screen.findByRole("heading", { name: "1 migration run" })).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Start migration plan" }));
    fireEvent.change(screen.getByLabelText("Migration plan JSON"), { target: { value: JSON.stringify(manifest) } });
    await user.click(screen.getByRole("button", { name: "Check cutover readiness" }));

    expect(await screen.findByText("Ready to move: 1 of 1 identities.")).toBeInTheDocument();
    expect(screen.getByText(manifest.new_authority_id)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Start migration" }));

    await waitFor(() => expect(apiMock.startMigrationRun).toHaveBeenCalledWith(manifest));
    expect(await axe(container)).toHaveNoViolations();
  });

  it("wires pause and rollback controls to the durable run", async () => {
    const user = userEvent.setup();
    renderMigration();
    expect(await screen.findByRole("heading", { name: "1 migration run" })).toBeInTheDocument();
    await user.click(screen.getByText("Run history, wave evidence, and rollback controls"));

    expect(await screen.findByText("existing-rollover")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "canary · verifying_live" }).closest("li")).toHaveTextContent("2 members · 75% verified (3/4 trust checks)");
    expect(screen.getByText("kubernetes → payments/api")).toBeInTheDocument();
    expect(screen.getByText("SHA256:CURRENT-A")).toBeInTheDocument();
    expect(screen.getByText("SHA256:NEXT-A")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Pause run" }));
    await waitFor(() => expect(apiMock.pauseMigrationRun).toHaveBeenCalledWith(existingRun.id));
    await user.click(screen.getByRole("button", { name: "Review rollback" }));
    const confirmation = screen.getByRole("alertdialog", { name: "Roll back existing-rollover?" });
    expect(confirmation).toHaveTextContent("server-owned rollback path");
    expect(apiMock.rollbackMigrationRun).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "Roll back run" }));
    await waitFor(() => expect(apiMock.rollbackMigrationRun).toHaveBeenCalledWith(existingRun.id));
  });
});
