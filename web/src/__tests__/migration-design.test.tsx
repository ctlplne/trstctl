import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
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

vi.mock("@/lib/api", async (original) => {
  const actual = await original<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});

function renderMigration() {
  return render(
    <AppQueryProvider>
      <Migration />
    </AppQueryProvider>,
  );
}

describe("route 028 decision-first migration design", () => {
  beforeEach(() => {
    for (const mock of Object.values(apiMock)) mock.mockReset();
    apiMock.migrationRuns.mockResolvedValue({ items: [] });
  });

  it("answers cutover readiness before revealing source mappings and controls", async () => {
    const user = userEvent.setup();
    renderMigration();

    expect(await screen.findByRole("heading", { level: 1, name: "Move to trstctl" })).toBeInTheDocument();
    expect(screen.getByText("What can move now, what blocks cutover, and how to roll back.", { exact: true })).toBeInTheDocument();
    const operate = screen.getByTestId("page-depth-operate");
    expect(within(operate).getAllByRole("button")).toHaveLength(1);
    const startPlan = within(operate).getByRole("button", { name: "Start migration plan" });

    expect(await screen.findByRole("heading", { level: 2, name: "No migration runs yet" })).toBeInTheDocument();
    expect(screen.getByText("Create and check a plan before trstctl changes any trust.", { exact: true })).toBeInTheDocument();
    const plan = screen.getByText("Plan details and source mappings", { exact: true }).closest("details");
    const gates = screen.getByText("Assessment, dual-run evidence, and cutover gates", { exact: true }).closest("details");
    const history = screen.getByText("Run history, wave evidence, and rollback controls", { exact: true }).closest("details");
    expect(plan).not.toHaveAttribute("open");
    expect(gates).not.toHaveAttribute("open");
    expect(history).not.toHaveAttribute("open");
    expect(screen.queryByLabelText("Migration plan JSON")).not.toBeInTheDocument();

    await user.click(startPlan);
    const manifest = await screen.findByLabelText("Migration plan JSON");
    expect(plan).toHaveAttribute("open");
    expect(manifest).toHaveFocus();
  });

  it("rejects incomplete mappings locally and invalidates an assessment when its plan changes", async () => {
    const user = userEvent.setup();
    apiMock.assessMigration.mockResolvedValue({
      plan_id: "safe-cutover",
      members: 1,
      migratable: 1,
      guidance: "Every required fact was observed.",
      unknowns: [],
      waves: [{ id: "canary", ordinal: 1, members: ["identity-1"] }],
    });
    renderMigration();

    await user.click(await screen.findByRole("button", { name: "Start migration plan" }));
    await user.click(screen.getByRole("button", { name: "Check cutover readiness" }));
    expect(await screen.findByText(/This plan is incomplete or is not valid JSON/)).toBeInTheDocument();
    expect(apiMock.assessMigration).not.toHaveBeenCalled();

    const complete = {
      plan_id: "safe-cutover",
      new_authority_id: "40400000-0000-4000-8000-000000000042",
      waves: [
        {
          id: "canary",
          ordinal: 1,
          members: [{ identity_id: "identity-1", agent_id: "agent-1", trust_anchor_path: "/etc/trstctl/next-root.pem" }],
        },
      ],
    };
    const editor = screen.getByLabelText("Migration plan JSON");
    fireEvent.change(editor, { target: { value: JSON.stringify(complete) } });
    await user.click(screen.getByRole("button", { name: "Check cutover readiness" }));
    expect(await screen.findByRole("button", { name: "Start migration" })).toBeInTheDocument();

    await user.type(editor, " ");
    expect(screen.queryByRole("button", { name: "Start migration" })).not.toBeInTheDocument();
  });

  it("blocks start when the assessment does not bind to the exact reviewed plan", async () => {
    const user = userEvent.setup();
    apiMock.assessMigration.mockResolvedValue({
      plan_id: "different-plan",
      members: 1,
      migratable: 1,
      guidance: "Counts alone are not plan identity.",
      unknowns: [],
      waves: [{ id: "canary", ordinal: 1, members: ["identity-1"] }],
    });
    renderMigration();

    await user.click(await screen.findByRole("button", { name: "Start migration plan" }));
    fireEvent.change(screen.getByLabelText("Migration plan JSON"), {
      target: {
        value: JSON.stringify({
          plan_id: "reviewed-plan",
          new_authority_id: "40400000-0000-4000-8000-000000000042",
          waves: [
            {
              id: "canary",
              ordinal: 1,
              members: [{ identity_id: "identity-1", agent_id: "agent-1", trust_anchor_path: "/etc/trstctl/next-root.pem" }],
            },
          ],
        }),
      },
    });
    await user.click(screen.getByRole("button", { name: "Check cutover readiness" }));

    expect(await screen.findByText(/does not match the plan, waves, and identities/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Start migration" })).not.toBeInTheDocument();
    expect(apiMock.startMigrationRun).not.toHaveBeenCalled();
  });
});
