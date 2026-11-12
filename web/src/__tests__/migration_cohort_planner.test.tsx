import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { AppQueryProvider } from "@/lib/query";
import { Migration } from "@/pages/Migration";

const authorityID = "40400000-0000-4000-8000-000000000042";
const webA = "40400000-0000-4000-8000-0000000031a1";
const webB = "40400000-0000-4000-8000-0000000031a2";
const agentID = "40400000-0000-4000-8000-000000000044";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    assessMigration: vi.fn(),
    migrationCohortPlan: vi.fn(),
    startMigrationRun: vi.fn(),
    migrationRuns: vi.fn(),
    pauseMigrationRun: vi.fn(),
    resumeMigrationRun: vi.fn(),
    rollbackMigrationRun: vi.fn(),
    caAuthorities: vi.fn(),
    identities: vi.fn(),
    agents: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (original) => {
  const actual = await original<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});

// P3-L1: the plan editor builds canary-first cohorts from a profile (or an
// issuer), shows what it placed and skipped, and fills the waves only when
// the operator uses them; the plan then goes through review and assessment.
describe("migration cohort planner", () => {
  beforeEach(() => {
    for (const mock of Object.values(apiMock)) mock.mockReset();
    apiMock.migrationRuns.mockResolvedValue({ items: [] });
    apiMock.caAuthorities.mockResolvedValue({ items: [{ id: authorityID, common_name: "QA new CA", status: "active" }] });
    apiMock.identities.mockResolvedValue([
      { id: webA, name: "web-a.p3l1.test", kind: "x509_certificate", status: "deployed" },
      { id: webB, name: "web-b.p3l1.test", kind: "x509_certificate", status: "deployed" },
    ]);
    apiMock.agents.mockResolvedValue([{ id: agentID, name: "web host", status: "active", presence: { state: "online" } }]);
    apiMock.migrationCohortPlan.mockResolvedValue({
      selector: { profile: "p3l1-web" },
      canary_size: 1,
      cohort_size: 25,
      members: 2,
      truncated: false,
      waves: [
        { id: "canary", ordinal: 1, members: [{ identity_id: webA, name: "web-a.p3l1.test", agent_id: agentID }] },
        { id: "cohort-2", ordinal: 2, members: [{ identity_id: webB, name: "web-b.p3l1.test", agent_id: agentID }] },
      ],
      skipped: [{ identity_id: "40400000-0000-4000-8000-0000000031a5", name: "web-e.p3l1.test", reason: "not deployed (requested)" }],
      skipped_count: 1,
      guidance: "A read-only proposal.",
    });
    apiMock.assessMigration.mockResolvedValue({
      plan_id: "p3l1",
      members: 2,
      migratable: 2,
      guidance: "Any unknown blocks the start of a migration.",
      unknowns: [],
      waves: [
        { id: "canary", ordinal: 1, members: [webA] },
        { id: "cohort-2", ordinal: 2, members: [webB] },
      ],
      revoke_predecessors: false,
    });
  });

  it("plans cohorts from a profile and uses them as the plan's waves", async () => {
    const user = userEvent.setup();
    render(
      <AppQueryProvider>
        <Migration />
      </AppQueryProvider>,
    );
    await user.click(await screen.findByRole("button", { name: "Start migration plan" }));
    await user.type(screen.getByLabelText("Plan ID"), "p3l1");
    await user.selectOptions(await screen.findByLabelText("New CA authority"), authorityID);
    await user.click(screen.getByRole("button", { name: "Map waves" }));

    const plan = screen.getByRole("button", { name: "Plan cohorts" });
    expect(plan).toBeDisabled();
    await user.type(screen.getByLabelText("Profile"), "p3l1-web");
    await user.click(plan);
    expect(apiMock.migrationCohortPlan).toHaveBeenCalledWith({ profile: "p3l1-web", issuer_ca_id: undefined, canary_size: 1, cohort_size: 25 });
    expect(await screen.findByText("2 members in 2 cohorts; 1 skipped")).toBeInTheDocument();
    expect(screen.getByText(/web-e\.p3l1\.test · not deployed \(requested\)/)).toBeInTheDocument();
    expect(apiMock.assessMigration).not.toHaveBeenCalled();

    await user.click(screen.getByRole("button", { name: "Use these cohorts" }));
    await user.click(screen.getByRole("button", { name: "Review exact plan" }));
    await user.click(screen.getByRole("button", { name: "Check cutover readiness" }));
    expect(apiMock.assessMigration).toHaveBeenCalledWith({
      plan_id: "p3l1",
      require_full_trust: true,
      waves: [
        { id: "canary", ordinal: 1, members: [webA] },
        { id: "cohort-2", ordinal: 2, members: [webB] },
      ],
    });
    expect(await screen.findByRole("button", { name: "Start migration" })).toBeInTheDocument();
  });
});
