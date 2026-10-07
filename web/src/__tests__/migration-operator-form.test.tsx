import { beforeEach, describe, expect, it, vi } from "vitest";
import { act, fireEvent, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { AppQueryProvider } from "@/lib/query";
import { Migration } from "@/pages/Migration";

const authorityID = "40400000-0000-4000-8000-000000000042";
const identityID = "40400000-0000-4000-8000-000000000043";
const agentID = "40400000-0000-4000-8000-000000000044";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    assessMigration: vi.fn(),
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

function renderRoute() {
  return render(
    <AppQueryProvider>
      <Migration />
    </AppQueryProvider>,
  );
}

describe("migration operator plan", () => {
  beforeEach(() => {
    for (const mock of Object.values(apiMock)) mock.mockReset();
    apiMock.migrationRuns.mockResolvedValue({ items: [] });
    apiMock.caAuthorities.mockResolvedValue({ items: [{ id: authorityID, common_name: "QA new CA", status: "active" }] });
    apiMock.identities.mockResolvedValue([{ id: identityID, name: "payments TLS", kind: "x509_certificate", status: "deployed" }]);
    apiMock.agents.mockResolvedValue([{ id: agentID, name: "payments host", status: "active", presence: { state: "online" } }]);
  });

  it("builds and reviews an exact plan from served rosters, then invalidates readiness on edit", async () => {
    const user = userEvent.setup();
    apiMock.assessMigration.mockResolvedValue({
      plan_id: "payments-cutover",
      members: 1,
      migratable: 1,
      guidance: "Any unknown blocks the start of a migration.",
      unknowns: [],
      waves: [{ id: "canary", ordinal: 1, members: [identityID] }],
    });
    renderRoute();

    await user.click(await screen.findByRole("button", { name: "Start migration plan" }));
    expect(await screen.findByLabelText("New CA authority")).toBeInTheDocument();
    expect(screen.queryByLabelText("Migration plan JSON")).not.toBeInTheDocument();
    await user.clear(screen.getByLabelText("Plan ID"));
    await user.type(screen.getByLabelText("Plan ID"), "payments-cutover");
    await user.selectOptions(screen.getByLabelText("New CA authority"), authorityID);
    await user.click(screen.getByRole("button", { name: "Map waves" }));
    await user.selectOptions(screen.getByLabelText("Identity"), identityID);
    await user.selectOptions(screen.getByLabelText("Host agent"), agentID);
    await user.click(screen.getByRole("button", { name: "Review exact plan" }));
    expect(screen.getByText("QA new CA")).toBeInTheDocument();
    expect(screen.getByText(/payments TLS/)).toBeInTheDocument();
    expect(screen.getByText(/payments host/)).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Check cutover readiness" }));
    expect(apiMock.assessMigration).toHaveBeenCalledWith({
      plan_id: "payments-cutover",
      require_full_trust: true,
      waves: [{ id: "canary", ordinal: 1, members: [identityID] }],
    });
    expect(await screen.findByRole("button", { name: "Start migration" })).toBeInTheDocument();
    const planSection = screen.getByText("Plan details and source mappings");
    await user.click(planSection);
    await user.click(planSection);
    await user.click(screen.getByRole("button", { name: "Previous" }));
    await user.click(screen.getByRole("button", { name: "Previous" }));
    expect(screen.getByLabelText("Plan ID")).toHaveValue("payments-cutover");
    await user.click(screen.getByRole("button", { name: "Map waves" }));
    await user.clear(screen.getByLabelText("Trust-anchor path"));
    await user.type(screen.getByLabelText("Trust-anchor path"), "/etc/trstctl/changed-root.pem");
    expect(screen.queryByRole("button", { name: "Start migration" })).not.toBeInTheDocument();
  });

  it("keeps JSON as an explicit advanced path and rejects incomplete input before the API", async () => {
    const user = userEvent.setup();
    renderRoute();
    await user.click(await screen.findByRole("button", { name: "Start migration plan" }));
    await user.click(screen.getByRole("button", { name: "Advanced JSON" }));
    const editor = await screen.findByLabelText("Migration plan JSON");
    fireEvent.change(editor, { target: { value: "{}" } });
    await user.click(screen.getByRole("button", { name: "Check cutover readiness" }));
    expect(await screen.findByText(/incomplete or is not valid JSON/)).toBeInTheDocument();
    expect(apiMock.assessMigration).not.toHaveBeenCalled();
  });

  it("reviews the normalized request that assessment will receive", async () => {
    const user = userEvent.setup();
    renderRoute();
    await user.click(await screen.findByRole("button", { name: "Start migration plan" }));
    await user.type(screen.getByLabelText("Plan ID"), "  payments-cutover  ");
    await user.selectOptions(screen.getByLabelText("New CA authority"), authorityID);
    await user.click(screen.getByRole("button", { name: "Map waves" }));
    await user.selectOptions(screen.getByLabelText("Identity"), identityID);
    await user.selectOptions(screen.getByLabelText("Host agent"), agentID);
    await user.click(screen.getByRole("button", { name: "Review exact plan" }));
    const planValue = screen.getByText("payments-cutover", { selector: "dd" });
    expect(planValue.textContent).toBe("payments-cutover");
  });

  it("rejects duplicate identities and sends reordered waves in reviewed order", async () => {
    const user = userEvent.setup();
    const secondIdentityID = "40400000-0000-4000-8000-000000000045";
    apiMock.identities.mockResolvedValue([
      { id: identityID, name: "payments TLS", kind: "x509_certificate", status: "deployed" },
      { id: secondIdentityID, name: "ledger TLS", kind: "x509_certificate", status: "deployed" },
    ]);
    apiMock.assessMigration.mockResolvedValue({
      plan_id: "ca-rollover-2026",
      members: 2,
      migratable: 2,
      guidance: "Any unknown blocks the start of a migration.",
      unknowns: [],
      waves: [
        { id: "wave-2", ordinal: 1, members: [secondIdentityID] },
        { id: "canary", ordinal: 2, members: [identityID] },
      ],
    });
    renderRoute();
    await user.click(await screen.findByRole("button", { name: "Start migration plan" }));
    await user.type(screen.getByLabelText("Plan ID"), "ca-rollover-2026");
    await user.selectOptions(await screen.findByLabelText("New CA authority"), authorityID);
    await user.click(screen.getByRole("button", { name: "Map waves" }));
    await user.selectOptions(screen.getByLabelText("Identity"), identityID);
    await user.selectOptions(screen.getByLabelText("Host agent"), agentID);
    await user.click(screen.getByRole("button", { name: "Add wave" }));
    await user.selectOptions(screen.getAllByLabelText("Identity")[1], identityID);
    await user.selectOptions(screen.getAllByLabelText("Host agent")[1], agentID);
    await user.click(screen.getByRole("button", { name: "Review exact plan" }));
    expect(await screen.findByText("An identity may appear in only one wave.")).toBeInTheDocument();
    expect(apiMock.assessMigration).not.toHaveBeenCalled();

    await user.selectOptions(screen.getAllByLabelText("Identity")[1], secondIdentityID);
    await user.click(screen.getByRole("button", { name: "Move wave 2 up" }));
    await user.click(screen.getByRole("button", { name: "Review exact plan" }));
    await user.click(screen.getByRole("button", { name: "Check cutover readiness" }));
    expect(apiMock.assessMigration).toHaveBeenCalledWith({
      plan_id: "ca-rollover-2026",
      require_full_trust: true,
      waves: [
        { id: "wave-2", ordinal: 1, members: [secondIdentityID] },
        { id: "canary", ordinal: 2, members: [identityID] },
      ],
    });
  });

  it("does not accept a late assessment for a plan edited while the request was pending", async () => {
    const user = userEvent.setup();
    let finishAssessment: (result: unknown) => void = () => {};
    apiMock.assessMigration.mockReturnValue(
      new Promise((resolve) => {
        finishAssessment = resolve;
      }),
    );
    renderRoute();
    await user.click(await screen.findByRole("button", { name: "Start migration plan" }));
    await user.click(screen.getByRole("button", { name: "Advanced JSON" }));
    const editor = await screen.findByLabelText("Migration plan JSON");
    const plan = {
      plan_id: "late-assessment",
      new_authority_id: authorityID,
      waves: [{ id: "canary", ordinal: 1, members: [{ identity_id: identityID, agent_id: agentID, trust_anchor_path: "/etc/trstctl/next-root.pem" }] }],
    };
    fireEvent.change(editor, { target: { value: JSON.stringify(plan) } });
    await user.click(screen.getByRole("button", { name: "Check cutover readiness" }));
    expect(apiMock.assessMigration).toHaveBeenCalledOnce();
    fireEvent.change(editor, { target: { value: JSON.stringify({ ...plan, new_authority_id: "different-authority" }) } });
    await act(async () =>
      finishAssessment({
        plan_id: "late-assessment",
        members: 1,
        migratable: 1,
        guidance: "Ready",
        unknowns: [],
        waves: [{ id: "canary", ordinal: 1, members: [identityID] }],
      }),
    );
    expect(screen.queryByRole("button", { name: "Start migration" })).not.toBeInTheDocument();
  });
});
