import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { ApiError } from "@/lib/apiTransport";
import type { ChangePlan, ChangeSet } from "@/lib/api";
import { ChangeSets, changeSetFromForm, changeSetTemplates } from "@/pages/ChangeSets";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    aiStatus: vi.fn(),
    planChangeSet: vi.fn(),
    applyChangeSet: vi.fn(),
    draftChangeSet: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (original) => {
  const actual = await original<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});

// The set the served draft test plans (internal/server/change_set_draft_served_test.go):
// the form has to write the same object the API, GitOps and a draft write.
const onboardBilling: ChangeSet = {
  name: "onboard billing",
  owners: [{ key: "billing", kind: "team", name: "Billing", application_id: "app-7", environment: "staging" }],
  profiles: [{ name: "billing-web", spec: { allowed_key_algorithms: ["ECDSA"], allowed_protocols: ["acme"], max_validity: "720h" } }],
  members: [{ subject: "dev@billing.example", roles: ["viewer"] }],
};

const item = (kind: string, key: string, action: "create" | "update" | "unchanged") => ({
  kind,
  key,
  action,
  expected_digest: "sha256:" + kind,
  identities: [],
  credentials: [],
  grants: kind === "member" ? ["viewer for dev@billing.example"] : [],
  destinations: [],
  approvals: [],
  effects: [kind + ".created"],
  verification: "read back " + kind,
});

const plan: ChangePlan = {
  name: "onboard billing",
  change_set_digest: "sha256:intent",
  plan_digest: "sha256:plan",
  changes: 3,
  items: [item("owner", "billing", "create"), item("profile", "billing-web", "create"), item("member", "dev@billing.example", "create")],
};

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <ChangeSets />
    </QueryClientProvider>,
  );
}

async function fillOnboardBilling(user: ReturnType<typeof userEvent.setup>) {
  const name = screen.getByLabelText("Change set name");
  await user.clear(name);
  await user.type(name, "onboard billing");
  await user.type(screen.getByLabelText("Owner key"), "billing");
  await user.type(screen.getByLabelText("Owner name"), "Billing");
  await user.type(screen.getByLabelText("Application ID"), "app-7");
  await user.type(screen.getByLabelText("Environment"), "staging");
  await user.type(screen.getByLabelText("Profile name"), "billing-web");
  await user.type(screen.getByLabelText("Member subject"), "dev@billing.example");
}

describe("A248 reviewed change sets in the console", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    apiMock.aiStatus.mockResolvedValue({ enabled: false, model_configured: false });
    apiMock.planChangeSet.mockResolvedValue(plan);
    apiMock.applyChangeSet.mockResolvedValue({
      name: "onboard billing",
      change_set_digest: "sha256:intent",
      plan_digest: "sha256:plan",
      complete: false,
      results: [
        { kind: "owner", key: "billing", outcome: "created", verified: true },
        { kind: "profile", key: "billing-web", outcome: "created", verified: true },
        { kind: "member", key: "dev@billing.example", outcome: "refused", error: "approval required", verified: false },
      ],
    });
  });

  it("builds the typed set the API plans: empty rows dropped, lists split, JSON parsed", () => {
    const invalid = (field: string) => `bad ${field}`;
    const form = structuredClone(changeSetTemplates.onboard);
    form.name = " onboard billing ";
    form.owners[0] = { ...form.owners[0], key: "billing", name: "Billing", application_id: "app-7", environment: "staging" };
    form.profiles[0] = { ...form.profiles[0], name: "billing-web" };
    form.members = [
      { subject: "dev@billing.example", roles: " viewer, " },
      { subject: "", roles: "admin" },
    ];
    expect(changeSetFromForm(form, invalid)).toEqual({ set: onboardBilling });

    form.owners[0].escalation_chain = "oncall, , lead";
    form.targets = [{ key: "lb", name: "edge", connector: "nginx", config: '{"path":"/etc/ssl"}', enabled: true }];
    const built = changeSetFromForm(form, invalid);
    expect("set" in built && built.set.owners?.[0].escalation_chain).toEqual(["oncall", "lead"]);
    expect("set" in built && built.set.deployment_targets).toEqual([
      { key: "lb", name: "edge", connector: "nginx", config: { path: "/etc/ssl" }, enabled: true },
    ]);

    form.profiles[0].spec = "{not json";
    expect(changeSetFromForm(form, invalid)).toEqual({ error: "bad billing-web" });
  });

  it("plans the form's set, shows what applying would do, and applies only that plan", async () => {
    const user = userEvent.setup();
    renderPage();
    await fillOnboardBilling(user);
    await user.click(screen.getByRole("button", { name: "Plan" }));

    await waitFor(() => expect(apiMock.planChangeSet).toHaveBeenCalledWith(onboardBilling));
    expect(await screen.findByText("3 of 3 objects change. Plan sha256:plan; intent sha256:intent.")).toBeInTheDocument();
    expect(screen.getByText("viewer for dev@billing.example")).toBeInTheDocument();
    expect(screen.getByText("read back profile")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Apply the reviewed plan" }));
    await waitFor(() => expect(apiMock.applyChangeSet).toHaveBeenCalledWith({ change_set: onboardBilling, plan_digest: "sha256:plan" }));
    expect(await screen.findByText("Applied, but not every object verified; see each row.")).toBeInTheDocument();
    const refused = screen.getByText("refused: approval required").closest("tr");
    expect(refused).not.toBeNull();
    expect(within(refused as HTMLElement).getByText("Not verified")).toBeInTheDocument();
    expect(screen.getAllByText("Verified")).toHaveLength(2);
  });

  it("makes a plan stale when the set is edited after planning, and apply waits for a new plan", async () => {
    const user = userEvent.setup();
    renderPage();
    await fillOnboardBilling(user);
    await user.click(screen.getByRole("button", { name: "Plan" }));
    await screen.findByText(/3 of 3 objects change/);
    const apply = screen.getByRole("button", { name: "Apply the reviewed plan" });
    expect(apply).toBeEnabled();

    await user.type(screen.getByLabelText("Description"), "after review");
    expect(await screen.findByText("The edit after planning makes this plan stale; plan again.")).toBeInTheDocument();
    expect(apply).toBeDisabled();
    expect(apiMock.applyChangeSet).not.toHaveBeenCalled();
  });

  it("says the tenant changed when apply answers 409, and applies nothing else", async () => {
    apiMock.applyChangeSet.mockRejectedValue(new ApiError(409, JSON.stringify({ detail: "the tenant changed since this plan" })));
    const user = userEvent.setup();
    renderPage();
    await fillOnboardBilling(user);
    await user.click(screen.getByRole("button", { name: "Plan" }));
    await screen.findByText(/3 of 3 objects change/);
    await user.click(screen.getByRole("button", { name: "Apply the reviewed plan" }));
    expect(await screen.findByText("The tenant changed since this plan was made. Plan again and review.")).toBeInTheDocument();
    expect(apiMock.applyChangeSet).toHaveBeenCalledTimes(1);
  });

  it("offers an AI draft only with a configured model, and a draft is planned like any set", async () => {
    const first = renderPage();
    await waitFor(() => expect(apiMock.aiStatus).toHaveBeenCalled());
    expect(screen.queryByRole("button", { name: "Draft with AI" })).not.toBeInTheDocument();
    first.unmount();

    apiMock.aiStatus.mockResolvedValue({ enabled: true, model_configured: true });
    apiMock.draftChangeSet.mockResolvedValue({ change_set: onboardBilling, plan, model: "stub-drafter" });
    const user = userEvent.setup();
    renderPage();
    await user.type(await screen.findByLabelText("What should the change set do?"), "onboard billing");
    await user.click(screen.getByRole("button", { name: "Draft with AI" }));

    await waitFor(() => expect(apiMock.draftChangeSet).toHaveBeenCalledWith({ request: "onboard billing" }));
    const json = (await screen.findByLabelText("Change set (JSON)")) as HTMLTextAreaElement;
    expect(JSON.parse(json.value)).toEqual(onboardBilling);
    expect(await screen.findByText(/3 of 3 objects change/)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Apply the reviewed plan" }));
    await waitFor(() => expect(apiMock.applyChangeSet).toHaveBeenCalledWith({ change_set: onboardBilling, plan_digest: "sha256:plan" }));
  });

  it("shows why a drafted set does not plan, with nothing to apply", async () => {
    apiMock.aiStatus.mockResolvedValue({ enabled: true, model_configured: true });
    apiMock.draftChangeSet.mockResolvedValue({ change_set: { name: "x" }, refused: "a change set needs at least one object", model: "stub-drafter" });
    const user = userEvent.setup();
    renderPage();
    await user.type(await screen.findByLabelText("What should the change set do?"), "do something");
    await user.click(screen.getByRole("button", { name: "Draft with AI" }));
    expect(await screen.findByText("The draft does not plan: a change set needs at least one object")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Apply the reviewed plan" })).toBeDisabled();
  });
});
