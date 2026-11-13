import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { SecretProjectsWorkflow } from "@/pages/secrets/SecretProjectsWorkflow";

const { apiMock, can } = vi.hoisted(() => ({
  apiMock: {
    listSecretProjects: vi.fn(),
    getSecretProject: vi.fn(),
    createSecretProject: vi.fn(),
    putSecretProjectMember: vi.fn(),
    deleteSecretProjectMember: vi.fn(),
    renameSecretProject: vi.fn(),
    renameSecretProjectEnvironment: vi.fn(),
  },
  can: { value: true },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});
vi.mock("@/components/rbac", () => ({ useCan: () => can.value }));

const payments = {
  slug: "payments",
  name: "Payments",
  owner: "unknown",
  created_at: "2026-11-01T00:00:00Z",
  environments: [
    {
      slug: "dev",
      restricted: false,
      access: "open",
      secrets: [{ name: "payments/dev/db/password", key: "db/password", version: 2, owner: "unknown" }],
    },
    { slug: "stage", restricted: true, access: "restricted", secrets: [] },
  ],
  members: [{ subject: "team-a-ci", role: "developer", environments: ["stage"], granted_at: "2026-11-01T00:00:00Z" }],
};

describe("A235 secrets projects", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    can.value = true;
    apiMock.listSecretProjects.mockResolvedValue({ items: [{ slug: "payments", name: "Payments", owner: "unknown", created_at: "2026-11-01T00:00:00Z" }] });
    apiMock.getSecretProject.mockResolvedValue(payments);
  });

  it("names unknown ownership and hides a restricted environment's secrets", async () => {
    const user = userEvent.setup();
    render(<SecretProjectsWorkflow />);
    const list = await screen.findByRole("list", { name: "Projects" });
    expect(within(list).getByText("Unknown owner")).toBeInTheDocument();
    await user.click(within(list).getByRole("button", { name: "Open" }));
    expect(await screen.findByText("Only granted members see these secrets.")).toBeInTheDocument();
    expect(screen.getByText("db/password")).toBeInTheDocument();
    expect(screen.queryByText(/stage\/db/)).not.toBeInTheDocument();
    expect(screen.getByText("Set an owner to see this application's certificates and identities here.")).toBeInTheDocument();
    expect(screen.getByText("team-a-ci")).toBeInTheDocument();
  });

  it("shows the owner's certificates and identities with their health", async () => {
    apiMock.getSecretProject.mockResolvedValue({
      ...payments,
      owner: "Payments team",
      owner_resources: {
        certificates: 3,
        identities: 1,
        certificates_needing_work: 1,
        application_id: "APP-PAY",
        owners: 2,
        soonest_certificates: [{ id: "c1", kind: "certificate", name: "CN=api.payments", health: "expiring", not_after: "2026-11-20T00:00:00Z" }],
        soonest_identities: [{ id: "i1", kind: "spiffe", name: "payments-api", health: "ok" }],
      },
    });
    const user = userEvent.setup();
    render(<SecretProjectsWorkflow />);
    await user.click(await screen.findByRole("button", { name: "Open" }));
    expect(await screen.findByText(/holds 3 certificates and 1 identities; 1 certificates need attention/)).toBeInTheDocument();
    // A235-L5: the view spans every owner of the owner's CMDB application.
    expect(screen.getByText("Application APP-PAY: across its 2 owners in the CMDB.")).toBeInTheDocument();
    expect(screen.getByText("Expiring within 30 days")).toBeInTheDocument();
    expect(screen.getByText("CN=api.payments")).toBeInTheDocument();
  });

  it("creates a project from slugs, marking restricted environments", async () => {
    apiMock.createSecretProject.mockResolvedValue(payments);
    const user = userEvent.setup();
    render(<SecretProjectsWorkflow />);
    await user.type(await screen.findByRole("textbox", { name: "Project slug" }), "payments");
    await user.click(screen.getByRole("button", { name: "Create project" }));
    expect(apiMock.createSecretProject).toHaveBeenCalledWith({
      slug: "payments",
      name: "",
      environments: [
        { slug: "dev", restricted: false },
        { slug: "stage", restricted: true },
      ],
    });
  });

  // A235-L1: a project admin without access:write manages members within its
  // own grant, as the server reports it: the grant form, a revoke only for a
  // member inside that grant, and no project creation.
  it("lets a project admin restricted to stage manage stage members only", async () => {
    can.value = false;
    apiMock.getSecretProject.mockResolvedValue({
      ...payments,
      can_manage_members: true,
      manageable_environments: ["stage"],
      members: [
        { subject: "team-a-ci", role: "developer", environments: ["stage"], granted_at: "2026-11-01T00:00:00Z" },
        { subject: "release-bot", role: "admin", environments: [], granted_at: "2026-11-01T00:00:00Z" },
      ],
    });
    apiMock.putSecretProjectMember.mockResolvedValue(payments);
    const user = userEvent.setup();
    render(<SecretProjectsWorkflow />);
    await user.click(await screen.findByRole("button", { name: "Open" }));
    await screen.findByText("release-bot");
    expect(screen.queryByRole("button", { name: "Create project" })).not.toBeInTheDocument();
    expect(screen.getByText("As this project's admin you grant and revoke members within stage.")).toBeInTheDocument();
    expect(screen.getAllByRole("button", { name: "Revoke" })).toHaveLength(1);
    const form = within(screen.getByRole("form", { name: "Grant a project member" }));
    await user.type(form.getByRole("textbox", { name: "Member subject" }), "team-b-ci");
    await user.type(form.getByRole("textbox", { name: "Environments" }), "stage");
    await user.click(form.getByRole("button", { name: "Grant" }));
    expect(apiMock.putSecretProjectMember).toHaveBeenCalledWith("payments", "team-b-ci", { role: "developer", environments: ["stage"] });
  });

  // A235-L3: access:write renames the project and an environment; the slug
  // stays and the form says so.
  it("renames the project and an environment, keeping their slugs", async () => {
    apiMock.renameSecretProject.mockResolvedValue({ ...payments, name: "Payments Platform" });
    apiMock.renameSecretProjectEnvironment.mockResolvedValue({ ...payments, name: "Payments Platform" });
    const user = userEvent.setup();
    render(<SecretProjectsWorkflow />);
    await user.click(await screen.findByRole("button", { name: "Open" }));
    await user.click(await screen.findByRole("button", { name: "Rename" }));
    let form = within(screen.getByRole("form", { name: "Rename this project" }));
    expect(form.getByText("The slug payments stays, so secret names do not change.")).toBeInTheDocument();
    const projectName = form.getByRole("textbox", { name: "New name" });
    await user.clear(projectName);
    await user.type(projectName, "Payments Platform");
    await user.click(form.getByRole("button", { name: "Save name" }));
    expect(apiMock.renameSecretProject).toHaveBeenCalledWith("payments", { name: "Payments Platform" });
    expect(await screen.findByRole("heading", { name: "Payments Platform" })).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Rename environment stage" }));
    form = within(screen.getByRole("form", { name: "Rename environment stage" }));
    const envName = form.getByRole("textbox", { name: "New name" });
    await user.clear(envName);
    await user.type(envName, "Staging");
    await user.click(form.getByRole("button", { name: "Save name" }));
    expect(apiMock.renameSecretProjectEnvironment).toHaveBeenCalledWith("payments", "stage", { name: "Staging" });
  });

  it("offers no create, grant or revoke without access:write", async () => {
    can.value = false;
    const user = userEvent.setup();
    render(<SecretProjectsWorkflow />);
    await user.click(await screen.findByRole("button", { name: "Open" }));
    await screen.findByText("team-a-ci");
    expect(screen.queryByRole("button", { name: "Create project" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Revoke" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Grant" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Rename" })).not.toBeInTheDocument();
  });
});
