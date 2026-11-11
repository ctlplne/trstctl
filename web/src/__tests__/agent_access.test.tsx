import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { AccessAuthority, AccessBundle, AccessRun } from "@/lib/api";
import { AgentAccess } from "@/pages/AgentAccess";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    accessBundles: vi.fn(),
    accessBundle: vi.fn(),
    createAccessBundle: vi.fn(),
    updateAccessBundle: vi.fn(),
    deleteAccessBundle: vi.fn(),
    grantAccessBundle: vi.fn(),
    ungrantAccessBundle: vi.fn(),
    accessAuthority: vi.fn(),
    issueAccessRun: vi.fn(),
    accessRuns: vi.fn(),
    revokeAccessRun: vi.fn(),
    accessActivity: vi.fn(),
    exportAccessActivity: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (original) => {
  const actual = await original<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});

const now = "2026-11-04T04:00:00Z";
const full: AccessBundle = {
  id: "b-full",
  name: "deploy-full",
  description: "",
  permissions: ["certs:read", "owners:read"],
  audiences: ["ci"],
  max_run_ttl_seconds: 1800,
  access_targets: [],
  revision: 1,
  created_by: "admin",
  created_at: now,
  updated_at: now,
  live_grants: 1,
  active_runs: 1,
};

const run: AccessRun = {
  id: "run-1",
  principal: "ci:deploy",
  bundle_ids: ["b-full"],
  bundle_names: ["deploy-full"],
  grant_ids: ["g-full"],
  permissions: ["certs:read", "owners:read"],
  effective: ["certs:read", "owners:read"],
  label: "deploy #1",
  status: "active",
  expires_at: now,
  issued_by: "ci:deploy",
  issued_at: now,
  chain: [
    { step: "bundle_saved", actor: "admin", at: now, detail: "deploy-full, revision 1" },
    { step: "granted", actor: "admin", at: now, detail: "machine grant to ci:deploy" },
    { step: "run_issued", actor: "ci:deploy", at: now, detail: "for ci:deploy" },
  ],
};

const bounds = {
  revocation: "Takes effect on the run's next request.",
  outage: "Checked online.",
  lasting: "What a run made stays.",
  max_run_ttl_seconds: 1800,
};

const remaining: AccessAuthority = {
  principal: "ci:deploy",
  permissions: [{ permission: "owners:read", via: [{ grant_id: "g-owners", bundle_id: "b-owners", bundle_name: "deploy-owners" }] }],
  grants: [],
  runs: [run],
  bounds,
  computed_at: now,
};

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <AgentAccess />
    </QueryClientProvider>,
  );
}

describe("A251 agent access in the console", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    apiMock.accessBundles.mockResolvedValue({ items: [full] });
    apiMock.accessBundle.mockResolvedValue({
      ...full,
      grants: [{ id: "g-full", bundle_id: "b-full", principal_type: "machine", principal: "ci:deploy", granted_by: "admin", granted_at: now, live: true }],
      runs: [run],
    });
    apiMock.accessRuns.mockResolvedValue({ items: [run] });
    apiMock.accessActivity.mockResolvedValue({
      items: [
        {
          at: now,
          action: "run_issued",
          bundle_ids: ["b-full"],
          bundle_names: ["deploy-full"],
          run_id: "run-1",
          principal: "ci:deploy",
          actor: "ci:deploy",
          detail: "deploy #1",
        },
      ],
      next_cursor: "",
    });
  });

  it("creates a bundle from the form and opens it", async () => {
    apiMock.createAccessBundle.mockResolvedValue({ ...full, id: "b-new", name: "mcp-readers" });
    const user = userEvent.setup();
    renderPage();
    await user.type(screen.getByLabelText("Bundle name"), "mcp-readers");
    await user.type(screen.getByLabelText("Permissions (comma-separated, such as certs:read, owners:read)"), "owners:read, , certs:read");
    await user.click(screen.getByLabelText("MCP servers"));
    await user.click(screen.getByRole("button", { name: "Create bundle" }));
    await waitFor(() =>
      expect(apiMock.createAccessBundle).toHaveBeenCalledWith({
        name: "mcp-readers",
        description: "",
        permissions: ["owners:read", "certs:read"],
        audiences: ["ci", "mcp_server"],
        max_run_ttl_seconds: 900,
      }),
    );
    await waitFor(() => expect(apiMock.accessBundle).toHaveBeenCalledWith("b-new"));
  });

  // A257-L3: a bundle's access targets are shown, set at creation and edited
  // at the revision read.
  it("shows a bundle's access targets and creates a bundle with targets", async () => {
    apiMock.accessBundles.mockResolvedValue({
      items: [{ ...full, access_targets: [{ target_type: "ssh", target_id: "bastion-01", roles: ["ops", "read"] }] }],
    });
    apiMock.createAccessBundle.mockResolvedValue({ ...full, id: "b-new", name: "jump-hosts" });
    const user = userEvent.setup();
    renderPage();
    expect(await screen.findByText("ssh/bastion-01: ops, read")).toBeInTheDocument();
    await user.type(screen.getByLabelText("Bundle name"), "jump-hosts");
    await user.type(screen.getByLabelText("Permissions (comma-separated, such as certs:read, owners:read)"), "access:sessions.open");
    const targets = screen.getByRole("textbox", { name: "Access targets (one per line: type/id: role, role)" });
    await user.type(targets, "ssh/bastion-01: ops{Enter}postgres/orders-db: reporting, audit");
    await user.click(screen.getByRole("button", { name: "Create bundle" }));
    await waitFor(() =>
      expect(apiMock.createAccessBundle).toHaveBeenCalledWith({
        name: "jump-hosts",
        description: "",
        permissions: ["access:sessions.open"],
        audiences: ["ci"],
        max_run_ttl_seconds: 900,
        access_targets: [
          { target_type: "ssh", target_id: "bastion-01", roles: ["ops"] },
          { target_type: "postgres", target_id: "orders-db", roles: ["reporting", "audit"] },
        ],
      }),
    );
  });

  it("edits a bundle's access targets at the revision it read", async () => {
    const targeted = {
      ...full,
      permissions: ["access:sessions.open"],
      access_targets: [{ target_type: "ssh" as const, target_id: "bastion-01", roles: ["ops"] }],
    };
    apiMock.accessBundles.mockResolvedValue({ items: [targeted] });
    apiMock.accessBundle.mockResolvedValue({ ...targeted, grants: [], runs: [] });
    apiMock.updateAccessBundle.mockResolvedValue({ ...targeted, revision: 2 });
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByRole("button", { name: "deploy-full" }));
    const editor = within(await screen.findByRole("region", { name: "Access targets for deploy-full" }));
    const box = editor.getByRole("textbox", { name: "Access targets (one per line: type/id: role, role)" });
    expect(box).toHaveValue("ssh/bastion-01: ops");
    await user.clear(box);
    await user.type(box, "rdp/finance-ws: admin{Enter}ssh/bastion-01: ops, read");
    await user.click(editor.getByRole("button", { name: "Save access targets" }));
    await waitFor(() =>
      expect(apiMock.updateAccessBundle).toHaveBeenCalledWith("b-full", {
        name: "deploy-full",
        description: "",
        permissions: ["access:sessions.open"],
        audiences: ["ci"],
        max_run_ttl_seconds: 1800,
        access_targets: [
          { target_type: "rdp", target_id: "finance-ws", roles: ["admin"] },
          { target_type: "ssh", target_id: "bastion-01", roles: ["ops", "read"] },
        ],
        revision: 1,
      }),
    );
  });

  it("refuses an access target line it cannot read without saving", async () => {
    apiMock.accessBundle.mockResolvedValue({ ...full, grants: [], runs: [] });
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByRole("button", { name: "deploy-full" }));
    const editor = within(await screen.findByRole("region", { name: "Access targets for deploy-full" }));
    await user.type(editor.getByRole("textbox", { name: "Access targets (one per line: type/id: role, role)" }), "telnet/old-switch: admin");
    await user.click(editor.getByRole("button", { name: "Save access targets" }));
    expect(await screen.findByText(/Not understood: telnet\/old-switch: admin/)).toBeInTheDocument();
    expect(apiMock.updateAccessBundle).not.toHaveBeenCalled();
  });

  it("shows the authority that remains after one of several grants is removed", async () => {
    apiMock.ungrantAccessBundle.mockResolvedValue({
      grant: {
        id: "g-full",
        bundle_id: "b-full",
        principal_type: "machine",
        principal: "ci:deploy",
        granted_by: "admin",
        granted_at: now,
        removed_at: now,
        live: false,
      },
      authority: remaining,
    });
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByRole("button", { name: "deploy-full" }));
    await user.click(await screen.findByRole("button", { name: "Remove ci:deploy's grant" }));
    await waitFor(() => expect(apiMock.ungrantAccessBundle).toHaveBeenCalledWith("b-full", "g-full", "removed in the console"));
    expect(await screen.findByText("ci:deploy holds, now:")).toBeInTheDocument();
    expect(screen.getByText("owners:read, through deploy-owners")).toBeInTheDocument();
    expect(screen.queryByText(/certs:read, through/)).not.toBeInTheDocument();
    expect(screen.getByText("Takes effect on the run's next request.")).toBeInTheDocument();
    expect(screen.getByText(/Run run-1: bundle_saved \(admin\) → granted \(admin\) → run_issued \(ci:deploy\)/)).toBeInTheDocument();
  });

  it("shows a run's token once with its launch lines, and revokes runs", async () => {
    apiMock.issueAccessRun.mockResolvedValue({
      run,
      token: "trst_console-run-token",
      launch: {
        token_env: "TRSTCTL_TOKEN",
        server_env: "TRSTCTL_SERVER",
        custom_agent: "TRSTCTL_TOKEN=<this run's token> ./your-agent",
        ci: "masked CI variable",
        mcp_server: '{"command": "trstctl-cli"}',
      },
      bounds,
    });
    apiMock.revokeAccessRun.mockResolvedValue({ ...run, status: "revoked", effective: [] });
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByRole("button", { name: "deploy-full" }));
    await user.type(await screen.findByLabelText("Label (such as a job ID)"), "agent smoke");
    await user.click(screen.getByRole("button", { name: "Start run" }));
    await waitFor(() => expect(apiMock.issueAccessRun).toHaveBeenCalledWith({ bundle_ids: ["b-full"], ttl_seconds: 900, label: "agent smoke" }));
    expect(await screen.findByDisplayValue("trst_console-run-token")).toBeInTheDocument();
    expect(screen.getByText("TRSTCTL_TOKEN=<this run's token> ./your-agent")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Done" }));
    expect(screen.queryByDisplayValue("trst_console-run-token")).not.toBeInTheDocument();

    const runs = screen.getByText("ci:deploy: deploy #1").closest("tr") as HTMLElement;
    expect(within(runs).getByText("certs:read, owners:read")).toBeInTheDocument();
    await user.click(within(runs).getByRole("button", { name: "Revoke ci:deploy's run" }));
    await waitFor(() => expect(apiMock.revokeAccessRun).toHaveBeenCalledWith("run-1"));
  });

  it("asks before deleting a bundle", async () => {
    apiMock.deleteAccessBundle.mockResolvedValue({ id: "b-full", name: "deploy-full", deleted: true, grants_affected: 1, runs_affected: 1, deleted_at: now });
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByRole("button", { name: "Delete" }));
    expect(apiMock.deleteAccessBundle).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "Delete deploy-full: its grants and runs stop now" }));
    await waitFor(() => expect(apiMock.deleteAccessBundle).toHaveBeenCalledWith("b-full"));
  });

  it("searches activity and exports what matches", async () => {
    const createObjectURL = vi.fn(() => "blob:activity");
    const revokeObjectURL = vi.fn();
    Object.assign(URL, { createObjectURL, revokeObjectURL });
    const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
    apiMock.exportAccessActivity.mockResolvedValue({ kind: "trstctl.access-activity-export/v1", items: [] });
    const user = userEvent.setup();
    renderPage();
    expect(await screen.findByText("Run started under deploy-full")).toBeInTheDocument();
    const activityCard = screen.getByText("Activity").closest("div")?.parentElement as HTMLElement;
    await user.type(within(activityCard).getByLabelText("Principal"), "ci:deploy");
    await user.type(within(activityCard).getByLabelText("Search"), "deploy #1");
    await user.click(screen.getByRole("button", { name: "Search activity" }));
    await waitFor(() => expect(apiMock.accessActivity).toHaveBeenLastCalledWith({ principal: "ci:deploy", q: "deploy #1", limit: 20 }));
    await user.click(screen.getByRole("button", { name: "Export activity" }));
    await waitFor(() => expect(apiMock.exportAccessActivity).toHaveBeenCalledWith({ principal: "ci:deploy", q: "deploy #1", bundle: undefined }));
    expect(createObjectURL).toHaveBeenCalled();
    expect(click).toHaveBeenCalledTimes(1);
    click.mockRestore();
  });
});
