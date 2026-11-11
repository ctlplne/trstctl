import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ApiError } from "@/lib/api";
import { SlackApprovalsPanel } from "@/pages/SlackApprovalsPanel";

const { apiMock, perms } = vi.hoisted(() => ({
  apiMock: {
    getSlackApp: vi.fn(),
    startSlackInstall: vi.fn(),
    listSlackChannels: vi.fn(),
    setSlackApprovalChannel: vi.fn(),
    createSlackLinkCode: vi.fn(),
    uninstallSlackApp: vi.fn(),
  },
  perms: { value: new Set<string>() },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});
vi.mock("@/components/rbac", () => ({ useCan: (perm: string) => perms.value.has(perm) }));

const installed = {
  configured: true,
  installed: true,
  team_id: "T0N8TEAM",
  team_name: "N8 Workspace",
  approval_channel_id: "C0SECURITY",
  approval_channel_name: "security-approvals",
  installed_by: "slack-admin@example.test",
  installed_at: "2026-11-11T07:00:00Z",
  duplicate_post_check: false,
};

describe("N8 Slack approvals panel", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    perms.value = new Set(["connectors:read", "connectors:write", "approvals:review"]);
    apiMock.getSlackApp.mockResolvedValue(installed);
  });

  it("says an install without the channel history can post twice, and installs again through Slack's consent screen (N8-L1)", async () => {
    apiMock.startSlackInstall.mockResolvedValue({
      authorize_url: "https://slack.example.test/oauth/v2/authorize?state=s1",
      expires_at: "2026-11-11T07:10:00Z",
    });
    const user = userEvent.setup();
    render(<SlackApprovalsPanel />);
    expect(await screen.findByText(/a post retried after its answer was lost can appear twice/)).toBeInTheDocument();
    expect(screen.getByText("#security-approvals")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Install again" }));
    expect(apiMock.startSlackInstall).toHaveBeenCalledTimes(1);
    expect(await screen.findByRole("link", { name: /Open Slack's consent screen/ })).toHaveAttribute(
      "href",
      "https://slack.example.test/oauth/v2/authorize?state=s1",
    );
  });

  it("says an install with the channel history checks before posting (N8-L1)", async () => {
    apiMock.getSlackApp.mockResolvedValue({ ...installed, duplicate_post_check: true });
    render(<SlackApprovalsPanel />);
    expect(await screen.findByText(/looks in the channel for an earlier post of the same request/)).toBeInTheDocument();
    expect(screen.queryByText(/can appear twice/)).not.toBeInTheDocument();
  });

  it("picks the approval channel from the channels the app sees", async () => {
    apiMock.listSlackChannels.mockResolvedValue({
      items: [
        { id: "C0SECURITY", name: "security-approvals", is_member: true },
        { id: "C0OPS", name: "ops", is_private: true },
      ],
    });
    apiMock.setSlackApprovalChannel.mockResolvedValue({ ...installed, approval_channel_id: "C0OPS", approval_channel_name: "ops" });
    const user = userEvent.setup();
    render(<SlackApprovalsPanel />);
    await user.click(await screen.findByRole("button", { name: "Pick the approval channel" }));
    await user.selectOptions(await screen.findByRole("combobox", { name: "Approval channel" }), "C0OPS");
    expect(screen.getByRole("option", { name: "ops (private)" })).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Post approvals here" }));
    expect(apiMock.setSlackApprovalChannel).toHaveBeenCalledWith({ channel_id: "C0OPS" });
    expect(await screen.findByText("#ops")).toBeInTheDocument();
  });

  it("gives a reviewer a one-time link code without the install's details", async () => {
    perms.value = new Set(["approvals:review"]);
    apiMock.createSlackLinkCode.mockResolvedValue({ code: "ab12-cd34", expires_at: "2026-11-11T07:10:00Z" });
    const user = userEvent.setup();
    render(<SlackApprovalsPanel />);
    await user.click(screen.getByRole("button", { name: "Link my Slack user" }));
    expect(await screen.findByText(/type \/trstctl link ab12-cd34 before/)).toBeInTheDocument();
    expect(apiMock.getSlackApp).not.toHaveBeenCalled();
    expect(screen.queryByRole("button", { name: /Install/ })).not.toBeInTheDocument();
  });

  it("says when the control plane has no Slack app, and uninstalls only after a confirmation", async () => {
    apiMock.getSlackApp.mockRejectedValueOnce(new ApiError(404, '{"detail":"not configured"}'));
    const { unmount } = render(<SlackApprovalsPanel />);
    expect(await screen.findByText(/not configured on this control plane/)).toBeInTheDocument();
    unmount();

    apiMock.uninstallSlackApp.mockResolvedValue(undefined);
    apiMock.getSlackApp.mockResolvedValueOnce(installed).mockResolvedValueOnce({ configured: true, installed: false });
    const user = userEvent.setup();
    render(<SlackApprovalsPanel />);
    await user.click(await screen.findByRole("button", { name: "Uninstall" }));
    expect(apiMock.uninstallSlackApp).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "Uninstall the Slack app" }));
    expect(apiMock.uninstallSlackApp).toHaveBeenCalledTimes(1);
    expect(await screen.findByText("The Slack app is not installed for this tenant.")).toBeInTheDocument();
  });
});
