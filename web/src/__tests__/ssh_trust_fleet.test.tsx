import { afterEach, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { AppQueryProvider } from "@/lib/query";
import { api, type SSHTrustFleetRollout } from "@/lib/api";
import { SSHTrustFleetPanel } from "@/pages/ssh/SSHTrustFleetPanel";

const ready = "00000000-0000-4000-8000-000000000001";
const skipped = "00000000-0000-4000-8000-000000000002";
const rollout = {
  id: "00000000-0000-4000-8000-000000000003",
  tenant_id: "tenant",
  approval_request_id: "approval",
  requester: "operator",
  created_at: "2026-10-28T12:00:00Z",
  updated_at: "2026-10-28T12:00:00Z",
  state: "pending",
  window_expired: false,
  plan_digest: "sha256:plan",
  plan: {
    name: "Owned hosts",
    reason: "Add staged CA",
    public_ca_key: "cHVibGlj",
    ca_fingerprint: "SHA256:ca",
    expires_at: "2026-10-28T12:15:00Z",
    hosts: [
      { agent_id: ready, state: "ready", readiness_digest: "sha256:policy" },
      { agent_id: skipped, state: "skipped", reason: "disabled" },
    ],
  },
  hosts: [
    { agent_id: ready, state: "queued" },
    { agent_id: skipped, state: "skipped", skip_reason: "disabled" },
  ],
} satisfies SSHTrustFleetRollout;
function mount() {
  return render(
    <MemoryRouter>
      <AppQueryProvider>
        <SSHTrustFleetPanel publicKey="ssh-ed25519 AAAA" canConfigure />
      </AppQueryProvider>
    </MemoryRouter>,
  );
}
afterEach(() => vi.restoreAllMocks());
it("previews exact ready and skipped hosts, requests approval, and keeps queued jobs pending", async () => {
  vi.spyOn(api, "sshTrustFleetRollouts").mockResolvedValue({ items: [] });
  vi.spyOn(api, "sshTrustFleetRollout").mockResolvedValue(rollout);
  vi.spyOn(api, "agentPage").mockResolvedValue({
    agents: [
      { id: ready, name: "ready-host", roles: ["host"] },
      { id: skipped, name: "opt-out-host", roles: ["host"] },
    ],
  } as Awaited<ReturnType<typeof api.agentPage>>);
  const preview = vi
    .spyOn(api, "previewSSHTrustFleet")
    .mockResolvedValue({ effect_free: true, job_kind_enabled: true, ready_hosts: 1, skipped_hosts: 1, plan: rollout.plan, plan_digest: rollout.plan_digest });
  const approval = vi.spyOn(api, "requestSSHTrustFleetApproval").mockResolvedValue({
    plan: rollout.plan,
    plan_digest: rollout.plan_digest,
    approval_request_id: "approval",
    approval_intent_digest: "intent",
    required_approvals: 2,
    approval_count: 0,
    expires_at: rollout.plan.expires_at,
    status: "pending",
  });
  const start = vi.spyOn(api, "startSSHTrustFleet").mockResolvedValue(rollout);
  mount();
  const user = userEvent.setup();
  await user.click(await screen.findByRole("button", { name: "Plan fleet change" }));
  await user.type(screen.getByLabelText("Rollout name"), "Owned hosts");
  await user.type(screen.getByLabelText("Reason for reviewers"), "Add staged CA");
  await user.click(await screen.findByRole("checkbox", { name: "Select ready-host" }));
  await user.click(screen.getByRole("checkbox", { name: "Select opt-out-host" }));
  await user.click(screen.getByRole("button", { name: "Preview hosts" }));
  expect(await screen.findByText("1 ready; 1 skipped. Preview changes no host.")).toBeInTheDocument();
  expect(screen.getByText("Local opt-in is off")).toBeInTheDocument();
  expect(start).not.toHaveBeenCalled();
  await user.click(screen.getByRole("button", { name: "Request approval" }));
  expect(await screen.findByRole("link", { name: "Open approval inbox" })).toHaveAttribute("href", "/approvals");
  expect(approval).toHaveBeenCalledWith({ plan: rollout.plan, plan_digest: rollout.plan_digest }, expect.any(String));
  await user.click(screen.getByRole("button", { name: "Start approved rollout" }));
  expect(await screen.findByText("Pending host receipts")).toBeInTheDocument();
  expect(preview).toHaveBeenCalledWith(expect.objectContaining({ agent_ids: [ready, skipped] }));
  expect(start).toHaveBeenCalledWith(expect.objectContaining({ approval_request_id: "approval", approval_intent_digest: "intent" }), expect.any(String));
});
it("shows rollback as attention required and removes stale completion after a failed refresh", async () => {
  const failed: SSHTrustFleetRollout = {
    ...rollout,
    state: "attention_required",
    hosts: [
      {
        ...rollout.hosts[0],
        state: "failed",
        receipt: {
          agent_id: ready,
          rollout_id: rollout.id,
          plan_digest: rollout.plan_digest,
          readiness_digest: "sha256:policy",
          ca_fingerprint: "SHA256:ca",
          state: "failed",
          reason_code: "apply_failed",
          phase: "health",
          rollback: "verified",
          changed: true,
          ca_read_back: false,
          effective_config_read_back: false,
          validated: true,
          reloaded: true,
          healthy: false,
          checked_at: rollout.created_at,
        },
      },
      rollout.hosts[1],
    ],
  };
  vi.spyOn(api, "sshTrustFleetRollouts").mockResolvedValue({ items: [failed] });
  const detail = vi.spyOn(api, "sshTrustFleetRollout").mockResolvedValue(failed);
  mount();
  const user = userEvent.setup();
  await user.click(await screen.findByRole("button", { name: "Inspect Owned hosts" }));
  expect(await screen.findByText("Prior configuration restored and checked")).toBeInTheDocument();
  expect(screen.getAllByText("Needs attention").length).toBeGreaterThan(0);
  detail.mockRejectedValue(new Error("source evidence unavailable"));
  await user.click(screen.getByRole("button", { name: "Refresh host receipts" }));
  await waitFor(() => expect(screen.queryByText("Prior configuration restored and checked")).not.toBeInTheDocument());
  expect(await screen.findByRole("alert")).toHaveTextContent("source evidence unavailable");
});
