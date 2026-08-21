import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { Operations } from "@/pages/Operations";
import { AppQueryProvider } from "@/lib/query";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    rotationRuns: vi.fn(),
    connectorDeliveries: vi.fn(),
    approvalRequests: vi.fn(),
    approveApprovalRequest: vi.fn(),
    denyApprovalRequest: vi.fn(),
    agentJobPosture: vi.fn(),
    bulkheadStats: vi.fn(),
    transitionIdentity: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});

function renderOperations() {
  return render(
    <AppQueryProvider>
      <MemoryRouter>
        <Operations />
      </MemoryRouter>
    </AppQueryProvider>,
  );
}

describe("C10-2 operations queue", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    for (const mock of Object.values(apiMock)) mock.mockReset();
    apiMock.rotationRuns.mockResolvedValue({
      items: [
        {
          id: "rot-1",
          identity_id: "id-rot",
          status: "running",
          trigger: "expiry-window",
          predecessor_fingerprint: "sha256:old",
          successor_fingerprint: "sha256:new",
          created_at: "2026-06-26T10:00:00Z",
          updated_at: "2026-06-26T10:03:00Z",
          tenant_id: "t1",
        },
      ],
    });
    apiMock.connectorDeliveries.mockResolvedValue({
      items: [
        {
          id: "dep-1",
          connector: "kubernetes",
          destination: "cluster/prod",
          target: "ns/payments",
          status: "delivered",
          attempts: 2,
          fingerprint: "sha256:live",
          identity_id: "id-dep",
          created_at: "2026-06-26T10:01:00Z",
          updated_at: "2026-06-26T10:04:00Z",
          tenant_id: "t1",
        },
      ],
    });
    apiMock.approvalRequests.mockResolvedValue([
      {
        id: "019fec49-6641-7131-ae7f-17f7ea4b5e0e",
        intent_digest: "sha256:jit-db",
        resource_id: "jit-1",
        resource_name: "jit-db",
        resource_kind: "identity",
        action: "issue",
        requester: "dev@example.test",
        target_version: "transition:0",
        evidence_refs: [],
        approval_count: 1,
        required_approvals: 3,
        status: "pending",
        created_at: "2026-06-26T10:01:00Z",
        expires_at: "2026-06-26T11:01:00Z",
      },
    ]);
    apiMock.approveApprovalRequest.mockResolvedValue({
      id: "019fec49-6641-7131-ae7f-17f7ea4b5e0e",
      intent_digest: "sha256:jit-db",
      resource: "jit-1",
      action: "issue",
      approver: "ra@example.test",
      approvals: 2,
      approval_count: 2,
      required_approvals: 3,
      status: "pending",
    });
    apiMock.denyApprovalRequest.mockResolvedValue({
      id: "019fec49-6641-7131-ae7f-17f7ea4b5e0e",
      intent_digest: "sha256:jit-db",
      resource: "jit-1",
      action: "issue",
      approver: "ra@example.test",
      status: "denied",
    });
    apiMock.transitionIdentity.mockResolvedValue({
      id: "jit-1",
      name: "jit-db",
      kind: "x509_certificate",
      status: "retired",
      owner_id: "owner-1",
    });
    apiMock.agentJobPosture.mockResolvedValue({ served: true, generated_at: "2026-06-26T10:05:00Z", claimable_kinds: [], queues: [] });
    apiMock.bulkheadStats.mockResolvedValue({ served: true, pools: [] });
  });

  it("renders operations, filters them, records approval decisions, and fails closed for missing cancel support", async () => {
    const user = userEvent.setup();
    renderOperations();

    expect(await screen.findByRole("heading", { name: "Jobs and queues" })).toBeInTheDocument();
    await waitFor(() => expect(apiMock.rotationRuns).toHaveBeenCalledWith({ limit: 50 }));
    expect(apiMock.connectorDeliveries).toHaveBeenCalledWith({ limit: 50 });
    expect(apiMock.approvalRequests).toHaveBeenCalled();

    const attention = screen.getByRole("list", { name: "Jobs needing attention" });
    const rotationRow = within(attention).getByText("Rotate an identity").closest("li")!;
    expect(within(rotationRow).getByText("Running")).toBeInTheDocument();
    expect(screen.queryByText("rot-1")).not.toBeInTheDocument();
    await user.click(within(rotationRow).getByRole("button", { name: "Review Rotate an identity" }));
    const rotationDialog = await screen.findByRole("dialog", { name: "Job: Rotate an identity" });
    expect(within(rotationDialog).getByText("rot-1")).toBeInTheDocument();
    expect(within(rotationDialog).queryByRole("button", { name: /cancel/i })).not.toBeInTheDocument();
    await user.click(within(rotationDialog).getByRole("button", { name: "Close" }));

    await user.click(screen.getByText("All jobs and filters"));
    expect(screen.getByRole("combobox", { name: "Status filter" })).toBeInTheDocument();
    expect(screen.getByRole("combobox", { name: "Type filter" })).toBeInTheDocument();
    const allJobs = screen.getByRole("list", { name: "All jobs" });
    expect(within(allJobs).getByText("Deploy to Prod")).toBeInTheDocument();

    const approvalRow = within(attention).getByText("Approve Issue for jit-db").closest("li")!;
    expect(within(approvalRow).getByText("Awaiting approval")).toBeInTheDocument();
    await user.click(within(approvalRow).getByRole("button", { name: "Approve issue for jit-db" }));
    await waitFor(() => expect(apiMock.approveApprovalRequest).toHaveBeenCalledWith("019fec49-6641-7131-ae7f-17f7ea4b5e0e", "sha256:jit-db"));
    expect(await screen.findByRole("status")).toHaveTextContent("issue approval recorded for jit-db");

    await user.click(within(approvalRow).getByRole("button", { name: "Reject issue for jit-db" }));
    const dialog = await screen.findByRole("dialog", { name: "Reject issue for jit-db" });
    await user.type(within(dialog).getByLabelText("Reason"), "missing CAB approval");
    await user.click(within(dialog).getByRole("button", { name: "Reject request" }));
    await waitFor(() =>
      expect(apiMock.denyApprovalRequest).toHaveBeenCalledWith("019fec49-6641-7131-ae7f-17f7ea4b5e0e", "sha256:jit-db", "missing CAB approval"),
    );
    expect(apiMock.transitionIdentity).not.toHaveBeenCalled();

    expect(screen.queryByRole("button", { name: /cancel rot-1/i })).not.toBeInTheDocument();
  });
});
