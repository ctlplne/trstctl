import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { ThemeProvider } from "@/components/ThemeProvider";
import { AuthProvider } from "@/auth/AuthProvider";
import { AppRoutes } from "@/App";
import { ApiError, UnauthorizedError, type PendingApprovalRequest } from "@/lib/api";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    me: vi.fn(),
    authMethods: vi.fn().mockResolvedValue({ oidc: true, saml: false, ldap: false }),
    identities: vi.fn(),
    approvalRequests: vi.fn(),
    approveApprovalRequest: vi.fn(),
    approveEphemeralCredential: vi.fn(),
    approveIdentityAction: vi.fn(),
    auditEvents: vi.fn(),
    exportAudit: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: apiMock };
});

function renderAt(path: string) {
  return render(
    <ThemeProvider>
      <AuthProvider>
        <MemoryRouter initialEntries={[path]}>
          <AppRoutes />
        </MemoryRouter>
      </AuthProvider>
    </ThemeProvider>,
  );
}

function approvalRequest(overrides: Partial<PendingApprovalRequest> = {}): PendingApprovalRequest {
  return {
    id: "approval-request-1",
    intent_digest: "sha256:8ec59a9c",
    resource_id: "jit-1",
    resource_name: "jit-db",
    resource_kind: "identity",
    action: "issue",
    requester: "dev@example.test",
    target_version: "transition:0",
    reason: "issue the requested workload credential",
    evidence_refs: ["ticket:SEC-77"],
    approval_count: 1,
    required_approvals: 2,
    status: "pending",
    created_at: "2026-06-19T17:00:00Z",
    expires_at: "2026-06-19T18:00:00Z",
    ...overrides,
  };
}

describe("dedicated approvals inbox", () => {
  beforeEach(() => {
    for (const mock of Object.values(apiMock)) mock.mockReset();
    apiMock.authMethods.mockResolvedValue({ oidc: true, saml: false, ldap: false });
    apiMock.me.mockResolvedValue({ permissions: ["*"], subject: "ra-1", tenant_id: "t1", email: "ra@example.test" });
    apiMock.approvalRequests.mockResolvedValue([]);
    apiMock.approveApprovalRequest.mockResolvedValue({
      id: "approval-request-1",
      status: "approved",
      approval_count: 2,
      required_approvals: 2,
    });
    apiMock.approveEphemeralCredential.mockResolvedValue({
      id: "019fec49-6641-7131-ae7f-17f7ea4b5e0e",
      intent_digest: "sha256:ephemeral",
      resource: "jit-client-7",
      action: "issue",
      approver: "ra-1",
      approvals: 1,
      approval_count: 1,
      required_approvals: 2,
      status: "pending",
    });
    apiMock.approveIdentityAction.mockResolvedValue({ resource: "jit-1", action: "issue", approver: "ra", approvals: 2 });
    apiMock.auditEvents.mockResolvedValue([]);
    apiMock.exportAudit.mockResolvedValue({ format: "jws", bundle: "sealed" });
  });

  it("AUD-77 does not invent approval rows from issued or deployed identities", async () => {
    apiMock.identities.mockResolvedValue([
      {
        id: "issued-1",
        name: "issued-without-request",
        kind: "x509_certificate",
        owner_id: "owner-1",
        status: "issued",
      },
      {
        id: "deployed-1",
        name: "deployed-without-request",
        kind: "x509_certificate",
        owner_id: "owner-1",
        status: "deployed",
      },
    ]);
    apiMock.approvalRequests.mockResolvedValue([]);

    renderAt("/approvals");

    expect(await screen.findByText("No pending approvals")).toBeInTheDocument();
    expect(screen.queryByRole("table", { name: "Pending approvals" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /approve revoke for/i })).not.toBeInTheDocument();
    expect(apiMock.approvalRequests).toHaveBeenCalledTimes(1);
    expect(apiMock.identities).not.toHaveBeenCalled();
  });

  it("AUD-77 approves a genuine served request by immutable request id and digest", async () => {
    apiMock.identities.mockResolvedValue([]);
    apiMock.approvalRequests.mockResolvedValue([approvalRequest()]);
    const user = userEvent.setup();

    renderAt("/approvals");

    const row = (await screen.findByText("jit-db")).closest("tr")!;
    expect(within(row).getByText("approval-request-1")).toBeInTheDocument();
    expect(within(row).getByText("transition:0")).toBeInTheDocument();
    expect(within(row).getByText("issue the requested workload credential")).toBeInTheDocument();
    expect(within(row).getByText("ticket:SEC-77")).toBeInTheDocument();
    expect(within(row).getByText("sha256:8ec59a9c")).toBeInTheDocument();
    await user.click(within(row).getByRole("button", { name: /approve issue for jit-db/i }));

    await waitFor(() => expect(apiMock.approveApprovalRequest).toHaveBeenCalledWith("approval-request-1", "sha256:8ec59a9c"));
    expect(apiMock.approveIdentityAction).not.toHaveBeenCalled();
  });

  it("binds an ephemeral client request id to the genuine queue UUID and digest", async () => {
    apiMock.approvalRequests.mockResolvedValue([
      approvalRequest({
        id: "019fec49-6641-7131-ae7f-17f7ea4b5e0e",
        intent_digest: "sha256:ephemeral",
        resource_id: "jit-client-7",
        resource_name: "ephemeral jit-client-7",
        resource_kind: "ephemeral",
      }),
    ]);
    const user = userEvent.setup();

    renderAt("/approvals");

    const form = await screen.findByRole("form", { name: "Approve ephemeral credential" });
    await user.type(within(form).getByRole("textbox", { name: "Request ID" }), "jit-client-7");
    await user.click(within(form).getByRole("button", { name: "Approve issue" }));

    await waitFor(() =>
      expect(apiMock.approveEphemeralCredential).toHaveBeenCalledWith("019fec49-6641-7131-ae7f-17f7ea4b5e0e", {
        action: "issue",
        request_id: "019fec49-6641-7131-ae7f-17f7ea4b5e0e",
        intent_digest: "sha256:ephemeral",
      }),
    );
  });

  it("registers /approvals, points navigation there, and approves as a distinct principal", async () => {
    apiMock.approvalRequests.mockResolvedValue([approvalRequest()]);
    const user = userEvent.setup();
    renderAt("/approvals");

    expect(await screen.findByRole("heading", { name: "Approvals" })).toBeInTheDocument();
    // S-C1: the Platform space's sidebar row points here; the "Pending
    // approvals" urgency worklist lives on the Home plane's sidebar.
    expect(screen.getByRole("link", { name: /^Approvals$/i })).toHaveAttribute("href", "/approvals");
    const row = (await screen.findByText("jit-db")).closest("tr")!;
    expect(within(row).getByText("dev@example.test")).toBeInTheDocument();
    // S-C18: the quorum renders structured have/need plus what is still
    // outstanding, so the raw "1/2" string is now split across elements.
    expect(within(row).getByText("1")).toBeInTheDocument();
    expect(within(row).getByText("2")).toBeInTheDocument();
    expect(within(row).getByText("1 more needed")).toBeInTheDocument();
    expect(within(row).getByText("2026-06-19T18:00:00Z")).toBeInTheDocument();
    expect(within(row).getByRole("link", { name: /audit trail/i })).toHaveAttribute("href", "/audit?q=approval-request-1+sha256%3A8ec59a9c");

    await user.click(within(row).getByRole("button", { name: /approve issue for jit-db/i }));

    await waitFor(() => expect(apiMock.approveApprovalRequest).toHaveBeenCalledWith("approval-request-1", "sha256:8ec59a9c"));
    expect(apiMock.approveIdentityAction).not.toHaveBeenCalled();
    expect(await screen.findByRole("status")).toHaveTextContent("issue approval recorded");
  });

  it("serves rotation approvals from the same inbox and posts the rotate action", async () => {
    apiMock.approveApprovalRequest.mockResolvedValue({ id: "rotation-request-1", status: "approved", approval_count: 2, required_approvals: 2 });
    apiMock.approvalRequests.mockResolvedValue([
      approvalRequest({
        id: "rotation-request-1",
        intent_digest: "sha256:rotate",
        resource_id: "rot-1",
        resource_name: "rotating-db",
        action: "rotate",
        requester: "sre@example.test",
        target_version: "transition:8",
      }),
    ]);
    const user = userEvent.setup();
    renderAt("/approvals");

    const row = (await screen.findByText("rotating-db")).closest("tr")!;
    expect(within(row).getByRole("button", { name: /approve rotate for rotating-db/i })).toBeInTheDocument();
    expect(within(row).getByRole("link", { name: /audit trail/i })).toHaveAttribute("href", "/audit?q=rotation-request-1+sha256%3Arotate");

    await user.click(within(row).getByRole("button", { name: /approve rotate for rotating-db/i }));

    await waitFor(() => expect(apiMock.approveApprovalRequest).toHaveBeenCalledWith("rotation-request-1", "sha256:rotate"));
    expect(apiMock.approveIdentityAction).not.toHaveBeenCalled();
    expect(await screen.findByRole("status")).toHaveTextContent("rotate approval recorded");
  });

  it("renders a genuine secret-create request and decides its exact immutable intent", async () => {
    apiMock.approvalRequests.mockResolvedValue([
      approvalRequest({
        id: "secret-create-request-1",
        intent_digest: "sha256:secret-create",
        resource_id: "secret:payments/database",
        resource_name: "payments/database",
        resource_kind: "secret",
        action: "create",
        requester: "platform@example.test",
        target_version: "secret:0",
      }),
    ]);
    const user = userEvent.setup();
    renderAt("/approvals");

    const row = (await screen.findByText("payments/database")).closest("tr")!;
    await user.click(within(row).getByRole("button", { name: /approve create for payments\/database/i }));

    await waitFor(() => expect(apiMock.approveApprovalRequest).toHaveBeenCalledWith("secret-create-request-1", "sha256:secret-create"));
    expect(apiMock.approveIdentityAction).not.toHaveBeenCalled();
  });

  it("disables self-approval with an accessible explanation", async () => {
    apiMock.me.mockResolvedValue({ permissions: ["*"], subject: "dev-1", tenant_id: "t1", email: "dev@example.test" });
    apiMock.approvalRequests.mockResolvedValue([approvalRequest({ resource_name: "own-request", requester: "dev@example.test", approval_count: 0 })]);
    renderAt("/approvals");

    const row = await screen.findByRole("row", { name: /own-request/i });
    const approve = within(row).getByRole("button", { name: /approve issue for own-request/i });
    expect(approve).toBeDisabled();
    expect(approve).toHaveAccessibleDescription(/requesters cannot approve their own request/i);
    expect(screen.getByText(/use a distinct approver/i)).toBeInTheDocument();
  });

  it("renders empty, loading, permission-denied, and problem states", async () => {
    apiMock.approvalRequests.mockResolvedValueOnce([]);
    const empty = renderAt("/approvals");
    expect(await screen.findByText("No pending approvals")).toBeInTheDocument();
    expect(empty.container.querySelector('[data-state-primitive="empty"]')).toBeInTheDocument();
    empty.unmount();

    apiMock.approvalRequests.mockReturnValueOnce(new Promise(() => undefined));
    const loading = renderAt("/approvals");
    expect(await screen.findByText(/loading approvals/i)).toBeInTheDocument();
    expect(loading.container.querySelector('[data-state-primitive="loading"]')).toBeInTheDocument();
    loading.unmount();

    apiMock.approvalRequests.mockRejectedValue(new UnauthorizedError());
    const denied = renderAt("/approvals");
    expect(await screen.findByText("Permission denied", {}, { timeout: 3_000 })).toBeInTheDocument();
    expect(denied.container.querySelector('[data-state-primitive="permission-denied"]')).toBeInTheDocument();
    denied.unmount();

    apiMock.approvalRequests.mockReset();
    apiMock.approvalRequests.mockRejectedValue(new ApiError(503, JSON.stringify({ title: "Bulkhead shed", detail: "approval queue is shedding" })));
    const failed = renderAt("/approvals");
    expect(await screen.findByRole("alert", {}, { timeout: 3_000 })).toHaveTextContent(/approval queue is shedding/i);
    expect(failed.container.querySelector('[data-state-primitive="error"]')).toBeInTheDocument();
  });

  it("applies audit query params from approval evidence links", async () => {
    apiMock.identities.mockResolvedValue([]);
    renderAt("/audit?type=identity.approval&q=jit-1+issue");

    await screen.findByRole("heading", { name: "Audit" });
    await waitFor(() =>
      expect(apiMock.auditEvents).toHaveBeenCalledWith({
        type: "identity.approval",
        q: "jit-1 issue",
        limit: 50,
      }),
    );
  });
});
