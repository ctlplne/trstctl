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
    issuanceRequests: vi.fn(),
    ticketIntakeSchedule: vi.fn(),
    approveApprovalRequest: vi.fn(),
    denyApprovalRequest: vi.fn(),
    approveIssuanceRequest: vi.fn(),
    denyIssuanceRequest: vi.fn(),
    approveEphemeralCredential: vi.fn(),
    approveIdentityAction: vi.fn(),
    auditEvents: vi.fn(),
    exportAudit: vi.fn(),
  },
}));

vi.mock("@/lib/bootstrapApi", async (orig) => {
  const actual = await orig<typeof import("@/lib/bootstrapApi")>();
  return { ...actual, bootstrapApi: apiMock };
});

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
    apiMock.issuanceRequests.mockResolvedValue({ items: [], open: 0, guidance: "" });
    apiMock.ticketIntakeSchedule.mockImplementation(async (system: "servicenow" | "jira") => ({
      configured: false,
      system,
      enabled: false,
      read_count: 0,
      pages_completed: 0,
      coverage_complete: false,
      eligible_count: 0,
      skipped_count: 0,
      guidance: "",
    }));
    apiMock.approveApprovalRequest.mockResolvedValue({
      id: "approval-request-1",
      status: "approved",
      approval_count: 2,
      required_approvals: 2,
    });
    apiMock.denyApprovalRequest.mockResolvedValue({
      id: "approval-request-1",
      status: "denied",
      approval_count: 1,
      required_approvals: 2,
    });
    apiMock.approveIssuanceRequest.mockImplementation(async (id: string) => ({
      id,
      tenant_id: "t1",
      subject: "payments-jit-mtls",
      owner_id: "owner-payments",
      profile: "service-mtls:4",
      requester: "requester@example.test",
      justification: "Temporary mTLS access for the approved deployment window",
      status: "approved",
      decided_by: "ra-1",
      expires_at: "2026-09-06T16:00:00Z",
      created_at: "2026-08-30T16:00:00Z",
    }));
    apiMock.denyIssuanceRequest.mockImplementation(async (id: string, reason: string) => ({
      id,
      tenant_id: "t1",
      subject: "payments-jit-mtls",
      owner_id: "owner-payments",
      profile: "service-mtls:4",
      requester: "requester@example.test",
      justification: "Temporary mTLS access for the approved deployment window",
      status: "denied",
      decided_by: "ra-1",
      decision_reason: reason,
      expires_at: "2026-09-06T16:00:00Z",
      created_at: "2026-08-30T16:00:00Z",
    }));
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

  it("answers what needs approval before revealing request history and specialized tools", async () => {
    apiMock.issuanceRequests.mockResolvedValue({
      items: [
        {
          id: "issuance-request-issued-1",
          tenant_id: "t1",
          subject: "qa-design-partner-mtls",
          requester: "demo-admin",
          status: "issued",
          created_at: "2026-06-19T17:00:00Z",
          expires_at: "2026-06-19T18:00:00Z",
          issued_by: "se-demo-operator",
          justification: "Design-partner QA proof for a service mTLS certificate",
        },
      ],
      open: 0,
      guidance: "",
    });
    const user = userEvent.setup();
    renderAt("/approvals");

    expect(await screen.findByRole("heading", { level: 1, name: "Requests waiting for approval" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Requests waiting for approval" })).toHaveAttribute("href", "/approvals");
    expect(screen.getByText("What change is requested, why, and its consequence.", { exact: true })).toBeInTheDocument();
    expect(screen.getByText("Policy result, requester, evidence, dual-control history.", { exact: true })).toBeInTheDocument();
    expect(await screen.findByRole("heading", { level: 2, name: "Nothing needs approval right now" })).toBeInTheDocument();
    expect(screen.getByText("0 requests are waiting for a decision", { exact: true })).toBeInTheDocument();

    const actions = screen.getByTestId("page-depth-operate");
    expect(within(actions).getAllByRole("button")).toHaveLength(1);
    expect(within(actions).getByRole("button", { name: "Review request" })).toBeDisabled();
    expect(screen.queryByRole("form")).not.toBeInTheDocument();
    expect(screen.queryByRole("table")).not.toBeInTheDocument();
    expect(document.querySelectorAll("main input, main select, main textarea")).toHaveLength(0);
    expect(apiMock.ticketIntakeSchedule).not.toHaveBeenCalled();

    for (const title of ["All pending requests and evidence", "Issuance request lifecycle and history", "Specialized approval tools"]) {
      expect(screen.getByText(title, { exact: true }).closest("details")).not.toHaveAttribute("open");
    }

    await user.click(screen.getByText("Issuance request lifecycle and history", { exact: true }));
    expect(await screen.findByRole("heading", { name: "Issuance requests" })).toBeInTheDocument();
    expect(screen.getByText("qa-design-partner-mtls", { exact: true })).toBeInTheDocument();
    await waitFor(() => expect(apiMock.ticketIntakeSchedule).toHaveBeenCalledTimes(2));

    await user.click(screen.getByText("Specialized approval tools", { exact: true }));
    expect(screen.getByRole("form", { name: "Approve ephemeral credential" })).toBeInTheDocument();
  });

  it("reviews a first-class JIT certificate request directly, then reveals the safe issuance step", async () => {
    apiMock.issuanceRequests.mockResolvedValue({
      items: [
        {
          id: "issuance-request-jit-1",
          tenant_id: "t1",
          subject: "payments-jit-mtls",
          owner_id: "owner-payments",
          profile: "service-mtls:4",
          requester: "requester@example.test",
          justification: "Temporary mTLS access for the approved deployment window",
          status: "requested",
          expires_at: "2026-09-06T16:00:00Z",
          created_at: "2026-08-30T16:00:00Z",
        },
      ],
      open: 1,
      guidance: "Approval is a decision; issuance is a separate, recoverable step.",
    });
    const user = userEvent.setup();
    renderAt("/approvals");

    expect(await screen.findByRole("heading", { name: "Issue a credential for payments-jit-mtls" })).toBeInTheDocument();
    await user.click(screen.getByTestId("page-depth-operate").querySelector("button")!);

    const dialog = screen.getByRole("dialog", { name: "Review request" });
    expect(within(dialog).getByText("Temporary mTLS access for the approved deployment window")).toBeInTheDocument();
    expect(within(dialog).getByText("service-mtls:4")).toBeInTheDocument();
    expect(within(dialog).getByText("owner-payments")).toBeInTheDocument();
    expect(within(dialog).getByText("issuance-request-jit-1")).toBeInTheDocument();
    expect(within(dialog).getAllByText(/permits a separate issuance step/i).length).toBeGreaterThan(0);
    expect(within(dialog).getByRole("link", { name: /audit trail/i })).toHaveAttribute("href", "/audit?q=issuance-request-jit-1");

    await user.click(within(dialog).getByRole("button", { name: "Approve request" }));
    await waitFor(() => expect(apiMock.approveIssuanceRequest).toHaveBeenCalledWith("issuance-request-jit-1"));
    expect(await screen.findByRole("status")).toHaveTextContent(/issue approval recorded/i);
    expect(screen.getByText("Issuance request lifecycle and history", { exact: true }).closest("details")).toHaveAttribute("open");
  });

  it("requires a reason before denying a first-class JIT certificate request", async () => {
    apiMock.issuanceRequests.mockResolvedValue({
      items: [
        {
          id: "issuance-request-jit-deny",
          tenant_id: "t1",
          subject: "payments-jit-mtls",
          owner_id: "owner-payments",
          profile: "service-mtls:4",
          requester: "requester@example.test",
          justification: "Temporary mTLS access for the approved deployment window",
          status: "requested",
          expires_at: "2026-09-06T16:00:00Z",
          created_at: "2026-08-30T16:00:00Z",
        },
      ],
      open: 1,
      guidance: "",
    });
    const user = userEvent.setup();
    renderAt("/approvals");

    await user.click(await screen.findByRole("button", { name: "Review request" }));
    const dialog = screen.getByRole("dialog", { name: "Review request" });
    await user.click(within(dialog).getByRole("button", { name: "Reject request" }));
    const reason = within(dialog).getByRole("textbox", { name: "Why is this request being rejected?" });
    await user.type(reason, "The requested host is outside the approved deployment scope.");
    await user.click(within(dialog).getByRole("button", { name: "Record rejection" }));

    await waitFor(() =>
      expect(apiMock.denyIssuanceRequest).toHaveBeenCalledWith("issuance-request-jit-deny", "The requested host is outside the approved deployment scope."),
    );
    expect(await screen.findByRole("status")).toHaveTextContent(/issue request rejected/i);
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

    expect(await screen.findByRole("heading", { name: "Nothing needs approval right now" })).toBeInTheDocument();
    expect(screen.queryByRole("table", { name: "Pending approval requests" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /approve revoke for/i })).not.toBeInTheDocument();
    expect(apiMock.approvalRequests).toHaveBeenCalledTimes(1);
    expect(apiMock.identities).not.toHaveBeenCalled();
  });

  it("AUD-77 approves a genuine served request by immutable request id and digest", async () => {
    apiMock.identities.mockResolvedValue([]);
    apiMock.approvalRequests.mockResolvedValue([approvalRequest()]);
    const user = userEvent.setup();

    renderAt("/approvals");

    expect(await screen.findByRole("heading", { name: "Issue a credential for jit-db" })).toBeInTheDocument();
    expect(screen.getByText("This permits a separate issuance step. It does not mint a credential by itself.")).toBeInTheDocument();
    await user.click(screen.getByTestId("page-depth-operate").querySelector("button")!);
    const dialog = screen.getByRole("dialog", { name: "Review request" });
    await waitFor(() => expect(within(dialog).getByRole("heading", { name: "Review request" })).toHaveFocus());
    expect(within(dialog).getByText("approval-request-1")).toBeInTheDocument();
    expect(within(dialog).getByText("transition:0")).toBeInTheDocument();
    expect(within(dialog).getAllByText("issue the requested workload credential").length).toBeGreaterThan(0);
    expect(within(dialog).getByText("ticket:SEC-77")).toBeInTheDocument();
    expect(within(dialog).getByText("sha256:8ec59a9c")).toBeInTheDocument();
    expect(within(dialog).getByText(/does not mint a credential by itself/i)).toBeInTheDocument();
    expect(within(dialog).getByText(/server placed this exact intent in the protected queue/i)).toBeInTheDocument();
    await user.click(within(dialog).getByRole("button", { name: "Approve request" }));

    await waitFor(() => expect(apiMock.approveApprovalRequest).toHaveBeenCalledWith("approval-request-1", "sha256:8ec59a9c"));
    expect(apiMock.approveIdentityAction).not.toHaveBeenCalled();
  });

  it("reviews consequence and records a reasoned rejection against the immutable intent", async () => {
    apiMock.approvalRequests.mockResolvedValue([approvalRequest({ action: "revoke", reason: "credential confirmed compromised" })]);
    const user = userEvent.setup();
    renderAt("/approvals");

    expect(await screen.findByText(/can interrupt systems still using the credential/i)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Review request" }));
    const dialog = screen.getByRole("dialog", { name: "Review request" });
    expect(dialog).toHaveClass("max-h-[calc(100dvh-2rem)]", "overflow-y-auto", "overscroll-contain");
    expect(within(dialog).getByText(/credential values and private keys never enter this review/i)).toBeInTheDocument();
    expect(dialog.textContent).not.toMatch(/BEGIN .* PRIVATE KEY|raw token/i);
    await user.click(within(dialog).getByRole("button", { name: "Reject request" }));
    await user.type(within(dialog).getByRole("textbox", { name: "Why is this request being rejected?" }), "Evidence does not justify the outage");
    await user.click(within(dialog).getByRole("button", { name: "Record rejection" }));

    await waitFor(() =>
      expect(apiMock.denyApprovalRequest).toHaveBeenCalledWith("approval-request-1", "sha256:8ec59a9c", "Evidence does not justify the outage"),
    );
    expect(apiMock.approveApprovalRequest).not.toHaveBeenCalled();
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

    await user.click(await screen.findByText("Specialized approval tools", { exact: true }));
    const form = screen.getByRole("form", { name: "Approve ephemeral credential" });
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

    expect(await screen.findByRole("heading", { name: "Requests waiting for approval" })).toBeInTheDocument();
    // S-C1: the Platform space's sidebar row points here; the "Pending
    // approvals" urgency worklist lives on the Home plane's sidebar.
    expect(screen.getByRole("link", { name: /^Requests waiting for approval$/i })).toHaveAttribute("href", "/approvals");
    expect(await screen.findByText("dev@example.test")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Review request" }));
    const dialog = screen.getByRole("dialog", { name: "Review request" });
    // S-C18: the quorum renders structured have/need plus what is still
    // outstanding, so the raw "1/2" string is now split across elements.
    expect(within(dialog).getByText("1/2")).toBeInTheDocument();
    expect(within(dialog).getByRole("link", { name: /audit trail/i })).toHaveAttribute("href", "/audit?q=approval-request-1+sha256%3A8ec59a9c");

    await user.click(within(dialog).getByRole("button", { name: "Approve request" }));

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

    expect(await screen.findByRole("heading", { name: "Rotate rotating-db" })).toBeInTheDocument();
    expect(screen.getByText(/current credential stays unchanged until execution/i)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Review request" }));
    const dialog = screen.getByRole("dialog", { name: "Review request" });
    expect(within(dialog).getByRole("link", { name: /audit trail/i })).toHaveAttribute("href", "/audit?q=rotation-request-1+sha256%3Arotate");

    await user.click(within(dialog).getByRole("button", { name: "Approve request" }));

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

    expect(await screen.findByRole("heading", { name: "Create payments/database" })).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Review request" }));
    await user.click(within(screen.getByRole("dialog", { name: "Review request" })).getByRole("button", { name: "Approve request" }));

    await waitFor(() => expect(apiMock.approveApprovalRequest).toHaveBeenCalledWith("secret-create-request-1", "sha256:secret-create"));
    expect(apiMock.approveIdentityAction).not.toHaveBeenCalled();
  });

  it("disables self-approval with an accessible explanation", async () => {
    apiMock.me.mockResolvedValue({ permissions: ["*"], subject: "dev-1", tenant_id: "t1", email: "dev@example.test" });
    apiMock.approvalRequests.mockResolvedValue([approvalRequest({ resource_name: "own-request", requester: "dev@example.test", approval_count: 0 })]);
    renderAt("/approvals");

    await screen.findByRole("heading", { name: "1 request is waiting" });
    const primaryReview = screen.getByRole("button", { name: "Review request" });
    expect(primaryReview).toBeDisabled();
    expect(primaryReview).toHaveAccessibleDescription(/different person must decide/i);
    const user = userEvent.setup();
    await user.click(screen.getByText("All pending requests and evidence", { exact: true }));
    expect(await screen.findByRole("group", { name: "Scrollable columns for Pending approval requests" })).toHaveAttribute("tabindex", "0");
    const row = await screen.findByRole("row", { name: /own-request/i });
    await user.click(within(row).getByRole("button", { name: "Review request" }));
    const dialog = screen.getByRole("dialog", { name: "Review request" });
    const approve = within(dialog).getByRole("button", { name: "Approve request" });
    expect(approve).toBeDisabled();
    expect(approve).toHaveAccessibleDescription(/different person must approve or reject/i);
    expect(within(dialog).getByText(/audit record proves an independent review/i)).toBeInTheDocument();
  });

  it("renders empty, loading, permission-denied, and problem states", async () => {
    apiMock.approvalRequests.mockResolvedValueOnce([]);
    const empty = renderAt("/approvals");
    expect(await screen.findByRole("heading", { name: "Nothing needs approval right now" })).toBeInTheDocument();
    await userEvent.setup().click(screen.getByText("All pending requests and evidence", { exact: true }));
    expect(empty.container.querySelector('[data-state-primitive="empty"]')).toBeInTheDocument();
    empty.unmount();

    apiMock.approvalRequests.mockReturnValueOnce(new Promise(() => undefined));
    const loading = renderAt("/approvals");
    expect(await screen.findByRole("heading", { name: /checking what needs approval/i })).toBeInTheDocument();
    await userEvent.setup().click(screen.getByText("All pending requests and evidence", { exact: true }));
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

    await screen.findByRole("heading", { name: "Change history" });
    await waitFor(() =>
      expect(apiMock.auditEvents).toHaveBeenCalledWith(
        {
          type: "identity.approval",
          q: "jit-1 issue",
          limit: 50,
        },
        expect.any(AbortSignal),
      ),
    );
  });
});
