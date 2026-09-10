import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, within, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { ThemeProvider } from "@/components/ThemeProvider";
import { AuthProvider } from "@/auth/AuthProvider";
import { AppRoutes } from "@/App";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    me: vi.fn(),
    authMethods: vi.fn().mockResolvedValue({ oidc: true, saml: false, ldap: false }),
    approvalRequests: vi.fn(),
    issuanceRequests: vi.fn(),
    approveApprovalRequest: vi.fn(),
    auditEvents: vi.fn(),
    exportAudit: vi.fn(),
  },
}));

vi.mock("@/lib/bootstrapApi", async (orig) => {
  const actual = await orig<typeof import("@/lib/bootstrapApi")>();
  return { ...actual, bootstrapApi: { ...actual.bootstrapApi, ...apiMock } };
});

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
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

const pending = {
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
  required_approvals: 2,
  status: "pending",
  created_at: "2026-06-19T17:00:00Z",
  expires_at: "2026-06-19T18:00:00Z",
};

beforeEach(() => {
  for (const mock of Object.values(apiMock)) mock.mockReset();
  apiMock.authMethods.mockResolvedValue({ oidc: true, saml: false, ldap: false });
  apiMock.issuanceRequests.mockResolvedValue({ items: [], open: 0, guidance: "" });
  apiMock.approveApprovalRequest.mockResolvedValue({
    id: pending.id,
    intent_digest: pending.intent_digest,
    resource: pending.resource_id,
    action: pending.action,
    approver: "ra",
    approvals: 2,
    approval_count: 2,
    required_approvals: 2,
    status: "approved",
  });
  apiMock.auditEvents.mockResolvedValue([]);
  apiMock.exportAudit.mockResolvedValue({ format: "jws", bundle: "sealed" });
});

describe("U8-4 self-service approvals inbox", () => {
  it("approves a pending action as a distinct principal through the served endpoint", async () => {
    apiMock.me.mockResolvedValue({ permissions: ["*"], subject: "ra-1", tenant_id: "t1", email: "ra@example.test" });
    apiMock.approvalRequests.mockResolvedValue([pending]);
    const user = userEvent.setup();
    renderAt("/approvals");

    await screen.findByRole("heading", { name: "Issue a credential for jit-db" });
    await user.click(screen.getByRole("button", { name: "Review request" }));
    await user.click(within(screen.getByRole("dialog", { name: "Review request" })).getByRole("button", { name: "Approve request" }));
    await waitFor(() => expect(apiMock.approveApprovalRequest).toHaveBeenCalledWith(pending.id, pending.intent_digest));
  });

  it("blocks self-approval of one's own request", async () => {
    apiMock.me.mockResolvedValue({ permissions: ["*"], subject: "dev-1", tenant_id: "t1", email: "dev@example.test" });
    apiMock.approvalRequests.mockResolvedValue([{ ...pending, resource_name: "own-request" }]);
    renderAt("/approvals");

    await screen.findByRole("heading", { name: "1 request is waiting" });
    expect(screen.getByRole("button", { name: "Review request" })).toBeDisabled();
  });
});
