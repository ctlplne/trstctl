import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { ThemeProvider } from "@/components/ThemeProvider";
import { AuthProvider } from "@/auth/AuthProvider";
import { AppRoutes } from "@/App";
import { ApiError, UnauthorizedError } from "@/lib/api";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    me: vi.fn(),
    identities: vi.fn(),
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

describe("dedicated approvals inbox", () => {
  beforeEach(() => {
    for (const mock of Object.values(apiMock)) mock.mockReset();
    apiMock.me.mockResolvedValue({ subject: "ra-1", tenant_id: "t1", email: "ra@example.test" });
    apiMock.approveIdentityAction.mockResolvedValue({ resource: "jit-1", action: "issue", approver: "ra", approvals: 2 });
    apiMock.auditEvents.mockResolvedValue([]);
    apiMock.exportAudit.mockResolvedValue({ format: "jws", bundle: "sealed" });
  });

  it("registers /approvals, points navigation there, and approves as a distinct principal", async () => {
    apiMock.identities.mockResolvedValue([
      {
        id: "jit-1",
        name: "jit-db",
        kind: "x509_certificate",
        owner_id: "owner-1",
        status: "requested",
        attributes: {
          requester: "dev@example.test",
          approvals: "1/2",
          grant_expires_at: "2026-06-19T18:00:00Z",
        },
      },
    ]);
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
    expect(within(row).getByRole("link", { name: /audit trail/i })).toHaveAttribute("href", "/audit?type=identity.approval&q=jit-1+issue");

    await user.click(within(row).getByRole("button", { name: /approve issue for jit-db/i }));

    await waitFor(() => expect(apiMock.approveIdentityAction).toHaveBeenCalledWith("jit-1", "issue"));
    expect(await screen.findByRole("status")).toHaveTextContent("issue approval recorded");
  });

  it("serves rotation approvals from the same inbox and posts the rotate action", async () => {
    apiMock.approveIdentityAction.mockResolvedValue({ resource: "rot-1", action: "rotate", approver: "ra", approvals: 2 });
    apiMock.identities.mockResolvedValue([
      {
        id: "rot-1",
        name: "rotating-db",
        kind: "x509_certificate",
        owner_id: "owner-1",
        status: "renewing",
        attributes: {
          requester: "sre@example.test",
          approvals: "1/2",
          grant_expires_at: "2026-06-19T18:00:00Z",
        },
      },
    ]);
    const user = userEvent.setup();
    renderAt("/approvals");

    const row = (await screen.findByText("rotating-db")).closest("tr")!;
    expect(within(row).getByRole("button", { name: /approve rotate for rotating-db/i })).toBeInTheDocument();
    expect(within(row).getByRole("link", { name: /audit trail/i })).toHaveAttribute("href", "/audit?type=identity.approval&q=rot-1+rotate");

    await user.click(within(row).getByRole("button", { name: /approve rotate for rotating-db/i }));

    await waitFor(() => expect(apiMock.approveIdentityAction).toHaveBeenCalledWith("rot-1", "rotate"));
    expect(await screen.findByRole("status")).toHaveTextContent("rotate approval recorded");
  });

  it("disables self-approval with an accessible explanation", async () => {
    apiMock.me.mockResolvedValue({ subject: "dev-1", tenant_id: "t1", email: "dev@example.test" });
    apiMock.identities.mockResolvedValue([
      {
        id: "jit-1",
        name: "own-request",
        kind: "x509_certificate",
        owner_id: "owner-1",
        status: "requested",
        attributes: { requester: "dev@example.test", approvals: "0/2" },
      },
    ]);
    renderAt("/approvals");

    const row = await screen.findByRole("row", { name: /own-request/i });
    const approve = within(row).getByRole("button", { name: /approve issue for own-request/i });
    expect(approve).toBeDisabled();
    expect(approve).toHaveAccessibleDescription(/requesters cannot approve their own request/i);
    expect(screen.getByText(/use a distinct approver/i)).toBeInTheDocument();
  });

  it("renders empty, loading, permission-denied, and problem states", async () => {
    apiMock.identities.mockResolvedValueOnce([]);
    const empty = renderAt("/approvals");
    expect(await screen.findByText("No pending approvals")).toBeInTheDocument();
    expect(empty.container.querySelector('[data-state-primitive="empty"]')).toBeInTheDocument();
    empty.unmount();

    apiMock.identities.mockReturnValueOnce(new Promise(() => undefined));
    const loading = renderAt("/approvals");
    expect(await screen.findByText(/loading approvals/i)).toBeInTheDocument();
    expect(loading.container.querySelector('[data-state-primitive="loading"]')).toBeInTheDocument();
    loading.unmount();

    apiMock.identities.mockRejectedValueOnce(new UnauthorizedError());
    const denied = renderAt("/approvals");
    expect(await screen.findByText("Permission denied")).toBeInTheDocument();
    expect(denied.container.querySelector('[data-state-primitive="permission-denied"]')).toBeInTheDocument();
    denied.unmount();

    apiMock.identities.mockRejectedValueOnce(new ApiError(503, JSON.stringify({ title: "Bulkhead shed", detail: "approval queue is shedding" })));
    const failed = renderAt("/approvals");
    expect(await screen.findByRole("alert")).toHaveTextContent(/approval queue is shedding/i);
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
