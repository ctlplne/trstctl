import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, within, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { ThemeProvider } from "@/components/ThemeProvider";
import { AuthProvider } from "@/auth/AuthProvider";
import { AppRoutes } from "@/App";

const { apiMock } = vi.hoisted(() => ({
  apiMock: { me: vi.fn(), identities: vi.fn(), approveIdentityAction: vi.fn(), auditEvents: vi.fn(), exportAudit: vi.fn() },
}));

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
  id: "jit-1",
  name: "jit-db",
  kind: "x509_certificate",
  owner_id: "owner-1",
  status: "requested",
  attributes: { requester: "dev@example.test", approvals: "1/2", grant_expires_at: "2026-06-19T18:00:00Z" },
};

beforeEach(() => {
  for (const mock of Object.values(apiMock)) mock.mockReset();
  apiMock.approveIdentityAction.mockResolvedValue({ resource: "jit-1", action: "issue", approver: "ra", approvals: 2 });
  apiMock.auditEvents.mockResolvedValue([]);
  apiMock.exportAudit.mockResolvedValue({ format: "jws", bundle: "sealed" });
});

describe("U8-4 self-service approvals inbox", () => {
  it("approves a pending action as a distinct principal through the served endpoint", async () => {
    apiMock.me.mockResolvedValue({ subject: "ra-1", tenant_id: "t1", email: "ra@example.test" });
    apiMock.identities.mockResolvedValue([pending]);
    const user = userEvent.setup();
    renderAt("/approvals");

    const row = (await screen.findByText("jit-db")).closest("tr")!;
    await user.click(within(row).getByRole("button", { name: /approve issue for jit-db/i }));
    await waitFor(() => expect(apiMock.approveIdentityAction).toHaveBeenCalledWith("jit-1", "issue"));
  });

  it("blocks self-approval of one's own request", async () => {
    apiMock.me.mockResolvedValue({ subject: "dev-1", tenant_id: "t1", email: "dev@example.test" });
    apiMock.identities.mockResolvedValue([{ ...pending, name: "own-request" }]);
    renderAt("/approvals");

    const row = (await screen.findByText("own-request")).closest("tr")!;
    expect(within(row).getByRole("button", { name: /approve issue for own-request/i })).toBeDisabled();
  });
});
