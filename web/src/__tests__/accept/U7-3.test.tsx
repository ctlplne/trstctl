import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { Audit } from "@/pages/Audit";
import { AppQueryProvider } from "@/lib/query";

const { apiMock } = vi.hoisted(() => ({ apiMock: { auditEvents: vi.fn(), auditFeeds: vi.fn(), exportAudit: vi.fn() } }));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});

beforeEach(() => {
  apiMock.auditEvents
    .mockReset()
    .mockResolvedValue([
      { id: "p1", sequence: 7, tenant_id: "t1", time: "2026-06-20T10:00:00Z", type: "policy.decision", hash: "h1", data: { decision: "allow" } },
    ]);
  apiMock.exportAudit.mockReset().mockResolvedValue({ format: "json", bundle: "B" });
  apiMock.auditFeeds.mockReset().mockResolvedValue({ items: [] });
});

// U7-3: policy decisions are served through the audit event stream (type policy.decision).
// The dry-run/preview half of the card is NOT served by the pinned OpenAPI contract and is escalated.
describe("U7-3 policy decisions from the audit stream", () => {
  it("renders policy.decision events and re-queries them through the served preset", async () => {
    const user = userEvent.setup();
    render(
      <AppQueryProvider>
        <MemoryRouter>
          <Audit />
        </MemoryRouter>
      </AppQueryProvider>,
    );
    await waitFor(() => expect(apiMock.auditEvents).toHaveBeenCalled());
    expect(await screen.findByText("policy.decision")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Policy decisions" }));
    await waitFor(() => expect(apiMock.auditEvents).toHaveBeenCalledWith(expect.objectContaining({ type: "policy.decision" })));
  });
});
