import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { Audit } from "@/pages/Audit";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    auditEvents: vi.fn(),
    exportAudit: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});

beforeEach(() => {
  apiMock.auditEvents
    .mockReset()
    .mockResolvedValue([{ id: "e1", sequence: 41, tenant_id: "t1", time: "2026-06-20T10:00:00Z", type: "identity.issued", hash: "abc123def456" }]);
  apiMock.exportAudit.mockReset().mockResolvedValue({ format: "json", bundle: "BASE64BUNDLE" });
});

describe("U6-2 audit explorer uplift", () => {
  it("filters audit events and downloads a signed evidence bundle from served endpoints", async () => {
    const user = userEvent.setup();
    render(
      <MemoryRouter>
        <Audit />
      </MemoryRouter>,
    );
    await waitFor(() => expect(apiMock.auditEvents).toHaveBeenCalled());
    expect(await screen.findByText("identity.issued")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Policy decisions" }));
    await waitFor(() => expect(apiMock.auditEvents).toHaveBeenCalledWith(expect.objectContaining({ type: "policy.decision" })));

    await user.click(screen.getByRole("button", { name: "Export evidence" }));
    await waitFor(() => expect(apiMock.exportAudit).toHaveBeenCalled());
    expect(await screen.findByRole("heading", { name: "Signed evidence bundle ready" })).toBeInTheDocument();
  });
});
