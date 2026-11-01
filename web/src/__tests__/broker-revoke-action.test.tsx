import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { BrokerRevokeAction } from "@/pages/workloads/BrokerRevokeAction";

const { apiMock, can } = vi.hoisted(() => ({ apiMock: { revokeBrokerAgentIdentity: vi.fn() }, can: { value: true } }));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});
vi.mock("@/components/rbac", () => ({ useCan: () => can.value }));

describe("Q4 one-call agent identity revoke", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    can.value = true;
  });

  it("revokes with the chosen reason and retries with the same key", async () => {
    apiMock.revokeBrokerAgentIdentity.mockRejectedValueOnce(new Error("network"));
    apiMock.revokeBrokerAgentIdentity.mockResolvedValueOnce({ total_matched: 1, total_revoked: 1, total_failed: 0 });
    const onRevoked = vi.fn();
    const user = userEvent.setup();
    render(<BrokerRevokeAction certificateId="c1" onRevoked={onRevoked} />);
    await user.selectOptions(screen.getByRole("combobox", { name: "Reason" }), "cessationOfOperation");
    await user.click(screen.getByRole("button", { name: "Revoke identity" }));
    await user.click(screen.getByRole("button", { name: "Revoke identity" }));
    const [first, second] = apiMock.revokeBrokerAgentIdentity.mock.calls;
    expect(first[0]).toBe("c1");
    expect(first[1]).toEqual({ reason: "cessationOfOperation" });
    expect(second[2]).toBe(first[2]);
    expect(await screen.findByText("Revoked. Relying parties refuse its next use.")).toBeInTheDocument();
    expect(onRevoked).toHaveBeenCalledTimes(1);
  });

  it("is hidden without certificate issuance authority", () => {
    can.value = false;
    const { container } = render(<BrokerRevokeAction certificateId="c1" onRevoked={() => {}} />);
    expect(container).toBeEmptyDOMElement();
  });
});
