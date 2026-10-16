import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { IntlProvider } from "@/i18n/I18nProvider";
import { PCASDelegationPanel } from "@/pages/posture/PCASDelegationPanel";

const { pcasMock } = vi.hoisted(() => ({
  pcasMock: {
    configureDelegationScope: vi.fn(),
    raiseDelegationFloor: vi.fn(),
    delegationScopes: vi.fn(),
    requestStatus: vi.fn(),
  },
}));
vi.mock("@/lib/pcasApi", () => ({ pcasApi: pcasMock }));

describe("PCAS delegation console", () => {
  beforeEach(() => {
    for (const mock of Object.values(pcasMock)) mock.mockReset();
  });

  it("holds an exact review and reports signer confirmation only after delivered readback", async () => {
    const user = userEvent.setup();
    pcasMock.configureDelegationScope.mockResolvedValue({ request_id: "scope-1", scope_id: "root", epoch_floor: 2, status: "queued" });
    pcasMock.requestStatus.mockResolvedValue({ request_id: "scope-1", kind: "delegation_scope", status: "delivered", attempts: 1 });
    pcasMock.delegationScopes.mockResolvedValue({
      scopes: [
        {
          scope_id: "root",
          epoch_floor: 2,
          signer_confirmed: true,
          signer_receipt: { operation_id: "scope-1", applied_floor: 2, applied_parent_scope_id: "", public_key_der: "AQID", signature: "AQID" },
        },
      ],
      count: 1,
    });
    render(
      <IntlProvider>
        <PCASDelegationPanel />
      </IntlProvider>,
    );
    await user.type(screen.getByLabelText("Scope ID"), "root");
    await user.clear(screen.getByLabelText("Minimum successor epoch"));
    await user.type(screen.getByLabelText("Minimum successor epoch"), "2");
    await user.click(screen.getByRole("button", { name: "Review scope" }));
    await user.type(screen.getByLabelText("Parent scope ID (blank for root)"), "changed");
    expect(screen.queryByRole("button", { name: "Queue signer command" })).not.toBeInTheDocument();
    await user.clear(screen.getByLabelText("Parent scope ID (blank for root)"));
    await user.click(screen.getByRole("button", { name: "Review scope" }));
    await user.click(screen.getByRole("button", { name: "Queue signer command" }));
    await waitFor(() => expect(pcasMock.configureDelegationScope).toHaveBeenCalledWith({ scope_id: "root", parent_scope_id: "", epoch_floor: 2 }));
    expect(screen.getByText(/Delivery state: queued/)).toBeInTheDocument();
    expect(screen.queryByText("Signer confirmed")).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Refresh command and scopes" }));
    expect(await screen.findByText("Signer confirmed")).toBeInTheDocument();
    expect(screen.getByText(/Signed operation:/)).toHaveTextContent("scope-1");
    expect(screen.getByText(/Signer public key/)).toHaveTextContent("AQID");
  });
});
