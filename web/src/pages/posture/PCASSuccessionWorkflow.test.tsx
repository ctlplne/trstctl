import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { IntlProvider } from "@/i18n/I18nProvider";
import { PCASSuccessionWorkflow } from "@/pages/posture/PCASSuccessionWorkflow";

const { pcasMock } = vi.hoisted(() => ({
  pcasMock: { registerGenesis: vi.fn(), requestSuccession: vi.fn(), requestStatus: vi.fn(), chain: vi.fn() },
}));

vi.mock("@/lib/pcasApi", () => ({ pcasApi: pcasMock }));

describe("PCAS first-use console", () => {
  beforeEach(() => {
    for (const mock of Object.values(pcasMock)) mock.mockReset();
  });

  it("requires review of exact values and displays durable signer readback", async () => {
    const user = userEvent.setup();
    pcasMock.registerGenesis.mockResolvedValue({ request_id: "genesis-1", status: "queued" });
    pcasMock.requestStatus.mockResolvedValue({ request_id: "genesis-1", kind: "genesis", status: "delivered", attempts: 1 });
    pcasMock.chain.mockResolvedValue({
      identity_id: "spiffe://example.test/workload/api",
      genesis: { algorithm: "ECDSA-P256", epoch: 0 },
      trust_root_public_der: "AQID",
      records: [],
      count: 0,
    });
    render(
      <IntlProvider>
        <PCASSuccessionWorkflow />
      </IntlProvider>,
    );
    await user.type(screen.getByLabelText("Stable identity ID"), "spiffe://example.test/workload/api");
    await user.type(screen.getByLabelText("Deployment scope"), "spiffe://example.test");
    await user.click(screen.getByRole("button", { name: "Review first-key registration" }));
    expect(screen.getByText("Review the exact genesis")).toBeInTheDocument();
    await user.clear(screen.getByLabelText("Deployment scope"));
    await user.type(screen.getByLabelText("Deployment scope"), "spiffe://changed.test");
    expect(screen.queryByRole("button", { name: "Register first key" })).not.toBeInTheDocument();
    expect(pcasMock.registerGenesis).not.toHaveBeenCalled();

    await user.clear(screen.getByLabelText("Deployment scope"));
    await user.type(screen.getByLabelText("Deployment scope"), "spiffe://example.test");
    await user.click(screen.getByRole("button", { name: "Review first-key registration" }));
    await user.click(screen.getByRole("button", { name: "Register first key" }));
    await waitFor(() =>
      expect(pcasMock.registerGenesis).toHaveBeenCalledWith({
        identity_id: "spiffe://example.test/workload/api",
        algorithm: "ECDSA-P256",
        deployment_scope: "spiffe://example.test",
      }),
    );
    expect(screen.getByText("genesis-1")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Refresh request and chain" }));
    expect(await screen.findByText("Signed first-key anchor")).toBeInTheDocument();
    expect(screen.getByText(/Delivery state: delivered/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Review succession" })).toBeInTheDocument();
  });
});
