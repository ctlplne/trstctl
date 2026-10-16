import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { IntlProvider } from "@/i18n/I18nProvider";
import { PCASSuccessionWorkflow } from "@/pages/posture/PCASSuccessionWorkflow";

const { pcasMock } = vi.hoisted(() => ({
  pcasMock: {
    registerGenesis: vi.fn(),
    requestSuccession: vi.fn(),
    requestStatus: vi.fn(),
    chain: vi.fn(),
    checkpoint: vi.fn(),
    retirementStatus: vi.fn(),
    configureRetirement: vi.fn(),
  },
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

  it("shows the checkpoint signer fingerprint and exact log head", async () => {
    const user = userEvent.setup();
    pcasMock.checkpoint.mockResolvedValue({
      identity_id: "spiffe://example.test/workload/api",
      epoch: 1,
      log_tree_size: 3,
      log_root: "AQID",
      signer_public_der: "AQID",
      issued_at: "2026-10-12T00:00:00Z",
      checkpoint: {},
      signature: "AQID",
    });
    render(
      <IntlProvider>
        <PCASSuccessionWorkflow />
      </IntlProvider>,
    );
    await user.type(screen.getByLabelText("Stable identity ID"), "spiffe://example.test/workload/api");
    await user.click(screen.getByRole("button", { name: "Read signed checkpoint" }));
    expect(await screen.findByText("Latest signed epoch checkpoint")).toBeInTheDocument();
    expect(screen.getByText(/Log entries: 3/)).toBeInTheDocument();
    expect(screen.getByText(/Log root \(base64\):/)).toHaveTextContent("AQID");
    expect(screen.getByText(/Compare this fingerprint/)).toBeInTheDocument();
  });

  it("reads and reviews a bound retirement quorum before changing it", async () => {
    const user = userEvent.setup();
    pcasMock.retirementStatus.mockResolvedValue({
      identity_id: "spiffe://example.test/workload/api",
      predecessor_epoch: 0,
      threshold: 1,
      roster: [{ relying_party: "rp-a", public_der: "AQID" }],
      validity_window_seconds: 3600,
      predecessor_handle: "pcas-key-a",
      status: "active",
      rewrap_complete: false,
      updated_at: "2026-10-15T00:00:00Z",
    });
    pcasMock.configureRetirement.mockResolvedValue({
      identity_id: "spiffe://example.test/workload/api",
      predecessor_epoch: 0,
      threshold: 1,
      roster: [{ relying_party: "rp-a", public_der: "AQID" }],
      validity_window_seconds: 7200,
      predecessor_handle: "pcas-key-a",
      status: "active",
      rewrap_complete: false,
      updated_at: "2026-10-15T00:01:00Z",
    });
    render(
      <IntlProvider>
        <PCASSuccessionWorkflow />
      </IntlProvider>,
    );
    await user.type(screen.getByLabelText("Stable identity ID"), "spiffe://example.test/workload/api");
    await user.click(screen.getByRole("button", { name: "Read retirement policy" }));
    await waitFor(() => expect(pcasMock.retirementStatus).toHaveBeenCalledWith("spiffe://example.test/workload/api", 0));
    expect(screen.getByText(/Rewrap complete: No/)).toBeInTheDocument();
    expect(screen.getByText(/predecessor key is selected from this tenant/)).toBeInTheDocument();
    expect(screen.queryByLabelText("Predecessor signer handle (optional)")).not.toBeInTheDocument();
    await user.clear(screen.getByLabelText("Acknowledgment window (seconds)"));
    await user.type(screen.getByLabelText("Acknowledgment window (seconds)"), "7200");
    await user.click(screen.getByRole("button", { name: "Review retirement policy" }));
    expect(screen.getByRole("button", { name: "Save reviewed retirement policy" })).toBeInTheDocument();
    expect(screen.getByText("rp-a: AQID")).toBeInTheDocument();
    await user.clear(screen.getByLabelText("Public key DER (base64) 1"));
    await user.type(screen.getByLabelText("Public key DER (base64) 1"), "AQIE");
    expect(screen.queryByRole("button", { name: "Save reviewed retirement policy" })).not.toBeInTheDocument();
    await user.clear(screen.getByLabelText("Public key DER (base64) 1"));
    await user.type(screen.getByLabelText("Public key DER (base64) 1"), "AQID");
    await user.click(screen.getByRole("button", { name: "Review retirement policy" }));
    await user.click(screen.getByRole("button", { name: "Save reviewed retirement policy" }));
    await waitFor(() =>
      expect(pcasMock.configureRetirement).toHaveBeenCalledWith({
        identity_id: "spiffe://example.test/workload/api",
        predecessor_epoch: 0,
        threshold: 1,
        roster: [{ relying_party: "rp-a", public_der: "AQID" }],
        validity_window_seconds: 7200,
      }),
    );
    expect(screen.getByText(/Updated at: 2026-10-15T00:01:00Z/)).toBeInTheDocument();
  });
});
