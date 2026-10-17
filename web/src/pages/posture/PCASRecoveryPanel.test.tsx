import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { IntlProvider } from "@/i18n/I18nProvider";
import { AppQueryProvider } from "@/lib/query";
import { ApiError } from "@/lib/apiTransport";
import { PCASRecoveryPanel } from "@/pages/posture/PCASRecoveryPanel";

const { pcasMock } = vi.hoisted(() => ({
  pcasMock: {
    chain: vi.fn(),
    recoveryPolicy: vi.fn(),
    configureRecoveryPolicy: vi.fn(),
    prepareRecoverySuccessor: vi.fn(),
    recoverySuccessor: vi.fn(),
    requestRecovery: vi.fn(),
    requestStatus: vi.fn(),
  },
}));

vi.mock("@/lib/pcasApi", () => ({ pcasApi: pcasMock }));

const genesis = {
  identity_id: "spiffe://qa.example/service",
  tenant_id: "11111111-1111-1111-1111-111111111111",
  deployment_scope: "spiffe://qa.example",
  algorithm: "ECDSA-P256",
  public_key: "AQID",
  epoch: 0,
  trust_root_att: "AQID",
};

describe("PCAS threshold recovery console", () => {
  beforeEach(() => {
    for (const mock of Object.values(pcasMock)) mock.mockReset();
    pcasMock.chain.mockResolvedValue({
      identity_id: genesis.identity_id,
      genesis,
      trust_root_public_der: "AQID",
      records: [],
      count: 0,
    });
    pcasMock.recoveryPolicy.mockResolvedValue({
      identity_id: genesis.identity_id,
      threshold: 2,
      roster: [
        { ID: "custodian-a", PubDER: "AQID" },
        { ID: "custodian-b", PubDER: "BAUG" },
      ],
      trust_root_der: "BwgJ",
      updated_at: "2026-10-17T00:00:00Z",
    });
  });

  it("shows the enforced public quorum before offering a recovery request", async () => {
    render(
      <AppQueryProvider>
        <IntlProvider>
          <PCASRecoveryPanel identityID={genesis.identity_id} />
        </IntlProvider>
      </AppQueryProvider>,
    );
    expect(await screen.findByRole("heading", { name: "Threshold recovery" })).toBeInTheDocument();
    expect(await screen.findByText(/2 of 2 distinct custodians/)).toBeInTheDocument();
    expect(screen.getByText(/custodian-a/)).toBeInTheDocument();
    expect(pcasMock.requestRecovery).not.toHaveBeenCalled();
  });

  it("explains that the next epoch needs preparation when no signer receipt exists", async () => {
    const user = userEvent.setup();
    pcasMock.recoverySuccessor.mockRejectedValue(
      new ApiError(
        404,
        JSON.stringify({
          detail: "recovery successor preparation has not completed",
        }),
      ),
    );
    render(
      <AppQueryProvider>
        <IntlProvider>
          <PCASRecoveryPanel identityID={genesis.identity_id} />
        </IntlProvider>
      </AppQueryProvider>,
    );
    await screen.findByText(/2 of 2 distinct custodians/);
    await user.click(screen.getByRole("button", { name: "Read prepared key and signer receipt" }));
    expect(await screen.findByText(/No signer-held successor is prepared for epoch 1/)).toBeInTheDocument();
    expect(screen.getByText(/Review key preparation, then read the signed receipt/)).toBeInTheDocument();
  });

  it("reviews and saves a distinct public custodian quorum without private keys", async () => {
    const user = userEvent.setup();
    pcasMock.configureRecoveryPolicy.mockResolvedValue({
      identity_id: genesis.identity_id,
      status: "configured",
      updated_at: "2026-10-17T00:01:00Z",
    });
    render(
      <AppQueryProvider>
        <IntlProvider>
          <PCASRecoveryPanel identityID={genesis.identity_id} />
        </IntlProvider>
      </AppQueryProvider>,
    );
    await screen.findByText(/2 of 2 distinct custodians/);
    fireEvent.change(screen.getByLabelText("Recovery trust-root public key (base64 DER)"), { target: { value: "BwgJ" } });
    fireEvent.change(screen.getByLabelText("Custodian ID 1"), { target: { value: "custodian-a" } });
    fireEvent.change(screen.getByLabelText("Custodian public key DER 1"), { target: { value: "AQID" } });
    fireEvent.change(screen.getByLabelText("Custodian ID 2"), { target: { value: "custodian-b" } });
    fireEvent.change(screen.getByLabelText("Custodian public key DER 2"), { target: { value: "BAUG" } });
    await user.click(screen.getByRole("button", { name: "Review recovery policy" }));
    expect(screen.getByText("Review the exact public quorum")).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Custodian ID 2"), { target: { value: "changed" } });
    await user.click(screen.getByRole("button", { name: "Save reviewed recovery policy" }));
    expect(pcasMock.configureRecoveryPolicy).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "Review recovery policy" }));
    await user.click(screen.getByRole("button", { name: "Save reviewed recovery policy" }));
    await waitFor(() =>
      expect(pcasMock.configureRecoveryPolicy).toHaveBeenCalledWith({
        identity_id: genesis.identity_id,
        threshold: 2,
        trust_root_der: "BwgJ",
        roster: [
          { ID: "custodian-a", PubDER: "AQID" },
          { ID: "changed", PubDER: "BAUG" },
        ],
      }),
    );
  });

  it("binds the submitted authorization to the prepared signer key and current predecessor", async () => {
    const user = userEvent.setup();
    pcasMock.prepareRecoverySuccessor.mockResolvedValue({ request_id: "prep-1", status: "queued" });
    pcasMock.requestStatus.mockResolvedValue({ request_id: "prep-1", kind: "recovery_successor_prepare", status: "delivered", attempts: 1 });
    pcasMock.recoverySuccessor.mockResolvedValue({
      tenant_id: genesis.tenant_id,
      identity_id: genesis.identity_id,
      deployment_scope: genesis.deployment_scope,
      epoch: 1,
      algorithm: "ECDSA-P384",
      handle: "tenant-bound-handle",
      public_key_der: "CgsM",
      request_id: "prep-1",
      signer_signature: "DQ4P",
      event_id: "event-1",
    });
    pcasMock.requestRecovery.mockResolvedValue({ request_id: "recovery-1", status: "queued" });
    render(
      <AppQueryProvider>
        <IntlProvider>
          <PCASRecoveryPanel identityID={genesis.identity_id} />
        </IntlProvider>
      </AppQueryProvider>,
    );
    await screen.findByText(/2 of 2 distinct custodians/);
    await user.click(screen.getByRole("button", { name: "Review key preparation" }));
    await user.click(screen.getByRole("button", { name: "Prepare signer-held key" }));
    expect(await screen.findByText(/Prepared public key/)).toHaveTextContent("CgsM");

    const artifact = {
      Statement: {
        DeploymentScope: genesis.deployment_scope,
        IdentityID: genesis.identity_id,
        TenantID: genesis.tenant_id,
        Epoch: 1,
        SuccessorAlg: "ECDSA-P384",
        SuccessorPub: "wrong-key",
        Nonce: "qa-nonce",
      },
      Threshold: 2,
      Roster: [
        { ID: "custodian-a", PubDER: "AQID" },
        { ID: "custodian-b", PubDER: "BAUG" },
      ],
      RosterSig: "AQID",
      Approvals: [
        { ApproverID: "custodian-a", Signature: "AQID" },
        { ApproverID: "custodian-b", Signature: "BAUG" },
      ],
    };
    const input = screen.getByLabelText("Signed authorization JSON");
    fireEvent.change(input, { target: { value: JSON.stringify(artifact) } });
    await user.click(screen.getByRole("button", { name: "Review recovery request" }));
    expect(await screen.findByText(/differs from the current tenant chain/)).toBeInTheDocument();
    expect(pcasMock.requestRecovery).not.toHaveBeenCalled();

    fireEvent.change(input, { target: { value: JSON.stringify({ ...artifact, Statement: { ...artifact.Statement, SuccessorPub: "CgsM" } }) } });
    await user.click(screen.getByRole("button", { name: "Review recovery request" }));
    await user.click(screen.getByRole("button", { name: "Queue signed recovery" }));
    await waitFor(() =>
      expect(pcasMock.requestRecovery).toHaveBeenCalledWith(
        expect.objectContaining({
          identity_id: genesis.identity_id,
          predecessor_epoch: 0,
          predecessor_algorithm: "ECDSA-P256",
          predecessor_public_der: "AQID",
          epoch: 1,
          successor_handle: "tenant-bound-handle",
          target_algorithm: "ECDSA-P384",
          trust_root_der: "BwgJ",
        }),
      ),
    );
  });
});
