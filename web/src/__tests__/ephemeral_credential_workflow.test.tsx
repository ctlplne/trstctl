import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { EphemeralCredentialWorkflow } from "@/pages/workloads/EphemeralCredentialWorkflow";
import type { EphemeralCredentialPreview } from "@/lib/api";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    previewEphemeralCredential: vi.fn(),
    requestEphemeralCredential: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});

const readyPreview: EphemeralCredentialPreview = {
  approval_permission: "certs:issue",
  approval_required: true,
  approval_ttl_seconds: 900,
  attestation_verification: "execution_only",
  blockers: [],
  capability: "ephemeral_credential_issuance",
  data_handling: ["Preview returns SHA-256 digests only."],
  default_ttl_seconds: 600,
  effect_free: true,
  effective_ttl_seconds: 300,
  issuance_external_effects: [],
  issuance_signer_calls: ["Sign one X.509-SVID."],
  issuance_writes: ["Append one certificate-issued event."],
  max_ttl_seconds: 3600,
  method: "k8s_sat",
  payload_sha256: "a".repeat(64),
  preview_external_effects: [],
  preview_signer_calls: [],
  preview_writes: [],
  public_key_sha256: "b".repeat(64),
  ready: true,
  recovery_steps: ["Retry the exact request with a fresh idempotency key."],
  request_id: "jit-browser-test",
  request_permission: "certs:request",
  requested_ttl_seconds: 300,
  requester: "requester@example.test",
  required_approvals: 1,
  steps: ["Submit the exact request.", "A different principal approves it.", "Resubmit and sign once."],
  submission_external_effects: ["Enqueue one approval notification."],
  submission_signer_calls: [],
  submission_writes: ["Append one immutable approval request."],
  supported_methods: ["k8s_sat"],
  trust_domain: "workloads.example.test",
  ttl_clamped: false,
  ttl_defaulted: false,
};

function renderWorkflow() {
  return render(
    <MemoryRouter>
      <EphemeralCredentialWorkflow />
    </MemoryRouter>,
  );
}

async function enterRequest() {
  fireEvent.change(screen.getByLabelText("Request ID"), { target: { value: "jit-browser-test" } });
  fireEvent.change(screen.getByLabelText("Proof method"), { target: { value: "k8s_sat" } });
  fireEvent.change(screen.getByLabelText("Workload proof (base64)"), { target: { value: "c2Vuc2l0aXZlLXByb29m" } });
  fireEvent.change(screen.getByLabelText("Public key (PEM)"), { target: { value: "-----BEGIN PUBLIC KEY-----\nZmFrZQ==\n-----END PUBLIC KEY-----" } });
  fireEvent.change(screen.getByLabelText("Requested lifetime in seconds"), { target: { value: "300" } });
  await userEvent.click(screen.getByRole("button", { name: "Preview request" }));
}

describe("ephemeral credential workflow", () => {
  beforeEach(() => {
    apiMock.previewEphemeralCredential.mockReset().mockResolvedValue(readyPreview);
    apiMock.requestEphemeralCredential.mockReset();
  });

  it("previews the exact request, waits for a different approver, and recovers one issued certificate", async () => {
    apiMock.requestEphemeralCredential
      .mockResolvedValueOnce({
        state: "awaiting_approval",
        request_id: "jit-browser-test",
        approval_request_id: "approval-7",
        intent_digest: "c".repeat(64),
        subject: "workload-7",
        required_approvals: 1,
        approvals: 0,
        expires_at: "2026-08-29T12:15:00Z",
        attestation: { id: "att-7", method: "k8s_sat", selectors: ["ns:prod"], subject: "workload-7", verified_at: "2026-08-29T12:00:00Z" },
      })
      .mockResolvedValueOnce({
        state: "issued",
        spiffe_id: "spiffe://workloads.example.test/_trstctl/v1/tenant/11111111-1111-4111-8111-111111111111/ephemeral/method/k8s_sat/subject/workload-7",
        request_id: "jit-browser-test",
        approval_request_id: "approval-7",
        intent_digest: "c".repeat(64),
        subject: "workload-7",
        credential_id: "cred-7",
        certificate_id: "cert-7",
        certificate_pem: "-----BEGIN CERTIFICATE-----\nY2VydA==\n-----END CERTIFICATE-----",
        required_approvals: 1,
        approvals: 1,
        expires_at: "2026-08-29T12:15:00Z",
        not_after: "2026-08-29T12:05:00Z",
        attestation: { id: "att-7", method: "k8s_sat", selectors: ["ns:prod"], subject: "workload-7", verified_at: "2026-08-29T12:01:00Z" },
      });

    renderWorkflow();
    await enterRequest();

    expect(await screen.findByRole("heading", { name: "Ready to send for approval" })).toBeInTheDocument();
    expect(apiMock.previewEphemeralCredential).toHaveBeenCalledWith({
      request_id: "jit-browser-test",
      method: "k8s_sat",
      payload_base64: "c2Vuc2l0aXZlLXByb29m",
      public_key_pem: "-----BEGIN PUBLIC KEY-----\nZmFrZQ==\n-----END PUBLIC KEY-----",
      ttl_seconds: 300,
    });
    expect(screen.queryByDisplayValue("c2Vuc2l0aXZlLXByb29m")).not.toBeInTheDocument();
    expect(apiMock.requestEphemeralCredential).not.toHaveBeenCalled();

    await userEvent.click(screen.getByRole("button", { name: "Send for approval" }));
    expect(await screen.findByRole("heading", { name: "Waiting for a different approver" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Open approval queue" })).toHaveAttribute("href", "/approvals");
    expect(screen.getByText("approval-7")).toBeInTheDocument();
    expect(screen.queryByText("Signed workload ID")).not.toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: "Check approval and issue" }));
    expect(await screen.findByRole("heading", { name: "Temporary certificate issued" })).toBeInTheDocument();
    expect(screen.getByText(/private key never enters trstctl/i)).toBeInTheDocument();
    await userEvent.click(screen.getByText("Signed workload ID"));
    expect(
      screen.getByText("spiffe://workloads.example.test/_trstctl/v1/tenant/11111111-1111-4111-8111-111111111111/ephemeral/method/k8s_sat/subject/workload-7"),
    ).toBeVisible();
    expect(apiMock.requestEphemeralCredential).toHaveBeenCalledTimes(2);
    expect(apiMock.requestEphemeralCredential.mock.calls[1]).toEqual(apiMock.requestEphemeralCredential.mock.calls[0]);
  });

  it("does not label an unknown issuance state as success or offer its unconfirmed identity", async () => {
    apiMock.requestEphemeralCredential.mockResolvedValue({ state: "new-server-state", spiffe_id: "spiffe://unconfirmed.test/workload" });
    renderWorkflow();
    await enterRequest();
    await screen.findByRole("heading", { name: "Ready to send for approval" });
    await userEvent.click(screen.getByRole("button", { name: "Send for approval" }));
    expect(await screen.findByText("Issuance outcome is unconfirmed")).toBeInTheDocument();
    expect(screen.queryByText("Temporary certificate issued")).not.toBeInTheDocument();
    expect(screen.queryByText("Signed workload ID")).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Check approval and issue" })).not.toBeInTheDocument();
    expect(screen.queryByText("spiffe://unconfirmed.test/workload")).not.toBeInTheDocument();
    expect(apiMock.requestEphemeralCredential).toHaveBeenCalledTimes(1);
  });

  it("shows server blockers and keeps submission disabled", async () => {
    apiMock.previewEphemeralCredential.mockResolvedValue({
      ...readyPreview,
      ready: false,
      blockers: ['attestation method "unknown" is not configured'],
      supported_methods: ["k8s_sat", "tpm"],
    });
    renderWorkflow();
    await enterRequest();

    expect(await screen.findByRole("heading", { name: "Fix these items before submitting" })).toBeInTheDocument();
    expect(screen.getByText(/is not configured/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Send for approval" })).toBeDisabled();
    await waitFor(() => expect(apiMock.requestEphemeralCredential).not.toHaveBeenCalled());
  });
});
