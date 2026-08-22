import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import userEvent from "@testing-library/user-event";
import { SSHTrust } from "@/pages/SSHTrust";
import { ApiError } from "@/lib/api";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    sshStatus: vi.fn(),
    sshFleet: vi.fn(),
    recordSSHTrustRollout: vi.fn(),
    issueAttestedSSHUserCert: vi.fn(),
    revokeSSHCertificate: vi.fn(),
    retireSSHHost: vi.fn(),
  },
}));

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return { ...actual, api: { ...actual.api, ...apiMock } };
});

function renderSSHTrust() {
  return render(
    <MemoryRouter>
      <SSHTrust />
    </MemoryRouter>,
  );
}

describe("SSH trust served workflow surface", () => {
  beforeEach(() => {
    for (const mock of Object.values(apiMock)) mock.mockReset();
    apiMock.sshStatus.mockResolvedValue({
      served: true,
      tenant_id: "tenant-1",
      authority_key: "ssh-ed25519 AAAA trstctl-ca",
      krl_version: 7,
      revoked_count: 2,
      attestors: ["k8s_sat"],
    });
    apiMock.sshFleet.mockResolvedValue({
      hosts: [
        {
          location: "/home/alice/.ssh/authorized_keys",
          keys: 1,
          standing_keys: 1,
          orphaned_keys: 1,
          key_types: ["ssh-ed25519"],
          sources: ["ssh-authorized-keys"],
          first_observed: "2026-06-27T09:00:00Z",
          last_observed: "2026-06-27T09:00:00Z",
          under_ca: false,
        },
      ],
      host_count: 1,
      key_count: 1,
      standing_key_count: 1,
      orphaned_key_count: 1,
      hosts_not_under_ca: 1,
    });
    apiMock.recordSSHTrustRollout.mockResolvedValue({
      id: "evt-rollout",
      tenant_id: "tenant-1",
      source_id: "",
      target_hosts: ["edge-1.internal"],
      candidate_ca_fingerprint: "",
      reload_command: "systemctl reload sshd",
      health_command: "ssh -o BatchMode=yes localhost true",
      rollback_plan: "restore trusted_user_ca_keys backup and reload sshd",
      status: "planned",
      confirmed: true,
      recorded_at: "2026-06-27T10:00:00Z",
    });
    apiMock.issueAttestedSSHUserCert.mockResolvedValue({
      certificate: "ssh-rsa-cert-v01@openssh.com AAAA",
      serial: 42,
      key_id: "jit-deployer",
      subject: "system:serviceaccount:default:deployer",
      principals: ["system:serviceaccount:default:deployer"],
      approver: "ssh-approver",
      source_addresses: ["10.0.0.0/24"],
      force_command: "/usr/local/bin/deploy",
      valid_before: "2026-06-27T10:15:00Z",
      attestation: { id: "att-1", method: "k8s_sat", subject: "system:serviceaccount:default:deployer", selectors: [], verified_at: "2026-06-27T10:00:00Z" },
    });
    apiMock.revokeSSHCertificate.mockResolvedValue({
      served: true,
      tenant_id: "tenant-1",
      authority_key: "ssh-ed25519 AAAA trstctl-ca",
      krl_version: 8,
      revoked_count: 3,
      attestors: ["k8s_sat"],
    });
    apiMock.retireSSHHost.mockResolvedValue({
      id: "evt-retire",
      tenant_id: "tenant-1",
      host: "edge-1.internal",
      status: "retired",
      recorded_at: "2026-06-27T10:20:00Z",
    });
  });

  it("loads SSH status and records an explicitly confirmed trust rollout", async () => {
    const user = userEvent.setup();
    renderSSHTrust();

    expect(screen.getByRole("heading", { name: "SSH access" })).toBeInTheDocument();
    expect(await screen.findByText("ssh-ed25519 AAAA trstctl-ca")).toBeInTheDocument();
    expect(screen.getByRole("table", { name: "SSH standing access inventory" })).toHaveTextContent("/home/alice/.ssh/authorized_keys");
    expect(screen.getByText(/1 standing.*1 orphaned/)).toBeInTheDocument();
    expect(screen.getByText("7")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Record trust rollout" })).toBeDisabled();

    await user.click(screen.getByLabelText("Confirm high-blast-radius SSH trust rollout evidence"));
    expect(screen.getByRole("button", { name: "Record trust rollout" })).toBeDisabled();
    await user.type(screen.getByLabelText("Candidate CA fingerprint"), "SHA256:reviewed-canary-ca");
    await user.click(screen.getByRole("button", { name: "Record trust rollout" }));

    await waitFor(() =>
      expect(apiMock.recordSSHTrustRollout).toHaveBeenCalledWith(
        expect.objectContaining({
          target_hosts: ["edge-1.internal"],
          status: "planned",
          confirmed: true,
        }),
      ),
    );
    expect(await screen.findByText("evt-rollout")).toBeInTheDocument();
  });

  it("renders the honest empty state for a pre-inventory rolling-upgrade payload", async () => {
    apiMock.sshFleet.mockResolvedValue({
      host_count: 0,
      key_count: 0,
      standing_key_count: 0,
      orphaned_key_count: 0,
      hosts_not_under_ca: 0,
    });

    renderSSHTrust();

    expect(await screen.findByText("No agent-reported SSH key locations yet.")).toBeInTheDocument();
    expect(screen.queryByRole("table", { name: "SSH standing access inventory" })).not.toBeInTheDocument();
  });

  it("explains when the SSH workflow is not enabled", async () => {
    apiMock.sshStatus.mockRejectedValue(
      new ApiError(503, JSON.stringify({ title: "Service Unavailable", status: 503, detail: "ssh workflow is not enabled" })),
    );

    renderSSHTrust();

    expect(await screen.findByText("SSH workflow failed")).toBeInTheDocument();
    expect(screen.getByText("ssh workflow is not enabled")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "SSH trust is not configured yet" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Open setup guidance" })).toHaveAttribute("href", "/protocols");
    expect(screen.queryByRole("form", { name: "Record SSH trust rollout" })).not.toBeInTheDocument();
  });

  it("keeps the workflow reason when secondary fleet inventory is rate limited", async () => {
    apiMock.sshStatus.mockRejectedValue(
      new ApiError(503, JSON.stringify({ title: "Service Unavailable", status: 503, detail: "ssh workflow is not enabled" })),
    );
    apiMock.sshFleet.mockRejectedValue(
      new ApiError(429, JSON.stringify({ title: "Too Many Requests", status: 429, detail: "rate limit exceeded for this tenant" }), 1),
    );

    renderSSHTrust();

    expect(await screen.findByText("ssh workflow is not enabled")).toBeInTheDocument();
    expect(screen.queryByText(/retry in 1s/i)).not.toBeInTheDocument();
  });

  it("issues an attested user cert, revokes it into the KRL, and retires a host", async () => {
    const user = userEvent.setup();
    renderSSHTrust();

    await screen.findByText("ssh-ed25519 AAAA trstctl-ca");
    await user.type(screen.getByLabelText("Attestation payload base64"), "eyJzdWIiOiJzYSJ9");
    await user.type(screen.getByLabelText("SSH public key"), "ssh-ed25519 AAAATEST user@example.test");
    await user.click(screen.getByRole("button", { name: "Issue attested SSH cert" }));

    await waitFor(() =>
      expect(apiMock.issueAttestedSSHUserCert).toHaveBeenCalledWith(
        expect.objectContaining({
          method: "k8s_sat",
          payload_base64: "eyJzdWIiOiJzYSJ9",
          public_key: "ssh-ed25519 AAAATEST user@example.test",
          ttl_seconds: 900,
          approver: "ssh-approver",
          principals: ["web"],
          source_addresses: ["10.0.0.0/24"],
          force_command: "/usr/local/bin/deploy",
        }),
      ),
    );
    expect(screen.getByLabelText("Attestation payload base64")).toHaveValue("");
    expect(screen.getByLabelText("SSH public key")).toHaveValue("");
    expect(await screen.findByLabelText("Issued SSH certificate")).toHaveValue("ssh-rsa-cert-v01@openssh.com AAAA");
    expect(screen.getByText(/approver ssh-approver/)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Revoke and publish KRL" }));

    await waitFor(() =>
      expect(apiMock.revokeSSHCertificate).toHaveBeenCalledWith(
        expect.objectContaining({
          serial: 42,
          key_id: "jit-deployer",
        }),
      ),
    );
    await user.click(screen.getByRole("button", { name: "Record host retired" }));
    await waitFor(() =>
      expect(apiMock.retireSSHHost).toHaveBeenCalledWith(
        expect.objectContaining({
          host: "edge-1.internal",
          reason: "standing SSH access replaced by certificate trust",
        }),
      ),
    );
    expect(await screen.findByText("edge-1.internal:retired")).toBeInTheDocument();
    expect(screen.queryByText(/BEGIN OPENSSH PRIVATE KEY/)).not.toBeInTheDocument();
  });
});
