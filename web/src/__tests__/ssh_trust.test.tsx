import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import userEvent from "@testing-library/user-event";
import { SSHTrust } from "@/pages/SSHTrust";
import { ApiError } from "@/lib/api";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    sshStatus: vi.fn(),
    sshFleet: vi.fn(),
    recordSSHTrustRollout: vi.fn(),
    previewSSHCertificate: vi.fn(),
    issueSSHCertificate: vi.fn(),
    previewAttestedSSHUserCert: vi.fn(),
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
    apiMock.previewSSHCertificate.mockResolvedValue({
      ready: true,
      effect_free: true,
      certificate_type: "host",
      key_id: "edge-1.internal",
      principals: ["edge-1.internal"],
      requested_ttl_seconds: 90000,
      effective_ttl_seconds: 86400,
      ttl_defaulted: false,
      ttl_clamped: true,
      public_key_type: "ssh-ed25519",
      public_key_fingerprint: "SHA256:subject",
      authority_fingerprint: "SHA256:authority",
      critical_options: {},
      extensions: {},
      preview_writes: [],
      preview_external_effects: [],
      preview_signer_calls: [],
      issuance_writes: ["append ssh.cert.issued audit event"],
      issuance_external_effects: [],
      issuance_signer_calls: ["sign one SSH host certificate"],
      blockers: [],
      recovery_steps: ["Revoke by serial or key ID, then distribute the new KRL."],
      secret_data_handling: ["Only a public SSH key is accepted; trstctl never receives the private key."],
    });
    apiMock.issueSSHCertificate.mockResolvedValue({
      certificate: "ssh-ed25519-cert-v01@openssh.com AAAAHOST",
      certificate_type: "host",
      serial: 43,
      key_id: "edge-1.internal",
      principals: ["edge-1.internal"],
      valid_before: "2026-06-28T10:00:00Z",
      critical_options: {},
      extensions: {},
      authority_fingerprint: "SHA256:authority",
      krl_version: 7,
    });
    apiMock.previewAttestedSSHUserCert.mockResolvedValue({
      capability: "F45",
      ready: true,
      effect_free: true,
      method: "k8s_sat",
      supported_methods: ["k8s_sat"],
      key_id: "jit-deployer",
      approver: "ssh-approver",
      principals: ["web"],
      source_addresses: ["10.0.0.0/24"],
      force_command: "/usr/local/bin/deploy",
      requested_ttl_seconds: 900,
      effective_ttl_seconds: 900,
      ttl_defaulted: false,
      ttl_clamped: false,
      public_key_type: "ssh-ed25519",
      public_key_fingerprint: "SHA256:ssh-subject",
      authority_fingerprint: "SHA256:ssh-authority",
      required_permission: "certs:issue",
      attestation_verification: "execution_only",
      payload_sha256: "proof-digest",
      preview_writes: [],
      preview_external_effects: [],
      preview_signer_calls: [],
      execution_writes: ["record attestation verification and issuance audit evidence"],
      execution_external_effects: [],
      execution_signer_calls: ["sign one short-lived SSH user certificate"],
      blockers: [],
      recovery_steps: ["Retry the exact request with the same Idempotency-Key if the response is lost."],
      data_handling: ["The preview returns only a digest of the proof and never the proof itself."],
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
    expect(await screen.findByRole("heading", { name: "Choose what you want to do" })).toBeInTheDocument();
    expect(screen.getByRole("table", { name: "SSH standing access inventory" })).toHaveTextContent("/home/alice/.ssh/authorized_keys");
    expect(screen.getAllByText(/1 standing.*1 orphaned/)).toHaveLength(2);
    expect(screen.queryByRole("form", { name: "Record SSH trust rollout" })).not.toBeInTheDocument();

    const technicalDetails = screen.getByText("Show SSH technical status").closest("details") as HTMLDetailsElement;
    expect(technicalDetails).not.toHaveAttribute("open");
    await user.click(within(technicalDetails).getByText("Show SSH technical status"));
    expect(technicalDetails).toHaveAttribute("open");
    expect(screen.getByText("ssh-ed25519 AAAA trstctl-ca")).toBeInTheDocument();
    expect(screen.getByText("7")).toBeInTheDocument();
    const chooser = screen.getByRole("heading", { name: "Choose what you want to do" }).closest("section") as HTMLElement;
    await user.click(within(chooser).getByRole("button", { name: "Plan SSH trust rollout" }));
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

  it("labels readiness counts without broken singular grammar", async () => {
    apiMock.sshStatus.mockResolvedValue({
      served: true,
      tenant_id: "tenant-1",
      authority_key: "ssh-ed25519 AAAA trstctl-ca",
      krl_version: 7,
      revoked_count: 1,
      attestors: [],
    });

    renderSSHTrust();

    expect(await screen.findByText("Revocation entries: 1 · Proof methods: 0")).toBeInTheDocument();
    expect(screen.queryByText("1 revoked certificates · 0 proof methods available")).not.toBeInTheDocument();
  });

  it("previews the exact host-certificate plan before issuing and hides raw material by default", async () => {
    const user = userEvent.setup();
    renderSSHTrust();

    const chooser = (await screen.findByRole("heading", { name: "Choose what you want to do" })).closest("section") as HTMLElement;
    await user.click(within(chooser).getByRole("button", { name: "Issue host or user certificate" }));
    await user.type(screen.getByLabelText("SSH public key"), "ssh-ed25519 AAAATEST edge-1");
    await user.clear(screen.getByLabelText("Certificate name"));
    await user.type(screen.getByLabelText("Certificate name"), "edge-1.internal");
    await user.clear(screen.getByLabelText("Allowed hostnames or users"));
    await user.type(screen.getByLabelText("Allowed hostnames or users"), "edge-1.internal");
    await user.clear(screen.getByLabelText("Lifetime in seconds"));
    await user.type(screen.getByLabelText("Lifetime in seconds"), "90000");
    await user.click(screen.getByRole("button", { name: "Review exact plan" }));

    await waitFor(() =>
      expect(apiMock.previewSSHCertificate).toHaveBeenCalledWith({
        certificate_type: "host",
        public_key: "ssh-ed25519 AAAATEST edge-1",
        key_id: "edge-1.internal",
        principals: ["edge-1.internal"],
        ttl_seconds: 90000,
        critical_options: {},
        extensions: {},
      }),
    );
    expect(await screen.findByRole("heading", { name: "Ready to issue" })).toBeInTheDocument();
    expect(screen.getByText("24 hours")).toBeInTheDocument();
    expect(screen.getByText("A 25-hour request will be limited to 24 hours.")).toBeInTheDocument();
    expect(screen.getByText("No writes, network calls, or signer calls happened during this preview.")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Issue SSH host certificate" }));
    await waitFor(() => expect(apiMock.issueSSHCertificate).toHaveBeenCalledTimes(1));
    expect(await screen.findByRole("heading", { name: "Host certificate issued" })).toBeInTheDocument();
    expect(screen.getByText("Serial 43")).toBeInTheDocument();
    expect(screen.queryByLabelText("SSH public key")).not.toBeInTheDocument();
    expect(screen.queryByText("ssh-ed25519-cert-v01@openssh.com AAAAHOST")).not.toBeInTheDocument();

    const disclosure = screen.getByText("Show public certificate").closest("details") as HTMLDetailsElement;
    expect(disclosure).not.toHaveAttribute("open");
    await user.click(within(disclosure).getByText("Show public certificate"));
    expect(screen.getByText("ssh-ed25519-cert-v01@openssh.com AAAAHOST")).toBeInTheDocument();
    await user.click(within(chooser).getByRole("button", { name: "Remove access" }));
    expect(screen.getByLabelText("Certificate serial")).toHaveValue("43");
    expect(screen.getByLabelText("Revocation scope")).toHaveValue("serial");
    expect(screen.queryByLabelText("Key ID")).not.toBeInTheDocument();
    await user.selectOptions(screen.getByLabelText("Revocation scope"), "key_id");
    expect(screen.getByLabelText("Key ID")).toHaveValue("edge-1.internal");
  });

  it("reveals user-only restrictions and sends them in the exact preview", async () => {
    apiMock.previewSSHCertificate.mockResolvedValueOnce({
      ready: true,
      effect_free: true,
      certificate_type: "user",
      key_id: "edge-1.internal",
      principals: ["edge-1.internal"],
      requested_ttl_seconds: 3600,
      effective_ttl_seconds: 3600,
      ttl_defaulted: false,
      ttl_clamped: false,
      public_key_type: "ssh-ed25519",
      public_key_fingerprint: "SHA256:subject",
      authority_fingerprint: "SHA256:authority",
      critical_options: { "source-address": "10.0.0.0/24", "force-command": "/usr/local/bin/deploy" },
      extensions: { "permit-X11-forwarding": "" },
      preview_writes: [],
      preview_external_effects: [],
      preview_signer_calls: [],
      issuance_writes: ["append audit event"],
      issuance_external_effects: [],
      issuance_signer_calls: ["sign one SSH user certificate"],
      blockers: [],
      recovery_steps: ["Revoke and distribute KRL."],
      secret_data_handling: ["Public key only."],
    });
    const user = userEvent.setup();
    renderSSHTrust();
    const chooser = (await screen.findByRole("heading", { name: "Choose what you want to do" })).closest("section") as HTMLElement;
    await user.click(within(chooser).getByRole("button", { name: "Issue host or user certificate" }));
    await user.selectOptions(screen.getByLabelText("Certificate type"), "user");
    await user.type(screen.getByLabelText("SSH public key"), "ssh-ed25519 AAAAUSER deployer");
    await user.type(screen.getByLabelText("Allowed source addresses"), "10.0.0.0/24");
    await user.type(screen.getByLabelText("Forced command"), "/usr/local/bin/deploy");
    await user.type(screen.getByLabelText("Extra user permissions"), "permit-X11-forwarding");
    await user.click(screen.getByRole("button", { name: "Review exact plan" }));

    await waitFor(() =>
      expect(apiMock.previewSSHCertificate).toHaveBeenCalledWith(
        expect.objectContaining({
          certificate_type: "user",
          critical_options: { "source-address": "10.0.0.0/24", "force-command": "/usr/local/bin/deploy" },
          extensions: { "permit-X11-forwarding": "" },
        }),
      ),
    );
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

  it("reviews an exact serial without a key-ID wildcard and explains distribution", async () => {
    const user = userEvent.setup();
    renderSSHTrust();
    const chooser = (await screen.findByRole("heading", { name: "Choose what you want to do" })).closest("section") as HTMLElement;
    await user.click(within(chooser).getByRole("button", { name: "Remove access" }));
    expect(screen.getByLabelText("Revocation scope")).toHaveValue("serial");
    expect(screen.queryByLabelText("Key ID")).not.toBeInTheDocument();
    await user.type(screen.getByLabelText("Certificate serial"), " 42 ");
    await user.click(screen.getByRole("button", { name: "Review revocation" }));
    expect(apiMock.revokeSSHCertificate).not.toHaveBeenCalled();
    expect(screen.getByText("Revoke serial 42. This request does not revoke other serials with the same key ID.")).toBeInTheDocument();
    expect(
      screen.getByText("This KRL matches certificates from any issuing CA. Check every consumer that uses this list before publishing."),
    ).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Revoke and publish KRL" }));
    await waitFor(() => expect(apiMock.revokeSSHCertificate).toHaveBeenCalledWith({ serial: 42, reason: "operator requested revocation" }, expect.any(String)));
    expect(await screen.findByRole("heading", { name: "KRL published" })).toBeInTheDocument();
    expect(screen.getByRole("progressbar", { name: "SSH revocation progress" })).toHaveAttribute("aria-valuenow", "67");
    expect(
      screen.getByText(
        "Publish succeeded. Distribute the current KRL to every relying host and SSH client, then verify that the revoked certificate is rejected and replacement access works.",
      ),
    ).toBeInTheDocument();
    expect(screen.getByText("Revocation entries: 3 · Proof methods: 1")).toBeInTheDocument();
  });

  it.each(["key_id", "both"])("makes %s revocation scope explicit and omits unselected fields", async (scope) => {
    const user = userEvent.setup();
    renderSSHTrust();
    const chooser = (await screen.findByRole("heading", { name: "Choose what you want to do" })).closest("section") as HTMLElement;
    await user.click(within(chooser).getByRole("button", { name: "Remove access" }));
    await user.selectOptions(screen.getByLabelText("Revocation scope"), scope);
    await user.type(screen.getByLabelText("Key ID"), " shared-deployer ");
    if (scope === "both") await user.type(screen.getByLabelText("Certificate serial"), "42");
    await user.click(screen.getByRole("button", { name: "Review revocation" }));
    expect(
      screen.getByText(
        "All certificates with key ID shared-deployer are blocked, including future replacements using that name. A replacement needs a different key ID.",
      ),
    ).toBeInTheDocument();
    expect(apiMock.revokeSSHCertificate).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "Revoke and publish KRL" }));
    await waitFor(() =>
      expect(apiMock.revokeSSHCertificate).toHaveBeenCalledWith(
        { ...(scope === "both" ? { serial: 42 } : {}), key_id: "shared-deployer", reason: "operator requested revocation" },
        expect.any(String),
      ),
    );
  });

  it.each(["0", "42.5", "-1", "1e3", "9007199254740993"])("refuses ambiguous serial %s before a mutation", async (serial) => {
    const user = userEvent.setup();
    renderSSHTrust();
    const chooser = (await screen.findByRole("heading", { name: "Choose what you want to do" })).closest("section") as HTMLElement;
    await user.click(within(chooser).getByRole("button", { name: "Remove access" }));
    await user.type(screen.getByLabelText("Certificate serial"), serial);
    await user.click(screen.getByRole("button", { name: "Review revocation" }));
    expect(
      await screen.findByText(
        "Enter a positive whole-number serial no larger than 9007199254740991. Use the API for larger serials; the console must not round them.",
      ),
    ).toBeInTheDocument();
    expect(screen.getByLabelText("Certificate serial")).toHaveAttribute("aria-invalid", "true");
    expect(apiMock.revokeSSHCertificate).not.toHaveBeenCalled();
  });

  it("uses the edited review and keeps one idempotency key after an uncertain response", async () => {
    apiMock.revokeSSHCertificate.mockRejectedValueOnce(new ApiError(503, JSON.stringify({ detail: "response lost after publish" })));
    const user = userEvent.setup();
    renderSSHTrust();
    const chooser = (await screen.findByRole("heading", { name: "Choose what you want to do" })).closest("section") as HTMLElement;
    await user.click(within(chooser).getByRole("button", { name: "Remove access" }));
    await user.type(screen.getByLabelText("Certificate serial"), "42");
    await user.click(screen.getByRole("button", { name: "Review revocation" }));
    await user.click(screen.getByRole("button", { name: "Previous" }));
    await user.clear(screen.getByLabelText("Certificate serial"));
    await user.type(screen.getByLabelText("Certificate serial"), "43");
    await user.click(screen.getByRole("button", { name: "Review revocation" }));
    expect(screen.getByText("Revoke serial 43. This request does not revoke other serials with the same key ID.")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Revoke and publish KRL" }));
    expect(await screen.findByText(/response lost after publish/)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Retry publication" }));
    await screen.findByRole("heading", { name: "KRL published" });
    const calls = apiMock.revokeSSHCertificate.mock.calls;
    expect(calls).toHaveLength(2);
    expect(calls[1]).toEqual(calls[0]);
    expect(calls[0][0].serial).toBe(43);
  });

  it("issues an attested user cert, revokes it into the KRL, and retires a host", async () => {
    const user = userEvent.setup();
    renderSSHTrust();

    const chooser = (await screen.findByRole("heading", { name: "Choose what you want to do" })).closest("section") as HTMLElement;
    await user.click(within(chooser).getByRole("button", { name: "Request SSH access" }));
    await user.type(screen.getByLabelText("Attestation payload base64"), "eyJzdWIiOiJzYSJ9");
    await user.type(screen.getByLabelText("SSH public key"), "ssh-ed25519 AAAATEST user@example.test");
    await user.click(screen.getByRole("button", { name: "Review exact plan" }));

    await waitFor(() =>
      expect(apiMock.previewAttestedSSHUserCert).toHaveBeenCalledWith(
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
    expect(apiMock.issueAttestedSSHUserCert).not.toHaveBeenCalled();
    expect(await screen.findByRole("heading", { name: "Ready to verify and issue" })).toBeInTheDocument();
    expect(screen.getByText("No writes, external calls, audit events, or signer calls happened during this review.")).toBeInTheDocument();
    expect(screen.getByText("Retry the exact request with the same Idempotency-Key if the response is lost.")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Verify proof and issue SSH certificate" }));

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
        expect.any(String),
      ),
    );
    expect(screen.getByLabelText("Attestation payload base64")).toHaveValue("");
    expect(screen.getByLabelText("SSH public key")).toHaveValue("");
    expect(await screen.findByLabelText("Issued SSH certificate")).toHaveValue("ssh-rsa-cert-v01@openssh.com AAAA");
    expect(screen.getByText(/approver ssh-approver/)).toBeInTheDocument();
    await user.click(within(chooser).getByRole("button", { name: "Remove access" }));
    expect(screen.getByLabelText("Certificate serial")).toHaveValue("42");
    expect(screen.getByLabelText("Revocation scope")).toHaveValue("serial");
    await user.click(screen.getByRole("button", { name: "Review revocation" }));
    await user.click(screen.getByRole("button", { name: "Revoke and publish KRL" }));

    await waitFor(() => expect(apiMock.revokeSSHCertificate).toHaveBeenCalledWith({ serial: 42, reason: "operator requested revocation" }, expect.any(String)));
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

  it("recovers an uncertain attested issuance with the same request and idempotency key", async () => {
    apiMock.issueAttestedSSHUserCert
      .mockRejectedValueOnce(new ApiError(503, JSON.stringify({ title: "Service Unavailable", status: 503, detail: "response lost after signing" })))
      .mockResolvedValueOnce({
        certificate: "ssh-rsa-cert-v01@openssh.com AAAA",
        serial: 42,
        key_id: "jit-deployer",
        subject: "system:serviceaccount:default:deployer",
        principals: ["web"],
        approver: "ssh-approver",
        source_addresses: ["10.0.0.0/24"],
        force_command: "/usr/local/bin/deploy",
        valid_before: "2026-06-27T10:15:00Z",
        attestation: { id: "att-1", method: "k8s_sat", subject: "system:serviceaccount:default:deployer", selectors: [], verified_at: "2026-06-27T10:00:00Z" },
      });
    const user = userEvent.setup();
    renderSSHTrust();

    const chooser = (await screen.findByRole("heading", { name: "Choose what you want to do" })).closest("section") as HTMLElement;
    await user.click(within(chooser).getByRole("button", { name: "Request SSH access" }));
    await user.type(screen.getByLabelText("Attestation payload base64"), "eyJzdWIiOiJzYSJ9");
    await user.type(screen.getByLabelText("SSH public key"), "ssh-ed25519 AAAATEST user@example.test");
    await user.click(screen.getByRole("button", { name: "Review exact plan" }));
    await user.click(await screen.findByRole("button", { name: "Verify proof and issue SSH certificate" }));

    expect(
      await screen.findByText("The response was uncertain. Retry the unchanged request so trstctl can return the original result instead of issuing twice."),
    ).toBeInTheDocument();
    expect(screen.getByLabelText("Attestation payload base64")).toHaveValue("eyJzdWIiOiJzYSJ9");
    expect(screen.getByLabelText("SSH public key")).toHaveValue("ssh-ed25519 AAAATEST user@example.test");
    await user.click(screen.getByRole("button", { name: "Retry unchanged request" }));

    await waitFor(() => expect(apiMock.issueAttestedSSHUserCert).toHaveBeenCalledTimes(2));
    const first = apiMock.issueAttestedSSHUserCert.mock.calls[0];
    const second = apiMock.issueAttestedSSHUserCert.mock.calls[1];
    expect(second[0]).toEqual(first[0]);
    expect(second[1]).toBe(first[1]);
    expect(await screen.findByRole("heading", { name: "SSH access certificate issued" })).toBeInTheDocument();
  });

  it("keeps review usable when an older node returns null empty arrays", async () => {
    apiMock.previewAttestedSSHUserCert.mockResolvedValueOnce({
      capability: "F45",
      ready: true,
      effect_free: true,
      effective_ttl_seconds: 900,
      required_permission: "certs:issue",
      public_key_fingerprint: "SHA256:ssh-subject",
      authority_fingerprint: "SHA256:ssh-authority",
      approver: "ssh-approver",
      payload_sha256: "proof-digest",
      blockers: null,
      recovery_steps: null,
    });
    const user = userEvent.setup();
    renderSSHTrust();

    const chooser = (await screen.findByRole("heading", { name: "Choose what you want to do" })).closest("section") as HTMLElement;
    await user.click(within(chooser).getByRole("button", { name: "Request SSH access" }));
    await user.type(screen.getByLabelText("Attestation payload base64"), "eyJzdWIiOiJzYSJ9");
    await user.type(screen.getByLabelText("SSH public key"), "ssh-ed25519 AAAATEST user@example.test");
    await user.click(screen.getByRole("button", { name: "Review exact plan" }));

    expect(await screen.findByRole("heading", { name: "Ready to verify and issue" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Verify proof and issue SSH certificate" })).toBeEnabled();
    expect(screen.queryByText("This page stopped unexpectedly")).not.toBeInTheDocument();
  });
});
