import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { ApiError } from "@/lib/api";
import { Secrets } from "@/pages/Secrets";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    secretPage: vi.fn(),
    createSecret: vi.fn(),
    getSecret: vi.fn(),
    rotateSecret: vi.fn(),
    deleteSecret: vi.fn(),
    approveSecretChange: vi.fn(),
    issuePKISecret: vi.fn(),
    machineLogin: vi.fn(),
    createShare: vi.fn(),
    redeemShare: vi.fn(),
    issueEphemeralAPIKey: vi.fn(),
    issueDynamicLease: vi.fn(),
    renewDynamicLease: vi.fn(),
    revokeDynamicLease: vi.fn(),
    encryptTransit: vi.fn(),
    decryptTransit: vi.fn(),
    hmacTransit: vi.fn(),
    rewrapTransit: vi.fn(),
    signTransit: vi.fn(),
    secretRepositoryScanning: vi.fn(),
    thirdPartySecretScanning: vi.fn(),
    ingestThirdPartySecretScan: vi.fn(),
    cloudSecretManagers: vi.fn(),
    secretSyncTargets: vi.fn(),
    kubernetesSecretOperator: vi.fn(),
    secretWorkloadInjection: vi.fn(),
    scanSecrets: vi.fn(),
    syncSecret: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: apiMock };
});

function renderSecrets() {
  return render(
    <MemoryRouter>
      <Secrets />
    </MemoryRouter>,
  );
}

function repoScanPostureFixture() {
  return {
    capability: "CAP-SCAN-01",
    served: true,
    generated_at: "2026-06-29T00:00:00Z",
    scanner: "gitleaks v8.27.2",
    minimum_rules_active: 140,
    providers: [
      {
        id: "github",
        name: "GitHub",
        realtime_triggers: ["push", "pull_request"],
        auth_mode: "authenticated webhook",
        ingest_mode: "normalized GitHub event queues secret_repo discovery",
        ref_types: ["branch", "commit_sha"],
        secret_handling: "redacted metadata only",
        outbox_mode: "discovery.run outbox",
      },
      {
        id: "gitlab",
        name: "GitLab",
        realtime_triggers: ["push", "merge_request"],
        auth_mode: "authenticated webhook",
        ingest_mode: "normalized GitLab event queues secret_repo discovery",
        ref_types: ["branch", "commit_sha"],
        secret_handling: "redacted metadata only",
        outbox_mode: "discovery.run outbox",
      },
      {
        id: "bitbucket",
        name: "Bitbucket",
        realtime_triggers: ["repo:push", "pullrequest:updated"],
        auth_mode: "authenticated webhook",
        ingest_mode: "normalized Bitbucket event queues secret_repo discovery",
        ref_types: ["branch", "commit_sha"],
        secret_handling: "redacted metadata only",
        outbox_mode: "discovery.run outbox",
      },
    ],
    webhook_paths: [
      "/api/v1/secrets/scans/repositories/github/webhook",
      "/api/v1/secrets/scans/repositories/gitlab/webhook",
      "/api/v1/secrets/scans/repositories/bitbucket/webhook",
    ],
    queue_model: "authenticated provider webhook records a tenant-scoped discovery run",
    redaction_model: "rule/file/line only",
    event_flow: ["discovery.source.upserted", "discovery.run.queued", "discovery.finding.recorded", "discovery.run.completed"],
    release_gates: [
      { id: "provider-webhook-contract", command: "go test", artifact: "repo-secret-scan-contract", required: true },
      { id: "architecture-lint", command: "make lint test", artifact: "local gate transcript", required: true },
    ],
    operator_actions: ["install provider webhooks"],
    residuals: ["native provider signature verification remains a follow-up"],
    evidence_refs: ["internal/api/secrets.go"],
    architecture_controls: ["AN-2", "AN-5", "AN-6", "AN-8"],
  };
}

function thirdPartyScanPostureFixture() {
  return {
    capability: "CAP-SCAN-04",
    served: true,
    generated_at: "2026-06-29T00:00:00Z",
    scanner: "gitleaks v8.27.2",
    minimum_rules_active: 140,
    providers: [
      {
        id: "cicd_log",
        name: "CI/CD logs",
        artifact_kinds: ["workflow log", "job trace"],
        ingest_mode: "artifact path queues secret_third_party discovery",
        secret_handling: "raw logs stay outside trstctl; redacted metadata only",
        outbox_mode: "discovery.run outbox",
      },
      {
        id: "container_registry",
        name: "Container registries",
        artifact_kinds: ["manifest", "layer metadata"],
        ingest_mode: "artifact path queues secret_third_party discovery",
        secret_handling: "raw registry artifacts stay outside trstctl",
        outbox_mode: "discovery.run outbox",
      },
      {
        id: "slack",
        name: "Slack",
        artifact_kinds: ["export jsonl", "message transcript"],
        ingest_mode: "artifact path queues secret_third_party discovery",
        secret_handling: "raw chat exports stay outside trstctl",
        outbox_mode: "discovery.run outbox",
      },
      {
        id: "jira",
        name: "Jira",
        artifact_kinds: ["issue export", "attachment manifest"],
        ingest_mode: "artifact path queues secret_third_party discovery",
        secret_handling: "raw issue exports stay outside trstctl",
        outbox_mode: "discovery.run outbox",
      },
    ],
    ingest_paths: [
      "/api/v1/secrets/scans/third-party/cicd_log/ingest",
      "/api/v1/secrets/scans/third-party/container_registry/ingest",
      "/api/v1/secrets/scans/third-party/slack/ingest",
      "/api/v1/secrets/scans/third-party/jira/ingest",
    ],
    queue_model: "artifact-path ingest records a tenant-scoped discovery run",
    redaction_model: "rule/file/line and credential_ref only",
    event_flow: ["discovery.source.upserted", "discovery.run.queued", "discovery.finding.recorded", "discovery.run.completed"],
    release_gates: [
      { id: "third-party-artifact-contract", command: "go test", artifact: "cap-scan-04-contract", required: true },
      { id: "architecture-lint", command: "make lint test", artifact: "local gate transcript", required: true },
    ],
    operator_actions: ["export CI log, registry, Slack, or Jira artifacts to a scanner-readable path"],
    residuals: ["native provider API polling and signature verification remain follow-ups"],
    evidence_refs: ["internal/api/secrets.go", "internal/server/discovery.go"],
    architecture_controls: ["AN-2", "AN-5", "AN-6", "AN-8"],
  };
}

function syncTargetCatalogFixture() {
  const targets: Array<[string, string, string]> = [
    ["aws-secrets-manager", "AWS Secrets Manager", "aws"],
    ["gcp-secret-manager", "GCP Secret Manager", "gcp"],
    ["azure-key-vault", "Azure Key Vault", "azure"],
    ["github-actions", "GitHub Actions", "github"],
    ["gitlab-ci", "GitLab CI", "gitlab"],
    ["vercel-netlify", "Vercel", "vercel"],
    ["ci", "Generic CI secret endpoint", "ci"],
  ];
  return {
    capability: "CAP-SECR-03",
    served: true,
    generated_at: "2026-06-29T00:00:00Z",
    configured_targets: targets.map(([id]) => id),
    outbox_mode: "sealed PostgreSQL outbox",
    evidence_refs: ["internal/secretsync/pushers.go"],
    residuals: ["operator config required"],
    targets: targets.map(([id, name, platform]) => ({
      id,
      name,
      platform,
      configured: true,
      delivery_mode: `${name} delivery`,
      auth_mode: "operator token",
      wire_format: "base64 payload",
      secret_handling: "metadata only",
      capabilities: ["outbox-delivery"],
    })),
  };
}

function cloudSecretManagerFixture() {
  return {
    capability: "CAP-SEC-04",
    served: true,
    generated_at: "2026-06-29T00:00:00Z",
    summary: {
      total_providers: 4,
      discovery_supported: 4,
      discovery_configured: 4,
      sync_supported: 3,
      sync_configured: 3,
      fully_configured: 4,
      configured_connections: 7,
    },
    configured_providers: ["aws-secrets-manager", "azure-key-vault", "gcp-secret-manager", "hashicorp-vault"],
    configured_sync_targets: ["aws-secrets-manager", "azure-key-vault", "gcp-secret-manager"],
    discovery_mode: "tenant-scoped cloud_secret source execution",
    outbox_mode: "sealed PostgreSQL outbox",
    secret_handling: "metadata only",
    architecture_controls: ["AN-1", "AN-2", "AN-5", "AN-6", "AN-8"],
    evidence_refs: ["internal/api/secrets.go", "internal/server/secrets_sync_served_test.go"],
    residuals: ["operator config required"],
    recommended_next_actions: ["configure cloud_secret sources"],
    providers: [
      ["aws-secrets-manager", "AWS Secrets Manager", "aws", true, true],
      ["gcp-secret-manager", "GCP Secret Manager", "gcp", true, true],
      ["azure-key-vault", "Azure Key Vault", "azure", true, true],
      ["hashicorp-vault", "HashiCorp Vault KV", "vault", true, false],
    ].map(([id, name, platform, discoveryConfigured, syncConfigured]) => ({
      id,
      name,
      platform,
      discovery_supported: true,
      discovery_configured: Boolean(discoveryConfigured),
      discovery_source_kind: "cloud_secret",
      discovery_source_count: 1,
      discovery_read_ops: ["GET only"],
      sync_supported: id !== "hashicorp-vault",
      sync_configured: Boolean(syncConfigured),
      sync_target_id: id === "hashicorp-vault" ? "" : String(id),
      sync_write_operation: id === "hashicorp-vault" ? "" : "provider write",
      secret_handling: "secret values are byte-backed and never rendered",
      capabilities: ["cloud-secret-manager"],
      evidence_refs: ["internal/secretsync/pushers.go"],
    })),
  };
}

function kubernetesSecretOperatorFixture() {
  return {
    capability: "CAP-SECR-04",
    served: true,
    generated_at: "2026-06-29T00:00:00Z",
    crds: [
      {
        kind: "TrstctlSecretSync",
        api_group: "trstctl.com",
        api_version: "trstctl.com/v1alpha1",
        plural: "trstctlsecretsyncs",
        status: "served",
        owns: ["Kubernetes Secret data", "status.contentHash"],
        evidence_ref: "deploy/operator/crd.yaml",
      },
      {
        kind: "TrstctlControlPlane",
        api_group: "trstctl.com",
        api_version: "trstctl.com/v1alpha1",
        plural: "trstctlcontrolplanes",
        status: "served",
        owns: ["control-plane Deployment"],
        evidence_ref: "deploy/operator/crd.yaml",
      },
    ],
    sync_flow: ["resolve through served secret store", "write Kubernetes Secret", "patch workload templates"],
    reload_workloads: ["Deployment", "StatefulSet", "DaemonSet"],
    secret_handling: "operator reads resolved values as bytes and reports metadata only",
    architecture_controls: ["control-plane token from Secret reference"],
    evidence_refs: ["internal/operator/secretsync.go", "deploy/operator/crd.yaml"],
    residuals: ["operator still uses a polling reconcile loop rather than a shared informer/workqueue controller"],
    recommended_next_actions: ["move to informer-backed queues"],
  };
}

function secretWorkloadInjectionFixture() {
  return {
    capability: "CAP-SECR-05",
    served: true,
    generated_at: "2026-06-30T00:00:00Z",
    crd: {
      kind: "TrstctlSecretInjection",
      api_group: "trstctl.com",
      api_version: "trstctl.com/v1alpha1",
      plural: "trstctlsecretinjections",
      status: "served",
      owns: ["app-container file mounts", "trstctl-agent secret-injection sidecar"],
      evidence_ref: "deploy/operator/crd.yaml",
    },
    modes: [
      {
        id: "file",
        name: "Shared-volume file injection",
        delivered_by: "trstctl-agent",
        workload_change: "pod template patch",
        secret_handling: "byte-backed",
        capabilities: ["no-code-workload-injection"],
      },
      {
        id: "env",
        name: "Environment reference injection",
        delivered_by: "Kubernetes valueFrom",
        workload_change: "env reference patch",
        secret_handling: "metadata-only",
        capabilities: ["env-reference"],
      },
    ],
    workload_kinds: ["Deployment", "StatefulSet", "DaemonSet"],
    sidecar_command: ["/usr/local/bin/trstctl-agent", "--secret-inject"],
    annotations: ["trstctl.com/secret-injection-hash"],
    sync_dependency: "TrstctlSecretSync",
    secret_handling: "operator reads source Secret metadata; sidecar copies bytes without string conversion",
    architecture_controls: ["AN-8"],
    evidence_refs: ["internal/operator/secretinjection.go", "internal/agent/secretinject/secretinject.go"],
    residuals: ["operator still uses a polling reconcile loop rather than a shared informer/workqueue controller"],
    recommended_next_actions: ["declare TrstctlSecretInjection items"],
  };
}

describe("secrets surface", () => {
  beforeEach(() => {
    localStorage.clear();
    sessionStorage.clear();
    vi.restoreAllMocks();
    for (const mock of Object.values(apiMock)) mock.mockReset();
    apiMock.secretPage.mockResolvedValue({
      items: [
        {
          name: "app/db/password",
          version: 3,
          created_at: "2026-06-18T10:00:00Z",
          updated_at: "2026-06-19T10:00:00Z",
        },
      ],
    });
    apiMock.createSecret.mockResolvedValue({ name: "app/cache/token", version: 1 });
    apiMock.getSecret.mockResolvedValue({ name: "app/db/password", value: "SUPER-SECRET", version: 3 });
    apiMock.rotateSecret.mockResolvedValue({ name: "app/db/password", version: 4, updated_at: "2026-06-19T11:00:00Z" });
    apiMock.deleteSecret.mockResolvedValue(undefined);
    apiMock.approveSecretChange.mockResolvedValue({
      resource: "secret:app/db/password",
      action: "rotate",
      approver: "bob",
      approvals: 2,
    });
    apiMock.issuePKISecret.mockResolvedValue({
      serial: "pki-01",
      certificate: "-----BEGIN CERTIFICATE-----\nCERT\n-----END CERTIFICATE-----",
      private_key: "-----BEGIN PRIVATE KEY-----\nKEY\n-----END PRIVATE KEY-----",
    });
    apiMock.machineLogin.mockResolvedValue({
      session_id: "sess-1",
      principal: "svc-api",
      method: "token",
      scopes: ["secrets:read", "secrets:write"],
      expires_at: "2026-06-19T13:00:00Z",
    });
    apiMock.createShare.mockResolvedValue({ token: "SHARE-TOKEN-1", expires_at: "2026-06-19T13:30:00Z" });
    apiMock.redeemShare.mockResolvedValue({ value: "redeemed-secret" });
    apiMock.issueEphemeralAPIKey.mockResolvedValue({
      id: "33333333-3333-3333-3333-333333333333",
      tenant_id: "44444444-4444-4444-4444-444444444444",
      subject: "ci/deploy-preview",
      scopes: ["repo:payments:read", "deploy:staging:write"],
      created_at: "2026-06-19T13:00:00Z",
      expires_at: "2026-06-19T13:15:00Z",
      token: "epk_live_reveal_once_123",
    });
    apiMock.issueDynamicLease.mockResolvedValue({
      id: "lease-postgres-1",
      provider: "postgresql",
      role: "readonly-reporting",
      state: "active",
      issued_at: "2026-06-19T13:00:00Z",
      expires_at: "2026-06-19T13:20:00Z",
      credential: "postgres://lease-secret",
    });
    apiMock.renewDynamicLease.mockResolvedValue({
      id: "lease-postgres-1",
      provider: "postgresql",
      role: "readonly-reporting",
      state: "active",
      issued_at: "2026-06-19T13:00:00Z",
      expires_at: "2026-06-19T13:25:00Z",
    });
    apiMock.revokeDynamicLease.mockResolvedValue({
      id: "lease-postgres-1",
      provider: "postgresql",
      role: "readonly-reporting",
      state: "revoked",
      issued_at: "2026-06-19T13:00:00Z",
      expires_at: "2026-06-19T13:25:00Z",
    });
    apiMock.encryptTransit.mockResolvedValue({ ciphertext: "trst:v1:ciphertext", version: 4 });
    apiMock.decryptTransit.mockResolvedValue({ plaintext: "aGVsbG8gdHJhbnNpdA==" });
    apiMock.hmacTransit.mockResolvedValue({ hmac: "hmac-base64" });
    apiMock.rewrapTransit.mockResolvedValue({ ciphertext: "trst:v4:rewrapped", version: 4 });
    apiMock.signTransit.mockResolvedValue({ signature: "signature-base64", public_der: "public-der-base64" });
    apiMock.secretRepositoryScanning.mockResolvedValue(repoScanPostureFixture());
    apiMock.thirdPartySecretScanning.mockResolvedValue(thirdPartyScanPostureFixture());
    apiMock.ingestThirdPartySecretScan.mockResolvedValue({
      capability: "CAP-SCAN-04",
      provider: "slack",
      source: "acme/slack",
      source_id: "secret-third-party:slack:acme-slack",
      run_id: "66666666-6666-6666-6666-666666666666",
      queued: true,
      status: "queued",
      outbox_destination: "discovery.run",
      scanner: "gitleaks v8.27.2",
      discovery_run_path: "/api/v1/discovery/runs/66666666-6666-6666-6666-666666666666",
    });
    apiMock.cloudSecretManagers.mockResolvedValue(cloudSecretManagerFixture());
    apiMock.secretSyncTargets.mockResolvedValue(syncTargetCatalogFixture());
    apiMock.kubernetesSecretOperator.mockResolvedValue(kubernetesSecretOperatorFixture());
    apiMock.secretWorkloadInjection.mockResolvedValue(secretWorkloadInjectionFixture());
    apiMock.scanSecrets.mockResolvedValue({
      run_id: "55555555-5555-5555-5555-555555555555",
      scanner: "gitleaks",
      engine_version: "8.18.2",
      mode: "workspace",
      custom_rules: false,
      capabilities: ["pattern-rules", "entropy-rules", "default-rules-100-plus", "workspace"],
      rules_active: 121,
      findings_count: 1,
      findings: [{ rule_id: "generic-api-key", file: "config/ci.yml", line: 42, credential_ref: "sha256:6e5a...91bb" }],
    });
    apiMock.syncSecret.mockResolvedValue({
      name: "app/db/password",
      target: "kubernetes/prod",
      remote_key: "Secret/payments-db/password",
      enqueued: true,
      delivered: false,
    });
  });

  it("lists metadata, creates, reveals, rotates, and deletes native secrets without storage writes", async () => {
    const storageSpy = vi.spyOn(Storage.prototype, "setItem");
    const user = userEvent.setup();
    renderSecrets();

    expect(await screen.findByRole("heading", { name: "Secrets" })).toBeInTheDocument();
    expect(screen.getByRole("table", { name: "Native secret metadata" })).toBeInTheDocument();
    expect(screen.getByRole("searchbox", { name: "Search native secret metadata" })).toBeInTheDocument();
    expect(screen.getByText("app/db/password")).toBeInTheDocument();
    expect(screen.getByText("native store")).toBeInTheDocument();
    expect(screen.getByText("v3")).toBeInTheDocument();
    expect(screen.getByText("Scheduled rotation and downstream sync aren't in the console yet")).toBeInTheDocument();
    expect(screen.getByText(/Rollback-safe static rotation is available for configured backends/i)).toBeInTheDocument();
    expect(screen.getByText("Auth-method administration isn't in the console yet")).toBeInTheDocument();
    expect(screen.getByText(/revoked methods are not available in the console yet/i)).toBeInTheDocument();
    expect(screen.getByText("Secret-change approvals")).toBeInTheDocument();
    expect(screen.getByText("No pending secret changes captured in this browser session.")).toBeInTheDocument();
    expect(screen.queryByText("Secret-change approvals aren't in the console yet")).not.toBeInTheDocument();
    expect(screen.queryByText("SUPER-SECRET")).not.toBeInTheDocument();
    await waitFor(() => expect(apiMock.cloudSecretManagers).toHaveBeenCalled());
    expect(screen.getByText("CAP-SEC-04")).toBeInTheDocument();
    expect(screen.getByText("4 discovery providers, 3 sync targets configured")).toBeInTheDocument();
    expect(screen.getByText("HashiCorp Vault KV")).toBeInTheDocument();
    expect(screen.getByText("not supported")).toBeInTheDocument();
    await waitFor(() => expect(apiMock.kubernetesSecretOperator).toHaveBeenCalled());
    expect(screen.getByText("CAP-SECR-04")).toBeInTheDocument();
    expect(screen.getByText("TrstctlSecretSync - served")).toBeInTheDocument();
    expect(screen.getAllByText("StatefulSet").length).toBeGreaterThan(0);
    await waitFor(() => expect(apiMock.secretWorkloadInjection).toHaveBeenCalled());
    expect(screen.getByText("CAP-SECR-05")).toBeInTheDocument();
    expect(screen.getByText("TrstctlSecretInjection - served")).toBeInTheDocument();
    expect(screen.getByText("Shared-volume file injection")).toBeInTheDocument();

    await user.type(screen.getByRole("searchbox", { name: "Search native secret metadata" }), "cache");
    expect(screen.getByText("No secret metadata matches the current search.")).toBeInTheDocument();
    expect(screen.queryByText("app/db/password")).not.toBeInTheDocument();
    await user.clear(screen.getByRole("searchbox", { name: "Search native secret metadata" }));
    expect(screen.getByText("app/db/password")).toBeInTheDocument();

    const metadataRow = screen.getAllByRole("row", { name: /app\/db\/password/i })[0];
    await user.click(within(metadataRow).getByRole("button", { name: /view metadata/i }));
    const drawer = screen.getByRole("dialog", { name: "Secret metadata" });
    expect(within(drawer).getByText("app/db/password")).toBeInTheDocument();
    expect(within(drawer).getByText("native store")).toBeInTheDocument();
    expect(within(drawer).getByText("v3")).toBeInTheDocument();
    expect(within(drawer).queryByText("SUPER-SECRET")).not.toBeInTheDocument();
    await user.click(within(drawer).getByRole("button", { name: /close/i }));

    const createForm = within(screen.getByRole("form", { name: "Create secret" }));
    await user.type(createForm.getByLabelText("Secret name"), "app/cache/token");
    await user.type(createForm.getByLabelText("Secret value"), "new-secret-value");
    await user.click(createForm.getByRole("button", { name: /create secret/i }));

    await waitFor(() => expect(apiMock.createSecret).toHaveBeenCalledWith({ name: "app/cache/token", value: "new-secret-value" }));
    expect(await screen.findByText(/stored as version 1/i)).toBeInTheDocument();
    expect(screen.queryByText("new-secret-value")).not.toBeInTheDocument();

    const row = screen.getAllByRole("row", { name: /app\/db\/password/i })[0];
    await user.click(within(row).getByRole("button", { name: /reveal once/i }));
    expect(await screen.findByText("SUPER-SECRET")).toBeInTheDocument();

    await user.click(within(row).getByRole("button", { name: /prepare rotate/i }));
    const rotateForm = within(screen.getByRole("form", { name: "Rotate secret" }));
    await user.type(rotateForm.getByLabelText("Replacement value"), "rotated-secret");
    await user.click(rotateForm.getByRole("button", { name: /rotate secret/i }));
    await waitFor(() =>
      expect(apiMock.rotateSecret).toHaveBeenCalledWith("app/db/password", {
        name: "app/db/password",
        value: "rotated-secret",
      }),
    );
    expect(await screen.findByText(/rotated to version 4/i)).toBeInTheDocument();
    expect(screen.queryByText("rotated-secret")).not.toBeInTheDocument();

    await user.click(within(screen.getAllByRole("row", { name: /app\/db\/password/i })[0]).getByRole("button", { name: /prepare delete/i }));
    const deleteForm = within(screen.getByRole("form", { name: "Delete secret" }));
    await user.type(deleteForm.getByLabelText("Type the exact secret name"), "app/db/password");
    await user.click(deleteForm.getByRole("button", { name: /delete secret/i }));
    await waitFor(() => expect(apiMock.deleteSecret).toHaveBeenCalledWith("app/db/password"));
    expect(await screen.findByText(/deleted from the native store/i)).toBeInTheDocument();

    expect(storageSpy).not.toHaveBeenCalled();
    expect(localStorage.length).toBe(0);
    expect(sessionStorage.length).toBe(0);
  });

  it("queues denied secret changes for distinct approval and retry completion", async () => {
    const user = userEvent.setup();
    apiMock.rotateSecret
      .mockRejectedValueOnce(
        new ApiError(403, JSON.stringify({ detail: "dual control: this action has not been approved by the required number of distinct approvers" })),
      )
      .mockResolvedValueOnce({ name: "app/db/password", version: 4, updated_at: "2026-06-19T11:00:00Z" });
    apiMock.deleteSecret
      .mockRejectedValueOnce(
        new ApiError(403, JSON.stringify({ detail: "dual control: this action has not been approved by the required number of distinct approvers" })),
      )
      .mockResolvedValueOnce(undefined);
    apiMock.approveSecretChange
      .mockResolvedValueOnce({ resource: "secret:app/db/password", action: "rotate", approver: "bob", approvals: 2 })
      .mockResolvedValueOnce({ resource: "secret:app/db/password", action: "delete", approver: "carol", approvals: 2 });

    renderSecrets();
    await screen.findByText("app/db/password");

    await user.click(within(screen.getAllByRole("row", { name: /app\/db\/password/i })[0]).getByRole("button", { name: /prepare rotate/i }));
    const rotateForm = within(screen.getByRole("form", { name: "Rotate secret" }));
    await user.type(rotateForm.getByLabelText("Replacement value"), "approval-rotate-value");
    await user.click(rotateForm.getByRole("button", { name: /rotate secret/i }));

    await waitFor(() =>
      expect(apiMock.rotateSecret).toHaveBeenNthCalledWith(1, "app/db/password", {
        name: "app/db/password",
        value: "approval-rotate-value",
      }),
    );
    expect(await screen.findByText("Rotation is waiting for secret-change approval.")).toBeInTheDocument();
    expect(screen.getByText("Rotate/update - app/db/password")).toBeInTheDocument();

    let approvalList = screen.getByRole("list", { name: "Pending secret-change approvals" });
    await user.click(within(approvalList).getByRole("button", { name: /approve rotate\/update for app\/db\/password/i }));
    await waitFor(() => expect(apiMock.approveSecretChange).toHaveBeenNthCalledWith(1, "app/db/password", "rotate"));
    expect(await screen.findByText(/bob approved Rotate\/update for app\/db\/password/i)).toBeInTheDocument();

    approvalList = screen.getByRole("list", { name: "Pending secret-change approvals" });
    await user.click(within(approvalList).getByRole("button", { name: /retry rotate\/update for app\/db\/password/i }));
    await waitFor(() => expect(apiMock.rotateSecret).toHaveBeenCalledTimes(2));
    expect(apiMock.rotateSecret).toHaveBeenLastCalledWith("app/db/password", {
      name: "app/db/password",
      value: "approval-rotate-value",
    });
    expect(await screen.findByText(/rotated to version 4 after approval/i)).toBeInTheDocument();
    expect(screen.queryByDisplayValue("approval-rotate-value")).not.toBeInTheDocument();

    await user.click(within(screen.getAllByRole("row", { name: /app\/db\/password/i })[0]).getByRole("button", { name: /prepare delete/i }));
    const deleteForm = within(screen.getByRole("form", { name: "Delete secret" }));
    await user.type(deleteForm.getByLabelText("Type the exact secret name"), "app/db/password");
    await user.click(deleteForm.getByRole("button", { name: /delete secret/i }));

    await waitFor(() => expect(apiMock.deleteSecret).toHaveBeenNthCalledWith(1, "app/db/password"));
    expect(await screen.findByText("Delete is waiting for secret-change approval.")).toBeInTheDocument();
    expect(screen.getByText("Delete - app/db/password")).toBeInTheDocument();

    approvalList = screen.getByRole("list", { name: "Pending secret-change approvals" });
    await user.click(within(approvalList).getByRole("button", { name: /approve delete for app\/db\/password/i }));
    await waitFor(() => expect(apiMock.approveSecretChange).toHaveBeenNthCalledWith(2, "app/db/password", "delete"));
    expect(await screen.findByText(/carol approved Delete for app\/db\/password/i)).toBeInTheDocument();

    approvalList = screen.getByRole("list", { name: "Pending secret-change approvals" });
    await user.click(within(approvalList).getByRole("button", { name: /retry delete for app\/db\/password/i }));
    await waitFor(() => expect(apiMock.deleteSecret).toHaveBeenCalledTimes(2));
    expect(apiMock.deleteSecret).toHaveBeenLastCalledWith("app/db/password");
    expect(await screen.findByText(/deleted after approval/i)).toBeInTheDocument();
  });

  it("shows developer snippets and runs an access test without rendering the value", async () => {
    const user = userEvent.setup();
    renderSecrets();
    await screen.findByText("app/db/password");

    expect(screen.getByText(/trstctl secrets get app\/db\/password/)).toBeInTheDocument();
    expect(screen.getByText(/client\.secrets\.get/)).toBeInTheDocument();
    expect(screen.queryByText("SUPER-SECRET")).not.toBeInTheDocument();

    const accessForm = within(screen.getByRole("form", { name: "Secret access test" }));
    await user.click(accessForm.getByRole("button", { name: /run access test/i }));

    await waitFor(() => expect(apiMock.getSecret).toHaveBeenCalledWith("app/db/password"));
    expect(await screen.findByText(/Access test passed for app\/db\/password/i)).toBeInTheDocument();
    expect(screen.queryByText("SUPER-SECRET")).not.toBeInTheDocument();
  });

  it("issues ephemeral API keys, runs secret scans, and drives leases", async () => {
    const storageSpy = vi.spyOn(Storage.prototype, "setItem");
    const user = userEvent.setup();
    renderSecrets();
    await screen.findByText("app/db/password");

    expect(screen.getByRole("heading", { name: "Ephemeral API keys" })).toBeInTheDocument();
    expect(screen.getByText("Reveal-once key issuance")).toBeInTheDocument();
    expect(screen.getByText(/short-lived token/i)).toBeInTheDocument();
    const issueForm = within(screen.getByRole("form", { name: "Issue ephemeral API key" }));
    await user.type(issueForm.getByLabelText("Subject"), "ci/deploy-preview");
    await user.type(issueForm.getByLabelText("Scopes"), "repo:payments:read, deploy:staging:write");
    await user.clear(issueForm.getByLabelText("TTL seconds"));
    await user.type(issueForm.getByLabelText("TTL seconds"), "900");
    await user.click(issueForm.getByRole("button", { name: /issue api key/i }));

    await waitFor(() =>
      expect(apiMock.issueEphemeralAPIKey).toHaveBeenCalledWith({
        subject: "ci/deploy-preview",
        scopes: ["repo:payments:read", "deploy:staging:write"],
        ttl_seconds: 900,
      }),
    );
    expect(await screen.findByText("epk_live_reveal_once_123")).toBeInTheDocument();
    expect(screen.getByText("33333333-3333-3333-3333-333333333333")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /dismiss/i }));
    expect(screen.queryByText("epk_live_reveal_once_123")).not.toBeInTheDocument();

    expect(screen.getByRole("heading", { name: "Code and CI secret scanning bridge" })).toBeInTheDocument();
    await waitFor(() => expect(apiMock.secretRepositoryScanning).toHaveBeenCalled());
    await waitFor(() => expect(apiMock.thirdPartySecretScanning).toHaveBeenCalled());
    expect(screen.getByText("CAP-SCAN-01")).toBeInTheDocument();
    expect(screen.getByText("CAP-SCAN-04")).toBeInTheDocument();
    expect(screen.getByText("GitHub")).toBeInTheDocument();
    expect(screen.getByText("GitLab")).toBeInTheDocument();
    expect(screen.getByText("Bitbucket")).toBeInTheDocument();
    expect(screen.getAllByText("Slack").length).toBeGreaterThan(0);
    expect(screen.getByText("/api/v1/secrets/scans/third-party/slack/ingest")).toBeInTheDocument();
    expect(screen.getByText("/api/v1/secrets/scans/repositories/github/webhook")).toBeInTheDocument();
    const thirdPartyForm = within(screen.getByRole("form", { name: "Queue third-party secret scan" }));
    await user.selectOptions(thirdPartyForm.getByLabelText("External source"), "slack");
    await user.type(thirdPartyForm.getByLabelText("Source ref"), "acme/slack");
    await user.type(thirdPartyForm.getByLabelText("Artifact path"), "/var/lib/trstctl/exports/slack.jsonl");
    await user.type(thirdPartyForm.getByLabelText("Event"), "message_export");
    await user.click(thirdPartyForm.getByRole("button", { name: /queue scan/i }));
    await waitFor(() =>
      expect(apiMock.ingestThirdPartySecretScan).toHaveBeenCalledWith("slack", {
        source: "acme/slack",
        artifact_path: "/var/lib/trstctl/exports/slack.jsonl",
        event: "message_export",
      }),
    );
    expect(await screen.findByText(/slack scan queued as run 66666666-6666-6666-6666-666666666666/i)).toBeInTheDocument();
    const scanForm = within(screen.getByRole("form", { name: "Run secret scan" }));
    await user.type(scanForm.getByLabelText("Path"), "github.com/example/payments");
    await user.click(scanForm.getByRole("button", { name: /run scan/i }));
    await waitFor(() => expect(apiMock.scanSecrets).toHaveBeenCalledWith({ path: "github.com/example/payments", mode: "workspace" }));
    expect(await screen.findByText("55555555-5555-5555-5555-555555555555")).toBeInTheDocument();
    expect(screen.getByText("entropy-rules")).toBeInTheDocument();
    expect(screen.getByText("generic-api-key")).toBeInTheDocument();
    expect(screen.getByText("config/ci.yml")).toBeInTheDocument();
    expect(screen.getByText("sha256:6e5a...91bb")).toBeInTheDocument();

    expect(screen.getByRole("heading", { name: "Dynamic secrets" })).toBeInTheDocument();
    expect(screen.getByText("No dynamic lease issued yet.")).toBeInTheDocument();
    const leaseForm = within(screen.getByRole("form", { name: "Issue dynamic secret lease" }));
    await user.selectOptions(leaseForm.getByLabelText("Provider"), "postgresql");
    await user.type(leaseForm.getByLabelText("Role"), "readonly-reporting");
    await user.clear(leaseForm.getByLabelText("TTL seconds"));
    await user.type(leaseForm.getByLabelText("TTL seconds"), "1200");
    await user.click(leaseForm.getByRole("button", { name: /issue lease/i }));
    await waitFor(() => expect(apiMock.issueDynamicLease).toHaveBeenCalledWith({ provider: "postgresql", role: "readonly-reporting", ttl_seconds: 1200 }));
    expect(await screen.findByText("lease-postgres-1")).toBeInTheDocument();
    expect(screen.getByText("postgres://lease-secret")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /dismiss/i }));
    expect(screen.queryByText("postgres://lease-secret")).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /renew lease/i }));
    await waitFor(() => expect(apiMock.renewDynamicLease).toHaveBeenCalledWith("lease-postgres-1", { extend_seconds: 300 }));
    await user.click(screen.getByRole("button", { name: /revoke lease/i }));
    await waitFor(() => expect(apiMock.revokeDynamicLease).toHaveBeenCalledWith("lease-postgres-1"));
    expect(await screen.findByText("revoked")).toBeInTheDocument();
    expect(screen.getByText("Lease state")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /mint key|triage leak|rotate leaked/i })).not.toBeInTheDocument();
    expect(storageSpy).not.toHaveBeenCalled();
    expect(localStorage.length).toBe(0);
    expect(sessionStorage.length).toBe(0);
  });

  it("runs transit encrypt/decrypt and keeps secret sync disclosure scoped", async () => {
    const storageSpy = vi.spyOn(Storage.prototype, "setItem");
    const user = userEvent.setup();
    renderSecrets();
    await screen.findByText("app/db/password");

    expect(screen.getByRole("heading", { name: "Transit and KMIP" })).toBeInTheDocument();
    const transitForm = within(screen.getByRole("form", { name: "Transit encrypt and decrypt" }));
    await user.type(transitForm.getByLabelText("Key name"), "payments-pii");
    await user.type(transitForm.getByLabelText("Plaintext"), "hello transit");
    await user.type(transitForm.getByLabelText("AAD"), "tenant-a");
    await user.click(transitForm.getByRole("button", { name: /encrypt/i }));
    await waitFor(() =>
      expect(apiMock.encryptTransit).toHaveBeenCalledWith({
        key: "payments-pii",
        plaintext: "aGVsbG8gdHJhbnNpdA==",
        aad: "dGVuYW50LWE=",
      }),
    );
    expect(transitForm.getByLabelText("Plaintext")).toHaveValue("");
    expect(screen.getAllByText("trst:v1:ciphertext").length).toBeGreaterThan(0);
    expect(screen.getByText("v4")).toBeInTheDocument();
    await user.click(transitForm.getByRole("button", { name: /decrypt/i }));
    await waitFor(() =>
      expect(apiMock.decryptTransit).toHaveBeenCalledWith({
        key: "payments-pii",
        ciphertext: "trst:v1:ciphertext",
        aad: "dGVuYW50LWE=",
      }),
    );
    expect(await screen.findByText("hello transit")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /dismiss/i }));
    expect(screen.queryByText("hello transit")).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: /compute hmac/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /sign message/i })).toBeInTheDocument();

    expect(screen.getByRole("heading", { name: "Secret sync and platform integrations" })).toBeInTheDocument();
    const syncForm = within(screen.getByRole("form", { name: "Sync stored secret" }));
    expect(syncForm.getByLabelText("Secret name")).toHaveValue("app/db/password");
    await user.type(syncForm.getByLabelText("Target"), "kubernetes/prod");
    await user.type(syncForm.getByLabelText("Remote key"), "Secret/payments-db/password");
    await user.click(syncForm.getByRole("button", { name: /sync secret/i }));
    await waitFor(() =>
      expect(apiMock.syncSecret).toHaveBeenCalledWith({
        name: "app/db/password",
        target: "kubernetes/prod",
        remote_key: "Secret/payments-db/password",
      }),
    );
    expect(await screen.findByText("Queued")).toBeInTheDocument();
    expect(screen.getByText("Not delivered")).toBeInTheDocument();
    expect(screen.getByText("Secret/payments-db/password")).toBeInTheDocument();
    expect(screen.queryByText(/raw target token|BEGIN .* PRIVATE KEY/)).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /push|rollback/i })).not.toBeInTheDocument();
    expect(storageSpy).not.toHaveBeenCalled();
    expect(localStorage.length).toBe(0);
    expect(sessionStorage.length).toBe(0);
  });

  it("issues PKI secrets, tests machine login, and creates/redeems one-time shares once", async () => {
    const storageSpy = vi.spyOn(Storage.prototype, "setItem");
    apiMock.redeemShare
      .mockResolvedValueOnce({ value: "redeemed-secret" })
      .mockRejectedValueOnce(new ApiError(410, JSON.stringify({ detail: "share already redeemed" })));
    const user = userEvent.setup();
    renderSecrets();
    await screen.findByText("app/db/password");

    const pkiForm = within(screen.getByRole("form", { name: "Issue PKI secret" }));
    await user.type(pkiForm.getByLabelText("Common name"), "svc.internal");
    await user.clear(pkiForm.getByLabelText("TTL seconds"));
    await user.type(pkiForm.getByLabelText("TTL seconds"), "600");
    await user.click(pkiForm.getByRole("button", { name: /issue pki secret/i }));

    await waitFor(() => expect(apiMock.issuePKISecret).toHaveBeenCalledWith({ common_name: "svc.internal", ttl_seconds: 600 }));
    expect(await screen.findByText(/PKI bundle pki-01/i)).toBeInTheDocument();
    expect(screen.getByText(/BEGIN PRIVATE KEY/)).toBeInTheDocument();

    const loginForm = within(screen.getByRole("form", { name: "Machine login test" }));
    await user.type(loginForm.getByLabelText("Credential"), "tenant-bound-machine-token");
    await user.click(loginForm.getByRole("button", { name: /test login/i }));

    await waitFor(() => expect(apiMock.machineLogin).toHaveBeenCalledWith({ method: "token", credential: "tenant-bound-machine-token" }));
    expect(screen.getByText("sess-1")).toBeInTheDocument();
    expect(screen.getByText("svc-api")).toBeInTheDocument();
    expect(loginForm.getByLabelText("Credential")).toHaveValue("");
    expect(screen.queryByText("tenant-bound-machine-token")).not.toBeInTheDocument();

    const shareForm = within(screen.getByRole("form", { name: "Create one-time share" }));
    await user.type(shareForm.getByLabelText("Value to share"), "share-this-once");
    await user.click(shareForm.getByRole("button", { name: /create share/i }));
    await waitFor(() => expect(apiMock.createShare).toHaveBeenCalledWith({ value: "share-this-once", ttl_seconds: 300 }));
    expect(await screen.findByText("SHARE-TOKEN-1")).toBeInTheDocument();
    expect(screen.queryByText("share-this-once")).not.toBeInTheDocument();

    const redeemForm = within(screen.getByRole("form", { name: "Redeem one-time share" }));
    await user.type(redeemForm.getByLabelText("Share token"), "SHARE-TOKEN-1");
    await user.click(redeemForm.getByRole("button", { name: /redeem share/i }));
    await waitFor(() => expect(apiMock.redeemShare).toHaveBeenCalledWith({ token: "SHARE-TOKEN-1" }));
    expect(await screen.findByText("redeemed-secret")).toBeInTheDocument();

    await user.click(redeemForm.getByRole("button", { name: /redeem share/i }));
    expect(await screen.findByText("share already redeemed")).toBeInTheDocument();

    expect(storageSpy).not.toHaveBeenCalled();
    expect(localStorage.length).toBe(0);
    expect(sessionStorage.length).toBe(0);
  });

  it("shows the fail-closed disabled state when secrets API or KEK is unavailable", async () => {
    apiMock.secretPage.mockRejectedValueOnce(new ApiError(503, JSON.stringify({ detail: "secrets.enable_api disabled or KEK missing" })));
    renderSecrets();

    expect(await screen.findByText("Secrets API unavailable or disabled")).toBeInTheDocument();
    expect(screen.getByText(/secrets.enable_api disabled or KEK missing/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /create secret/i })).toBeDisabled();
  });

  it("renders the shared grid empty state for an enabled store with no metadata", async () => {
    apiMock.secretPage.mockResolvedValueOnce({ items: [] });
    renderSecrets();

    expect(await screen.findByText("No secrets stored yet")).toBeInTheDocument();
    expect(screen.getByText(/Only the name and version return/)).toBeInTheDocument();
  });
});
