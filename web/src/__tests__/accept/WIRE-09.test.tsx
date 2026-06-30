import { readFileSync } from "node:fs";
import path from "node:path";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { Secrets } from "@/pages/Secrets";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    secretPage: vi.fn(),
    createSecret: vi.fn(),
    getSecret: vi.fn(),
    rotateSecret: vi.fn(),
    deleteSecret: vi.fn(),
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
    unvaultedSecrets: vi.fn(),
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

function unvaultedSecretPostureFixture() {
  return {
    capability: "CAP-SECR-07",
    served: true,
    generated_at: "2026-06-30T00:00:00Z",
    summary: {
      repository_sources: 1,
      third_party_sources: 1,
      cloud_secret_sources: 1,
      vault_providers_supported: 4,
      vault_providers_visible: 4,
      sync_targets_configured: 3,
      leaked_secret_findings: 1,
    },
    detection_sources: [
      {
        id: "repositories",
        name: "Git repository secret scanning",
        source_kind: "secret_repo",
        configured_count: 1,
        detection_mode: "served scan",
        secret_handling: "redacted metadata",
        findings_kind: "leaked_secret",
        capabilities: ["unvaulted-secret-detection"],
        evidence_refs: ["internal/secretscan/repository.go"],
      },
    ],
    vault_providers: [
      {
        id: "aws-secrets-manager",
        name: "AWS Secrets Manager",
        discovery_configured: true,
        discovery_source_count: 1,
        sync_supported: true,
        sync_configured: true,
        augmentation_mode: "sealed-outbox sync",
        capabilities: ["multi-vault-visibility"],
        evidence_refs: ["internal/discovery/cloudsecret/awssm/awssm.go"],
      },
      {
        id: "azure-key-vault",
        name: "Azure Key Vault",
        discovery_configured: true,
        discovery_source_count: 1,
        sync_supported: true,
        sync_configured: true,
        augmentation_mode: "sealed-outbox sync",
        capabilities: ["multi-vault-visibility"],
        evidence_refs: ["internal/discovery/cloudsecret/azurekv/azurekv.go"],
      },
    ],
    configured_vaults: ["aws-secrets-manager", "gcp-secret-manager", "azure-key-vault", "hashicorp-vault"],
    configured_sync_targets: ["aws-secrets-manager", "gcp-secret-manager", "azure-key-vault"],
    workflow: ["detect", "augment"],
    secret_handling: "unvaulted detections persist metadata only and vault values never return through this route",
    architecture_controls: ["AN-8"],
    evidence_refs: ["internal/api/secrets.go"],
    residuals: ["automated pull-request rewrites remain outside this posture route"],
    recommended_next_actions: ["wire repository and third-party scan sources"],
  };
}

describe("WIRE-09 secret scanning and sync wiring", () => {
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
    apiMock.unvaultedSecrets.mockResolvedValue(unvaultedSecretPostureFixture());
    apiMock.scanSecrets.mockResolvedValue({
      run_id: "55555555-5555-5555-5555-555555555555",
      scanner: "gitleaks",
      engine_version: "8.18.2",
      mode: "workspace",
      custom_rules: false,
      capabilities: ["pattern-rules", "entropy-rules", "default-rules-100-plus", "workspace"],
      rules_active: 121,
      findings_count: 1,
      findings: [
        {
          rule_id: "generic-api-key",
          file: "config/ci.yml",
          line: 42,
          credential_ref: "sha256:6e5a...91bb",
        },
      ],
    });
    apiMock.syncSecret.mockResolvedValue({
      name: "app/db/password",
      target: "kubernetes/prod",
      remote_key: "Secret/payments-db/password",
      enqueued: true,
      delivered: false,
    });
  });

  it("renders served scan findings and sync status without raw secret leakage", async () => {
    const storageSpy = vi.spyOn(Storage.prototype, "setItem");
    const user = userEvent.setup();
    renderSecrets();

    await screen.findByText("app/db/password");
    await waitFor(() => expect(apiMock.secretRepositoryScanning).toHaveBeenCalled());
    await waitFor(() => expect(apiMock.thirdPartySecretScanning).toHaveBeenCalled());
    await waitFor(() => expect(apiMock.cloudSecretManagers).toHaveBeenCalled());
    await waitFor(() => expect(apiMock.secretSyncTargets).toHaveBeenCalled());
    await waitFor(() => expect(apiMock.kubernetesSecretOperator).toHaveBeenCalled());
    await waitFor(() => expect(apiMock.secretWorkloadInjection).toHaveBeenCalled());
    await waitFor(() => expect(apiMock.unvaultedSecrets).toHaveBeenCalled());
    expect(screen.getByText("CAP-SCAN-01")).toBeInTheDocument();
    expect(screen.getByText("CAP-SCAN-04")).toBeInTheDocument();
    expect(screen.getByText("CAP-SEC-04")).toBeInTheDocument();
    expect(screen.getByText("4 discovery providers, 3 sync targets configured")).toBeInTheDocument();
    expect(screen.getByText("CAP-SECR-03")).toBeInTheDocument();
    expect(screen.getByText("CAP-SECR-04")).toBeInTheDocument();
    expect(screen.getByText("TrstctlSecretSync - served")).toBeInTheDocument();
    expect(screen.getByText("CAP-SECR-05")).toBeInTheDocument();
    expect(screen.getByText("TrstctlSecretInjection - served")).toBeInTheDocument();
    expect(screen.getByText("CAP-SECR-07")).toBeInTheDocument();
    expect(screen.getByText("1 leaked findings, 4 vaults visible, 3 sync targets configured")).toBeInTheDocument();
    expect(screen.getAllByText("DaemonSet").length).toBeGreaterThan(0);
    expect(screen.getAllByText("AWS Secrets Manager").length).toBeGreaterThan(0);
    expect(screen.getAllByText("GCP Secret Manager").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Azure Key Vault").length).toBeGreaterThan(0);
    expect(screen.getByText("GitHub Actions")).toBeInTheDocument();
    expect(screen.getByText("GitLab CI")).toBeInTheDocument();
    expect(screen.getByText("Vercel")).toBeInTheDocument();
    expect(screen.getByText("Generic CI secret endpoint")).toBeInTheDocument();
    expect(screen.getByText("GitHub")).toBeInTheDocument();
    expect(screen.getByText("GitLab")).toBeInTheDocument();
    expect(screen.getByText("Bitbucket")).toBeInTheDocument();
    expect(screen.getAllByText("Slack").length).toBeGreaterThan(0);
    expect(screen.getByText("/api/v1/secrets/scans/third-party/slack/ingest")).toBeInTheDocument();
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

    const syncForm = within(screen.getByRole("form", { name: "Sync stored secret" }));
    await user.clear(syncForm.getByLabelText("Target"));
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
    expect(screen.queryByText(/ghp_plaintext_secret|BEGIN .* PRIVATE KEY|raw target token/i)).not.toBeInTheDocument();
    expect(storageSpy).not.toHaveBeenCalled();
    expect(localStorage.length).toBe(0);
    expect(sessionStorage.length).toBe(0);
  });

  it("removes secret scanning and sync fixtures", () => {
    const source = readFileSync(path.join(process.cwd(), "src/pages/Secrets.tsx"), "utf8");
    expect(source).not.toMatch(/const\s+scanningRows/);
    expect(source).not.toMatch(/const\s+syncRows/);
    expect(source).not.toMatch(/Secret scanning finding fixtures/);
    expect(source).not.toMatch(/Secret sync platform fixtures/);
  });
});
