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
    apiMock.scanSecrets.mockResolvedValue({
      run_id: "55555555-5555-5555-5555-555555555555",
      scanner: "gitleaks",
      engine_version: "8.18.2",
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
    expect(screen.getByText("CAP-SCAN-01")).toBeInTheDocument();
    expect(screen.getByText("GitHub")).toBeInTheDocument();
    expect(screen.getByText("GitLab")).toBeInTheDocument();
    expect(screen.getByText("Bitbucket")).toBeInTheDocument();
    const scanForm = within(screen.getByRole("form", { name: "Run secret scan" }));
    await user.type(scanForm.getByLabelText("Path"), "github.com/example/payments");
    await user.click(scanForm.getByRole("button", { name: /run scan/i }));

    await waitFor(() => expect(apiMock.scanSecrets).toHaveBeenCalledWith({ path: "github.com/example/payments" }));
    expect(await screen.findByText("55555555-5555-5555-5555-555555555555")).toBeInTheDocument();
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
