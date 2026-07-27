import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { Posture } from "@/pages/Posture";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    discoverySources: vi.fn(),
    discoveryRuns: vi.fn(),
    discoveryFindings: vi.fn(),
    ctMonitoring: vi.fn(),
    updateCTMonitoring: vi.fn(),
    driftRemediation: vi.fn(),
    decideDriftRemediation: vi.fn(),
    listCBOMAssets: vi.fn(),
    startCBOMScan: vi.fn(),
    editions: vi.fn(),
    planPQCMigration: vi.fn(),
    startPQCMigration: vi.fn(),
    getPQCMigrationProgress: vi.fn(),
    rollbackPQCMigration: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});

async function renderPosture() {
  const result = render(
    <MemoryRouter>
      <Posture />
    </MemoryRouter>,
  );
  await waitFor(() => expect(apiMock.listCBOMAssets).toHaveBeenCalled());
  await waitFor(() => expect(apiMock.discoveryFindings).toHaveBeenCalled());
  await waitFor(() => expect(apiMock.ctMonitoring).toHaveBeenCalled());
  await waitFor(() => expect(apiMock.driftRemediation).toHaveBeenCalled());
  await waitFor(() => expect(apiMock.editions).toHaveBeenCalled());
  return result;
}

describe("posture collector disclosures", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    apiMock.discoverySources.mockReset().mockResolvedValue({
      items: [
        {
          id: "source-ct",
          tenant_id: "tenant-1",
          kind: "ct_log",
          name: "Public CT logs",
          config: {},
          created_at: "2026-06-20T09:00:00Z",
          updated_at: "2026-06-20T09:00:00Z",
        },
        {
          id: "source-drift",
          tenant_id: "tenant-1",
          kind: "drift",
          name: "Agent drift watch",
          config: {},
          created_at: "2026-06-20T09:05:00Z",
          updated_at: "2026-06-20T09:05:00Z",
        },
      ],
    });
    apiMock.discoveryRuns.mockReset().mockResolvedValue({
      items: [
        {
          id: "run-ct",
          tenant_id: "tenant-1",
          source_id: "source-ct",
          status: "succeeded",
          dry_run: false,
          requested_by: "operator",
          targets: 1,
          discovered: 1,
          failed: 0,
          rejected: 0,
          created_at: "2026-06-20T10:00:00Z",
          completed_at: "2026-06-20T10:00:05Z",
        },
        {
          id: "run-drift",
          tenant_id: "tenant-1",
          source_id: "source-drift",
          status: "failed",
          dry_run: false,
          requested_by: "agent",
          targets: 1,
          discovered: 1,
          failed: 1,
          rejected: 0,
          created_at: "2026-06-20T10:05:00Z",
          completed_at: "2026-06-20T10:05:07Z",
        },
      ],
    });
    apiMock.discoveryFindings.mockReset().mockResolvedValue({
      items: [
        {
          id: "finding-ct",
          tenant_id: "tenant-1",
          run_id: "run-ct",
          source_id: "source-ct",
          kind: "x509_certificate",
          ref: "*.payments.example.com",
          provenance: "ct_log:argon2026",
          fingerprint: "abcdef1234567890abcdef1234567890",
          risk_score: 88,
          metadata: { alert: "unexpected SAN outside approved issuer profile", secret_value: "RAW-CT-LEAK" },
          discovered_at: "2026-06-20T10:00:04Z",
        },
        {
          id: "finding-drift",
          tenant_id: "tenant-1",
          run_id: "run-drift",
          source_id: "source-drift",
          kind: "credential_drift",
          ref: "agent-7:/etc/tls/current.pem",
          provenance: "drift:/etc/tls/current.pem",
          fingerprint: "fedcba0987654321fedcba0987654321",
          risk_score: 91,
          metadata: { evidence: "fingerprint mismatch on deployed certificate", secret_value: "RAW-DRIFT-LEAK" },
          discovered_at: "2026-06-20T10:05:06Z",
        },
      ],
    });
    apiMock.ctMonitoring.mockReset().mockResolvedValue({
      capability: "F17",
      watchlist_path: "/api/v1/discovery/ct-monitoring",
      sources_path: "/api/v1/discovery/sources",
      runs_path: "/api/v1/discovery/runs",
      findings_path: "/api/v1/discovery/findings",
      notification_destination: "notification.unexpected_issuance",
      outbox_backed_alerts: true,
      watched_domains: ["example.com"],
      logs: [{ url: "https://ct.googleapis.com/logs/argon2026/", next_index: 42 }],
      source: {
        id: "source-ct",
        tenant_id: "tenant-1",
        kind: "ct_log",
        name: "Public CT logs",
        config: {
          logs: ["https://ct.googleapis.com/logs/argon2026/"],
          watched_domains: ["example.com"],
          max_batch: 25,
        },
        created_at: "2026-06-20T09:00:00Z",
        updated_at: "2026-06-20T09:00:00Z",
      },
      summary: {
        source_count: 1,
        watched_domain_count: 1,
        log_count: 1,
        finding_count: 1,
        unexpected_issuance_count: 1,
        open_finding_count: 1,
        outbox_alert_channel_count: 1,
      },
      findings: [],
    });
    apiMock.updateCTMonitoring.mockReset().mockResolvedValue({
      capability: "F17",
      watched_domains: ["example.com", "payments.example.com"],
      logs: [{ url: "https://ct.example/log", next_index: 0 }],
      source: {
        id: "source-ct",
        tenant_id: "tenant-1",
        kind: "ct_log",
        name: "Public CT logs",
        config: {
          logs: ["https://ct.example/log"],
          watched_domains: ["example.com", "payments.example.com"],
          max_batch: 10,
        },
        created_at: "2026-06-20T09:00:00Z",
        updated_at: "2026-06-20T11:00:00Z",
      },
      run: {
        id: "run-ct-next",
        tenant_id: "tenant-1",
        source_id: "source-ct",
        status: "queued",
        dry_run: false,
        requested_by: "operator",
        targets: 0,
        discovered: 0,
        failed: 0,
        rejected: 0,
        created_at: "2026-06-20T11:00:00Z",
      },
      summary: {
        source_count: 1,
        watched_domain_count: 2,
        log_count: 1,
        finding_count: 1,
        unexpected_issuance_count: 1,
        open_finding_count: 1,
        outbox_alert_channel_count: 1,
      },
      findings: [],
      outbox_backed_alerts: true,
    });
    apiMock.driftRemediation.mockReset().mockResolvedValue({
      capability: "F18",
      dashboard_path: "/api/v1/discovery/drift-remediation",
      sources_path: "/api/v1/discovery/sources",
      runs_path: "/api/v1/discovery/runs",
      findings_path: "/api/v1/discovery/findings",
      summary: {
        source_count: 1,
        finding_count: 1,
        open_finding_count: 1,
        investigating_count: 0,
        remediated_count: 0,
        dismissed_count: 0,
        remediation_decision_count: 0,
        deleted_count: 0,
        replaced_count: 1,
        relocated_count: 0,
        permission_changed_count: 0,
        certificate_count: 1,
        ssh_key_count: 0,
        secret_count: 0,
      },
      findings: [
        {
          finding_id: "finding-drift",
          run_id: "run-drift",
          source_id: "source-drift",
          source_name: "Agent drift watch",
          ref: "agent-7:/etc/tls/current.pem",
          provenance: "drift:/etc/tls/current.pem",
          fingerprint: "fedcba0987654321fedcba0987654321",
          risk_score: 91,
          drift_type: "replaced",
          credential_class: "certificate",
          triage_status: "unmanaged",
          metadata: { evidence: "fingerprint mismatch on deployed certificate", secret_value: "RAW-DRIFT-LEAK" },
          recommended_action: "rotate and redeploy the expected certificate, or mark the new fingerprint managed with change evidence",
          available_decisions: ["investigate", "mark_managed", "dismiss"],
          evidence_refs: ["discovery.finding:finding-drift", "discovery.run:run-drift", "discovery.source:source-drift"],
        },
      ],
    });
    apiMock.decideDriftRemediation.mockReset().mockResolvedValue({
      decision: "investigate",
      evidence_refs: ["event:discovery.finding.triage_changed", "discovery.finding:finding-drift"],
      finding: {
        finding_id: "finding-drift",
        run_id: "run-drift",
        source_id: "source-drift",
        source_name: "Agent drift watch",
        ref: "agent-7:/etc/tls/current.pem",
        provenance: "drift:/etc/tls/current.pem",
        fingerprint: "fedcba0987654321fedcba0987654321",
        risk_score: 91,
        drift_type: "replaced",
        credential_class: "certificate",
        triage_status: "investigating",
        triage_reason: "operator opened drift remediation investigation",
        metadata: { evidence: "fingerprint mismatch on deployed certificate" },
        recommended_action: "rotate and redeploy the expected certificate, or mark the new fingerprint managed with change evidence",
        available_decisions: ["mark_managed", "dismiss"],
        evidence_refs: ["discovery.finding:finding-drift", "event:discovery.finding.triage_changed"],
      },
    });
    apiMock.listCBOMAssets.mockReset().mockResolvedValue({
      migration_progress: {
        total_assets: 2,
        out_of_policy_assets: 1,
        quantum_vulnerable_assets: 1,
        post_quantum_ready_assets: 1,
        percent_migrated: 50,
      },
      items: [
        {
          id: "11111111-1111-1111-1111-111111111111",
          kind: "tls_endpoint",
          location: "legacy mesh edge",
          algorithm: "RSA",
          key_bits: 1024,
          protocol: "TLS 1.0",
          cipher: "RC4",
          library: "openssl-1.0.1",
          migration_generation: "wave-0",
          migration_standard: "FIPS 203",
          migration_target: "ML-KEM hybrid",
          out_of_policy: true,
          quantum_vulnerable: true,
          reasons: ["RSA-1024 below policy floor"],
          strength: "weak",
        },
        {
          id: "asset-modern-1",
          kind: "tls_endpoint",
          location: "https://edge.example.com:443",
          algorithm: "ECDSA",
          key_bits: 256,
          protocol: "TLS 1.3",
          cipher: "AES-GCM",
          library: "boringssl",
          migration_generation: "wave-1",
          migration_standard: "FIPS 203",
          migration_target: "ML-KEM hybrid",
          out_of_policy: false,
          quantum_vulnerable: false,
          reasons: ["meets current policy floor"],
          strength: "strong",
        },
      ],
    });
    apiMock.startCBOMScan.mockReset();
    apiMock.editions.mockReset().mockResolvedValue({
      tier: "community",
      state: "community",
      features: [{ name: "pqc", tier: "enterprise", licensed: false, mode: "off" }],
      fips: { module_active: false, required: false, self_test_passed: true },
      packaging: {
        category_label: "",
        positioning: "",
        billable_unit: "",
        provider_billing_unit: "",
        no_per_certificate_billing: true,
        no_ephemeral_identity_billing: true,
        certificate_counters_classification: "",
        managed_boundary: "",
        pricing_posture: "",
        evidence_rail: [],
        editions: [],
        meters: [],
      },
    });
    apiMock.planPQCMigration.mockReset();
    apiMock.startPQCMigration.mockReset();
    apiMock.getPQCMigrationProgress.mockReset();
    apiMock.rollbackPQCMigration.mockReset();
  });

  it("renders CT monitoring through Discovery findings", async () => {
    const user = userEvent.setup();
    await renderPosture();

    expect(screen.getByRole("heading", { name: "Crypto posture" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Certificate Transparency monitoring" })).toBeInTheDocument();
    expect(screen.getAllByText("https://ct.googleapis.com/logs/argon2026/").length).toBeGreaterThan(0);
    expect(screen.getByText("42")).toBeInTheDocument();
    expect(screen.getByLabelText("Watched domains")).toHaveValue("example.com");
    expect(screen.getByLabelText("CT log URLs")).toHaveValue("https://ct.googleapis.com/logs/argon2026/");

    await user.clear(screen.getByLabelText("Watched domains"));
    await user.type(screen.getByLabelText("Watched domains"), "example.com\npayments.example.com");
    await user.clear(screen.getByLabelText("CT log URLs"));
    await user.type(screen.getByLabelText("CT log URLs"), "https://ct.example/log");
    await user.clear(screen.getByLabelText("Max entries per poll"));
    await user.type(screen.getByLabelText("Max entries per poll"), "10");
    await user.click(screen.getByRole("button", { name: "Save and poll CT" }));

    await waitFor(() =>
      expect(apiMock.updateCTMonitoring).toHaveBeenCalledWith({
        name: "Public CT logs",
        logs: ["https://ct.example/log"],
        watched_domains: ["example.com", "payments.example.com"],
        max_batch: 10,
        run_now: true,
      }),
    );
    expect(await screen.findByText("Run run-ct-next queued")).toBeInTheDocument();

    const row = await screen.findByRole("row", { name: /\*\.payments\.example\.com Public CT logs x509_certificate 88 succeeded/i });
    expect(within(row).getByText("unexpected SAN outside approved issuer profile")).toBeInTheDocument();
    expect(screen.queryByText("RAW-CT-LEAK")).not.toBeInTheDocument();
    expect(screen.queryByText("Dedicated CT dashboard coming soon")).not.toBeInTheDocument();
  });

  it("renders drift remediation workflow and records an operator decision", async () => {
    const user = userEvent.setup();
    await renderPosture();

    expect(screen.getByRole("heading", { name: "Drift detection" })).toBeInTheDocument();
    const row = await screen.findByRole("row", { name: /agent-7:\/etc\/tls\/current\.pem Agent drift watch credential_drift 91 failed/i });
    expect(within(row).getByText("fingerprint mismatch on deployed certificate")).toBeInTheDocument();
    const workflow = screen.getByRole("table", { name: "Drift remediation workflow" });
    expect(
      within(workflow).getByRole("row", { name: /agent-7:\/etc\/tls\/current\.pem Agent drift watch Replaced certificate 91 Unmanaged rotate and redeploy/i }),
    ).toBeInTheDocument();

    await user.click(within(workflow).getByRole("button", { name: "Investigate agent-7:/etc/tls/current.pem" }));
    await waitFor(() =>
      expect(apiMock.decideDriftRemediation).toHaveBeenCalledWith("finding-drift", {
        decision: "investigate",
        reason: "operator opened drift remediation investigation",
      }),
    );
    expect(await screen.findByText("Investigation decision recorded for agent-7:/etc/tls/current.pem")).toBeInTheDocument();
    expect(within(workflow).getByText("Investigating")).toBeInTheDocument();
    expect(screen.queryByText("RAW-DRIFT-LEAK")).not.toBeInTheDocument();
  });

  it("renders CBOM crypto posture with a served scan trigger and inventory rows", async () => {
    await renderPosture();

    expect(screen.getByRole("heading", { name: "CBOM and cryptographic observability" })).toBeInTheDocument();
    expect(screen.getByLabelText("TLS endpoints")).toBeInTheDocument();
    expect(screen.getByLabelText("Host config paths")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Run CBOM scan" })).toBeInTheDocument();
    expect(screen.getByText(/RSA-2048, EC-256, and TLS 1.2/)).toBeInTheDocument();
    expect(screen.getByText(/3DES\/DES\/RC4\/NULL\/EXPORT\/MD5/)).toBeInTheDocument();

    const row = screen.getByRole("row", { name: /https:\/\/edge\.example\.com:443 tls_endpoint ecdsa-256 tls 1\.3 \/ aes-gcm allowed/i });
    expect(within(row).getByText("ML-KEM hybrid")).toBeInTheDocument();
    expect(screen.queryByText("CBOM dashboard controls coming soon")).not.toBeInTheDocument();
    expect(screen.queryByText("Non-interactive CBOM preview")).not.toBeInTheDocument();
  });

  it("renders crypto-agility readiness from CBOM inventory", async () => {
    await renderPosture();

    expect(screen.getByRole("heading", { name: "Crypto-agility readiness" })).toBeInTheDocument();
    const readiness = screen.getByRole("region", { name: "Crypto-agility readiness" });
    expect(
      within(readiness).getByRole("row", { name: /legacy mesh edge tls_endpoint RSA-1024 \/ TLS 1\.0 \/ RC4 Out of policy ML-KEM hybrid/i }),
    ).toBeInTheDocument();
    expect(
      within(readiness).getByRole("row", { name: /https:\/\/edge\.example\.com:443 tls_endpoint ECDSA-256 \/ TLS 1\.3 \/ AES-GCM Ready/i }),
    ).toBeInTheDocument();
    expect(screen.queryByText(/coming soon/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/fixture/i)).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /run inventory|enable pqc|change algorithm/i })).not.toBeInTheDocument();
  });

  it("keeps Community CBOM useful without calling unavailable migration routes", async () => {
    await renderPosture();

    expect(screen.getByRole("heading", { name: "PQC migration workflow" })).toBeInTheDocument();
    expect(screen.getByText("Migration execution is unavailable in this edition")).toBeInTheDocument();
    expect(screen.getByText(/Community keeps CBOM discovery and readiness fully usable/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Review editions and license state" })).toHaveAttribute("href", "/admin/editions");
    expect(apiMock.planPQCMigration).not.toHaveBeenCalled();
    expect(apiMock.startPQCMigration).not.toHaveBeenCalled();
    expect(apiMock.getPQCMigrationProgress).not.toHaveBeenCalled();
    expect(apiMock.rollbackPQCMigration).not.toHaveBeenCalled();
  });

  it("previews, explicitly starts, monitors, and rolls back a licensed migration", async () => {
    apiMock.editions.mockResolvedValue({
      tier: "enterprise",
      state: "active",
      features: [{ name: "pqc", tier: "enterprise", licensed: true, mode: "enabled" }],
      fips: { module_active: false, required: false, self_test_passed: true },
      packaging: {
        category_label: "",
        positioning: "",
        billable_unit: "",
        provider_billing_unit: "",
        no_per_certificate_billing: true,
        no_ephemeral_identity_billing: true,
        certificate_counters_classification: "",
        managed_boundary: "",
        pricing_posture: "",
        evidence_rail: [],
        editions: [],
        meters: [],
      },
    });
    apiMock.planPQCMigration.mockResolvedValue({
      reissues: [
        {
          asset_id: "11111111-1111-1111-1111-111111111111",
          location: "legacy mesh edge",
          current_algorithm: "RSA-1024",
          target_algorithm: "ML-DSA-65",
          effective_algorithm: "hybrid",
          protocol: "acme",
          rollback_on_failure: true,
        },
      ],
      tls_rollouts: [],
      residuals: [],
      reissue_count: 1,
      tls_rollout_count: 0,
    });
    apiMock.startPQCMigration.mockResolvedValue({
      run_id: "run-pqc-1",
      queued: 1,
      certificate_reissues_queued: 1,
      tls_findings_queued: 0,
      target_algorithm: "ML-DSA-65",
      effective_algorithm: "hybrid",
      protocol: "acme",
      rollback_configured: true,
      migration_progress: {
        total_assets: 2,
        out_of_policy_assets: 1,
        quantum_vulnerable_assets: 1,
        post_quantum_ready_assets: 1,
        percent_migrated: 50,
      },
      queued_at: "2026-07-27T12:00:00Z",
    });
    apiMock.getPQCMigrationProgress.mockResolvedValue({
      run_id: "run-pqc-1",
      total: 1,
      queued: 0,
      applied: 1,
      failed: 0,
      rolled_back: 0,
      findings: [],
    });
    apiMock.rollbackPQCMigration.mockResolvedValue({
      run_id: "run-pqc-1",
      queued: 1,
      reason: "operator rollback from the Posture console",
      migration_progress: {
        total_assets: 2,
        out_of_policy_assets: 1,
        quantum_vulnerable_assets: 1,
        post_quantum_ready_assets: 1,
        percent_migrated: 50,
      },
      queued_at: "2026-07-27T12:01:00Z",
    });

    const user = userEvent.setup();
    await renderPosture();
    await user.click(screen.getByRole("checkbox", { name: "Select legacy mesh edge for PQC migration" }));
    await user.click(screen.getByRole("button", { name: "Preview migration plan" }));
    await waitFor(() =>
      expect(apiMock.planPQCMigration).toHaveBeenCalledWith({
        asset_ids: ["11111111-1111-1111-1111-111111111111"],
        target_algorithm: "ML-DSA-65",
        protocol: "acme",
        rollback_on_failure: true,
      }),
    );

    const startButton = await screen.findByRole("button", { name: "Start migration" });
    expect(startButton).toBeDisabled();
    await user.click(screen.getByRole("checkbox", { name: /I reviewed this exact plan/ }));
    await user.click(startButton);
    expect(await screen.findByText("Migration run run-pqc-1 queued")).toBeInTheDocument();
    expect(apiMock.startPQCMigration).toHaveBeenCalledWith({
      asset_ids: ["11111111-1111-1111-1111-111111111111"],
      target_algorithm: "ML-DSA-65",
      protocol: "acme",
      rollback_on_failure: true,
    });

    await user.click(screen.getByRole("button", { name: "Refresh progress" }));
    expect(await screen.findByText("1 applied · 0 queued · 0 failed · 0 rolled back")).toBeInTheDocument();
    expect(apiMock.getPQCMigrationProgress).toHaveBeenCalledWith("run-pqc-1");

    await user.click(screen.getByRole("checkbox", { name: /I reviewed the current run evidence/ }));
    await user.click(screen.getByRole("button", { name: "Queue rollback" }));
    await waitFor(() =>
      expect(apiMock.rollbackPQCMigration).toHaveBeenCalledWith(
        "run-pqc-1",
        ["11111111-1111-1111-1111-111111111111"],
        "operator rollback from the Posture console",
      ),
    );
    expect(await screen.findByText("1 rollback actions queued")).toBeInTheDocument();
  });
});
