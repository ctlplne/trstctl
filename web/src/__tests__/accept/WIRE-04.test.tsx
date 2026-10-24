import { readFileSync } from "node:fs";
import path from "node:path";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { Posture } from "@/pages/Posture";
import { AppQueryProvider } from "@/lib/query";

const cbomProgress = {
  total_assets: 0,
  out_of_policy_assets: 0,
  quantum_vulnerable_assets: 0,
  post_quantum_ready_assets: 0,
  percent_migrated: 0,
};

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    discoverySources: vi.fn(),
    discoveryRuns: vi.fn(),
    discoveryFindings: vi.fn(),
    ctMonitoring: vi.fn(),
    driftRemediation: vi.fn(),
    listCBOMAssets: vi.fn(),
    startCBOMScan: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});

function renderPosture() {
  return render(
    <MemoryRouter>
      <AppQueryProvider>
        <Posture />
      </AppQueryProvider>
    </MemoryRouter>,
  );
}

describe("WIRE-04 Posture discovery wiring", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    for (const mock of Object.values(apiMock)) mock.mockReset();
    apiMock.listCBOMAssets.mockResolvedValue({ items: [], migration_progress: cbomProgress });
    apiMock.discoverySources.mockResolvedValue({
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
    apiMock.discoveryRuns.mockResolvedValue({
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
    apiMock.discoveryFindings.mockResolvedValue({ items: [] });
    apiMock.ctMonitoring.mockResolvedValue({
      capability: "F17",
      watchlist_path: "/api/v1/discovery/ct-monitoring",
      sources_path: "/api/v1/discovery/sources",
      runs_path: "/api/v1/discovery/runs",
      findings_path: "/api/v1/discovery/findings",
      notification_destination: "notification.unexpected_issuance",
      outbox_backed_alerts: true,
      watched_domains: [],
      logs: [],
      summary: {
        source_count: 1,
        watched_domain_count: 0,
        log_count: 0,
        finding_count: 1,
        unexpected_issuance_count: 1,
        open_finding_count: 1,
        investigating_count: 0,
        managed_count: 0,
        dismissed_count: 0,
        outbox_alert_channel_count: 0,
      },
      findings: [
        {
          id: "finding-ct",
          tenant_id: "tenant-1",
          run_id: "run-ct",
          source_id: "source-ct",
          kind: "ct_unexpected_issuance",
          ref: "*.payments.example.com",
          provenance: "ct:https://ct.googleapis.com/logs/argon2026/",
          fingerprint: "abcdef1234567890abcdef1234567890",
          risk_score: 88,
          metadata: { log_url: "https://ct.googleapis.com/logs/argon2026/", issuer: "CN=Unexpected Issuing CA", secret_value: "RAW-CT-LEAK" },
          triage_status: "unmanaged",
          discovered_at: "2026-06-20T10:00:04Z",
          first_seen_at: "2026-06-20T10:00:04Z",
          last_seen_at: "2026-06-20T10:00:04Z",
          seen_count: 1,
        },
      ],
    });
    apiMock.driftRemediation.mockResolvedValue({
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
          expected_mode: "sha256:fedcba09",
          actual_mode: "sha256:01234567",
          triage_status: "unmanaged",
          metadata: { secret_value: "RAW-DRIFT-LEAK" },
          recommended_action: "rotate and redeploy the expected certificate, or mark the new fingerprint managed with change evidence",
          available_decisions: ["investigate", "mark_managed", "dismiss"],
          evidence_refs: ["discovery.finding:finding-drift"],
        },
      ],
    });
  });

  // A105: the CT-log and drift dashboards render from their own served,
  // server-counted responses; the page takes no browser-side findings sample.
  it("renders CT-log and drift findings from the served dashboard responses", async () => {
    const user = userEvent.setup();
    renderPosture();

    expect(apiMock.discoverySources).toHaveBeenCalledWith({ limit: 50 });
    expect(apiMock.discoveryRuns).toHaveBeenCalledWith({ limit: 50 });
    expect(apiMock.ctMonitoring).toHaveBeenCalledWith({ triageStatus: undefined });
    expect(apiMock.driftRemediation).toHaveBeenCalledWith({ triageStatus: undefined });
    expect(apiMock.discoveryFindings).not.toHaveBeenCalled();
    await user.click(screen.getByText("Certificate, AD CS, authority, and drift evidence", { exact: true }));

    const ctRow = await screen.findByRole("row", { name: /\*\.payments\.example\.com CN=Unexpected Issuing CA/i });
    expect(within(ctRow).getByText("Unmanaged")).toBeInTheDocument();

    const driftRow = await screen.findByRole("row", { name: /agent-7:\/etc\/tls\/current\.pem Agent drift watch Replaced certificate/i });
    expect(within(driftRow).getByText("sha256:fedcba09 → sha256:01234567")).toBeInTheDocument();

    expect(screen.queryByText(/RAW-CT-LEAK|RAW-DRIFT-LEAK/)).not.toBeInTheDocument();
    expect(screen.queryByText("example.com")).not.toBeInTheDocument();
    expect(screen.queryByText("Deleted credential")).not.toBeInTheDocument();
  });

  it("removes the static CT and drift fixture arrays from the Posture page", () => {
    const source = readFileSync(path.join(process.cwd(), "src/pages/Posture.tsx"), "utf8");
    expect(source).not.toMatch(/const\s+ctRows/);
    expect(source).not.toMatch(/const\s+driftRows/);
  });
});
