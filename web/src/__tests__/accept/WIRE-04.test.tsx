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
    apiMock.discoveryFindings.mockResolvedValue({
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
  });

  it("renders CT-log and drift findings from the served Discovery responses", async () => {
    const user = userEvent.setup();
    renderPosture();

    expect(apiMock.discoverySources).toHaveBeenCalledWith({ limit: 50 });
    expect(apiMock.discoveryRuns).toHaveBeenCalledWith({ limit: 50 });
    expect(apiMock.discoveryFindings).toHaveBeenCalledWith({ limit: 50 });
    await user.click(screen.getByText("Certificate, AD CS, authority, and drift evidence", { exact: true }));

    const ctRow = await screen.findByRole("row", { name: /\*\.payments\.example\.com Public CT logs x509_certificate 88 succeeded/i });
    expect(within(ctRow).getByText("unexpected SAN outside approved issuer profile")).toBeInTheDocument();

    const driftRow = await screen.findByRole("row", { name: /agent-7:\/etc\/tls\/current\.pem Agent drift watch credential_drift 91 failed/i });
    expect(within(driftRow).getByText("fingerprint mismatch on deployed certificate")).toBeInTheDocument();

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
