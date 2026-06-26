import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { Posture } from "@/pages/Posture";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    discoverySources: vi.fn(),
    discoveryRuns: vi.fn(),
    discoveryFindings: vi.fn(),
    listCBOMAssets: vi.fn(),
    startCBOMScan: vi.fn(),
    startPQCMigration: vi.fn(),
    rollbackPQCMigration: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});

const progress = { total_assets: 1, out_of_policy_assets: 1, quantum_vulnerable_assets: 1, post_quantum_ready_assets: 0, percent_migrated: 0 };

beforeEach(() => {
  apiMock.discoverySources.mockReset().mockResolvedValue({ items: [] });
  apiMock.discoveryRuns.mockReset().mockResolvedValue({ items: [] });
  apiMock.discoveryFindings.mockReset().mockResolvedValue({ items: [] });
  apiMock.listCBOMAssets.mockReset().mockResolvedValue({
    migration_progress: progress,
    items: [
      {
        id: "asset-weak-1",
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
    ],
  });
  apiMock.startPQCMigration.mockReset().mockResolvedValue({
    run_id: "migration-run-1",
    queued: 1,
    target_algorithm: "ML-KEM hybrid",
    effective_algorithm: "X25519+ML-KEM",
    protocol: "x509",
    rollback_configured: true,
    queued_at: "2026-06-20T11:00:00Z",
    migration_progress: progress,
  });
  apiMock.rollbackPQCMigration.mockReset().mockResolvedValue({
    run_id: "migration-run-1",
    queued: 1,
    reason: "operator requested rollback",
    queued_at: "2026-06-20T11:05:00Z",
    migration_progress: progress,
  });
});

describe("U5-3 PQC migration orchestration", () => {
  it("queues a migration over quantum-vulnerable assets and rolls it back through served endpoints", async () => {
    const user = userEvent.setup();
    render(
      <MemoryRouter>
        <Posture />
      </MemoryRouter>,
    );
    await waitFor(() => expect(apiMock.listCBOMAssets).toHaveBeenCalled());

    expect(await screen.findByRole("heading", { name: "PQC migration orchestration" })).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Queue PQC migration" }));
    await waitFor(() => expect(apiMock.startPQCMigration).toHaveBeenCalled());
    expect(await screen.findByText("migration-run-1")).toBeInTheDocument();
    expect(screen.getByText("X25519+ML-KEM")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: /Rollback migration migration-run-1/i }));
    await waitFor(() => expect(apiMock.rollbackPQCMigration).toHaveBeenCalled());
  });
});
