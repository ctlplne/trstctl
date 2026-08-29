import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { Posture } from "@/pages/Posture";
import { AppQueryProvider } from "@/lib/query";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    discoverySources: vi.fn(),
    discoveryRuns: vi.fn(),
    discoveryFindings: vi.fn(),
    listCBOMAssets: vi.fn(),
    previewCBOMScan: vi.fn(),
    startCBOMScan: vi.fn(),
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
  apiMock.previewCBOMScan.mockReset().mockResolvedValue({
    capability: "F52",
    ready: true,
    effect_free: true,
    normalized_request: { tls_endpoints: ["legacy.example.com:443"] },
    source_count: 1,
    tls_connection_limit: 1,
    host_read_selector_count: 0,
    host_file_read_limit: 0,
    host_file_byte_limit: 0,
    finding_write_limit: 2,
    worker_limit: 4,
    queue_depth: 64,
    per_endpoint_timeout_seconds: 10,
    outside_calls: ["Open one TLS connection."],
    host_reads: [],
    durable_writes: ["Append at most two observations."],
    signer_calls: 0,
    outbox_calls: 0,
    blockers: [],
    recovery_steps: ["Correct an unreachable target and retry."],
    safety_notes: ["Preview is effect-free."],
  });
  apiMock.startCBOMScan.mockReset().mockResolvedValue({
    migration_progress: progress,
    report: { failed: 0, findings: 1, out_of_policy: 1, quantum_vulnerable: 1, sources: 1, weak: 1 },
  });
});

describe("U5-2 CBOM inventory explorer", () => {
  it("renders the served CBOM asset inventory and triggers a scan from the UI", async () => {
    const user = userEvent.setup();
    render(
      <MemoryRouter>
        <AppQueryProvider>
          <Posture />
        </AppQueryProvider>
      </MemoryRouter>,
    );
    await waitFor(() => expect(apiMock.listCBOMAssets).toHaveBeenCalled());
    await user.click(screen.getByText("Algorithm inventory and scan evidence", { exact: true }));
    expect(await screen.findByRole("heading", { name: "CBOM and cryptographic observability" })).toBeInTheDocument();
    // The weak asset is rendered from served inventory (appears in both the CBOM and readiness tables).
    expect(screen.getAllByText("legacy mesh edge").length).toBeGreaterThan(0);
    await user.type(screen.getByLabelText("TLS services"), "legacy.example.com");
    await user.click(screen.getByRole("button", { name: "Review scan plan" }));
    await user.click(await screen.findByRole("button", { name: "Run this reviewed plan" }));
    await waitFor(() => expect(apiMock.startCBOMScan).toHaveBeenCalled());
  });
});
