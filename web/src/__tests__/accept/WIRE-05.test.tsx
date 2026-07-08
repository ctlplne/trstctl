import { readFileSync } from "node:fs";
import path from "node:path";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { Posture } from "@/pages/Posture";

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
      <Posture />
    </MemoryRouter>,
  );
}

describe("WIRE-05 Posture crypto-agility readiness wiring", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    for (const mock of Object.values(apiMock)) mock.mockReset();
    apiMock.discoverySources.mockResolvedValue({ items: [] });
    apiMock.discoveryRuns.mockResolvedValue({ items: [] });
    apiMock.discoveryFindings.mockResolvedValue({ items: [] });
    apiMock.listCBOMAssets.mockResolvedValue({
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
          id: "22222222-2222-2222-2222-222222222222",
          kind: "workload",
          location: "api workload",
          algorithm: "ECDSA",
          key_bits: 256,
          protocol: "TLS 1.3",
          cipher: "AES-GCM",
          library: "boringssl",
          migration_generation: "wave-2",
          migration_standard: "licensed",
          migration_target: "already current-policy ready",
          out_of_policy: false,
          quantum_vulnerable: false,
          reasons: ["meets current policy floor"],
          strength: "strong",
        },
      ],
    });
  });

  it("renders crypto-agility readiness from served CBOM data", async () => {
    renderPosture();

    const row = await screen.findByRole("row", { name: /legacy mesh edge tls_endpoint rsa-1024 tls 1\.0 \/ rc4 out of policy ML-KEM hybrid/i });
    expect(within(row).getByText("RSA-1024 below policy floor")).toBeInTheDocument();
  });

  it("removes crypto-agility and PQC migration fixtures and coming-soon copy", () => {
    const source = readFileSync(path.join(process.cwd(), "src/pages/Posture.tsx"), "utf8");
    expect(source).not.toMatch(/const\s+cryptoAgilityRows/);
    expect(source).not.toMatch(/const\s+pqcMigrationRows/);
    expect(source).not.toMatch(/coming soon/i);
    expect(source).not.toMatch(/fixture/i);
  });
});
