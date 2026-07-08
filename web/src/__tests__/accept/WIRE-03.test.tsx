import { readFileSync } from "node:fs";
import path from "node:path";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { Posture } from "@/pages/Posture";

const emptyProgress = {
  total_assets: 0,
  out_of_policy_assets: 0,
  quantum_vulnerable_assets: 0,
  post_quantum_ready_assets: 0,
  percent_migrated: 0,
};

const scannedProgress = {
  total_assets: 1,
  out_of_policy_assets: 1,
  quantum_vulnerable_assets: 1,
  post_quantum_ready_assets: 0,
  percent_migrated: 25,
};

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
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

describe("WIRE-03 Posture CBOM wiring", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    apiMock.listCBOMAssets.mockReset();
    apiMock.startCBOMScan.mockReset();
    apiMock.listCBOMAssets.mockResolvedValueOnce({ items: [], migration_progress: emptyProgress }).mockResolvedValueOnce({
      migration_progress: scannedProgress,
      items: [
        {
          id: "asset-weak-1",
          kind: "tls_endpoint",
          location: "https://legacy.example.com:443",
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
          reasons: ["RSA-1024 below policy floor", "TLS 1.0 is banned"],
          strength: "weak",
        },
      ],
    });
    apiMock.startCBOMScan.mockResolvedValue({
      migration_progress: scannedProgress,
      report: {
        sources: 2,
        findings: 1,
        weak: 1,
        failed: 0,
        out_of_policy: 1,
        quantum_vulnerable: 1,
      },
    });
  });

  it("starts a served CBOM scan and renders inventory rows from the refreshed endpoint", async () => {
    const user = userEvent.setup();
    renderPosture();

    await waitFor(() => expect(apiMock.listCBOMAssets).toHaveBeenCalledTimes(1));

    await user.type(screen.getByLabelText("TLS endpoints"), "https://legacy.example.com:443\napi.internal:8443");
    await user.type(screen.getByLabelText("Host config paths"), "/etc/ssh/sshd_config");
    await user.click(screen.getByRole("button", { name: "Run CBOM scan" }));

    expect(apiMock.startCBOMScan).toHaveBeenCalledWith({
      tls_endpoints: ["https://legacy.example.com:443", "api.internal:8443"],
      host_configs: ["/etc/ssh/sshd_config"],
    });

    expect(await screen.findByText("1 out of policy")).toBeInTheDocument();
    expect(screen.getByText("25% migrated")).toBeInTheDocument();

    const row = await screen.findByRole("row", { name: /https:\/\/legacy\.example\.com:443 tls_endpoint rsa-1024 tls 1\.0 \/ rc4 out of policy/i });
    expect(within(row).getByText("ML-KEM hybrid")).toBeInTheDocument();
    expect(within(row).getByText(/RSA-1024 below policy floor/)).toBeInTheDocument();
  });

  it("removes the static CBOM fixture array from the Posture page", () => {
    const source = readFileSync(path.join(process.cwd(), "src/pages/Posture.tsx"), "utf8");
    expect(source).not.toMatch(/const\s+cbomRows/);
    expect(source).not.toMatch(/Non-interactive CBOM preview/);
  });
});
