import { readFileSync } from "node:fs";
import path from "node:path";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { Posture } from "@/pages/Posture";
import { AppQueryProvider } from "@/lib/query";

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
    previewCBOMScan: vi.fn(),
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

describe("WIRE-03 Posture CBOM wiring", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    apiMock.listCBOMAssets.mockReset();
    apiMock.previewCBOMScan.mockReset();
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
    apiMock.previewCBOMScan.mockResolvedValue({
      capability: "F52",
      ready: true,
      effect_free: true,
      normalized_request: {
        tls_endpoints: ["api.internal:8443", "legacy.example.com:443"],
        host_configs: ["/etc/ssh/sshd_config"],
      },
      source_count: 2,
      tls_connection_limit: 2,
      host_read_selector_count: 1,
      host_file_read_limit: 256,
      host_file_byte_limit: 1048576,
      finding_write_limit: 1028,
      worker_limit: 4,
      queue_depth: 64,
      per_endpoint_timeout_seconds: 10,
      outside_calls: ["Open at most 2 TLS connections."],
      host_reads: ["Read one declared host selector."],
      durable_writes: ["Append and project at most 1028 observations."],
      signer_calls: 0,
      outbox_calls: 0,
      blockers: [],
      recovery_steps: ["Correct an unreachable target and retry only that target."],
      safety_notes: ["Preview performs no read or write."],
    });
  });

  it("starts a served CBOM scan and renders inventory rows from the refreshed endpoint", async () => {
    const user = userEvent.setup();
    renderPosture();

    await waitFor(() => expect(apiMock.listCBOMAssets).toHaveBeenCalledTimes(1));
    await user.click(screen.getByText("Algorithm inventory and scan evidence", { exact: true }));

    await user.type(screen.getByLabelText("TLS services"), "https://legacy.example.com:443\napi.internal:8443");
    await user.type(screen.getByLabelText("Host configuration files"), "/etc/ssh/sshd_config");
    await user.click(screen.getByRole("button", { name: "Review scan plan" }));

    expect(apiMock.previewCBOMScan).toHaveBeenCalledWith({
      tls_endpoints: ["https://legacy.example.com:443", "api.internal:8443"],
      host_configs: ["/etc/ssh/sshd_config"],
    });
    expect(await screen.findByText("Ready to scan")).toBeInTheDocument();
    expect(screen.getByText("legacy.example.com:443")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Run this reviewed plan" }));

    expect(apiMock.startCBOMScan).toHaveBeenCalledWith({
      tls_endpoints: ["api.internal:8443", "legacy.example.com:443"],
      host_configs: ["/etc/ssh/sshd_config"],
    });

    const outOfPolicyValues = await screen.findAllByText("1 out of policy");
    expect(outOfPolicyValues.some((value) => value.tagName === "DD")).toBe(true);
    expect(screen.getByText("25% migrated")).toBeInTheDocument();

    const row = await screen.findByRole("row", { name: /https:\/\/legacy\.example\.com:443 tls_endpoint rsa-1024 tls 1\.0 \/ rc4 out of policy/i });
    expect(within(row).getByText("ML-KEM hybrid")).toBeInTheDocument();
    expect(within(row).getByText(/RSA-1024 below policy floor/)).toBeInTheDocument();
  });

  it("fails closed on an unsafe preview and keeps the reviewed plan recoverable after execution fails", async () => {
    apiMock.previewCBOMScan.mockRejectedValueOnce(new Error("TLS origin must not include a path"));
    apiMock.startCBOMScan.mockRejectedValueOnce(new Error("TLS target did not answer before the bounded timeout"));
    const user = userEvent.setup();
    renderPosture();

    await waitFor(() => expect(apiMock.listCBOMAssets).toHaveBeenCalledTimes(1));
    await user.click(screen.getByText("Algorithm inventory and scan evidence", { exact: true }));
    await user.type(screen.getByLabelText("TLS services"), "https://legacy.example.com/private");
    await user.click(screen.getByRole("button", { name: "Review scan plan" }));

    expect(await screen.findByText("TLS origin must not include a path")).toBeInTheDocument();
    expect(apiMock.startCBOMScan).not.toHaveBeenCalled();

    await user.click(screen.getByRole("button", { name: "Previous" }));
    await user.clear(screen.getByLabelText("TLS services"));
    await user.type(screen.getByLabelText("TLS services"), "legacy.example.com");
    await user.click(screen.getByRole("button", { name: "Review scan plan" }));
    await user.click(await screen.findByRole("button", { name: "Run this reviewed plan" }));

    expect(await screen.findByText("TLS target did not answer before the bounded timeout")).toBeInTheDocument();
    expect(screen.getAllByText("Correct an unreachable target and retry only that target.").length).toBeGreaterThan(0);
    await user.click(screen.getByRole("button", { name: "Retry this exact plan" }));

    expect(await screen.findByText("The scan finished and the inventory was refreshed")).toBeInTheDocument();
    expect(apiMock.startCBOMScan).toHaveBeenCalledTimes(2);
  });

  it("removes the static CBOM fixture array from the Posture page", () => {
    const source = readFileSync(path.join(process.cwd(), "src/pages/Posture.tsx"), "utf8");
    expect(source).not.toMatch(/const\s+cbomRows/);
    expect(source).not.toMatch(/Non-interactive CBOM preview/);
  });
});
