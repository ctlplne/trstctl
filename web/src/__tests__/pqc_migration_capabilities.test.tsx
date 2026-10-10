import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { PQCMigrationWorkflow } from "@/components/PQCMigrationWorkflow";
import { CapabilityFixtureProvider } from "@/lib/capabilities";
import { AppQueryProvider } from "@/lib/query";
import type { CapabilityView, CapabilityRuntimeOperation } from "@/lib/api-types.gen";
import type { CBOMAsset } from "@/lib/api";

const mocks = vi.hoisted(() => ({
  editions: vi.fn(),
  planPQCMigration: vi.fn(),
  startPQCMigration: vi.fn(),
  getPQCMigrationProgress: vi.fn(),
  rollbackPQCMigration: vi.fn(),
  connectorTargets: vi.fn(),
  identities: vi.fn(),
}));
vi.mock("@/lib/api", () => ({ api: mocks }));
const operations = ["planPQCMigration", "startPQCMigration", "getPQCMigrationProgress", "rollbackPQCMigration"];
const asset = {
  id: "asset-1",
  kind: "certificate-key",
  location: "127.0.0.1:10443",
  algorithm: "ECDSA",
  quantum_vulnerable: true,
  migration_target: "ML-DSA-65",
} as CBOMAsset;
const tlsAsset = {
  id: "tls-asset-1",
  kind: "host-config",
  location: "edge.internal:443",
  algorithm: "TLSv1.0",
  protocol: "TLSv1.0",
  quantum_vulnerable: true,
  out_of_policy: true,
} as CBOMAsset;

function view(state: "community" | "read_only" = "community", overrides: CapabilityRuntimeOperation[] = []): CapabilityView {
  return {
    schema_version: 2,
    contract_schema_version: 3,
    enforcement_note: "Server authorization is authoritative.",
    license: { tier: state === "community" ? "community" : "enterprise", state },
    items: [],
    operations: operations.map((operation_id) => overrides.find((op) => op.operation_id === operation_id) ?? { operation_id, state: "allowed" }),
  };
}
function workflow(runtime: CapabilityView | null, loading = false, assets: CBOMAsset[] = [asset]) {
  return (
    <MemoryRouter>
      <AppQueryProvider>
        <CapabilityFixtureProvider view={runtime} loading={loading}>
          <PQCMigrationWorkflow assets={assets} />
        </CapabilityFixtureProvider>
      </AppQueryProvider>
    </MemoryRouter>
  );
}
beforeEach(() => {
  vi.resetAllMocks();
  mocks.editions.mockResolvedValue({ tier: "community", state: "community", features: [] });
  mocks.planPQCMigration.mockResolvedValue({ reissues: [], tls_rollouts: [], residuals: [], reissue_count: 1, tls_rollout_count: 0 });
  mocks.startPQCMigration.mockResolvedValue({ run_id: "run-1" });
  mocks.getPQCMigrationProgress.mockResolvedValue({
    run_id: "run-1",
    total: 1,
    applied: 1,
    queued: 0,
    failed: 0,
    rolled_back: 0,
    findings: [
      {
        run_id: "run-1",
        asset_id: "asset-1",
        finding_kind: "certificate-key",
        status: "applied",
        target_id: "apache-1",
        target_revision: "revision-1",
        connector: "apache",
        updated_at: "2026-10-10T00:00:00Z",
      },
    ],
  });
  mocks.rollbackPQCMigration.mockResolvedValue({ queued: 1 });
  mocks.connectorTargets.mockResolvedValue({
    items: [
      { id: "target-1", name: "Lab Envoy", connector: "envoy", enabled: true },
      {
        id: "apache-1",
        name: "Lab Apache",
        connector: "apache",
        enabled: true,
        config: {
          executor: "agent",
          cert_path: "/lab/tls/apache.crt",
          key_path: "/lab/tls/apache.key",
          verify_address: "127.0.0.1:10443",
          verify_server_name: "apache.partner-lab.example.com",
        },
      },
    ],
  });
  mocks.identities.mockResolvedValue([
    {
      id: "identity-1",
      kind: "x509_certificate",
      status: "requested",
      name: "apache.partner-lab.example.com",
      attributes: { subject_key_algorithm: "ML-DSA-65", deployment_target_id: "apache-1" },
    },
  ]);
});

async function bindCertificate(user: ReturnType<typeof userEvent.setup>) {
  await user.click(await screen.findByRole("checkbox", { name: "Select 127.0.0.1:10443 for PQC migration" }));
  await user.selectOptions(await screen.findByRole("combobox", { name: "Deployment target for 127.0.0.1:10443" }), "apache-1");
  await user.selectOptions(screen.getByRole("combobox", { name: "Requested identity for 127.0.0.1:10443" }), "identity-1");
}

describe("Core PQC runtime authority", () => {
  it("offers an observed TLS 1.2 endpoint for a reviewed PQC posture rollout even when current policy permits it", async () => {
    const observed = {
      id: "observed-tls12",
      kind: "tls-endpoint",
      location: "edge.internal:443",
      protocol: "TLSv1.2",
      strength: "acceptable",
      quantum_vulnerable: false,
      out_of_policy: false,
    } as CBOMAsset;
    render(workflow(view(), false, [observed]));
    expect(await screen.findByRole("checkbox", { name: "Select edge.internal:443 · TLSv1.2 for PQC migration" })).toBeInTheDocument();
  });

  it("distinguishes protocol and cipher findings at the same config path", async () => {
    const user = userEvent.setup();
    const cipherAsset = { ...tlsAsset, id: "tls-asset-2", protocol: undefined, cipher: "TLS_RSA_WITH_3DES_EDE_CBC_SHA" } as CBOMAsset;
    render(workflow(view(), false, [tlsAsset, cipherAsset]));
    await user.click(await screen.findByRole("checkbox", { name: "Select edge.internal:443 · TLSv1.0 for PQC migration" }));
    await user.click(screen.getByRole("checkbox", { name: "Select edge.internal:443 · TLS_RSA_WITH_3DES_EDE_CBC_SHA for PQC migration" }));
    expect(screen.getByText("TLSv1.0 → X25519MLKEM768")).toBeInTheDocument();
    expect(screen.getByText("TLS_RSA_WITH_3DES_EDE_CBC_SHA → X25519MLKEM768")).toBeInTheDocument();
    expect(await screen.findByRole("combobox", { name: "Deployment target for edge.internal:443 · TLSv1.0" })).toBeInTheDocument();
    expect(screen.getByRole("combobox", { name: "Deployment target for edge.internal:443 · TLS_RSA_WITH_3DES_EDE_CBC_SHA" })).toBeInTheDocument();
  });

  it("requires an explicit TLS target and sends the same reviewed binding to preview and start", async () => {
    const user = userEvent.setup();
    render(workflow(view(), false, [tlsAsset]));
    await user.click(await screen.findByRole("checkbox", { name: "Select edge.internal:443 · TLSv1.0 for PQC migration" }));
    const preview = screen.getByRole("button", { name: "Preview migration plan" });
    expect(preview).toBeDisabled();
    await user.selectOptions(await screen.findByRole("combobox", { name: "Deployment target for edge.internal:443 · TLSv1.0" }), "target-1");
    expect(preview).toBeEnabled();
    await user.click(preview);
    await waitFor(() =>
      expect(mocks.planPQCMigration).toHaveBeenCalledWith(
        expect.objectContaining({
          tls_bindings: [
            {
              asset_id: "tls-asset-1",
              target_id: "target-1",
              desired: {
                minimum_version: "TLSv1.3",
                cipher_suites: [],
                key_exchange_groups: ["X25519MLKEM768", "X25519"],
              },
            },
          ],
        }),
      ),
    );
    await user.click(await screen.findByRole("checkbox", { name: /Completion requires a signed readback/ }));
    await user.click(screen.getByRole("button", { name: "Start migration" }));
    expect(mocks.startPQCMigration).toHaveBeenCalledWith(mocks.planPQCMigration.mock.calls[0][0]);
  });
  it.each(["community", "read_only"] as const)("allows the whole reviewed workflow with %s license state", async (state) => {
    const user = userEvent.setup();
    render(workflow(view(state)));
    await bindCertificate(user);
    await user.click(screen.getByRole("button", { name: "Preview migration plan" }));
    const start = await screen.findByRole("button", { name: "Start migration" });
    expect(start).toBeDisabled();
    await user.click(screen.getByRole("checkbox", { name: /Completion requires a signed readback/ }));
    await user.click(start);
    await user.click(await screen.findByRole("button", { name: "Refresh progress" }));
    expect(await screen.findByText("1 applied · 0 queued · 0 failed · 0 rolled back")).toBeInTheDocument();
    await user.click(screen.getByRole("checkbox", { name: "Select 127.0.0.1:10443 for PQC migration" }));
    await user.click(screen.getByRole("checkbox", { name: /I reviewed the current run evidence/ }));
    await user.click(screen.getByRole("button", { name: "Queue rollback" }));
    await waitFor(() => expect(mocks.rollbackPQCMigration).toHaveBeenCalledWith("run-1", ["asset-1"], expect.any(String)));
    expect(mocks.editions).not.toHaveBeenCalled();
  });

  it("reopens a durable run after console reload and scopes rollback to its applied finding", async () => {
    const user = userEvent.setup();
    const runId = "61590807-8822-484b-beb7-e471dc892d4d";
    mocks.getPQCMigrationProgress.mockResolvedValue({
      run_id: runId,
      total: 2,
      applied: 1,
      queued: 1,
      failed: 0,
      rolled_back: 0,
      findings: [
        {
          run_id: runId,
          asset_id: "asset-1",
          finding_kind: "certificate-key",
          status: "applied",
          target_id: "apache-1",
          target_revision: "revision-1",
          connector: "apache",
          updated_at: "2026-10-10T00:00:00Z",
        },
        {
          run_id: runId,
          asset_id: "queued-asset",
          finding_kind: "tls-endpoint",
          status: "queued",
          target_id: "envoy-1",
          target_revision: "revision-1",
          connector: "envoy",
          updated_at: "2026-10-10T00:00:00Z",
        },
      ],
    });
    render(workflow(view()));
    await user.type(screen.getByRole("textbox", { name: "Existing migration run ID" }), runId);
    await user.click(screen.getByRole("button", { name: "Open run" }));
    expect(await screen.findByText(`Run ${runId}`)).toBeInTheDocument();
    await user.click(screen.getByRole("checkbox", { name: /I reviewed the current run evidence/ }));
    await user.click(screen.getByRole("button", { name: "Queue rollback" }));
    await waitFor(() => expect(mocks.rollbackPQCMigration).toHaveBeenCalledWith(runId, ["asset-1"], expect.any(String)));
  });

  it.each(["denied", "unavailable"] as const)("refuses %s planning without pretending it needs a license", async (state) => {
    render(
      workflow(
        view("community", [
          {
            operation_id: "planPQCMigration",
            state,
            ...(state === "unavailable" ? { code: "dependency_not_configured" as const, detail: "Migration issuer is not configured." } : {}),
          },
        ]),
      ),
    );
    expect(await screen.findByText(state === "unavailable" ? "Migration issuer is not configured." : /role does not include.*permission/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Preview migration plan" })).not.toBeInTheDocument();
    expect(mocks.planPQCMigration).not.toHaveBeenCalled();
  });

  it("keeps missing and loading capability truth closed", () => {
    const result = render(workflow(null, true));
    expect(screen.queryByRole("button", { name: "Preview migration plan" })).not.toBeInTheDocument();
    result.rerender(workflow(null));
    expect(screen.queryByRole("button", { name: "Preview migration plan" })).not.toBeInTheDocument();
  });

  it("rechecks start authority after preview", async () => {
    const user = userEvent.setup();
    const result = render(workflow(view()));
    await bindCertificate(user);
    await user.click(screen.getByRole("button", { name: "Preview migration plan" }));
    await user.click(await screen.findByRole("checkbox", { name: /Completion requires a signed readback/ }));
    result.rerender(workflow(view("community", [{ operation_id: "startPQCMigration", state: "denied" }])));
    const start = screen.getByRole("button", { name: "Start migration" });
    expect(start).toBeDisabled();
    await user.click(start);
    expect(mocks.startPQCMigration).not.toHaveBeenCalled();
  });

  it("checks progress and rollback separately after planning permission changes", async () => {
    const user = userEvent.setup();
    const result = render(workflow(view()));
    await bindCertificate(user);
    await user.click(screen.getByRole("button", { name: "Preview migration plan" }));
    await user.click(await screen.findByRole("checkbox", { name: /Completion requires a signed readback/ }));
    await user.click(screen.getByRole("button", { name: "Start migration" }));
    await screen.findByRole("button", { name: "Refresh progress" });
    result.rerender(
      workflow(
        view("community", [
          { operation_id: "planPQCMigration", state: "denied" },
          { operation_id: "getPQCMigrationProgress", state: "denied" },
          { operation_id: "rollbackPQCMigration", state: "denied" },
        ]),
      ),
    );
    expect(screen.getByRole("button", { name: "Refresh progress" })).toBeDisabled();
    await user.click(screen.getByRole("checkbox", { name: /I reviewed the current run evidence/ }));
    expect(screen.getByRole("button", { name: "Queue rollback" })).toBeDisabled();
    expect(mocks.getPQCMigrationProgress).not.toHaveBeenCalled();
    expect(mocks.rollbackPQCMigration).not.toHaveBeenCalled();
    result.rerender(workflow(view("community", [{ operation_id: "planPQCMigration", state: "denied" }])));
    await user.click(screen.getByRole("button", { name: "Refresh progress" }));
    expect(await screen.findByText("1 applied · 0 queued · 0 failed · 0 rolled back")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Queue rollback" }));
    await waitFor(() => expect(mocks.rollbackPQCMigration).toHaveBeenCalled());
  });
});
