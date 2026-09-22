import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { PQCMigrationWorkflow } from "@/components/PQCMigrationWorkflow";
import { CapabilityFixtureProvider } from "@/lib/capabilities";
import type { CapabilityView, CapabilityRuntimeOperation } from "@/lib/api-types.gen";
import type { CBOMAsset } from "@/lib/api";

const mocks = vi.hoisted(() => ({
  editions: vi.fn(),
  planPQCMigration: vi.fn(),
  startPQCMigration: vi.fn(),
  getPQCMigrationProgress: vi.fn(),
  rollbackPQCMigration: vi.fn(),
}));
vi.mock("@/lib/api", () => ({ api: mocks }));
const operations = ["planPQCMigration", "startPQCMigration", "getPQCMigrationProgress", "rollbackPQCMigration"];
const asset = {
  id: "asset-1",
  kind: "certificate-key",
  location: "localhost:8443",
  algorithm: "ECDSA",
  quantum_vulnerable: true,
  migration_target: "ML-DSA-65",
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
function workflow(runtime: CapabilityView | null, loading = false) {
  return (
    <MemoryRouter>
      <CapabilityFixtureProvider view={runtime} loading={loading}>
        <PQCMigrationWorkflow assets={[asset]} />
      </CapabilityFixtureProvider>
    </MemoryRouter>
  );
}
beforeEach(() => {
  vi.resetAllMocks();
  mocks.editions.mockResolvedValue({ tier: "community", state: "community", features: [] });
  mocks.planPQCMigration.mockResolvedValue({ reissues: [], tls_rollouts: [], residuals: [], reissue_count: 1, tls_rollout_count: 0 });
  mocks.startPQCMigration.mockResolvedValue({ run_id: "run-1" });
  mocks.getPQCMigrationProgress.mockResolvedValue({ applied: 1, queued: 0, failed: 0, rolled_back: 0 });
  mocks.rollbackPQCMigration.mockResolvedValue({ queued: 1 });
});

describe("Core PQC runtime authority", () => {
  it.each(["community", "read_only"] as const)("allows the whole reviewed workflow with %s license state", async (state) => {
    const user = userEvent.setup();
    render(workflow(view(state)));
    await user.click(await screen.findByRole("checkbox", { name: "Select localhost:8443 for PQC migration" }));
    await user.click(screen.getByRole("button", { name: "Preview migration plan" }));
    const start = await screen.findByRole("button", { name: "Start migration" });
    expect(start).toBeDisabled();
    await user.click(screen.getByRole("checkbox", { name: /I reviewed this exact plan/ }));
    await user.click(start);
    await user.click(await screen.findByRole("button", { name: "Refresh progress" }));
    expect(await screen.findByText("1 applied · 0 queued · 0 failed · 0 rolled back")).toBeInTheDocument();
    await user.click(screen.getByRole("checkbox", { name: /I reviewed the current run evidence/ }));
    await user.click(screen.getByRole("button", { name: "Queue rollback" }));
    await waitFor(() => expect(mocks.rollbackPQCMigration).toHaveBeenCalledWith("run-1", ["asset-1"], expect.any(String)));
    expect(mocks.editions).not.toHaveBeenCalled();
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
    await user.click(await screen.findByRole("checkbox", { name: "Select localhost:8443 for PQC migration" }));
    await user.click(screen.getByRole("button", { name: "Preview migration plan" }));
    await user.click(await screen.findByRole("checkbox", { name: /I reviewed this exact plan/ }));
    result.rerender(workflow(view("community", [{ operation_id: "startPQCMigration", state: "denied" }])));
    const start = screen.getByRole("button", { name: "Start migration" });
    expect(start).toBeDisabled();
    await user.click(start);
    expect(mocks.startPQCMigration).not.toHaveBeenCalled();
  });

  it("checks progress and rollback separately after planning permission changes", async () => {
    const user = userEvent.setup();
    const result = render(workflow(view()));
    await user.click(await screen.findByRole("checkbox", { name: "Select localhost:8443 for PQC migration" }));
    await user.click(screen.getByRole("button", { name: "Preview migration plan" }));
    await user.click(await screen.findByRole("checkbox", { name: /I reviewed this exact plan/ }));
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
