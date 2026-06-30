import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { Incidents } from "@/pages/Incidents";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    graphBlastRadius: vi.fn(),
    incidentExecutions: vi.fn(),
    executeIncident: vi.fn(),
    remediationPlaybooks: vi.fn(),
    remediationPlaybookRuns: vi.fn(),
    ownerRemediationActions: vi.fn(),
    acceptOwnerRemediationAction: vi.fn(),
    fleetReissuanceRuns: vi.fn(),
    startFleetReissuance: vi.fn(),
    pauseFleetReissuance: vi.fn(),
    resumeFleetReissuance: vi.fn(),
    rollbackFleetReissuance: vi.fn(),
    exportFleetReissuanceEvidence: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return {
    ...actual,
    api: {
      ...actual.api,
      graphBlastRadius: apiMock.graphBlastRadius,
      incidentExecutions: apiMock.incidentExecutions,
      executeIncident: apiMock.executeIncident,
      remediationPlaybooks: apiMock.remediationPlaybooks,
      remediationPlaybookRuns: apiMock.remediationPlaybookRuns,
      ownerRemediationActions: apiMock.ownerRemediationActions,
      acceptOwnerRemediationAction: apiMock.acceptOwnerRemediationAction,
      fleetReissuanceRuns: apiMock.fleetReissuanceRuns,
      startFleetReissuance: apiMock.startFleetReissuance,
      pauseFleetReissuance: apiMock.pauseFleetReissuance,
      resumeFleetReissuance: apiMock.resumeFleetReissuance,
      rollbackFleetReissuance: apiMock.rollbackFleetReissuance,
      exportFleetReissuanceEvidence: apiMock.exportFleetReissuanceEvidence,
    },
  };
});

function renderIncidents() {
  return render(
    <MemoryRouter>
      <Incidents />
    </MemoryRouter>,
  );
}

const blastRadius = {
  node: { id: "id:11111111-1111-1111-1111-111111111111", kind: "credential", name: "payments identity" },
  affected: [{ id: "wl:payments", kind: "workload", name: "payments service" }],
  by_kind: { workload: 1 },
};

const execution = {
  id: "exec-1",
  tenant_id: "tenant-1",
  compromised_identity_id: "11111111-1111-1111-1111-111111111111",
  replacement_identity_id: "replacement-1",
  connector_delivery_id: "delivery-1",
  status: "executed",
  phase: "replacement_deployed_and_compromised_revoked",
  reason: "key export detected",
  blast_radius: blastRadius,
  revocation_status: "revocation_publish_queued",
  evidence_bundle_format: "jws",
  evidence_bundle: "sealed.audit.bundle",
  failed_targets: [],
  rollback_refs: ["restore previous binding"],
  idempotency_key: "idem-1",
  created_by: "incident-commander",
  created_at: "2026-06-26T14:00:00Z",
  updated_at: "2026-06-26T14:00:00Z",
};

const fleetRun = {
  id: "fleet-1",
  tenant_id: "tenant-1",
  issuer_id: "issuer-1",
  status: "executed",
  phase: "fleet_reissued_and_compromised_revoked",
  reason: "CA compromise",
  batch_size: 25,
  batch_count: 1,
  connector: "nginx",
  target: "edge/prod",
  graph_impact: { node: { id: "iss:issuer-1", kind: "issuer", name: "issuer" }, affected: [], by_kind: {} },
  affected_identity_ids: ["id-1"],
  replacement_identity_ids: ["id-2"],
  revoked_identity_ids: ["id-1"],
  connector_delivery_ids: ["delivery-1"],
  batches: [],
  health_gates: [{ name: "replacement deployed", status: "passed" }],
  failed_targets: [],
  rollback_refs: ["restore previous binding"],
  evidence_bundle_format: "jws",
  evidence_bundle: "fleet.audit.bundle",
  idempotency_key: "fleet-1",
  created_by: "incident-commander",
  created_at: "2026-06-26T14:00:00Z",
  updated_at: "2026-06-26T14:00:00Z",
};

describe("POL-02 incident polish", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    apiMock.graphBlastRadius.mockReset().mockResolvedValue(blastRadius);
    apiMock.incidentExecutions.mockReset().mockResolvedValue({ items: [] });
    apiMock.executeIncident.mockReset().mockResolvedValue(execution);
    apiMock.remediationPlaybooks.mockReset().mockResolvedValue({ capability: "CAP-REM-01", status: "served", generated_at: "2026-06-26T14:00:00Z", items: [] });
    apiMock.remediationPlaybookRuns.mockReset().mockResolvedValue({ items: [] });
    apiMock.ownerRemediationActions.mockReset().mockResolvedValue({
      capability: "CAP-REM-02",
      status: "served",
      generated_at: "2026-06-26T14:00:00Z",
      summary: { total: 0, open: 0, accepted: 0, critical: 0, high: 0, medium: 0, low: 0 },
      items: [],
      evidence_refs: [],
    });
    apiMock.acceptOwnerRemediationAction.mockReset();
    apiMock.fleetReissuanceRuns.mockReset().mockResolvedValue({ items: [fleetRun] });
    apiMock.startFleetReissuance.mockReset().mockResolvedValue(fleetRun);
    apiMock.pauseFleetReissuance.mockReset().mockResolvedValue({ ...fleetRun, status: "paused" });
    apiMock.resumeFleetReissuance.mockReset().mockResolvedValue(fleetRun);
    apiMock.rollbackFleetReissuance.mockReset().mockResolvedValue({ ...fleetRun, status: "rollback_recorded" });
    apiMock.exportFleetReissuanceEvidence.mockReset().mockResolvedValue({
      run_id: fleetRun.id,
      evidence_bundle_format: "jws",
      evidence_bundle: "fleet.audit.bundle",
      rollback_refs: fleetRun.rollback_refs,
      failed_targets: [],
      exported_at: fleetRun.updated_at,
    });
  });

  it("uses operator-facing form labels, serves fleet runs, and moves break-glass to help", async () => {
    const user = userEvent.setup();
    renderIncidents();

    expect(await screen.findByRole("heading", { name: "Incidents" })).toBeInTheDocument();
    expect(screen.getByLabelText("Affected identity")).toBeInTheDocument();
    expect(screen.getAllByLabelText("What happened")[0]).toBeInTheDocument();
    expect(screen.getByLabelText("Replacement identity name")).toBeInTheDocument();
    expect(screen.getAllByLabelText("Delivery method")[0]).toBeInTheDocument();
    expect(screen.getAllByLabelText("Deployment target")[0]).toBeInTheDocument();
    expect(screen.getAllByLabelText("Rollback instructions")[0]).toBeInTheDocument();
    expect(screen.queryByLabelText("Connector")).not.toBeInTheDocument();
    expect(screen.queryByLabelText("Target")).not.toBeInTheDocument();
    expect(screen.queryByLabelText("Rollback reference")).not.toBeInTheDocument();

    const fleetTable = screen.getByRole("table", { name: "Fleet reissuance runs" });
    expect(within(fleetTable).getByText("fleet-1")).toBeInTheDocument();
    expect(screen.getByLabelText("Compromised issuer")).toBeInTheDocument();
    expect(screen.getByLabelText("Batch size")).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Break-glass procedures" })).not.toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Break-glass help" }));
    const dialog = screen.getByRole("dialog", { name: "Break-glass help" });
    expect(within(dialog).getByText(/quorum approval/i)).toBeInTheDocument();
    expect(within(dialog).getByText(/post-incident checklist/i)).toBeInTheDocument();

    await user.type(screen.getByLabelText("Affected identity"), "11111111-1111-1111-1111-111111111111");
    await user.clear(screen.getAllByLabelText("What happened")[0]);
    await user.type(screen.getAllByLabelText("What happened")[0], "key export detected");
    await user.type(screen.getAllByLabelText("Deployment target")[0], "edge/prod/payments");
    await user.type(screen.getAllByLabelText("Rollback instructions")[0], "restore previous binding");
    await user.click(screen.getByRole("button", { name: "Execute incident" }));

    await waitFor(() =>
      expect(apiMock.executeIncident).toHaveBeenCalledWith({
        identity_id: "11111111-1111-1111-1111-111111111111",
        reason: "key export detected",
        replacement_name: "",
        connector: "nginx",
        target: "edge/prod/payments",
        delivery_rollback_ref: "restore previous binding",
      }),
    );
    expect(await screen.findByText("Incident execution recorded")).toBeInTheDocument();
    expect(screen.getAllByText("replacement_deployed_and_compromised_revoked").length).toBeGreaterThan(0);
  });
});
