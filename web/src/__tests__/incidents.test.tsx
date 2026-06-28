import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { ApiError } from "@/lib/api";
import { Incidents } from "@/pages/Incidents";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    graphBlastRadius: vi.fn(),
    incidentExecutions: vi.fn(),
    executeIncident: vi.fn(),
    createServiceNowTicket: vi.fn(),
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
      createServiceNowTicket: apiMock.createServiceNowTicket,
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

const impact = {
  node: { id: "id:11111111-1111-1111-1111-111111111111", kind: "credential", name: "payments-api identity" },
  affected: [
    { id: "wl:payments", kind: "workload", name: "payments service" },
    { id: "res:ledger", kind: "resource", name: "ledger database" },
  ],
  by_kind: { workload: [{ id: "wl:payments", kind: "workload", name: "payments service" }], resource: [] },
};

const execution = {
  id: "22222222-2222-2222-2222-222222222222",
  tenant_id: "tenant-1",
  compromised_identity_id: "11111111-1111-1111-1111-111111111111",
  replacement_identity_id: "33333333-3333-3333-3333-333333333333",
  connector_delivery_id: "44444444-4444-4444-4444-444444444444",
  status: "executed",
  phase: "replacement_deployed_and_compromised_revoked",
  reason: "private key compromise",
  blast_radius: impact,
  revocation_status: "revocation_publish_queued",
  evidence_bundle_format: "jws",
  evidence_bundle: "sealed.audit.bundle",
  failed_targets: ["nginx:edge/prod/payments:unrouted"],
  rollback_refs: ["identity:11111111-1111-1111-1111-111111111111", "restore previous fullchain"],
  idempotency_key: "idem-1",
  created_by: "incident-commander",
  created_at: "2026-06-20T12:00:00Z",
  updated_at: "2026-06-20T12:00:00Z",
  connector_delivery: {
    id: "44444444-4444-4444-4444-444444444444",
    tenant_id: "tenant-1",
    destination: "connector.deploy",
    connector: "nginx",
    target: "edge/prod/payments",
    status: "unrouted",
    attempts: 1,
    created_at: "2026-06-20T12:00:00Z",
    updated_at: "2026-06-20T12:00:00Z",
  },
};

const fleetRun = {
  id: "66666666-6666-6666-6666-666666666666",
  tenant_id: "tenant-1",
  issuer_id: "77777777-7777-7777-7777-777777777777",
  status: "executed",
  phase: "fleet_reissued_and_compromised_revoked",
  reason: "intermediate CA private key exposure",
  batch_size: 1,
  batch_count: 2,
  connector: "nginx",
  target: "edge/prod",
  graph_impact: {
    node: { id: "iss:77777777-7777-7777-7777-777777777777", kind: "issuer", name: "compromised intermediate" },
    affected: [{ id: "id:11111111-1111-1111-1111-111111111111", kind: "credential", name: "payments-api" }],
    by_kind: { credential: [] },
  },
  affected_identity_ids: ["11111111-1111-1111-1111-111111111111", "88888888-8888-8888-8888-888888888888"],
  replacement_identity_ids: ["99999999-9999-9999-9999-999999999999", "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"],
  revoked_identity_ids: ["11111111-1111-1111-1111-111111111111", "88888888-8888-8888-8888-888888888888"],
  connector_delivery_ids: ["bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", "cccccccc-cccc-cccc-cccc-cccccccccccc"],
  batches: [
    {
      index: 1,
      status: "completed",
      identity_ids: ["11111111-1111-1111-1111-111111111111"],
      replacement_identity_ids: ["99999999-9999-9999-9999-999999999999"],
      health_gate: "replacement deployed:passed",
    },
    {
      index: 2,
      status: "completed",
      identity_ids: ["88888888-8888-8888-8888-888888888888"],
      replacement_identity_ids: ["aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"],
      health_gate: "revocation published:passed",
    },
  ],
  health_gates: [
    { name: "replacement deployed", status: "passed" },
    { name: "revocation published", status: "passed" },
  ],
  failed_targets: ["nginx:edge/prod:unrouted"],
  rollback_refs: ["issuer:77777777-7777-7777-7777-777777777777", "restore previous bindings"],
  evidence_bundle_format: "jws",
  evidence_bundle: "fleet.audit.bundle",
  idempotency_key: "fleet-1",
  created_by: "incident-commander",
  created_at: "2026-06-20T12:10:00Z",
  updated_at: "2026-06-20T12:10:00Z",
  replacement_identities: [],
  connector_deliveries: [],
};

describe("incident response served execution surface", () => {
  beforeEach(() => {
    apiMock.graphBlastRadius.mockReset().mockResolvedValue(impact);
    apiMock.incidentExecutions.mockReset().mockResolvedValue({ items: [execution] });
    apiMock.executeIncident.mockReset().mockResolvedValue(execution);
    apiMock.fleetReissuanceRuns.mockReset().mockResolvedValue({ items: [fleetRun] });
    apiMock.startFleetReissuance.mockReset().mockResolvedValue(fleetRun);
    apiMock.pauseFleetReissuance.mockReset().mockResolvedValue({ ...fleetRun, status: "paused", phase: "operator_paused" });
    apiMock.resumeFleetReissuance.mockReset().mockResolvedValue({ ...fleetRun, phase: "resume_recorded" });
    apiMock.rollbackFleetReissuance.mockReset().mockResolvedValue({
      ...fleetRun,
      status: "rollback_recorded",
      phase: "rollback_evidence_recorded",
      rollback_refs: [...fleetRun.rollback_refs, "restore previous credential bindings"],
    });
    apiMock.exportFleetReissuanceEvidence.mockReset().mockResolvedValue({
      run_id: fleetRun.id,
      evidence_bundle_format: "jws",
      evidence_bundle: "fleet.audit.bundle",
      rollback_refs: fleetRun.rollback_refs,
      failed_targets: fleetRun.failed_targets,
      exported_at: fleetRun.updated_at,
    });
    apiMock.createServiceNowTicket.mockReset().mockResolvedValue({
      id: "55555555-5555-5555-5555-555555555555",
      tenant_id: "tenant-1",
      provider: "servicenow",
      destination: "itsm.servicenow",
      table: "incident",
      status: "queued",
      outbox_id: 42,
      idempotency_key: "evt-555",
      created_at: "2026-06-20T12:05:00Z",
    });
  });

  it("loads execution evidence and runs served replacement-before-revoke remediation", async () => {
    const user = userEvent.setup();
    renderIncidents();

    expect(screen.getByRole("heading", { name: "Incidents" })).toBeInTheDocument();
    expect(await screen.findByRole("heading", { name: "Execution evidence" })).toBeInTheDocument();
    expect(await screen.findByText("22222222-2222-2222-2222-222222222222")).toBeInTheDocument();
    expect(screen.queryByText(/Incident execution is not served/i)).not.toBeInTheDocument();

    await user.type(screen.getByLabelText("Affected identity"), "11111111-1111-1111-1111-111111111111");
    await user.clear(screen.getAllByLabelText("What happened")[0]);
    await user.type(screen.getAllByLabelText("What happened")[0], "key export detected");
    await user.type(screen.getAllByLabelText("Deployment target")[0], "edge/prod/payments");
    await user.type(screen.getAllByLabelText("Rollback instructions")[0], "restore previous fullchain");
    await user.click(screen.getByRole("button", { name: "Preview blast radius" }));

    await waitFor(() => expect(apiMock.graphBlastRadius).toHaveBeenCalledWith("id:11111111-1111-1111-1111-111111111111"));
    expect(await screen.findByRole("heading", { name: "Blast-radius snapshot" })).toBeInTheDocument();
    expect(screen.getByText("payments service")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Execute incident" }));

    await waitFor(() =>
      expect(apiMock.executeIncident).toHaveBeenCalledWith({
        identity_id: "11111111-1111-1111-1111-111111111111",
        reason: "key export detected",
        replacement_name: "",
        connector: "nginx",
        target: "edge/prod/payments",
        delivery_rollback_ref: "restore previous fullchain",
      }),
    );
    expect(await screen.findByText("Incident execution recorded")).toBeInTheDocument();
    expect(await screen.findByText("nginx:edge/prod/payments:unrouted")).toBeInTheDocument();
    expect(screen.getAllByText("jws").length).toBeGreaterThan(0);
    expect(screen.getByText("sealed.audit.bundle")).toBeInTheDocument();

    await user.type(screen.getByLabelText("ServiceNow instance"), "http://servicenow.test");
    await user.type(screen.getByLabelText("Ticket summary"), "Rotate exposed TLS private key");
    await user.click(screen.getByRole("button", { name: "Queue ServiceNow ticket" }));

    await waitFor(() =>
      expect(apiMock.createServiceNowTicket).toHaveBeenCalledWith({
        instance_url: "http://servicenow.test",
        table: "incident",
        token_ref: "servicenow-ticket-token",
        short_description: "Rotate exposed TLS private key",
        description: "",
        category: "security",
        urgency: "2",
        impact: "2",
        correlation_id: "",
      }),
    );
    expect(await screen.findByText("ServiceNow ticket queued")).toBeInTheDocument();
    expect(screen.getByText("55555555-5555-5555-5555-555555555555")).toBeInTheDocument();
  });

  it("runs fleet reissuance actions and keeps break-glass in help", async () => {
    apiMock.graphBlastRadius.mockRejectedValueOnce(new ApiError(503, JSON.stringify({ detail: "graph projection is rebuilding" })));
    const user = userEvent.setup();
    renderIncidents();

    await user.type(await screen.findByLabelText("Affected identity"), "11111111-1111-1111-1111-111111111111");
    await user.click(screen.getByRole("button", { name: "Preview blast radius" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("graph projection is rebuilding");
    expect(screen.getByRole("heading", { name: "Fleet re-issuance" })).toBeInTheDocument();
    expect(screen.getByRole("table", { name: "Fleet reissuance runs" })).toBeInTheDocument();
    expect(screen.getByText("66666666-6666-6666-6666-666666666666")).toBeInTheDocument();
    expect(screen.getByText("2 affected")).toBeInTheDocument();
    await user.type(screen.getByLabelText("Compromised issuer"), "77777777-7777-7777-7777-777777777777");
    await user.clear(screen.getByLabelText("Batch size"));
    await user.type(screen.getByLabelText("Batch size"), "1");
    await user.type(screen.getAllByLabelText("Deployment target")[1], "edge/prod");
    await user.type(screen.getAllByLabelText("Rollback instructions")[1], "restore previous bindings");
    await user.click(screen.getByRole("button", { name: "Start fleet run" }));
    await waitFor(() =>
      expect(apiMock.startFleetReissuance).toHaveBeenCalledWith(
        expect.objectContaining({
          issuer_id: "77777777-7777-7777-7777-777777777777",
          batch_size: 1,
          connector: "nginx",
          target: "edge/prod",
          rollback_ref: "restore previous bindings",
        }),
      ),
    );
    expect(await screen.findByText("Fleet run recorded")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Pause fleet run 66666666" }));
    await waitFor(() => expect(apiMock.pauseFleetReissuance).toHaveBeenCalledWith(fleetRun.id, { reason: "operator pause" }));
    await user.click(screen.getByRole("button", { name: "Resume fleet run 66666666" }));
    await waitFor(() => expect(apiMock.resumeFleetReissuance).toHaveBeenCalledWith(fleetRun.id, { reason: "operator resume" }));
    await user.click(screen.getByRole("button", { name: "Rollback fleet run 66666666" }));
    await waitFor(() =>
      expect(apiMock.rollbackFleetReissuance).toHaveBeenCalledWith(fleetRun.id, {
        reason: "operator rollback",
        rollback_ref: "restore previous credential bindings",
      }),
    );
    expect(await screen.findByText("Fleet evidence exported")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Export fleet run 66666666 evidence" }));
    await waitFor(() => expect(apiMock.exportFleetReissuanceEvidence).toHaveBeenCalledWith(fleetRun.id));
    await waitFor(() => expect(screen.getAllByText("fleet.audit.bundle").length).toBeGreaterThan(0));
    expect(screen.queryByRole("heading", { name: "Break-glass procedures" })).not.toBeInTheDocument();

    const opener = screen.getByRole("button", { name: "Break-glass help" });
    await user.click(opener);

    const dialog = screen.getByRole("dialog", { name: "Break-glass help" });
    const close = within(dialog).getByRole("button", { name: "Close help" });
    expect(close).toHaveFocus();
    await user.tab();
    expect(close).toHaveFocus();
    expect(dialog).toHaveTextContent(/emergency declaration/i);
    expect(dialog).toHaveTextContent(/quorum approval/i);
    expect(dialog).toHaveTextContent(/offline issue/i);
    expect(dialog).toHaveTextContent(/post-incident checklist/i);

    await user.keyboard("{Escape}");
    expect(screen.queryByRole("dialog", { name: "Break-glass help" })).not.toBeInTheDocument();
    expect(opener).toHaveFocus();
  });
});
