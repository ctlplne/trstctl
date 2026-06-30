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
    dispatchResponseIntegrations: vi.fn(),
    createServiceNowTicket: vi.fn(),
    remediationPlaybooks: vi.fn(),
    remediationPlaybookRuns: vi.fn(),
    runRemediationPlaybook: vi.fn(),
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
      dispatchResponseIntegrations: apiMock.dispatchResponseIntegrations,
      createServiceNowTicket: apiMock.createServiceNowTicket,
      remediationPlaybooks: apiMock.remediationPlaybooks,
      remediationPlaybookRuns: apiMock.remediationPlaybookRuns,
      runRemediationPlaybook: apiMock.runRemediationPlaybook,
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

const playbooks = [
  {
    id: "identity-revoke",
    name: "Revoke identity",
    action: "revoke",
    status: "served",
    capability: "CAP-REM-01",
    summary: "Revoke an identity",
    external_effect: "revocation.publish outbox",
    required_inputs: ["target_identity_id"],
    evidence_sources: ["remediation.playbook_run.recorded event"],
  },
  {
    id: "credential-rotate",
    name: "Rotate credential",
    action: "rotate",
    status: "served",
    capability: "CAP-REM-01",
    summary: "Rotate a credential",
    external_effect: "ca.issue, connector.deploy, revocation.publish outbox",
    required_inputs: ["target_identity_id"],
    evidence_sources: ["remediation.playbook_run.recorded event"],
  },
  {
    id: "nhi-right-size",
    name: "Right-size NHI grants",
    action: "right_size",
    status: "served",
    capability: "CAP-REM-01",
    summary: "Queue least-privilege grants",
    external_effect: "connector.right_size outbox",
    required_inputs: ["inventory_id or target_identity_id"],
    evidence_sources: ["GET /api/v1/nhi/posture/overprivilege", "remediation.playbook_run.recorded event"],
  },
];

const playbookRun = {
  id: "dddddddd-dddd-dddd-dddd-dddddddddddd",
  tenant_id: "tenant-1",
  playbook_id: "nhi-right-size",
  target_identity_id: "11111111-1111-1111-1111-111111111111",
  inventory_id: "identity/11111111-1111-1111-1111-111111111111",
  status: "queued",
  phase: "right_size_connector_intent_queued",
  action: "right_size",
  reason: "right-size unused grants",
  connector: "aws-iam",
  target: "arn:aws:iam::123456789012:role/payments-bot",
  connector_delivery_id: "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee",
  scope_delta: {
    remove_scopes: ["secrets:write"],
    used_scopes: ["secrets:read"],
  },
  evidence_refs: ["nhi_posture:CAP-POST-01"],
  rollback_refs: ["restore iam policy version v17"],
  idempotency_key: "playbook-1",
  created_by: "incident-commander",
  created_at: "2026-06-20T12:20:00Z",
  updated_at: "2026-06-20T12:20:00Z",
  connector_delivery: {
    id: "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee",
    tenant_id: "tenant-1",
    destination: "connector.right_size",
    connector: "aws-iam",
    target: "arn:aws:iam::123456789012:role/payments-bot",
    status: "queued",
    attempts: 1,
    created_at: "2026-06-20T12:20:00Z",
    updated_at: "2026-06-20T12:20:00Z",
  },
};

const ownerAction = {
  id: "right-size-aWRlbnRpdHkvMTEx",
  owner_id: "owner-payments",
  owner_name: "payments-team",
  owner_email: "payments-owner@example.com",
  inventory_id: "identity/11111111-1111-1111-1111-111111111111",
  target_identity_id: "11111111-1111-1111-1111-111111111111",
  display_name: "payments-owner-bot",
  kind: "service_account",
  source: "managed",
  playbook_id: "nhi-right-size",
  action: "right_size",
  status: "open",
  severity: "high",
  risk_score: 82,
  connector: "aws-iam",
  target: "arn:aws:iam::123456789012:role/payments-bot",
  reason: "owner accepted least-privilege right-size remediation",
  recommendation: "Remove unused admin grants and keep observed read scope.",
  remove_scopes: ["admin:*", "secrets:write"],
  recommended_scopes: ["secrets:read"],
  evidence_refs: ["nhi_posture:CAP-POST-01"],
  rollback_ref: "restore prior grants admin:*,secrets:write",
};

const ownerRemediationRun = {
  capability: "CAP-REM-02",
  status: "accepted",
  action: {
    ...ownerAction,
    status: "accepted",
    remediation_run_id: playbookRun.id,
    connector_delivery_id: "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee",
  },
  remediation_run: playbookRun,
};

const responseDispatch = {
  id: "99999999-1111-2222-3333-444444444444",
  tenant_id: "tenant-1",
  status: "queued",
  idempotency_key: "response-event-1",
  created_at: "2026-06-20T12:30:00Z",
  destinations: [
    { id: "splunk", provider: "splunk", destination: "response.splunk", status: "queued", outbox_id: 71, idempotency_key: "response-event-1:splunk" },
    { id: "jira", provider: "jira", destination: "response.jira", status: "queued", outbox_id: 72, idempotency_key: "response-event-1:jira" },
    { id: "slack", provider: "slack", destination: "notification.response", status: "queued", outbox_id: 73, idempotency_key: "response-event-1:slack" },
    { id: "servicenow", provider: "servicenow", destination: "itsm.servicenow", status: "queued", outbox_id: 74, idempotency_key: "response-event-1:servicenow" },
  ],
};

describe("incident response served execution surface", () => {
  beforeEach(() => {
    apiMock.graphBlastRadius.mockReset().mockResolvedValue(impact);
    apiMock.incidentExecutions.mockReset().mockResolvedValue({ items: [execution] });
    apiMock.executeIncident.mockReset().mockResolvedValue(execution);
    apiMock.remediationPlaybooks.mockReset().mockResolvedValue({ capability: "CAP-REM-01", status: "served", generated_at: "2026-06-20T12:00:00Z", items: playbooks });
    apiMock.remediationPlaybookRuns.mockReset().mockResolvedValue({ items: [playbookRun] });
    apiMock.runRemediationPlaybook.mockReset().mockResolvedValue(playbookRun);
    apiMock.ownerRemediationActions.mockReset().mockResolvedValue({
      capability: "CAP-REM-02",
      status: "served",
      generated_at: "2026-06-20T12:25:00Z",
      summary: { total: 1, open: 1, accepted: 0, critical: 0, high: 1, medium: 0, low: 0 },
      items: [ownerAction],
      evidence_refs: ["GET /api/v1/nhi/posture/overprivilege", "remediation.playbook_run.recorded"],
    });
    apiMock.acceptOwnerRemediationAction.mockReset().mockResolvedValue(ownerRemediationRun);
    apiMock.dispatchResponseIntegrations.mockReset().mockResolvedValue(responseDispatch);
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

    await user.type(screen.getAllByLabelText("ServiceNow instance")[1], "http://servicenow.test");
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

  it("dispatches served SIEM SOAR chat and ITSM response integrations", async () => {
    const user = userEvent.setup();
    renderIncidents();

    expect(await screen.findByRole("heading", { name: "SIEM / SOAR / ITSM dispatch" })).toBeInTheDocument();

    await user.type(screen.getByLabelText("Response title"), "Contain compromised payments credential");
    await user.type(screen.getByLabelText("Response summary"), "Rotate, revoke, page responders, and open investigation.");
    await user.type(screen.getAllByLabelText("Correlation ID")[0], "INC-2026-1001");
    await user.type(screen.getByLabelText("Evidence references"), "incident/exec-1, audit/event-2");
    await user.type(screen.getByLabelText("Splunk HEC endpoint"), "https://splunk.example/services/collector");
    await user.type(screen.getByLabelText("Jira endpoint"), "https://jira.example");
    await user.clear(screen.getByLabelText("Jira project"));
    await user.type(screen.getByLabelText("Jira project"), "SEC");
    await user.type(screen.getAllByLabelText("ServiceNow instance")[0], "https://now.example");
    await user.click(screen.getByRole("button", { name: "Dispatch response" }));

    await waitFor(() =>
      expect(apiMock.dispatchResponseIntegrations).toHaveBeenCalledWith({
        title: "Contain compromised payments credential",
        summary: "Rotate, revoke, page responders, and open investigation.",
        severity: "critical",
        correlation_id: "INC-2026-1001",
        evidence_refs: ["incident/exec-1", "audit/event-2"],
        destinations: [
          { id: "splunk", provider: "splunk", endpoint_url: "https://splunk.example/services/collector", token_ref: "splunk-response-token" },
          {
            id: "jira",
            provider: "jira",
            endpoint_url: "https://jira.example",
            project_key: "SEC",
            issue_type: "Task",
            token_ref: "jira-response-token",
          },
          { id: "slack", provider: "slack", channel: "security-incidents" },
          { id: "servicenow", provider: "servicenow", instance_url: "https://now.example", table: "incident", token_ref: "servicenow-response-token" },
        ],
      }),
    );
    expect(await screen.findByText("Response dispatch queued")).toBeInTheDocument();
    expect(screen.getByText("response.splunk")).toBeInTheDocument();
    expect(screen.getByText("response.jira")).toBeInTheDocument();
    expect(screen.getByText("notification.response")).toBeInTheDocument();
    expect(screen.getByText("itsm.servicenow")).toBeInTheDocument();
  });

  it("runs a served NHI right-size remediation playbook", async () => {
    const user = userEvent.setup();
    renderIncidents();

    expect(await screen.findByRole("heading", { name: "Automated remediation playbooks" })).toBeInTheDocument();
    expect(screen.getByText("Right-size NHI grants")).toBeInTheDocument();
    expect(await screen.findByText("dddddddd-dddd-dddd-dddd-dddddddddddd")).toBeInTheDocument();

    await user.type(screen.getByLabelText("Target identity"), "11111111-1111-1111-1111-111111111111");
    await user.clear(screen.getByLabelText("Playbook delivery method"));
    await user.type(screen.getByLabelText("Playbook delivery method"), "aws-iam");
    await user.type(screen.getByLabelText("Provider target"), "arn:aws:iam::123456789012:role/payments-bot");
    await user.type(screen.getByLabelText("Remove scopes"), "secrets:write");
    await user.type(screen.getByLabelText("Playbook rollback instructions"), "restore iam policy version v17");
    await user.click(screen.getByRole("button", { name: "Run right-size" }));

    await waitFor(() =>
      expect(apiMock.runRemediationPlaybook).toHaveBeenCalledWith("nhi-right-size", {
        target_identity_id: "11111111-1111-1111-1111-111111111111",
        inventory_id: "",
        reason: "right-size unused grants",
        connector: "aws-iam",
        target: "arn:aws:iam::123456789012:role/payments-bot",
        remove_scopes: ["secrets:write"],
        recommended_scopes: [],
        rollback_ref: "restore iam policy version v17",
      }),
    );
    expect(await screen.findByText("Playbook run recorded")).toBeInTheDocument();
    expect(screen.getAllByText("connector.right_size").length).toBeGreaterThan(0);
  });

  it("accepts a served owner self-remediation action", async () => {
    const user = userEvent.setup();
    renderIncidents();

    expect(await screen.findByRole("heading", { name: "Owner self-remediation" })).toBeInTheDocument();
    expect(screen.getByText("payments-owner-bot")).toBeInTheDocument();
    expect(screen.getByText("1 open / 0 accepted")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Accept" }));

    await waitFor(() =>
      expect(apiMock.acceptOwnerRemediationAction).toHaveBeenCalledWith(ownerAction.id, {
        reason: "owner accepted least-privilege right-size remediation",
        connector: "aws-iam",
        target: "arn:aws:iam::123456789012:role/payments-bot",
        remove_scopes: ["admin:*", "secrets:write"],
        recommended_scopes: ["secrets:read"],
        rollback_ref: "restore prior grants admin:*,secrets:write",
      }),
    );
    expect(await screen.findByText("Owner remediation recorded")).toBeInTheDocument();
    expect(screen.getByText("0 open / 1 accepted")).toBeInTheDocument();
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
