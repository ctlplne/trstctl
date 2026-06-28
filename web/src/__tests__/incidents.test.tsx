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

describe("incident response served execution surface", () => {
  beforeEach(() => {
    apiMock.graphBlastRadius.mockReset().mockResolvedValue(impact);
    apiMock.incidentExecutions.mockReset().mockResolvedValue({ items: [execution] });
    apiMock.executeIncident.mockReset().mockResolvedValue(execution);
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
    await user.clear(screen.getByLabelText("What happened"));
    await user.type(screen.getByLabelText("What happened"), "key export detected");
    await user.type(screen.getByLabelText("Deployment target"), "edge/prod/payments");
    await user.type(screen.getByLabelText("Rollback instructions"), "restore previous fullchain");
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
    expect(screen.getByText("jws")).toBeInTheDocument();
    expect(screen.getByText("sealed.audit.bundle")).toBeInTheDocument();

    await user.type(screen.getByLabelText("ServiceNow instance"), "http://servicenow.test");
    await user.type(screen.getByLabelText("Ticket summary"), "Rotate exposed TLS private key");
    await user.click(screen.getByRole("button", { name: "Queue ServiceNow ticket" }));

    await waitFor(() =>
      expect(apiMock.createServiceNowTicket).toHaveBeenCalledWith({
        instance_url: "http://servicenow.test",
        table: "incident",
        token_ref: "env:TRSTCTL_SERVICENOW_TOKEN",
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

  it("renders fleet and break-glass sections with error state for unavailable graph preview", async () => {
    apiMock.graphBlastRadius.mockRejectedValueOnce(new ApiError(503, JSON.stringify({ detail: "graph projection is rebuilding" })));
    const user = userEvent.setup();
    renderIncidents();

    await user.type(await screen.findByLabelText("Affected identity"), "11111111-1111-1111-1111-111111111111");
    await user.click(screen.getByRole("button", { name: "Preview blast radius" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("graph projection is rebuilding");
    expect(screen.getByRole("heading", { name: "Example fleet re-issuance plan" })).toBeInTheDocument();
    expect(screen.getByText(/Example planning data/i)).toBeInTheDocument();
    expect(screen.getByText("Wave 0")).toBeInTheDocument();
    expect(screen.getByText("48 percent complete")).toBeInTheDocument();
    expect(screen.getByText("2 failed targets")).toBeInTheDocument();
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
