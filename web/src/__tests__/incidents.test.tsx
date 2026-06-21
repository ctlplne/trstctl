import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { ApiError } from "@/lib/api";
import { Incidents } from "@/pages/Incidents";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    graphBlastRadius: vi.fn(),
    incidentExecutions: vi.fn(),
    executeIncident: vi.fn(),
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
  });

  it("loads execution evidence and runs served replacement-before-revoke remediation", async () => {
    const user = userEvent.setup();
    renderIncidents();

    expect(screen.getByRole("heading", { name: "Incidents" })).toBeInTheDocument();
    expect(await screen.findByRole("heading", { name: "Execution evidence" })).toBeInTheDocument();
    expect(await screen.findByText("22222222-2222-2222-2222-222222222222")).toBeInTheDocument();
    expect(screen.queryByText(/Incident execution is not served/i)).not.toBeInTheDocument();

    await user.type(screen.getByLabelText("Compromised identity ID"), "11111111-1111-1111-1111-111111111111");
    await user.clear(screen.getByLabelText("Reason"));
    await user.type(screen.getByLabelText("Reason"), "key export detected");
    await user.type(screen.getByLabelText("Target"), "edge/prod/payments");
    await user.type(screen.getByLabelText("Rollback reference"), "restore previous fullchain");
    await user.click(screen.getByRole("button", { name: "Preview blast radius" }));

    await waitFor(() =>
      expect(apiMock.graphBlastRadius).toHaveBeenCalledWith("id:11111111-1111-1111-1111-111111111111"),
    );
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
    expect(await screen.findByText("nginx:edge/prod/payments:unrouted")).toBeInTheDocument();
    expect(screen.getByText("jws")).toBeInTheDocument();
    expect(screen.getByText("sealed.audit.bundle")).toBeInTheDocument();
  });

  it("renders fleet and break-glass sections with error state for unavailable graph preview", async () => {
    apiMock.graphBlastRadius.mockRejectedValueOnce(
      new ApiError(503, JSON.stringify({ detail: "graph projection is rebuilding" })),
    );
    const user = userEvent.setup();
    renderIncidents();

    await user.type(await screen.findByLabelText("Compromised identity ID"), "11111111-1111-1111-1111-111111111111");
    await user.click(screen.getByRole("button", { name: "Preview blast radius" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("graph projection is rebuilding");
    expect(screen.getByRole("heading", { name: "Fleet re-issuance for CA compromise" })).toBeInTheDocument();
    expect(screen.getByText("Wave 0")).toBeInTheDocument();
    expect(screen.getByText("48 percent complete")).toBeInTheDocument();
    expect(screen.getByText("2 failed targets")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Break-glass procedures" })).toBeInTheDocument();
    expect(screen.getByText(/emergency declaration/i)).toBeInTheDocument();
    expect(screen.getByText(/quorum approval/i)).toBeInTheDocument();
    expect(screen.getAllByText(/offline issue/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/post-incident checklist/i).length).toBeGreaterThan(0);
  });
});
