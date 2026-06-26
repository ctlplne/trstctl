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

describe("POL-02 incident polish", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    apiMock.graphBlastRadius.mockReset().mockResolvedValue(blastRadius);
    apiMock.incidentExecutions.mockReset().mockResolvedValue({ items: [] });
    apiMock.executeIncident.mockReset().mockResolvedValue(execution);
  });

  it("uses operator-facing form labels, marks fleet rows as examples, and moves break-glass to help", async () => {
    const user = userEvent.setup();
    renderIncidents();

    expect(await screen.findByRole("heading", { name: "Incidents" })).toBeInTheDocument();
    expect(screen.getByLabelText("Affected identity")).toBeInTheDocument();
    expect(screen.getByLabelText("What happened")).toBeInTheDocument();
    expect(screen.getByLabelText("Replacement identity name")).toBeInTheDocument();
    expect(screen.getByLabelText("Delivery method")).toBeInTheDocument();
    expect(screen.getByLabelText("Deployment target")).toBeInTheDocument();
    expect(screen.getByLabelText("Rollback instructions")).toBeInTheDocument();
    expect(screen.queryByLabelText("Connector")).not.toBeInTheDocument();
    expect(screen.queryByLabelText("Target")).not.toBeInTheDocument();
    expect(screen.queryByLabelText("Rollback reference")).not.toBeInTheDocument();

    const exampleTable = screen.getByRole("table", { name: "Example fleet reissuance plan" });
    expect(within(exampleTable).getByText("Wave 0")).toBeInTheDocument();
    expect(screen.getByText(/Example planning data/i)).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Break-glass procedures" })).not.toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Break-glass help" }));
    const dialog = screen.getByRole("dialog", { name: "Break-glass help" });
    expect(within(dialog).getByText(/quorum approval/i)).toBeInTheDocument();
    expect(within(dialog).getByText(/post-incident checklist/i)).toBeInTheDocument();

    await user.type(screen.getByLabelText("Affected identity"), "11111111-1111-1111-1111-111111111111");
    await user.clear(screen.getByLabelText("What happened"));
    await user.type(screen.getByLabelText("What happened"), "key export detected");
    await user.type(screen.getByLabelText("Deployment target"), "edge/prod/payments");
    await user.type(screen.getByLabelText("Rollback instructions"), "restore previous binding");
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
