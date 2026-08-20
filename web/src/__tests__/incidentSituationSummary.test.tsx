import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import type { FleetReissuanceRun, IncidentExecution } from "@/lib/api";
import { IncidentSituationSummary } from "@/pages/incidents/IncidentsPageParts";

function execution(overrides: Partial<IncidentExecution> = {}): IncidentExecution {
  return {
    id: "response-1",
    tenant_id: "tenant-1",
    compromised_identity_id: "credential-1",
    status: "running",
    phase: "",
    failed_targets: [],
    rollback_refs: [],
    created_at: "2026-08-20T12:00:00Z",
    updated_at: "2026-08-20T12:00:00Z",
    blast_radius: {
      node: { id: "credential-1", kind: "credential", name: "Payments certificate" },
      affected: [{ id: "workload-1", kind: "workload", name: "Payments API" }],
      by_kind: { workload: 1 },
    },
    ...overrides,
  };
}

function fleetRun(overrides: Partial<FleetReissuanceRun> = {}): FleetReissuanceRun {
  return {
    id: "fleet-1",
    tenant_id: "tenant-1",
    issuer_id: "issuer-1",
    mode: "live",
    status: "running",
    phase: "canary",
    affected_identity_ids: ["credential-1"],
    replacement_identity_ids: [],
    revoked_identity_ids: [],
    exact_trust_hosts: [],
    exact_trust_store_ids: [],
    candidate_trust_hosts: [],
    candidate_trust_store_ids: [],
    batches: [],
    batch_count: 1,
    batch_size: 1,
    next_batch_index: 0,
    graph_impact: {
      node: { id: "issuer-1", kind: "issuer", name: "Issuing CA" },
      affected: [],
      by_kind: {},
    },
    health_gates: [],
    rollback_refs: [],
    created_at: "2026-08-20T12:00:00Z",
    updated_at: "2026-08-20T12:00:00Z",
    ...overrides,
  };
}

function renderSummary({
  executions = [],
  fleetRuns = [],
  loading = false,
  error = null,
}: {
  executions?: IncidentExecution[];
  fleetRuns?: FleetReissuanceRun[];
  loading?: boolean;
  error?: string | null;
} = {}) {
  return render(<IncidentSituationSummary executions={executions} fleetRuns={fleetRuns} loading={loading} error={error} />);
}

describe("incident situation summary", () => {
  it("does not claim a situation while evidence is loading", () => {
    renderSummary({ loading: true, executions: [execution()] });

    expect(screen.getByText("Checking the incident record now.")).toBeInTheDocument();
    expect(screen.getAllByText("Waiting for evidence before making a claim.")).toHaveLength(2);
    expect(screen.queryByText(/latest response/i)).not.toBeInTheDocument();
  });

  it("fails closed when the evidence read fails", () => {
    renderSummary({ error: "request failed" });

    expect(screen.getByText("Incident evidence could not be loaded.")).toBeInTheDocument();
    expect(screen.getByText("The affected scope is unknown because the evidence read failed.")).toBeInTheDocument();
    expect(screen.getByText("Retry the evidence read before changing a credential.")).toBeInTheDocument();
  });

  it("states the empty situation and the safe first step", () => {
    renderSummary();

    expect(screen.getByText("No incident response is active.")).toBeInTheDocument();
    expect(screen.getByText("Nothing is currently marked affected.")).toBeInTheDocument();
    expect(screen.getByText(/plan replacement before revocation/i)).toBeInTheDocument();
  });

  it("summarizes a completed individual response with singular grammar", () => {
    renderSummary({
      executions: [
        execution({
          status: "executed",
          phase: "replacement_deployed_and_compromised_revoked",
          replacement_identity_id: "credential-2",
          evidence_bundle: "sealed-bundle",
        }),
      ],
    });

    expect(screen.getByText("The latest response for Payments certificate is Executed.")).toBeInTheDocument();
    expect(screen.getByText("Payments certificate has one connected item in the recorded affected scope.")).toBeInTheDocument();
    expect(screen.getByText(/verify recovery and close temporary access/i)).toBeInTheDocument();
  });

  it("does not invent target failures when only the execution status failed", () => {
    renderSummary({ executions: [execution({ status: "failed" })] });

    expect(screen.getByText("The response for Payments certificate failed; no failed delivery target was recorded.")).toBeInTheDocument();
    expect(screen.getByText("Review the failure evidence and recovery state before changing another credential.")).toBeInTheDocument();
  });

  it("uses singular failed-target guidance", () => {
    renderSummary({ executions: [execution({ status: "failed", failed_targets: ["edge-1"] })] });

    expect(screen.getByText("The response for Payments certificate needs attention; one delivery target failed.")).toBeInTheDocument();
    expect(screen.getByText("Review and recover the failed delivery target before continuing.")).toBeInTheDocument();
  });

  it("stops normal continuation after a fleet rollback", () => {
    renderSummary({ fleetRuns: [fleetRun({ status: "rolled_back" })] });

    expect(screen.getByText("The latest fleet response has status Rolled Back and covers one credential.")).toBeInTheDocument();
    expect(screen.getByText("The fleet plan names one affected credential.")).toBeInTheDocument();
    expect(screen.getByText("Review the fleet halt or rollback evidence before deciding whether to resume.")).toBeInTheDocument();
  });

  it("uses plural fleet language when multiple credentials are affected", () => {
    renderSummary({ fleetRuns: [fleetRun({ affected_identity_ids: ["credential-1", "credential-2"] })] });

    expect(screen.getByText("The latest fleet response has status Running and covers 2 credentials.")).toBeInTheDocument();
    expect(screen.getByText("The fleet plan names 2 affected credentials.")).toBeInTheDocument();
    expect(screen.getByText(/verify each cohort before revocation/i)).toBeInTheDocument();
  });
});
