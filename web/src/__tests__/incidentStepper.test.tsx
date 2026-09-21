import { describe, expect, it } from "vitest";
import { incidentSteps } from "@/pages/incidents/IncidentsPageParts";
import type { IncidentExecution } from "@/lib/api";

function execution(overrides: Partial<IncidentExecution> = {}): IncidentExecution {
  return {
    id: "exec-1",
    tenant_id: "tenant-1",
    compromised_identity_id: "id-1",
    status: "running",
    phase: "",
    failed_targets: [],
    rollback_refs: [],
    created_at: "2026-07-26T00:00:00Z",
    updated_at: "2026-07-26T00:00:00Z",
    blast_radius: { edges: [], nodes: [] },
    ...overrides,
  } as IncidentExecution;
}

function stateOf(steps: ReturnType<typeof incidentSteps>, id: string) {
  return steps.find((step) => step.id === id)?.state;
}

// S-C17: each step is decided by a concrete field on the served record, so
// the stepper can never drift from what actually happened.
describe("incident remediation stepper", () => {
  it("starts every step pending on a fresh execution", () => {
    expect(incidentSteps(execution()).map((step) => step.state)).toEqual(["pending", "pending", "pending", "pending"]);
  });

  it("marks issuance done from the replacement identity, not from the phase text", () => {
    const steps = incidentSteps(execution({ replacement_identity_id: "id-2" }));
    expect(stateOf(steps, "issued")).toBe("done");
    expect(stateOf(steps, "deployed")).toBe("pending");
  });

  it("reads deployment and revocation out of the compound phase string", () => {
    const steps = incidentSteps(execution({ replacement_identity_id: "id-2", phase: "replacement_deployed_and_compromised_revoked", status: "succeeded" }));
    expect(stateOf(steps, "deployed")).toBe("done");
    expect(stateOf(steps, "revoked")).toBe("done");
  });

  it("accepts the fleet re-issuance phase as deployment", () => {
    const steps = incidentSteps(execution({ phase: "fleet_reissued_and_compromised_revoked" }));
    expect(stateOf(steps, "deployed")).toBe("done");
    expect(stateOf(steps, "revoked")).toBe("done");
  });

  it("honors the dedicated revocation status when the phase does not say so", () => {
    const steps = incidentSteps(execution({ revocation_status: "revoked" }));
    expect(stateOf(steps, "revoked")).toBe("done");
  });

  it("marks the sealed evidence bundle done", () => {
    const steps = incidentSteps(execution({ evidence_bundle: "bundle://exec-1" }));
    expect(stateOf(steps, "evidence")).toBe("done");
  });

  it("shows unreached steps as failed — not merely pending — once the run failed", () => {
    const steps = incidentSteps(execution({ status: "failed", replacement_identity_id: "id-2" }));
    expect(stateOf(steps, "issued")).toBe("done");
    expect(stateOf(steps, "deployed")).toBe("failed");
    expect(stateOf(steps, "evidence")).toBe("failed");
  });

  it("treats failed targets as a failure even when the status has not caught up", () => {
    const steps = incidentSteps(execution({ failed_targets: ["node-a"] }));
    expect(stateOf(steps, "deployed")).toBe("failed");
  });
});
