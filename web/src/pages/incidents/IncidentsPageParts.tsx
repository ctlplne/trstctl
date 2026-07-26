import { StatusBadge } from "@/components/StatusBadge";
import { translateNow } from "@/i18n/I18nProvider";
import type { IncidentExecution } from "@/lib/api";

// S-C17 (extracted per R-09 before editing the Incidents monolith): a
// compromise execution reported a bare `phase` string like
// "replacement_deployed_and_compromised_revoked", which is precise for a log
// and unreadable as progress. The steps below are NOT a guessed ordering of
// that string — each one is decided by a concrete field the served execution
// carries, so the stepper cannot drift from the record.

export type IncidentStepState = "done" | "pending" | "failed";
export type IncidentStep = { id: "issued" | "deployed" | "revoked" | "evidence"; state: IncidentStepState };

export function incidentSteps(execution: IncidentExecution): IncidentStep[] {
  const phase = (execution.phase ?? "").toLowerCase();
  const status = (execution.status ?? "").toLowerCase();
  const failed = status === "failed" || (execution.failed_targets?.length ?? 0) > 0;

  // Replacement issued: the record names the successor identity.
  const issued = Boolean(execution.replacement_identity_id || execution.replacement_identity);
  // Deployed: the phase says so (it is the only place delivery is recorded).
  const deployed = phase.includes("deployed") || phase.includes("fleet_reissued");
  // Revoked: either the phase or the dedicated revocation status says so.
  const revoked = phase.includes("revoked") || (execution.revocation_status ?? "").toLowerCase() === "revoked";
  // Evidence: a sealed bundle exists.
  const evidence = Boolean(execution.evidence_bundle);

  const state = (done: boolean): IncidentStepState => (done ? "done" : failed ? "failed" : "pending");
  return [
    { id: "issued", state: state(issued) },
    { id: "deployed", state: state(deployed) },
    { id: "revoked", state: state(revoked) },
    { id: "evidence", state: state(evidence) },
  ];
}

const stepLabelKeys = {
  issued: "incidents.step.issued",
  deployed: "incidents.step.deployed",
  revoked: "incidents.step.revoked",
  evidence: "incidents.step.evidence",
} as const;

export function IncidentStepper({ execution }: { execution: IncidentExecution }) {
  const steps = incidentSteps(execution);
  return (
    <ol className="flex flex-wrap items-center gap-2" aria-label={translateNow("incidents.step.stepperLabel")}>
      {steps.map((step, index) => (
        <li key={step.id} className="flex items-center gap-2">
          {index > 0 ? (
            <span aria-hidden="true" className="text-muted-foreground">
              →
            </span>
          ) : null}
          <StatusBadge
            vocabulary="lifecycle"
            value={step.state === "done" ? "completed" : step.state}
            label={translateNow(stepLabelKeys[step.id])}
            tone={step.state === "done" ? "success" : step.state === "failed" ? "critical" : "neutral"}
          />
        </li>
      ))}
    </ol>
  );
}

/** Severity read as a badge rather than lowercase prose, so a critical row is
 * visible in a scan of the remediation table. */
export function IncidentSeverityBadge({ severity }: { severity: string }) {
  const value = (severity || "unknown").toLowerCase();
  const tone = value === "critical" ? "critical" : value === "high" ? "critical" : value === "warning" || value === "medium" ? "warning" : "neutral";
  return <StatusBadge vocabulary="risk" value={value} label={severity || "unknown"} tone={tone} />;
}
