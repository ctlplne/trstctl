import type { ReactNode } from "react";
import { StatusBadge } from "@/components/StatusBadge";
import { translateNow, useTranslation } from "@/i18n/I18nProvider";
import type { FleetReissuanceRun, IncidentExecution } from "@/lib/api";
import { humanizeStatus } from "@/lib/statusVocab";

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

/** Exact response proof stays collapsed until an expert asks for it. Missing
 * approval or recovery fields are named as missing; the UI never fills gaps
 * with an optimistic status. */
export function IncidentExecutionProof({ execution }: { execution: IncidentExecution }) {
  const { t, formatDateTime } = useTranslation();
  const deliveryState = execution.connector_delivery?.status ?? execution.connector_delivery_id ?? t("incidents.proof.notRecorded");
  const approvalState = execution.created_by
    ? t("incidents.proof.approvalMissingWithActor", { actor: execution.created_by })
    : t("incidents.proof.approvalMissing");

  return (
    <details className="group overflow-hidden rounded-panel border border-border bg-card">
      <summary className="flex cursor-pointer list-none flex-wrap items-center justify-between gap-2 px-4 py-3 marker:hidden hover:bg-muted/40">
        <span className="font-medium">{t("incidents.proof.open")}</span>
        <span className="font-mono text-xs text-muted-foreground">{execution.id}</span>
      </summary>
      <div className="grid gap-4 border-t border-border p-4">
        <IncidentStepper execution={execution} />
        <div className="grid gap-4 xl:grid-cols-3">
          <section aria-labelledby={`incident-proof-timeline-${execution.id}`} className="rounded-panel border border-border bg-background p-3">
            <h4 id={`incident-proof-timeline-${execution.id}`} className="font-semibold">
              {t("incidents.proof.timeline")}
            </h4>
            <dl className="mt-3 grid gap-2 text-sm">
              <ProofRow label={t("incidents.proof.created")}>{formatDateTime(execution.created_at)}</ProofRow>
              <ProofRow label={t("incidents.proof.updated")}>{formatDateTime(execution.updated_at)}</ProofRow>
              <ProofRow label={t("incidents.proof.status")}>{execution.status}</ProofRow>
              <ProofRow label={t("incidents.proof.phase")}>{execution.phase || t("incidents.proof.notRecorded")}</ProofRow>
            </dl>
          </section>
          <section aria-labelledby={`incident-proof-evidence-${execution.id}`} className="rounded-panel border border-border bg-background p-3">
            <h4 id={`incident-proof-evidence-${execution.id}`} className="font-semibold">
              {t("incidents.proof.evidenceApprovals")}
            </h4>
            <dl className="mt-3 grid gap-2 text-sm">
              <ProofRow label={t("incidents.proof.executionID")} mono>
                {execution.id}
              </ProofRow>
              <ProofRow label={t("incidents.proof.idempotencyKey")} mono>
                {execution.idempotency_key || t("incidents.proof.notRecorded")}
              </ProofRow>
              <ProofRow label={t("incidents.proof.evidenceFormat")}>{execution.evidence_bundle_format || t("incidents.proof.notRecorded")}</ProofRow>
              <ProofRow label={t("incidents.proof.evidenceBundle")} mono>
                {execution.evidence_bundle || t("incidents.proof.notRecorded")}
              </ProofRow>
              <ProofRow label={t("incidents.proof.approvals")}>{approvalState}</ProofRow>
            </dl>
          </section>
          <section aria-labelledby={`incident-proof-recovery-${execution.id}`} className="rounded-panel border border-border bg-background p-3">
            <h4 id={`incident-proof-recovery-${execution.id}`} className="font-semibold">
              {t("incidents.proof.replacementRecovery")}
            </h4>
            <dl className="mt-3 grid gap-2 text-sm">
              <ProofRow label={t("incidents.proof.replacementIdentity")} mono>
                {execution.replacement_identity_id || t("incidents.proof.notRecorded")}
              </ProofRow>
              <ProofRow label={t("incidents.proof.revocation")}>{execution.revocation_status || t("incidents.proof.notRecorded")}</ProofRow>
              <ProofRow label={t("incidents.proof.delivery")}>{deliveryState}</ProofRow>
              <ProofRow label={t("incidents.proof.failedTargets")}>{execution.failed_targets.join(", ") || t("incidents.proof.none")}</ProofRow>
              <ProofRow label={t("incidents.proof.rollbackReferences")}>{execution.rollback_refs.join(", ") || t("incidents.proof.none")}</ProofRow>
            </dl>
          </section>
        </div>
      </div>
    </details>
  );
}

function ProofRow({ label, mono = false, children }: { label: string; mono?: boolean; children: ReactNode }) {
  return (
    <div>
      <dt className="text-xs font-medium text-muted-foreground">{label}</dt>
      <dd className={mono ? "break-all font-mono text-xs" : "break-words"}>{children}</dd>
    </div>
  );
}

/** Severity read as a badge rather than lowercase prose, so a critical row is
 * visible in a scan of the remediation table. */
export function IncidentSeverityBadge({ severity }: { severity: string }) {
  const value = (severity || "unknown").toLowerCase();
  const tone = value === "critical" ? "critical" : value === "high" ? "critical" : value === "warning" || value === "medium" ? "warning" : "neutral";
  return <StatusBadge vocabulary="risk" value={value} label={severity || "unknown"} tone={tone} />;
}

/** IncidentSituationSummary answers the three questions an incident commander
 * needs before the workspace exposes forms and evidence tables. It summarizes
 * only served records; missing evidence stays explicit instead of being guessed. */
export function IncidentSituationSummary({
  executions,
  fleetRuns,
  loading,
  error,
}: {
  executions: IncidentExecution[];
  fleetRuns: FleetReissuanceRun[];
  loading: boolean;
  error: string | null;
}) {
  const { t } = useTranslation();
  const latestExecution = executions[0];
  const latestFleetRun = fleetRuns[0];

  let happening = t("incidents.situation.happeningEmpty");
  let affected = t("incidents.situation.affectedEmpty");
  let containment = t("incidents.situation.containmentEmpty");

  if (loading) {
    happening = t("incidents.situation.loading");
    affected = t("incidents.situation.waitingForEvidence");
    containment = t("incidents.situation.waitingForEvidence");
  } else if (error) {
    happening = t("incidents.situation.loadFailed");
    affected = t("incidents.situation.evidenceUnavailable");
    containment = t("incidents.situation.retryBeforeActing");
  } else if (latestExecution) {
    const failedTargets = latestExecution.failed_targets?.length ?? 0;
    const executionFailed = latestExecution.status.toLowerCase() === "failed";
    const affectedItems = latestExecution.blast_radius?.affected?.length ?? 0;
    const affectedName = latestExecution.blast_radius?.node?.name || t("incidents.situation.compromisedCredential");
    happening =
      failedTargets > 0
        ? t(failedTargets === 1 ? "incidents.situation.happeningFailedOne" : "incidents.situation.happeningFailedMany", {
            credential: affectedName,
            count: failedTargets,
          })
        : executionFailed
          ? t("incidents.situation.happeningFailedStatus", { credential: affectedName })
          : t("incidents.situation.happeningRecorded", {
              credential: affectedName,
              status: humanizeStatus(latestExecution.status),
            });
    affected = t(affectedItems === 1 ? "incidents.situation.affectedRecordedOne" : "incidents.situation.affectedRecordedMany", {
      credential: affectedName,
      count: affectedItems,
    });

    const steps = incidentSteps(latestExecution);
    const replacementIssued = steps.find((step) => step.id === "issued")?.state === "done";
    const replacementDeployed = steps.find((step) => step.id === "deployed")?.state === "done";
    const compromisedRevoked = steps.find((step) => step.id === "revoked")?.state === "done";
    const evidenceSealed = steps.find((step) => step.id === "evidence")?.state === "done";
    if (failedTargets > 0) {
      containment = t(failedTargets === 1 ? "incidents.situation.containmentFailedTargetOne" : "incidents.situation.containmentFailedTargetMany", {
        count: failedTargets,
      });
    } else if (executionFailed) containment = t("incidents.situation.containmentReviewFailure");
    else if (!replacementIssued) containment = t("incidents.situation.containmentPlanReplacement");
    else if (!replacementDeployed) containment = t("incidents.situation.containmentDeployReplacement");
    else if (!compromisedRevoked) containment = t("incidents.situation.containmentRevokeCompromised");
    else if (!evidenceSealed) containment = t("incidents.situation.containmentSealEvidence");
    else containment = t("incidents.situation.containmentVerifyRecovery");
  } else if (latestFleetRun) {
    const affectedCredentials = latestFleetRun.affected_identity_ids.length;
    const failedTargets = latestFleetRun.failed_targets?.length ?? 0;
    const fleetStopped = ["failed", "halted", "rolled_back"].includes(latestFleetRun.status.toLowerCase());
    happening = t(affectedCredentials === 1 ? "incidents.situation.fleetRecordedOne" : "incidents.situation.fleetRecordedMany", {
      status: humanizeStatus(latestFleetRun.status),
      count: affectedCredentials,
    });
    affected = t(affectedCredentials === 1 ? "incidents.situation.fleetAffectedOne" : "incidents.situation.fleetAffectedMany", {
      count: affectedCredentials,
    });
    containment =
      failedTargets > 0
        ? t(failedTargets === 1 ? "incidents.situation.containmentFailedTargetOne" : "incidents.situation.containmentFailedTargetMany", {
            count: failedTargets,
          })
        : fleetStopped
          ? t("incidents.situation.containmentFleetStopped")
          : t("incidents.situation.containmentContinueFleet");
  }

  return (
    <section aria-labelledby="incident-situation-heading" className="ui-panel grid gap-4 p-comfortable">
      <div>
        <h2 id="incident-situation-heading" className="text-title font-semibold">
          {t("incidents.situation.title")}
        </h2>
        <p className="mt-1 text-sm text-muted-foreground">{t("incidents.situation.description")}</p>
      </div>
      <div className="grid gap-3 lg:grid-cols-3">
        <article className="rounded-panel border border-border bg-background p-4">
          <h3 className="text-body font-semibold">{t("incidents.situation.happening")}</h3>
          <p className="mt-2 text-sm text-muted-foreground">{happening}</p>
        </article>
        <article className="rounded-panel border border-border bg-background p-4">
          <h3 className="text-body font-semibold">{t("incidents.situation.affected")}</h3>
          <p className="mt-2 text-sm text-muted-foreground">{affected}</p>
        </article>
        <article className="rounded-panel border border-border bg-background p-4">
          <h3 className="text-body font-semibold">{t("incidents.situation.containment")}</h3>
          <p className="mt-2 text-sm text-muted-foreground">{containment}</p>
        </article>
      </div>
    </section>
  );
}
