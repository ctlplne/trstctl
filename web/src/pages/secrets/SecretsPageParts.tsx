import { useState, type ReactNode } from "react";
import { Copy, Loader2, PlayCircle, ShieldCheck, X } from "lucide-react";
import { ErrorState } from "@/components/StatePrimitives";
import { Button } from "@/components/ui/button";
import { useTranslation, translateNow } from "@/i18n/I18nProvider";
import { formatDateTime as formatDateTimePolicy } from "@/i18n/format";
import {
  ApiError,
  type DynamicLease,
  type MachineLoginResponse,
  type SecretApprovalAction,
  type SecretMeta,
  type SecretRepositoryScanPosture,
  type SecretRotationDueRun,
  type SecretRotationSchedule,
  type ThirdPartySecretScanPosture,
} from "@/lib/api";
import { StatusBadge } from "@/components/StatusBadge";

export type SecretApprovalQueueItem = {
  id: string;
  name: string;
  action: SecretApprovalAction;
  openedAt: string;
  status: "pending" | "approved" | "completed";
  approvals?: number;
  approver?: string;
  error?: string;
};

type Translate = ReturnType<typeof useTranslation>["t"];

export type SecretRotationDeferredEvidence = {
  schedule_id: string;
  reason: "approval_pending" | "command_in_flight" | "command_claimed" | "config_revision_unanchored";
  due_at: string;
  error?: string;
};

export const secretRotationDeferredReasonKeys = {
  approval_pending: "secrets.rotation.deferredReason.approvalPending",
  command_in_flight: "secrets.rotation.deferredReason.commandInFlight",
  command_claimed: "secrets.rotation.deferredReason.commandClaimed",
  config_revision_unanchored: "secrets.rotation.deferredReason.configRevisionUnanchored",
} as const;

const secretRotationDeferredReasons = new Set<SecretRotationDeferredEvidence["reason"]>([
  "approval_pending",
  "command_in_flight",
  "command_claimed",
  "config_revision_unanchored",
]);

const secretRotationTickSystemErrors = new Set([
  "scheduler operation was interrupted; retry this tick",
  "scheduler processing failed; retry this tick and inspect server logs",
  "scheduler tick lease expired before durable completion; the exact tick was terminalized as indeterminate and a new Idempotency-Key is required",
]);

const secretRotationDeferredErrors: Record<SecretRotationDeferredEvidence["reason"], string> = {
  approval_pending: "scheduled rotation is waiting for approval",
  command_in_flight: "scheduled rotation command is already in progress",
  command_claimed: "scheduled rotation command is already in progress",
  config_revision_unanchored: "schedule configuration must be re-saved before it can run",
};

const secretRotationGenericTerminalErrors = new Set([
  "application-secret approval is no longer usable",
  "no such secret",
  "resource not found",
  "approval requester cannot approve their own request",
  "approval request expired",
  "approval request superseded",
  "approval authority already consumed",
  "approval target version or state drifted",
  "approval request has not reached quorum",
  "connector rotation target is required",
  "secret sync target is not configured",
  "connector rotation old_ref must be version:<n>",
  "connector rotation old_ref does not name the current version",
  "scheduled rotation failed",
]);

const secretRotationUnsupportedErrors = new Set([
  "dynamic-lease rotation is unavailable until its issue, delivery, and predecessor retirement phases share one durable worker command",
  "scheduled static-provider rotation is unavailable until a durable worker owns stage, cutover, verification, rollback, and retirement",
  "scheduled rotation is unavailable",
]);

function recordValue(candidate: unknown): candidate is Record<string, unknown> {
  return candidate !== null && typeof candidate === "object" && !Array.isArray(candidate);
}

function secretRotationRunErrorIsClosed(status: unknown, detail: unknown): boolean {
  if (typeof status !== "string" || (detail !== undefined && typeof detail !== "string")) return false;
  if (detail === undefined || detail === "") return true;
  switch (status) {
    case "completed":
    case "queued":
      return false;
    case "delivery_failed":
      return detail === "connector delivery failed";
    case "rollback_failed":
      return detail === "scheduled rotation rollback failed";
    case "unsupported":
      return secretRotationUnsupportedErrors.has(detail);
    case "failed":
    case "rolled_back":
    case "retire_pending":
      return secretRotationGenericTerminalErrors.has(detail);
    default:
      return false;
  }
}

// The browser treats the API as an untrusted byte boundary too. This mirrors
// the server's closed durable vocabulary so a corrupted proxy/cache or an old
// retained receipt cannot turn provider text back into operator-visible copy.
export function secretRotationDueEvidenceHasClosedErrors(value: unknown): boolean {
  if (!recordValue(value) || !Array.isArray(value.runs) || !Array.isArray(value.deferred)) return false;
  if (
    value.system_error !== undefined &&
    (typeof value.system_error !== "string" || (value.system_error !== "" && !secretRotationTickSystemErrors.has(value.system_error)))
  ) {
    return false;
  }
  for (const candidate of value.runs) {
    if (!recordValue(candidate) || !recordValue(candidate.rotation)) return false;
    const runError = candidate.error ?? "";
    const rotationError = candidate.rotation.error ?? "";
    const rollbackError = candidate.rotation.rollback_error ?? "";
    if (
      !secretRotationRunErrorIsClosed(candidate.status, runError) ||
      !secretRotationRunErrorIsClosed(candidate.status, rotationError) ||
      runError !== rotationError ||
      (rollbackError !== "" && rollbackError !== "scheduled rotation rollback failed")
    ) {
      return false;
    }
  }
  for (const candidate of value.deferred) {
    if (!recordValue(candidate) || !secretRotationDeferredReasons.has(candidate.reason as SecretRotationDeferredEvidence["reason"])) {
      return false;
    }
    const detail = candidate.error ?? "";
    if (
      typeof detail !== "string" ||
      (detail !== "" && detail !== secretRotationDeferredErrors[candidate.reason as SecretRotationDeferredEvidence["reason"]])
    ) {
      return false;
    }
  }
  return true;
}

export type SecretRotationDueEvidence = SecretRotationDueRun & {
  scanned?: number;
  deferred?: SecretRotationDeferredEvidence[];
  run_limit_reached?: boolean;
  scan_limit_reached?: boolean;
  complete?: boolean;
  partial?: boolean;
  failed_schedule_id?: string;
  system_error?: string;
};

export type SecretRotationPartialReceipt = SecretRotationDueEvidence & {
  scanned: number;
  deferred: SecretRotationDeferredEvidence[];
  run_limit_reached: boolean;
  scan_limit_reached: boolean;
  complete: false;
  partial: boolean;
  system_error: string;
};

const secretRotationScheduleRunStatuses = new Set([
  "completed",
  "queued",
  "failed",
  "rolled_back",
  "rollback_failed",
  "retire_pending",
  "delivery_failed",
  "unsupported",
]);
const secretRotationUUIDPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// R-09: scheduler receipt decoding lives with the extracted Secrets page parts,
// not in the monolith. A 503 is renderable evidence only when it is the exact,
// bounded scheduler envelope; generic problem bodies must clear the prior tick.
export function parseSecretRotationPartialReceipt(error: unknown): SecretRotationPartialReceipt | null {
  if (!(error instanceof ApiError) || error.status !== 503) return null;

  let value: unknown;
  try {
    value = JSON.parse(error.body);
  } catch {
    return null;
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;

  const receipt = value as Record<string, unknown>;
  const runs = receipt.runs;
  const deferred = receipt.deferred;
  const ran = receipt.ran;
  const scanned = receipt.scanned;
  const systemError = receipt.system_error;
  if (
    typeof ran !== "number" ||
    !Number.isInteger(ran) ||
    ran < 0 ||
    ran > 50 ||
    typeof scanned !== "number" ||
    !Number.isInteger(scanned) ||
    scanned < 0 ||
    scanned > 500 ||
    !Array.isArray(runs) ||
    !Array.isArray(deferred) ||
    receipt.complete !== false ||
    typeof receipt.partial !== "boolean" ||
    typeof receipt.run_limit_reached !== "boolean" ||
    typeof receipt.scan_limit_reached !== "boolean" ||
    typeof systemError !== "string" ||
    systemError.trim() === "" ||
    (receipt.failed_schedule_id !== undefined &&
      (typeof receipt.failed_schedule_id !== "string" || !secretRotationUUIDPattern.test(receipt.failed_schedule_id)))
  ) {
    return null;
  }

  const stringField = (record: Record<string, unknown>, key: string) => typeof record[key] === "string" && record[key] !== "";
  const optionalStringField = (record: Record<string, unknown>, key: string) => record[key] === undefined || typeof record[key] === "string";
  const timestampField = (record: Record<string, unknown>, key: string) => stringField(record, key) && !Number.isNaN(Date.parse(record[key] as string));
  const uuidField = (record: Record<string, unknown>, key: string) => typeof record[key] === "string" && secretRotationUUIDPattern.test(record[key] as string);
  const validRun = (candidate: unknown) => {
    if (!recordValue(candidate) || !recordValue(candidate.rotation)) return false;
    const rotation = candidate.rotation;
    return (
      uuidField(candidate, "schedule_id") &&
      uuidField(candidate, "run_id") &&
      stringField(candidate, "status") &&
      secretRotationScheduleRunStatuses.has(candidate.status as string) &&
      timestampField(candidate, "ran_at") &&
      typeof candidate.reconciled === "boolean" &&
      optionalStringField(candidate, "error") &&
      stringField(rotation, "key") &&
      stringField(rotation, "old_ref") &&
      typeof rotation.new_ref === "string" &&
      typeof rotation.completed === "boolean" &&
      typeof rotation.queued === "boolean" &&
      typeof rotation.rolled_back === "boolean" &&
      typeof rotation.rollback_attempted === "boolean" &&
      typeof rotation.rollback_failed === "boolean" &&
      optionalStringField(rotation, "rollback_error") &&
      optionalStringField(rotation, "failed_phase") &&
      optionalStringField(rotation, "error")
    );
  };
  const validDeferred = (candidate: unknown) =>
    recordValue(candidate) &&
    uuidField(candidate, "schedule_id") &&
    typeof candidate.reason === "string" &&
    secretRotationDeferredReasons.has(candidate.reason as SecretRotationDeferredEvidence["reason"]) &&
    timestampField(candidate, "due_at") &&
    optionalStringField(candidate, "error");

  if (
    runs.length !== ran ||
    scanned < runs.length + deferred.length ||
    receipt.partial !== (runs.length > 0 || deferred.length > 0) ||
    (receipt.run_limit_reached === true && ran !== 50) ||
    (receipt.scan_limit_reached === true && scanned !== 500) ||
    !runs.every(validRun) ||
    !deferred.every(validDeferred) ||
    !secretRotationDueEvidenceHasClosedErrors(receipt)
  ) {
    return null;
  }
  return receipt as unknown as SecretRotationPartialReceipt;
}

// S-C19 (extracted per R-09 before editing the Secrets monolith): rotation
// schedules showed a next-run timestamp, which means the operator has to do
// date arithmetic in their head to notice that a rotation never happened. The
// served schedule already carries everything needed to say it outright:
// enabled, next_run_at, last_run_at, last_run_status.

export type RotationHealth = {
  /** Overdue: enabled, its next run is in the past, and nothing has run since. */
  overdue: boolean;
  /** How far past due, in whole days (0 when not overdue). */
  overdueDays: number;
  /** Stale: enabled and the last successful run is older than two intervals. */
  stale: boolean;
  /** Never run at all — a schedule that exists but has produced nothing. */
  neverRun: boolean;
  /** The last run failed, which is why the next one may not have happened. */
  lastRunFailed: boolean;
};

const DAY_MS = 24 * 60 * 60 * 1000;

export function rotationHealth(schedule: SecretRotationSchedule, now: Date = new Date()): RotationHealth {
  const neverRun = !schedule.last_run_at;
  const lastRunStatus = (schedule.last_run_status ?? "").toLowerCase();
  const lastRunFailed = ["failed", "rolled_back", "delivery_failed", "rollback_failed", "retire_pending"].includes(lastRunStatus);
  if (!schedule.enabled) {
    // A disabled schedule is a deliberate operator choice, never a finding.
    return { overdue: false, overdueDays: 0, stale: false, neverRun, lastRunFailed };
  }
  const nextRun = Date.parse(schedule.next_run_at ?? "");
  const overdue = Number.isFinite(nextRun) && nextRun < now.getTime();
  const overdueDays = overdue ? Math.floor((now.getTime() - nextRun) / DAY_MS) : 0;

  const lastRun = Date.parse(schedule.last_run_at ?? "");
  // Two intervals of silence is the signal: one missed run can be a worker
  // hiccup, two means the schedule is not actually rotating anything.
  const staleAfterMs = Math.max(schedule.interval_seconds, 1) * 2 * 1000;
  const stale = Number.isFinite(lastRun) ? now.getTime() - lastRun > staleAfterMs : overdue;

  return { overdue, overdueDays, stale, neverRun, lastRunFailed };
}

export function RotationHealthBadges({ schedule, now }: { schedule: SecretRotationSchedule; now?: Date }) {
  const health = rotationHealth(schedule, now);
  if (!health.overdue && !health.stale && !health.neverRun && !health.lastRunFailed) {
    return <span className="text-caption text-muted-foreground">{translateNow("secrets.rotationHealth.onTrack")}</span>;
  }
  return (
    <div className="flex flex-wrap gap-1">
      {health.overdue ? (
        <StatusBadge
          vocabulary="lifecycle"
          value="overdue"
          label={
            health.overdueDays > 0
              ? translateNow("secrets.rotationHealth.overdueDays", { days: String(health.overdueDays) })
              : translateNow("secrets.rotationHealth.overdue")
          }
          tone="critical"
        />
      ) : null}
      {health.stale && !health.overdue ? (
        <StatusBadge vocabulary="lifecycle" value="stale" label={translateNow("secrets.rotationHealth.stale")} tone="warning" />
      ) : null}
      {health.neverRun ? <StatusBadge vocabulary="lifecycle" value="never_run" label={translateNow("secrets.rotationHealth.neverRun")} tone="warning" /> : null}
      {health.lastRunFailed ? (
        <StatusBadge vocabulary="lifecycle" value="failed" label={translateNow("secrets.rotationHealth.lastRunFailed")} tone="critical" />
      ) : null}
    </div>
  );
}

export function RevealPanel({ title, value, children, onDismiss }: { title: string; value: string; children: ReactNode; onDismiss: () => void }) {
  const [copied, setCopied] = useState(false);
  async function copyValue() {
    try {
      await navigator.clipboard?.writeText(value);
      setCopied(true);
    } catch {
      setCopied(true);
    }
  }
  return (
    <div className="ui-panel grid gap-3 p-3 text-sm">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <p className="font-medium">{title}</p>
          <p className="mt-1 text-muted-foreground">{children}</p>
        </div>
        <Button type="button" variant="ghost" size="sm" onClick={onDismiss}>
          <X className="h-4 w-4" aria-hidden="true" />
          {translateNow("source.dismiss.48845bff33")}
        </Button>
      </div>
      <pre className="max-h-56 overflow-auto whitespace-pre-wrap break-all rounded bg-muted px-3 py-2 font-mono text-xs">{value}</pre>
      <div className="flex flex-wrap items-center gap-2">
        <Button type="button" size="sm" variant="outline" onClick={() => void copyValue()}>
          <Copy className="h-4 w-4" aria-hidden="true" />
          {translateNow("source.copy.once.acfaa3d4d6")}
        </Button>
        {copied && <span className="text-xs text-muted-foreground">{translateNow("source.copied.from.this.reveal.panel.0707425cf6")}</span>}
      </div>
    </div>
  );
}

export function Snippet({ title, text }: { title: string; text: string }) {
  return (
    <div className="ui-panel grid gap-2 p-3 text-sm">
      <p className="font-medium">{title}</p>
      <pre className="overflow-x-auto whitespace-pre-wrap rounded bg-muted px-3 py-2 font-mono text-xs">{text}</pre>
    </div>
  );
}

export function MachineSession({ session }: { session: MachineLoginResponse }) {
  return (
    <dl className="ui-panel grid gap-2 p-3 text-sm md:grid-cols-2">
      <div>
        <dt className="font-medium text-muted-foreground">{translateNow("source.session.id.cb9ac5c561")}</dt>
        <dd className="break-all font-mono text-xs">{session.session_id}</dd>
      </div>
      <div>
        <dt className="font-medium text-muted-foreground">{translateNow("source.principal.afc19f1734")}</dt>
        <dd>{session.principal}</dd>
      </div>
      <div>
        <dt className="font-medium text-muted-foreground">{translateNow("source.method.52a0f9b65b")}</dt>
        <dd>{session.method}</dd>
      </div>
      <div>
        <dt className="font-medium text-muted-foreground">{translateNow("source.expires.f6725f3af0")}</dt>
        <dd>{formatDate(session.expires_at)}</dd>
      </div>
      <div className="md:col-span-2">
        <dt className="font-medium text-muted-foreground">{translateNow("source.scopes.0d5644ff52")}</dt>
        <dd>{session.scopes.join(", ") || translateNow("source.no.scopes.f466129b86")}</dd>
      </div>
    </dl>
  );
}

export function DynamicLeaseMetadata({ lease }: { lease: DynamicLease }) {
  return (
    <dl className="grid gap-2 md:grid-cols-2">
      <div>
        <dt className="font-medium text-muted-foreground">{translateNow("source.lease.id.9730377afc")}</dt>
        <dd className="break-all font-mono text-xs">{lease.id}</dd>
      </div>
      <div>
        <dt className="font-medium text-muted-foreground">{translateNow("source.state.a3b50c4767")}</dt>
        <dd>{lease.state}</dd>
      </div>
      <div>
        <dt className="font-medium text-muted-foreground">{translateNow("source.provider.472590ae97")}</dt>
        <dd>{lease.provider}</dd>
      </div>
      <div>
        <dt className="font-medium text-muted-foreground">{translateNow("source.role.14736a2eb9")}</dt>
        <dd>{lease.role}</dd>
      </div>
      <div>
        <dt className="font-medium text-muted-foreground">{translateNow("source.issued.0221e48751")}</dt>
        <dd>{formatDate(lease.issued_at)}</dd>
      </div>
      <div>
        <dt className="font-medium text-muted-foreground">{translateNow("source.expires.f6725f3af0")}</dt>
        <dd>{formatDate(lease.expires_at)}</dd>
      </div>
    </dl>
  );
}

export function RepositoryScanPosture({ posture }: { posture: SecretRepositoryScanPosture }) {
  const { t } = useTranslation();
  return (
    <div className="ui-panel grid min-w-0 max-w-full gap-3 p-comfortable text-sm">
      <div className="flex flex-wrap items-center gap-3">
        <span className="rounded-md bg-status-success/10 px-2 py-1 font-mono text-xs text-status-success">{posture.capability}</span>
        <span className="font-medium">{posture.served ? t("secrets.repoScan.active") : t("secrets.repoScan.unavailable")}</span>
        <span className="text-muted-foreground">{t("secrets.repoScan.ruleFloor", { scanner: posture.scanner, rules: posture.minimum_rules_active })}</span>
      </div>
      <div className="min-w-0 max-w-full overflow-x-auto">
        <table className="ui-table min-w-[52rem]">
          <caption className="sr-only">{t("secrets.repoScan.providerCaption")}</caption>
          <thead>
            <tr>
              <th scope="col">{t("secrets.repoScan.provider")}</th>
              <th scope="col">{t("secrets.repoScan.triggers")}</th>
              <th scope="col">{t("secrets.repoScan.ingress")}</th>
              <th scope="col">{t("secrets.repoScan.outbox")}</th>
            </tr>
          </thead>
          <tbody>
            {posture.providers.map((provider) => (
              <tr key={provider.id} className="align-top">
                <td className="font-medium">{provider.name}</td>
                <td>{provider.realtime_triggers.join(", ")}</td>
                <td>{provider.ingest_mode}</td>
                <td>{provider.outbox_mode}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <dl className="grid gap-3 md:grid-cols-2">
        <div>
          <dt className="font-medium text-muted-foreground">{t("secrets.repoScan.webhookPaths")}</dt>
          <dd className="mt-1 grid gap-1 font-mono text-xs">
            {posture.webhook_paths.map((path) => (
              <span key={path}>{path}</span>
            ))}
          </dd>
        </div>
        <div>
          <dt className="font-medium text-muted-foreground">{t("secrets.repoScan.eventFlow")}</dt>
          <dd className="mt-1 grid gap-1 font-mono text-xs">
            {posture.event_flow.map((event) => (
              <span key={event}>{event}</span>
            ))}
          </dd>
        </div>
        <div>
          <dt className="font-medium text-muted-foreground">{t("secrets.repoScan.releaseGates")}</dt>
          <dd className="mt-1">{posture.release_gates.map((gate) => gate.id).join(", ")}</dd>
        </div>
        <div>
          <dt className="font-medium text-muted-foreground">{t("secrets.repoScan.residuals")}</dt>
          <dd className="mt-1">{posture.residuals.join(" ")}</dd>
        </div>
      </dl>
    </div>
  );
}

export function ThirdPartyScanPosture({ posture }: { posture: ThirdPartySecretScanPosture }) {
  const { t } = useTranslation();
  return (
    <div className="ui-panel grid min-w-0 max-w-full gap-3 p-comfortable text-sm">
      <div className="flex flex-wrap items-center gap-3">
        <span className="rounded-md bg-status-success/10 px-2 py-1 font-mono text-xs text-status-success">{posture.capability}</span>
        <span className="font-medium">{posture.served ? t("secrets.thirdPartyScan.active") : t("secrets.thirdPartyScan.unavailable")}</span>
        <span className="text-muted-foreground">{t("secrets.repoScan.ruleFloor", { scanner: posture.scanner, rules: posture.minimum_rules_active })}</span>
      </div>
      <div className="min-w-0 max-w-full overflow-x-auto">
        <table className="ui-table min-w-[52rem]">
          <caption className="sr-only">{t("secrets.thirdPartyScan.providerCaption")}</caption>
          <thead>
            <tr>
              <th scope="col">{t("secrets.repoScan.provider")}</th>
              <th scope="col">{t("secrets.thirdPartyScan.artifactKinds")}</th>
              <th scope="col">{t("secrets.repoScan.ingress")}</th>
              <th scope="col">{t("secrets.repoScan.outbox")}</th>
            </tr>
          </thead>
          <tbody>
            {posture.providers.map((provider) => (
              <tr key={provider.id} className="align-top">
                <td className="font-medium">{provider.name}</td>
                <td>{provider.artifact_kinds.join(", ")}</td>
                <td>{provider.ingest_mode}</td>
                <td>{provider.outbox_mode}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <dl className="grid gap-3 md:grid-cols-2">
        <div>
          <dt className="font-medium text-muted-foreground">{t("secrets.thirdPartyScan.ingestPaths")}</dt>
          <dd className="mt-1 grid gap-1 font-mono text-xs">
            {posture.ingest_paths.map((path) => (
              <span key={path}>{path}</span>
            ))}
          </dd>
        </div>
        <div>
          <dt className="font-medium text-muted-foreground">{t("secrets.repoScan.eventFlow")}</dt>
          <dd className="mt-1 grid gap-1 font-mono text-xs">
            {posture.event_flow.map((event) => (
              <span key={event}>{event}</span>
            ))}
          </dd>
        </div>
        <div>
          <dt className="font-medium text-muted-foreground">{t("secrets.repoScan.releaseGates")}</dt>
          <dd className="mt-1">{posture.release_gates.map((gate) => gate.id).join(", ")}</dd>
        </div>
        <div>
          <dt className="font-medium text-muted-foreground">{t("secrets.repoScan.residuals")}</dt>
          <dd className="mt-1">{posture.residuals.join(" ")}</dd>
        </div>
      </dl>
    </div>
  );
}

export function SecretApprovalQueue({
  items,
  busyKey,
  canRetry,
  onApprove,
  onRetry,
}: {
  items: SecretApprovalQueueItem[];
  busyKey: string | null;
  canRetry: (item: SecretApprovalQueueItem) => boolean;
  onApprove: (item: SecretApprovalQueueItem) => void;
  onRetry: (item: SecretApprovalQueueItem) => void;
}) {
  const { t } = useTranslation();
  return (
    <div className="ui-panel grid gap-3 p-comfortable">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h3 className="text-title font-semibold">{t("secrets.approvals.heading")}</h3>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{t("secrets.approvals.description")}</p>
        </div>
        <span className="rounded-control border border-border px-2.5 py-1 text-xs font-semibold text-muted-foreground">{t("secrets.approvals.badge")}</span>
      </div>
      {items.length === 0 ? (
        <p className="rounded-control border border-border bg-muted/30 px-3 py-2 text-sm text-muted-foreground">{t("secrets.approvals.empty")}</p>
      ) : (
        <div className="grid gap-2" role="list" aria-label={t("secrets.approvals.listLabel")}>
          {items.map((item) => {
            const approveBusy = busyKey === `${item.id}:approve`;
            const retryBusy = busyKey === `${item.id}:retry`;
            const retryReady = canRetry(item);
            const actionLabel = secretApprovalActionLabel(item.action, t);
            return (
              <article key={item.id} role="listitem" className="grid gap-3 rounded-md border border-border bg-background p-3">
                <div className="flex flex-wrap items-start justify-between gap-2">
                  <div>
                    <p className="font-medium">
                      {actionLabel} - {item.name}
                    </p>
                    <p className="text-xs text-muted-foreground">
                      {t("secrets.approvals.openedStatus", { openedAt: formatDate(item.openedAt), status: secretApprovalStatusLabel(item, t) })}
                    </p>
                  </div>
                  <span className="rounded-control border border-border px-2 py-1 text-xs font-semibold text-muted-foreground">{item.status}</span>
                </div>
                <div className="flex flex-wrap gap-2">
                  <Button
                    type="button"
                    size="sm"
                    variant="outline"
                    aria-label={t("secrets.approvals.approveAction", { action: actionLabel, name: item.name })}
                    disabled={approveBusy || retryBusy || item.status === "completed"}
                    onClick={() => onApprove(item)}
                  >
                    {approveBusy ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <ShieldCheck className="h-4 w-4" aria-hidden="true" />}
                    {t("secrets.approvals.approve")}
                  </Button>
                  <Button
                    type="button"
                    size="sm"
                    disabled={approveBusy || retryBusy || !retryReady}
                    aria-label={t("secrets.approvals.retryAction", { action: actionLabel, name: item.name })}
                    onClick={() => onRetry(item)}
                  >
                    {retryBusy ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <PlayCircle className="h-4 w-4" aria-hidden="true" />}
                    {t("secrets.approvals.retry")}
                  </Button>
                </div>
                {item.error && <ErrorState title={t("secrets.approvals.errorTitle")}>{item.error}</ErrorState>}
              </article>
            );
          })}
        </div>
      )}
    </div>
  );
}

export function defaultThirdPartyProviders(): ThirdPartySecretScanPosture["providers"] {
  return [
    { id: "cicd_log", name: "CI/CD logs", artifact_kinds: ["ci_cd_log"], ingest_mode: "", secret_handling: "", outbox_mode: "" },
    {
      id: "container_registry",
      name: "Container registry exports",
      artifact_kinds: ["container_registry_export"],
      ingest_mode: "",
      secret_handling: "",
      outbox_mode: "",
    },
    { id: "slack", name: "Slack exports", artifact_kinds: ["slack_export"], ingest_mode: "", secret_handling: "", outbox_mode: "" },
    { id: "jira", name: "Jira exports", artifact_kinds: ["jira_export"], ingest_mode: "", secret_handling: "", outbox_mode: "" },
  ];
}

export function secretApprovalQueueID(action: SecretApprovalAction, name: string): string {
  return `${action}:${name}`;
}

export function secretApprovalActionLabel(action: SecretApprovalAction, t: Translate): string {
  switch (action) {
    case "rotate":
      return t("secrets.approvals.actionRotate");
    case "recover":
      return t("secrets.approvals.actionRecover");
    case "delete":
      return t("secrets.approvals.actionDelete");
  }
}

function secretApprovalStatusLabel(item: SecretApprovalQueueItem, t: Translate): string {
  if (item.status === "completed") return t("secrets.approvals.statusCompleted");
  if (item.status === "approved") {
    if (item.approver && item.approvals != null) return t("secrets.approvals.statusApprovedWithCount", { approver: item.approver, count: item.approvals });
    if (item.approver) return t("secrets.approvals.statusApprovedBy", { approver: item.approver });
    return t("secrets.approvals.statusApproved");
  }
  return item.approvals != null ? t("secrets.approvals.statusCount", { count: item.approvals }) : t("secrets.approvals.statusAwaiting");
}

export function mergeMeta(current: SecretMeta[], incoming: SecretMeta[]): SecretMeta[] {
  const byName = new Map(current.map((item) => [item.name, item]));
  for (const item of incoming) byName.set(item.name, item);
  return [...byName.values()].sort((a, b) => a.name.localeCompare(b.name));
}

export function leaseMetadataOnly(lease: DynamicLease): DynamicLease {
  const metadata = { ...lease };
  delete metadata.credential;
  return metadata;
}

function formatDate(value?: string): string {
  if (!value) return "-";
  return formatDateTimePolicy(value);
}

export function parseScopeList(value: string): string[] {
  return value
    .split(/[\n,]+/)
    .map((scope) => scope.trim())
    .filter(Boolean);
}

export function encodeTransitBytes(value: string): string {
  const bytes = new TextEncoder().encode(value);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

export function decodeTransitBytes(value: string): string {
  const binary = atob(value);
  const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
  return new TextDecoder().decode(bytes);
}
