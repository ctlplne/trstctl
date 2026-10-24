import { useState } from "react";
import { CheckCircle2, ClipboardCheck, SearchCheck, XCircle } from "lucide-react";
import { EmptyState } from "@/components/EmptyState";
import { StatusBadge } from "@/components/StatusBadge";
import { ErrorState, LoadingState } from "@/components/StatePrimitives";
import { Button } from "@/components/ui/button";
import { Field } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { translateNow, useTranslation } from "@/i18n/I18nProvider";
import { formatDateTime } from "@/i18n/format";
import {
  api,
  type CTMonitoring,
  type DiscoveryFindingResolutionRequest,
  type DiscoveryTriageFilter,
  type DriftRemediation,
  type DriftRemediationDecisionRequest,
  type DriftRemediationFinding,
} from "@/lib/api";
import { Metric, PreviewTable } from "./PostureParts";

// A105: the CT-log and drift Posture dashboards. Each lists one page of its
// own source kind's findings from the server, narrowed by triage status, and
// shows counts the server took over every finding of that kind. A106: each
// row shows its resolution and can be resolved (investigate, record
// remediated, accept the risk until a time, reopen).

export const triageFilters = [
  "unmanaged",
  "investigating",
  "managed",
  "dismissed",
  "remediated",
  "accepted_risk",
] as const satisfies readonly DiscoveryTriageFilter[];

const triageFilterLabels = {
  unmanaged: "posture.dashboards.triage.unmanaged",
  investigating: "posture.dashboards.triage.investigating",
  managed: "posture.dashboards.triage.managed",
  dismissed: "posture.dashboards.triage.dismissed",
  remediated: "posture.dashboards.triage.remediated",
  accepted_risk: "posture.dashboards.triage.accepted_risk",
} as const;

export type DashboardTriage = DiscoveryTriageFilter | "";

/** One dashboard's page state: what the filter shows, and whether more pages load. */
export interface DashboardPaging {
  filter: DashboardTriage;
  onFilter: (filter: DashboardTriage) => void;
  onLoadMore: () => void;
  loadingMore: boolean;
}

/** The fields of a finding's resolution a dashboard row shows and resolves. */
export interface ResolutionFacts {
  id: string;
  ref: string;
  status: string;
  assignee?: string;
  dueAt?: string;
  evidenceRef?: string;
  acceptedUntil?: string;
  overdue?: boolean;
  regressed?: boolean;
}

/** One dashboard's resolution state: the finding being resolved and the last result. */
export interface DashboardResolving {
  target: ResolutionFacts | null;
  result: string | null;
  onResolve: (facts: ResolutionFacts) => void;
  onCancel: () => void;
  onResolved: (message: string) => void;
}

type ResolutionAction = DiscoveryFindingResolutionRequest["action"];

// What each status may move to, as the server's transitions allow; managed
// and dismissed are terminal.
const actionsByStatus: Record<string, ResolutionAction[]> = {
  "": ["investigate", "remediated", "accept_risk"],
  unmanaged: ["investigate", "remediated", "accept_risk"],
  investigating: ["investigate", "remediated", "accept_risk"],
  remediated: ["reopen"],
  accepted_risk: ["investigate", "remediated", "reopen"],
};

const actionLabels = {
  investigate: "posture.dashboards.resolution.investigate",
  remediated: "posture.dashboards.resolution.remediated",
  accept_risk: "posture.dashboards.resolution.acceptRisk",
  reopen: "posture.dashboards.resolution.reopen",
} as const;

function triageCounts(counts: Record<string, unknown> | undefined): Record<DiscoveryTriageFilter, number> {
  const out = { unmanaged: 0, investigating: 0, managed: 0, dismissed: 0, remediated: 0, accepted_risk: 0 };
  for (const status of triageFilters) {
    const count = counts?.[status];
    out[status] = typeof count === "number" ? count : 0;
  }
  return out;
}

function TriageFilterBar({
  counts,
  total,
  shown,
  paging,
}: {
  counts: Record<DiscoveryTriageFilter, number>;
  total: number;
  shown: number;
  paging: DashboardPaging;
}) {
  const { t } = useTranslation();
  const listed = paging.filter ? counts[paging.filter] : total;
  return (
    <div className="flex flex-wrap items-end justify-between gap-3">
      <Field label={t("posture.dashboards.triageFilter")}>
        {(control) => (
          <Select {...control} value={paging.filter} onChange={(event) => paging.onFilter(event.target.value as DashboardTriage)}>
            <option value="">{t("posture.dashboards.triageAll", { count: total })}</option>
            {triageFilters.map((status) => (
              <option key={status} value={status}>
                {t(triageFilterLabels[status], { count: counts[status] })}
              </option>
            ))}
          </Select>
        )}
      </Field>
      <p className="text-sm text-muted-foreground">{t("posture.dashboards.showing", { shown, total: listed })}</p>
    </div>
  );
}

function LoadMore({ nextCursor, paging }: { nextCursor?: string; paging: DashboardPaging }) {
  const { t } = useTranslation();
  if (!nextCursor) return null;
  return (
    <Button type="button" variant="outline" className="w-fit" disabled={paging.loadingMore} onClick={paging.onLoadMore}>
      {paging.loadingMore ? t("posture.dashboards.loadingMore") : t("posture.dashboards.loadMore")}
    </Button>
  );
}

function ResolutionDetails({ facts }: { facts: ResolutionFacts }) {
  const { t } = useTranslation();
  return (
    <span className="mt-1 grid gap-0.5 text-xs text-muted-foreground">
      {facts.assignee ? <span>{t("posture.dashboards.resolution.assignedTo", { assignee: facts.assignee })}</span> : null}
      {facts.dueAt ? <span>{t("posture.dashboards.resolution.due", { date: formatDateTime(facts.dueAt) })}</span> : null}
      {facts.overdue ? <span className="font-medium text-status-critical">{t("posture.dashboards.resolution.overdue")}</span> : null}
      {facts.acceptedUntil ? <span>{t("posture.dashboards.resolution.acceptedUntil", { date: formatDateTime(facts.acceptedUntil) })}</span> : null}
      {facts.evidenceRef ? <span>{t("posture.dashboards.resolution.evidence", { ref: facts.evidenceRef })}</span> : null}
      {facts.regressed ? <span className="font-medium text-status-critical">{t("posture.dashboards.resolution.regressed")}</span> : null}
    </span>
  );
}

function ResolveButton({ facts, onResolve }: { facts: ResolutionFacts; onResolve: (facts: ResolutionFacts) => void }) {
  const { t } = useTranslation();
  if (!(actionsByStatus[facts.status] ?? []).length) return null;
  return (
    <Button type="button" variant="outline" aria-label={t("posture.dashboards.resolveFinding", { ref: facts.ref })} onClick={() => onResolve(facts)}>
      <ClipboardCheck className="h-4 w-4" aria-hidden="true" />
      {t("posture.dashboards.resolve")}
    </Button>
  );
}

function isoFromLocal(value: string): string | undefined {
  if (!value) return undefined;
  const at = new Date(value);
  return Number.isNaN(at.getTime()) ? undefined : at.toISOString();
}

/** FindingResolutionPanel records one resolution for the finding being resolved; the server validates it. */
export function FindingResolutionPanel({
  target,
  onCancel,
  onResolved,
}: {
  target: ResolutionFacts;
  onCancel: () => void;
  onResolved: (message: string) => void;
}) {
  const { t } = useTranslation();
  const actions = actionsByStatus[target.status] ?? [];
  const [action, setAction] = useState<ResolutionAction>(actions[0] ?? "reopen");
  const [reason, setReason] = useState("");
  const [assignee, setAssignee] = useState(target.assignee ?? "");
  const [dueAt, setDueAt] = useState("");
  const [evidenceRef, setEvidenceRef] = useState("");
  const [expiresAt, setExpiresAt] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit() {
    const request: DiscoveryFindingResolutionRequest = { action, reason };
    if (action === "investigate") {
      request.assignee = assignee;
      request.due_at = isoFromLocal(dueAt);
    }
    if (action === "remediated") request.evidence_ref = evidenceRef;
    if (action === "accept_risk") request.expires_at = isoFromLocal(expiresAt);
    setBusy(true);
    setError(null);
    try {
      await api.resolveDiscoveryFinding(target.id, request);
      onResolved(t("posture.dashboards.resolution.recorded", { ref: target.ref }));
    } catch (err) {
      setError(err instanceof Error ? err.message : t("posture.dashboards.resolution.failed"));
    } finally {
      setBusy(false);
    }
  }

  const title = t("posture.dashboards.resolution.title", { ref: target.ref });
  return (
    <section aria-label={title} className="grid gap-3 rounded-panel border border-border p-comfortable">
      <h3 className="text-sm font-semibold">{title}</h3>
      <div className="grid gap-3 md:grid-cols-2">
        <Field label={t("posture.dashboards.resolution.action")}>
          {(control) => (
            <Select {...control} value={action} onChange={(event) => setAction(event.target.value as ResolutionAction)}>
              {actions.map((option) => (
                <option key={option} value={option}>
                  {t(actionLabels[option])}
                </option>
              ))}
            </Select>
          )}
        </Field>
        <Field label={t("posture.dashboards.resolution.reason")}>
          {(control) => <Input {...control} value={reason} onChange={(event) => setReason(event.target.value)} />}
        </Field>
        {action === "investigate" ? (
          <>
            <Field label={t("posture.dashboards.resolution.assignee")}>
              {(control) => <Input {...control} value={assignee} onChange={(event) => setAssignee(event.target.value)} />}
            </Field>
            <Field label={t("posture.dashboards.resolution.dueAt")}>
              {(control) => <Input {...control} type="datetime-local" value={dueAt} onChange={(event) => setDueAt(event.target.value)} />}
            </Field>
          </>
        ) : null}
        {action === "remediated" ? (
          <Field label={t("posture.dashboards.resolution.evidenceRef")}>
            {(control) => <Input {...control} value={evidenceRef} onChange={(event) => setEvidenceRef(event.target.value)} />}
          </Field>
        ) : null}
        {action === "accept_risk" ? (
          <Field label={t("posture.dashboards.resolution.expiresAt")}>
            {(control) => <Input {...control} type="datetime-local" value={expiresAt} onChange={(event) => setExpiresAt(event.target.value)} />}
          </Field>
        ) : null}
      </div>
      {error ? <ErrorState title={t("posture.dashboards.resolution.failed")}>{error}</ErrorState> : null}
      <div className="flex flex-wrap gap-2">
        <Button type="button" disabled={busy} onClick={() => void submit()}>
          {busy ? t("posture.dashboards.resolution.submitting") : t("posture.dashboards.resolution.submit")}
        </Button>
        <Button type="button" variant="outline" disabled={busy} onClick={onCancel}>
          {t("posture.dashboards.resolution.cancel")}
        </Button>
      </div>
    </section>
  );
}

function metadataText(metadata: unknown, key: string): string {
  if (!metadata || typeof metadata !== "object") return "";
  const value = (metadata as Record<string, unknown>)[key];
  return typeof value === "string" ? value : typeof value === "number" ? String(value) : "";
}

function metadataNames(metadata: unknown): string[] {
  if (!metadata || typeof metadata !== "object") return [];
  const value = (metadata as Record<string, unknown>).sans;
  return Array.isArray(value) ? value.filter((name): name is string => typeof name === "string") : [];
}

/** CT-log dashboard: unexpected issuance with its names, issuer, log entry, sightings, triage and resolution. */
export function CTFindingsDashboard({
  state,
  loading,
  error,
  paging,
  resolving,
}: {
  state: CTMonitoring | null;
  loading: boolean;
  error: string | null;
  paging: DashboardPaging;
  resolving: DashboardResolving;
}) {
  const { t } = useTranslation();
  if (loading) return <LoadingState>{t("posture.dashboards.ct.loading")}</LoadingState>;
  const summary = state?.summary;
  const findings = state?.findings ?? [];
  return (
    <div className="grid gap-3">
      {error ? <ErrorState title={t("posture.dashboards.ct.unavailable")}>{error}</ErrorState> : null}
      {resolving.result ? <p className="text-sm font-medium text-status-success">{resolving.result}</p> : null}
      <TriageFilterBar counts={triageCounts(summary?.triage_counts)} total={summary?.finding_count ?? 0} shown={findings.length} paging={paging} />
      {findings.length === 0 ? (
        <EmptyState title={paging.filter ? t("posture.dashboards.ct.noneInFilter") : t("posture.dashboards.ct.none")} />
      ) : (
        <PreviewTable
          title={t("posture.dashboards.ct.title")}
          headers={[
            t("posture.dashboards.ct.colNames"),
            t("posture.dashboards.ct.colIssuer"),
            t("posture.dashboards.ct.colLog"),
            t("posture.dashboards.colFirstSeen"),
            t("posture.dashboards.colLastSeen"),
            t("posture.dashboards.colStatus"),
            t("posture.dashboards.ct.colFingerprint"),
            t("posture.dashboards.colResolve"),
          ]}
        >
          {findings.map((finding) => {
            const names = metadataNames(finding.metadata);
            const index = metadataText(finding.metadata, "index");
            const status = finding.triage_status ?? "unmanaged";
            const facts: ResolutionFacts = {
              id: finding.id,
              ref: finding.ref,
              status,
              assignee: finding.triage_assignee,
              dueAt: finding.triage_due_at,
              evidenceRef: finding.triage_evidence_ref,
              acceptedUntil: finding.risk_accepted_until,
              overdue: finding.overdue,
              regressed: finding.regressed,
            };
            return (
              <tr key={finding.id} className="align-top">
                <td className="font-medium">
                  <span className="block">{finding.ref}</span>
                  {names.length > 1 ? (
                    <span className="text-xs text-muted-foreground">{t("posture.dashboards.ct.moreNames", { count: names.length - 1 })}</span>
                  ) : null}
                </td>
                <td>{metadataText(finding.metadata, "issuer") || t("posture.dashboards.notReported")}</td>
                <td>
                  <span className="block break-all font-mono text-xs">{metadataText(finding.metadata, "log_url")}</span>
                  {index ? <span className="text-xs text-muted-foreground">{t("posture.dashboards.ct.logIndex", { index })}</span> : null}
                </td>
                <td>{formatDateTime(finding.first_seen_at)}</td>
                <td>{formatDateTime(finding.last_seen_at)}</td>
                <td>
                  <StatusBadge value={status} label={triageLabel(status)} tone={triageTone(status)} />
                  <ResolutionDetails facts={facts} />
                </td>
                <td className="font-mono text-xs" title={finding.fingerprint}>
                  {finding.fingerprint
                    ? t("posture.dashboards.ct.fingerprintPrefix", { prefix: finding.fingerprint.slice(0, 16) })
                    : t("posture.dashboards.notReported")}
                </td>
                <td>
                  <ResolveButton facts={facts} onResolve={resolving.onResolve} />
                </td>
              </tr>
            );
          })}
        </PreviewTable>
      )}
      <LoadMore nextCursor={state?.next_cursor} paging={paging} />
      {resolving.target ? <FindingResolutionPanel target={resolving.target} onCancel={resolving.onCancel} onResolved={resolving.onResolved} /> : null}
    </div>
  );
}

export type DriftDecision = DriftRemediationDecisionRequest["decision"];

/** Drift dashboard: each watched credential's drift, what was expected and observed, its triage, decisions and resolution. */
export function DriftFindingsDashboard({
  state,
  loading,
  error,
  busy,
  result,
  onDecision,
  paging,
  resolving,
}: {
  state: DriftRemediation | null;
  loading: boolean;
  error: string | null;
  busy: string | null;
  result: string | null;
  onDecision: (finding: DriftRemediationFinding, decision: DriftDecision) => void;
  paging: DashboardPaging;
  resolving: DashboardResolving;
}) {
  const { t } = useTranslation();
  if (loading) return <LoadingState>{translateNow("source.loading.drift.remediation.c1b6240bc3")}</LoadingState>;

  const summary = state?.summary;
  const findings = state?.findings ?? [];
  return (
    <div className="grid gap-3 rounded-panel border border-border p-comfortable">
      <dl className="grid gap-3 md:grid-cols-5">
        <Metric label="Watched sources" value={String(summary?.source_count ?? 0)} />
        <Metric label="Open drift" value={String(summary?.open_finding_count ?? 0)} />
        <Metric label="Replaced" value={String(summary?.replaced_count ?? 0)} />
        <Metric label="Permissions" value={String(summary?.permission_changed_count ?? 0)} />
        <Metric label="Decisions" value={String(summary?.remediation_decision_count ?? 0)} />
      </dl>
      {error ? <ErrorState title={translateNow("source.drift.remediation.unavailable.2da12cc33d")}>{error}</ErrorState> : null}
      {result ? <p className="text-sm font-medium text-status-success">{result}</p> : null}
      {resolving.result ? <p className="text-sm font-medium text-status-success">{resolving.result}</p> : null}
      <TriageFilterBar counts={triageCounts(summary?.triage_counts)} total={summary?.finding_count ?? 0} shown={findings.length} paging={paging} />
      {findings.length === 0 ? (
        <EmptyState
          title={paging.filter ? t("posture.dashboards.drift.noneInFilter") : translateNow("source.no.drift.remediation.findings.returned.yet.5034b41d52")}
        />
      ) : (
        <PreviewTable
          title={translateNow("source.drift.remediation.workflow.9456b591c4")}
          headers={[
            t("posture.dashboards.drift.colCredential"),
            t("posture.dashboards.drift.colDrift"),
            t("posture.dashboards.drift.colExpectedObserved"),
            t("posture.dashboards.drift.colRisk"),
            t("posture.dashboards.colStatus"),
            t("posture.dashboards.drift.colAction"),
            t("posture.dashboards.drift.colDecision"),
          ]}
        >
          {findings.map((finding) => {
            const facts: ResolutionFacts = {
              id: finding.finding_id,
              ref: finding.ref,
              status: finding.triage_status,
              assignee: finding.triage_assignee,
              dueAt: finding.triage_due_at,
              evidenceRef: finding.triage_evidence_ref,
              acceptedUntil: finding.risk_accepted_until,
              overdue: finding.overdue,
              regressed: finding.regressed,
            };
            return (
              <tr key={finding.finding_id} className="align-top">
                <td className="font-medium">
                  <span className="block">{finding.ref}</span>
                  <span className="text-xs text-muted-foreground">{finding.source_name}</span>
                </td>
                <td>
                  <span className="block">{driftLabel(finding.drift_type)}</span>
                  <span className="text-xs text-muted-foreground">{finding.credential_class}</span>
                </td>
                <td className="font-mono text-xs">
                  {t("posture.dashboards.drift.expectedObserved", {
                    expected: finding.expected_mode || t("posture.dashboards.notReported"),
                    observed: finding.actual_mode || t("posture.dashboards.notReported"),
                  })}
                </td>
                <td>{finding.risk_score}</td>
                <td>
                  <StatusBadge value={finding.triage_status} label={triageLabel(finding.triage_status)} tone={triageTone(finding.triage_status)} />
                  <ResolutionDetails facts={facts} />
                </td>
                <td>{finding.recommended_action}</td>
                <td>
                  <div className="flex flex-wrap gap-2">
                    <Button
                      type="button"
                      variant="outline"
                      title={translateNow("source.investigate.e264109347")}
                      aria-label={translateNow("source.investigate.value1.39e7603180", { value1: finding.ref })}
                      disabled={!finding.available_decisions.includes("investigate") || busy === `${finding.finding_id}:investigate`}
                      onClick={() => onDecision(finding, "investigate")}
                    >
                      <SearchCheck className="h-4 w-4" aria-hidden="true" />
                      {translateNow("source.investigate.e264109347")}
                    </Button>
                    <Button
                      type="button"
                      variant="outline"
                      title={translateNow("source.mark.managed.61a3f9305a")}
                      aria-label={translateNow("source.mark.managed.value1.ba545156d1", { value1: finding.ref })}
                      disabled={!finding.available_decisions.includes("mark_managed") || busy === `${finding.finding_id}:mark_managed`}
                      onClick={() => onDecision(finding, "mark_managed")}
                    >
                      <CheckCircle2 className="h-4 w-4" aria-hidden="true" />
                      {translateNow("source.managed.8f2de600bf")}
                    </Button>
                    <Button
                      type="button"
                      variant="outline"
                      title={translateNow("source.dismiss.48845bff33")}
                      aria-label={translateNow("source.dismiss.value1.540d3af43e", { value1: finding.ref })}
                      disabled={!finding.available_decisions.includes("dismiss") || busy === `${finding.finding_id}:dismiss`}
                      onClick={() => onDecision(finding, "dismiss")}
                    >
                      <XCircle className="h-4 w-4" aria-hidden="true" />
                      {translateNow("source.dismiss.48845bff33")}
                    </Button>
                    <ResolveButton facts={facts} onResolve={resolving.onResolve} />
                  </div>
                </td>
              </tr>
            );
          })}
        </PreviewTable>
      )}
      <LoadMore nextCursor={state?.next_cursor} paging={paging} />
      {resolving.target ? <FindingResolutionPanel target={resolving.target} onCancel={resolving.onCancel} onResolved={resolving.onResolved} /> : null}
    </div>
  );
}

function driftLabel(value: DriftRemediationFinding["drift_type"]): string {
  switch (value) {
    case "deleted":
      return "Deleted";
    case "replaced":
      return "Replaced";
    case "relocated":
      return "Relocated";
    case "permission_changed":
      return "Permission changed";
    default:
      return "Unknown";
  }
}

function triageLabel(value: string): string {
  switch (value) {
    case "investigating":
      return "Investigating";
    case "managed":
      return "Managed";
    case "dismissed":
      return "Dismissed";
    case "remediated":
      return "Remediated";
    case "accepted_risk":
      return "Risk accepted";
    default:
      return "Unmanaged";
  }
}

function triageTone(value: string) {
  switch (value) {
    case "managed":
    case "remediated":
      return "success";
    case "dismissed":
    case "accepted_risk":
      return "neutral";
    case "investigating":
      return "warning";
    default:
      return "critical";
  }
}
