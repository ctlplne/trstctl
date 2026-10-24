import { CheckCircle2, SearchCheck, XCircle } from "lucide-react";
import { EmptyState } from "@/components/EmptyState";
import { StatusBadge } from "@/components/StatusBadge";
import { ErrorState, LoadingState } from "@/components/StatePrimitives";
import { Button } from "@/components/ui/button";
import { Field } from "@/components/ui/field";
import { Select } from "@/components/ui/select";
import { translateNow, useTranslation } from "@/i18n/I18nProvider";
import { formatDateTime } from "@/i18n/format";
import type { CTMonitoring, DiscoveryTriageFilter, DriftRemediation, DriftRemediationDecisionRequest, DriftRemediationFinding } from "@/lib/api";
import { Metric, PreviewTable } from "./PostureParts";

// A105: the CT-log and drift Posture dashboards. Each lists one page of its
// own source kind's findings from the server, narrowed by triage status, and
// shows counts the server took over every finding of that kind.

export const triageFilters = ["unmanaged", "investigating", "managed", "dismissed"] as const satisfies readonly DiscoveryTriageFilter[];

const triageFilterLabels = {
  unmanaged: "posture.dashboards.triage.unmanaged",
  investigating: "posture.dashboards.triage.investigating",
  managed: "posture.dashboards.triage.managed",
  dismissed: "posture.dashboards.triage.dismissed",
} as const;

export type DashboardTriage = DiscoveryTriageFilter | "";

/** One dashboard's page state: what the filter shows, and whether more pages load. */
export interface DashboardPaging {
  filter: DashboardTriage;
  onFilter: (filter: DashboardTriage) => void;
  onLoadMore: () => void;
  loadingMore: boolean;
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

/** CT-log dashboard: unexpected issuance with its names, issuer, log entry, sightings and triage. */
export function CTFindingsDashboard({
  state,
  loading,
  error,
  paging,
}: {
  state: CTMonitoring | null;
  loading: boolean;
  error: string | null;
  paging: DashboardPaging;
}) {
  const { t } = useTranslation();
  if (loading) return <LoadingState>{t("posture.dashboards.ct.loading")}</LoadingState>;
  const summary = state?.summary;
  const counts = {
    unmanaged: summary?.open_finding_count ?? 0,
    investigating: summary?.investigating_count ?? 0,
    managed: summary?.managed_count ?? 0,
    dismissed: summary?.dismissed_count ?? 0,
  };
  const findings = state?.findings ?? [];
  return (
    <div className="grid gap-3">
      {error ? <ErrorState title={t("posture.dashboards.ct.unavailable")}>{error}</ErrorState> : null}
      <TriageFilterBar counts={counts} total={summary?.finding_count ?? 0} shown={findings.length} paging={paging} />
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
          ]}
        >
          {findings.map((finding) => {
            const names = metadataNames(finding.metadata);
            const index = metadataText(finding.metadata, "index");
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
                  <StatusBadge
                    value={finding.triage_status ?? "unmanaged"}
                    label={triageLabel(finding.triage_status ?? "")}
                    tone={triageTone(finding.triage_status ?? "")}
                  />
                </td>
                <td className="font-mono text-xs" title={finding.fingerprint}>
                  {finding.fingerprint
                    ? t("posture.dashboards.ct.fingerprintPrefix", { prefix: finding.fingerprint.slice(0, 16) })
                    : t("posture.dashboards.notReported")}
                </td>
              </tr>
            );
          })}
        </PreviewTable>
      )}
      <LoadMore nextCursor={state?.next_cursor} paging={paging} />
    </div>
  );
}

export type DriftDecision = DriftRemediationDecisionRequest["decision"];

/** Drift dashboard: each watched credential's drift, what was expected and observed, its triage and the decisions left. */
export function DriftFindingsDashboard({
  state,
  loading,
  error,
  busy,
  result,
  onDecision,
  paging,
}: {
  state: DriftRemediation | null;
  loading: boolean;
  error: string | null;
  busy: string | null;
  result: string | null;
  onDecision: (finding: DriftRemediationFinding, decision: DriftDecision) => void;
  paging: DashboardPaging;
}) {
  const { t } = useTranslation();
  if (loading) return <LoadingState>{translateNow("source.loading.drift.remediation.c1b6240bc3")}</LoadingState>;

  const summary = state?.summary;
  const counts = {
    unmanaged: summary?.open_finding_count ?? 0,
    investigating: summary?.investigating_count ?? 0,
    managed: summary?.remediated_count ?? 0,
    dismissed: summary?.dismissed_count ?? 0,
  };
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
      <TriageFilterBar counts={counts} total={summary?.finding_count ?? 0} shown={findings.length} paging={paging} />
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
          {findings.map((finding) => (
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
                </div>
              </td>
            </tr>
          ))}
        </PreviewTable>
      )}
      <LoadMore nextCursor={state?.next_cursor} paging={paging} />
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
    default:
      return "Unmanaged";
  }
}

function triageTone(value: string) {
  switch (value) {
    case "managed":
      return "success";
    case "dismissed":
      return "neutral";
    case "investigating":
      return "warning";
    default:
      return "critical";
  }
}
