import { StatusBadge } from "@/components/StatusBadge";
import { translateNow } from "@/i18n/I18nProvider";
import type { DiscoveryMonitoring } from "@/lib/api";

type DiscoveryMonitoringSource = DiscoveryMonitoring["sources"][number];

// S-C15 (extracted per R-09 before editing the Discovery monolith): the
// sources table listed name/kind/targets/updated, so answering "did this
// source actually run, and did it find anything" meant leaving for the Runs
// tab and matching ids by eye. The served monitoring read model already joins
// every source to its last run, its finding counts, and its schedule — this
// folds that answer back into the row.

export type SourceActivity = {
  lastRunStatus: string;
  lastRunAt: string;
  lastRunError: string;
  openFindings: number;
  findings: number;
  failedRuns: number;
  scheduled: boolean;
  /** Drift: the source is scheduled, has run before, and its most recent run failed. */
  drifting: boolean;
  /** Never ran: a configured source that has produced no run at all. */
  neverRan: boolean;
};

export function sourceActivityByID(monitoring: DiscoveryMonitoringSource[]): Map<string, SourceActivity> {
  const out = new Map<string, SourceActivity>();
  for (const row of monitoring) {
    const lastRunStatus = row.last_run_status ?? "";
    const neverRan = (row.run_count ?? 0) === 0;
    out.set(row.source_id, {
      lastRunStatus,
      lastRunAt: row.last_run_completed_at ?? row.last_discovery_at ?? "",
      lastRunError: row.last_run_error ?? "",
      openFindings: row.open_finding_count ?? 0,
      findings: row.finding_count ?? 0,
      failedRuns: row.failed_run_count ?? 0,
      scheduled: Boolean(row.scheduled),
      drifting: Boolean(row.scheduled) && !neverRan && lastRunStatus.toLowerCase() === "failed",
      neverRan,
    });
  }
  return out;
}

export function SourceActivityCell({ activity, formatDateTime }: { activity?: SourceActivity; formatDateTime: (value: string) => string }) {
  if (!activity) return <span className="text-caption text-muted-foreground">{translateNow("discovery.sourceActivity.noMonitoring")}</span>;
  if (activity.neverRan) {
    return <StatusBadge vocabulary="lifecycle" value="never_run" label={translateNow("discovery.sourceActivity.neverRan")} tone="warning" />;
  }
  return (
    <div className="grid gap-1">
      <div className="flex flex-wrap items-center gap-2">
        <StatusBadge vocabulary="lifecycle" value={activity.lastRunStatus || "unknown"} />
        {activity.lastRunAt ? <span className="text-caption text-muted-foreground">{formatDateTime(activity.lastRunAt)}</span> : null}
        {activity.drifting ? <StatusBadge vocabulary="risk" value="drift" label={translateNow("discovery.sourceActivity.drift")} tone="critical" /> : null}
      </div>
      {activity.lastRunError ? <span className="text-caption text-status-critical">{activity.lastRunError}</span> : null}
    </div>
  );
}

export function SourceFindingsCell({ activity }: { activity?: SourceActivity }) {
  if (!activity) return <span className="text-caption text-muted-foreground">—</span>;
  return (
    <span className="text-sm">
      {translateNow("discovery.sourceActivity.findings", { open: String(activity.openFindings), total: String(activity.findings) })}
    </span>
  );
}
