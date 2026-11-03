import type { ReactNode } from "react";
import { StatusBadge } from "@/components/StatusBadge";
import { ErrorState, LoadingState } from "@/components/StatePrimitives";
import { Button } from "@/components/ui/button";
import { useTranslation } from "@/i18n/I18nProvider";
import { api } from "@/lib/api";
import { useApiQuery } from "@/lib/query";

/** Deployment health (A246): backup freshness, restore proof, queue lag, signer
 * readiness, data freshness and dependency health, each with the numbers
 * behind its state. */
export function OperationsDashboardPanel() {
  const { t, formatDateTime } = useTranslation();
  const result = useApiQuery(["operations-dashboard"], () => api.operationsDashboard(), { retry: false, live: { intervalMs: 15_000 } });
  const tile = (title: string, state: string, detail: string, extra?: ReactNode) => (
    <div className="rounded-control border border-border p-3 text-sm">
      <div className="flex items-center justify-between gap-2">
        <h3 className="font-medium">{title}</h3>
        <StatusBadge vocabulary="health" value={state} />
      </div>
      <p className="mt-1 text-muted-foreground">{detail}</p>
      {extra}
    </div>
  );
  // A response missing a section (an older server, a sparse stub) reads as
  // unknown rather than breaking the page.
  const raw = result.data;
  const d = raw
    ? {
        backup: raw.backup ?? { state: "unknown", detail: "", configured: false, verified: false },
        restore_proof: raw.restore_proof ?? { state: "unknown", detail: "" },
        queues: raw.queues ?? { state: "unknown", detail: "", pending: 0, processing: 0, stranded: 0, failed: 0 },
        signer: raw.signer ?? { state: "unknown", detail: "", healthy: false },
        data_freshness: raw.data_freshness ?? { state: "unknown", detail: "", event_head: 0, projection_applied: 0, lag_events: 0 },
        dependencies: raw.dependencies ?? [],
      }
    : undefined;
  return (
    <section aria-labelledby="operations-dashboard-heading" className="ui-panel grid gap-3 p-comfortable">
      <div>
        <h2 id="operations-dashboard-heading" className="text-title font-semibold">
          {t("operations.dashboard.title")}
        </h2>
        <p className="max-w-3xl text-sm text-muted-foreground">{t("operations.dashboard.help")}</p>
      </div>
      {result.error ? (
        <div className="grid gap-2">
          <ErrorState title={t("operations.dashboard.failed")}>{result.error}</ErrorState>
          <Button onClick={result.refetch}>{t("operations.dashboard.retry")}</Button>
        </div>
      ) : !d ? (
        <LoadingState>{t("operations.dashboard.loading")}</LoadingState>
      ) : (
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {tile(
            t("operations.dashboard.backup"),
            d.backup.state,
            d.backup.detail,
            d.backup.last_backup_at && (
              <p className="mt-1 text-xs text-muted-foreground">{t("operations.dashboard.backupTaken", { at: formatDateTime(d.backup.last_backup_at) })}</p>
            ),
          )}
          {tile(
            t("operations.dashboard.restore"),
            d.restore_proof.state,
            d.restore_proof.detail,
            d.restore_proof.completed_at && (
              <p className="mt-1 text-xs text-muted-foreground">
                {t("operations.dashboard.restoreNumbers", {
                  at: formatDateTime(d.restore_proof.completed_at),
                  rpo: String(d.restore_proof.rpo_seconds ?? 0),
                  rto: String(d.restore_proof.rto_seconds ?? 0),
                })}
              </p>
            ),
          )}
          {tile(
            t("operations.dashboard.queues"),
            d.queues.state,
            d.queues.detail,
            <p className="mt-1 text-xs text-muted-foreground">
              {t("operations.dashboard.queueNumbers", {
                pending: String(d.queues.pending),
                processing: String(d.queues.processing),
                stranded: String(d.queues.stranded),
                failed: String(d.queues.failed),
              })}
            </p>,
          )}
          {tile(t("operations.dashboard.signer"), d.signer.state, d.signer.detail)}
          {tile(
            t("operations.dashboard.freshness"),
            d.data_freshness.state,
            d.data_freshness.detail,
            <p className="mt-1 text-xs text-muted-foreground">
              {t("operations.dashboard.freshnessNumbers", {
                head: String(d.data_freshness.event_head),
                applied: String(d.data_freshness.projection_applied),
                lag: String(d.data_freshness.lag_events),
              })}
            </p>,
          )}
          <div className="rounded-control border border-border p-3 text-sm">
            <h3 className="font-medium">{t("operations.dashboard.dependencies")}</h3>
            <ul className="mt-1 grid gap-1">
              {d.dependencies.map((dep) => (
                <li key={dep.name}>
                  <StatusBadge vocabulary="health" value={dep.healthy ? "ok" : "critical"} />{" "}
                  {t("operations.dashboard.dependency", { name: dep.name, verdict: dep.healthy ? t("operations.dashboard.healthy") : (dep.detail ?? "") })}
                </li>
              ))}
            </ul>
          </div>
        </div>
      )}
    </section>
  );
}
