import { useCallback, useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";

import { Button } from "@/components/ui/button";
import { useTranslation } from "@/i18n/I18nProvider";
import { api, type Identity, type LifecycleAutomationPlan } from "@/lib/api";
import { apiProblemContext } from "@/lib/apiProblem";

type Props = {
  identities: Identity[];
  onReviewRenewal: (identity: Identity, label: string, reason: string) => void;
};

function durationHours(value: string): number | null {
  const match = /^(\d+(?:\.\d+)?)h/.exec(value);
  return match ? Number(match[1]) : null;
}

function durationDays(value: string, seconds?: number): number | null {
  if (typeof seconds === "number" && Number.isFinite(seconds)) return Math.round(seconds / 86_400);
  const hours = durationHours(value);
  return hours == null ? null : Math.round(hours / 24);
}

export function LifecycleAutomationPanel({ identities, onReviewRenewal }: Props) {
  const { t, formatDateTime } = useTranslation();
  const [plan, setPlan] = useState<LifecycleAutomationPlan | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const identityByID = useMemo(() => new Map(identities.map((identity) => [identity.id, identity])), [identities]);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      setPlan(await api.lifecycleAutomationPlan());
      setError(null);
    } catch (err) {
      setError(apiProblemContext(err, t("identities.automation.loadFailed")));
    } finally {
      setLoading(false);
    }
  }, [t]);

  useEffect(() => {
    void load();
  }, [load]);

  const renewDays = plan ? durationDays(plan.scheduler.renew_before, plan.scheduler.renew_before_seconds) : null;
  const alertDays = plan ? durationDays(plan.scheduler.alert_before, plan.scheduler.alert_before_seconds) : null;
  const schedulerMessage =
    plan?.scheduler.status === "deferred"
      ? t("identities.automation.deferred")
      : plan?.scheduler.status === "disabled"
        ? t("identities.automation.disabled")
        : t("identities.automation.running");

  return (
    <section aria-labelledby="lifecycle-automation-heading" className="ui-panel mb-4 overflow-hidden">
      <div className="flex flex-wrap items-start justify-between gap-3 border-b border-border px-5 py-4">
        <div>
          <p className="text-caption font-medium uppercase tracking-wide text-muted-foreground">{t("identities.automation.eyebrow")}</p>
          <h2 id="lifecycle-automation-heading" className="mt-1 text-title font-semibold">
            {t("identities.automation.heading")}
          </h2>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{t("identities.automation.answer")}</p>
        </div>
        <Button type="button" size="sm" variant="outline" loading={loading} onClick={() => void load()}>
          {t("identities.automation.refresh")}
        </Button>
      </div>

      {error ? (
        <div className="px-5 py-4 text-sm" role="status">
          <p className="font-medium text-risk-critical">{t("identities.automation.unavailable")}</p>
          <p className="mt-1 text-muted-foreground">{error}</p>
        </div>
      ) : loading && !plan ? (
        <p className="px-5 py-4 text-sm text-muted-foreground" role="status">
          {t("identities.automation.loading")}
        </p>
      ) : plan ? (
        <div className="grid gap-5 px-5 py-4">
          <div className="grid gap-3 lg:grid-cols-[minmax(0,1.5fr)_repeat(3,minmax(7rem,0.5fr))]">
            <div className="rounded-control bg-muted/50 p-3">
              <p className="text-sm font-semibold">{schedulerMessage}</p>
              <p className="mt-1 text-sm text-muted-foreground">
                {renewDays == null
                  ? t("identities.automation.renewConfigured", { duration: plan.scheduler.renew_before })
                  : t("identities.automation.renewDays", { count: renewDays })}
                {" "}
                {alertDays == null
                  ? t("identities.automation.alertConfigured", { duration: plan.scheduler.alert_before })
                  : t("identities.automation.alertDays", { count: alertDays })}
              </p>
              <p className="mt-2 text-sm text-muted-foreground">{t("identities.automation.ariFirst")}</p>
            </div>
            <Metric label={t("identities.automation.monitored")} value={plan.summary.monitored} />
            <Metric label={t("identities.automation.dueNow")} value={plan.summary.due_now} />
            <Metric label={t("identities.automation.failed")} value={plan.summary.renewal_failed + plan.summary.outbox_failed} />
          </div>

          <div className="grid gap-2 text-sm text-muted-foreground">
            <p>
              {t("identities.automation.maintenance")}
              {plan.scheduler.maintenance_deferral
                ? t("identities.automation.maintenanceDeferral", { reason: plan.scheduler.maintenance_deferral })
                : ""}
              {plan.scheduler.next_open ? t("identities.automation.nextOpen", { time: formatDateTime(plan.scheduler.next_open) }) : ""}
            </p>
            <p>{t("identities.automation.cancelLimit")}</p>
          </div>

          {plan.items.some((item) => item.due || item.identity_status === "renewal_failed") ? (
            <div className="grid gap-2">
              <h3 className="text-sm font-semibold">{t("identities.automation.pendingHeading")}</h3>
              {plan.items
                .filter((item) => item.due || item.identity_status === "renewal_failed")
                .map((item) => {
                  const identity = identityByID.get(item.identity_id);
                  const retry = item.identity_status === "renewal_failed";
                  return (
                    <div key={item.identity_id} className="flex flex-wrap items-center justify-between gap-3 border-t border-border py-3 first:border-t-0">
                      <div className="min-w-0">
                        <p className="truncate text-sm font-medium">{item.identity_name}</p>
                        <p className="text-xs text-muted-foreground">
                          {item.owner_name} · {item.reason}
                          {item.not_after ? t("identities.automation.expires", { time: formatDateTime(item.not_after) }) : ""}
                        </p>
                        {item.blockers.length > 0 && <p className="mt-1 text-xs text-risk-warning">{item.blockers.join(" ")}</p>}
                      </div>
                      <Button
                        type="button"
                        size="sm"
                        variant="outline"
                        disabled={!identity || item.blockers.length > 0}
                        onClick={() => identity && onReviewRenewal(identity, retry ? t("identities.automation.retryAction") : t("identities.automation.startAction"), item.reason)}
                      >
                        {retry ? t("identities.automation.retryAction") : t("identities.automation.startAction")}
                      </Button>
                    </div>
                  );
                })}
            </div>
          ) : (
            <p className="text-sm text-muted-foreground">{t("identities.automation.noneDue")}</p>
          )}

          <details className="border-t border-border pt-3 text-sm">
            <summary className="cursor-pointer font-medium">{t("identities.automation.details")}</summary>
            <div className="mt-3 grid gap-3 text-muted-foreground md:grid-cols-2">
              <div>
                <p className="font-medium text-foreground">{t("identities.automation.queueHeading")}</p>
                <p>{t("identities.automation.queueCounts", { pending: plan.summary.outbox_pending, processing: plan.summary.outbox_processing, failed: plan.summary.outbox_failed })}</p>
                <p className="mt-2">{t("identities.automation.previewSafe")}</p>
              </div>
              <div>
                <p className="font-medium text-foreground">{t("identities.automation.recoveryHeading")}</p>
                <div className="mt-1 flex flex-wrap gap-x-3 gap-y-1">
                  <Link className="font-medium text-brand-accent hover:underline" to="/operations">
                    {t("identities.automation.openRuns")}
                  </Link>
                  <Link className="font-medium text-brand-accent hover:underline" to="/connectors">
                    {t("identities.automation.openConnectors")}
                  </Link>
                  <Link className="font-medium text-brand-accent hover:underline" to="/notifications">
                    {t("identities.automation.openAlerts")}
                  </Link>
                </div>
              </div>
            </div>
          </details>
        </div>
      ) : null}
    </section>
  );
}

function Metric({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded-control border border-border p-3">
      <p className="text-2xl font-semibold tabular-nums">{value}</p>
      <p className="mt-1 text-xs text-muted-foreground">{label}</p>
    </div>
  );
}
