import type { ReactNode } from "react";
import { Link } from "react-router-dom";
import { AlertTriangle, BellRing, CircleGauge, ShieldAlert, Users } from "lucide-react";
import { PageHeader } from "@/components/PageHeader";
import { LoadingState } from "@/components/StatePrimitives";
import { api, type ContextualRiskPriority } from "@/lib/api";
import { useApiQuery } from "@/lib/query";
import { useTranslation } from "@/i18n/I18nProvider";

function summaryCount(summary: Record<string, unknown> | undefined, key: string): number {
  const value = Number(summary?.[key]);
  return Number.isInteger(value) && value >= 0 ? value : 0;
}

function readyChannel(channel: { configured: boolean; enabled: boolean }): boolean {
  return channel.configured && channel.enabled;
}

function domainKey(kind: string): "nav.module.certificates" | "nav.module.secrets" | "nav.space.workload" | "nav.space.posture" {
  const normalized = kind.toLowerCase();
  if (normalized.includes("cert") || normalized === "x509") return "nav.module.certificates";
  if (normalized.includes("secret") || normalized.includes("token") || normalized.includes("api_key")) return "nav.module.secrets";
  if (normalized.includes("sign")) return "nav.space.posture";
  return "nav.space.workload";
}

function riskDeadline(priority: ContextualRiskPriority, t: ReturnType<typeof useTranslation>["t"]): string {
  const deadline = new Date(priority.expires_at).getTime();
  if (!Number.isFinite(deadline)) return t("trustOperations.deadline.unknown");
  const days = Math.ceil((deadline - Date.now()) / 86_400_000);
  if (days < 0) return t("trustOperations.deadline.expired");
  if (days === 0) return t("trustOperations.deadline.today");
  return t(days === 1 ? "trustOperations.deadline.one" : "trustOperations.deadline.many", { count: String(days) });
}

/** TrustOperations is the calm cross-domain cockpit. It composes existing
 * tenant-scoped read models; it does not invent another risk, owner, alert, or
 * worker authority. The linked pages remain the places where operators mutate
 * each system and inspect exact evidence. */
export function TrustOperations() {
  const { t } = useTranslation();
  const risks = useApiQuery(["risk", "contextual-priorities"], api.contextualRiskPriorities, { live: { intervalMs: 30_000 } });
  const incidents = useApiQuery(["incident-executions", { limit: 100 }], () => api.incidentExecutions({ limit: 100 }), { live: { intervalMs: 30_000 } });
  const notifications = useApiQuery(["notifications", { limit: 100 }], () => api.notifications({ limit: 100 }), { live: { intervalMs: 30_000 } });
  const channels = useApiQuery(["notification-channels"], api.notificationChannels, { live: { intervalMs: 60_000 } });
  const policies = useApiQuery(["notification-routing-policies"], api.notificationRoutingPolicies, { live: { intervalMs: 60_000 } });
  const ownership = useApiQuery(["ownership-attribution"], api.ownershipAttribution, { live: { intervalMs: 60_000 } });
  const workers = useApiQuery(["operations", "bulkheads"], api.bulkheadStats, { live: { intervalMs: 30_000 } });

  const loading = risks.loading || incidents.loading || notifications.loading || channels.loading || policies.loading || ownership.loading || workers.loading;
  const urgent = (risks.data?.priorities ?? []).filter((row) => row.severity === "critical" || row.severity === "high").slice(0, 5);
  const openIncidents = (incidents.data?.items ?? []).filter((row) => row.status !== "completed" && row.status !== "rolled_back").length;
  const deadDeliveries = (notifications.data?.items ?? []).filter((row) => row.status === "dead").length;
  const ownerGaps = summaryCount(ownership.data?.summary, "orphaned");
  const readyChannels = (channels.data?.items ?? []).filter(readyChannel).length;
  const routingReady = readyChannels > 0 && (policies.data?.items ?? []).length > 0;
  const workerHealthy = Boolean(workers.data?.served) && (workers.data?.pools ?? []).every((pool) => pool.rejected === 0 && pool.panicked === 0);
  const primaryTo = deadDeliveries > 0 ? "/notifications?status=dead" : urgent.length > 0 ? "/risk?sort=score" : "/operations";

  return (
    <section aria-labelledby="trust-operations-heading" className="space-y-6">
      <PageHeader
        title={t("trustOperations.title")}
        titleId="trust-operations-heading"
        description={t("trustOperations.answer")}
        technicalDetails={t("trustOperations.technical")}
        actions={
          <Link
            to={primaryTo}
            className="inline-flex min-h-10 items-center gap-2 rounded-control bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground hover:bg-primary/90"
          >
            <ShieldAlert className="h-4 w-4" aria-hidden="true" />
            {t("trustOperations.review")}
          </Link>
        }
      />

      {loading ? (
        <LoadingState>{t("trustOperations.loading")}</LoadingState>
      ) : (
        <>
          <section aria-labelledby="trust-operations-attention-heading" className="ui-panel space-y-4 p-comfortable">
            <div>
              <h2 id="trust-operations-attention-heading" className="text-title font-semibold">
                {urgent.length > 0 ? t("trustOperations.attentionTitle", { count: String(urgent.length) }) : t("trustOperations.attentionHealthy")}
              </h2>
              <p className="mt-1 text-sm text-muted-foreground">
                {urgent.length > 0 ? t("trustOperations.attentionHelp") : t("trustOperations.attentionHealthyHelp")}
              </p>
            </div>
            {urgent.length > 0 ? (
              <ul aria-label={t("trustOperations.attentionLabel")} className="divide-y divide-border">
                {urgent.map((priority) => (
                  <li
                    key={priority.credential_id}
                    className="grid gap-3 py-4 first:pt-0 last:pb-0 lg:grid-cols-[minmax(12rem,1fr)_minmax(12rem,1fr)_auto] lg:items-center"
                  >
                    <div className="min-w-0">
                      <strong className="block truncate text-body">{priority.subject}</strong>
                      <span className="mt-1 block text-caption text-muted-foreground">{t(domainKey(priority.kind))}</span>
                    </div>
                    <dl className="grid gap-1 text-sm sm:grid-cols-2">
                      <div>
                        <dt className="sr-only">{t("trustOperations.deadlineLabel")}</dt>
                        <dd>{riskDeadline(priority, t)}</dd>
                      </div>
                      <div>
                        <dt className="sr-only">{t("trustOperations.ownerLabel")}</dt>
                        <dd>{priority.owner_active ? t("trustOperations.owner.present") : t("trustOperations.owner.missing")}</dd>
                      </div>
                      <div className="sm:col-span-2 text-muted-foreground">
                        <dt className="sr-only">{t("trustOperations.nextActionLabel")}</dt>
                        <dd>{priority.recommended_action}</dd>
                      </div>
                    </dl>
                    <Link to="/risk?sort=score" className="text-sm font-semibold text-brand-accent hover:underline">
                      {t("trustOperations.remediate")}
                    </Link>
                  </li>
                ))}
              </ul>
            ) : null}
          </section>

          <section aria-labelledby="trust-operations-health-heading" className="space-y-3">
            <div>
              <h2 id="trust-operations-health-heading" className="text-title font-semibold">
                {t("trustOperations.healthTitle")}
              </h2>
              <p className="mt-1 text-sm text-muted-foreground">{t("trustOperations.healthHelp")}</p>
            </div>
            <ul aria-label={t("trustOperations.healthLabel")} className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
              <HealthLink
                to="/incidents"
                icon={<AlertTriangle className="h-4 w-4" aria-hidden="true" />}
                label={t(openIncidents === 1 ? "trustOperations.incidents.one" : "trustOperations.incidents.many", { count: String(openIncidents) })}
                urgent={openIncidents > 0}
              />
              <HealthLink
                to="/owners?status=orphaned"
                icon={<Users className="h-4 w-4" aria-hidden="true" />}
                label={t(ownerGaps === 1 ? "trustOperations.ownership.one" : "trustOperations.ownership.many", { count: String(ownerGaps) })}
                urgent={ownerGaps > 0}
              />
              <HealthLink
                to="/notifications?status=dead"
                icon={<BellRing className="h-4 w-4" aria-hidden="true" />}
                label={t(deadDeliveries === 1 ? "trustOperations.alerts.one" : "trustOperations.alerts.many", { count: String(deadDeliveries) })}
                urgent={deadDeliveries > 0}
              />
              <HealthLink
                to="/operations"
                icon={<CircleGauge className="h-4 w-4" aria-hidden="true" />}
                label={t(workerHealthy ? "trustOperations.workers.healthy" : "trustOperations.workers.review")}
                urgent={!workerHealthy}
              />
            </ul>
          </section>

          <section aria-labelledby="trust-operations-routing-heading" className="border-t border-border pt-5">
            <h2 id="trust-operations-routing-heading" className="text-title font-semibold">
              {t("trustOperations.routingTitle")}
            </h2>
            <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
              {routingReady
                ? t("trustOperations.routingReady", { channels: String(readyChannels), policies: String(policies.data?.items?.length ?? 0) })
                : t("trustOperations.routingUnsafe", { channels: String(readyChannels), policies: String(policies.data?.items?.length ?? 0) })}
            </p>
            <Link to="/notifications" className="mt-3 inline-block text-sm font-semibold text-brand-accent hover:underline">
              {t("trustOperations.routingReview")}
            </Link>
          </section>
        </>
      )}
    </section>
  );
}

function HealthLink({ to, icon, label, urgent }: { to: string; icon: ReactNode; label: string; urgent: boolean }) {
  return (
    <li>
      <Link to={to} className="ui-panel flex min-h-20 items-center gap-3 p-4 hover:border-brand-accent/50">
        <span className={urgent ? "text-risk-critical" : "text-brand-accent"}>{icon}</span>
        <span className="text-sm font-semibold">{label}</span>
      </Link>
    </li>
  );
}
