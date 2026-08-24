import type { ReactNode } from "react";
import { Link } from "react-router-dom";
import { AlertTriangle, BellRing, CheckCircle2 } from "lucide-react";
import { StackedTimeBarChart, TimeBarChart, type StackedTimeBarDatum, type TimeBarDatum } from "@/components/charts";
import type {
  Certificate,
  CertificateHealthDashboard,
  ConnectorDelivery,
  Identity,
  Notification,
  NotificationChannel,
  NotificationRoutingPolicy,
  Owner,
  RotationRun,
} from "@/lib/api";
import { useTranslation } from "@/i18n/I18nProvider";
import type { Locale, MessageKey } from "@/i18n/messages";
import { formatShortDate } from "@/i18n/format";

const DAY = 86_400_000;
const WEEK = 7 * DAY;

type Evidence<T> = T[] | null;

export interface LifecycleCockpitProps {
  certificates: Certificate[];
  health: CertificateHealthDashboard;
  owners: Evidence<Owner>;
  identities: Evidence<Identity>;
  rotationRuns: Evidence<RotationRun>;
  deliveries: Evidence<ConnectorDelivery>;
  notifications: Evidence<Notification>;
  channels: Evidence<NotificationChannel>;
  routingPolicies: Evidence<NotificationRoutingPolicy>;
}

type AutomationState = "failed" | "delayed" | "running" | "verified" | "managed-unverified" | "manual" | "unknown";

type ActionRow = {
  certificate: Certificate;
  commonName: string;
  environment: string;
  deadline: string;
  automation: AutomationState;
  automationLabel: string;
  ownerLabel: string;
  ownerGap: boolean;
  reason: string;
  actionLabel: string;
  actionTo: string;
  priority: number;
};

function certificateRecord(certificate: Certificate): Record<string, unknown> {
  return certificate as unknown as Record<string, unknown>;
}

function attributes(certificate: Certificate): Record<string, unknown> {
  const value = certificateRecord(certificate).attributes;
  return value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : {};
}

function firstText(certificate: Certificate, keys: string[]): string {
  const record = certificateRecord(certificate);
  const attrs = attributes(certificate);
  for (const key of keys) {
    const value = record[key] ?? attrs[key];
    if (typeof value === "string" && value.trim()) return value.trim();
  }
  return "";
}

function commonName(subject: string): string {
  const match = subject.match(/(?:^|,)\s*CN=([^,]+)/i);
  return (match?.[1] ?? subject).trim();
}

function environmentFor(certificate: Certificate, owner: Owner | undefined): string {
  const explicit = firstText(certificate, ["environment", "env"]);
  if (explicit) return explicit;
  const location = certificate.deployment_location?.toLowerCase() ?? "";
  for (const candidate of ["production", "prod", "staging", "stage", "development", "dev"]) {
    if (new RegExp(`(^|[^a-z])${candidate}([^a-z]|$)`).test(location)) return candidate;
  }
  if (owner?.environment?.trim()) return owner.environment.trim();
  return "Not recorded";
}

function daysUntil(value?: string): number | null {
  if (!value) return null;
  const time = new Date(value).getTime();
  if (!Number.isFinite(time)) return null;
  return Math.ceil((time - Date.now()) / DAY);
}

function ownerIsReachable(owner: Owner | undefined): boolean {
  return Boolean(owner && (owner.email?.trim() || owner.escalation_chain.some((entry) => entry.trim())));
}

function latestByTime<T>(items: T[], time: (item: T) => string | undefined): T | undefined {
  return items.reduce<T | undefined>((latest, item) => {
    if (!latest) return item;
    return new Date(time(item) ?? 0).getTime() > new Date(time(latest) ?? 0).getTime() ? item : latest;
  }, undefined);
}

function matchingIdentity(certificate: Certificate, identities: Identity[]): Identity | undefined {
  const name = commonName(certificate.subject).toLowerCase();
  return identities.find((identity) => identity.kind === "x509_certificate" && identity.name.trim().toLowerCase() === name);
}

function matchingRun(certificate: Certificate, identity: Identity | undefined, runs: RotationRun[]): RotationRun | undefined {
  return latestByTime(
    runs.filter(
      (run) =>
        (identity && run.identity_id === identity.id) ||
        run.predecessor_fingerprint === certificate.fingerprint ||
        run.successor_fingerprint === certificate.fingerprint,
    ),
    (run) => run.updated_at || run.created_at,
  );
}

function matchingDelivery(certificate: Certificate, identity: Identity | undefined, deliveries: ConnectorDelivery[]): ConnectorDelivery | undefined {
  return latestByTime(
    deliveries.filter(
      (delivery) =>
        delivery.fingerprint === certificate.fingerprint ||
        (identity && delivery.identity_id === identity.id) ||
        Boolean(certificate.deployment_location && delivery.destination === certificate.deployment_location),
    ),
    (delivery) => delivery.updated_at || delivery.created_at,
  );
}

function deliveryIssue(delivery: ConnectorDelivery | undefined): "failed" | "unverified" | "delayed" | null {
  if (!delivery) return null;
  if (["failed", "verify_failed", "rollback_failed", "rollback_refused"].includes(delivery.status)) return "failed";
  if (delivery.status === "delivered") return "unverified";
  if (["queued", "rollback_queued", "dry_run_queued"].includes(delivery.status)) {
    const queuedAt = new Date(delivery.created_at).getTime();
    if (Number.isFinite(queuedAt) && Date.now() - queuedAt > 15 * 60_000) return "delayed";
  }
  return null;
}

function automationState(certificate: Certificate, identity: Identity | undefined, run: RotationRun | undefined, evidenceObserved: boolean): AutomationState {
  if (!evidenceObserved) return "unknown";
  if (run?.status === "failed") return "failed";
  if (run?.status === "running") {
    const lastUpdate = new Date(run.updated_at || run.created_at).getTime();
    if (Number.isFinite(lastUpdate) && Date.now() - lastUpdate > 30 * 60_000) return "delayed";
    return "running";
  }
  if (run?.status === "succeeded" && run.successor_fingerprint === certificate.fingerprint) return "verified";
  if (identity) return "managed-unverified";
  return "manual";
}

function workArrivalData(certificates: Certificate[], labelForRange: (start: number, end: number) => string): TimeBarDatum[] {
  const data = Array.from({ length: 6 }, (_, index) => ({ label: labelForRange(index * 15, index * 15 + 14), value: 0, tone: "warning" as const }));
  for (const certificate of certificates) {
    if (certificate.status === "revoked") continue;
    const days = daysUntil(certificate.not_after);
    if (days === null || days < 0 || days > 90) continue;
    const index = Math.min(5, Math.floor(days / 15));
    data[index]!.value += 1;
  }
  return data;
}

function outcomeData(
  runs: RotationRun[],
  deliveries: ConnectorDelivery[],
  locale: Locale,
  timeZone: string,
  succeededLabel: string,
  failedLabel: string,
): StackedTimeBarDatum[] {
  const now = Date.now();
  const buckets = Array.from({ length: 6 }, (_, index) => {
    const start = now - (5 - index) * WEEK;
    return {
      start,
      label: formatShortDate(start, { locale, timeZone }),
      success: 0,
      failure: 0,
    };
  });
  const add = (when: string | undefined, succeeded: boolean) => {
    const time = new Date(when ?? 0).getTime();
    const index = Math.floor((time - buckets[0]!.start) / WEEK);
    if (index < 0 || index >= buckets.length) return;
    if (succeeded) buckets[index]!.success += 1;
    else buckets[index]!.failure += 1;
  };
  for (const run of runs) {
    if (run.status === "running") continue;
    add(run.completed_at || run.updated_at || run.created_at, run.status === "succeeded");
  }
  for (const delivery of deliveries) {
    if (["queued", "rollback_queued", "dry_run_queued", "dry_run_planned"].includes(delivery.status)) continue;
    const succeeded = ["delivered", "verified", "config_validated", "rollback_recorded", "rolled_back", "test_succeeded"].includes(delivery.status);
    add(delivery.updated_at || delivery.created_at, succeeded);
  }
  return buckets.map((bucket) => ({
    label: bucket.label,
    segments: [
      { label: succeededLabel, value: bucket.success, tone: "success" as const },
      { label: failedLabel, value: bucket.failure, tone: "critical" as const },
    ],
  }));
}

/** This cockpit composes tenant-scoped read models. It never calls an API,
 * guesses that a provider delivery reached a human, or treats a configured
 * job as proof that renewal and deployment actually succeeded. */
export function LifecycleCockpit(props: LifecycleCockpitProps) {
  const { t, locale, timeZone } = useTranslation();
  const owners = props.owners ?? [];
  const identities = props.identities ?? [];
  const runs = props.rotationRuns ?? [];
  const deliveries = props.deliveries ?? [];
  const ownerByID = new Map(owners.map((owner) => [owner.id, owner]));
  const evidenceObserved = props.identities !== null && props.rotationRuns !== null;
  const certificateFingerprints = new Set(props.certificates.map((certificate) => certificate.fingerprint));
  const certificateIdentityIDs = new Set(
    props.certificates.map((certificate) => matchingIdentity(certificate, identities)?.id).filter((identityID): identityID is string => Boolean(identityID)),
  );
  const certificateDestinations = new Set(
    props.certificates.map((certificate) => certificate.deployment_location).filter((destination): destination is string => Boolean(destination)),
  );
  const scopedRuns = runs.filter(
    (run) =>
      certificateIdentityIDs.has(run.identity_id) ||
      Boolean(run.predecessor_fingerprint && certificateFingerprints.has(run.predecessor_fingerprint)) ||
      Boolean(run.successor_fingerprint && certificateFingerprints.has(run.successor_fingerprint)),
  );
  const scopedDeliveries = deliveries.filter(
    (delivery) =>
      Boolean(delivery.identity_id && certificateIdentityIDs.has(delivery.identity_id)) ||
      Boolean(delivery.fingerprint && certificateFingerprints.has(delivery.fingerprint)) ||
      Boolean(delivery.destination && certificateDestinations.has(delivery.destination)),
  );

  const allActionRows = props.certificates
    .map((certificate): ActionRow | null => {
      if (certificate.status === "revoked") return null;
      const days = daysUntil(certificate.not_after);
      const identity = matchingIdentity(certificate, identities);
      const run = matchingRun(certificate, identity, scopedRuns);
      const delivery = matchingDelivery(certificate, identity, scopedDeliveries);
      const automation = automationState(certificate, identity, run, evidenceObserved);
      const owner = certificate.owner_id ? ownerByID.get(certificate.owner_id) : undefined;
      const hasOwner = Boolean(certificate.owner_id);
      const ownerObserved = props.owners !== null;
      const reachable = ownerIsReachable(owner);
      const renewalFailure = run?.status === "failed";
      const deploymentIssueState = deliveryIssue(delivery);
      const deploymentFailure = deploymentIssueState !== null;
      const urgentExpiry = days !== null && days <= 30;
      if (!urgentExpiry && !renewalFailure && !deploymentFailure && hasOwner && reachable) return null;

      let deadline = t("certificateCockpit.deadline.unknown");
      if (days !== null && days < 0)
        deadline = t(days === -1 ? "certificateCockpit.deadline.expiredOne" : "certificateCockpit.deadline.expiredMany", { count: String(Math.abs(days)) });
      else if (days === 0) deadline = t("certificateCockpit.deadline.today");
      else if (days === 1) deadline = t("certificateCockpit.deadline.one");
      else if (days !== null) deadline = t("certificateCockpit.deadline.many", { count: String(days) });

      const reasons: string[] = [];
      if (days !== null && days < 0) reasons.push(t("certificateCockpit.reason.expired"));
      else if (days !== null && days <= 7) reasons.push(t("certificateCockpit.reason.sevenDays"));
      else if (days !== null && days <= 30) reasons.push(t("certificateCockpit.reason.thirtyDays"));
      if (renewalFailure) reasons.push(t("certificateCockpit.reason.renewalFailed"));
      if (deploymentIssueState === "failed")
        reasons.push(t(delivery?.status === "verify_failed" ? "certificateCockpit.reason.verificationFailed" : "certificateCockpit.reason.deploymentFailed"));
      if (deploymentIssueState === "unverified") reasons.push(t("certificateCockpit.reason.deploymentUnverified"));
      if (deploymentIssueState === "delayed") reasons.push(t("certificateCockpit.reason.deploymentDelayed"));
      if (automation === "delayed") reasons.push(t("certificateCockpit.reason.renewalDelayed"));
      if (automation === "managed-unverified") reasons.push(t("certificateCockpit.reason.renewalUnverified"));
      if (!hasOwner) reasons.push(t("certificateCockpit.reason.ownerMissing"));
      else if (ownerObserved && !reachable) reasons.push(t("certificateCockpit.reason.ownerUnreachable"));

      let actionLabel = t("certificateCockpit.action.review");
      let actionTo = `/certificates?certificate=${encodeURIComponent(certificate.id)}`;
      if (!hasOwner) {
        actionLabel = t("owners.design.assign");
        actionTo = "/owners?status=orphaned";
      } else if (renewalFailure && identity) {
        actionLabel = t("certificateCockpit.action.retryRenewal");
        actionTo = `/identities?identity=${encodeURIComponent(identity.id)}`;
      } else if (automation === "delayed" && identity) {
        actionLabel = t("certificateCockpit.action.reviewRenewal");
        actionTo = `/identities?identity=${encodeURIComponent(identity.id)}`;
      } else if (deploymentFailure) {
        actionLabel = t("certificateCockpit.action.repairDeployment");
        actionTo = "/connectors?status=failed";
      } else if (identity) {
        actionLabel = t("certificateCockpit.action.renew");
        actionTo = `/identities?identity=${encodeURIComponent(identity.id)}`;
      } else {
        actionLabel = t("certificateCockpit.action.replace");
        actionTo = "/request";
      }

      return {
        certificate,
        commonName: commonName(certificate.subject),
        environment: environmentFor(certificate, owner),
        deadline,
        automation,
        automationLabel: t(`certificateCockpit.automation.${automation}` as MessageKey),
        ownerLabel: !hasOwner
          ? t("certificateCockpit.owner.missing")
          : owner
            ? reachable
              ? owner.name
              : t("certificateCockpit.owner.unreachable", { name: owner.name })
            : ownerObserved
              ? t("certificateCockpit.owner.unresolved")
              : t("certificateCockpit.owner.unchecked"),
        ownerGap: !hasOwner || (ownerObserved && !reachable),
        reason: reasons.join(" · ") || t("certificateCockpit.reason.review"),
        actionLabel,
        actionTo,
        priority:
          (days !== null && days < 0 ? 100 : 0) +
          (renewalFailure ? 80 : 0) +
          (deploymentFailure ? 60 : 0) +
          (!hasOwner ? 40 : 0) +
          Math.max(0, 30 - (days ?? 30)),
      };
    })
    .filter((row): row is ActionRow => row !== null)
    .sort((left, right) => right.priority - left.priority);

  const actionRows = allActionRows.slice(0, 10);
  const ownerGaps = allActionRows.filter((row) => row.ownerGap).length;
  const renewalFailures = scopedRuns.filter((run) => run.status === "failed").length;
  const deploymentIssues = scopedDeliveries.map(deliveryIssue).filter((issue): issue is NonNullable<ReturnType<typeof deliveryIssue>> => issue !== null);
  const deploymentFailures = deploymentIssues.length;
  const onlyExplicitDeploymentFailures = deploymentIssues.every((issue) => issue === "failed");
  const arrival = workArrivalData(props.certificates, (start, end) => t("certificateCockpit.arrival.range", { start: String(start), end: String(end) }));
  const outcomes = outcomeData(scopedRuns, scopedDeliveries, locale, timeZone, t("audit.design.result.succeeded"), t("audit.design.result.failed"));
  const deadUrgent = (props.notifications ?? []).filter(
    (notification) => notification.status === "dead" && allActionRows.some((row) => row.certificate.id === notification.certificate_id),
  ).length;
  const readyChannels = (props.channels ?? []).filter((channel) => channel.configured && channel.enabled).length;
  const policyCount = props.routingPolicies?.length ?? 0;
  const routingObserved = props.notifications !== null && props.channels !== null && props.routingPolicies !== null;
  const routingReady = routingObserved && readyChannels > 0 && policyCount > 0;

  return (
    <section aria-labelledby="certificate-cockpit-heading" className="mb-6 space-y-5">
      <div className="flex flex-wrap items-start justify-between gap-3 border-b border-border pb-4">
        <div>
          <h2 id="certificate-cockpit-heading" className="text-title font-semibold">
            {t("certificateCockpit.title")}
          </h2>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
            {allActionRows.length > 0
              ? t("certificateCockpit.answer.attention", { count: String(allActionRows.length) })
              : t("certificateCockpit.answer.clear")}
          </p>
        </div>
        <Link to={actionRows[0]?.actionTo ?? "/certificates"} className="text-sm font-semibold text-brand-accent hover:underline">
          {actionRows[0]?.actionLabel ?? t("certificateCockpit.action.reviewInventory")}
        </Link>
      </div>

      <section aria-label={t("certificateCockpit.metrics.label")}>
        <ul className="grid gap-px overflow-hidden rounded-card border border-border bg-border sm:grid-cols-3 xl:grid-cols-6">
          <MetricLink to="/certificates?expiry=7d" label={t("source.expired.424a2551d3")} value={props.health.summary.expired} metric="expired" urgent />
          <MetricLink
            to="/certificates?expiry=7d"
            label={t("moduleKpi.certificates.expiring7d")}
            value={props.health.summary.expiring_7d}
            metric="expiring-7d"
            urgent
          />
          <MetricLink
            to="/certificates?expiry=30d"
            label={t("moduleKpi.certificates.expiring30d")}
            value={props.health.summary.expiring_30d}
            metric="expiring-30d"
            urgent={props.health.summary.expiring_30d > 0}
          />
          <MetricLink
            to="/owners?status=orphaned"
            label={t("certificateCockpit.metric.ownerGaps")}
            value={props.owners === null ? t("source.not.checked.d3tri00006") : ownerGaps}
            metric="owner-gaps"
            urgent={ownerGaps > 0}
          />
          <MetricLink to="/certificates" label={t("moduleKpi.certificates.active")} value={props.health.summary.active} metric="active" />
          <MetricLink to="/ca-hierarchy" label={t("moduleKpi.certificates.authorities")} value={t("moduleKpi.view")} metric="authorities" />
        </ul>
      </section>

      <div className="grid gap-3 sm:grid-cols-2">
        <EvidenceLine urgent={renewalFailures > 0} icon={<AlertTriangle className="h-4 w-4" aria-hidden="true" />}>
          {t(renewalFailures === 1 ? "certificateCockpit.renewalFailure.one" : "certificateCockpit.renewalFailure.many", { count: String(renewalFailures) })}
        </EvidenceLine>
        <EvidenceLine urgent={deploymentFailures > 0} icon={<AlertTriangle className="h-4 w-4" aria-hidden="true" />}>
          {t(
            onlyExplicitDeploymentFailures
              ? deploymentFailures === 1
                ? "certificateCockpit.deploymentFailure.one"
                : "certificateCockpit.deploymentFailure.many"
              : deploymentFailures === 1
                ? "certificateCockpit.deploymentAttention.one"
                : "certificateCockpit.deploymentAttention.many",
            { count: String(deploymentFailures) },
          )}
        </EvidenceLine>
      </div>

      <div className="grid gap-4 xl:grid-cols-2">
        <ChartPanel title={t("certificateCockpit.arrival.title")} help={t("certificateCockpit.arrival.help")}>
          <TimeBarChart ariaLabel={t("certificateCockpit.arrival.aria")} data={arrival} tone="warning" />
          <DataTable label={t("certificateCockpit.arrival.tableAria")} headings={[t("certificateCockpit.table.window"), t("nav.item.certificates")]}>
            {arrival.map((row) => (
              <tr key={row.label}>
                <th scope="row">{row.label}</th>
                <td>{row.value}</td>
              </tr>
            ))}
          </DataTable>
        </ChartPanel>
        <ChartPanel title={t("certificateCockpit.outcomes.title")} help={t("certificateCockpit.outcomes.help")}>
          <StackedTimeBarChart ariaLabel={t("certificateCockpit.outcomes.aria")} data={outcomes} />
          <DataTable
            label={t("certificateCockpit.outcomes.tableAria")}
            headings={[t("certificateCockpit.table.week"), t("audit.design.result.succeeded"), t("audit.design.result.failed")]}
          >
            {outcomes.map((row) => (
              <tr key={row.label}>
                <th scope="row">{row.label}</th>
                <td>{row.segments[0]?.value ?? 0}</td>
                <td>{row.segments[1]?.value ?? 0}</td>
              </tr>
            ))}
          </DataTable>
        </ChartPanel>
      </div>

      <section aria-labelledby="certificate-action-queue-heading" className="ui-panel overflow-hidden">
        <div className="border-b border-border p-4">
          <h3 id="certificate-action-queue-heading" className="text-body font-semibold">
            {t("certificateCockpit.queue.title")}
          </h3>
          <p className="mt-1 text-caption text-muted-foreground">{t("certificateCockpit.queue.help")}</p>
        </div>
        <div className="overflow-x-auto">
          <table aria-label={t("certificateCockpit.queue.title")} className="w-full min-w-[68rem] text-left text-sm">
            <thead className="bg-muted/50 text-caption text-muted-foreground">
              <tr>
                <th className="px-4 py-2 font-medium" scope="col">
                  {t("search.kind.certificate")}
                </th>
                <th className="px-3 py-2 font-medium" scope="col">
                  {t("owners.readiness.environment")}
                </th>
                <th className="px-3 py-2 font-medium" scope="col">
                  {t("trustOperations.deadlineLabel")}
                </th>
                <th className="px-3 py-2 font-medium" scope="col">
                  {t("certificateCockpit.queue.automation")}
                </th>
                <th className="px-3 py-2 font-medium" scope="col">
                  {t("certificateCockpit.queue.owner")}
                </th>
                <th className="px-3 py-2 font-medium" scope="col">
                  {t("certificateCockpit.queue.reason")}
                </th>
                <th className="px-4 py-2 font-medium" scope="col">
                  {t("pageHeader.operate")}
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {actionRows.map((row) => (
                <tr key={row.certificate.id}>
                  <th scope="row" className="px-4 py-3 font-medium">
                    {row.commonName}
                  </th>
                  <td className="px-3 py-3">{row.environment}</td>
                  <td className="px-3 py-3 whitespace-nowrap">{row.deadline}</td>
                  <td className="px-3 py-3 whitespace-nowrap">{row.automationLabel}</td>
                  <td className="px-3 py-3">{row.ownerLabel}</td>
                  <td className="max-w-sm px-3 py-3 text-muted-foreground">{row.reason}</td>
                  <td className="px-4 py-3 whitespace-nowrap">
                    <Link to={row.actionTo} className="font-semibold text-brand-accent hover:underline">
                      {row.actionLabel}
                    </Link>
                  </td>
                </tr>
              ))}
              {actionRows.length === 0 ? (
                <tr>
                  <td colSpan={7} className="px-4 py-5 text-muted-foreground">
                    {t("certificateCockpit.queue.empty")}
                  </td>
                </tr>
              ) : null}
            </tbody>
          </table>
        </div>
      </section>

      <section aria-labelledby="certificate-alert-safety-heading" className="border-s-2 border-border ps-4">
        <div className="flex items-start gap-3">
          <BellRing className={deadUrgent > 0 || !routingReady ? "mt-0.5 h-4 w-4 text-risk-critical" : "mt-0.5 h-4 w-4 text-brand-accent"} aria-hidden="true" />
          <div>
            <h3 id="certificate-alert-safety-heading" className="text-body font-semibold">
              {t("certificateCockpit.alert.title")}
            </h3>
            <p className="mt-1 text-sm text-muted-foreground">
              {!routingObserved
                ? t("certificateCockpit.alert.unchecked")
                : routingReady
                  ? t("certificateCockpit.alert.ready", { channels: String(readyChannels), policies: String(policyCount) })
                  : t("certificateCockpit.alert.unsafe", { channels: String(readyChannels), policies: String(policyCount) })}
            </p>
            <p className={deadUrgent > 0 ? "mt-1 text-sm text-risk-critical" : "mt-1 text-sm text-muted-foreground"}>
              {t(deadUrgent === 1 ? "certificateCockpit.alert.deadOne" : "certificateCockpit.alert.deadMany", { count: String(deadUrgent) })}
            </p>
            <p className="mt-1 text-caption text-muted-foreground">{t("certificateCockpit.alert.humanProof")}</p>
            <Link
              to={deadUrgent > 0 ? "/notifications?status=dead" : "/notifications"}
              className="mt-2 inline-block text-sm font-semibold text-brand-accent hover:underline"
            >
              {t(deadUrgent > 0 ? "certificateCockpit.alert.repair" : "certificateCockpit.alert.review")}
            </Link>
          </div>
        </div>
      </section>
    </section>
  );
}

function MetricLink({ label, metric, to, urgent = false, value }: { label: string; metric: string; to: string; urgent?: boolean; value: number | string }) {
  return (
    <li className="bg-background">
      <Link to={to} className="block min-h-24 p-3 hover:bg-muted/40">
        <span className="block text-caption text-muted-foreground">{label}</span>
        <span
          data-metric={metric}
          className={urgent ? "mt-2 block text-2xl font-semibold tabular-nums text-risk-critical" : "mt-2 block text-2xl font-semibold tabular-nums"}
        >
          {value}
        </span>
      </Link>
    </li>
  );
}

function EvidenceLine({ children, icon, urgent }: { children: string; icon: ReactNode; urgent: boolean }) {
  return (
    <div className="ui-panel flex items-center gap-3 p-3">
      <span className={urgent ? "text-risk-critical" : "text-brand-accent"}>{urgent ? icon : <CheckCircle2 className="h-4 w-4" aria-hidden="true" />}</span>
      <span className="text-sm font-medium">{children}</span>
    </div>
  );
}

function ChartPanel({ children, help, title }: { children: ReactNode; help: string; title: string }) {
  return (
    <section className="ui-panel p-4">
      <h3 className="text-body font-semibold">{title}</h3>
      <p className="mt-1 text-caption text-muted-foreground">{help}</p>
      <div className="mt-3">{children}</div>
    </section>
  );
}

function DataTable({ children, headings, label }: { children: ReactNode; headings: string[]; label: string }) {
  return (
    <table aria-label={label} className="sr-only">
      <thead>
        <tr>
          {headings.map((heading) => (
            <th key={heading} scope="col">
              {heading}
            </th>
          ))}
        </tr>
      </thead>
      <tbody>{children}</tbody>
    </table>
  );
}
