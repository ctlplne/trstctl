import { FormEvent, useEffect, useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { Activity, AlertTriangle, FilePlus2, PlugZap, Send, ShieldCheck } from "lucide-react";
import {
  ApiError,
  UnauthorizedError,
  api,
  type BulkRevokeRequest,
  type Certificate,
  type CertificateHealthDashboard,
  type ConnectorDelivery,
  type CRLDistribution,
  type RevocationHealth,
  type CTSubmission,
  type Identity,
  type Notification,
  type NotificationChannel,
  type NotificationRoutingPolicy,
  type Owner,
  type RogueCertificatePosture,
  type RotationRun,
} from "@/lib/api";
import { CredentialChip } from "@/components/CredentialChip";
import { PageTabs, tabPanelProps } from "@/components/PageTabs";
import { StepShell, type CarouselStep } from "@/components/wizard/StepShell";
import { DataGrid, type DataGridColumn } from "@/components/DataGrid";
import { DataGridToolbar } from "@/components/DataGridToolbar";
import { DetailDrawer } from "@/components/DetailDrawer";
import { Dialog } from "@/components/Dialog";
import { Button } from "@/components/ui/button";
import { BulkActionBar } from "@/components/bulk";
import { useToast } from "@/components/ToastProvider";
import { CredentialActivityTimeline } from "@/components/CredentialActivityTimeline";
import { EmptyState } from "@/components/EmptyState";
import { ErrorState, LoadingState, PermissionDeniedState } from "@/components/StatePrimitives";
import { StatusBadge } from "@/components/StatusBadge";
import { PageHeader } from "@/components/PageHeader";
import { validityBandForDates } from "@/lib/statusVocab";
import { useTranslation, translateNow } from "@/i18n/I18nProvider";
import { formatNumber as formatNumberPolicy } from "@/i18n/format";
import { certificateDisplayName, certificateReplacementPath } from "@/lib/certificatePresentation";
import type { MessageKey } from "@/i18n/messages";
import { ReadinessPanel, ReadinessSimulator, DeploymentReceipts, RenewalHistory, autoRenewingCount } from "@/components/certs";
import { LifecycleCockpit } from "@/components/certs/LifecycleCockpit";
import type { GridViewPrimitive } from "@/lib/gridViews";
import { revocationReasons } from "@/lib/revocation";
import { RevocationCenter } from "@/pages/certificates/RevocationCenter";
import {
  certificateEnvironment,
  certificateProfile,
  certificateTeamID,
  certificateTeamLabel,
  effectiveOwnershipLabel,
  ownerIsReachable,
  teamFacetOptions,
} from "@/pages/certificates/certificateInventory";
import { AppQueryProvider, useApiQuery, useHasAppQueryProvider } from "@/lib/query";
import { useAuth } from "@/auth/AuthProvider";

type ExpiryFilter = "all" | "7d" | "30d" | "90d";

const expiryFilters: Array<{ value: ExpiryFilter; label: string; days?: number }> = [
  { value: "all", label: translateNow("source.all.a52ace420f") },
  { value: "7d", label: translateNow("source.7d.bf8cc07ad6"), days: 7 },
  { value: "30d", label: translateNow("source.7.30d.425b95671a"), days: 30 },
  { value: "90d", label: translateNow("source.30.90d.f8499e46ac"), days: 90 },
];

function expiringBefore(filter: ExpiryFilter): string | undefined {
  const days = expiryFilters.find((f) => f.value === filter)?.days;
  if (!days) return undefined;
  const cutoff = new Date(Date.now() + days * 24 * 60 * 60 * 1000);
  return cutoff.toISOString();
}

function expiryFromSearchParam(value: string | null): ExpiryFilter {
  return expiryFilters.some((filter) => filter.value === value) ? (value as ExpiryFilter) : "all";
}

/** The page's object list (the inventory table) renders first; every
 * specialist panel lives behind a sibling tab (audit P0: mega-page pattern). */
type CertificatesTab = "inventory" | "health" | "crlct" | "renewal";
const certificateTabIds: readonly CertificatesTab[] = ["inventory", "health", "crlct", "renewal"];

function tabFromSearchParam(value: string | null): CertificatesTab {
  return certificateTabIds.includes(value as CertificatesTab) ? (value as CertificatesTab) : "inventory";
}

function ingestSteps(t: (key: MessageKey) => string): CarouselStep[] {
  return [
    { id: "pem", label: t("certificates.ingest.pem.label"), description: t("certificates.ingest.pem.description") },
    { id: "placement", label: t("certificates.ingest.placement.label"), description: t("certificates.ingest.placement.description") },
    { id: "review", label: t("certificates.ingest.review.label"), description: t("certificates.ingest.review.description") },
  ];
}

type Notice = { kind: "permission" | "error"; message: string };
type FacetFilter = "all" | string;

function stringFromGridMetadata(metadata: Record<string, GridViewPrimitive>, key: string, fallback = "all"): string {
  const value = metadata[key];
  return typeof value === "string" && value ? value : fallback;
}

function expiryFromGridMetadata(metadata: Record<string, GridViewPrimitive>): ExpiryFilter {
  return expiryFromSearchParam(stringFromGridMetadata(metadata, "expiry"));
}

function limitFromGridMetadata(metadata: Record<string, GridViewPrimitive>, fallback: number): number {
  const value = metadata.limit;
  return typeof value === "number" && [5, 20, 50].includes(value) ? value : fallback;
}

function setOptionalParam(params: URLSearchParams, key: string, value: string) {
  if (value === "all" || value === "") {
    params.delete(key);
  } else {
    params.set(key, value);
  }
}

function noticeForError(err: unknown, action: string): Notice {
  if (err instanceof UnauthorizedError) {
    return { kind: "permission", message: `Your session cannot ${action}.` };
  }
  if (err instanceof ApiError) {
    try {
      const problem = JSON.parse(err.body) as { detail?: string; title?: string };
      return { kind: "error", message: problem.detail || problem.title || err.message };
    } catch {
      return { kind: "error", message: err.body || err.message };
    }
  }
  return { kind: "error", message: err instanceof Error ? err.message : String(err) };
}

function formatCount(value: number): string {
  return formatNumberPolicy(value);
}

function splitCertificateLines(value: string): string[] {
  return value
    .split(/\r?\n|,/)
    .map((item) => item.trim())
    .filter(Boolean);
}

function splitPEMBlocks(value: string): string[] {
  const trimmed = value.trim();
  if (!trimmed) return [];
  const matches = trimmed.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g);
  if (matches?.length) return matches.map((item) => item.trim());
  return splitCertificateLines(trimmed);
}

/** Run a secondary data fetch so it can never crash the primary inventory:
 * a missing method (undefined in a test mock) or a rejected promise both
 * resolve to undefined instead of throwing. The certificate grid is the
 * bulkhead that must survive an auxiliary panel's outage (AN-7). */
function settleOptional<T>(make: () => Promise<T>): Promise<T | undefined> {
  try {
    return Promise.resolve(make()).catch(() => undefined);
  } catch {
    return Promise.resolve(undefined);
  }
}

function CertificateHealthPanel({ health }: { health: CertificateHealthDashboard }) {
  const { t, formatDate } = useTranslation();
  const state = health.summary.health;
  const stateClass =
    state === "critical"
      ? "border-destructive/40 bg-destructive/10 text-destructive"
      : state === "warning"
        ? "border-status-warning/50 bg-status-warning/10 text-status-warning"
        : "border-status-success/40 bg-status-success/10 text-status-success";
  const stateIcon = state === "critical" ? <AlertTriangle className="h-4 w-4" aria-hidden="true" /> : <ShieldCheck className="h-4 w-4" aria-hidden="true" />;
  const stateLabel =
    state === "critical"
      ? t("certificates.health.stateCritical")
      : state === "warning"
        ? t("certificates.health.stateWarning")
        : t("certificates.health.stateOk");
  const topSources = health.source_breakdown.slice(0, 4);
  const soon = health.expiring.slice(0, 5);
  return (
    <section aria-labelledby="cert-health-heading" className="border-y border-border py-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 id="cert-health-heading" className="text-base font-semibold">
            {t("certificates.health.heading")}
          </h2>
          <p className="mt-1 text-sm text-muted-foreground">{t("certificates.health.description")}</p>
        </div>
        <span className={`inline-flex min-h-8 items-center gap-2 rounded-md border px-2.5 text-sm font-medium ${stateClass}`}>
          {stateIcon}
          {stateLabel}
        </span>
      </div>
      <div className="mt-4 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <HealthStat label={t("certificates.health.totalInventory")} value={health.summary.total} />
        <HealthStat label={t("certificates.health.expiring7d")} value={health.summary.expiring_7d} />
        <HealthStat label={t("certificates.health.expiring30d")} value={health.summary.expiring_30d} />
        {/* H5: the strip stopped at 30 days and the buckets stopped at 90, so a
            hierarchy expiring in two years rendered identically to one expiring
            in twenty. This band is where CA expiry actually lives. */}
        <HealthStat label={t("certificates.health.expiringLongHorizon")} value={Math.max(0, (health.summary.expiring_3y ?? 0) - health.summary.expiring_90d)} />
        <HealthStat label={t("certificates.health.externalSources")} value={health.summary.external_source_count} />
      </div>
      <div className="mt-4 grid gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(20rem,1fr)]">
        <div>
          <div className="mb-2 flex items-center gap-2 text-sm font-medium">
            <Activity className="h-4 w-4" aria-hidden="true" />
            {t("certificates.health.sourcePosture")}
          </div>
          <div className="grid gap-2">
            {topSources.map((source) => (
              <div
                key={source.source}
                className="grid grid-cols-[minmax(0,1fr)_auto_auto] items-center gap-3 rounded-md border border-border px-3 py-2 text-sm"
              >
                <span className="truncate font-medium">{source.source}</span>
                <span className="text-muted-foreground">{source.count}</span>
                <span className={source.external ? "text-status-warning" : "text-muted-foreground"}>
                  {source.external ? t("certificates.health.external") : t("certificates.health.issued")}
                </span>
              </div>
            ))}
          </div>
        </div>
        <div>
          <div className="mb-2 text-sm font-medium">{t("certificates.health.soonestExpirations")}</div>
          {soon.length === 0 ? (
            <p className="rounded-md border border-border px-3 py-2 text-sm text-muted-foreground">{t("certificates.health.no90dExpirations")}</p>
          ) : (
            <div className="grid gap-2">
              {soon.map((item) => (
                <div key={item.id} className="grid gap-1 rounded-md border border-border px-3 py-2 text-sm">
                  <div className="flex items-center justify-between gap-3">
                    <span className="min-w-0 truncate font-medium">{item.subject}</span>
                    <span className={item.externally_issued ? "text-status-warning" : "text-muted-foreground"}>{item.days_remaining}d</span>
                  </div>
                  <div className="flex flex-wrap gap-x-3 gap-y-1 text-xs text-muted-foreground">
                    <span>{item.source}</span>
                    <span>{formatDate(item.not_after)}</span>
                    {item.deployment_location && <span>{item.deployment_location}</span>}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </section>
  );
}

function CRLDistributionPanel({ distributions }: { distributions: CRLDistribution[] }) {
  const { t, formatDate } = useTranslation();
  const totalShards = distributions.reduce((sum, item) => sum + (item.shards?.length ?? 0), 0);
  const totalRevoked = distributions.reduce((sum, item) => sum + item.revoked_count, 0);
  return (
    <section aria-labelledby="crl-distribution-heading" className="border-y border-border py-4">
      <h2 id="crl-distribution-heading" className="text-base font-semibold">
        {t("certificates.crl.heading")}
      </h2>
      <p className="mt-1 text-sm text-muted-foreground">
        {distributions.length > 0
          ? t("certificates.crl.summary", {
              caCount: formatCount(distributions.length),
              shardCount: formatCount(totalShards),
              revokedCount: formatCount(totalRevoked),
            })
          : t("certificates.crl.empty")}
      </p>
      {distributions.length > 0 && (
        <ul className="mt-4 grid gap-2">
          {distributions.map((item) => (
            <li key={item.ca_id} className="rounded-md border border-border p-3 text-sm">
              <span className="font-medium">{item.ca_id}</span>
              <div className="mt-1 flex flex-wrap gap-3 text-xs">
                <a className="font-mono text-primary underline" href={item.full_url}>
                  #{item.full_number}
                </a>
                <span>
                  {formatCount(item.shards?.length ?? 0)} · {t("certificates.crl.shardPlan", { shardCount: formatCount(item.shard_count) })}
                </span>
                {item.delta_url && (
                  <a className="font-mono text-primary underline" href={item.delta_url}>
                    {t("certificates.crl.deltaBase", { base: item.delta_base_number ?? "" })}
                  </a>
                )}
                <span>
                  {formatDate(item.this_update)} → {formatDate(item.next_update)}
                </span>
              </div>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

function RevocationHealthPanel({ health }: { health: RevocationHealth }) {
  const { t, formatDate } = useTranslation();
  const statusLabel = (status: RevocationHealth["items"][number]["status"]): string =>
    t(
      status === "fresh"
        ? "certificates.health.stateOk"
        : status === "expiring"
          ? "nav.task.expiringSoon.label"
          : status === "stale"
            ? "secrets.rotationHealth.stale"
            : status === "unparseable"
              ? "integrate.gitops.invalid"
              : "protocols.ari.failed",
    );
  const statusTone = (status: RevocationHealth["items"][number]["status"]) =>
    status === "fresh" ? "success" : status === "expiring" || status === "unreachable" ? "warning" : "critical";
  return (
    <section aria-labelledby="revocation-health-heading" className="border-y border-border py-4">
      <h2 id="revocation-health-heading" className="text-base font-semibold">
        {t("source.revocation.r2cap00001")}
      </h2>
      {health.observed && (
        <ul className="mt-4 grid gap-2">
          {health.items.map((item) => (
            <li key={item.target_key} className="rounded-md border border-border p-3 text-sm">
              <div className="flex items-start justify-between gap-3">
                <span className="min-w-0 truncate font-mono text-xs">{item.endpoint}</span>
                <StatusBadge value={item.status} tone={statusTone(item.status)} label={statusLabel(item.status)} />
              </div>
              <p className="mt-1 text-xs text-muted-foreground">
                {item.protocol.toUpperCase()} · {item.issuer_subject} · {item.signature_verified ? t("source.verified.j2dr000007") : item.detail_code} ·{" "}
                {item.next_update ? formatDate(item.next_update) : formatDate(item.observed_at)} · {item.observed_by_agent_name} ·{" "}
                <span className="font-mono">{item.evidence_digest.slice(0, 12)}…</span>
              </p>
            </li>
          ))}
        </ul>
      )}
      <p className="mt-3 text-xs text-muted-foreground">{health.guidance}</p>
    </section>
  );
}

type RogueCertificateFinding = RogueCertificatePosture["findings"][number];

function roguePolicyLabel(finding: RogueCertificateFinding, t: (key: MessageKey, values?: Record<string, number | string>) => string): string {
  return finding.policy_status === "rogue" ? t("certificates.rogue.policyRogue") : t("certificates.rogue.policyNonCompliant");
}

function rogueTypeLabel(type: string, t: (key: MessageKey, values?: Record<string, number | string>) => string): string {
  const keys: Partial<Record<string, MessageKey>> = {
    ct_unexpected_issuance: "certificates.rogue.typeCTUnexpected",
    not_in_inventory: "certificates.rogue.typeNotInInventory",
    weak_key_algorithm: "certificates.rogue.typeWeakKey",
    lifetime_exceeds_policy: "certificates.rogue.typeLifetime",
    expired_active_certificate: "certificates.rogue.typeExpiredActive",
    owner_missing: "certificates.rogue.typeOwnerMissing",
    issuer_missing: "certificates.rogue.typeIssuerMissing",
  };
  const key = keys[type];
  return key ? t(key) : type.replaceAll("_", " ");
}

function severityClass(severity: RogueCertificateFinding["severity"]): string {
  switch (severity) {
    case "critical":
      return "border-destructive/40 bg-destructive/10 text-destructive";
    case "high":
      return "border-status-warning/50 bg-status-warning/10 text-status-warning";
    case "medium":
      return "border-primary/30 bg-primary/10 text-primary";
    default:
      return "border-border bg-muted text-muted-foreground";
  }
}

function RogueCertificatePanel({ posture }: { posture: RogueCertificatePosture }) {
  const { t } = useTranslation();
  const findings = posture.findings.slice(0, 6);
  const highOrCritical = posture.summary.critical + posture.summary.high;
  return (
    <section aria-labelledby="rogue-certificates-heading" className="border-y border-border py-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 id="rogue-certificates-heading" className="text-base font-semibold">
            {t("certificates.rogue.heading")}
          </h2>
          <p className="mt-1 text-sm text-muted-foreground">{t("certificates.rogue.description")}</p>
        </div>
        <span
          className={`inline-flex min-h-8 items-center gap-2 rounded-md border px-2.5 text-sm font-medium ${highOrCritical > 0 ? "border-destructive/40 bg-destructive/10 text-destructive" : "border-status-success/40 bg-status-success/10 text-status-success"}`}
        >
          {highOrCritical > 0 ? <AlertTriangle className="h-4 w-4" aria-hidden="true" /> : <ShieldCheck className="h-4 w-4" aria-hidden="true" />}
          {t("certificates.rogue.findingBadge", { count: formatCount(posture.summary.findings) })}
        </span>
      </div>
      <div className="mt-4 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <HealthStat label={t("certificates.rogue.metricRogue")} value={posture.summary.rogue} />
        <HealthStat label={t("certificates.rogue.metricNonCompliant")} value={posture.summary.non_compliant} />
        <HealthStat label={t("certificates.rogue.metricCT")} value={posture.summary.ct_unexpected} />
        <HealthStat label={t("certificates.rogue.metricHigh")} value={highOrCritical} />
      </div>
      {findings.length === 0 ? (
        <p className="mt-4 rounded-md border border-border px-3 py-2 text-sm text-muted-foreground">{t("certificates.rogue.empty")}</p>
      ) : (
        <div className="mt-4 overflow-x-auto">
          <table className="min-w-full text-left text-sm">
            <caption className="sr-only">{t("certificates.rogue.caption")}</caption>
            <thead className="border-b border-border text-xs text-muted-foreground">
              <tr>
                <th scope="col" className="py-2 pr-4 font-medium">
                  {t("certificates.rogue.columnSubject")}
                </th>
                <th scope="col" className="px-4 py-2 font-medium">
                  {t("certificates.rogue.columnStatus")}
                </th>
                <th scope="col" className="px-4 py-2 font-medium">
                  {t("certificates.rogue.columnSeverity")}
                </th>
                <th scope="col" className="px-4 py-2 font-medium">
                  {t("certificates.rogue.columnEvidence")}
                </th>
                <th scope="col" className="pl-4 py-2 font-medium">
                  {t("certificates.rogue.columnRecommendation")}
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {findings.map((finding) => (
                <tr key={finding.id}>
                  <td className="py-2 pr-4 align-top">
                    <span className="block max-w-[18rem] truncate font-medium">{finding.subject}</span>
                    <span className="block max-w-[18rem] truncate text-xs text-muted-foreground">
                      {finding.dns_names?.slice(0, 2).join(", ") || finding.source}
                    </span>
                  </td>
                  <td className="px-4 py-2 align-top">
                    <span className="block font-medium">{roguePolicyLabel(finding, t)}</span>
                    <span className="block max-w-[16rem] text-xs text-muted-foreground">
                      {finding.finding_types.map((type) => rogueTypeLabel(type, t)).join(", ")}
                    </span>
                  </td>
                  <td className="px-4 py-2 align-top">
                    <span className={`inline-flex min-h-7 items-center rounded-md border px-2 text-xs font-medium ${severityClass(finding.severity)}`}>
                      {finding.severity}
                    </span>
                    <span className="mt-1 block text-xs text-muted-foreground">
                      {t("certificates.rogue.riskScore", { score: formatCount(finding.risk_score) })}
                    </span>
                  </td>
                  <td className="px-4 py-2 align-top">
                    <span className="block max-w-[16rem] break-all font-mono text-xs text-muted-foreground">
                      {finding.evidence_refs.slice(0, 2).join(", ")}
                    </span>
                  </td>
                  <td className="pl-4 py-2 align-top">
                    <span className="block max-w-[24rem] text-sm">{finding.recommendation}</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

function CTSubmissionPanel({
  loading,
  error,
  result,
  certificatePEM,
  precertificatePEM,
  chainPEM,
  logs,
  allowPrivate,
  onCertificatePEM,
  onPrecertificatePEM,
  onChainPEM,
  onLogs,
  onAllowPrivate,
  onSubmit,
  className,
}: {
  loading: boolean;
  error: Notice | null;
  result: CTSubmission | null;
  certificatePEM: string;
  precertificatePEM: string;
  chainPEM: string;
  logs: string;
  allowPrivate: boolean;
  onCertificatePEM: (value: string) => void;
  onPrecertificatePEM: (value: string) => void;
  onChainPEM: (value: string) => void;
  onLogs: (value: string) => void;
  onAllowPrivate: (value: boolean) => void;
  onSubmit: (event: FormEvent<HTMLFormElement>) => void;
  className?: string;
}) {
  const { t } = useTranslation();
  return (
    <section aria-labelledby="ct-submission-heading" className={className ?? "border-y border-border py-4"}>
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 id="ct-submission-heading" className="text-base font-semibold">
            {t("certificates.ct.heading")}
          </h2>
        </div>
        {result && (
          <span className="inline-flex min-h-8 items-center gap-2 rounded-md border border-status-success/40 bg-status-success/10 px-2.5 text-sm font-medium text-status-success">
            {t("certificates.ct.queuedBadge", { capability: result.capability, queued: formatCount(result.queued) })}
          </span>
        )}
      </div>
      <form onSubmit={onSubmit} className="mt-4 grid gap-3">
        <div className="grid gap-3 lg:grid-cols-2">
          <label className="grid gap-1 text-sm font-medium" htmlFor="ct-certificate-pem">
            {t("certificates.ct.certificatePEM")}
            <textarea
              id="ct-certificate-pem"
              value={certificatePEM}
              onChange={(event) => onCertificatePEM(event.target.value)}
              rows={6}
              className="w-full rounded-md border border-border bg-background px-3 py-2 font-mono text-xs"
              placeholder={translateNow("source.begin.certificate.ddddb6cbd3")}
            />
          </label>
          <label className="grid gap-1 text-sm font-medium" htmlFor="ct-precertificate-pem">
            {t("certificates.ct.precertificatePEM")}
            <textarea
              id="ct-precertificate-pem"
              value={precertificatePEM}
              onChange={(event) => onPrecertificatePEM(event.target.value)}
              rows={6}
              className="w-full rounded-md border border-border bg-background px-3 py-2 font-mono text-xs"
              placeholder={translateNow("source.begin.certificate.ddddb6cbd3")}
            />
          </label>
        </div>
        <div className="grid gap-3 lg:grid-cols-[minmax(0,1fr)_minmax(16rem,0.7fr)]">
          <label className="grid gap-1 text-sm font-medium" htmlFor="ct-chain-pem">
            {t("certificates.ct.chainPEM")}
            <textarea
              id="ct-chain-pem"
              value={chainPEM}
              onChange={(event) => onChainPEM(event.target.value)}
              rows={4}
              className="w-full rounded-md border border-border bg-background px-3 py-2 font-mono text-xs"
              placeholder={t("certificates.ct.chainPlaceholder")}
            />
          </label>
          <label className="grid gap-1 text-sm font-medium" htmlFor="ct-log-urls">
            {t("certificates.ct.logs")}
            <textarea
              id="ct-log-urls"
              value={logs}
              onChange={(event) => onLogs(event.target.value)}
              rows={4}
              className="w-full rounded-md border border-border bg-background px-3 py-2 font-mono text-xs"
              placeholder={t("certificates.ct.logsPlaceholder")}
            />
          </label>
        </div>
        <div className="flex flex-wrap items-center justify-between gap-3">
          <label className="inline-flex items-center gap-2 text-sm font-medium" htmlFor="ct-allow-private">
            <input
              id="ct-allow-private"
              type="checkbox"
              checked={allowPrivate}
              onChange={(event) => onAllowPrivate(event.target.checked)}
              className="h-4 w-4 rounded border-border"
            />
            {t("certificates.ct.allowPrivate")}
          </label>
          <button
            type="submit"
            disabled={loading}
            className="inline-flex min-h-10 items-center justify-center gap-2 rounded-md bg-primary px-3 py-2 text-sm font-medium text-primary-foreground disabled:opacity-60"
          >
            <Send className="h-4 w-4" aria-hidden="true" />
            {loading ? t("certificates.ct.queueing") : t("certificates.ct.queue")}
          </button>
        </div>
      </form>
      {error?.kind === "permission" && <PermissionDeniedState>{error.message}</PermissionDeniedState>}
      {error?.kind === "error" && <ErrorState title={t("certificates.ct.errorTitle")}>{error.message}</ErrorState>}
      {result && (
        <p role="status" className="mt-3 text-sm text-status-success">
          {t(result.logs.length === 1 ? "certificates.ct.acceptedOne" : "certificates.ct.acceptedMany", { count: formatCount(result.logs.length) })}
        </p>
      )}
    </section>
  );
}

function HealthStat({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded-md border border-border px-3 py-2">
      <div className="text-xs text-muted-foreground">{label}</div>
      <div className="text-xl font-semibold">{value}</div>
    </div>
  );
}

export function Certificates() {
  // The app supplies a shared cache. Isolated component workbenches use the
  // same provider, never a second implementation of the live read behavior.
  const hasQueryProvider = useHasAppQueryProvider();
  return hasQueryProvider ? (
    <CertificateWorkspace />
  ) : (
    <AppQueryProvider>
      <CertificateWorkspace />
    </AppQueryProvider>
  );
}

function CertificateWorkspace() {
  const { t, formatDate, formatDateTime } = useTranslation();
  const { user } = useAuth();
  const [searchParams, setSearchParams] = useSearchParams();
  const [certificates, setCertificates] = useState<Certificate[]>([]);
  const [nextCursor, setNextCursor] = useState<string | undefined>();
  const [loading, setLoading] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState<Notice | null>(null);
  const [query, setQuery] = useState("");
  const [expiry, setExpiry] = useState<ExpiryFilter>(() => expiryFromSearchParam(searchParams.get("expiry")));
  const [issuerFilter, setIssuerFilter] = useState<FacetFilter>(() => searchParams.get("issuer") ?? "all");
  const [profileFilter, setProfileFilter] = useState<FacetFilter>(() => searchParams.get("profile") ?? "all");
  const [teamFilter, setTeamFilter] = useState<FacetFilter>(() => searchParams.get("team") ?? "all");
  const [environmentFilter, setEnvironmentFilter] = useState<FacetFilter>(() => searchParams.get("environment") ?? "all");
  const [limit, setLimit] = useState(20);
  const [detailID, setDetailID] = useState<string | null>(null);
  const [detail, setDetail] = useState<Certificate | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState<Notice | null>(null);
  const [showIngest, setShowIngest] = useState(false);
  const [ingestStep, setIngestStep] = useState(0);
  const [pem, setPem] = useState("");
  const [ownerID, setOwnerID] = useState("");
  const [source, setSource] = useState("manual-ui");
  const [deploymentLocation, setDeploymentLocation] = useState("");
  const [ingestLoading, setIngestLoading] = useState(false);
  const [ingestError, setIngestError] = useState<Notice | null>(null);
  const [ingestSuccess, setIngestSuccess] = useState<string | null>(null);
  const [rotationRuns, setRotationRuns] = useState<RotationRun[]>([]);
  const [deliveries, setDeliveries] = useState<ConnectorDelivery[]>([]);
  const [rotationRunsObserved, setRotationRunsObserved] = useState(false);
  const [deliveriesObserved, setDeliveriesObserved] = useState(false);
  const [owners, setOwners] = useState<Owner[]>([]);
  const [identities, setIdentities] = useState<Identity[]>([]);
  const [ownersObserved, setOwnersObserved] = useState(false);
  const [identitiesObserved, setIdentitiesObserved] = useState(false);
  const [notifications, setNotifications] = useState<Notification[] | null>(null);
  const [notificationChannels, setNotificationChannels] = useState<NotificationChannel[] | null>(null);
  const [notificationRoutingPolicies, setNotificationRoutingPolicies] = useState<NotificationRoutingPolicy[] | null>(null);
  const [renewingIds, setRenewingIds] = useState<Set<string>>(() => new Set());
  const healthQuery = useApiQuery<CertificateHealthDashboard | null>(
    ["certificate-health", user?.tenant_id ?? null, user?.subject ?? null, (user?.permissions ?? []).join("|")],
    async ({ signal }) => (await api.certificateHealth(signal)) ?? null,
    { live: { intervalMs: 30_000 }, enabled: typeof api.certificateHealth === "function" },
  );
  const health = healthQuery.data;
  const [crlDistributions, setCRLDistributions] = useState<CRLDistribution[]>([]);
  const [revocationHealth, setRevocationHealth] = useState<RevocationHealth | null>(null);
  const [roguePosture, setRoguePosture] = useState<RogueCertificatePosture | null>(null);
  const [ctCertificatePEM, setCTCertificatePEM] = useState("");
  const [ctPrecertificatePEM, setCTPrecertificatePEM] = useState("");
  const [ctChainPEM, setCTChainPEM] = useState("");
  const [ctLogs, setCTLogs] = useState("");
  const [ctAllowPrivate, setCTAllowPrivate] = useState(false);
  const [ctLoading, setCTLoading] = useState(false);
  const [ctError, setCTError] = useState<Notice | null>(null);
  const [ctResult, setCTResult] = useState<CTSubmission | null>(null);
  const [ctDialogOpen, setCTDialogOpen] = useState(false);
  const [tab, setTab] = useState<CertificatesTab>(() => tabFromSearchParam(searchParams.get("tab")));
  const [selectedIds, setSelectedIds] = useState<Set<string>>(() => new Set());
  const [bulkRevokeOpen, setBulkRevokeOpen] = useState(false);
  const [bulkReason, setBulkReason] = useState<BulkRevokeRequest["reason"]>("keyCompromise");
  const [bulkBusy, setBulkBusy] = useState(false);
  const [bulkError, setBulkError] = useState<string | null>(null);
  const { toast } = useToast();

  useEffect(() => {
    let cancelled = false;
    Promise.all([
      settleOptional(() => api.crlDistributions()),
      settleOptional(() => api.revocationHealth()),
      settleOptional(() => api.rogueCertificates()),
      settleOptional(() => api.rotationRuns({ limit: 100 })),
      settleOptional(() => api.connectorDeliveries({ limit: 50 })),
      settleOptional(() => api.owners()),
      settleOptional(() => api.identities()),
      settleOptional(() => api.notifications({ limit: 100 })),
      settleOptional(() => api.notificationChannels()),
      settleOptional(() => api.notificationRoutingPolicies()),
    ]).then(
      ([
        crlResult,
        revocationResult,
        rogueResult,
        rotationResult,
        deliveryResult,
        ownerResult,
        identityResult,
        notificationResult,
        channelResult,
        policyResult,
      ]) => {
        if (cancelled) return;
        if (crlResult) setCRLDistributions(crlResult.items ?? []);
        if (revocationResult) setRevocationHealth(revocationResult);
        if (rogueResult) setRoguePosture(rogueResult);
        if (rotationResult) {
          setRotationRuns(rotationResult.items ?? []);
          setRotationRunsObserved(true);
        }
        if (deliveryResult) {
          setDeliveries(deliveryResult.items ?? []);
          setDeliveriesObserved(true);
        }
        if (ownerResult) {
          setOwners(ownerResult);
          setOwnersObserved(true);
        }
        if (identityResult) {
          setIdentities(identityResult);
          setIdentitiesObserved(true);
        }
        if (notificationResult) setNotifications(notificationResult.items ?? []);
        if (channelResult) setNotificationChannels(channelResult.items ?? []);
        if (policyResult) setNotificationRoutingPolicies(policyResult.items ?? []);
      },
    );
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    api
      .certificatePage({ limit, expiringBefore: expiringBefore(expiry) })
      .then((page) => {
        if (cancelled) return;
        setCertificates(page.items ?? []);
        setNextCursor(page.next_cursor || undefined);
      })
      .catch((err: unknown) => {
        if (!cancelled) setError(noticeForError(err, "read certificate inventory"));
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [expiry, limit]);

  async function loadNextPage() {
    if (!nextCursor) return;
    setLoadingMore(true);
    setError(null);
    try {
      const page = await api.certificatePage({
        limit,
        cursor: nextCursor,
        expiringBefore: expiringBefore(expiry),
      });
      setCertificates((current) => [...current, ...(page.items ?? [])]);
      setNextCursor(page.next_cursor || undefined);
    } catch (err) {
      setError(noticeForError(err, "page certificate inventory"));
    } finally {
      setLoadingMore(false);
    }
  }

  function selectTab(next: string) {
    const value = tabFromSearchParam(next);
    setTab(value);
    setSearchParams(
      (current) => {
        const nextParams = new URLSearchParams(current);
        if (value === "inventory") {
          nextParams.delete("tab");
        } else {
          nextParams.set("tab", value);
        }
        return nextParams;
      },
      { replace: true },
    );
  }

  function selectExpiry(nextExpiry: ExpiryFilter) {
    setExpiry(nextExpiry);
    setSearchParams(
      (current) => {
        const next = new URLSearchParams(current);
        if (nextExpiry === "all") {
          next.delete("expiry");
        } else {
          next.set("expiry", nextExpiry);
        }
        return next;
      },
      { replace: true },
    );
  }

  function selectFacet(key: "environment" | "issuer" | "profile" | "team", value: FacetFilter) {
    if (key === "issuer") setIssuerFilter(value);
    if (key === "profile") setProfileFilter(value);
    if (key === "team") setTeamFilter(value);
    if (key === "environment") setEnvironmentFilter(value);
    setSearchParams(
      (current) => {
        const next = new URLSearchParams(current);
        if (value === "all") {
          next.delete(key);
        } else {
          next.set(key, value);
        }
        return next;
      },
      { replace: true },
    );
  }

  function restoreCertificateGridView(metadata: Record<string, GridViewPrimitive>) {
    const nextExpiry = expiryFromGridMetadata(metadata);
    const nextIssuer = stringFromGridMetadata(metadata, "issuer");
    const nextProfile = stringFromGridMetadata(metadata, "profile");
    const nextTeam = stringFromGridMetadata(metadata, "team");
    const nextEnvironment = stringFromGridMetadata(metadata, "environment");

    setQuery(stringFromGridMetadata(metadata, "query", ""));
    setExpiry(nextExpiry);
    setIssuerFilter(nextIssuer);
    setProfileFilter(nextProfile);
    setTeamFilter(nextTeam);
    setEnvironmentFilter(nextEnvironment);
    setLimit(limitFromGridMetadata(metadata, limit));
    setSearchParams(
      (current) => {
        const next = new URLSearchParams(current);
        setOptionalParam(next, "expiry", nextExpiry);
        setOptionalParam(next, "issuer", nextIssuer);
        setOptionalParam(next, "profile", nextProfile);
        setOptionalParam(next, "team", nextTeam);
        setOptionalParam(next, "environment", nextEnvironment);
        return next;
      },
      { replace: true },
    );
  }

  async function openDetail(c: Certificate) {
    setDetailID(c.id);
    setDetail(null);
    setDetailLoading(true);
    setDetailError(null);
    try {
      setDetail(await api.getCertificate(c.id));
    } catch (err) {
      setDetailError(noticeForError(err, "read certificate detail"));
    } finally {
      setDetailLoading(false);
    }
  }

  async function submitIngest(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setIngestError(null);
    setIngestSuccess(null);
    if (!pem.trim()) {
      setIngestError({ kind: "error", message: translateNow("source.pem.is.required.0a8b6ce9cc") });
      return;
    }
    setIngestLoading(true);
    try {
      const cert = await api.ingestCertificate({
        pem,
        owner_id: ownerID.trim() || undefined,
        source: source.trim() || undefined,
        deployment_location: deploymentLocation.trim() || undefined,
      });
      setCertificates((current) => [cert, ...current.filter((c) => c.id !== cert.id)]);
      setPem("");
      setOwnerID("");
      setDeploymentLocation("");
      setSource("manual-ui");
      setIngestSuccess(`Ingested ${cert.subject}.`);
      healthQuery.refetch();
    } catch (err) {
      setIngestError(noticeForError(err, "ingest a certificate"));
    } finally {
      setIngestLoading(false);
    }
  }

  async function submitCT(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setCTError(null);
    setCTResult(null);
    const logs = splitCertificateLines(ctLogs);
    if (!ctCertificatePEM.trim()) {
      setCTError({ kind: "error", message: t("certificates.ct.errorCertificateRequired") });
      return;
    }
    if (logs.length === 0) {
      setCTError({ kind: "error", message: t("certificates.ct.errorLogRequired") });
      return;
    }
    setCTLoading(true);
    try {
      setCTResult(
        await api.submitCertificateTransparency({
          certificate_pem: ctCertificatePEM,
          precertificate_pem: ctPrecertificatePEM.trim() || undefined,
          chain_pem: splitPEMBlocks(ctChainPEM),
          logs,
          allow_private_endpoint: ctAllowPrivate || undefined,
        }),
      );
    } catch (err) {
      setCTError(noticeForError(err, t("certificates.ct.action")));
    } finally {
      setCTLoading(false);
    }
  }

  /** submitBulkRevoke sends ONE bulk revocation request for every selected
   * certificate (no client-side fan-out) and reports the server's per-item
   * totals, then refreshes the first inventory page. */
  async function submitBulkRevoke() {
    const ids = Array.from(selectedIds);
    if (ids.length === 0) return;
    setBulkBusy(true);
    setBulkError(null);
    try {
      const result = await api.bulkRevokeCertificates({ certificate_ids: ids, reason: bulkReason });
      healthQuery.refetch();
      setBulkRevokeOpen(false);
      setSelectedIds(new Set());
      toast({
        kind: result.total_failed > 0 ? "warning" : "success",
        title: `Revoked ${result.total_revoked} of ${result.total_matched}`,
        description: `Skipped ${result.total_skipped}, failed ${result.total_failed}.`,
      });
      const page = await settleOptional(() => api.certificatePage({ limit, expiringBefore: expiringBefore(expiry) }));
      if (page) {
        setCertificates(page.items ?? []);
        setNextCursor(page.next_cursor || undefined);
      }
    } catch (err) {
      setBulkError(noticeForError(err, "bulk revoke certificates").message);
    } finally {
      setBulkBusy(false);
    }
  }

  function recordReviewedRevocation(updated: Identity) {
    setIdentities((current) => current.map((identity) => (identity.id === updated.id ? updated : identity)));
    toast({
      kind: "success",
      title: t("certificates.revocation.accepted"),
      description: t("certificates.revocation.description"),
    });
    healthQuery.refetch();
    void Promise.all([
      settleOptional(() => api.certificatePage({ limit, expiringBefore: expiringBefore(expiry) })),
      settleOptional(() => api.crlDistributions()),
      settleOptional(() => api.revocationHealth()),
    ]).then(([page, nextCRLs, nextRevocationHealth]) => {
      if (page) {
        setCertificates(page.items ?? []);
        setNextCursor(page.next_cursor || undefined);
      }
      if (nextCRLs) setCRLDistributions(nextCRLs.items ?? []);
      if (nextRevocationHealth) setRevocationHealth(nextRevocationHealth);
    });
  }

  function recordExactCertificateRevocation(updated: Certificate) {
    setCertificates((current) => current.map((certificate) => (certificate.id === updated.id ? updated : certificate)));
    toast({
      kind: "success",
      title: t("certificates.revocation.certificateAccepted"),
      description: t("certificates.revocation.description"),
    });
    healthQuery.refetch();
    void Promise.all([
      settleOptional(() => api.certificatePage({ limit, expiringBefore: expiringBefore(expiry) })),
      settleOptional(() => api.crlDistributions()),
      settleOptional(() => api.revocationHealth()),
    ]).then(([page, nextCRLs, nextRevocationHealth]) => {
      if (page) {
        setCertificates(page.items ?? []);
        setNextCursor(page.next_cursor || undefined);
      }
      if (nextCRLs) setCRLDistributions(nextCRLs.items ?? []);
      if (nextRevocationHealth) setRevocationHealth(nextRevocationHealth);
    });
  }

  const ownerByID = useMemo(() => new Map(owners.map((owner) => [owner.id, owner])), [owners]);
  const identityByCN = useMemo(() => {
    const map = new Map<string, Identity>();
    for (const identity of identities) {
      if (identity.kind !== "x509_certificate") continue;
      map.set(identity.name.trim().toLowerCase(), identity);
    }
    return map;
  }, [identities]);

  /** startRenew advances the MANAGING IDENTITY to `renewing` (the same
   * idempotent transition the Identities page uses), so the expiring-certs
   * worklist can finish Job 1 without a page hop (S-N1 / DA-05). */
  async function startRenew(certificate: Certificate, identity: Identity) {
    setRenewingIds((current) => new Set(current).add(certificate.id));
    try {
      await api.transitionIdentity(identity.id, "renewing", `renew requested from certificate inventory (${certificate.subject})`);
      toast({
        title: t("certificates.lifecycle.renewStarted"),
        description: `${identity.name} is now renewing; track progress on Identities.`,
      });
    } catch (err) {
      toast({
        kind: "error",
        title: t("certificates.lifecycle.renewFailed"),
        description: err instanceof Error ? err.message : String(err),
      });
    } finally {
      setRenewingIds((current) => {
        const next = new Set(current);
        next.delete(certificate.id);
        return next;
      });
    }
  }
  const issuerOptions = useMemo(
    () =>
      uniqueOptions(
        certificates.map((certificate) => certificate.issuer),
        issuerFilter,
      ),
    [certificates, issuerFilter],
  );
  const profileOptions = useMemo(
    () =>
      uniqueOptions(
        certificates.map((certificate) => certificateProfile(certificate)),
        profileFilter,
      ),
    [certificates, profileFilter],
  );
  const environmentOptions = useMemo(
    () =>
      uniqueOptions(
        certificates.map((certificate) => certificateEnvironment(certificate)),
        environmentFilter,
      ),
    [certificates, environmentFilter],
  );
  const teamOptions = useMemo(() => teamFacetOptions(certificates, ownerByID, owners, teamFilter), [certificates, ownerByID, owners, teamFilter]);
  const columns = useMemo(
    () =>
      certificateColumns(
        ownerByID,
        formatDate,
        lifecycleColumn({
          identityByCN,
          renewingIds,
          onRenew: (c, i) => void startRenew(c, i),
          replaceLabel: t("certificates.lifecycle.replaceViaRequest"),
        }),
      ),
    // eslint-disable-next-line react-hooks/exhaustive-deps -- startRenew is stable per render semantics used across this page
    [ownerByID, identityByCN, renewingIds, t, formatDate],
  );

  const filtered = useMemo(() => {
    const all = certificates;
    const q = query.trim().toLowerCase();
    return all.filter((c) => {
      if (issuerFilter !== "all" && c.issuer !== issuerFilter) return false;
      if (profileFilter !== "all" && certificateProfile(c) !== profileFilter) return false;
      if (teamFilter !== "all" && certificateTeamID(c, ownerByID) !== teamFilter) return false;
      if (environmentFilter !== "all" && certificateEnvironment(c) !== environmentFilter) return false;
      if (!q) return true;
      return [
        certificateDisplayName(c),
        ...(c.sans ?? []),
        c.issuer,
        c.status,
        c.fingerprint,
        c.serial,
        c.deployment_location,
        certificateProfile(c),
        certificateEnvironment(c),
        certificateTeamLabel(c, ownerByID),
      ]
        .filter(Boolean)
        .some((v) => v!.toLowerCase().includes(q));
    });
  }, [certificates, environmentFilter, issuerFilter, ownerByID, profileFilter, query, teamFilter]);

  return (
    <section aria-labelledby="certs-heading" className="min-w-0 max-w-full">
      <PageHeader
        titleId="certs-heading"
        title={t("nav.item.certificates")}
        description="See which certificates are healthy, which expire soon, and what needs action."
        technicalDetails="Exact evidence includes the subject and SANs, serial number, issuer chain, validity window, source, owner, deployment receipt, renewal job, revocation state, CRL and CT state, and immutable events. Private keys are never displayed."
        actions={
          <Button type="button" onClick={() => setShowIngest((v) => !v)}>
            {showIngest ? translateNow("source.close.ingest.9381182077") : translateNow("source.add.certificate.6fa2cfd67c")}
          </Button>
        }
      />

      {showIngest && (
        <form onSubmit={submitIngest} aria-labelledby="ingest-heading" className="mb-6 grid gap-4">
          <h2 id="ingest-heading" className="sr-only">
            {translateNow("source.add.certificate.6fa2cfd67c")}
          </h2>
          <StepShell
            steps={ingestSteps(t)}
            currentIndex={ingestStep}
            nextDisabled={ingestStep === 0 ? !pem.trim() : ingestStep >= 2}
            nextLabel={ingestStep === 0 ? t("certificates.ingest.nextPlacement") : t("certificates.ingest.nextReview")}
            onNext={ingestStep < 2 ? () => setIngestStep((current) => Math.min(current + 1, 2)) : undefined}
            onPrevious={() => setIngestStep((current) => Math.max(current - 1, 0))}
          >
            {ingestStep === 0 && (
              <label className="grid gap-1 text-sm font-medium" htmlFor="cert-pem">
                {translateNow("source.certificate.pem.85627425ca")}
                <textarea
                  id="cert-pem"
                  value={pem}
                  onChange={(e) => setPem(e.target.value)}
                  rows={8}
                  className="w-full rounded-md border border-border bg-background px-3 py-2 font-mono text-xs"
                  placeholder={translateNow("source.begin.certificate.ddddb6cbd3")}
                />
              </label>
            )}
            {ingestStep === 1 && (
              <div className="grid gap-3 md:grid-cols-3">
                <label className="grid gap-1 text-sm font-medium" htmlFor="cert-owner">
                  {translateNow("source.owner.id.1611f5e055")}
                  {/* Autocomplete from the loaded owner roster — no pasting owner
                      UUIDs from another page. */}
                  <input
                    id="cert-owner"
                    value={ownerID}
                    onChange={(e) => setOwnerID(e.target.value)}
                    list="cert-owner-options"
                    className="rounded-md border border-border bg-background px-3 py-2 text-sm font-normal"
                    placeholder={translateNow("source.optional.ec91fdd925")}
                  />
                  <datalist id="cert-owner-options">
                    {owners.map((owner) => (
                      <option key={owner.id} value={owner.id}>
                        {owner.name}
                      </option>
                    ))}
                  </datalist>
                </label>
                <label className="grid gap-1 text-sm font-medium" htmlFor="cert-source">
                  {translateNow("source.source.0e570ca6fa")}
                  <input
                    id="cert-source"
                    value={source}
                    onChange={(e) => setSource(e.target.value)}
                    className="rounded-md border border-border bg-background px-3 py-2 text-sm"
                  />
                </label>
                <label className="grid gap-1 text-sm font-medium" htmlFor="cert-location">
                  {translateNow("source.deployment.location.5a9f62f9fc")}
                  <input
                    id="cert-location"
                    value={deploymentLocation}
                    onChange={(e) => setDeploymentLocation(e.target.value)}
                    className="rounded-md border border-border bg-background px-3 py-2 text-sm"
                    placeholder={translateNow("source.cluster.service.path.f9947d11c2")}
                  />
                </label>
              </div>
            )}
            {ingestStep === 2 && (
              <div className="grid max-w-xl gap-4">
                <dl className="grid gap-2 rounded-panel border border-border bg-muted/40 p-3 text-sm">
                  <div className="flex items-center justify-between gap-3">
                    <dt className="text-caption text-muted-foreground">{translateNow("source.certificate.pem.85627425ca")}</dt>
                    <dd className="font-mono text-xs">{translateNow("source.value1.lines.a4d63c8ae4", { value1: pem.trim().split("\n").length })}</dd>
                  </div>
                  <div className="flex items-center justify-between gap-3">
                    <dt className="text-caption text-muted-foreground">{translateNow("source.owner.id.1611f5e055")}</dt>
                    <dd>{owners.find((owner) => owner.id === ownerID)?.name ?? (ownerID.trim() || t("certificates.ingest.ownerUnassigned"))}</dd>
                  </div>
                  <div className="flex items-center justify-between gap-3">
                    <dt className="text-caption text-muted-foreground">{translateNow("source.source.0e570ca6fa")}</dt>
                    <dd>{source.trim() || "—"}</dd>
                  </div>
                  <div className="flex items-center justify-between gap-3">
                    <dt className="text-caption text-muted-foreground">{translateNow("source.deployment.location.5a9f62f9fc")}</dt>
                    <dd>{deploymentLocation.trim() || "—"}</dd>
                  </div>
                </dl>
                {ingestError?.kind === "permission" && <PermissionDeniedState>{ingestError.message}</PermissionDeniedState>}
                {ingestError?.kind === "error" && (
                  <ErrorState title={translateNow("source.could.not.ingest.certificate.f876a7f9c6")}>{ingestError.message}</ErrorState>
                )}
                {ingestSuccess && (
                  <p role="status" className="text-sm text-status-success">
                    {ingestSuccess}
                  </p>
                )}
                <div>
                  <Button type="submit" loading={ingestLoading}>
                    {translateNow("source.ingest.certificate.6c25a63cd4")}
                  </Button>
                </div>
              </div>
            )}
          </StepShell>
        </form>
      )}

      {loading && <LoadingState>{translateNow("source.loading.certificates.3ed54a94d8")}</LoadingState>}
      {error?.kind === "permission" && <PermissionDeniedState>{error.message}</PermissionDeniedState>}
      {error?.kind === "error" && <ErrorState title={translateNow("source.could.not.load.certificates.21ae8e6e19")}>{error.message}</ErrorState>}

      {!loading && certificates.length === 0 && !error && (
        <EmptyState
          icon={<FilePlus2 className="h-5 w-5" aria-hidden="true" />}
          title={translateNow("source.no.certificates.yet.f1e2ab559a")}
          primaryAction={{ label: translateNow("source.issue.first.certificate.4d8af98e7d"), to: "/request", icon: <FilePlus2 className="h-4 w-4" /> }}
          secondaryAction={{ label: translateNow("source.connect.an.issuer.c155ecb073"), to: "/ca-hierarchy", icon: <PlugZap className="h-4 w-4" /> }}
        >
          {translateNow("source.start.with.a.profile.bound.request.or.conn.19cdbff548")}
        </EmptyState>
      )}

      {certificates.length > 0 && (
        <>
          <PageTabs
            idPrefix="certs"
            ariaLabel="Certificate workspaces"
            active={tab}
            onChange={selectTab}
            tabs={[
              { id: "inventory", label: t("certificates.tabs.inventory") },
              { id: "health", label: t("certificates.tabs.health") },
              { id: "crlct", label: t("certificates.tabs.crlct") },
              { id: "renewal", label: t("certificates.tabs.renewal") },
            ]}
          />
          {tab === "health" && (
            <div {...tabPanelProps("certs", "health")} className="grid gap-4">
              {healthQuery.error ? <ErrorState title={t("certificateCockpit.snapshot.unavailable")} /> : health && <CertificateHealthPanel health={health} />}
              {roguePosture && <RogueCertificatePanel posture={roguePosture} />}
            </div>
          )}
          {tab === "crlct" && (
            <div {...tabPanelProps("certs", "crlct")} className="grid gap-4">
              <RevocationCenter
                certificates={certificates}
                targetCertificateID={searchParams.get("certificate_id") ?? undefined}
                identities={identities}
                health={revocationHealth}
                distributions={crlDistributions}
                onCertificateRevoked={recordExactCertificateRevocation}
                onRevoked={recordReviewedRevocation}
              />
              {revocationHealth && <RevocationHealthPanel health={revocationHealth} />}
              <CRLDistributionPanel distributions={crlDistributions} />
              <section aria-labelledby="ct-launch-heading" className="border-y border-border py-4">
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <div>
                    <h2 id="ct-launch-heading" className="text-base font-semibold">
                      {t("certificates.ct.heading")}
                    </h2>
                    {ctResult ? (
                      <p role="status" className="mt-1 text-sm text-status-success">
                        {t(ctResult.logs.length === 1 ? "certificates.ct.acceptedOne" : "certificates.ct.acceptedMany", {
                          count: formatCount(ctResult.logs.length),
                        })}
                      </p>
                    ) : (
                      <p className="mt-1 text-sm text-muted-foreground">{t("certificates.ct.launchDescription")}</p>
                    )}
                  </div>
                  <Button type="button" variant="secondary" onClick={() => setCTDialogOpen(true)}>
                    <Send className="h-4 w-4" aria-hidden="true" />
                    {t("certificates.ct.launch")}
                  </Button>
                </div>
              </section>
            </div>
          )}
          {tab === "renewal" && (
            <div {...tabPanelProps("certs", "renewal")} className="grid gap-4">
              <div className="grid gap-4 lg:grid-cols-2">
                <ReadinessPanel certificates={certificates} rotationRuns={rotationRuns} />
                <ReadinessSimulator certificates={certificates} autoRenewing={autoRenewingCount(certificates, rotationRuns)} />
              </div>
              <DeploymentReceipts deliveries={deliveries} />
            </div>
          )}
          {tab === "inventory" && (
            <div {...tabPanelProps("certs", "inventory")} className="grid min-w-0 max-w-full gap-4">
              {!health && healthQuery.error && <ErrorState title={t("certificateCockpit.snapshot.unavailable")} />}
              {health && (
                <LifecycleCockpit
                  certificates={certificates}
                  health={health}
                  healthRefreshing={healthQuery.fetching}
                  healthUnavailable={healthQuery.error !== null}
                  onExpiryBoundary={healthQuery.refetch}
                  owners={ownersObserved ? owners : null}
                  identities={identitiesObserved ? identities : null}
                  rotationRuns={rotationRunsObserved ? rotationRuns : null}
                  deliveries={deliveriesObserved ? deliveries : null}
                  notifications={notifications}
                  channels={notificationChannels}
                  routingPolicies={notificationRoutingPolicies}
                />
              )}
              <BulkActionBar count={selectedIds.size} onClear={() => setSelectedIds(new Set())} className="sticky top-0 z-10 mb-3 shadow-elevation1">
                <Button
                  type="button"
                  size="sm"
                  variant="destructive-outline"
                  onClick={() => {
                    setBulkError(null);
                    setBulkRevokeOpen(true);
                  }}
                >
                  {translateNow("source.revoke.selected.38b0352f6d")}
                  {selectedIds.size})…
                </Button>
              </BulkActionBar>
              <DataGrid
                ariaLabel="Inventoried certificates"
                rows={filtered}
                columns={columns}
                getRowId={(c) => c.id}
                selection={{
                  selectedIds,
                  onSelectedIdsChange: setSelectedIds,
                  getRowLabel: certificateDisplayName,
                }}
                state={filtered.length === 0 ? "empty" : "ready"}
                stateTitle="No certificates match your search."
                showColumnChooser
                viewStorageKey="certificates-inventory"
                viewMetadata={{
                  query,
                  expiry,
                  issuer: issuerFilter,
                  profile: profileFilter,
                  team: teamFilter,
                  environment: environmentFilter,
                  limit,
                }}
                onViewRestore={restoreCertificateGridView}
                virtualization={{ rowHeight: 52, viewportHeight: 520, overscan: 6, threshold: 80 }}
                toolbar={({ columnChooser, savedViews }) => (
                  <DataGridToolbar
                    searchLabel="Search loaded rows"
                    searchPlaceholder="Subject, issuer, serial, fingerprint..."
                    searchValue={query}
                    onSearchChange={setQuery}
                    filterSummary={certificateFilterSummary(issuerFilter, profileFilter, teamFilter, environmentFilter, expiry)}
                    resultSummary={
                      filtered.length === 1
                        ? t("certificates.inventory.loadedOne")
                        : t("certificates.inventory.loadedMany", { count: formatCount(filtered.length) })
                    }
                    filters={
                      <>
                        <label className="grid gap-1 text-sm font-medium" htmlFor="cert-issuer-filter">
                          {translateNow("source.issuer.filter.32db997051")}
                          <select
                            id="cert-issuer-filter"
                            value={issuerFilter}
                            onChange={(e) => selectFacet("issuer", e.target.value)}
                            className="min-h-9 rounded-md border border-border bg-background px-2 text-sm"
                          >
                            <option value="all">{translateNow("source.all.issuers.ab00116bbe")}</option>
                            {issuerOptions.map((issuer) => (
                              <option key={issuer} value={issuer}>
                                {issuer}
                              </option>
                            ))}
                          </select>
                        </label>
                        <label className="grid gap-1 text-sm font-medium" htmlFor="cert-profile-filter">
                          {translateNow("source.profile.filter.d447429270")}
                          <select
                            id="cert-profile-filter"
                            value={profileFilter}
                            onChange={(e) => selectFacet("profile", e.target.value)}
                            className="min-h-9 rounded-md border border-border bg-background px-2 text-sm"
                          >
                            <option value="all">{translateNow("source.all.profiles.18f6aff3fe")}</option>
                            {profileOptions.map((profile) => (
                              <option key={profile} value={profile}>
                                {profile}
                              </option>
                            ))}
                          </select>
                        </label>
                        <label className="grid gap-1 text-sm font-medium" htmlFor="cert-team-filter">
                          {translateNow("source.team.filter.f485fa9dcf")}
                          <select
                            id="cert-team-filter"
                            value={teamFilter}
                            onChange={(e) => selectFacet("team", e.target.value)}
                            className="min-h-9 rounded-md border border-border bg-background px-2 text-sm"
                          >
                            <option value="all">{translateNow("source.all.teams.bf65fc89ca")}</option>
                            {teamOptions.map((team) => (
                              <option key={team.value} value={team.value}>
                                {team.label}
                              </option>
                            ))}
                          </select>
                        </label>
                        <label className="grid gap-1 text-sm font-medium" htmlFor="cert-environment-filter">
                          {translateNow("source.environment.filter.3495eee74d")}
                          <select
                            id="cert-environment-filter"
                            value={environmentFilter}
                            onChange={(e) => selectFacet("environment", e.target.value)}
                            className="min-h-9 rounded-md border border-border bg-background px-2 text-sm"
                          >
                            <option value="all">{translateNow("source.all.environments.f19ac5a6af")}</option>
                            {environmentOptions.map((environment) => (
                              <option key={environment} value={environment}>
                                {environment}
                              </option>
                            ))}
                          </select>
                        </label>
                        <fieldset>
                          <legend className="mb-1 text-sm font-medium">{translateNow("source.server.expiry.filter.129321a4ff")}</legend>
                          <div className="flex flex-wrap gap-2">
                            {expiryFilters.map((f) => (
                              <button
                                key={f.value}
                                type="button"
                                onClick={() => selectExpiry(f.value)}
                                aria-pressed={expiry === f.value}
                                className={`min-h-9 rounded-md border px-2.5 text-sm ${
                                  expiry === f.value ? "border-primary bg-primary text-primary-foreground" : "border-border bg-background"
                                }`}
                              >
                                {f.label}
                              </button>
                            ))}
                          </div>
                        </fieldset>
                        <label className="grid gap-1 text-sm font-medium" htmlFor="cert-limit">
                          {translateNow("source.page.size.bd69e66e00")}
                          <select
                            id="cert-limit"
                            value={limit}
                            onChange={(e) => setLimit(Number(e.target.value))}
                            className="min-h-9 rounded-md border border-border bg-background px-2 text-sm"
                          >
                            <option value={5}>5</option>
                            <option value={20}>20</option>
                            <option value={50}>50</option>
                          </select>
                        </label>
                      </>
                    }
                    savedViews={savedViews}
                    columnChooser={columnChooser}
                  />
                )}
                onRowOpen={(c) => void openDetail(c)}
                rowActionLabel={certificateRowActionLabel}
              />

              <div className="mt-4 flex items-center gap-3">
                {nextCursor ? (
                  <button
                    type="button"
                    onClick={() => void loadNextPage()}
                    disabled={loadingMore}
                    className="inline-flex min-h-10 items-center rounded-md border border-border px-3 py-2 text-sm disabled:opacity-60"
                  >
                    {loadingMore ? translateNow("source.loading.next.page.8c0453192f") : translateNow("source.load.next.page.d31b4bf690")}
                  </button>
                ) : (
                  <p className="text-sm text-muted-foreground">{translateNow("source.no.more.certificate.pages.e8cec79bea")}</p>
                )}
              </div>
            </div>
          )}
        </>
      )}

      <Dialog
        open={bulkRevokeOpen}
        onClose={() => {
          if (!bulkBusy) setBulkRevokeOpen(false);
        }}
        titleId="bulk-revoke-certs-title"
        descriptionId="bulk-revoke-certs-desc"
        role="alertdialog"
        className="fixed inset-0 z-50 flex items-center justify-center p-4"
        overlayClassName="absolute inset-0 bg-black/55"
        panelClassName="relative w-full max-w-xl rounded-panel border border-destructive/40 bg-card p-4 text-sm shadow-elevation2"
      >
        <h2 id="bulk-revoke-certs-title" className="text-title font-semibold text-destructive">
          {translateNow("source.revoke.87e6d00bbf")} {selectedIds.size} {translateNow("source.selected.certificate.4d9927e917")}
          {selectedIds.size === 1 ? "" : "s"}?
        </h2>
        <p id="bulk-revoke-certs-desc" className="mt-1 text-destructive">
          {translateNow("source.this.submits.one.bulk.revocation.request.f.f1809ceaf2")} {selectedIds.size} selected certificates. Revocation cannot be undone;
          CRL and OCSP distribution completes asynchronously.
        </p>
        <label className="mt-3 grid gap-1 text-sm font-medium text-destructive" htmlFor="bulk-revoke-reason">
          {translateNow("source.revocation.reason.b11670420f")}
          <select
            id="bulk-revoke-reason"
            value={bulkReason}
            onChange={(event) => setBulkReason(event.target.value as BulkRevokeRequest["reason"])}
            className="min-h-9 rounded-control border border-destructive/40 bg-background px-3 py-2 text-sm font-normal text-foreground"
          >
            {revocationReasons.map((reason) => (
              <option key={reason} value={reason}>
                {reason}
              </option>
            ))}
          </select>
        </label>
        {bulkError && <p className="mt-3 text-sm font-medium text-risk-critical">{bulkError}</p>}
        <div className="mt-3 flex gap-2">
          <Button type="button" size="sm" variant="destructive" loading={bulkBusy} disabled={selectedIds.size === 0} onClick={() => void submitBulkRevoke()}>
            {translateNow("source.confirm.bulk.revoke.d613327838")}
          </Button>
          <Button type="button" size="sm" variant="ghost" disabled={bulkBusy} onClick={() => setBulkRevokeOpen(false)}>
            {translateNow("source.cancel.19766ed6cc")}
          </Button>
        </div>
      </Dialog>

      <Dialog
        open={ctDialogOpen}
        onClose={() => {
          if (!ctLoading) setCTDialogOpen(false);
        }}
        titleId="ct-submission-heading"
        className="fixed inset-0 z-50 flex items-center justify-center p-4"
        overlayClassName="absolute inset-0 bg-black/55"
        panelClassName="relative max-h-[85vh] w-full max-w-3xl overflow-y-auto rounded-panel border border-border bg-card p-4 shadow-elevation3"
      >
        <CTSubmissionPanel
          className=""
          loading={ctLoading}
          error={ctError}
          result={ctResult}
          certificatePEM={ctCertificatePEM}
          precertificatePEM={ctPrecertificatePEM}
          chainPEM={ctChainPEM}
          logs={ctLogs}
          allowPrivate={ctAllowPrivate}
          onCertificatePEM={setCTCertificatePEM}
          onPrecertificatePEM={setCTPrecertificatePEM}
          onChainPEM={setCTChainPEM}
          onLogs={setCTLogs}
          onAllowPrivate={setCTAllowPrivate}
          onSubmit={submitCT}
        />
        <div className="mt-3 flex justify-end">
          <Button type="button" size="sm" variant="ghost" disabled={ctLoading} onClick={() => setCTDialogOpen(false)}>
            {translateNow("source.close.7d9eb7acb1")}
          </Button>
        </div>
      </Dialog>

      <DetailDrawer
        open={!!detailID}
        title={translateNow("source.certificate.details.fccff74faf")}
        description={detailID ? `Fetched certificate ${detailID}.` : undefined}
        onClose={() => setDetailID(null)}
      >
        {detailLoading && <LoadingState>{translateNow("source.loading.certificate.details.a52129b338")}</LoadingState>}
        {detailError?.kind === "permission" && <PermissionDeniedState>{detailError.message}</PermissionDeniedState>}
        {detailError?.kind === "error" && (
          <ErrorState title={translateNow("source.could.not.load.certificate.details.7999752b96")}>{detailError.message}</ErrorState>
        )}
        {detail && (
          <>
            {/* S-C11: close the response loop — a certificate detail is where
                an operator decides something is wrong, so the graph (blast
                radius) and the incident form are one click away instead of a
                copied id and two navigations. */}
            <nav aria-label={translateNow("certificates.detail.relatedViews")} className="mb-3 flex flex-wrap gap-3 text-sm">
              <Link className="text-brand-accent underline" to={`/graph?node=${encodeURIComponent(detail.id)}`}>
                {translateNow("certificates.detail.viewInGraph")}
              </Link>
              <Link className="text-brand-accent underline" to={`/incidents?identity=${encodeURIComponent(detail.id)}`}>
                {translateNow("certificates.detail.respond")}
              </Link>
            </nav>
            <dl className="grid gap-3 text-sm md:grid-cols-2">
              <div>
                <dt className="font-medium text-muted-foreground">{translateNow("source.subject.6897128384")}</dt>
                <dd className="break-all">{certificateDisplayName(detail)}</dd>
              </div>
              <div>
                <dt className="font-medium text-muted-foreground">{translateNow("source.issuer.39e02c46a0")}</dt>
                <dd>{detail.issuer || "-"}</dd>
              </div>
              <div>
                <dt className="font-medium text-muted-foreground">{translateNow("source.sans.7a15c9b7f6")}</dt>
                <dd>{detail.sans?.length ? detail.sans.join(", ") : "-"}</dd>
              </div>
              <div>
                <dt className="font-medium text-muted-foreground">{translateNow("source.key.algorithm.36da451ea3")}</dt>
                <dd>{detail.key_algorithm || "-"}</dd>
              </div>
              <div>
                <dt className="font-medium text-muted-foreground">{translateNow("source.serial.8ea0949377")}</dt>
                <dd className="mt-0.5">{detail.serial ? <CredentialChip value={detail.serial} label="serial number" /> : "-"}</dd>
              </div>
              <div>
                <dt className="font-medium text-muted-foreground">{translateNow("source.fingerprint.ba7af0b704")}</dt>
                <dd className="mt-0.5">{detail.fingerprint ? <CredentialChip value={detail.fingerprint} label="fingerprint" head={12} tail={8} /> : "-"}</dd>
              </div>
              <div>
                <dt className="font-medium text-muted-foreground">{translateNow("source.validity.9c3050e867")}</dt>
                <dd>
                  <time dateTime={detail.not_before} title={detail.not_before}>
                    {formatDateTime(detail.not_before)}
                  </time>{" "}
                  {translateNow("source.to.663ea1bfff")}{" "}
                  <time dateTime={detail.not_after} title={detail.not_after}>
                    {formatDateTime(detail.not_after)}
                  </time>
                </dd>
              </div>
              <div>
                <dt className="font-medium text-muted-foreground">{translateNow("source.status.920e413c7d")}</dt>
                <dd>{detail.status}</dd>
              </div>
              {detail.status === "revoked" && (
                <>
                  <div>
                    <dt className="font-medium text-muted-foreground">{translateNow("source.revoked.at.144e77bcf0")}</dt>
                    <dd>{formatDate(detail.revoked_at)}</dd>
                  </div>
                  <div>
                    <dt className="font-medium text-muted-foreground">{translateNow("source.revocation.reason.b11670420f")}</dt>
                    <dd>{detail.revocation_reason || "-"}</dd>
                  </div>
                </>
              )}
              <div className="sm:col-span-2">
                <dt className="font-medium text-muted-foreground">{translateNow("source.custody.key.b5cust0001")}</dt>
                <dd className={detail.key_origin === "control_plane" ? "text-status-warning" : undefined}>{detail.custody_summary}</dd>
                {!detail.key_origin ? (
                  // Unrecorded is a third answer, not a default. A certificate a
                  // scan found has an origin nobody watched, and rendering that
                  // as reassurance is exactly what an auditor should not be
                  // handed.
                  <dd className="mt-1 text-xs text-muted-foreground">{translateNow("source.custody.unrecorded.b5cust0002")}</dd>
                ) : null}
              </div>
              <div>
                <dt className="font-medium text-muted-foreground">{translateNow("source.source.0e570ca6fa")}</dt>
                <dd>{detail.source || "-"}</dd>
              </div>
              <div>
                <dt className="font-medium text-muted-foreground">{translateNow("source.deployment.location.5a9f62f9fc")}</dt>
                <dd>{detail.deployment_location || "-"}</dd>
              </div>
              <div>
                <dt className="font-medium text-muted-foreground">{t("certificateCockpit.detail.effectiveOwnership")}</dt>
                <dd>
                  {(() => {
                    if (!detail.owner_id) return t("certificateCockpit.owner.missing");
                    const owner = ownerByID.get(detail.owner_id);
                    return (
                      <span className="grid gap-0.5">
                        <Link className="text-primary underline" to={`/owners?owner=${encodeURIComponent(detail.owner_id)}`}>
                          {owner?.name || detail.owner_id}
                        </Link>
                        {owner ? (
                          <span className="text-xs text-muted-foreground">
                            {effectiveOwnershipLabel(owner)} ·{" "}
                            {ownerIsReachable(owner) ? t("certificateCockpit.detail.reachable") : t("certificateCockpit.detail.noAlertContact")}
                          </span>
                        ) : (
                          <span className="text-xs text-muted-foreground">{t("certificateCockpit.owner.unresolved")}</span>
                        )}
                      </span>
                    );
                  })()}
                </dd>
              </div>
              <div className="md:col-span-2">
                <dt className="flex items-center justify-between gap-2 font-medium text-muted-foreground">
                  {translateNow("source.renewal.history.771f739290")}
                  {(() => {
                    const identity = renewableIdentityFor(detail, identityByCN);
                    if (identity) {
                      const busy = renewingIds.has(detail.id);
                      return (
                        <Button
                          type="button"
                          size="sm"
                          variant="outline"
                          disabled={busy}
                          aria-label={translateNow("source.renew.value1.c52ad584ec", { value1: certificateCN(detail.subject) || detail.subject })}
                          onClick={() => void startRenew(detail, identity)}
                        >
                          {busy ? translateNow("source.renewing.81caaaa0e6") : translateNow("source.renew.now.905758c33c")}
                        </Button>
                      );
                    }
                    if (detail.status === "active") {
                      return (
                        <Link to={certificateReplacementPath(detail)} className="text-caption font-medium text-brand-accent hover:underline">
                          {t(detail.source?.startsWith("attested:") ? "certificates.lifecycle.replaceAttested" : "certificates.lifecycle.notManaged")}
                        </Link>
                      );
                    }
                    return null;
                  })()}
                </dt>
                <dd>
                  <RenewalHistory
                    runs={rotationRuns.filter((r) => r.predecessor_fingerprint === detail.fingerprint || r.successor_fingerprint === detail.fingerprint)}
                  />
                </dd>
              </div>
              <div className="md:col-span-2">
                <dt className="sr-only">{t("certificateCockpit.detail.activity")}</dt>
                <dd>
                  <CredentialActivityTimeline credentialLabel={certificateDisplayName(detail)} />
                </dd>
              </div>
            </dl>
          </>
        )}
      </DetailDrawer>
    </section>
  );
}

/** certificateCN pulls the CN attribute out of an X.509 subject string so a
 * certificate can be matched to the non-human identity that holds it (the
 * durable identity record is named by CN in the issuance path). */
export function certificateCN(subject: string): string {
  const match = /(?:^|[,/]\s*)CN=([^,/]+)/i.exec(subject);
  return (match?.[1] ?? "").trim().toLowerCase();
}

/** renewableIdentityFor returns the managing identity for a certificate when
 * one exists: an x509 identity whose name matches the certificate CN and that
 * is not already retired/revoked. */
function renewableIdentityFor(certificate: Certificate, identityByCN: Map<string, Identity>): Identity | undefined {
  if (certificate.status !== "active" || certificate.source?.startsWith("attested:")) return undefined;
  const commonName = certificateCN(certificate.subject);
  if (!commonName) return undefined;
  const identity = identityByCN.get(commonName);
  if (!identity) return undefined;
  if (identity.status === "retired" || identity.status === "revoked") return undefined;
  return identity;
}

type LifecycleColumnContext = {
  identityByCN: Map<string, Identity>;
  renewingIds: Set<string>;
  onRenew: (certificate: Certificate, identity: Identity) => void;
  replaceLabel: string;
};

/** lifecycleColumn closes the DA-05 dead-end: managed rows get Renew wired to
 * the identity lifecycle transition; unmanaged active rows degrade honestly to
 * the self-service replace path instead of silence. */
function lifecycleColumn(context: LifecycleColumnContext): DataGridColumn<Certificate> {
  return {
    id: "lifecycle",
    header: "Lifecycle",
    hiddenByDefault: true,
    className: "whitespace-nowrap align-middle",
    cell: (c) => {
      const identity = renewableIdentityFor(c, context.identityByCN);
      if (identity) {
        const busy = context.renewingIds.has(c.id);
        return (
          <Button
            type="button"
            size="sm"
            variant="outline"
            disabled={busy}
            aria-label={translateNow("source.renew.value1.c52ad584ec", { value1: certificateCN(c.subject) || c.subject })}
            onClick={() => context.onRenew(c, identity)}
          >
            {busy ? translateNow("source.renewing.81caaaa0e6") : translateNow("source.renew.90c1689b0b")}
          </Button>
        );
      }
      if (c.status === "active") {
        return (
          <Link to={certificateReplacementPath(c)} className="text-caption font-medium text-brand-accent hover:underline">
            {c.source?.startsWith("attested:") ? translateNow("certificates.lifecycle.replaceAttested") : context.replaceLabel}
          </Link>
        );
      }
      return <span className="text-muted-foreground">—</span>;
    },
  };
}

function certificateColumns(
  ownerByID: Map<string, Owner>,
  formatDate: (value?: string) => string,
  lifecycle?: DataGridColumn<Certificate>,
): Array<DataGridColumn<Certificate>> {
  const base: Array<DataGridColumn<Certificate>> = [
    {
      id: "subject",
      header: "Subject",
      sortable: true,
      className: "min-w-64 align-middle",
      cell: (c) => (
        <span title={certificateDisplayName(c)} className="block max-w-80 truncate font-medium">
          {certificateDisplayName(c)}
        </span>
      ),
    },
    {
      id: "issuer",
      header: "Issuer",
      hiddenByDefault: true,
      className: "min-w-52 align-middle",
      cell: (c) =>
        c.issuer ? (
          <span title={c.issuer} className="block max-w-64 truncate">
            {c.issuer}
          </span>
        ) : (
          "-"
        ),
    },
    {
      id: "profile",
      header: "Profile",
      hiddenByDefault: true,
      className: "whitespace-nowrap align-middle",
      cell: (c) => certificateProfile(c) || <span className="text-muted-foreground">-</span>,
    },
    {
      id: "team",
      header: "Team",
      className: "min-w-36 align-middle",
      cell: (c) => {
        const owner = c.owner_id ? ownerByID.get(c.owner_id) : undefined;
        const label = certificateTeamLabel(c, ownerByID) || owner?.name || c.owner_id;
        if (!label) return <span className="text-muted-foreground">{translateNow("certificateCockpit.owner.missing")}</span>;
        return (
          <span className="grid gap-0.5">
            <span>{label}</span>
            {owner ? <span className="text-xs text-muted-foreground">{effectiveOwnershipLabel(owner)}</span> : null}
          </span>
        );
      },
    },
    {
      id: "algorithm",
      header: "Algorithm",
      hiddenByDefault: true,
      className: "whitespace-nowrap align-middle",
      cell: (c) => c.key_algorithm || "-",
    },
    {
      id: "expires",
      header: "Expires",
      sortable: true,
      className: "whitespace-nowrap align-middle",
      cell: (c) => (
        <time dateTime={c.not_after} title={c.not_after}>
          {formatDate(c.not_after)}
        </time>
      ),
    },
    {
      id: "expiry-band",
      header: "Needs attention",
      className: "whitespace-nowrap align-middle",
      cell: (c) =>
        c.status === "active" ? (
          <StatusBadge vocabulary="expiry" value={validityBandForDates(c.not_before, c.not_after)} />
        ) : (
          <StatusBadge vocabulary="certificate" value={c.status} />
        ),
    },
    {
      id: "status",
      header: "Status",
      hiddenByDefault: true,
      className: "whitespace-nowrap align-middle",
      cell: (c) => (
        <div className="grid gap-1">
          <StatusBadge vocabulary="certificate" value={c.status} />
          {c.status === "revoked" && c.revocation_reason && <span className="text-xs text-muted-foreground">{c.revocation_reason}</span>}
        </div>
      ),
    },
  ];
  return lifecycle ? [...base, lifecycle] : base;
}

function certificateRowActionLabel(certificate: Certificate): string {
  if (certificate.status !== "active") return translateNow("certificates.inventory.review");
  const expiry = validityBandForDates(certificate.not_before, certificate.not_after);
  return expiry === "healthy" || expiry === "planned" ? translateNow("certificates.inventory.view") : translateNow("certificates.inventory.review");
}

function certificateFilterSummary(
  issuer: FacetFilter,
  profile: FacetFilter,
  team: FacetFilter,
  environment: FacetFilter,
  expiry: ExpiryFilter,
): string | undefined {
  const active = [issuer, profile, team, environment, expiry].filter((value) => value !== "all").length;
  if (active === 0) return undefined;
  return active === 1 ? translateNow("certificates.inventory.filterOne") : translateNow("certificates.inventory.filterMany", { count: formatCount(active) });
}

function uniqueOptions(values: Array<string | undefined>, selected: FacetFilter): string[] {
  const set = new Set(values.map((value) => value?.trim()).filter((value): value is string => Boolean(value)));
  if (selected !== "all") set.add(selected);
  return Array.from(set).sort((left, right) => left.localeCompare(right));
}
