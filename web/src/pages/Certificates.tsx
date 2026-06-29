import { FormEvent, useEffect, useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { Activity, AlertTriangle, FilePlus2, Layers3, PlugZap, Send, ShieldCheck } from "lucide-react";
import {
  ApiError,
  UnauthorizedError,
  api,
  type Certificate,
  type CertificateHealthDashboard,
  type ConnectorDelivery,
  type CRLDistribution,
  type CTSubmission,
  type Owner,
  type RotationRun,
} from "@/lib/api";
import { DataGrid, type DataGridColumn } from "@/components/DataGrid";
import { DetailDrawer } from "@/components/DetailDrawer";
import { CredentialActivityTimeline } from "@/components/CredentialActivityTimeline";
import { EmptyState } from "@/components/EmptyState";
import { ErrorState, LoadingState, PermissionDeniedState } from "@/components/StatePrimitives";
import { StatusBadge } from "@/components/StatusBadge";
import { PageHeader } from "@/components/PageHeader";
import { expiryBandForDate } from "@/lib/statusVocab";
import { useTranslation } from "@/i18n/I18nProvider";
import { formatDate as formatDatePolicy, formatNumber as formatNumberPolicy } from "@/i18n/format";
import { CertificatesDashboard, ReadinessPanel, ReadinessSimulator, DeploymentReceipts, RenewalHistory, autoRenewingCount } from "@/components/certs";
import type { RiskItem } from "@/components/risk";

type ExpiryFilter = "all" | "7d" | "30d" | "90d";

const expiryFilters: Array<{ value: ExpiryFilter; label: string; days?: number }> = [
  { value: "all", label: "All" },
  { value: "7d", label: "<7d", days: 7 },
  { value: "30d", label: "7-30d", days: 30 },
  { value: "90d", label: "30-90d", days: 90 },
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

type Notice = { kind: "permission" | "error"; message: string };
type FacetFilter = "all" | string;

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

function formatDate(value?: string): string {
  return formatDatePolicy(value);
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
  const { t } = useTranslation();
  const state = health.summary.health;
  const stateClass =
    state === "critical"
      ? "border-status-danger/40 bg-status-danger/10 text-status-danger"
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
  const { t } = useTranslation();
  const first = distributions[0];
  const totalShards = distributions.reduce((sum, item) => sum + item.shards.length, 0);
  const totalRevoked = distributions.reduce((sum, item) => sum + item.revoked_count, 0);
  return (
    <section aria-labelledby="crl-distribution-heading" className="border-y border-border py-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
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
        </div>
        <span className="inline-flex min-h-8 items-center gap-2 rounded-md border border-primary/30 bg-primary/10 px-2.5 text-sm font-medium text-primary">
          <Layers3 className="h-4 w-4" aria-hidden="true" />
          {first ? t("certificates.crl.shardPlan", { shardCount: formatCount(first.shard_count) }) : t("certificates.crl.awaiting")}
        </span>
      </div>
      {distributions.length > 0 && (
        <div className="mt-4 overflow-x-auto">
          <table className="min-w-full text-left text-sm">
            <thead className="border-b border-border text-xs uppercase text-muted-foreground">
              <tr>
                <th scope="col" className="py-2 pr-4 font-medium">
                  {t("certificates.crl.ca")}
                </th>
                <th scope="col" className="px-4 py-2 font-medium">
                  {t("certificates.crl.full")}
                </th>
                <th scope="col" className="px-4 py-2 font-medium">
                  {t("certificates.crl.shards")}
                </th>
                <th scope="col" className="px-4 py-2 font-medium">
                  {t("certificates.crl.delta")}
                </th>
                <th scope="col" className="pl-4 py-2 font-medium">
                  {t("certificates.crl.window")}
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {distributions.map((item) => (
                <tr key={item.ca_id}>
                  <td className="py-2 pr-4 align-top">
                    <span className="block max-w-[18rem] truncate font-medium">{item.ca_id}</span>
                    <span className="text-xs text-muted-foreground">{t("certificates.crl.revokedCount", { count: formatCount(item.revoked_count) })}</span>
                  </td>
                  <td className="px-4 py-2 align-top">
                    <a className="font-mono text-xs text-primary underline" href={item.full_url}>
                      #{item.full_number}
                    </a>
                  </td>
                  <td className="px-4 py-2 align-top">
                    <span className="block">{t("certificates.crl.servedCount", { count: formatCount(item.shards.length) })}</span>
                    <span className="text-xs text-muted-foreground">{t("certificates.crl.plannedCount", { count: formatCount(item.shard_count) })}</span>
                  </td>
                  <td className="px-4 py-2 align-top">
                    {item.delta_url ? (
                      <a className="font-mono text-xs text-primary underline" href={item.delta_url}>
                        {t("certificates.crl.deltaBase", { base: item.delta_base_number ?? "" })}
                      </a>
                    ) : (
                      <span className="text-muted-foreground">-</span>
                    )}
                  </td>
                  <td className="pl-4 py-2 align-top">
                    <span className="block">{formatDate(item.this_update)}</span>
                    <span className="text-xs text-muted-foreground">{t("certificates.crl.nextUpdate", { date: formatDate(item.next_update) })}</span>
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
}) {
  const { t } = useTranslation();
  return (
    <section aria-labelledby="ct-submission-heading" className="border-y border-border py-4">
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
              placeholder="-----BEGIN CERTIFICATE-----"
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
              placeholder="-----BEGIN CERTIFICATE-----"
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
  const { t } = useTranslation();
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
  const [pem, setPem] = useState("");
  const [ownerID, setOwnerID] = useState("");
  const [source, setSource] = useState("manual-ui");
  const [deploymentLocation, setDeploymentLocation] = useState("");
  const [ingestLoading, setIngestLoading] = useState(false);
  const [ingestError, setIngestError] = useState<Notice | null>(null);
  const [ingestSuccess, setIngestSuccess] = useState<string | null>(null);
  const [risks, setRisks] = useState<RiskItem[]>([]);
  const [rotationRuns, setRotationRuns] = useState<RotationRun[]>([]);
  const [deliveries, setDeliveries] = useState<ConnectorDelivery[]>([]);
  const [owners, setOwners] = useState<Owner[]>([]);
  const [health, setHealth] = useState<CertificateHealthDashboard | null>(null);
  const [crlDistributions, setCRLDistributions] = useState<CRLDistribution[]>([]);
  const [ctCertificatePEM, setCTCertificatePEM] = useState("");
  const [ctPrecertificatePEM, setCTPrecertificatePEM] = useState("");
  const [ctChainPEM, setCTChainPEM] = useState("");
  const [ctLogs, setCTLogs] = useState("");
  const [ctAllowPrivate, setCTAllowPrivate] = useState(false);
  const [ctLoading, setCTLoading] = useState(false);
  const [ctError, setCTError] = useState<Notice | null>(null);
  const [ctResult, setCTResult] = useState<CTSubmission | null>(null);

  useEffect(() => {
    let cancelled = false;
    Promise.all([
      settleOptional(() => api.certificateHealth()),
      settleOptional(() => api.crlDistributions()),
      settleOptional(() => api.risk({ sort: "score" })),
      settleOptional(() => api.rotationRuns({ limit: 100 })),
      settleOptional(() => api.connectorDeliveries({ limit: 50 })),
      settleOptional(() => api.owners()),
    ]).then(([healthResult, crlResult, riskResult, rotationResult, deliveryResult, ownerResult]) => {
      if (cancelled) return;
      if (healthResult) setHealth(healthResult);
      if (crlResult) setCRLDistributions(crlResult.items ?? []);
      if (riskResult) setRisks(riskResult);
      if (rotationResult) setRotationRuns(rotationResult.items ?? []);
      if (deliveryResult) setDeliveries(deliveryResult.items ?? []);
      if (ownerResult) setOwners(ownerResult);
    });
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
      setIngestError({ kind: "error", message: "PEM is required." });
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
      const nextHealth = await settleOptional(() => api.certificateHealth());
      if (nextHealth) setHealth(nextHealth);
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

  const ownerByID = useMemo(() => new Map(owners.map((owner) => [owner.id, owner])), [owners]);
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
  const columns = useMemo(() => certificateColumns(ownerByID), [ownerByID]);

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
        c.subject,
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
    <section aria-labelledby="certs-heading">
      <PageHeader
        titleId="certs-heading"
        title="Certificates"
        description="Your X.509 certificate inventory — search, filter by expiry, import, and inspect. For the non-human identities that hold these certificates, see Identities."
        actions={
          <>
            <Link
              to="/ca-hierarchy"
              className="inline-flex min-h-10 items-center justify-center gap-2 rounded-md border border-border bg-background px-3 py-2 text-sm font-medium hover:border-brand-accent/40 hover:bg-muted/60"
            >
              <PlugZap className="h-4 w-4" aria-hidden="true" />
              {t("nav.item.caHierarchy")}
            </Link>
            <Link
              to="/profiles"
              className="inline-flex min-h-10 items-center justify-center gap-2 rounded-md border border-border bg-background px-3 py-2 text-sm font-medium hover:border-brand-accent/40 hover:bg-muted/60"
            >
              <ShieldCheck className="h-4 w-4" aria-hidden="true" />
              {t("nav.item.profiles")}
            </Link>
            <button
              type="button"
              onClick={() => setShowIngest((v) => !v)}
              className="inline-flex min-h-10 items-center justify-center rounded-md bg-primary px-3 py-2 text-sm font-medium text-primary-foreground"
            >
              {showIngest ? "Close ingest" : "Add certificate"}
            </button>
          </>
        }
      />

      {showIngest && (
        <form onSubmit={submitIngest} aria-labelledby="ingest-heading" className="mb-6 grid gap-4 border-y border-border py-4">
          <div>
            <h2 id="ingest-heading" className="text-title font-semibold">
              Add certificate
            </h2>
            <p className="mt-1 text-sm text-muted-foreground">Paste a public certificate PEM. Private keys do not belong in this form.</p>
          </div>
          <label className="grid gap-1 text-sm font-medium" htmlFor="cert-pem">
            Certificate PEM
            <textarea
              id="cert-pem"
              value={pem}
              onChange={(e) => setPem(e.target.value)}
              rows={8}
              className="w-full rounded-md border border-border bg-background px-3 py-2 font-mono text-xs"
              placeholder="-----BEGIN CERTIFICATE-----"
            />
          </label>
          <div className="grid gap-3 md:grid-cols-3">
            <label className="grid gap-1 text-sm font-medium" htmlFor="cert-owner">
              Owner ID
              <input
                id="cert-owner"
                value={ownerID}
                onChange={(e) => setOwnerID(e.target.value)}
                className="rounded-md border border-border bg-background px-3 py-2 text-sm"
                placeholder="optional"
              />
            </label>
            <label className="grid gap-1 text-sm font-medium" htmlFor="cert-source">
              Source
              <input
                id="cert-source"
                value={source}
                onChange={(e) => setSource(e.target.value)}
                className="rounded-md border border-border bg-background px-3 py-2 text-sm"
              />
            </label>
            <label className="grid gap-1 text-sm font-medium" htmlFor="cert-location">
              Deployment location
              <input
                id="cert-location"
                value={deploymentLocation}
                onChange={(e) => setDeploymentLocation(e.target.value)}
                className="rounded-md border border-border bg-background px-3 py-2 text-sm"
                placeholder="cluster/service/path"
              />
            </label>
          </div>
          {ingestError?.kind === "permission" && <PermissionDeniedState>{ingestError.message}</PermissionDeniedState>}
          {ingestError?.kind === "error" && <ErrorState title="Could not ingest certificate">{ingestError.message}</ErrorState>}
          {ingestSuccess && (
            <p role="status" className="text-sm text-status-success">
              {ingestSuccess}
            </p>
          )}
          <div>
            <button
              type="submit"
              disabled={ingestLoading}
              className="inline-flex min-h-10 items-center justify-center rounded-md bg-primary px-3 py-2 text-sm font-medium text-primary-foreground disabled:opacity-60"
            >
              {ingestLoading ? "Ingesting..." : "Ingest certificate"}
            </button>
          </div>
        </form>
      )}

      {loading && <LoadingState>Loading certificates...</LoadingState>}
      {error?.kind === "permission" && <PermissionDeniedState>{error.message}</PermissionDeniedState>}
      {error?.kind === "error" && <ErrorState title="Could not load certificates">{error.message}</ErrorState>}

      {!loading && certificates.length === 0 && !error && (
        <EmptyState
          icon={<FilePlus2 className="h-5 w-5" aria-hidden="true" />}
          title="No certificates yet"
          primaryAction={{ label: "Issue first certificate", to: "/request", icon: <FilePlus2 className="h-4 w-4" /> }}
          secondaryAction={{ label: "Connect an issuer", to: "/ca-hierarchy", icon: <PlugZap className="h-4 w-4" /> }}
        >
          Start with a profile-bound request, or connect an issuer before the first certificate is minted.
        </EmptyState>
      )}

      {certificates.length > 0 && (
        <>
          <div className="mb-6 grid gap-4">
            {health && <CertificateHealthPanel health={health} />}
            <CRLDistributionPanel distributions={crlDistributions} />
            <CTSubmissionPanel
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
            <CertificatesDashboard certificates={certificates} risks={risks} />
            <div className="grid gap-4 lg:grid-cols-2">
              <ReadinessPanel certificates={certificates} rotationRuns={rotationRuns} />
              <ReadinessSimulator certificates={certificates} autoRenewing={autoRenewingCount(certificates, rotationRuns)} />
            </div>
            <DeploymentReceipts deliveries={deliveries} />
          </div>
          <div className="mb-4 grid gap-3 md:grid-cols-2 xl:grid-cols-[minmax(14rem,1.2fr)_repeat(4,minmax(10rem,12rem))_auto_auto] xl:items-end">
            <div>
              <label htmlFor="cert-search" className="mb-1 block text-sm font-medium">
                Search loaded rows
              </label>
              <input
                id="cert-search"
                type="search"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Subject, issuer, serial, fingerprint…"
                className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm"
              />
            </div>
            <label className="grid gap-1 text-sm font-medium" htmlFor="cert-issuer-filter">
              Issuer filter
              <select
                id="cert-issuer-filter"
                value={issuerFilter}
                onChange={(e) => selectFacet("issuer", e.target.value)}
                className="min-h-9 rounded-md border border-border bg-background px-2 text-sm"
              >
                <option value="all">All issuers</option>
                {issuerOptions.map((issuer) => (
                  <option key={issuer} value={issuer}>
                    {issuer}
                  </option>
                ))}
              </select>
            </label>
            <label className="grid gap-1 text-sm font-medium" htmlFor="cert-profile-filter">
              Profile filter
              <select
                id="cert-profile-filter"
                value={profileFilter}
                onChange={(e) => selectFacet("profile", e.target.value)}
                className="min-h-9 rounded-md border border-border bg-background px-2 text-sm"
              >
                <option value="all">All profiles</option>
                {profileOptions.map((profile) => (
                  <option key={profile} value={profile}>
                    {profile}
                  </option>
                ))}
              </select>
            </label>
            <label className="grid gap-1 text-sm font-medium" htmlFor="cert-team-filter">
              Team filter
              <select
                id="cert-team-filter"
                value={teamFilter}
                onChange={(e) => selectFacet("team", e.target.value)}
                className="min-h-9 rounded-md border border-border bg-background px-2 text-sm"
              >
                <option value="all">All teams</option>
                {teamOptions.map((team) => (
                  <option key={team.value} value={team.value}>
                    {team.label}
                  </option>
                ))}
              </select>
            </label>
            <label className="grid gap-1 text-sm font-medium" htmlFor="cert-environment-filter">
              Environment filter
              <select
                id="cert-environment-filter"
                value={environmentFilter}
                onChange={(e) => selectFacet("environment", e.target.value)}
                className="min-h-9 rounded-md border border-border bg-background px-2 text-sm"
              >
                <option value="all">All environments</option>
                {environmentOptions.map((environment) => (
                  <option key={environment} value={environment}>
                    {environment}
                  </option>
                ))}
              </select>
            </label>
            <fieldset>
              <legend className="mb-1 text-sm font-medium">Server expiry filter</legend>
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
              Page size
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
          </div>

          {filtered.length === 0 ? (
            <p className="text-sm text-muted-foreground">No certificates match your search.</p>
          ) : (
            <DataGrid
              ariaLabel="Inventoried certificates"
              rows={filtered}
              columns={columns}
              getRowId={(c) => c.id}
              onRowOpen={(c) => void openDetail(c)}
              rowActionLabel={() => "View details"}
            />
          )}

          <div className="mt-4 flex items-center gap-3">
            {nextCursor ? (
              <button
                type="button"
                onClick={() => void loadNextPage()}
                disabled={loadingMore}
                className="inline-flex min-h-10 items-center rounded-md border border-border px-3 py-2 text-sm disabled:opacity-60"
              >
                {loadingMore ? "Loading next page..." : "Load next page"}
              </button>
            ) : (
              <p className="text-sm text-muted-foreground">No more certificate pages.</p>
            )}
          </div>
        </>
      )}

      <DetailDrawer
        open={!!detailID}
        title="Certificate details"
        description={detailID ? `Fetched certificate ${detailID}.` : undefined}
        onClose={() => setDetailID(null)}
      >
        {detailLoading && <LoadingState>Loading certificate details...</LoadingState>}
        {detailError?.kind === "permission" && <PermissionDeniedState>{detailError.message}</PermissionDeniedState>}
        {detailError?.kind === "error" && <ErrorState title="Could not load certificate details">{detailError.message}</ErrorState>}
        {detail && (
          <dl className="grid gap-3 text-sm md:grid-cols-2">
            <div>
              <dt className="font-medium text-muted-foreground">Subject</dt>
              <dd>{detail.subject}</dd>
            </div>
            <div>
              <dt className="font-medium text-muted-foreground">Issuer</dt>
              <dd>{detail.issuer || "-"}</dd>
            </div>
            <div>
              <dt className="font-medium text-muted-foreground">SANs</dt>
              <dd>{detail.sans?.length ? detail.sans.join(", ") : "-"}</dd>
            </div>
            <div>
              <dt className="font-medium text-muted-foreground">Key algorithm</dt>
              <dd>{detail.key_algorithm || "-"}</dd>
            </div>
            <div>
              <dt className="font-medium text-muted-foreground">Serial</dt>
              <dd className="break-all font-mono text-xs">{detail.serial || "-"}</dd>
            </div>
            <div>
              <dt className="font-medium text-muted-foreground">Fingerprint</dt>
              <dd className="break-all font-mono text-xs">{detail.fingerprint}</dd>
            </div>
            <div>
              <dt className="font-medium text-muted-foreground">Validity</dt>
              <dd>
                {formatDate(detail.not_before)} to {formatDate(detail.not_after)}
              </dd>
            </div>
            <div>
              <dt className="font-medium text-muted-foreground">Status</dt>
              <dd>{detail.status}</dd>
            </div>
            {detail.status === "revoked" && (
              <>
                <div>
                  <dt className="font-medium text-muted-foreground">Revoked at</dt>
                  <dd>{formatDate(detail.revoked_at)}</dd>
                </div>
                <div>
                  <dt className="font-medium text-muted-foreground">Revocation reason</dt>
                  <dd>{detail.revocation_reason || "-"}</dd>
                </div>
              </>
            )}
            <div>
              <dt className="font-medium text-muted-foreground">Source</dt>
              <dd>{detail.source || "-"}</dd>
            </div>
            <div>
              <dt className="font-medium text-muted-foreground">Deployment location</dt>
              <dd>{detail.deployment_location || "-"}</dd>
            </div>
            <div>
              <dt className="font-medium text-muted-foreground">Owner</dt>
              <dd>
                {detail.owner_id ? (
                  <a className="text-primary underline" href={`/owners?owner=${encodeURIComponent(detail.owner_id)}`}>
                    {detail.owner_id}
                  </a>
                ) : (
                  "-"
                )}
              </dd>
            </div>
            <div className="md:col-span-2">
              <dt className="font-medium text-muted-foreground">Renewal history</dt>
              <dd>
                <RenewalHistory
                  runs={rotationRuns.filter((r) => r.predecessor_fingerprint === detail.fingerprint || r.successor_fingerprint === detail.fingerprint)}
                />
              </dd>
            </div>
            <div className="md:col-span-2">
              <CredentialActivityTimeline credentialLabel={detail.subject} />
            </div>
          </dl>
        )}
      </DetailDrawer>
    </section>
  );
}

function certificateColumns(ownerByID: Map<string, Owner>): Array<DataGridColumn<Certificate>> {
  return [
    {
      id: "subject",
      header: "Subject",
      sortable: true,
      cell: (c) => <span className="font-medium">{c.subject}</span>,
    },
    {
      id: "issuer",
      header: "Issuer",
      cell: (c) => c.issuer ?? "-",
    },
    {
      id: "profile",
      header: "Profile",
      cell: (c) => certificateProfile(c) || <span className="text-muted-foreground">-</span>,
    },
    {
      id: "team",
      header: "Team",
      cell: (c) => certificateTeamLabel(c, ownerByID) || <span className="text-muted-foreground">-</span>,
    },
    {
      id: "algorithm",
      header: "Algorithm",
      cell: (c) => c.key_algorithm || "-",
    },
    {
      id: "expires",
      header: "Expires",
      sortable: true,
      cell: (c) => formatDate(c.not_after),
    },
    {
      id: "expiry-band",
      header: "Band",
      cell: (c) => <StatusBadge vocabulary="expiry" value={expiryBandForDate(c.not_after)} />,
    },
    {
      id: "status",
      header: "Status",
      cell: (c) => (
        <div className="grid gap-1">
          <StatusBadge vocabulary="certificate" value={c.status} />
          {c.status === "revoked" && c.revocation_reason && <span className="text-xs text-muted-foreground">{c.revocation_reason}</span>}
        </div>
      ),
    },
  ];
}

function uniqueOptions(values: Array<string | undefined>, selected: FacetFilter): string[] {
  const set = new Set(values.map((value) => value?.trim()).filter((value): value is string => Boolean(value)));
  if (selected !== "all") set.add(selected);
  return Array.from(set).sort((left, right) => left.localeCompare(right));
}

function certificateRecord(c: Certificate): Record<string, unknown> {
  return c as unknown as Record<string, unknown>;
}

function certificateAttributes(c: Certificate): Record<string, unknown> {
  const value = certificateRecord(c).attributes;
  return value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : {};
}

function firstString(c: Certificate, keys: string[]): string {
  const record = certificateRecord(c);
  const attrs = certificateAttributes(c);
  for (const key of keys) {
    const value = record[key] ?? attrs[key];
    if (typeof value === "string" && value.trim()) return value.trim();
  }
  return "";
}

function certificateProfile(c: Certificate): string {
  return firstString(c, ["profile_name", "profile", "certificate_profile_name", "certificate_profile_id"]);
}

function certificateEnvironment(c: Certificate): string {
  const explicit = firstString(c, ["environment", "env"]);
  if (explicit) return explicit;
  const location = c.deployment_location?.toLowerCase() ?? "";
  for (const candidate of ["production", "prod", "staging", "stage", "development", "dev"]) {
    if (new RegExp(`(^|[^a-z])${candidate}([^a-z]|$)`).test(location)) return candidate;
  }
  return "";
}

function certificateTeamID(c: Certificate, ownerByID: Map<string, Owner>): string {
  const explicit = firstString(c, ["team_id"]);
  if (explicit) return explicit;
  if (c.owner_id && ownerByID.get(c.owner_id)?.kind === "team") return c.owner_id;
  return "";
}

function certificateTeamLabel(c: Certificate, ownerByID: Map<string, Owner>): string {
  const explicitName = firstString(c, ["team_name", "team"]);
  if (explicitName) return explicitName;
  const teamID = certificateTeamID(c, ownerByID);
  if (!teamID) return "";
  return ownerByID.get(teamID)?.name || teamID;
}

function teamFacetOptions(
  certificates: Certificate[],
  ownerByID: Map<string, Owner>,
  owners: Owner[],
  selected: FacetFilter,
): Array<{ value: string; label: string }> {
  const options = new Map<string, string>();
  for (const owner of owners) {
    if (owner.kind === "team") options.set(owner.id, owner.name || owner.id);
  }
  for (const certificate of certificates) {
    const teamID = certificateTeamID(certificate, ownerByID);
    if (teamID) options.set(teamID, certificateTeamLabel(certificate, ownerByID) || teamID);
  }
  if (selected !== "all" && !options.has(selected)) options.set(selected, selected);
  return Array.from(options, ([value, label]) => ({ value, label })).sort((left, right) => left.label.localeCompare(right.label));
}
