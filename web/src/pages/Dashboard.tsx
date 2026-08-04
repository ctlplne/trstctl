import { useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { Activity, AlertTriangle, Boxes, KeyRound, RotateCw, Rocket, ScrollText, Search, ShieldCheck, ShieldAlert, Siren } from "lucide-react";
import { api, type AuditEvent, type Certificate, type NHIInventory as NHIInventoryResponse, type RotationRun } from "@/lib/api";
import { useAuth } from "@/auth/AuthProvider";
import { useApiQuery } from "@/lib/query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Donut,
  Sparkline,
  StackedTimeBarChart,
  TimeBarChart,
  type ChartTone,
  type DonutSegment,
  type StackedTimeBarDatum,
  type TimeBarDatum,
} from "@/components/charts";
import { EmptyState } from "@/components/EmptyState";
import { PageHeader } from "@/components/PageHeader";
import { ReadinessPanel } from "@/components/certs";
import { NhiInventory } from "@/components/nhi";
import { NotificationCenter } from "@/components/notifications";
import { isOnboardingComplete } from "@/lib/onboardingState";
import { useTranslation, translateNow } from "@/i18n/I18nProvider";
import { formatDateTime, formatShortDate, type FormatPolicy } from "@/i18n/format";

const highRiskThreshold = 70;

function emptyNhiInventory(): NHIInventoryResponse {
  return { generated_at: new Date(0).toISOString(), items: [], summary: {}, coverage: [] };
}

function readNhiInventory(): Promise<NHIInventoryResponse> {
  const client = api as typeof api & { nhiInventory?: () => Promise<NHIInventoryResponse> };
  if (!client.nhiInventory) return Promise.resolve(emptyNhiInventory());
  return Promise.resolve(client.nhiInventory())
    .then((response) => response ?? emptyNhiInventory())
    .catch(() => emptyNhiInventory());
}

function inventoryCount(inventory: NHIInventoryResponse | null | undefined, kind: string): number {
  const raw = inventory?.summary?.[kind];
  const count = Number(raw);
  return Number.isFinite(count) ? count : 0;
}

/** True once the first-run wizard has been completed on this browser. A fresh,
 * empty tenant that has NOT onboarded is sent to setup instead of seeing demo
 * numbers (preview mode is a separate, intentional showcase). */
function readOnboardingDone(): boolean {
  return isOnboardingComplete();
}

/* S-N0 (DA-01/DA-12): real mode renders served data only. The readers below
 * feature-detect their api functions (the api object is mocked per-suite in
 * tests) and resolve to a null/empty fallback instead of throwing, following
 * the readNhiInventory precedent above. */

function readSecretsCount(): Promise<number | null> {
  const client = api as typeof api & { secretPage?: (o?: { limit?: number }) => Promise<{ items?: unknown[] }> };
  if (!client.secretPage) return Promise.resolve(null);
  return Promise.resolve(client.secretPage({ limit: 200 }))
    .then((r) => (r?.items ?? []).length)
    .catch(() => null);
}

function readOpenIncidents(): Promise<number | null> {
  const client = api as typeof api & {
    incidentExecutions?: (o?: { limit?: number }) => Promise<{ items?: Array<{ status?: string }> }>;
  };
  if (!client.incidentExecutions) return Promise.resolve(null);
  return Promise.resolve(client.incidentExecutions({ limit: 100 }))
    .then((r) => (r?.items ?? []).filter((x) => x.status !== "completed" && x.status !== "rolled_back").length)
    .catch(() => null);
}

function readRecentAudit(): Promise<AuditEvent[]> {
  const client = api as typeof api & { auditEvents?: (o?: { limit?: number }) => Promise<AuditEvent[]> };
  if (!client.auditEvents) return Promise.resolve([]);
  return Promise.resolve(client.auditEvents({ limit: 6 }))
    .then((events) => events ?? [])
    .catch(() => []);
}

const pqcAlgorithmPattern = /^(ml-kem|ml-dsa|slh-dsa|hybrid)/i;

function isPqcReady(certificate: Certificate): boolean {
  return pqcAlgorithmPattern.test(certificate.key_algorithm ?? "");
}

function expiresWithinDays(certificate: Certificate, days: number): boolean {
  if (!certificate.not_after || certificate.status === "revoked") return false;
  const expires = new Date(certificate.not_after).getTime();
  if (!Number.isFinite(expires)) return false;
  const now = Date.now();
  return expires >= now && expires <= now + days * dayMs;
}

/** Served algorithm mix: group live certificates by key algorithm so the donut
 * legend can never disagree with its own center count (DA-01's worst case). */
function servedAlgoMix(certificates: Certificate[]): Array<{ algo: string; n: number }> {
  const counts = new Map<string, number>();
  for (const certificate of certificates) {
    const algo = certificate.key_algorithm?.trim() || "unknown";
    counts.set(algo, (counts.get(algo) ?? 0) + 1);
  }
  return Array.from(counts.entries())
    .sort(([, a], [, b]) => b - a)
    .map(([algo, n]) => ({ algo, n }));
}

/** Served expiry bands over the live inventory (excludes revoked; counts every
 * non-expired certificate exactly once). */
function servedExpiryBands(certificates: Certificate[]): Array<{ label: string; n: number; tone: "crit" | "warn" | "ok" }> {
  let b7 = 0;
  let b30 = 0;
  let b90 = 0;
  let bLater = 0;
  const now = Date.now();
  for (const certificate of certificates) {
    if (!certificate.not_after || certificate.status === "revoked") continue;
    const expires = new Date(certificate.not_after).getTime();
    if (!Number.isFinite(expires) || expires < now) continue;
    const days = (expires - now) / dayMs;
    if (days <= 7) b7 += 1;
    else if (days <= 30) b30 += 1;
    else if (days <= 90) b90 += 1;
    else bLater += 1;
  }
  return [
    { label: translateNow("source.7d.bf8cc07ad6"), n: b7, tone: "crit" },
    { label: translateNow("source.7.30d.59a2cd28cb"), n: b30, tone: "warn" },
    { label: translateNow("source.30.90d.4e79b75fb1"), n: b90, tone: "ok" },
    { label: translateNow("source.90d.3ba89ead35"), n: bLater, tone: "ok" },
  ];
}

/** Dashboard is the single pane of glass over every non-human identity. Both
 * tenants and the isolated preview render through the same served read-model
 * shapes; previewData supplies those shapes only in the explicit demo build. */
export function Dashboard() {
  const { preview } = useAuth();
  const { formatNumber, t } = useTranslation();
  // S-C5 live tiles: Home's answers poll while the tab is visible (30s for
  // KPI feeds, 60s for the audit stream), pause entirely while hidden, and
  // catch up the moment the operator returns (certctl PERF-H1 pattern).
  const certs = useApiQuery(["certificates"], api.certificates, { live: { intervalMs: 30_000 } });
  const risk = useApiQuery(["risk", { sort: "score" }], () => api.risk({ sort: "score" }), { live: { intervalMs: 30_000 } });
  const identities = useApiQuery(["identities"], api.identities, { live: { intervalMs: 30_000 } });
  const nhiInventory = useApiQuery(["nhi-inventory"], readNhiInventory, { live: { intervalMs: 30_000 } });
  const rotationRuns = useApiQuery(["rotation-runs", { limit: 100 }], () => api.rotationRuns({ limit: 100 }), { live: { intervalMs: 30_000 } });
  // D2: what the estate is actually SERVING, as against what was deployed. The
  // two diverge silently, and this is the only tile on this page sourced from
  // observations rather than from trstctl's own records.
  const verifications = useApiQuery(
    ["endpoint-verifications"],
    () => (typeof api.endpointVerifications === "function" ? api.endpointVerifications() : Promise.reject(new Error("unavailable"))),
    { live: { intervalMs: 60_000 } },
  );
  const secretsCount = useApiQuery(["secrets-count"], readSecretsCount, { live: { intervalMs: 30_000 } });
  const openIncidents = useApiQuery(["open-incidents"], readOpenIncidents, { live: { intervalMs: 30_000 } });
  const recentAudit = useApiQuery(["recent-audit"], readRecentAudit, { live: { intervalMs: 60_000 } });
  const [dismissed, setDismissed] = useState(false);

  const riskRows = risk.data ?? [];
  const inventoryTotal = nhiInventory.data?.items?.length ?? identities.data?.length ?? 0;
  const resourcesLoading = certs.loading || risk.loading || identities.loading || nhiInventory.loading;
  const realEmpty = !resourcesLoading && (certs.data?.length ?? 0) === 0 && riskRows.length === 0 && inventoryTotal === 0;
  // A real, empty tenant that has not completed first-run setup is sent to the
  // wizard. Preview is populated by the isolated read-model catalog.
  const showOnboarding = realEmpty && !preview && !readOnboardingDone() && !dismissed;
  const servedCertificates = certs.data ?? [];
  const servedRotationRuns = rotationRuns.data?.items ?? [];

  const topRisk = [...riskRows].sort((a, b) => b.score - a.score).slice(0, 5);
  const highRisk = riskRows.filter((r) => r.score >= highRiskThreshold).length;

  const kpis = {
    certificates: certs.data?.length ?? 0,
    identities: inventoryTotal,
    secrets: secretsCount.data ?? inventoryCount(nhiInventory.data, "secret"),
    agentsOnline: inventoryCount(nhiInventory.data, "agent"),
    agentsTotal: inventoryCount(nhiInventory.data, "agent"),
    expiring7d: servedCertificates.filter((c) => expiresWithinDays(c, 7)).length,
    highRisk,
    openIncidents: openIncidents.data ?? 0,
    pqcReady: servedCertificates.filter(isPqcReady).length,
  };

  const rotateFirst = topRisk.map((r) => ({ subject: r.subject, detail: `risk score ${Math.round(r.score)}`, score: Math.round(r.score) }));

  if (showOnboarding) {
    return (
      <section aria-labelledby="dashboard-heading" className="space-y-6">
        <PageHeader
          title={translateNow("source.dashboard.67b6964686")}
          titleId="dashboard-heading"
          description="A single pane of glass over every non-human identity across your hybrid fleet."
        />
        <EmptyState
          icon={<Rocket className="h-5 w-5" aria-hidden="true" />}
          title={translateNow("source.welcome.to.trstctl.let.s.set.it.up.7d04de0c8b")}
          primaryAction={{ label: translateNow("source.set.up.trstctl.b56c208e41"), to: "/wizard", icon: <Rocket className="h-4 w-4" aria-hidden="true" /> }}
          secondaryAction={{ label: translateNow("source.explore.the.console.1f6607ee75"), onClick: () => setDismissed(true) }}
        >
          {translateNow("source.this.tenant.has.no.credentials.yet.the.fou.7b31a81e81")}
        </EmptyState>
      </section>
    );
  }

  // Nothing observed means no tile. A verified percentage over an estate
  // nobody has probed would read as an all-clear that nothing earned.
  const summary = verifications.data?.summary;
  const verificationTile =
    summary && summary.endpoints > 0
      ? {
          percent: summary.verified_percent,
          sub:
            summary.diverged > 0
              ? `${summary.diverged} diverged`
              : summary.unreachable > 0
                ? `${summary.unreachable} unreachable`
                : `${summary.verified}/${summary.endpoints} serving`,
          tone: summary.diverged > 0 ? ("crit" as const) : summary.unreachable > 0 ? ("warn" as const) : undefined,
        }
      : null;

  return (
    <section aria-labelledby="dashboard-heading" className="space-y-6">
      <PageHeader
        title={translateNow("source.dashboard.67b6964686")}
        titleId="dashboard-heading"
        description="A single pane of glass over every non-human identity — certificates, workloads, secrets, SSH and AI agents — across your hybrid fleet."
        actions={
          <>
            <ActionLink to="/discovery" icon={<Search className="h-4 w-4" aria-hidden="true" />}>
              {translateNow("source.discover.d4a33d5b78")}
            </ActionLink>
            <ActionLink to="/identities" icon={<RotateCw className="h-4 w-4" aria-hidden="true" />}>
              {translateNow("source.rotate.c3613b1704")}
            </ActionLink>
            <ActionLink to="/request" icon={<KeyRound className="h-4 w-4" aria-hidden="true" />} primary>
              {translateNow("source.issue.credential.ab0616c48f")}
            </ActionLink>
          </>
        }
      />

      {/* KPI row */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <Kpi icon={<ScrollText className="h-4 w-4" />} label="Certificates" value={kpis.certificates} to="/certificates" />
        <Kpi icon={<KeyRound className="h-4 w-4" />} label="Identities (NHI)" value={kpis.identities} to="/identities" />
        <Kpi icon={<Boxes className="h-4 w-4" />} label="Secrets" value={kpis.secrets} to="/secrets" />
        <Kpi
          icon={<Activity className="h-4 w-4" />}
          label="Agents online"
          value={kpis.agentsOnline}
          to="/agents"
          sub={kpis.agentsTotal ? `${kpis.agentsOnline}/${kpis.agentsTotal}` : undefined}
        />
        <Kpi
          icon={<AlertTriangle className="h-4 w-4" />}
          label="Expiring ≤7d"
          value={kpis.expiring7d}
          sub="needs action"
          tone="warn"
          to="/certificates?expiry=7d"
        />
        <Kpi icon={<ShieldAlert className="h-4 w-4" />} label="High-risk" value={kpis.highRisk} sub="rotate" tone="crit" to="/risk?sort=score" />
        {/* D2: verified % is a percentage of OBSERVED endpoints, not of the
            estate. Endpoints nobody has configured a listener address for are
            absent rather than counted — counting them as unverified would
            punish operators for the parts they have not reached yet, and
            counting them as verified would be a lie. The tile is hidden
            entirely until something has been observed, because "100%" over
            zero endpoints is the most misleading number this page could show. */}
        {verificationTile ? (
          <Kpi
            icon={<ShieldCheck className="h-4 w-4" />}
            label="Endpoints verified"
            value={verificationTile.percent}
            valueSuffix="%"
            sub={verificationTile.sub}
            tone={verificationTile.tone}
            to="/connectors"
          />
        ) : null}
        <Kpi
          icon={<Siren className="h-4 w-4" />}
          label="Open incidents"
          value={kpis.openIncidents}
          sub={kpis.openIncidents ? `${kpis.openIncidents} active` : "none"}
          tone={kpis.openIncidents ? "warn" : "ok"}
          to="/incidents"
        />
        <Kpi icon={<ShieldCheck className="h-4 w-4" />} label="Future-ready" value={kpis.pqcReady} to="/posture" tone="ok" />
      </div>

      {/* Non-human identity inventory — by kind, with a shared risk lens. */}
      <NhiInventory identities={identities.data ?? []} inventory={nhiInventory.data ?? undefined} risks={riskRows} />
      <NotificationCenter risks={riskRows} certs={certs.data ?? []} />
      <DashboardTrendCharts certificates={servedCertificates} rotationRuns={servedRotationRuns} />
      {/* 47-day renewal readiness on the global home (C-D1, 07-closeout plan):
          derived from the same served certs + rotation runs as the trend
          charts — the posture statement lives here, the simulator stays on
          Certificates. The 100-day SC-081 step lands 2027-03-15. */}
      <ReadinessPanel
        certificates={servedCertificates}
        rotationRuns={servedRotationRuns}
        actions={
          <Link to="/certificates?tab=renewal" className="text-caption font-medium text-brand-accent hover:underline">
            {t("dashboard.readiness.viewAll")}
          </Link>
        }
      />

      {/* Algorithm and expiry projections use the same served response shapes in
          both tenant and isolated-preview modes. */}
      <div className="grid gap-4 lg:grid-cols-3">
        <Card>
          <CardHeader>
            <CardTitle>
              {translateNow("source.algorithm.mix.a5ab80b898")}{" "}
              <span className="ml-1 text-caption font-normal text-muted-foreground">{translateNow("source.by.key.type.7228596a06")}</span>
            </CardTitle>
          </CardHeader>
          <CardContent>
            <Donut
              segments={algoSegments(servedAlgoMix(servedCertificates))}
              ariaLabel="Algorithm mix by key type"
              centerLabel={formatNumber(kpis.certificates)}
              centerSub="certificates"
              withLegend
            />
          </CardContent>
        </Card>
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle>
              {translateNow("source.expiry.bands.cbfe64f7cb")}{" "}
              <span className="ml-1 text-caption font-normal text-muted-foreground">{translateNow("source.time.to.expiry.b1bf11183a")}</span>
            </CardTitle>
          </CardHeader>
          <CardContent>
            <Bands bands={servedExpiryBands(servedCertificates)} />
          </CardContent>
        </Card>
      </div>

      {/* Rotate first + recent activity */}
      <div className="grid gap-4 lg:grid-cols-3">
        <Card>
          <CardHeader className="flex-row items-baseline justify-between space-y-0">
            <CardTitle>
              {translateNow("source.rotate.first.f4ea83b5ca")}{" "}
              <span className="ml-1 text-caption font-normal text-muted-foreground">{translateNow("source.highest.risk.c56ed7dd58")}</span>
            </CardTitle>
            <Link to="/risk?sort=score" className="text-caption font-medium text-brand-accent hover:underline">
              {translateNow("source.view.all.9a780508de")}
            </Link>
          </CardHeader>
          <CardContent>
            <ul className="-mt-1 divide-y divide-border">
              {rotateFirst.map((r) => (
                <li key={r.subject} className="flex items-center justify-between gap-3 py-2">
                  <span className="min-w-0">
                    <span className="block truncate text-body font-medium">{r.subject}</span>
                    <span className="block truncate text-caption text-muted-foreground">{r.detail}</span>
                  </span>
                  <RiskPip score={r.score} />
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex-row items-baseline justify-between space-y-0">
            <CardTitle>
              {translateNow("source.recent.activity.6cb44b5633")}{" "}
              <span className="ml-1 text-caption font-normal text-muted-foreground">{translateNow("source.audit.stream.22c7391e55")}</span>
            </CardTitle>
            <Link to="/audit" className="text-caption font-medium text-brand-accent hover:underline">
              {translateNow("source.explorer.464ef011fa")}
            </Link>
          </CardHeader>
          <CardContent>
            <RecentAuditList events={recentAudit.data ?? []} />
          </CardContent>
        </Card>
      </div>
    </section>
  );
}

function DashboardTrendCharts({ certificates, rotationRuns }: { certificates: Certificate[]; rotationRuns: RotationRun[] }) {
  const { locale, timeZone } = useTranslation();
  const formatPolicy = { locale, timeZone };
  const issuanceData = issuanceRateData(certificates, formatPolicy);
  const renewalData = renewalTrendData(rotationRuns, formatPolicy);
  const expirationData = expirationTimelineData(certificates, formatPolicy);

  return (
    <div className="grid gap-4 xl:grid-cols-3">
      <TrendCard title={translateNow("source.issuance.rate.91f4b7ff0d")} description="certificates recorded by day">
        <TimeBarChart ariaLabel="Certificate issuance rate by day" data={issuanceData} tone="brand" />
      </TrendCard>
      <TrendCard title={translateNow("source.renewal.jobs.ef0c816533")} description="success vs failure by day">
        <StackedTimeBarChart ariaLabel="Renewal job success and failure trend" data={renewalData} />
      </TrendCard>
      <TrendCard title={translateNow("source.expiration.timeline.d4a2b2aa1e")} description="next 90 days">
        <TimeBarChart ariaLabel="Certificate expirations over the next 90 days" data={expirationData} tone="warning" />
      </TrendCard>
    </div>
  );
}

function TrendCard({ children, description, title }: { children: ReactNode; description: string; title: string }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>
          {title} <span className="ml-1 text-caption font-normal text-muted-foreground">{description}</span>
        </CardTitle>
      </CardHeader>
      <CardContent>{children}</CardContent>
    </Card>
  );
}

function ActionLink({ to, icon, children, primary }: { to: string; icon: ReactNode; children: ReactNode; primary?: boolean }) {
  return (
    <Link
      to={to}
      className={
        primary
          ? "inline-flex min-h-9 items-center gap-2 rounded-control bg-primary px-3 py-2 text-body font-medium text-primary-foreground shadow-elevation1 transition hover:brightness-110 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus focus-visible:ring-offset-2 focus-visible:ring-offset-background"
          : "inline-flex min-h-9 items-center gap-2 rounded-control border border-border bg-card px-3 py-2 text-body font-medium transition-colors hover:border-brand-accent/40 hover:bg-muted/60 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus focus-visible:ring-offset-2 focus-visible:ring-offset-background"
      }
    >
      <span className={primary ? "" : "text-brand-accent"}>{icon}</span>
      {children}
    </Link>
  );
}

/* ----------------------------------------------------------------- KPI ---- */

function Kpi({
  icon,
  label,
  value,
  valueSuffix,
  delta,
  sub,
  spark,
  tone,
  to,
}: {
  icon: ReactNode;
  label: string;
  value: number;
  // valueSuffix renders immediately after the formatted number — "%" for a
  // ratio tile. Kept separate from the value so the number still goes through
  // formatNumber and stays localized.
  valueSuffix?: string;
  delta?: string;
  sub?: string;
  spark?: number[];
  tone?: "ok" | "warn" | "crit";
  to?: string;
}) {
  const { formatNumber } = useTranslation();
  const toneClass =
    tone === "crit" ? "text-destructive" : tone === "warn" ? "text-status-warning" : tone === "ok" ? "text-status-success" : "text-muted-foreground";
  const inner = (
    <Card className="h-full transition-[box-shadow,border-color,transform] group-hover:-translate-y-0.5 group-hover:border-brand-accent/40 group-hover:shadow-elevation2">
      <CardContent className="p-comfortable">
        <div className="flex items-center gap-2 text-caption font-medium text-muted-foreground">
          <span className="text-brand-accent">{icon}</span>
          {label}
        </div>
        <div className="mt-2 flex min-w-0 items-end justify-between gap-2">
          <span className="text-display font-semibold tracking-tight tabular-nums">
            {formatNumber(value)}
            {valueSuffix ? <span className="text-title font-medium text-muted-foreground">{valueSuffix}</span> : null}
          </span>
          {spark && <Sparkline points={spark} width={84} height={28} className="shrink" />}
        </div>
        {(delta || sub) && <div className={`mt-1 text-caption font-medium ${toneClass}`}>{delta ?? sub}</div>}
      </CardContent>
    </Card>
  );
  return to ? (
    <Link
      to={to}
      className="group block rounded-panel focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus focus-visible:ring-offset-2 focus-visible:ring-offset-background"
    >
      {inner}
    </Link>
  ) : (
    <div className="group">{inner}</div>
  );
}

/** RecentAuditList renders the SERVED audit stream (S-N0): event type, short
 * hash, and event time — no fabricated ok/retry chips, because audit events
 * are facts, not delivery attempts. */
function RecentAuditList({ events }: { events: AuditEvent[] }) {
  const { locale, timeZone, t } = useTranslation();
  const policy = { locale, timeZone };
  if (events.length === 0) {
    return <p className="py-2 text-caption text-muted-foreground">{t("dashboard.recentActivity.empty")}</p>;
  }
  return (
    <ul className="-mt-1 divide-y divide-border">
      {events.map((event) => (
        <li key={`${event.sequence}-${event.hash ?? ""}`} className="flex items-center justify-between gap-3 py-2">
          <span className="min-w-0">
            <span className="block truncate font-mono text-caption font-medium">{event.type}</span>
            {event.hash && <span className="block truncate text-caption text-muted-foreground">{event.hash.slice(0, 12)}…</span>}
          </span>
          <span className="shrink-0 font-mono text-caption text-muted-foreground">
            {formatDateTime(event.time, policy, { dateStyle: undefined, timeStyle: "short" })}
          </span>
        </li>
      ))}
    </ul>
  );
}

function RiskPip({ score }: { score: number }) {
  const tone =
    score >= 90 ? "bg-destructive/10 text-destructive" : score >= 75 ? "bg-status-warning/10 text-status-warning" : "bg-risk-medium/10 text-risk-medium";
  return <span className={`shrink-0 rounded-control px-2 py-0.5 text-caption font-semibold tabular-nums ${tone}`}>{score}</span>;
}

/* -------------------------------------------------------------- charts ---- */

const dayMs = 24 * 60 * 60 * 1000;

function issuanceRateData(certificates: Certificate[], policy: FormatPolicy): TimeBarDatum[] {
  const counts = new Map<string, number>();
  for (const certificate of certificates) {
    const key = dayKey(certificate.created_at ?? certificate.not_before);
    if (!key) continue;
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }
  return sortedCountData(counts, "brand", policy);
}

function renewalTrendData(rotationRuns: RotationRun[], policy: FormatPolicy): StackedTimeBarDatum[] {
  const counts = new Map<string, { failed: number; succeeded: number }>();
  for (const run of rotationRuns) {
    if (run.status !== "failed" && run.status !== "succeeded") continue;
    const key = dayKey(run.updated_at ?? run.completed_at ?? run.created_at);
    if (!key) continue;
    const current = counts.get(key) ?? { failed: 0, succeeded: 0 };
    current[run.status] += 1;
    counts.set(key, current);
  }
  return Array.from(counts.entries())
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([key, count]) => ({
      label: shortDateLabel(key, policy),
      segments: [
        { label: translateNow("source.succeeded.5dceaeceb6"), value: count.succeeded, tone: "success" as const },
        { label: translateNow("source.failed.5d28a90f44"), value: count.failed, tone: "critical" as const },
      ],
    }));
}

function expirationTimelineData(certificates: Certificate[], policy: FormatPolicy): TimeBarDatum[] {
  const now = Date.now();
  const horizon = now + 90 * dayMs;
  const counts = new Map<string, number>();
  for (const certificate of certificates) {
    if (!certificate.not_after) continue;
    const expires = new Date(certificate.not_after).getTime();
    if (!Number.isFinite(expires) || expires < now || expires > horizon) continue;
    const key = dayKey(certificate.not_after);
    if (!key) continue;
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }
  return sortedCountData(counts, "warning", policy);
}

function sortedCountData(counts: Map<string, number>, tone: TimeBarDatum["tone"], policy: FormatPolicy): TimeBarDatum[] {
  return Array.from(counts.entries())
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([key, value]) => ({ label: shortDateLabel(key, policy), value, tone }));
}

function dayKey(value?: string): string {
  if (!value) return "";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "";
  return date.toISOString().slice(0, 10);
}

function shortDateLabel(day: string, policy: FormatPolicy): string {
  return formatShortDate(`${day}T12:00:00Z`, policy);
}

/* Algorithm-mix donut tones: five tone families that stay distinct in BOTH
 * themes (several semantic tokens alias to the same mint/blue in dark mode,
 * so the cycle picks from non-overlapping families). */
const algoTones: ChartTone[] = ["operate", "observe", "gold", "high", "disclose"];

function algoSegments(mix: Array<{ algo: string; n: number }>): DonutSegment[] {
  return mix.map((segment, index) => ({ label: segment.algo, value: segment.n, tone: algoTones[index % algoTones.length] }));
}

function Bands({ bands }: { bands: Array<{ label: string; n: number; tone: "crit" | "warn" | "ok" }> }) {
  const { formatNumber } = useTranslation();
  const max = Math.max(...bands.map((b) => b.n), 1);
  const toneClass = (t: string) => (t === "crit" ? "bg-destructive" : t === "warn" ? "bg-status-warning" : "bg-brand-accent");
  return (
    <ul className="space-y-3">
      {bands.map((b) => (
        <li key={b.label}>
          <div className="mb-1 flex items-center justify-between text-caption">
            <span className="text-muted-foreground">{b.label}</span>
            <span className="font-medium tabular-nums">
              {formatNumber(b.n)} {translateNow("source.certs.254090ae56")}
            </span>
          </div>
          <div className="h-2 overflow-hidden rounded-full bg-muted">
            <div className={`h-full rounded-full ${toneClass(b.tone)}`} style={{ width: `${Math.max(3, (b.n / max) * 100)}%` }} />
          </div>
        </li>
      ))}
    </ul>
  );
}
