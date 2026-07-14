import { useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { Activity, AlertTriangle, Boxes, KeyRound, RotateCw, Rocket, ScrollText, Search, ShieldCheck, ShieldAlert, Siren } from "lucide-react";
import { api, type AuditEvent, type Certificate, type NHIInventory as NHIInventoryResponse, type RotationRun } from "@/lib/api";
import { useAuth } from "@/auth/AuthProvider";
import { useResource } from "@/lib/useResource";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  AreaTrend,
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
import { NhiInventory } from "@/components/nhi";
import { NotificationCenter } from "@/components/notifications";
import { demoDashboard } from "@/lib/demoData";
import { isOnboardingComplete } from "@/lib/onboardingState";
import { useTranslation } from "@/i18n/I18nProvider";
import { formatDateTime, formatShortDate, type FormatPolicy } from "@/i18n/format";

const highRiskThreshold = 70;

function emptyNhiInventory(): NHIInventoryResponse {
  return { generated_at: new Date(0).toISOString(), items: [], summary: {}, coverage: [] };
}

function readNhiInventory(): Promise<NHIInventoryResponse> {
  const client = api as typeof api & { nhiInventory?: () => Promise<NHIInventoryResponse> };
  return client.nhiInventory ? client.nhiInventory() : Promise.resolve(emptyNhiInventory());
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
  return client.secretPage ? client.secretPage({ limit: 200 }).then((r) => (r.items ?? []).length) : Promise.resolve(null);
}

function readOpenIncidents(): Promise<number | null> {
  const client = api as typeof api & {
    incidentExecutions?: (o?: { limit?: number }) => Promise<{ items?: Array<{ status?: string }> }>;
  };
  if (!client.incidentExecutions) return Promise.resolve(null);
  return client.incidentExecutions({ limit: 100 }).then(
    (r) => (r.items ?? []).filter((x) => x.status !== "completed" && x.status !== "rolled_back").length,
  );
}

function readRecentAudit(): Promise<AuditEvent[]> {
  const client = api as typeof api & { auditEvents?: (o?: { limit?: number }) => Promise<AuditEvent[]> };
  return client.auditEvents ? client.auditEvents({ limit: 6 }).catch(() => []) : Promise.resolve([]);
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
    { label: "<7d", n: b7, tone: "crit" },
    { label: "7–30d", n: b30, tone: "warn" },
    { label: "30–90d", n: b90, tone: "ok" },
    { label: ">90d", n: bLater, tone: "ok" },
  ];
}

/** Dashboard is the single pane of glass over every non-human identity. It renders
 * real served data when present; in dev/preview (no backend) it falls back to demo
 * data so the console reads as a live product rather than an empty shell. */
export function Dashboard() {
  const { preview } = useAuth();
  const { formatNumber } = useTranslation();
  const certs = useResource(api.certificates);
  const risk = useResource(() => api.risk({ sort: "score" }));
  const identities = useResource(api.identities);
  const nhiInventory = useResource(readNhiInventory);
  const rotationRuns = useResource(() => api.rotationRuns({ limit: 100 }));
  const secretsCount = useResource(readSecretsCount);
  const openIncidents = useResource(readOpenIncidents);
  const recentAudit = useResource(readRecentAudit);
  const [dismissed, setDismissed] = useState(false);

  const riskRows = risk.data ?? [];
  const inventoryTotal = nhiInventory.data?.items?.length ?? identities.data?.length ?? 0;
  const resourcesLoading = certs.loading || risk.loading || identities.loading || nhiInventory.loading;
  const realEmpty = !resourcesLoading && (certs.data?.length ?? 0) === 0 && riskRows.length === 0 && inventoryTotal === 0;
  // Preview mode stays a showcase (demo data). A real, empty tenant that has not
  // completed first-run setup is sent to the wizard instead of seeing demo numbers.
  const showOnboarding = realEmpty && !preview && !readOnboardingDone() && !dismissed;
  const useDemo = preview;
  const servedCertificates = certs.data ?? [];
  const servedRotationRuns = rotationRuns.data?.items ?? [];

  const d = demoDashboard;
  const topRisk = [...riskRows].sort((a, b) => b.score - a.score).slice(0, 5);
  const highRisk = riskRows.filter((r) => r.score >= highRiskThreshold).length;

  const kpis = useDemo
    ? d.kpis
    : {
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

  const rotateFirst = useDemo
    ? d.rotateFirst
    : topRisk.map((r) => ({ subject: r.subject, detail: `risk score ${Math.round(r.score)}`, score: Math.round(r.score) }));

  if (showOnboarding) {
    return (
      <section aria-labelledby="dashboard-heading" className="space-y-6">
        <PageHeader
          title="Dashboard"
          titleId="dashboard-heading"
          description="A single pane of glass over every non-human identity across your hybrid fleet."
        />
        <EmptyState
          icon={<Rocket className="h-5 w-5" aria-hidden="true" />}
          title="Welcome to trstctl — let's set it up"
          primaryAction={{ label: "Set up trstctl", to: "/wizard", icon: <Rocket className="h-4 w-4" aria-hidden="true" /> }}
          secondaryAction={{ label: "Explore the console", onClick: () => setDismissed(true) }}
        >
          This tenant has no credentials yet. The four-step setup connects an issuer, issues your first certificate, and enrolls an agent — about five minutes.
          Prefer to look around first? Explore the console.
        </EmptyState>
      </section>
    );
  }

  return (
    <section aria-labelledby="dashboard-heading" className="space-y-6">
      <PageHeader
        title="Dashboard"
        titleId="dashboard-heading"
        description="A single pane of glass over every non-human identity — certificates, workloads, secrets, SSH and AI agents — across your hybrid fleet."
        actions={
          <>
            <ActionLink to="/discovery" icon={<Search className="h-4 w-4" aria-hidden="true" />}>
              Discover
            </ActionLink>
            <ActionLink to="/identities" icon={<RotateCw className="h-4 w-4" aria-hidden="true" />}>
              Rotate
            </ActionLink>
            <ActionLink to="/request" icon={<KeyRound className="h-4 w-4" aria-hidden="true" />} primary>
              Issue credential
            </ActionLink>
          </>
        }
      />

      {/* KPI row */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <Kpi
          icon={<ScrollText className="h-4 w-4" />}
          label="Certificates"
          value={kpis.certificates}
          delta={useDemo ? d.deltas.certificates : undefined}
          spark={useDemo ? d.issuanceTrend : undefined}
        />
        <Kpi
          icon={<KeyRound className="h-4 w-4" />}
          label="Identities (NHI)"
          value={kpis.identities}
          delta={useDemo ? d.deltas.identities : undefined}
          spark={useDemo ? [28, 31, 30, 34, 33, 37, 39, 41, 44, 46, 48, 51] : undefined}
        />
        <Kpi
          icon={<Boxes className="h-4 w-4" />}
          label="Secrets"
          value={kpis.secrets}
          delta={useDemo ? d.deltas.secrets : undefined}
          spark={useDemo ? [20, 22, 21, 24, 23, 25, 26, 27, 27, 29, 30, 31] : undefined}
        />
        <Kpi
          icon={<Activity className="h-4 w-4" />}
          label="Agents online"
          value={kpis.agentsOnline}
          sub={kpis.agentsTotal ? `${kpis.agentsOnline}/${kpis.agentsTotal}` : undefined}
          spark={useDemo ? [44, 45, 46, 46, 47, 46, 47, 48, 47, 48, 46, 48] : undefined}
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
        <Kpi
          icon={<Siren className="h-4 w-4" />}
          label="Open incidents"
          value={kpis.openIncidents}
          sub={kpis.openIncidents ? `${kpis.openIncidents} active` : "none"}
          tone={kpis.openIncidents ? "warn" : "ok"}
          to="/incidents"
        />
        <Kpi
          icon={<ShieldCheck className="h-4 w-4" />}
          label="Future-ready"
          value={kpis.pqcReady}
          delta={useDemo ? d.deltas.pqcReady : undefined}
          tone="ok"
          spark={useDemo ? [10, 13, 16, 18, 21, 24, 26, 28, 30, 31, 33, 34] : undefined}
        />
      </div>

      {/* Non-human identity inventory — by kind, with a shared risk lens (real data only) */}
      {!useDemo && <NhiInventory identities={identities.data ?? []} inventory={nhiInventory.data ?? undefined} risks={riskRows} />}
      {!useDemo && <NotificationCenter risks={riskRows} certs={certs.data ?? []} />}
      {!useDemo && <DashboardTrendCharts certificates={servedCertificates} rotationRuns={servedRotationRuns} />}

      {/* Trend + algorithm mix. The monthly issuance-trend card is demo-showcase
          only (S-N0/DA-01): real tenants already get the served daily charts above,
          and rendering the fabricated series beside them destroyed trust. The
          algorithm mix renders SERVED segments in real mode so its legend can
          never disagree with its own center count again. */}
      <div className="grid gap-4 lg:grid-cols-3">
        {useDemo && (
          <Card className="lg:col-span-2">
            <CardHeader className="flex-row items-baseline justify-between space-y-0">
              <CardTitle>
                Issuance trend <span className="ml-1 text-caption font-normal text-muted-foreground">credentials issued per month</span>
              </CardTitle>
              <span className="rounded-control bg-brand-accent/10 px-2 py-0.5 text-caption font-medium text-brand-accent">
                {d.issuanceTrend[d.issuanceTrend.length - 1] ?? 0} this month
              </span>
            </CardHeader>
            <CardContent>
              <AreaTrend points={d.issuanceTrend} ariaLabel="Issuance trend over the last 12 months" />
            </CardContent>
          </Card>
        )}
        <Card>
          <CardHeader>
            <CardTitle>
              Algorithm mix <span className="ml-1 text-caption font-normal text-muted-foreground">by key type</span>
            </CardTitle>
          </CardHeader>
          <CardContent>
            <Donut
              segments={algoSegments(useDemo ? d.algoMix : servedAlgoMix(servedCertificates))}
              ariaLabel="Algorithm mix by key type"
              centerLabel={formatNumber(kpis.certificates)}
              centerSub="certificates"
              withLegend
            />
          </CardContent>
        </Card>
        {!useDemo && (
          <Card className="lg:col-span-2">
            <CardHeader>
              <CardTitle>
                Expiry bands <span className="ml-1 text-caption font-normal text-muted-foreground">time to expiry</span>
              </CardTitle>
            </CardHeader>
            <CardContent>
              <Bands bands={servedExpiryBands(servedCertificates)} />
            </CardContent>
          </Card>
        )}
      </div>

      {/* Expiry bands + rotate first + recent activity */}
      <div className="grid gap-4 lg:grid-cols-3">
        {useDemo && (
          <Card>
            <CardHeader>
              <CardTitle>
                Expiry bands <span className="ml-1 text-caption font-normal text-muted-foreground">time to expiry</span>
              </CardTitle>
            </CardHeader>
            <CardContent>
              <Bands bands={d.expiryBands} />
            </CardContent>
          </Card>
        )}

        <Card>
          <CardHeader className="flex-row items-baseline justify-between space-y-0">
            <CardTitle>
              Rotate first <span className="ml-1 text-caption font-normal text-muted-foreground">highest-risk</span>
            </CardTitle>
            <Link to="/risk?sort=score" className="text-caption font-medium text-brand-accent hover:underline">
              View all →
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
              Recent activity <span className="ml-1 text-caption font-normal text-muted-foreground">audit stream</span>
            </CardTitle>
            <Link to="/audit" className="text-caption font-medium text-brand-accent hover:underline">
              Explorer →
            </Link>
          </CardHeader>
          <CardContent>
            {useDemo ? (
              <ul className="-mt-1 divide-y divide-border">
                {d.recentActivity.map((a, i) => (
                  <li key={`${a.action}-${i}`} className="flex items-center justify-between gap-3 py-2">
                    <span className="min-w-0">
                      <span className="block truncate font-mono text-caption font-medium">{a.action}</span>
                      <span className="block truncate text-caption text-muted-foreground">{a.detail}</span>
                    </span>
                    <span className="flex shrink-0 items-center gap-2">
                      <span
                        className={
                          a.result === "ok"
                            ? "rounded-control bg-status-success/10 px-1.5 py-0.5 text-caption font-medium text-status-success"
                            : a.result === "retry"
                              ? "rounded-control bg-status-warning/10 px-1.5 py-0.5 text-caption font-medium text-status-warning"
                              : "rounded-control bg-destructive/10 px-1.5 py-0.5 text-caption font-medium text-destructive"
                        }
                      >
                        {a.result === "retry" ? "retry(2)" : a.result}
                      </span>
                      <span className="font-mono text-caption text-muted-foreground">{a.ts}</span>
                    </span>
                  </li>
                ))}
              </ul>
            ) : (
              <RecentAuditList events={recentAudit.data ?? []} />
            )}
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
      <TrendCard title="Issuance rate" description="certificates recorded by day">
        <TimeBarChart ariaLabel="Certificate issuance rate by day" data={issuanceData} tone="brand" />
      </TrendCard>
      <TrendCard title="Renewal jobs" description="success vs failure by day">
        <StackedTimeBarChart ariaLabel="Renewal job success and failure trend" data={renewalData} />
      </TrendCard>
      <TrendCard title="Expiration timeline" description="next 90 days">
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
          ? "inline-flex min-h-9 items-center gap-2 rounded-control bg-primary px-3 py-2 text-body font-medium text-primary-foreground shadow-elevation1 transition hover:brightness-110 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-accent focus-visible:ring-offset-2 focus-visible:ring-offset-background"
          : "inline-flex min-h-9 items-center gap-2 rounded-control border border-border bg-card px-3 py-2 text-body font-medium transition-colors hover:border-brand-accent/40 hover:bg-muted/60 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-accent focus-visible:ring-offset-2 focus-visible:ring-offset-background"
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
  delta,
  sub,
  spark,
  tone,
  to,
}: {
  icon: ReactNode;
  label: string;
  value: number;
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
          <span className="text-display font-semibold tracking-tight tabular-nums">{formatNumber(value)}</span>
          {spark && <Sparkline points={spark} width={84} height={28} className="shrink" />}
        </div>
        {(delta || sub) && <div className={`mt-1 text-caption font-medium ${toneClass}`}>{delta ?? sub}</div>}
      </CardContent>
    </Card>
  );
  return to ? (
    <Link
      to={to}
      className="group block rounded-panel focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-accent focus-visible:ring-offset-2 focus-visible:ring-offset-background"
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
        { label: "succeeded", value: count.succeeded, tone: "success" as const },
        { label: "failed", value: count.failed, tone: "critical" as const },
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
            <span className="font-medium tabular-nums">{formatNumber(b.n)} certs</span>
          </div>
          <div className="h-2 overflow-hidden rounded-full bg-muted">
            <div className={`h-full rounded-full ${toneClass(b.tone)}`} style={{ width: `${Math.max(3, (b.n / max) * 100)}%` }} />
          </div>
        </li>
      ))}
    </ul>
  );
}
