import { useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { Activity, AlertTriangle, Boxes, KeyRound, RotateCw, Rocket, ScrollText, Search, ShieldCheck, ShieldAlert, Siren } from "lucide-react";
import { api, type Certificate, type NHIInventory as NHIInventoryResponse, type RotationRun } from "@/lib/api";
import { useAuth } from "@/auth/AuthProvider";
import { useResource } from "@/lib/useResource";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { StackedTimeBarChart, TimeBarChart, type StackedTimeBarDatum, type TimeBarDatum } from "@/components/charts";
import { EmptyState } from "@/components/EmptyState";
import { PageHeader } from "@/components/PageHeader";
import { NhiInventory } from "@/components/nhi";
import { NotificationCenter } from "@/components/notifications";
import { demoDashboard } from "@/lib/demoData";
import { isOnboardingComplete } from "@/lib/onboardingState";
import { formatNumber as formatNumberPolicy } from "@/i18n/format";

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

/** Dashboard is the single pane of glass over every non-human identity. It renders
 * real served data when present; in dev/preview (no backend) it falls back to demo
 * data so the console reads as a live product rather than an empty shell. */
export function Dashboard() {
  const { preview } = useAuth();
  const certs = useResource(api.certificates);
  const risk = useResource(() => api.risk({ sort: "score" }));
  const identities = useResource(api.identities);
  const nhiInventory = useResource(readNhiInventory);
  const rotationRuns = useResource(() => api.rotationRuns({ limit: 100 }));
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
        secrets: inventoryCount(nhiInventory.data, "secret"),
        agentsOnline: inventoryCount(nhiInventory.data, "agent"),
        agentsTotal: inventoryCount(nhiInventory.data, "agent"),
        expiring7d: 0,
        highRisk,
        openIncidents: 0,
        pqcReady: 0,
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
          This tenant has no credentials yet. The four-step setup connects an issuer, issues your first
          certificate, and enrolls an agent — about five minutes. Prefer to look around first? Explore the console.
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
          spark={d.issuanceTrend}
        />
        <Kpi
          icon={<KeyRound className="h-4 w-4" />}
          label="Identities (NHI)"
          value={kpis.identities}
          delta={useDemo ? d.deltas.identities : undefined}
          spark={[28, 31, 30, 34, 33, 37, 39, 41, 44, 46, 48, 51]}
        />
        <Kpi
          icon={<Boxes className="h-4 w-4" />}
          label="Secrets"
          value={kpis.secrets}
          delta={useDemo ? d.deltas.secrets : undefined}
          spark={[20, 22, 21, 24, 23, 25, 26, 27, 27, 29, 30, 31]}
        />
        <Kpi
          icon={<Activity className="h-4 w-4" />}
          label="Agents online"
          value={kpis.agentsOnline}
          sub={kpis.agentsTotal ? `${kpis.agentsOnline}/${kpis.agentsTotal}` : undefined}
          spark={[44, 45, 46, 46, 47, 46, 47, 48, 47, 48, 46, 48]}
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
          label="PQC-ready"
          value={kpis.pqcReady}
          delta={useDemo ? d.deltas.pqcReady : undefined}
          tone="ok"
          spark={[10, 13, 16, 18, 21, 24, 26, 28, 30, 31, 33, 34]}
        />
      </div>

      {/* Non-human identity inventory — by kind, with a shared risk lens (real data only) */}
      {!useDemo && <NhiInventory identities={identities.data ?? []} inventory={nhiInventory.data ?? undefined} risks={riskRows} />}
      {!useDemo && <NotificationCenter risks={riskRows} certs={certs.data ?? []} />}
      {!useDemo && <DashboardTrendCharts certificates={servedCertificates} rotationRuns={servedRotationRuns} />}

      {/* Trend + algorithm mix */}
      <div className="grid gap-4 lg:grid-cols-3">
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
            <AreaTrend values={d.issuanceTrend} />
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>
              Algorithm mix <span className="ml-1 text-caption font-normal text-muted-foreground">by key type</span>
            </CardTitle>
          </CardHeader>
          <CardContent>
            <Donut segments={d.algoMix} centerLabel={formatNumberPolicy(kpis.certificates)} centerSub="certificates" />
          </CardContent>
        </Card>
      </div>

      {/* Expiry bands + rotate first + recent activity */}
      <div className="grid gap-4 lg:grid-cols-3">
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
          </CardContent>
        </Card>
      </div>
    </section>
  );
}

function DashboardTrendCharts({ certificates, rotationRuns }: { certificates: Certificate[]; rotationRuns: RotationRun[] }) {
  const issuanceData = issuanceRateData(certificates);
  const renewalData = renewalTrendData(rotationRuns);
  const expirationData = expirationTimelineData(certificates);

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
  const toneClass =
    tone === "crit" ? "text-destructive" : tone === "warn" ? "text-status-warning" : tone === "ok" ? "text-status-success" : "text-muted-foreground";
  const inner = (
    <Card className="h-full transition-[box-shadow,border-color,transform] group-hover:-translate-y-0.5 group-hover:border-brand-accent/40 group-hover:shadow-elevation2">
      <CardContent className="p-comfortable">
        <div className="flex items-center gap-2 text-caption font-medium text-muted-foreground">
          <span className="text-brand-accent">{icon}</span>
          {label}
        </div>
        <div className="mt-2 flex items-end justify-between gap-2">
          <span className="text-display font-semibold tracking-tight tabular-nums">{formatNumberPolicy(value)}</span>
          {spark && <Sparkline values={spark} />}
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

function RiskPip({ score }: { score: number }) {
  const tone =
    score >= 90 ? "bg-destructive/10 text-destructive" : score >= 75 ? "bg-status-warning/10 text-status-warning" : "bg-risk-medium/10 text-risk-medium";
  return <span className={`shrink-0 rounded-control px-2 py-0.5 text-caption font-semibold tabular-nums ${tone}`}>{score}</span>;
}

/* -------------------------------------------------------------- charts ---- */

const dayMs = 24 * 60 * 60 * 1000;

function issuanceRateData(certificates: Certificate[]): TimeBarDatum[] {
  const counts = new Map<string, number>();
  for (const certificate of certificates) {
    const key = dayKey(certificate.created_at ?? certificate.not_before);
    if (!key) continue;
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }
  return sortedCountData(counts, "brand");
}

function renewalTrendData(rotationRuns: RotationRun[]): StackedTimeBarDatum[] {
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
      label: shortDateLabel(key),
      segments: [
        { label: "succeeded", value: count.succeeded, tone: "success" as const },
        { label: "failed", value: count.failed, tone: "critical" as const },
      ],
    }));
}

function expirationTimelineData(certificates: Certificate[]): TimeBarDatum[] {
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
  return sortedCountData(counts, "warning");
}

function sortedCountData(counts: Map<string, number>, tone: TimeBarDatum["tone"]): TimeBarDatum[] {
  return Array.from(counts.entries())
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([key, value]) => ({ label: shortDateLabel(key), value, tone }));
}

function dayKey(value?: string): string {
  if (!value) return "";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "";
  return date.toISOString().slice(0, 10);
}

function shortDateLabel(day: string): string {
  return new Intl.DateTimeFormat("en-US", { month: "short", day: "numeric", timeZone: "UTC" }).format(new Date(`${day}T00:00:00Z`));
}

function Sparkline({ values }: { values: number[] }) {
  const w = 84;
  const h = 28;
  const max = Math.max(...values);
  const min = Math.min(...values);
  const span = Math.max(1, max - min);
  const pts = values.map((v, i) => [(i / (values.length - 1)) * w, h - ((v - min) / span) * (h - 4) - 2]);
  const line = pts.map(([x, y]) => `${x.toFixed(1)},${y.toFixed(1)}`).join(" ");
  return (
    <svg width={w} height={h} viewBox={`0 0 ${w} ${h}`} aria-hidden="true" className="overflow-visible">
      <polyline points={line} fill="none" stroke="hsl(var(--brand-accent))" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

function AreaTrend({ values }: { values: number[] }) {
  const w = 640;
  const h = 200;
  const pad = 8;
  const max = Math.max(...values);
  const min = Math.min(...values);
  const span = Math.max(1, max - min);
  const x = (i: number) => pad + (i / (values.length - 1)) * (w - pad * 2);
  const y = (v: number) => pad + (1 - (v - min) / span) * (h - pad * 2);
  const line = values.map((v, i) => `${x(i).toFixed(1)},${y(v).toFixed(1)}`).join(" ");
  const area = `M ${x(0)},${y(values[0])} L ${line.split(" ").join(" L ")} L ${x(values.length - 1)},${h - pad} L ${x(0)},${h - pad} Z`;
  return (
    <svg viewBox={`0 0 ${w} ${h}`} className="h-48 w-full" role="img" aria-label="Issuance trend over the last 12 months">
      <defs>
        <linearGradient id="trendfill" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor="hsl(var(--brand-accent))" stopOpacity="0.22" />
          <stop offset="100%" stopColor="hsl(var(--brand-accent))" stopOpacity="0" />
        </linearGradient>
      </defs>
      {[0.25, 0.5, 0.75].map((g) => (
        <line key={g} x1={pad} x2={w - pad} y1={pad + g * (h - pad * 2)} y2={pad + g * (h - pad * 2)} stroke="hsl(var(--border))" strokeWidth="1" />
      ))}
      <path d={area} fill="url(#trendfill)" />
      <polyline points={line} fill="none" stroke="hsl(var(--brand-accent))" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" />
      {values.map((v, i) => (
        <circle key={i} cx={x(i)} cy={y(v)} r="2.6" fill="hsl(var(--card))" stroke="hsl(var(--brand-accent))" strokeWidth="1.6" />
      ))}
    </svg>
  );
}

const donutPalette = ["hsl(var(--brand-accent))", "hsl(var(--observe))", "hsl(var(--status-info))", "hsl(var(--risk-medium))", "hsl(var(--disclose))"];

function Donut({ segments, centerLabel, centerSub }: { segments: Array<{ algo: string; n: number }>; centerLabel: string; centerSub: string }) {
  const total = segments.reduce((s, x) => s + x.n, 0) || 1;
  const r = 52;
  const c = 2 * Math.PI * r;
  const arcs = segments.reduce<{ offset: number; items: Array<{ algo: string; dash: string; strokeDashoffset: string; color: string }> }>(
    (state, seg, i) => {
      const frac = seg.n / total;
      return {
        offset: state.offset + frac,
        items: [
          ...state.items,
          {
            algo: seg.algo,
            dash: `${(frac * c).toFixed(2)} ${(c - frac * c).toFixed(2)}`,
            strokeDashoffset: (-state.offset * c).toFixed(2),
            color: donutPalette[i % donutPalette.length],
          },
        ],
      };
    },
    { offset: 0, items: [] },
  ).items;
  return (
    <div className="flex items-center gap-4">
      <svg width="128" height="128" viewBox="0 0 128 128" role="img" aria-label="Algorithm mix by key type">
        <g transform="rotate(-90 64 64)">
          <circle cx="64" cy="64" r={r} fill="none" stroke="hsl(var(--muted))" strokeWidth="16" />
          {arcs.map((arc) => (
            <circle
              key={arc.algo}
              cx="64"
              cy="64"
              r={r}
              fill="none"
              stroke={arc.color}
              strokeWidth="16"
              strokeDasharray={arc.dash}
              strokeDashoffset={arc.strokeDashoffset}
            />
          ))}
        </g>
        <text x="64" y="60" textAnchor="middle" className="fill-foreground text-[18px] font-semibold">
          {centerLabel}
        </text>
        <text x="64" y="78" textAnchor="middle" className="fill-muted-foreground text-[9px]">
          {centerSub}
        </text>
      </svg>
      <ul className="min-w-0 flex-1 space-y-1.5">
        {segments.map((seg, i) => (
          <li key={seg.algo} className="flex items-center justify-between gap-2 text-caption">
            <span className="flex min-w-0 items-center gap-2">
              <span className="h-2.5 w-2.5 shrink-0 rounded-sm" style={{ background: donutPalette[i % donutPalette.length] }} />
              <span className="truncate text-muted-foreground">{seg.algo}</span>
            </span>
            <span className="shrink-0 font-medium tabular-nums">{seg.n}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

function Bands({ bands }: { bands: Array<{ label: string; n: number; tone: "crit" | "warn" | "ok" }> }) {
  const max = Math.max(...bands.map((b) => b.n), 1);
  const toneClass = (t: string) => (t === "crit" ? "bg-destructive" : t === "warn" ? "bg-status-warning" : "bg-brand-accent");
  return (
    <ul className="space-y-3">
      {bands.map((b) => (
        <li key={b.label}>
          <div className="mb-1 flex items-center justify-between text-caption">
            <span className="text-muted-foreground">{b.label}</span>
            <span className="font-medium tabular-nums">{formatNumberPolicy(b.n)} certs</span>
          </div>
          <div className="h-2 overflow-hidden rounded-full bg-muted">
            <div className={`h-full rounded-full ${toneClass(b.tone)}`} style={{ width: `${Math.max(3, (b.n / max) * 100)}%` }} />
          </div>
        </li>
      ))}
    </ul>
  );
}
