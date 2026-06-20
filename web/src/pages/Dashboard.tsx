import type { ReactNode } from "react";
import { Link } from "react-router-dom";
import { AlertTriangle, Clock3, FileText, Gauge, Rocket, UserCheck, UserX } from "lucide-react";
import { api, type AuditEvent, type Certificate, type CredentialRisk } from "@/lib/api";
import { useResource } from "@/lib/useResource";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { EmptyState } from "@/components/EmptyState";
import { StatusBadge } from "@/components/StatusBadge";
import { approvalRows } from "@/lib/approvalQueue";
import { riskBand } from "@/lib/statusVocab";

const expiryWindowDays = 30;
const highRiskThreshold = 70;

function expiringBefore(days: number): string {
  return new Date(Date.now() + days * 24 * 60 * 60 * 1000).toISOString();
}

export function Dashboard() {
  const certs = useResource(api.certificates);
  const expiring = useResource(() =>
    api.certificatePage({ limit: 50, expiringBefore: expiringBefore(expiryWindowDays) }),
  );
  const risk = useResource(() => api.risk({ sort: "score" }));
  const identities = useResource(api.identities);
  const audit = useResource(() => api.auditEvents({ limit: 200 }));

  const riskRows = risk.data ?? [];
  const topRisk = [...riskRows].sort((a, b) => b.score - a.score).slice(0, 5);
  const highRiskRows = riskRows.filter((row) => row.score >= highRiskThreshold);
  const orphanedRows = riskRows.filter((row) => row.owner_active === false);
  const pendingApprovalRows = approvalRows(identities.data ?? []);
  const expiringRows = expiring.data?.items ?? [];
  const expiringSoon = expiringRows.filter((cert) => certificateExpiresWithin(cert, expiryWindowDays));
  const trend = lifecycleTrend(audit.data ?? []);
  const fresh =
    !certs.loading &&
    !risk.loading &&
    !identities.loading &&
    (certs.data?.length ?? 0) === 0 &&
    (risk.data?.length ?? 0) === 0 &&
    (identities.data?.length ?? 0) === 0;

  return (
    <section aria-labelledby="dashboard-heading">
      <h1 id="dashboard-heading" className="mb-4 text-2xl font-semibold">
        Overview
      </h1>

      {fresh && (
        <div className="mb-6">
          <EmptyState
            title="Welcome to trstctl"
            ctaTo="/wizard"
            ctaLabel="Get started"
          >
            Connect a CA, install an agent, and issue your first certificate — in under 15 minutes.
          </EmptyState>
        </div>
      )}

      <section aria-labelledby="quick-actions-heading" className="mb-6" aria-label="Quick actions">
        <h2 id="quick-actions-heading" className="mb-2 text-lg font-semibold">
          Quick actions
        </h2>
        <div className="flex flex-wrap gap-2">
          <QuickAction to="/request" icon={<Rocket className="h-4 w-4" aria-hidden="true" />}>
            Issue or request credential
          </QuickAction>
          <QuickAction to="/approvals" icon={<UserCheck className="h-4 w-4" aria-hidden="true" />}>
            Open approvals
          </QuickAction>
          <QuickAction to="/audit" icon={<FileText className="h-4 w-4" aria-hidden="true" />}>
            Export audit evidence
          </QuickAction>
        </div>
      </section>

      <section aria-labelledby="triage-heading" className="grid gap-4">
        <div>
          <h2 id="triage-heading" className="text-lg font-semibold">
            Operator triage
          </h2>
          <p className="mt-1 text-sm text-muted-foreground">Worklists that need attention first.</p>
        </div>
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
          <TriageTile
            to="/certificates?expiry=30d"
            icon={<Clock3 className="h-4 w-4" aria-hidden="true" />}
            title="What expires soon?"
            metric={expiring.loading ? "..." : expiringSoon.length}
            detail={`${expiryWindowDays}-day certificate worklist`}
            ariaLabel={`Review ${expiringSoon.length} expiring soon certificate${expiringSoon.length === 1 ? "" : "s"}`}
            status={<StatusBadge vocabulary="expiry" value={expiringSoon.length > 0 ? "watch" : "healthy"} />}
            error={expiring.error}
          />
          <TriageTile
            to="/approvals"
            icon={<AlertTriangle className="h-4 w-4" aria-hidden="true" />}
            title="Who needs approval?"
            metric={identities.loading ? "..." : pendingApprovalRows.length}
            detail="pending issue/revoke decisions"
            ariaLabel={`Review ${pendingApprovalRows.length} pending approval${pendingApprovalRows.length === 1 ? "" : "s"}`}
            status={<StatusBadge vocabulary="lifecycle" value={pendingApprovalRows.length > 0 ? "requested" : "issued"} />}
            error={identities.error}
          />
          <TriageTile
            to="/risk?sort=score"
            icon={<Gauge className="h-4 w-4" aria-hidden="true" />}
            title="What is highest risk?"
            metric={risk.loading ? "..." : topRisk[0] ? Math.round(topRisk[0].score) : "-"}
            detail={`${highRiskRows.length} high-risk credential${highRiskRows.length === 1 ? "" : "s"}`}
            ariaLabel={`Review ${highRiskRows.length} high-risk credential${highRiskRows.length === 1 ? "" : "s"}`}
            status={<StatusBadge vocabulary="risk" value={topRisk[0] ? riskBand(topRisk[0].score) : "none"} />}
            error={risk.error}
          />
          <TriageTile
            to="/risk?q=orphaned"
            icon={<UserX className="h-4 w-4" aria-hidden="true" />}
            title="What has no owner?"
            metric={risk.loading ? "..." : orphanedRows.length}
            detail="orphaned scored credentials"
            ariaLabel={`Review ${orphanedRows.length} orphaned credential${orphanedRows.length === 1 ? "" : "s"}`}
            status={<StatusBadge vocabulary="honesty" value={orphanedRows.length > 0 ? "observe" : "operate"} />}
            error={risk.error}
          />
          <DisclosureTile />
        </div>
      </section>

      <LifecycleTrend trend={trend} loading={audit.loading} error={audit.error} />

      {topRisk.length > 0 && (
        <div className="mt-6">
          <h2 className="mb-2 text-lg font-semibold">Rotate first</h2>
          <ul className="space-y-1 text-sm">
            {topRisk.map((c) => (
              <li key={c.credential_id} className="flex justify-between border-b border-border py-1">
                <span>{c.subject}</span>
                <span className="font-medium">{Math.round(c.score)}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </section>
  );
}

function QuickAction({ children, icon, to }: { children: ReactNode; icon: ReactNode; to: string }) {
  return (
    <Link
      to={to}
      className="inline-flex min-h-9 items-center gap-2 rounded-md border border-border px-3 py-2 text-sm font-medium hover:bg-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
    >
      <span className="text-primary">{icon}</span>
      {children}
    </Link>
  );
}

function DisclosureTile() {
  return (
    <Card className="h-full border-dashed">
      <CardHeader>
        <CardTitle className="flex items-center justify-between gap-3 text-base">
          <span className="flex min-w-0 items-center gap-2">
            <span className="text-primary">
              <AlertTriangle className="h-4 w-4" aria-hidden="true" />
            </span>
            <span>Delivery status not served</span>
          </span>
          <StatusBadge vocabulary="honesty" value="disclose" />
        </CardTitle>
      </CardHeader>
      <CardContent>
        <p className="text-sm font-medium">No failed deliveries number is shown.</p>
        <p className="mt-1 text-sm text-muted-foreground">
          Outbox delivery status is blocked on FE-PTR-OUTBOX / BACKEND-OUTBOX-STATUS. FE-022 will add the per-credential activity timeline when that read model is served.
        </p>
      </CardContent>
    </Card>
  );
}

function LifecycleTrend({
  error,
  loading,
  trend,
}: {
  error?: string | null;
  loading: boolean;
  trend: LifecycleTrendCounts;
}) {
  const max = Math.max(1, trend.issued, trend.renewed, trend.revoked);
  const summary = loading
    ? "Loading lifecycle trend from served audit events..."
    : error
      ? "Lifecycle trend unavailable."
      : trend.total === 0
        ? "No lifecycle events in the served audit window."
        : `Issued ${trend.issued}, renewed ${trend.renewed}, revoked ${trend.revoked} from served audit events.`;

  return (
    <section aria-labelledby="lifecycle-trend-heading" aria-label="Lifecycle trend" className="mt-6">
      <div className="mb-2">
        <h2 id="lifecycle-trend-heading" className="text-lg font-semibold">
          Lifecycle trend
        </h2>
        <p className="mt-1 text-sm text-muted-foreground">{summary}</p>
      </div>
      <div
        role="img"
        aria-label={`Lifecycle trend chart: issued ${trend.issued}, renewed ${trend.renewed}, revoked ${trend.revoked}`}
        className="grid max-w-xl grid-cols-3 items-end gap-3 rounded-panel border border-border bg-card p-4 shadow-elevation1"
      >
        {[
          ["Issued", trend.issued, "bg-operate"],
          ["Renewed", trend.renewed, "bg-observe"],
          ["Revoked", trend.revoked, "bg-destructive"],
        ].map(([label, count, color]) => (
          <div key={label} className="grid gap-2 text-center text-xs text-muted-foreground">
            <div className="flex h-28 items-end rounded bg-muted">
              <div
                className={`w-full rounded ${color}`}
                style={{ height: `${Math.max(8, (Number(count) / max) * 100)}%` }}
              />
            </div>
            <span className="font-medium text-foreground">{count}</span>
            <span>{label}</span>
          </div>
        ))}
      </div>
    </section>
  );
}

function TriageTile({
  to,
  icon,
  title,
  metric,
  detail,
  ariaLabel,
  status,
  error,
}: {
  to: string;
  icon: ReactNode;
  title: string;
  metric: string | number;
  detail: string;
  ariaLabel: string;
  status: ReactNode;
  error?: string | null;
}) {
  return (
    <Link to={to} aria-label={ariaLabel} className="group block rounded-panel focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring">
      <Card className="h-full transition-colors group-hover:border-primary">
        <CardHeader>
          <CardTitle className="flex items-center justify-between gap-3 text-base">
            <span className="flex min-w-0 items-center gap-2">
              <span className="text-primary">{icon}</span>
              <span>{title}</span>
            </span>
            {status}
          </CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-3xl font-semibold">
            {metric}
          </p>
          <p className="mt-1 text-sm text-muted-foreground">{error ? "Worklist unavailable" : detail}</p>
        </CardContent>
      </Card>
    </Link>
  );
}

export function certificateExpiresWithin(cert: Certificate, days: number): boolean {
  if (!cert.not_after) return false;
  return new Date(cert.not_after).getTime() <= new Date(expiringBefore(days)).getTime();
}

export function highRiskCount(rows: CredentialRisk[]): number {
  return rows.filter((row) => row.score >= highRiskThreshold).length;
}

interface LifecycleTrendCounts {
  issued: number;
  renewed: number;
  revoked: number;
  total: number;
}

export function lifecycleTrend(events: AuditEvent[]): LifecycleTrendCounts {
  const trend = { issued: 0, renewed: 0, revoked: 0, total: 0 };
  for (const event of events) {
    if (/issued|created/i.test(event.type)) {
      trend.issued += 1;
    } else if (/renew/i.test(event.type)) {
      trend.renewed += 1;
    } else if (/revok/i.test(event.type)) {
      trend.revoked += 1;
    } else {
      continue;
    }
    trend.total += 1;
  }
  return trend;
}
