import { SectionCard, DashboardGrid, AttentionList, AttentionRow } from "@/components/dashboard";
import { StatTile } from "@/components/charts";
import { StatusBadge } from "@/components/StatusBadge";
import type { CredentialRisk, Certificate } from "@/lib/api";

export type AlertSeverity = "critical" | "high" | "warning";

export interface AlertItem {
  id: string;
  severity: AlertSeverity;
  title: string;
  detail: string;
}

const severityRank: Record<AlertSeverity, number> = { critical: 0, high: 1, warning: 2 };

function daysUntil(value?: string): number {
  if (!value) return Number.POSITIVE_INFINITY;
  return Math.ceil((new Date(value).getTime() - Date.now()) / 86_400_000);
}

/** deriveAlerts turns served read models (credential risk + certificate expiry)
 * into a single severity-ranked alert stream. There is no dedicated alerts
 * endpoint, so the center is a projection of events the backend already serves;
 * channel configuration and scheduled digests are intentionally NOT here because
 * the backend does not serve them yet. */
export function deriveAlerts(risks: CredentialRisk[], certs: Certificate[]): AlertItem[] {
  const alerts: AlertItem[] = [];
  for (const risk of risks) {
    if (risk.score >= 90) alerts.push({ id: `risk-${risk.credential_id}`, severity: "critical", title: `Critical risk: ${risk.subject}`, detail: `composite score ${Math.round(risk.score)}` });
    else if (risk.score >= 70) alerts.push({ id: `risk-${risk.credential_id}`, severity: "high", title: `High risk: ${risk.subject}`, detail: `composite score ${Math.round(risk.score)}` });
  }
  for (const cert of certs) {
    const days = daysUntil(cert.not_after);
    if (days <= 7) alerts.push({ id: `cert-${cert.id}`, severity: "critical", title: `Expiring now: ${cert.subject}`, detail: `${days} day(s) to expiry` });
    else if (days <= 30) alerts.push({ id: `cert-${cert.id}`, severity: "warning", title: `Expiring soon: ${cert.subject}`, detail: `${days} day(s) to expiry` });
  }
  return alerts.sort((a, b) => severityRank[a.severity] - severityRank[b.severity]);
}

export function NotificationCenter({ risks = [], certs = [] }: { risks?: CredentialRisk[]; certs?: Certificate[] }) {
  const alerts = deriveAlerts(risks, certs);
  const counts = {
    critical: alerts.filter((a) => a.severity === "critical").length,
    high: alerts.filter((a) => a.severity === "high").length,
    warning: alerts.filter((a) => a.severity === "warning").length,
  };
  return (
    <SectionCard title="Alert center" description="Severity-ranked alerts projected from served risk and certificate-expiry events.">
      <DashboardGrid>
        <StatTile label="Critical" value={counts.critical} tone={counts.critical ? "critical" : undefined} />
        <StatTile label="High" value={counts.high} tone={counts.high ? "high" : undefined} />
        <StatTile label="Warning" value={counts.warning} tone={counts.warning ? "warning" : undefined} />
      </DashboardGrid>
      {alerts.length === 0 ? (
        <p className="mt-3 text-caption text-muted-foreground">No active alerts.</p>
      ) : (
        <AttentionList ariaLabel="Active alerts">
          {alerts.map((alert) => (
            <AttentionRow key={alert.id}>
              <StatusBadge vocabulary="risk" value={alert.severity === "warning" ? "medium" : alert.severity} />
              <span className="flex-1 truncate text-caption">{alert.title}</span>
              <span className="w-32 truncate text-caption text-muted-foreground">{alert.detail}</span>
            </AttentionRow>
          ))}
        </AttentionList>
      )}
    </SectionCard>
  );
}
