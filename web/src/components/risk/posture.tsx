import { DashboardGrid } from "@/components/dashboard";
import { StatTile } from "@/components/charts";
import { UnavailableState } from "@/components/StatePrimitives";
import { useTranslation } from "@/i18n/I18nProvider";
import type { UrgentRiskSummary } from "@/lib/api";

/** RiskPosture renders only the server's canonical union. It never recomputes
 * one projection locally, because a locally correct zero can still be a false
 * estate-wide all-clear when contextual discovery is critical (AUD-67). */
export function RiskPosture({ summary, loading, error }: { summary: UrgentRiskSummary | null; loading: boolean; error: string | null }) {
  const { t } = useTranslation();
  if (loading) {
    return <p className="mb-4 text-sm text-muted-foreground">{t("risk.urgent.loading")}</p>;
  }
  if (error || !summary || summary.status !== "complete") {
    return (
      <div className="mb-4">
        <UnavailableState title={t("risk.urgent.unavailableTitle")}>{error ?? t("risk.urgent.unavailableDetail")}</UnavailableState>
      </div>
    );
  }
  return (
    <section aria-label={t("risk.urgent.scopeLabel")} className="mb-4 space-y-2">
      <DashboardGrid>
        <StatTile label={t("risk.urgent.analyzed")} value={summary.unique_analyzed} />
        <StatTile label={t("risk.urgent.critical")} value={summary.critical} tone={summary.critical ? "critical" : undefined} />
        <StatTile label={t("risk.urgent.high")} value={summary.high} tone={summary.high ? "high" : undefined} />
        <StatTile
          label={t("risk.urgent.credentialProjection")}
          value={summary.credential_risk.critical + summary.credential_risk.high}
          hint={t("risk.urgent.sourceHint", {
            critical: summary.credential_risk.critical,
            high: summary.credential_risk.high,
          })}
        />
        <StatTile
          label={t("risk.urgent.contextualProjection")}
          value={summary.contextual_priorities.critical + summary.contextual_priorities.high}
          hint={t("risk.urgent.sourceHint", {
            critical: summary.contextual_priorities.critical,
            high: summary.contextual_priorities.high,
          })}
        />
      </DashboardGrid>
      <p className="text-caption text-muted-foreground">{summary.scope}</p>
    </section>
  );
}
