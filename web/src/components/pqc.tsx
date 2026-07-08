import type { CBOMMigrationProgress } from "@/lib/api";
import { useTranslation } from "@/i18n/I18nProvider";

export function PQCReadinessSummary({ progress }: { progress: CBOMMigrationProgress }) {
  const { t } = useTranslation();
  const percent = Math.max(0, Math.min(100, progress.percent_migrated));

  return (
    <div className="grid gap-3 rounded-panel border border-border p-comfortable md:grid-cols-[minmax(160px,0.8fr)_1fr]">
      <div className="grid content-center gap-2">
        <div className="h-3 overflow-hidden rounded-full bg-muted" role="img" aria-label={t("pqc.readiness.aria")}>
          <div className="h-full rounded-full bg-success" style={{ width: `${percent}%` }} />
        </div>
        <p className="text-display-sm font-semibold">{percent}%</p>
        <p className="text-sm text-muted-foreground">{t("pqc.readiness.migrated", { percent })}</p>
      </div>
      <dl className="grid gap-3 sm:grid-cols-3">
        <div>
          <dt className="text-xs font-medium uppercase tracking-wide text-muted-foreground">{t("pqc.readiness.totalAssets")}</dt>
          <dd className="text-title font-semibold">{progress.total_assets}</dd>
        </div>
        <div>
          <dt className="text-xs font-medium uppercase tracking-wide text-muted-foreground">{t("pqc.readiness.quantumVulnerable")}</dt>
          <dd className="text-title font-semibold">{progress.quantum_vulnerable_assets}</dd>
        </div>
        <div>
          <dt className="text-xs font-medium uppercase tracking-wide text-muted-foreground">{t("pqc.readiness.readyAssets")}</dt>
          <dd className="text-title font-semibold">{progress.post_quantum_ready_assets}</dd>
        </div>
      </dl>
    </div>
  );
}
