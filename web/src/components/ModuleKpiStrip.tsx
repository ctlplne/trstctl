import { Link } from "react-router-dom";
import { useTranslation } from "@/i18n/I18nProvider";
import { cn } from "@/lib/utils";

export interface ModuleKpi {
  /** Stable id for keys/tests. */
  id: string;
  label: string;
  /** Served value. Numbers are formatted through the locale policy; strings
   * (e.g. "—") render as-is. Never pass fabricated/demo data (S-N0 / S-B3). */
  value: number | string;
  /** Where clicking the KPI goes — a filtered list or a global plane. Every
   * KPI is a link (the DigiCert/Keyfactor dashboard-number-as-filter pattern). */
  to: string;
  tone?: "default" | "warn" | "crit" | "ok";
  sub?: string;
}

const toneClass: Record<NonNullable<ModuleKpi["tone"]>, string> = {
  default: "text-muted-foreground",
  warn: "text-status-warning",
  crit: "text-destructive",
  ok: "text-status-success",
};

/** ModuleKpiStrip renders a compact row of linked KPIs ABOVE a module's object
 * list (DESIGN rule 6: the list still renders first below this). It is a thin
 * telemetry strip, not a dashboard — 2–4 served numbers that each deep-link
 * into a filtered list. Cross-module planes stay on the global dashboard. */
export function ModuleKpiStrip({ ariaLabel, kpis }: { ariaLabel: string; kpis: ModuleKpi[] }) {
  const { formatNumber } = useTranslation();
  if (kpis.length === 0) return null;
  return (
    <section
      aria-label={ariaLabel}
      className="grid grid-cols-2 divide-x divide-y divide-border border-y border-border bg-card/35 sm:grid-cols-3 lg:grid-cols-4"
    >
      {kpis.map((kpi) => (
        <Link
          key={kpi.id}
          to={kpi.to}
          className="group block min-w-0 p-4 transition-colors hover:bg-muted/55 focus-visible:relative focus-visible:z-10 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-focus"
        >
          <span className="block text-caption font-medium text-muted-foreground">{kpi.label}</span>
          <span className="mt-1 block text-heading font-semibold tracking-tight tabular-nums">
            {typeof kpi.value === "number" ? formatNumber(kpi.value) : kpi.value}
          </span>
          {kpi.sub && <span className={cn("mt-0.5 block text-caption font-medium", toneClass[kpi.tone ?? "default"])}>{kpi.sub}</span>}
        </Link>
      ))}
    </section>
  );
}
