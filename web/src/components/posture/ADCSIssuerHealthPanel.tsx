import { StatusBadge } from "@/components/StatusBadge";
import { ErrorState } from "@/components/StatePrimitives";
import { useTranslation } from "@/i18n/I18nProvider";
import { api, type ADCSIssuerHealth } from "@/lib/api";
import { apiProblemMessage } from "@/lib/apiProblem";
import { useApiQuery } from "@/lib/query";

function healthTone(status: ADCSIssuerHealth["status"]): "success" | "warning" | "critical" | "neutral" {
  if (status === "healthy") return "success";
  if (status === "degraded") return "warning";
  if (status === "failing") return "critical";
  return "neutral";
}

/** A161: whether issuance through each AD CS issuer is working, from the issuances and classified refusals trstctl recorded. */
export function ADCSIssuerHealthPanel() {
  const { t, formatDateTime } = useTranslation();
  const query = useApiQuery(["adcs", "issuers", "health"], () => api.adcsIssuerHealth(), { retry: false, live: { intervalMs: 30_000 } });
  const items = query.data?.items ?? [];
  const statusLabel = (status: ADCSIssuerHealth["status"]) => {
    switch (status) {
      case "healthy":
        return t("adcs.issuerHealth.healthy");
      case "degraded":
        return t("adcs.issuerHealth.degraded");
      case "failing":
        return t("adcs.issuerHealth.failing");
      default:
        return t("adcs.issuerHealth.idle");
    }
  };
  return (
    <section aria-labelledby="adcs-issuer-health-heading" className="grid gap-3 border-b border-border py-4 text-sm">
      <div>
        <h2 id="adcs-issuer-health-heading" className="text-title font-semibold">
          {t("adcs.issuerHealth.heading")}
        </h2>
        <p className="mt-1 max-w-3xl text-muted-foreground">{t("adcs.issuerHealth.description", { days: query.data?.window_days ?? 7 })}</p>
      </div>
      {query.errorValue ? (
        <ErrorState title={t("adcs.issuerHealth.error")}>{apiProblemMessage(query.errorValue, t("adcs.issuerHealth.error"))}</ErrorState>
      ) : null}
      {query.data && items.length === 0 ? <p className="text-muted-foreground">{t("adcs.issuerHealth.none")}</p> : null}
      {items.length > 0 ? (
        <ul className="grid gap-3">
          {items.map((item) => (
            <li key={item.id} className="rounded-panel border border-border bg-card p-3">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="font-medium">{item.name}</span>
                <StatusBadge value={item.status} label={statusLabel(item.status)} tone={healthTone(item.status)} />
              </div>
              <p className="mt-1 text-muted-foreground">
                {item.last_success_at
                  ? t("adcs.issuerHealth.issuedWithLast", { count: item.issued_in_window, time: formatDateTime(item.last_success_at) })
                  : t("adcs.issuerHealth.issued", { count: item.issued_in_window })}
              </p>
              {item.last_failure_at ? (
                <div className="mt-2 grid gap-1">
                  <p>{t("adcs.issuerHealth.lastFailure", { time: formatDateTime(item.last_failure_at), cause: item.last_failure_cause ?? "" })}</p>
                  {item.last_failure_summary ? <p className="text-muted-foreground">{item.last_failure_summary}</p> : null}
                  {item.last_failure_remediation ? <p>{t("adcs.issuerHealth.remediation", { remediation: item.last_failure_remediation })}</p> : null}
                </div>
              ) : null}
            </li>
          ))}
        </ul>
      ) : null}
      {query.data?.guidance ? <p className="text-caption text-muted-foreground">{query.data.guidance}</p> : null}
    </section>
  );
}
