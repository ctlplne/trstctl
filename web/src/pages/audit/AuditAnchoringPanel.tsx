import { StatusBadge } from "@/components/StatusBadge";
import { ErrorState } from "@/components/StatePrimitives";
import { useTranslation } from "@/i18n/I18nProvider";
import { api, type AuditAnchoringStatus } from "@/lib/api";
import { apiProblemMessage } from "@/lib/apiProblem";
import { useApiQuery } from "@/lib/query";

type AnchoringState = AuditAnchoringStatus["state"];

function stateTone(state: AnchoringState): "success" | "warning" | "critical" | "neutral" {
  if (state === "anchoring") return "success";
  if (state === "failing") return "critical";
  if (state === "off") return "warning";
  return "neutral";
}

/** A147: the scheduled timestamps over the tenant's full audit chain. */
export function AuditAnchoringPanel() {
  const { t, formatDateTime, formatNumber } = useTranslation();
  const query = useApiQuery(["audit", "anchors"], () => api.auditAnchors(), { retry: false });
  const status = query.data;
  const stateLabel = (state: AnchoringState) => {
    switch (state) {
      case "anchoring":
        return t("audit.anchoring.state.anchoring");
      case "failing":
        return t("audit.anchoring.state.failing");
      case "off":
        return t("audit.anchoring.state.off");
      default:
        return t("audit.anchoring.state.unlicensed");
    }
  };
  return (
    <section aria-labelledby="audit-anchoring-heading" className="ui-panel p-comfortable text-sm">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h2 id="audit-anchoring-heading" className="text-title font-semibold">
          {t("audit.anchoring.heading")}
        </h2>
        {status && <StatusBadge value={status.state} label={stateLabel(status.state)} tone={stateTone(status.state)} />}
      </div>
      <p className="mt-1 max-w-3xl text-muted-foreground">{t("audit.anchoring.description")}</p>
      {query.errorValue ? <ErrorState title={t("audit.anchoring.error")}>{apiProblemMessage(query.errorValue, t("audit.anchoring.error"))}</ErrorState> : null}
      {status && (
        <div className="mt-3 grid gap-3">
          {status.detail && <p role="note">{status.detail}</p>}
          <p className="flex flex-wrap gap-x-4 gap-y-1 text-muted-foreground">
            {status.cadence_seconds > 0 && (
              <span>
                {t("audit.anchoring.cadence", { cadence: t("audit.anchoring.minutes", { count: formatNumber(Math.round(status.cadence_seconds / 60)) }) })}
              </span>
            )}
            <span>{t("audit.anchoring.count", { count: formatNumber(status.anchor_count) })}</span>
            {status.last_anchored_at && <span>{t("audit.anchoring.last", { time: formatDateTime(status.last_anchored_at) })}</span>}
          </p>
          {status.anchors.length === 0 ? (
            <p className="text-muted-foreground">{t("audit.anchoring.none")}</p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr>
                    <th scope="col" className="py-1 pr-3 font-semibold">
                      {t("audit.anchoring.through")}
                    </th>
                    <th scope="col" className="py-1 pr-3 font-semibold">
                      {t("audit.anchoring.anchoredAt")}
                    </th>
                    <th scope="col" className="py-1 font-semibold">
                      {t("audit.anchoring.head")}
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {status.anchors.slice(0, 10).map((anchor) => (
                    <tr key={`${anchor.through_sequence}-${anchor.token_sha256}`}>
                      <td className="py-1 pr-3 font-mono">{formatNumber(anchor.through_sequence)}</td>
                      <td className="py-1 pr-3">{formatDateTime(anchor.anchored_at)}</td>
                      <td className="break-all py-1 font-mono">{anchor.chain_head}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          <details>
            <summary className="cursor-pointer font-medium">{t("audit.anchoring.verify")}</summary>
            <p className="mt-1 text-muted-foreground">{status.verification}</p>
          </details>
        </div>
      )}
    </section>
  );
}
