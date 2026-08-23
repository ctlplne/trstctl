import { ErrorState, LoadingState, UnavailableState } from "@/components/StatePrimitives";
import { StatusBadge } from "@/components/StatusBadge";
import { formatDateTime } from "@/i18n/format";
import { useTranslation } from "@/i18n/I18nProvider";
import { api, type RevocationCachePosture } from "@/lib/api";
import { useApiQuery } from "@/lib/query";

function summary(posture: RevocationCachePosture) {
  return {
    fresh: posture.summary.fresh,
    stale: posture.summary.stale,
    empty: posture.summary.empty,
    error: posture.summary.error,
  };
}

export function RevocationCachePanel() {
  const { t } = useTranslation();
  const query = useApiQuery(["revocation", "caches"], api.revocationCaches, { live: { intervalMs: 30_000 } });
  const posture = query.data;

  return (
    <section aria-labelledby="revocation-cache-heading" className="grid gap-3 border-y border-border py-4">
      <div>
        <h2 id="revocation-cache-heading" className="text-title font-semibold">
          {t("protocols.revocationCache.heading")}
        </h2>
        <p className="mt-1 max-w-4xl text-caption text-muted-foreground">{t("protocols.revocationCache.description")}</p>
      </div>

      {query.loading ? <LoadingState>{t("protocols.revocationCache.loading")}</LoadingState> : null}
      {query.error ? <ErrorState title={t("protocols.revocationCache.loadFailed")}>{query.error}</ErrorState> : null}
      {!query.loading && !query.error && (!posture?.observed || posture.items.length === 0) ? (
        <UnavailableState title={t("protocols.revocationCache.emptyTitle")}>{t("protocols.revocationCache.emptyBody")}</UnavailableState>
      ) : null}

      {posture?.observed && posture.items.length > 0 ? (
        <>
          <p className="text-sm text-muted-foreground">{t("protocols.revocationCache.summary", summary(posture))}</p>
          <div className="ui-panel overflow-x-auto">
            <table className="ui-table min-w-[82rem]">
              <caption className="sr-only">{t("protocols.revocationCache.caption")}</caption>
              <thead>
                <tr>
                  <th scope="col">{t("protocols.revocationCache.segment")}</th>
                  <th scope="col">{t("protocols.revocationCache.relay")}</th>
                  <th scope="col">{t("protocols.revocationCache.cache")}</th>
                  <th scope="col">{t("protocols.revocationCache.endpoint")}</th>
                  <th scope="col">{t("protocols.revocationCache.freshness")}</th>
                  <th scope="col">{t("protocols.revocationCache.evidence")}</th>
                  <th scope="col">{t("protocols.revocationCache.traffic")}</th>
                </tr>
              </thead>
              <tbody>
                {posture.items.map((row) => (
                  <tr key={`${row.agent_id}:${row.protocol}:${row.cache_id}`} className="align-top">
                    <td className="font-medium">{row.segment}</td>
                    <td>
                      <p className="font-medium">{row.agent_name}</p>
                      <p className="mt-1 font-mono text-xs text-muted-foreground">{row.agent_id}</p>
                    </td>
                    <td>
                      <p className="font-medium">{row.cache_id}</p>
                      <p className="mt-1 max-w-[18rem] break-all font-mono text-xs text-muted-foreground">{row.issuer_fingerprint}</p>
                    </td>
                    <td>
                      <p className="font-mono text-xs">{row.protocol}</p>
                      <p className="mt-1 font-mono text-xs text-muted-foreground">{row.local_path}</p>
                    </td>
                    <td>
                      <StatusBadge value={row.status} />
                      {row.detail_code ? <p className="mt-1 font-mono text-xs text-muted-foreground">{row.detail_code}</p> : null}
                      <p className="mt-1 text-caption text-muted-foreground">
                        {row.next_update
                          ? t("protocols.revocationCache.nextUpdate", { at: formatDateTime(row.next_update) })
                          : t("protocols.revocationCache.noNextUpdate")}
                      </p>
                    </td>
                    <td className="text-xs">
                      <p>{row.signature_verified ? t("protocols.revocationCache.signatureVerified") : t("protocols.revocationCache.signatureUnverified")}</p>
                      <p className="mt-1 text-muted-foreground">
                        {row.last_validated_at
                          ? t("protocols.revocationCache.validated", { at: formatDateTime(row.last_validated_at) })
                          : t("protocols.revocationCache.neverValidated")}
                      </p>
                      <p className="text-muted-foreground">{t("protocols.revocationCache.reported", { at: formatDateTime(row.reported_at) })}</p>
                    </td>
                    <td className="text-xs">
                      <p>{t("protocols.revocationCache.cached", { count: row.cached_responses })}</p>
                      <p className="mt-1 text-muted-foreground">
                        {t("protocols.revocationCache.requests", { delivered: row.served_requests, blocked: row.refused_requests })}
                      </p>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      ) : null}
    </section>
  );
}
