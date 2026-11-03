import { StatusBadge } from "@/components/StatusBadge";
import { ErrorState } from "@/components/StatePrimitives";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { useTranslation } from "@/i18n/I18nProvider";
import { api, type IdentityRevocationReport as Report } from "@/lib/api";
import { useApiQuery } from "@/lib/query";

const nowCopy = {
  replaced: "identities.revocation.now.replaced",
  removed: "identities.revocation.now.removed",
  still_deployed: "identities.revocation.now.still_deployed",
  failed: "identities.revocation.now.failed",
} as const;

type Facet = Report["certificates"][number]["ca_status"];

/** The revocation report (A245): where a revocation has taken hold, kept
 * apart — the CA, the destinations that held the certificate, new connections
 * and the sessions already open. */
export function IdentityRevocationReport({ identityId }: { identityId: string }) {
  const { t, formatDateTime } = useTranslation();
  const result = useApiQuery(["identity-revocation-report", identityId], () => api.identityRevocationReport(identityId), {
    retry: false,
    live: { intervalMs: 15_000 },
  });
  const facet = (label: string, value: Facet) => (
    <div>
      <dt className="font-medium text-muted-foreground">{label}</dt>
      <dd>
        <StatusBadge vocabulary="revocation" value={value.state} /> <span className="text-muted-foreground">{value.detail}</span>
      </dd>
    </div>
  );
  return (
    <section className="mt-4 border-t border-border pt-4" aria-labelledby="identity-revocation-heading">
      <h3 id="identity-revocation-heading" className="font-semibold">
        {t("identities.revocation.title")}
      </h3>
      <p className="mt-1 text-xs text-muted-foreground">{t("identities.revocation.help")}</p>
      {result.error ? (
        <div className="mt-3 grid gap-2">
          <ErrorState title={t("identities.revocation.failed")}>{result.error}</ErrorState>
          <Button onClick={result.refetch}>{t("identities.revocation.retry")}</Button>
        </div>
      ) : !result.data ? (
        <div className="mt-3 grid grid-cols-2 gap-3" aria-busy="true">
          <Skeleton className="h-12" />
          <Skeleton className="h-12" />
        </div>
      ) : (result.data.certificates ?? []).length === 0 ? (
        <p className="mt-3 text-muted-foreground">{t("identities.revocation.empty")}</p>
      ) : (
        (result.data.certificates ?? []).map((cert) => (
          <div key={cert.certificate_id} className="mt-3 grid gap-2">
            <p className="font-medium">{t("identities.revocation.certificate", { serial: cert.serial, at: formatDateTime(cert.revoked_at) })}</p>
            <dl className="grid gap-3 sm:grid-cols-2">
              {facet(t("identities.revocation.facet.ca"), cert.ca_status)}
              {facet(t("identities.revocation.facet.deployed"), cert.deployed_material)}
              {facet(t("identities.revocation.facet.newConnections"), cert.new_connections)}
              {facet(t("identities.revocation.facet.sessions"), cert.existing_sessions)}
            </dl>
            {(cert.destinations ?? []).length > 0 && (
              <ul className="grid gap-1 text-xs text-muted-foreground">
                {(cert.destinations ?? []).map((d) => (
                  <li key={d.target}>{t("identities.revocation.destination", { target: d.target, now: t(nowCopy[d.now]) })}</li>
                ))}
              </ul>
            )}
            {(cert.endpoints ?? []).length > 0 && (
              <ul className="grid gap-1 text-xs text-muted-foreground">
                {(cert.endpoints ?? []).map((e) => (
                  <li key={`${e.endpoint_id}-${e.vantage}`}>
                    {t("identities.revocation.endpoint", { endpoint: e.endpoint_id, vantage: e.vantage, detail: e.detail })}
                  </li>
                ))}
              </ul>
            )}
          </div>
        ))
      )}
    </section>
  );
}
