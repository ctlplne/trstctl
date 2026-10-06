import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { StatusBadge } from "@/components/StatusBadge";
import { Button } from "@/components/ui/button";
import { useTranslation } from "@/i18n/I18nProvider";
import { api, type KeyCompromiseResult } from "@/lib/api";
import { isAccessDenied } from "@/lib/apiTransport";
import { liveRefetchInterval } from "@/lib/query";

/** One retained command has two separate receivers. Reading them together
 * keeps the console honest across reloads, retries, and a host-agent outage. */
export function KeyCompromiseEffects({ identityID, requestKey, initial }: { identityID: string; requestKey: string; initial: KeyCompromiseResult }) {
  const { t } = useTranslation();
  const result = useQuery({
    queryKey: ["key-compromise-effects", identityID, requestKey, initial.revocation.id, initial.containment.id],
    initialData: initial,
    staleTime: 0,
    retry: (count, error) => !isAccessDenied(error) && count < 1,
    meta: { live: true },
    queryFn: async () => {
      const read = await api.readKeyCompromise(identityID, requestKey);
      if (
        read.identity.id !== identityID ||
        read.revocation.id !== initial.revocation.id ||
        read.revocation.destination !== "revocation.publish" ||
        read.containment.id !== initial.containment.id ||
        read.containment.outbox_id !== initial.containment.outbox_id ||
        read.containment.identity_id !== identityID ||
        read.containment.fingerprint !== initial.containment.fingerprint
      ) {
        throw new Error(t("certificates.revocation.compromiseReadMismatch"));
      }
      return read;
    },
    refetchInterval: (query) => {
      if (query.state.error || !query.state.data) return false;
      const ca = query.state.data.revocation.status;
      const host = query.state.data.containment.status;
      return ["pending", "processing"].includes(ca) || host === "containment_queued" ? liveRefetchInterval(3000) : false;
    },
  });
  const read = result.isError ? null : result.data;
  return (
    <div className="grid gap-3">
      {read ? (
        <>
          <section aria-label={t("certificates.revocation.compromiseCAJob")} className="rounded-control border border-border p-3">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <h3 className="font-semibold">{t("certificates.revocation.compromiseCAJob")}</h3>
              <StatusBadge value={read.revocation.status} vocabulary="delivery" />
            </div>
            <p className="mt-2 text-muted-foreground">
              {read.revocation.status === "delivered"
                ? t("certificates.revocation.compromiseCADelivered")
                : read.revocation.status === "failed"
                  ? t("certificates.revocation.compromiseCAFailed")
                  : t("certificates.revocation.compromiseCAPending")}
            </p>
            <p className="mt-1 text-xs">{t("certificates.revocation.compromiseAttempts", { count: read.revocation.attempts })}</p>
            {read.revocation.last_error ? (
              <p role="alert" className="mt-2 break-words text-sm text-status-warning">
                {read.revocation.last_error}
              </p>
            ) : null}
          </section>
          <section aria-label={t("certificates.revocation.compromiseHostJob")} className="rounded-control border border-border p-3">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <h3 className="font-semibold">{t("certificates.revocation.compromiseHostJob")}</h3>
              <StatusBadge value={read.containment.status} vocabulary="delivery" />
            </div>
            <p className="mt-2 text-muted-foreground">
              {read.containment.status === "containment_stopped"
                ? t("connectors.containment.stockVerify")
                : read.containment.status === "containment_queued"
                  ? t("connectors.containment.queuedHelp")
                  : t("connectors.containment.noProof")}
            </p>
            <p className="mt-1 break-all text-xs">
              {t("connectors.containment.receipt")}: {read.containment.id}
            </p>
            {read.containment.detail && read.containment.status !== "containment_queued" ? (
              <details className="mt-2">
                <summary>{t("connectors.containment.signedEvidence")}</summary>
                <pre className="max-h-64 overflow-auto whitespace-pre-wrap break-all text-xs">{read.containment.detail}</pre>
              </details>
            ) : null}
          </section>
        </>
      ) : (
        <p role="alert" className="text-status-warning">
          {t("certificates.revocation.compromiseReadFailed")}
        </p>
      )}
      <div className="flex flex-wrap gap-3">
        <Button type="button" variant="outline" size="sm" loading={result.isFetching} onClick={() => void result.refetch({ cancelRefetch: false })}>
          {t("certificates.revocation.compromiseRefresh")}
        </Button>
        <Link className="self-center text-primary underline" to="/operations">
          {t("certificates.revocation.compromiseJobsLink")}
        </Link>
      </div>
    </div>
  );
}
