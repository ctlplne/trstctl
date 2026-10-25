import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { StatusBadge } from "@/components/StatusBadge";
import { Button } from "@/components/ui/button";
import { useTranslation } from "@/i18n/I18nProvider";
import { api, type KeyCompromiseResult } from "@/lib/api";
import { apiProblemContext } from "@/lib/apiProblem";
import { isAccessDenied } from "@/lib/apiTransport";
import { liveRefetchInterval } from "@/lib/query";

const retryableHostStatuses = new Set(["containment_failed", "containment_unverified"]);

/** One retained command has two separate receivers. Reading them together
 * keeps the console honest across reloads, retries, and a host-agent outage. */
export function KeyCompromiseEffects({ identityID, requestKey, initial }: { identityID: string; requestKey: string; initial: KeyCompromiseResult }) {
  const { t } = useTranslation();
  const [retry, setRetry] = useState<{ effect: "host" | "ca" | null; busy: boolean; notice: string | null; error: string | null }>({
    effect: null,
    busy: false,
    notice: null,
    error: null,
  });
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
        read.revocation.destination !== "revocation.publish" ||
        read.containment.id !== initial.containment.id ||
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
  const retryEffect = async (effect: "host" | "ca", bindingID: string | number) => {
    setRetry({ effect, busy: true, notice: null, error: null });
    try {
      // One key per exact failed attempt: a double click replays the same retry.
      await api.retryKeyCompromise(identityID, { request_key: requestKey, effect }, `identity-compromise-retry:${effect}:${requestKey}:${bindingID}`);
      setRetry({ effect: null, busy: false, notice: t("certificates.revocation.compromiseRetryQueued"), error: null });
      await result.refetch({ cancelRefetch: false });
    } catch (cause) {
      setRetry({ effect: null, busy: false, notice: null, error: apiProblemContext(cause, t("certificates.revocation.compromiseRetryFailed")) });
    }
  };
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
                  : read.revocation.status === "evidence_unavailable"
                    ? t("certificates.revocation.compromiseCAEvidenceUnavailable")
                    : t("certificates.revocation.compromiseCAPending")}
            </p>
            {read.revocation.status !== "evidence_unavailable" ? (
              <p className="mt-1 text-xs">{t("certificates.revocation.compromiseAttempts", { count: read.revocation.attempts })}</p>
            ) : null}
            {read.revocation.last_error ? (
              <p role="alert" className="mt-2 wrap-break-word text-sm text-status-warning">
                {read.revocation.last_error}
              </p>
            ) : null}
            {read.revocation.status === "failed" ? (
              <Button
                type="button"
                variant="outline"
                size="sm"
                className="mt-2"
                loading={retry.busy && retry.effect === "ca"}
                disabled={retry.busy}
                onClick={() => void retryEffect("ca", `${read.revocation.id}:${read.revocation.attempts}`)}
              >
                {t("certificates.revocation.compromiseRetryCA")}
              </Button>
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
            {retryableHostStatuses.has(read.containment.status) ? (
              <Button
                type="button"
                variant="outline"
                size="sm"
                className="mt-2"
                loading={retry.busy && retry.effect === "host"}
                disabled={retry.busy}
                onClick={() => void retryEffect("host", `${read.containment.outbox_id ?? "none"}:${read.containment.attempts}`)}
              >
                {t("certificates.revocation.compromiseRetryHost")}
              </Button>
            ) : null}
          </section>
          {retry.notice ? <p role="status">{retry.notice}</p> : null}
          {retry.error ? (
            <p role="alert" className="text-status-warning">
              {retry.error}
            </p>
          ) : null}
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
