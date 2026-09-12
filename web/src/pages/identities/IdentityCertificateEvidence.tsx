import { Link } from "react-router-dom";
import { CredentialChip } from "@/components/CredentialChip";
import { StatusBadge } from "@/components/StatusBadge";
import { ErrorState, UnavailableState } from "@/components/StatePrimitives";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { useTranslation } from "@/i18n/I18nProvider";
import { formatDateTime } from "@/i18n/format";
import { api } from "@/lib/api";
import { useApiQuery } from "@/lib/query";

export function IdentityCertificateEvidence({ identityId }: { identityId: string }) {
  const { t } = useTranslation();
  const result = useApiQuery(
    ["identity-deployment-evidence", identityId],
    async () => {
      const evidence = await api.identityDeploymentEvidence(identityId);
      if (
        evidence.identity_id !== identityId ||
        (evidence.receipt && evidence.receipt.identity_id !== identityId) ||
        (evidence.certificate && (!evidence.receipt || evidence.certificate.fingerprint !== evidence.receipt.fingerprint))
      ) {
        throw new Error(t("identities.certificate.mismatch"));
      }
      return evidence;
    },
    { retry: false, live: { intervalMs: 10_000 } },
  );
  const { receipt, certificate } = result.data ?? {};
  return (
    <section className="mt-4 border-t border-border pt-4" aria-labelledby="identity-certificate-heading">
      <h3 id="identity-certificate-heading" className="font-semibold">
        {t("identities.certificate.title")}
      </h3>
      <p className="mt-1 text-xs text-muted-foreground">{t("identities.certificate.scope")}</p>
      {result.error ? (
        <div className="mt-3 grid gap-2">
          <ErrorState title={t("identities.certificate.failed")}>{result.error}</ErrorState>
          <Button onClick={result.refetch}>{t("identities.certificate.retry")}</Button>
        </div>
      ) : !result.data ? (
        <div className="mt-3 grid grid-cols-2 gap-3" aria-busy="true">
          <Skeleton className="h-12" />
          <Skeleton className="h-12" />
        </div>
      ) : !receipt ? (
        <p className="mt-3 text-muted-foreground">{t("identities.certificate.empty")}</p>
      ) : (
        <div className="mt-3 grid gap-3">
          <p>
            {t("identities.certificate.receipt", { at: formatDateTime(receipt.updated_at), connector: receipt.connector, target: receipt.target })}{" "}
            <StatusBadge vocabulary="delivery" value={receipt.status} />
          </p>
          {!certificate ? (
            <UnavailableState title={t("identities.certificate.missing")} />
          ) : (
            <>
              <dl className="grid gap-3 sm:grid-cols-2">
                <div>
                  <dt className="font-medium text-muted-foreground">{t("identities.certificate.expires")}</dt>
                  <dd>{formatDateTime(certificate.not_after)}</dd>
                </div>
                <div>
                  <dt className="font-medium text-muted-foreground">{t("identities.certificate.validFrom")}</dt>
                  <dd>{formatDateTime(certificate.not_before)}</dd>
                </div>
                <div>
                  <dt className="font-medium text-muted-foreground">{t("source.status.920e413c7d")}</dt>
                  <dd>
                    <StatusBadge vocabulary="certificate" value={certificate.status} />
                  </dd>
                </div>
                <div>
                  <dt className="font-medium text-muted-foreground">{t("source.serial.8ea0949377")}</dt>
                  <dd>
                    <CredentialChip value={certificate.serial || "-"} label={t("source.serial.8ea0949377")} />
                  </dd>
                </div>
              </dl>
              <Link className="text-primary underline" to={`/certificates?tab=crlct&certificate_id=${encodeURIComponent(certificate.id)}`}>
                {t("identities.certificate.review")}
              </Link>
            </>
          )}
          <details className="text-xs text-muted-foreground">
            <summary className="cursor-pointer">{t("source.fingerprint.ba7af0b704")}</summary>
            <CredentialChip value={receipt.fingerprint || "-"} label={t("source.fingerprint.ba7af0b704")} fullValue />
          </details>
        </div>
      )}
    </section>
  );
}
