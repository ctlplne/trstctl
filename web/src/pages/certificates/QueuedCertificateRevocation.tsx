import { useEffect } from "react";
import { api, type Certificate } from "@/lib/api";
import { useApiQuery } from "@/lib/query";
import { useTranslation } from "@/i18n/I18nProvider";
import { Button } from "@/components/ui/button";

export function QueuedCertificateRevocation({ certificate, onConfirmed }: { certificate: Certificate; onConfirmed: (value: Certificate) => void }) {
  const { t } = useTranslation();
  const result = useApiQuery(["certificates", certificate.id, certificate.fingerprint, "revocation-result"], () => api.getCertificate(certificate.id), {
    live: { intervalMs: 2_000 },
    retry: false,
  });
  const matches = result.data?.id === certificate.id && result.data.fingerprint === certificate.fingerprint;
  useEffect(() => {
    if (!result.error && matches && result.data?.status === "revoked") onConfirmed(result.data);
  }, [matches, onConfirmed, result.data, result.error]);
  return (
    <div className="grid gap-2">
      <p role="status">{t("certificates.revocation.certificateQueued")}</p>
      <p>{t("certificates.revocation.certificateQueuedHelp")}</p>
      {result.error || (result.data && !matches) ? <p role="alert">{t("certificates.revocation.certificateReadUnavailable")}</p> : null}
      <Button type="button" variant="outline" loading={result.fetching} onClick={result.refetch}>
        {t("certificates.revocation.refreshResult")}
      </Button>
    </div>
  );
}
