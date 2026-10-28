import type { RevocationEndpointHealth } from "@/lib/api-types.gen";
import { formatDateTime } from "@/i18n/format";
import { useTranslation } from "@/i18n/I18nProvider";

// A211: the relay-verified CRL and OCSP answers that name this certificate —
// checks of its own serial when it is known only from a scan, and endpoint
// checks it represents. Evidence beside the inventory row, read as signed.
export function CertificateRevocationObservations({ observations }: { observations?: RevocationEndpointHealth[] }) {
  const { t } = useTranslation();
  if (!observations || observations.length === 0) return null;
  const answer = (observation: RevocationEndpointHealth): string => {
    if (observation.protocol === "crl" && observation.certificate_listed !== undefined) {
      return t(observation.certificate_listed ? "certificateCockpit.detail.revocationListed" : "certificateCockpit.detail.revocationNotListed");
    }
    if (observation.protocol === "ocsp" && observation.response_status === "good") return t("certificateCockpit.detail.revocationOCSPGood");
    if (observation.protocol === "ocsp" && observation.response_status === "revoked") return t("certificateCockpit.detail.revocationOCSPRevoked");
    return t("certificateCockpit.detail.revocationNoAnswer", { status: observation.status });
  };
  return (
    <div className="md:col-span-2">
      <dt className="font-medium text-muted-foreground">{t("certificateCockpit.detail.revocationObservations")}</dt>
      {observations.map((observation) => (
        <dd key={observation.target_key} className="break-all text-sm">
          {t("certificateCockpit.detail.revocationObservation", {
            protocol: observation.protocol.toUpperCase(),
            endpoint: observation.endpoint,
            answer: answer(observation),
            scope: t(
              observation.scope === "certificate" ? "certificateCockpit.detail.revocationOwnSerial" : "certificateCockpit.detail.revocationEndpointCheck",
            ),
            signature: t(
              observation.signature_verified
                ? "certificateCockpit.detail.revocationSignatureVerified"
                : "certificateCockpit.detail.revocationSignatureUnverified",
            ),
            agent: observation.observed_by_agent_name || observation.observed_by_agent_id,
            seen: formatDateTime(observation.observed_at),
          })}
        </dd>
      ))}
      <dd className="mt-1 text-xs text-muted-foreground">{t("certificateCockpit.detail.revocationObservationsNote")}</dd>
    </div>
  );
}
