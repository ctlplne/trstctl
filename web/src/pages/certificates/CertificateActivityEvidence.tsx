import { useState } from "react";
import { Link } from "react-router-dom";
import type { Certificate } from "@/lib/api";
import { certificateDisplayName } from "@/lib/certificatePresentation";
import { useTranslation } from "@/i18n/I18nProvider";
import { Field } from "@/components/ui/field";
import { Select } from "@/components/ui/select";
import { CredentialActivityTimeline } from "@/components/CredentialActivityTimeline";
import { IdentityActivityEvidence } from "@/pages/identities/IdentityActivityEvidence";

// Certificate identity links come from the served read model. Never infer one
// from a repeated common name, or borrow a newer certificate's delivery proof.
export function CertificateActivityEvidence({ certificate }: { certificate: Certificate }) {
  const { t } = useTranslation();
  const [requestedIdentity, setRequestedIdentity] = useState("");
  const identities = [...new Set(certificate.identity_ids ?? [])];
  const identityId = identities.includes(requestedIdentity) ? requestedIdentity : identities[0];
  const fingerprint = certificate.fingerprint;
  const label = certificateDisplayName(certificate);
  if (!identityId || !fingerprint) {
    const notice = t(!fingerprint ? "certificates.evidence.missingFingerprint" : "certificates.evidence.missingIdentity");
    return <CredentialActivityTimeline credentialLabel={label} deliveryNotice={notice} rotationNotice={notice} rollbackNotice={notice} />;
  }
  return (
    <div>
      <p className="mt-3 text-caption text-muted-foreground">{t("certificates.evidence.historical")}</p>
      {identities.length > 1 && (
        <Field label={t("certificates.evidence.identity")} description={t("certificates.evidence.identityHelp")}>
          {(control) => (
            <Select {...control} value={identityId} onChange={(event) => setRequestedIdentity(event.target.value)}>
              {identities.map((id) => (
                <option key={id} value={id}>
                  {id}
                </option>
              ))}
            </Select>
          )}
        </Field>
      )}
      <IdentityActivityEvidence key={`${identityId}:${fingerprint}`} identity={{ id: identityId, name: label }} certificateFingerprint={fingerprint} />
      {identities.length > 1 && (
        <Link className="mt-2 inline-block text-caption text-brand-accent underline" to={`/identities?identity=${encodeURIComponent(identityId)}`}>
          {t("certificates.evidence.openSelectedIdentity")}
        </Link>
      )}
    </div>
  );
}
