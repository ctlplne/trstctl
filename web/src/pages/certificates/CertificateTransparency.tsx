import type { CertificateTransparencyEntry } from "@/lib/api-types.gen";
import { formatDateTime } from "@/i18n/format";
import { useTranslation } from "@/i18n/I18nProvider";

// A213: what each Certificate Transparency log answered for this certificate —
// its SCT checked against the log key the submission named, and whether the
// log proved the entry is in a tree head it signed.
export function CertificateTransparency({ entries }: { entries?: CertificateTransparencyEntry[] }) {
  const { t } = useTranslation();
  if (!entries || entries.length === 0) return null;
  const sct = (entry: CertificateTransparencyEntry): string => {
    if (entry.sct_status === "verified") return t("certificateCockpit.detail.ctSCTVerified");
    if (entry.sct_status === "invalid") return t("certificateCockpit.detail.ctSCTInvalid", { reason: entry.sct_reason ?? "" });
    return t("certificateCockpit.detail.ctSCTUnverified", { reason: entry.sct_reason ?? "" });
  };
  const inclusion = (entry: CertificateTransparencyEntry): string => {
    switch (entry.inclusion_status) {
      case "verified":
        return t("certificateCockpit.detail.ctIncluded", { index: entry.leaf_index ?? 0, size: entry.tree_size ?? 0 });
      case "pending":
        return t("certificateCockpit.detail.ctInclusionPending");
      case "not_included":
        return t("certificateCockpit.detail.ctNotIncluded", { reason: entry.inclusion_reason ?? "" });
      case "proof_invalid":
        return t("certificateCockpit.detail.ctProofInvalid", { reason: entry.inclusion_reason ?? "" });
      default:
        return entry.inclusion_reason
          ? t("certificateCockpit.detail.ctInclusionNotCheckedBecause", { reason: entry.inclusion_reason })
          : t("certificateCockpit.detail.ctInclusionNotChecked");
    }
  };
  return (
    <div className="md:col-span-2">
      <dt className="font-medium text-muted-foreground">{t("certificateCockpit.detail.transparency")}</dt>
      {entries.map((entry) => (
        <dd key={entry.submission_id} className="break-all text-sm">
          {t("certificateCockpit.detail.transparencyEntry", {
            log: entry.log_url,
            entry: t(entry.entry_type === "precertificate" ? "certificateCockpit.detail.ctPrecertificate" : "certificateCockpit.detail.ctCertificate"),
            logged: formatDateTime(entry.sct_timestamp),
            sct: sct(entry),
            inclusion: inclusion(entry),
          })}
        </dd>
      ))}
      <dd className="mt-1 text-xs text-muted-foreground">{t("certificateCockpit.detail.transparencyNote")}</dd>
    </div>
  );
}
