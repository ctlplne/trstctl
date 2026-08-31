import { CredentialChip } from "@/components/CredentialChip";
import { useTranslation } from "@/i18n/I18nProvider";

/** Display only the server's certificate-derived identity. A friendly subject,
 * current tenant, owner or preview is not a replacement for the signed URI. */
export function WorkloadIdentityHandoff({ spiffeID }: { spiffeID?: string }) {
  const { t } = useTranslation();
  return (
    <details className="min-w-0 border-t border-border pt-3">
      <summary tabIndex={0} className="cursor-pointer text-sm font-medium">
        {t("workloads.signedIdentity.title")}
      </summary>
      <div className="mt-3 grid min-w-0 gap-3 text-sm">
        {spiffeID ? (
          <>
            <p className="text-muted-foreground">{t("workloads.signedIdentity.instructions")}</p>
            <CredentialChip value={spiffeID} label={t("workloads.signedIdentity.title")} fullValue />
          </>
        ) : (
          <p className="border-s-2 border-status-warning ps-3">{t("workloads.signedIdentity.unavailable")}</p>
        )}
        <p className="text-muted-foreground">{t("workloads.signedIdentity.cutover")}</p>
      </div>
    </details>
  );
}
