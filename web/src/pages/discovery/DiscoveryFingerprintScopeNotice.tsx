import { Button } from "@/components/ui/button";
import { CredentialChip } from "@/components/CredentialChip";
import { useTranslation } from "@/i18n/I18nProvider";

// A172-L2: the findings list is narrowed to every finding that names one
// certificate or key fingerprint; the notice says so and clears it.
export function DiscoveryFingerprintScopeNotice({ fingerprint, onClear }: { fingerprint: string; onClear: () => void }) {
  const { t } = useTranslation();
  return (
    <div className="flex flex-wrap items-center gap-2 rounded-control border border-border bg-muted/40 px-3 py-2 text-sm">
      <span>{t("discovery.findings.fingerprintScope")}</span>
      <CredentialChip value={fingerprint} label={t("discovery.findings.columnFingerprint")} />
      <Button type="button" variant="ghost" size="sm" onClick={onClear}>
        {t("discovery.findings.clearRunScope")}
      </Button>
    </div>
  );
}
