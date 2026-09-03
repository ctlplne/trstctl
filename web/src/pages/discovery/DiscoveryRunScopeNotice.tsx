import { CredentialChip } from "@/components/CredentialChip";
import { Button } from "@/components/ui/button";
import { useTranslation } from "@/i18n/I18nProvider";

// F39 browser repair, extracted before touching the Discovery monolith (R-09):
// a scan-result handoff must make its exact server-side run filter visible and
// reversible instead of quietly showing findings from every run.
export function DiscoveryRunScopeNotice({ runId, onClear }: { runId: string; onClear: () => void }) {
  const { t } = useTranslation();
  return (
    <div className="flex flex-wrap items-center gap-2 rounded-control border border-border bg-muted/40 px-3 py-2 text-sm">
      <span>{t("discovery.findings.runScope")}</span>
      <CredentialChip value={runId} label={t("discovery.findings.exactRunId")} />
      <Button type="button" variant="ghost" size="sm" onClick={onClear}>
        {t("discovery.findings.clearRunScope")}
      </Button>
    </div>
  );
}
