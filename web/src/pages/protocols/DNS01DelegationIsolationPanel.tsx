import { ArrowRight, ShieldCheck, TriangleAlert } from "lucide-react";
import { useTranslation } from "@/i18n/I18nProvider";
import type { ACMEDNS01ProviderConfig, ACMEDNS01QualificationRun } from "@/lib/api";

export function DNS01DelegationIsolationPanel({
  config,
  recordName,
  run,
}: {
  config: ACMEDNS01ProviderConfig;
  recordName: string;
  run: ACMEDNS01QualificationRun | null;
}) {
  const { t } = useTranslation();
  const target = config.delegation_target?.trim();
  const proved = Boolean(target) && run?.status === "passed";
  const attempted = Boolean(run);

  if (!target) {
    return (
      <section aria-label={t("protocols.dns01.delegation.label")} className="rounded-control border border-status-warning/30 bg-status-warning/10 p-4">
        <div className="flex items-start gap-3">
          <TriangleAlert className="mt-0.5 h-5 w-5 shrink-0 text-status-warning" aria-hidden="true" />
          <div>
            <h3 className="font-semibold">{t("protocols.dns01.delegation.directTitle")}</h3>
            <p className="mt-1 text-sm text-muted-foreground">{t("protocols.dns01.delegation.directHelp")}</p>
            <p className="mt-2 break-all font-mono text-xs text-muted-foreground">{recordName}</p>
          </div>
        </div>
      </section>
    );
  }

  return (
    <section aria-label={t("protocols.dns01.delegation.label")} className="grid gap-4 rounded-control border border-border bg-background p-4">
      <div className="flex items-start gap-3">
        {proved ? (
          <ShieldCheck className="mt-0.5 h-5 w-5 shrink-0 text-status-success" aria-hidden="true" />
        ) : (
          <TriangleAlert className="mt-0.5 h-5 w-5 shrink-0 text-status-warning" aria-hidden="true" />
        )}
        <div>
          <h3 className="font-semibold">
            {proved
              ? t("protocols.dns01.delegation.provedTitle")
              : attempted
                ? t("protocols.dns01.delegation.notProvedTitle")
                : t("protocols.dns01.delegation.pendingTitle")}
          </h3>
          <p className="mt-1 text-sm text-muted-foreground">{t("protocols.dns01.delegation.guardHelp")}</p>
        </div>
      </div>

      <div className="grid items-center gap-2 sm:grid-cols-[minmax(0,1fr)_auto_minmax(0,1fr)_auto_minmax(0,1fr)]">
        <DelegationStep label={t("protocols.dns01.delegation.productionName")} value={recordName} />
        <ArrowRight className="mx-auto h-4 w-4 rotate-90 text-muted-foreground sm:rotate-0" aria-hidden="true" />
        <DelegationStep label={t("protocols.dns01.delegation.requiredCNAME")} value={target} />
        <ArrowRight className="mx-auto h-4 w-4 rotate-90 text-muted-foreground sm:rotate-0" aria-hidden="true" />
        <DelegationStep label={t("protocols.dns01.delegation.providerWriteTarget")} value={target} />
      </div>

      <div className="rounded-control border border-border bg-muted/20 p-3">
        <p className="text-sm font-medium">{t("protocols.dns01.delegation.changeTitle")}</p>
        <p className="mt-1 break-all font-mono text-xs text-muted-foreground">
          {t("protocols.dns01.delegation.changeInstruction", { record: recordName, target })}
        </p>
        <p className="mt-2 text-caption text-muted-foreground">{t("protocols.dns01.delegation.failClosed")}</p>
      </div>
    </section>
  );
}

function DelegationStep({ label, value }: { label: string; value: string }) {
  return (
    <div className="min-w-0 rounded-control border border-border bg-muted/20 p-3">
      <p className="text-caption font-medium text-muted-foreground">{label}</p>
      <p className="mt-1 break-all font-mono text-xs">{value}</p>
    </div>
  );
}
