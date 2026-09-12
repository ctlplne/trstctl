import { ErrorState } from "@/components/StatePrimitives";
import { Button } from "@/components/ui/button";
import { useTranslation } from "@/i18n/I18nProvider";
import type { DynamicLease } from "@/lib/api";
import { DynamicLeaseMetadata, RevealPanel } from "./SecretsPageParts";

export function DynamicLeaseEvidence({
  lease,
  active,
  error,
  refresh,
  credential,
  dismiss,
}: {
  lease: DynamicLease;
  active: boolean;
  error: string | null;
  refresh: () => void;
  credential: { leaseID: string; value: string } | null;
  dismiss: () => void;
}) {
  const { t } = useTranslation();
  const complete = lease.revocation_status === "completed" && !!lease.revocation_completed_at;
  const status = error
    ? t("secrets.dynamic.statusUnavailable")
    : complete
      ? t("secrets.dynamic.providerRemoved")
      : lease.revocation_status === "failed"
        ? t("secrets.dynamic.providerRevokeFailed")
        : lease.revocation_status === "pending"
          ? t("secrets.dynamic.providerRevokePending")
          : active
            ? t("secrets.dynamic.issuedTitle")
            : t("secrets.dynamic.providerRemovalUnconfirmed");
  return (
    <div className="grid gap-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div role="status">
          <h3 className="font-semibold">{status}</h3>
          <p className="mt-1 text-sm text-muted-foreground">{t("secrets.dynamic.revocationTiming")}</p>
        </div>
        <Button type="button" variant="outline" onClick={refresh}>
          {t("secrets.dynamic.refreshStatus")}
        </Button>
      </div>
      {error ? <ErrorState title={t("secrets.dynamic.statusUnavailable")}>{error}</ErrorState> : null}
      <DynamicLeaseMetadata lease={lease} />
      {credential && active && credential.leaseID === lease.id ? (
        <RevealPanel title={t("secrets.dynamic.credentialTitle", { id: credential.leaseID })} onDismiss={dismiss} value={credential.value}>
          {t("secrets.dynamic.credentialHelp")}
        </RevealPanel>
      ) : null}
    </div>
  );
}
