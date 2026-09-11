import { useQuery } from "@tanstack/react-query";
import { StatusBadge } from "@/components/StatusBadge";
import { Button } from "@/components/ui/button";
import { useTranslation } from "@/i18n/I18nProvider";
import { api, type ConnectorDelivery } from "@/lib/api";
import { liveRefetchInterval } from "@/lib/query";
import { describeStatus } from "@/lib/statusVocab";

/** Rollback updates its original receipt. Read that ID, not a page of possibly
 * unrelated deliveries. A re-armed command gets its own query cache entry;
 * its result may change the command key and the display name to a route. */
export function RecoveryResult({ initial }: { initial: ConnectorDelivery }) {
  const { t } = useTranslation();
  const result = useQuery({
    queryKey: ["connector-recovery", initial.tenant_id, initial.id, initial.idempotency_key, initial.updated_at],
    initialData: initial,
    staleTime: 0,
    retry: false,
    meta: { live: true },
    queryFn: async () => {
      const receipt = await api.connectorDelivery(initial.id);
      if (
        receipt.id !== initial.id ||
        receipt.tenant_id !== initial.tenant_id ||
        receipt.outbox_id !== initial.outbox_id ||
        receipt.identity_id !== initial.identity_id ||
        receipt.connector !== initial.connector ||
        receipt.destination !== "connector.rollback"
      ) {
        throw new Error(t("connectors.recovery.readFailed"));
      }
      return receipt;
    },
    refetchInterval: (query) => (query.state.error || query.state.data?.status !== "rollback_queued" ? false : liveRefetchInterval(3000)),
  });
  const receipt = result.data;
  return (
    <section
      aria-labelledby="connector-recovery-result-heading"
      className="grid gap-2 rounded-control border border-border bg-muted/30 p-3 md:col-span-3"
      role="status"
    >
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h3 id="connector-recovery-result-heading" className="font-semibold">
          {result.isError
            ? t("connectors.recovery.notExecuted")
            : receipt.status === "rolled_back"
              ? t("connectors.recovery.restored")
              : receipt.status === "rollback_queued"
                ? t("connectors.recovery.queued")
                : t("connectors.recovery.notExecuted")}
        </h3>
        {!result.isError && <StatusBadge value={receipt.status} vocabulary="delivery" tone={describeStatus("delivery", receipt.status).tone} />}
      </div>
      {result.isError ? (
        <p role="alert" className="text-sm text-status-warning">
          {t("connectors.recovery.readFailed")}
        </p>
      ) : (
        <p className="text-sm text-muted-foreground">{receipt.detail || receipt.reason || "-"}</p>
      )}
      {(receipt.status !== "rolled_back" || result.isError) && (
        <Button
          type="button"
          size="sm"
          variant="outline"
          className="justify-self-start"
          loading={result.isFetching}
          onClick={() => void result.refetch({ cancelRefetch: false })}
        >
          {t("connectors.recovery.refresh")}
        </Button>
      )}
    </section>
  );
}
