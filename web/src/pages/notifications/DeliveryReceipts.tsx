import { CredentialChip } from "@/components/CredentialChip";
import { Num } from "@/components/typography";
import { useTranslation } from "@/i18n/I18nProvider";
import { formatDateTime } from "@/i18n/format";
import type { MessageKey } from "@/i18n/messages";
import type { Notification } from "@/lib/api";

const routingLabels = {
  explicit_policy: "notifications.receipts.explicit_policy",
  inherited_policy: "notifications.receipts.inherited_policy",
  default_policy: "notifications.receipts.default_policy",
  all_channels: "notifications.receipts.all_channels",
  channel_test: "notifications.receipts.channel_test",
} satisfies Record<string, MessageKey>;

export function DeliveryReceipts({ deliveries }: { deliveries: Notification["deliveries"] }) {
  const { t } = useTranslation();
  return (
    <section aria-label={t("notifications.receipts.heading")} className="min-w-0">
      <h3 className="text-sm font-semibold">{t("notifications.receipts.heading")}</h3>
      <p className="mt-1 text-sm text-muted-foreground">{t("notifications.receipts.help")}</p>
      {deliveries?.length ? (
        <ul className="mt-3 grid min-w-0 gap-3">
          {deliveries.map((receipt) => (
            <li key={receipt.id} className="min-w-0 border-t border-border pt-3 text-sm [overflow-wrap:anywhere]">
              <p className="font-medium">
                {receipt.channel} · <Num>{formatDateTime(receipt.delivered_at)}</Num>
              </p>
              <p className="mt-1 text-muted-foreground">
                {t(receipt.routing_source && routingLabels[receipt.routing_source] ? routingLabels[receipt.routing_source] : "notifications.receipts.unknown")}
              </p>
              {receipt.routing_policy_id ? (
                <dl className="mt-2 grid min-w-0 gap-2">
                  <div className="min-w-0">
                    <dt className="text-muted-foreground">{t("notifications.receipts.policy")}</dt>
                    <dd>
                      <CredentialChip value={receipt.routing_policy_id} fullValue />
                    </dd>
                  </div>
                  {receipt.routing_policy_scope ? (
                    <div>
                      <dt className="text-muted-foreground">{t("notifications.receipts.scope")}</dt>
                      <dd>{receipt.routing_policy_scope}</dd>
                    </div>
                  ) : null}
                </dl>
              ) : null}
              <details className="mt-2 min-w-0">
                <summary className="cursor-pointer text-muted-foreground">{t("notifications.receipts.proof")}</summary>
                <div className="mt-2 grid min-w-0 gap-2">
                  <CredentialChip value={receipt.id} fullValue />
                  {receipt.routing_policy_digest ? <CredentialChip value={receipt.routing_policy_digest} fullValue /> : null}
                </div>
              </details>
            </li>
          ))}
        </ul>
      ) : (
        <p className="mt-2 text-sm text-muted-foreground">{t("notifications.receipts.empty")}</p>
      )}
    </section>
  );
}
