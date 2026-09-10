import { useState } from "react";
import { CredentialActivityTimeline } from "@/components/CredentialActivityTimeline";
import { Button } from "@/components/ui/button";
import { useTranslation } from "@/i18n/I18nProvider";
import { api, type Identity } from "@/lib/api";
import { useApiQuery, type ApiQueryResult } from "@/lib/query";

type Receipt = { id: string; identity_id?: string; created_at?: string; updated_at?: string };
type ReceiptPage<T> = { items: T[]; next_cursor?: string };

/** Re-read only the pages the operator requested. UUID cursors are not a
 * time-order or a snapshot; never promote a partial scan to latest history. */
export async function readIdentityReceiptPages<T extends Receipt>(
  identityId: string,
  pages: number,
  load: (options: { identityId: string; limit: number; cursor?: string }) => Promise<ReceiptPage<T>>,
  signal: AbortSignal,
): Promise<ReceiptPage<T>> {
  const items = new Map<string, T>();
  const cursors = new Set<string>();
  let cursor: string | undefined;
  for (let page = 0; page < pages; page += 1) {
    signal.throwIfAborted();
    const result = await load({ identityId, limit: 50, ...(cursor ? { cursor } : {}) });
    signal.throwIfAborted();
    for (const item of result.items) {
      if (item.identity_id !== identityId) throw new Error("Receipt response does not match the selected identity.");
      items.set(item.id, item);
    }
    cursor = result.next_cursor || undefined;
    if (!cursor) break;
    if (cursors.has(cursor)) throw new Error("Receipt pagination did not advance.");
    cursors.add(cursor);
  }
  return { items: [...items.values()], next_cursor: cursor ?? "" };
}

function mostRecentlyUpdated<T extends Receipt>(result: ApiQueryResult<ReceiptPage<T>>): T | undefined {
  if (!result.data || result.error || result.data.next_cursor) return undefined;
  const time = (item: T) => Date.parse(item.updated_at || item.created_at || "") || 0;
  return result.data.items.reduce<T | undefined>((latest, item) => (!latest || time(item) > time(latest) ? item : latest), undefined);
}

export function IdentityActivityEvidence({ identity }: { identity: Identity }) {
  const { t } = useTranslation();
  const [deliveryPages, setDeliveryPages] = useState(1);
  const [rotationPages, setRotationPages] = useState(1);
  const deliveries = useApiQuery(
    ["connector-deliveries", { identityId: identity.id, pages: deliveryPages }],
    ({ signal }) => readIdentityReceiptPages(identity.id, deliveryPages, api.connectorDeliveries, signal),
    { retry: false, live: { intervalMs: 10_000 } },
  );
  const rotations = useApiQuery(
    ["rotation-runs", { identityId: identity.id, pages: rotationPages }],
    ({ signal }) => readIdentityReceiptPages(identity.id, rotationPages, api.rotationRuns, signal),
    { retry: false, live: { intervalMs: 10_000 } },
  );
  function notice<T>(result: ApiQueryResult<ReceiptPage<T>>): string | undefined {
    if (result.error) return `${t("source.delivery.evidence.failed.to.load.2625e33346")}: ${result.error}`;
    if (!result.data) return t("source.loading.delivery.evidence.7f2cdadedd");
    if (result.data.next_cursor) return t("identities.evidence.partialHistory", { count: result.data.items.length });
    return undefined;
  }
  const deliveryNotice = notice(deliveries);
  const rotationNotice = notice(rotations);
  return (
    <>
      <CredentialActivityTimeline
        credentialLabel={identity.name}
        deliveryReceipt={mostRecentlyUpdated(deliveries)}
        rotationRun={mostRecentlyUpdated(rotations)}
        deliveryNotice={deliveryNotice}
        rotationNotice={rotationNotice}
        rollbackNotice={deliveryNotice || rotationNotice ? t("identities.evidence.incompleteRollback") : undefined}
      />
      <p className="mt-2 text-xs text-muted-foreground">{t("identities.evidence.scanMeaning")}</p>
      <div className="mt-2 flex flex-wrap gap-2">
        {deliveries.error && <Button onClick={deliveries.refetch}>{t("identities.evidence.retryDeliveries")}</Button>}
        {rotations.error && <Button onClick={rotations.refetch}>{t("identities.evidence.retryRotations")}</Button>}
        {deliveries.data?.next_cursor && !deliveries.error && (
          <Button loading={deliveries.fetching} onClick={() => setDeliveryPages((pages) => pages + 1)}>
            {t("identities.evidence.moreDeliveries")}
          </Button>
        )}
        {rotations.data?.next_cursor && !rotations.error && (
          <Button loading={rotations.fetching} onClick={() => setRotationPages((pages) => pages + 1)}>
            {t("identities.evidence.moreRotations")}
          </Button>
        )}
      </div>
    </>
  );
}
