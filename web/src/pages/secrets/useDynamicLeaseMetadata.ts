import { useEffect, useMemo, useState } from "react";
import { useAuth } from "@/auth/AuthProvider";
import { useTranslation } from "@/i18n/I18nProvider";
import { api, type DynamicLease } from "@/lib/api";
import { useApiQuery, useQueryClient } from "@/lib/query";
import { leaseMetadataOnly } from "./SecretsPageParts";

/** Only non-secret, exact-lease metadata enters the query cache. */
export function useDynamicLeaseMetadata(receipt: DynamicLease | null) {
  const { user } = useAuth();
  const { t } = useTranslation();
  const client = useQueryClient();
  const key = useMemo(() => ["dynamic-secret-lease", user?.tenant_id, user?.subject, receipt?.id], [user?.tenant_id, user?.subject, receipt?.id]);
  const query = useApiQuery(
    key,
    async ({ signal }) => {
      const result = await api.getDynamicLease(receipt!.id, signal);
      if (result.id !== receipt!.id || result.provider !== receipt!.provider || result.role !== receipt!.role) {
        throw new Error(t("secrets.dynamic.metadataMismatch"));
      }
      return leaseMetadataOnly(result);
    },
    { enabled: !!receipt, retry: false, live: { intervalMs: 5000 } },
  );
  const lease = query.data ?? receipt;
  const [now, setNow] = useState(Date.now);
  useEffect(() => {
    const deadline = Date.parse(lease?.expires_at ?? "");
    let timer: ReturnType<typeof setTimeout> | undefined;
    function checkDeadline() {
      const current = Date.now();
      setNow(current);
      if (!Number.isFinite(deadline) || deadline <= current) return;
      // One deadline wake-up hides the reveal between reads. Long leases
      // re-arm at the browser timeout limit; this is not server polling.
      timer = setTimeout(checkDeadline, Math.min(2147483647, deadline - current + 1));
    }
    checkDeadline();
    return () => clearTimeout(timer);
  }, [lease?.expires_at]);
  const expiresAt = Date.parse(lease?.expires_at ?? "");
  const active = lease?.state === "active" && Number.isFinite(expiresAt) && expiresAt > now && !query.error;
  const ceiling = Date.parse(lease?.hard_expires_at ?? "");
  const headroom = active && Number.isFinite(ceiling) && Number.isFinite(expiresAt) ? Math.max(0, Math.floor((ceiling - expiresAt) / 1000)) : 0;

  async function acceptMutation(result: DynamicLease) {
    if (!receipt || result.id !== receipt.id || result.provider !== receipt.provider || result.role !== receipt.role) {
      throw new Error(t("secrets.dynamic.metadataMismatch"));
    }
    await client.cancelQueries({ queryKey: key, exact: true });
    client.setQueryData(key, leaseMetadataOnly(result));
    await client.invalidateQueries({ queryKey: key, exact: true });
  }

  return { lease, active, headroom, error: query.error, refresh: query.refetch, acceptMutation };
}
