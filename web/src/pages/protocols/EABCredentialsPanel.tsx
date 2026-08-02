import { useState } from "react";
import { DataGrid, type DataGridColumn } from "@/components/DataGrid";
import { useCan } from "@/components/rbac";
import { StatusBadge } from "@/components/StatusBadge";
import { Button } from "@/components/ui/button";
import { useTranslation } from "@/i18n/I18nProvider";
import { api, ApiError, type ACMEEABCredential, type ACMEEABPosture } from "@/lib/api";
import { useApiQuery } from "@/lib/query";

// The ACME external-account-binding operator panel (epic B4).
//
// EAB credentials were configuration and nothing else. An operator could read
// the key ids out of a config file and had no way to ask what any of them had
// done, or to stop one: a leaked credential meant editing config and restarting
// every node while the credential kept working.
//
// This shows what each credential authorizes, what has been taken under it, and
// gives the one verb that matters in an incident — switch this credential off
// now. Nothing here renders the HMAC key, because the served response does not
// carry it in any form.

type EABRead = { kind: "ready"; posture: ACMEEABPosture } | { kind: "permission-denied" } | { kind: "unavailable" };

async function readEABPosture(): Promise<EABRead> {
  try {
    return { kind: "ready", posture: await api.acmeEABCredentials() };
  } catch (error) {
    if (error instanceof ApiError && error.status === 403) return { kind: "permission-denied" };
    if (error instanceof ApiError && [0, 404, 501, 503].includes(error.status)) return { kind: "unavailable" };
    throw error;
  }
}

function stateTone(state: ACMEEABCredential["state"]) {
  if (state === "active") return "success" as const;
  if (state === "disabled") return "critical" as const;
  return "warning" as const;
}

export function EABCredentialsPanel() {
  const { formatDateTime, t } = useTranslation();
  const canRead = useCan("issuers:read");
  const canWrite = useCan("issuers:write");
  const available = typeof api.acmeEABCredentials === "function";
  const query = useApiQuery(["acme", "eab", "credentials"], readEABPosture, { enabled: canRead && available });
  const [busyKey, setBusyKey] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  if (!canRead || !available) return null;

  const posture = query.data?.kind === "ready" ? query.data.posture : null;
  const rows = posture?.items ?? [];

  const toggle = async (credential: ACMEEABCredential) => {
    setBusyKey(credential.key_id);
    setError(null);
    try {
      await api.setACMEEABCredentialDisabled(credential.key_id, !credential.disabled_by_operator);
      await query.refetch();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusyKey(null);
    }
  };

  const columns: Array<DataGridColumn<ACMEEABCredential>> = [
    {
      id: "key_id",
      header: t("protocols.eab.keyID"),
      cell: (credential) => (
        <span className="grid gap-1">
          <span className="break-all font-mono text-xs font-medium">{credential.key_id}</span>
          <StatusBadge value={credential.state} label={credential.state} tone={stateTone(credential.state)} />
          {credential.reason ? <span className="text-2xs text-muted-foreground">{credential.reason}</span> : null}
        </span>
      ),
    },
    {
      id: "scope",
      header: t("protocols.eab.scope"),
      cell: (credential) => (
        <span className="grid gap-1">
          {credential.allowed_identifiers?.length ? (
            <span className="font-mono text-xs">{credential.allowed_identifiers.join(", ")}</span>
          ) : (
            <span className="text-xs text-muted-foreground">{t("protocols.eab.unscoped")}</span>
          )}
          <span className="text-2xs text-muted-foreground">
            {credential.max_orders
              ? t("protocols.eab.quota", { used: credential.orders_created, max: credential.max_orders })
              : t("protocols.eab.noQuota")}
          </span>
          {credential.not_after ? <span className="text-2xs text-muted-foreground">{formatDateTime(credential.not_after)}</span> : null}
        </span>
      ),
    },
    {
      id: "usage",
      header: t("protocols.eab.usage"),
      cell: (credential) => (
        <span className="grid gap-1 text-xs">
          <span>{t("protocols.eab.accountsBound", { count: credential.accounts_bound })}</span>
          <span>{t("protocols.eab.ordersCreated", { count: credential.orders_created })}</span>
          <span className={credential.orders_denied > 0 ? "text-status-warning" : "text-muted-foreground"}>
            {t("protocols.eab.ordersDenied", { count: credential.orders_denied })}
          </span>
          {credential.last_used_at ? <span className="text-muted-foreground">{formatDateTime(credential.last_used_at)}</span> : null}
        </span>
      ),
    },
    {
      id: "actions",
      header: "",
      cell: (credential) =>
        canWrite && !credential.disabled_in_config ? (
          <Button
            type="button"
            size="sm"
            variant={credential.disabled_by_operator ? "outline" : "destructive"}
            disabled={busyKey === credential.key_id}
            onClick={() => void toggle(credential)}
          >
            {credential.disabled_by_operator ? t("protocols.eab.enable") : t("protocols.eab.disable")}
          </Button>
        ) : null,
    },
  ];

  return (
    <section aria-labelledby="acme-eab-heading" className="grid content-start gap-3 border-t border-border pt-4">
      <div>
        <h3 id="acme-eab-heading" className="text-body font-semibold">
          {t("protocols.eab.heading")}
        </h3>
        <p className="mt-1 text-sm text-muted-foreground">{t("protocols.eab.description")}</p>
      </div>
      {posture?.required ? <p className="text-xs text-muted-foreground">{t("protocols.eab.required")}</p> : null}
      {error ? <p className="text-sm text-risk-critical">{error}</p> : null}
      {query.data?.kind === "unavailable" || (posture && !posture.served) ? (
        <p className="text-sm text-muted-foreground">{t("protocols.eab.unavailable")}</p>
      ) : rows.length === 0 && !query.loading ? (
        <p className="text-sm text-muted-foreground">{t("protocols.eab.notConfigured")}</p>
      ) : (
        <DataGrid
          ariaLabel={t("protocols.eab.listLabel")}
          rows={rows}
          columns={columns}
          getRowId={(credential) => credential.key_id}
          virtualization={false}
        />
      )}
      <p className="text-2xs text-muted-foreground">{t("protocols.eab.rotation")}</p>
    </section>
  );
}
