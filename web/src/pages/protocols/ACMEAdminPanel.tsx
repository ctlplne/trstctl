import { useState } from "react";
import { DataGrid, type DataGridColumn } from "@/components/DataGrid";
import { useCan } from "@/components/rbac";
import { StatusBadge } from "@/components/StatusBadge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Select } from "@/components/ui/select";
import { useTranslation } from "@/i18n/I18nProvider";
import { api, ApiError, type ACMEAccount, type ACMEAccountList, type ACMEOrder, type BulkRevokeRequest } from "@/lib/api";
import { useApiQuery } from "@/lib/query";

// The ACME admin console (A52).
//
// The readiness panel above answers "can clients enroll here". This one
// answers what an operator asks once they do: which accounts exist and under
// which binding credential, what each has ordered, which authorization and
// challenge a stuck order is waiting on, and the two verbs that matter in an
// incident: retire an account (its next request is refused and its pending
// orders cancelled; issued certificates stay) and revoke an issued leaf
// through the same governed certificate path every other revocation uses.
// Nothing here renders key material; an account is named by the public
// thumbprint of its key.

type AccountsRead = { kind: "ready"; list: ACMEAccountList } | { kind: "permission-denied" } | { kind: "unavailable" };

async function readAccounts(): Promise<AccountsRead> {
  try {
    return { kind: "ready", list: await api.acmeAccounts() };
  } catch (error) {
    if (error instanceof ApiError && error.status === 403) return { kind: "permission-denied" };
    if (error instanceof ApiError && [0, 404, 501, 503].includes(error.status)) return { kind: "unavailable" };
    throw error;
  }
}

const REVOCATION_REASONS: Array<BulkRevokeRequest["reason"]> = [
  "keyCompromise",
  "superseded",
  "cessationOfOperation",
  "affiliationChanged",
  "privilegeWithdrawn",
  "unspecified",
];

function orderTone(status: string) {
  if (status === "valid") return "success" as const;
  if (status === "invalid") return "critical" as const;
  return "warning" as const;
}

export function ACMEAdminPanel() {
  const { t, formatDateTime } = useTranslation();
  const canRead = useCan("issuers:read");
  const canWrite = useCan("issuers:write");
  const canRevoke = useCan("certs:issue");
  const available = typeof api.acmeAccounts === "function";
  const accountsQuery = useApiQuery(["acme", "admin", "accounts"], readAccounts, { enabled: canRead && available });
  const [selected, setSelected] = useState<string | null>(null);
  const ordersQuery = useApiQuery(["acme", "admin", "orders", selected ?? ""], () => (selected ? api.acmeAccountOrders(selected) : Promise.resolve(null)), {
    enabled: canRead && available && selected !== null,
  });
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [reason, setReason] = useState<BulkRevokeRequest["reason"]>("keyCompromise");

  if (!canRead || !available) return null;
  const list = accountsQuery.data?.kind === "ready" ? accountsQuery.data.list : null;
  const accounts = list?.items ?? [];
  const orders = ordersQuery.data?.items ?? [];

  const run = async (key: string, action: () => Promise<unknown>) => {
    setBusy(key);
    setError(null);
    try {
      await action();
      await Promise.all([accountsQuery.refetch(), ordersQuery.refetch()]);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(null);
    }
  };

  const accountColumns: Array<DataGridColumn<ACMEAccount>> = [
    {
      id: "id",
      header: t("protocols.acmeAdmin.account"),
      cell: (account) => (
        <span className="grid gap-1">
          <span className="break-all font-mono text-xs font-medium">{account.id}</span>
          <StatusBadge value={account.status} label={account.status} tone={account.status === "valid" ? "success" : "critical"} />
          {account.eab_key_id ? <span className="text-2xs text-muted-foreground">{t("protocols.acmeAdmin.boundBy", { kid: account.eab_key_id })}</span> : null}
        </span>
      ),
    },
    {
      id: "usage",
      header: t("protocols.acmeAdmin.usage"),
      cell: (account) => (
        <span className="grid gap-1 text-xs">
          <span>{t("protocols.acmeAdmin.orders", { count: account.orders })}</span>
          <span>{t("protocols.acmeAdmin.certificates", { count: account.certificates })}</span>
          {account.contact?.length ? <span className="text-muted-foreground">{account.contact.join(", ")}</span> : null}
        </span>
      ),
    },
    {
      id: "actions",
      header: "",
      cell: (account) => (
        <span className="flex flex-wrap gap-1">
          <Button type="button" size="sm" variant={selected === account.id ? "default" : "outline"} onClick={() => setSelected(account.id)}>
            {t("protocols.acmeAdmin.showOrders")}
          </Button>
          {canWrite && account.status === "valid" ? (
            <Button
              type="button"
              size="sm"
              variant="destructive"
              disabled={busy === account.id}
              onClick={() => void run(account.id, () => api.deactivateACMEAccount(account.id))}
            >
              {t("protocols.acmeAdmin.deactivate")}
            </Button>
          ) : null}
        </span>
      ),
    },
  ];

  const orderColumns: Array<DataGridColumn<ACMEOrder>> = [
    {
      id: "order",
      header: t("protocols.acmeAdmin.order"),
      cell: (order) => (
        <span className="grid gap-1">
          <span className="font-mono text-xs">{order.identifiers.join(", ")}</span>
          <StatusBadge value={order.status} label={order.status} tone={orderTone(order.status)} />
          <span className="text-2xs text-muted-foreground">{formatDateTime(order.created_at)}</span>
          {order.profile ? <span className="text-2xs text-muted-foreground">{t("protocols.acmeAdmin.profile", { profile: order.profile })}</span> : null}
        </span>
      ),
    },
    {
      id: "validation",
      header: t("protocols.acmeAdmin.validation"),
      cell: (order) => (
        <span className="grid gap-1 text-xs">
          {order.authorizations.length === 0 ? <span className="text-muted-foreground">{t("protocols.acmeAdmin.noAuthorizations")}</span> : null}
          {order.authorizations.map((authz) => (
            <span key={authz.id} className="grid gap-0.5">
              <span>
                <span className="font-mono">{authz.domain}</span> · {authz.status}
              </span>
              {authz.challenges.map((challenge) => (
                <span key={challenge.id} className="text-2xs text-muted-foreground">
                  {challenge.type} · {challenge.status}
                </span>
              ))}
            </span>
          ))}
        </span>
      ),
    },
    {
      id: "certificate",
      header: t("protocols.acmeAdmin.certificate"),
      cell: (order) =>
        order.certificate_serial ? (
          <span className="grid gap-1 text-xs">
            <span className="break-all font-mono">{order.certificate_serial}</span>
            {order.revoked ? (
              <StatusBadge value="revoked" label={t("protocols.acmeAdmin.revoked")} tone="critical" />
            ) : canRevoke && order.certificate_record_id ? (
              <span className="flex flex-wrap items-center gap-1">
                <Select
                  aria-label={t("protocols.acmeAdmin.revokeReason")}
                  value={reason}
                  onChange={(event) => setReason(event.target.value as BulkRevokeRequest["reason"])}
                >
                  {REVOCATION_REASONS.map((value) => (
                    <option key={value} value={value}>
                      {value}
                    </option>
                  ))}
                </Select>
                <Button
                  type="button"
                  size="sm"
                  variant="destructive"
                  disabled={busy === order.id}
                  onClick={() => void run(order.id, () => api.bulkRevokeCertificates({ certificate_ids: [order.certificate_record_id as string], reason }))}
                >
                  {t("protocols.acmeAdmin.revoke")}
                </Button>
              </span>
            ) : null}
          </span>
        ) : (
          <span className="text-xs text-muted-foreground">{t("protocols.acmeAdmin.notIssued")}</span>
        ),
    },
  ];

  return (
    <Card role="region" id="acme-admin-panel" aria-labelledby="acme-admin-heading" className="grid scroll-mt-24 gap-4 p-comfortable">
      <div>
        <h2 id="acme-admin-heading" className="text-title font-semibold">
          {t("protocols.acmeAdmin.heading")}
        </h2>
        <p className="mt-1 text-body text-muted-foreground">{t("protocols.acmeAdmin.description")}</p>
      </div>
      {error ? <p className="text-sm text-risk-critical">{error}</p> : null}
      {accountsQuery.data?.kind === "unavailable" || (list && !list.served) ? (
        <p className="text-sm text-muted-foreground">{t("protocols.acmeAdmin.unavailable")}</p>
      ) : accounts.length === 0 && !accountsQuery.loading ? (
        <p className="text-sm text-muted-foreground">{t("protocols.acmeAdmin.noAccounts")}</p>
      ) : (
        <DataGrid
          ariaLabel={t("protocols.acmeAdmin.accountsLabel")}
          rows={accounts}
          columns={accountColumns}
          getRowId={(account) => account.id}
          virtualization={false}
        />
      )}
      {selected ? (
        <section aria-labelledby="acme-admin-orders-heading" className="grid gap-2 border-t border-border pt-3">
          <h3 id="acme-admin-orders-heading" className="text-body font-semibold">
            {t("protocols.acmeAdmin.ordersHeading", { account: selected })}
          </h3>
          {orders.length === 0 && !ordersQuery.loading ? (
            <p className="text-sm text-muted-foreground">{t("protocols.acmeAdmin.noOrders")}</p>
          ) : (
            <DataGrid
              ariaLabel={t("protocols.acmeAdmin.ordersLabel")}
              rows={orders}
              columns={orderColumns}
              getRowId={(order) => order.id}
              virtualization={false}
            />
          )}
        </section>
      ) : null}
      <p className="text-2xs text-muted-foreground">{t("protocols.acmeAdmin.contract")}</p>
    </Card>
  );
}
