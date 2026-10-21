import { useState, type FormEvent } from "react";
import { DataGrid, type DataGridColumn } from "@/components/DataGrid";
import { useCan } from "@/components/rbac";
import { StatusBadge } from "@/components/StatusBadge";
import { Button } from "@/components/ui/button";
import { Field } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { useTranslation } from "@/i18n/I18nProvider";
import { api, ApiError, type ACMEEABCredential, type ACMEEABPosture } from "@/lib/api";
import { useApiQuery } from "@/lib/query";

// The ACME external-account-binding operator panel (epic B4, A50/A53/A54).
//
// EAB credentials were configuration and nothing else. An operator could read
// the key ids out of a config file and had no way to ask what any of them had
// done, or to stop one: a leaked credential meant editing config and restarting
// every node while the credential kept working.
//
// This shows what each credential authorizes, what has been taken under it, and
// gives the verbs that matter: switch a credential off now, replace its policy
// at runtime, and rotate it by registering a successor whose MAC key is read
// from the tenant secret store by reference. Nothing here renders or accepts an
// HMAC key, because no served request or response carries one.

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
  if (state === "disabled" || state === "unavailable") return "critical" as const;
  return "warning" as const;
}

type OpenForm = { kind: "rotate"; credential: ACMEEABCredential } | { kind: "policy"; credential: ACMEEABCredential };

export function EABCredentialsPanel() {
  const { formatDateTime, t } = useTranslation();
  const canRead = useCan("issuers:read");
  const canWrite = useCan("issuers:write");
  const available = typeof api.acmeEABCredentials === "function";
  const query = useApiQuery(["acme", "eab", "credentials"], readEABPosture, { enabled: canRead && available });
  const [busyKey, setBusyKey] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [open, setOpen] = useState<OpenForm | null>(null);

  if (!canRead || !available) return null;

  const posture = query.data?.kind === "ready" ? query.data.posture : null;
  const rows = posture?.items ?? [];

  const run = async (kid: string, action: () => Promise<unknown>) => {
    setBusyKey(kid);
    setError(null);
    try {
      await action();
      setOpen(null);
      await query.refetch();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusyKey(null);
    }
  };
  const toggle = (credential: ACMEEABCredential) =>
    run(credential.key_id, () => api.setACMEEABCredentialDisabled(credential.key_id, !credential.disabled_by_operator));

  const columns: Array<DataGridColumn<ACMEEABCredential>> = [
    {
      id: "key_id",
      header: t("protocols.eab.keyID"),
      cell: (credential) => (
        <span className="grid gap-1">
          <span className="break-all font-mono text-xs font-medium">{credential.key_id}</span>
          <StatusBadge value={credential.state} label={credential.state} tone={stateTone(credential.state)} />
          {credential.reason ? <span className="text-2xs text-muted-foreground">{credential.reason}</span> : null}
          {credential.hmac_key_ref ? (
            <span className="break-all font-mono text-2xs text-muted-foreground">{t("protocols.eab.keyRef", { ref: credential.hmac_key_ref })}</span>
          ) : null}
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
            {credential.max_orders ? t("protocols.eab.quota", { used: credential.orders_created, max: credential.max_orders }) : t("protocols.eab.noQuota")}
          </span>
          {credential.not_after ? <span className="text-2xs text-muted-foreground">{formatDateTime(credential.not_after)}</span> : null}
          {credential.profile ? (
            <span className="text-2xs text-muted-foreground">{t("protocols.eab.profilePinned", { profile: credential.profile })}</span>
          ) : null}
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
        canWrite ? (
          <span className="flex flex-wrap gap-1">
            {!credential.disabled_in_config ? (
              <Button
                type="button"
                size="sm"
                variant={credential.disabled_by_operator ? "outline" : "destructive"}
                disabled={busyKey === credential.key_id}
                onClick={() => void toggle(credential)}
              >
                {credential.disabled_by_operator ? t("protocols.eab.enable") : t("protocols.eab.disable")}
              </Button>
            ) : null}
            <Button type="button" size="sm" variant="outline" disabled={busyKey === credential.key_id} onClick={() => setOpen({ kind: "policy", credential })}>
              {t("protocols.eab.policy")}
            </Button>
            <Button type="button" size="sm" variant="outline" disabled={busyKey === credential.key_id} onClick={() => setOpen({ kind: "rotate", credential })}>
              {t("protocols.eab.rotate")}
            </Button>
          </span>
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
        <DataGrid ariaLabel={t("protocols.eab.listLabel")} rows={rows} columns={columns} getRowId={(credential) => credential.key_id} virtualization={false} />
      )}
      {open?.kind === "rotate" ? (
        <RotateForm credential={open.credential} busy={busyKey === open.credential.key_id} onCancel={() => setOpen(null)} onSubmit={run} />
      ) : null}
      {open?.kind === "policy" ? (
        <PolicyForm credential={open.credential} busy={busyKey === open.credential.key_id} onCancel={() => setOpen(null)} onSubmit={run} />
      ) : null}
      <p className="text-2xs text-muted-foreground">{t("protocols.eab.rotation")}</p>
    </section>
  );
}

type FormProps = {
  credential: ACMEEABCredential;
  busy: boolean;
  onCancel: () => void;
  onSubmit: (kid: string, action: () => Promise<unknown>) => Promise<void>;
};

function RotateForm({ credential, busy, onCancel, onSubmit }: FormProps) {
  const { t } = useTranslation();
  const [successor, setSuccessor] = useState("");
  const [ref, setRef] = useState("secret://");
  const submit = (event: FormEvent) => {
    event.preventDefault();
    void onSubmit(credential.key_id, () => api.rotateACMEEABCredential(credential.key_id, { successor_key_id: successor.trim(), hmac_key_ref: ref.trim() }));
  };
  return (
    <form
      onSubmit={submit}
      className="grid gap-3 rounded-md border border-border p-3"
      aria-label={t("protocols.eab.rotateHeading", { kid: credential.key_id })}
    >
      <h4 className="text-sm font-semibold">{t("protocols.eab.rotateHeading", { kid: credential.key_id })}</h4>
      <Field label={t("protocols.eab.rotateSuccessor")} required>
        {(control) => <Input {...control} value={successor} onChange={(e) => setSuccessor(e.target.value)} autoComplete="off" />}
      </Field>
      <Field label={t("protocols.eab.rotateRef")} description={t("protocols.eab.rotateRefHelp")} required>
        {(control) => <Input {...control} value={ref} onChange={(e) => setRef(e.target.value)} autoComplete="off" />}
      </Field>
      <div className="flex gap-2">
        <Button type="submit" size="sm" disabled={busy || !successor.trim() || !ref.trim().startsWith("secret://")}>
          {t("protocols.eab.rotateSubmit")}
        </Button>
        <Button type="button" size="sm" variant="outline" onClick={onCancel} disabled={busy}>
          {t("protocols.eab.cancel")}
        </Button>
      </div>
    </form>
  );
}

function PolicyForm({ credential, busy, onCancel, onSubmit }: FormProps) {
  const { t } = useTranslation();
  const [identifiers, setIdentifiers] = useState((credential.allowed_identifiers ?? []).join(", "));
  const [maxOrders, setMaxOrders] = useState(String(credential.max_orders ?? 0));
  const [notAfter, setNotAfter] = useState(credential.not_after ? credential.not_after.slice(0, 16) : "");
  const [profile, setProfile] = useState(credential.profile ?? "");
  const submit = (event: FormEvent) => {
    event.preventDefault();
    const allowed = identifiers
      .split(",")
      .map((v) => v.trim())
      .filter(Boolean);
    const quota = Number.parseInt(maxOrders, 10);
    void onSubmit(credential.key_id, () =>
      api.updateACMEEABPolicy(credential.key_id, {
        allowed_identifiers: allowed,
        max_orders: Number.isFinite(quota) && quota > 0 ? quota : 0,
        not_after: notAfter ? new Date(notAfter).toISOString() : undefined,
        profile: profile.trim() || undefined,
      }),
    );
  };
  return (
    <form
      onSubmit={submit}
      className="grid gap-3 rounded-md border border-border p-3"
      aria-label={t("protocols.eab.policyHeading", { kid: credential.key_id })}
    >
      <h4 className="text-sm font-semibold">{t("protocols.eab.policyHeading", { kid: credential.key_id })}</h4>
      <Field label={t("protocols.eab.policyIdentifiers")} description={t("protocols.eab.policyIdentifiersHelp")}>
        {(control) => <Input {...control} value={identifiers} onChange={(e) => setIdentifiers(e.target.value)} autoComplete="off" />}
      </Field>
      <Field label={t("protocols.eab.policyMaxOrders")}>
        {(control) => <Input {...control} type="number" min={0} value={maxOrders} onChange={(e) => setMaxOrders(e.target.value)} />}
      </Field>
      <Field label={t("protocols.eab.policyNotAfter")}>
        {(control) => <Input {...control} type="datetime-local" value={notAfter} onChange={(e) => setNotAfter(e.target.value)} />}
      </Field>
      <Field label={t("protocols.eab.policyProfile")}>
        {(control) => <Input {...control} value={profile} onChange={(e) => setProfile(e.target.value)} autoComplete="off" />}
      </Field>
      <div className="flex gap-2">
        <Button type="submit" size="sm" disabled={busy}>
          {t("protocols.eab.policySubmit")}
        </Button>
        <Button type="button" size="sm" variant="outline" onClick={onCancel} disabled={busy}>
          {t("protocols.eab.cancel")}
        </Button>
      </div>
    </form>
  );
}
