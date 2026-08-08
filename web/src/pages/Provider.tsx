// SPDX-License-Identifier: MPL-2.0

import { useCallback, useEffect, useState } from "react";
import { translateNow } from "@/i18n/I18nProvider";
import type { MessageKey } from "@/i18n/messages";
import { formatDateTime } from "@/i18n/format";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  providerApi,
  providerToken,
  setProviderToken,
  clearProviderToken,
  ProviderAuthError,
  type ProviderTenant,
  type ProviderQuota,
  type ProviderBrand,
} from "@/lib/providerApi";

/**
 * The provider console (epic L3).
 *
 * A separate plane from the tenant console: its operator is the provider's own
 * staff, authenticated by the provider IdP (L1), so it lives at its own route
 * and carries an operator bearer rather than a tenant session. This is the
 * surface that was entirely missing — the /provider/v1 API existed with no web
 * client, so a licensed provider could provision and suspend customers only by
 * hand-crafting HTTP.
 *
 * It leads with the customer LIST because that is the provider's home question
 * ("who are my customers and what state are they in"), and every mutation —
 * suspend, offboard — is a confirmed, irreversible-looking action, because on
 * this plane one click changes a whole customer's world.
 */
export function Provider() {
  const [authed, setAuthed] = useState<boolean>(() => providerToken() !== null);

  if (!authed) {
    return <ProviderLogin onAuthed={() => setAuthed(true)} />;
  }
  return <ProviderConsole onSignOut={() => setAuthed(false)} />;
}

function ProviderLogin({ onAuthed }: { onAuthed: () => void }) {
  const [token, setToken] = useState("");
  return (
    <main className="mx-auto max-w-lg p-comfortable">
      <h1 className="text-headline font-semibold">{translateNow("source.provider.console.l3prov0001")}</h1>
      <p className="mt-2 text-caption text-muted-foreground">{translateNow("source.provider.login.intro.l3prov0002")}</p>
      <form
        className="mt-4 grid gap-3"
        onSubmit={(e) => {
          e.preventDefault();
          if (token.trim()) {
            setProviderToken(token.trim());
            onAuthed();
          }
        }}
      >
        <label className="grid gap-1">
          <span className="text-caption font-medium">{translateNow("source.provider.token.l3prov0003")}</span>
          <Input
            type="password"
            value={token}
            onChange={(e) => setToken(e.target.value)}
            autoComplete="off"
            aria-label={translateNow("source.provider.token.l3prov0003")}
          />
        </label>
        <Button type="submit" disabled={!token.trim()}>
          {translateNow("source.provider.signin.l3prov0004")}
        </Button>
      </form>
    </main>
  );
}

// numberOrUndefined turns a quota field's edit string into the value the plane
// stores: a blank field is UNLIMITED (undefined/omitted), never zero. A limit
// of zero would mean "may create nothing", which is a real but very different
// instruction from "no cap", and conflating them by treating blank as 0 would
// silently lock a customer out.
function editValue(v?: number): string {
  return v === undefined || v === null ? "" : String(v);
}
function numberOrUndefined(s: string): number | undefined {
  const trimmed = s.trim();
  if (trimmed === "") return undefined;
  const n = Number(trimmed);
  return Number.isFinite(n) && n >= 0 ? n : undefined;
}

function QuotaEditor({
  tenantId,
  initial,
  onSaved,
  onAuthError,
}: {
  tenantId: string;
  initial: ProviderQuota;
  onSaved: (saved: ProviderQuota) => void;
  onAuthError: () => void;
}) {
  const [agents, setAgents] = useState(editValue(initial.max_agents));
  const [certs, setCerts] = useState(editValue(initial.max_certificates_stored));
  const [secrets, setSecrets] = useState(editValue(initial.max_secrets_stored));
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);

  const field = (labelKey: MessageKey, value: string, setValue: (v: string) => void) => (
    <label className="grid gap-1">
      <span className="font-medium text-muted-foreground">{translateNow(labelKey)}</span>
      <Input
        type="number"
        min={0}
        value={value}
        onChange={(e) => setValue(e.target.value)}
        placeholder={translateNow("source.provider.quota.unlimited.l3prov0027")}
        aria-label={translateNow(labelKey)}
        className="w-28"
      />
    </label>
  );

  const save = async () => {
    setSaving(true);
    setSaveError(null);
    const next: ProviderQuota = {
      tenant_id: tenantId,
      max_agents: numberOrUndefined(agents),
      max_certificates_stored: numberOrUndefined(certs),
      max_secrets_stored: numberOrUndefined(secrets),
    };
    try {
      await providerApi.setQuota(tenantId, next);
      onSaved(await providerApi.getQuota(tenantId));
    } catch (err) {
      if (err instanceof ProviderAuthError) {
        onAuthError();
        return;
      }
      setSaveError(err instanceof Error ? err.message : String(err));
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="grid gap-2">
      <p className="text-muted-foreground">{translateNow("source.provider.quota.edit.hint.l3prov0028")}</p>
      <div className="flex flex-wrap items-end gap-3">
        {field("source.provider.quota.agents.l3prov0024", agents, setAgents)}
        {field("source.provider.quota.certs.l3prov0025", certs, setCerts)}
        {field("source.provider.quota.secrets.l3prov0026", secrets, setSecrets)}
        <Button type="button" disabled={saving} onClick={() => void save()}>
          {translateNow("source.provider.quota.save.l3prov0029")}
        </Button>
      </div>
      {saveError ? <p className="text-status-danger">{saveError}</p> : null}
    </div>
  );
}

type QuotaViewState =
  | { id: string; state: "loading" }
  | { id: string; state: "error" }
  | { id: string; state: "ok"; data: ProviderQuota };

function BrandEditor({
  tenantId,
  onSaved,
  onAuthError,
}: {
  tenantId: string;
  onSaved: () => void;
  onAuthError: () => void;
}) {
  const [productName, setProductName] = useState("");
  const [customDomain, setCustomDomain] = useState("");
  const [loginMessage, setLoginMessage] = useState("");
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);

  const field = (labelKey: MessageKey, value: string, setValue: (v: string) => void) => (
    <label className="grid gap-1">
      <span className="font-medium text-muted-foreground">{translateNow(labelKey)}</span>
      <Input value={value} onChange={(e) => setValue(e.target.value)} aria-label={translateNow(labelKey)} className="w-56" />
    </label>
  );

  const save = async () => {
    setSaving(true);
    setSaveError(null);
    const brand: ProviderBrand = {
      product_name: productName.trim() || undefined,
      custom_domain: customDomain.trim() || undefined,
      login_message: loginMessage.trim() || undefined,
    };
    try {
      await providerApi.setBrand(tenantId, brand);
      onSaved();
    } catch (err) {
      if (err instanceof ProviderAuthError) {
        onAuthError();
        return;
      }
      // A custom-domain collision (another customer already claims the host)
      // surfaces here as the store's refusal — shown, not swallowed.
      setSaveError(err instanceof Error ? err.message : String(err));
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="grid gap-2">
      <p className="text-muted-foreground">{translateNow("source.provider.brand.hint.l3prov0031")}</p>
      <div className="flex flex-wrap items-end gap-3">
        {field("source.provider.brand.product.l3prov0032", productName, setProductName)}
        {field("source.provider.brand.domain.l3prov0033", customDomain, setCustomDomain)}
        {field("source.provider.brand.message.l3prov0034", loginMessage, setLoginMessage)}
        <Button type="button" disabled={saving} onClick={() => void save()}>
          {translateNow("source.provider.brand.save.l3prov0035")}
        </Button>
      </div>
      {saveError ? <p className="text-status-danger">{saveError}</p> : null}
    </div>
  );
}

function ProviderConsole({ onSignOut }: { onSignOut: () => void }) {
  const [tenants, setTenants] = useState<ProviderTenant[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [slug, setSlug] = useState("");
  const [name, setName] = useState("");
  // The customer whose quota is expanded, as a discriminated union so the
  // render narrows cleanly between loading, a load failure, and a value.
  const [quotaView, setQuotaView] = useState<QuotaViewState | null>(null);
  // The customer whose brand editor is expanded. Brand has no read route here,
  // so it opens to an empty form the operator fills — a write surface, not a
  // round-trip.
  const [brandFor, setBrandFor] = useState<string | null>(null);

  const viewQuota = useCallback(
    async (id: string) => {
      if (quotaView?.id === id) {
        setQuotaView(null); // toggle closed
        return;
      }
      setQuotaView({ id, state: "loading" });
      try {
        setQuotaView({ id, state: "ok", data: await providerApi.getQuota(id) });
      } catch (err) {
        if (err instanceof ProviderAuthError) {
          clearProviderToken();
          onSignOut();
          return;
        }
        setQuotaView({ id, state: "error" });
      }
    },
    [quotaView, onSignOut],
  );

  const load = useCallback(async () => {
    setError(null);
    try {
      setTenants(await providerApi.listTenants());
    } catch (err) {
      if (err instanceof ProviderAuthError) {
        // The token expired or was refused. Drop it and send the operator back
        // to the gate rather than showing a red error over a stale session.
        clearProviderToken();
        onSignOut();
        return;
      }
      setError(err instanceof Error ? err.message : String(err));
    }
  }, [onSignOut]);

  useEffect(() => {
    void load();
  }, [load]);

  const act = useCallback(
    async (fn: () => Promise<void>) => {
      setBusy(true);
      setError(null);
      try {
        await fn();
        await load();
      } catch (err) {
        if (err instanceof ProviderAuthError) {
          clearProviderToken();
          onSignOut();
          return;
        }
        setError(err instanceof Error ? err.message : String(err));
      } finally {
        setBusy(false);
      }
    },
    [load, onSignOut],
  );

  const statusClass = (status: ProviderTenant["status"]) =>
    status === "active"
      ? "text-status-success"
      : status === "suspended"
        ? "text-status-warning"
        : "text-status-danger";

  return (
    <main className="mx-auto max-w-5xl p-comfortable">
      <header className="flex items-center justify-between">
        <div>
          <h1 className="text-headline font-semibold">{translateNow("source.provider.console.l3prov0001")}</h1>
          <p className="mt-1 text-caption text-muted-foreground">{translateNow("source.provider.customers.intro.l3prov0005")}</p>
        </div>
        <Button
          type="button"
          variant="outline"
          onClick={() => {
            clearProviderToken();
            onSignOut();
          }}
        >
          {translateNow("source.provider.signout.l3prov0006")}
        </Button>
      </header>

      {error ? <p className="mt-3 text-caption text-status-danger">{error}</p> : null}

      <section className="mt-5">
        <h2 className="text-title font-semibold">{translateNow("source.provider.provision.l3prov0007")}</h2>
        <form
          className="mt-2 flex flex-wrap items-end gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            if (slug.trim() && name.trim()) {
              void act(async () => {
                await providerApi.provisionTenant({ slug: slug.trim(), name: name.trim() });
                setSlug("");
                setName("");
              });
            }
          }}
        >
          <label className="grid gap-1">
            <span className="text-caption font-medium">{translateNow("source.provider.slug.l3prov0008")}</span>
            <Input value={slug} onChange={(e) => setSlug(e.target.value)} aria-label={translateNow("source.provider.slug.l3prov0008")} />
          </label>
          <label className="grid gap-1">
            <span className="text-caption font-medium">{translateNow("source.provider.name.l3prov0009")}</span>
            <Input value={name} onChange={(e) => setName(e.target.value)} aria-label={translateNow("source.provider.name.l3prov0009")} />
          </label>
          <Button type="submit" disabled={busy || !slug.trim() || !name.trim()}>
            {translateNow("source.provider.provision.action.l3prov0010")}
          </Button>
        </form>
      </section>

      <section className="mt-6">
        <h2 className="text-title font-semibold">{translateNow("source.provider.customers.l3prov0011")}</h2>
        {!tenants ? (
          <p className="mt-2 text-caption text-muted-foreground">{translateNow("source.loading.4f9d1e0e3a")}</p>
        ) : tenants.length === 0 ? (
          <p className="mt-2 text-caption text-muted-foreground">{translateNow("source.provider.none.l3prov0012")}</p>
        ) : (
          <div className="mt-2 overflow-x-auto">
            <table className="w-full text-caption">
              <thead>
                <tr className="text-left text-muted-foreground">
                  <th className="pr-4 font-medium">{translateNow("source.provider.col.name.l3prov0013")}</th>
                  <th className="pr-4 font-medium">{translateNow("source.provider.col.slug.l3prov0014")}</th>
                  <th className="pr-4 font-medium">{translateNow("source.provider.col.status.l3prov0015")}</th>
                  <th className="pr-4 font-medium">{translateNow("source.provider.col.created.l3prov0016")}</th>
                  <th className="pr-4 font-medium">{translateNow("source.provider.col.actions.l3prov0017")}</th>
                </tr>
              </thead>
              <tbody>
                {tenants.map((tenant) => (
                  <tr key={tenant.id} className="border-t border-border/60">
                    <td className="py-1 pr-4">{tenant.name}</td>
                    <td className="py-1 pr-4 font-mono text-xs">{tenant.slug}</td>
                    <td className={`py-1 pr-4 ${statusClass(tenant.status)}`}>{tenant.status}</td>
                    <td className="py-1 pr-4 text-xs text-muted-foreground">{formatDateTime(tenant.created_at)}</td>
                    <td className="py-1 pr-4">
                      {tenant.status === "active" ? (
                        <Button
                          type="button"
                          variant="outline"
                          disabled={busy}
                          onClick={() => {
                            if (window.confirm(translateNow("source.provider.suspend.confirm.l3prov0018"))) {
                              void act(() => providerApi.suspendTenant(tenant.id));
                            }
                          }}
                        >
                          {translateNow("source.provider.suspend.l3prov0019")}
                        </Button>
                      ) : null}
                      {tenant.status !== "offboarded" ? (
                        <Button
                          type="button"
                          variant="outline"
                          className="ml-2"
                          disabled={busy}
                          onClick={() => {
                            if (window.confirm(translateNow("source.provider.offboard.confirm.l3prov0020"))) {
                              void act(() => providerApi.offboardTenant(tenant.id));
                            }
                          }}
                        >
                          {translateNow("source.provider.offboard.l3prov0021")}
                        </Button>
                      ) : null}
                      <Button
                        type="button"
                        variant="ghost"
                        className="ml-2"
                        onClick={() => void viewQuota(tenant.id)}
                      >
                        {translateNow("source.provider.quota.l3prov0022")}
                      </Button>
                      {tenant.status !== "offboarded" ? (
                        <Button
                          type="button"
                          variant="ghost"
                          className="ml-2"
                          onClick={() => setBrandFor((cur) => (cur === tenant.id ? null : tenant.id))}
                        >
                          {translateNow("source.provider.brand.l3prov0030")}
                        </Button>
                      ) : null}
                    </td>
                  </tr>
                ))
                  /* The quota panel renders as its own row beneath the
                     customer, so the table layout is unaffected. An UNSET limit
                     is shown as "unlimited", never zero — a missing cap is the
                     absence of a limit, not a limit of nothing. */
                  .flatMap((rowEl, i) => {
                    const tenant = tenants[i];
                    const extras = [rowEl];
                    if (quotaView?.id === tenant.id) {
                      extras.push(
                        <tr key={`${tenant.id}-quota`} className="bg-muted/30">
                          <td colSpan={5} className="px-4 py-2 text-xs">
                            {quotaView.state === "loading" ? (
                              translateNow("source.loading.4f9d1e0e3a")
                            ) : quotaView.state === "error" ? (
                              <span className="text-muted-foreground">{translateNow("source.provider.quota.none.l3prov0023")}</span>
                            ) : (
                              <QuotaEditor
                                key={tenant.id}
                                tenantId={tenant.id}
                                initial={quotaView.data}
                                onSaved={(saved) => setQuotaView({ id: tenant.id, state: "ok", data: saved })}
                                onAuthError={() => {
                                  clearProviderToken();
                                  onSignOut();
                                }}
                              />
                            )}
                          </td>
                        </tr>,
                      );
                    }
                    if (brandFor === tenant.id) {
                      extras.push(
                        <tr key={`${tenant.id}-brand`} className="bg-muted/30">
                          <td colSpan={5} className="px-4 py-2 text-xs">
                            <BrandEditor
                              tenantId={tenant.id}
                              onSaved={() => setBrandFor(null)}
                              onAuthError={() => {
                                clearProviderToken();
                                onSignOut();
                              }}
                            />
                          </td>
                        </tr>,
                      );
                    }
                    return extras;
                  })}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </main>
  );
}
