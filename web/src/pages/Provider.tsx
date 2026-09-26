// SPDX-License-Identifier: BUSL-1.1

import { useCallback, useEffect, useState, type ReactNode } from "react";
import { QueryClientProvider } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { translateNow } from "@/i18n/I18nProvider";
import type { MessageKey } from "@/i18n/messages";
import { formatDateTime } from "@/i18n/format";
import { Button } from "@/components/ui/button";
import { DataGrid } from "@/components/DataGrid";
import { Input } from "@/components/ui/input";
import { createAppQueryClient, useApiQuery, useQueryClient } from "@/lib/query";
import { ProviderAccessPanel } from "@/pages/provider/ProviderAccessPanel";
import { ProviderBillingPanel } from "@/pages/provider/ProviderBillingPanel";
import {
  providerApi,
  providerToken,
  setProviderToken,
  clearProviderToken,
  ProviderAuthError,
  type ProviderTenant,
  type ProviderQuota,
  type ProviderBrand,
  type ProviderDrillReport,
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
  // Keep only the generic recovery reason outside the discarded session cache.
  // Credentials, customer data and server rejection details never cross it.
  const [authRefused, setAuthRefused] = useState(false);
  const signIn = useCallback(() => {
    setAuthRefused(false);
    setAuthed(true);
  }, []);
  const signOut = useCallback((reason?: "authentication") => {
    setAuthRefused(reason === "authentication");
    setAuthed(false);
  }, []);
  const availability = useApiQuery(["provider", "availability"], providerApi.availability);

  if (availability.loading) {
    return <ProviderAvailabilityState detail={translateNow("source.provider.availability.checking.g26prov0001")} />;
  }
  if (availability.data !== true) {
    return (
      <ProviderAvailabilityState
        detail={
          availability.data === false
            ? translateNow("source.provider.availability.unattached.g26prov0003")
            : translateNow("source.provider.availability.unknown.g26prov0002")
        }
      />
    );
  }

  return (
    <ProviderSessionQueries key={authed ? "operator" : "signed-out"}>
      {authed ? <ProviderConsole onSignOut={signOut} /> : <ProviderLogin onAuthed={signIn} authRefused={authRefused} />}
    </ProviderSessionQueries>
  );
}

// The Provider plane has its own authentication boundary. A new login must not
// inherit a previous operator's customer roster or in-flight query results from
// the tenant shell's longer-lived cache. Public attachment checks stay outside.
function ProviderSessionQueries({ children }: { children: ReactNode }) {
  const [client] = useState(createAppQueryClient);
  useEffect(() => {
    const refresh = () => {
      if (document.visibilityState === "visible") {
        void client.invalidateQueries({ predicate: (query) => query.meta?.live === true }, { cancelRefetch: false });
      }
    };
    document.addEventListener("visibilitychange", refresh);
    return () => {
      document.removeEventListener("visibilitychange", refresh);
      client.clear();
    };
  }, [client]);
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>;
}

function ProviderAvailabilityState({ detail }: { detail: string }) {
  return (
    <main className="mx-auto grid max-w-lg gap-3 p-comfortable">
      <h1 className="text-headline font-semibold">{translateNow("source.provider.console.l3prov0001")}</h1>
      <p className="text-caption text-muted-foreground">{detail}</p>
      <Link className="text-caption font-medium text-link underline" to="/">
        {translateNow("source.provider.availability.tenantConsole.g26prov0004")}
      </Link>
    </main>
  );
}

function ProviderLogin({ onAuthed, authRefused }: { onAuthed: () => void; authRefused: boolean }) {
  const [token, setToken] = useState("");
  const methods = useApiQuery(["provider", "auth-methods"], providerApi.authMethods);
  const session = useApiQuery(["provider", "session"], providerApi.session);
  useEffect(() => {
    if (session.data) onAuthed();
  }, [session.data, onAuthed]);
  return (
    <main className="mx-auto max-w-lg p-comfortable">
      <h1 className="text-headline font-semibold">{translateNow("source.provider.console.l3prov0001")}</h1>
      <p className="mt-2 text-caption text-muted-foreground">{translateNow("source.provider.login.intro.l3prov0002")}</p>
      {authRefused ? (
        <p role="alert" className="mt-3 text-caption text-status-danger">
          {translateNow("source.provider.login.refused.f2280001")}
        </p>
      ) : null}
      {(methods.data ?? []).includes("saml") ? (
        <Button type="button" className="mt-4 w-full" onClick={() => window.location.assign("/provider/v1/auth/saml/login")}>
          {translateNow("source.provider.saml.signin.aud580020")}
        </Button>
      ) : null}
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

function QuotaSummary({ quota }: { quota: ProviderQuota }) {
  const fields: [MessageKey, number | undefined][] = [
    ["source.provider.quota.agents.l3prov0024", quota.max_agents],
    ["source.provider.quota.certs.l3prov0025", quota.max_certificates_stored],
    ["source.provider.quota.secrets.l3prov0026", quota.max_secrets_stored],
  ];
  return (
    <dl className="grid gap-2 sm:grid-cols-3">
      {fields.map(([label, value]) => (
        <div key={label}>
          <dt className="text-muted-foreground">{translateNow(label)}</dt>
          <dd className="font-mono tabular-nums">{value ?? translateNow("source.provider.quota.unlimited.l3prov0027")}</dd>
        </div>
      ))}
    </dl>
  );
}

type QuotaViewState = { id: string; state: "loading" } | { id: string; state: "error" } | { id: string; state: "ok"; data: ProviderQuota };

function BrandEditor({ tenantId, onSaved, onAuthError }: { tenantId: string; onSaved: () => void; onAuthError: () => void }) {
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

function ProviderConsole({ onSignOut }: { onSignOut: (reason?: "authentication") => void }) {
  const queryClient = useQueryClient();
  const session = useApiQuery(["provider", "session"], providerApi.session, { retry: false, live: { intervalMs: 15_000 } });
  // Never infer grants from the role name or a previous successful operation.
  // Missing/unreadable authority keeps the identity but offers no controls.
  const authority = !session.error && session.data?.authority?.available ? session.data.authority : undefined;
  useEffect(() => {
    if (session.errorValue instanceof ProviderAuthError) {
      clearProviderToken();
      onSignOut("authentication");
    }
  }, [session.errorValue, onSignOut]);
  // A change in effective authority gets a separate read. A late response
  // for an old grant cannot repopulate the current customer or billing view.
  const customers = useApiQuery(["provider", "customers", session.data?.id, authority ?? null], providerApi.listTenants, {
    enabled: !!authority,
    retry: false,
    live: { intervalMs: 15_000 },
  });
  const activityQuery = useApiQuery(["provider", "activity", session.data?.id, authority ?? null], providerApi.listActivity, {
    enabled: !!authority,
    retry: false,
    live: { intervalMs: 15_000 },
  });
  const tenants = authority ? (customers.data?.filter((tenant) => authority.customers[tenant.id]) ?? null) : null;
  const activity = authority ? activityQuery.data : null;
  useEffect(() => {
    if (customers.errorValue instanceof ProviderAuthError || activityQuery.errorValue instanceof ProviderAuthError) {
      clearProviderToken();
      onSignOut("authentication");
    }
  }, [customers.errorValue, activityQuery.errorValue, onSignOut]);
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
  // The last isolation-drill result, or "running" while one is in flight. The
  // drill is deployment-wide, not per-customer, so it lives above the table.
  const [drill, setDrill] = useState<ProviderDrillReport | "running" | null>(null);

  const runDrill = useCallback(async () => {
    setDrill("running");
    setError(null);
    try {
      setDrill(await providerApi.runIsolationDrill());
      await queryClient.invalidateQueries({ queryKey: ["provider", "activity"] });
    } catch (err) {
      if (err instanceof ProviderAuthError) {
        clearProviderToken();
        onSignOut("authentication");
        return;
      }
      setDrill(null);
      setError(err instanceof Error ? err.message : String(err));
    }
  }, [onSignOut, queryClient]);

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
          onSignOut("authentication");
          return;
        }
        setQuotaView({ id, state: "error" });
      }
    },
    [quotaView, onSignOut],
  );

  const load = useCallback(async () => {
    await Promise.all([
      queryClient.invalidateQueries({ queryKey: ["provider", "customers"] }),
      queryClient.invalidateQueries({ queryKey: ["provider", "activity"] }),
    ]);
  }, [queryClient]);

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
          onSignOut("authentication");
          return;
        }
        setError(err instanceof Error ? err.message : String(err));
        // A rejected or interrupted response can still have retained an
        // offboarding request. Show the server's current state immediately.
        await load();
      } finally {
        setBusy(false);
        void queryClient.invalidateQueries({ queryKey: ["provider", "session"] });
      }
    },
    [load, onSignOut, queryClient],
  );

  const statusClass = (status: ProviderTenant["status"]) =>
    status === "active" ? "text-status-success" : status === "suspended" || status === "offboarding" ? "text-status-warning" : "text-status-danger";

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
            void providerApi
              .signOut()
              .catch(() => undefined)
              .finally(() => {
                clearProviderToken();
                onSignOut();
              });
          }}
        >
          {translateNow("source.provider.signout.l3prov0006")}
        </Button>
      </header>

      {error || customers.error || activityQuery.error ? (
        <p className="mt-3 text-caption text-status-danger">{error || customers.error || activityQuery.error}</p>
      ) : null}

      {session.loading ? (
        <p className="mt-3 text-caption text-muted-foreground">{translateNow("capabilities.loading")}</p>
      ) : !authority ? (
        <div className="mt-3 text-caption" role="status">
          <p>{translateNow("capabilities.readFailed.title")}</p>
          <Button type="button" variant="outline" onClick={session.refetch}>
            {translateNow("capabilities.retry")}
          </Button>
        </div>
      ) : null}
      {authority?.access_read ? (
        <ProviderAccessPanel
          canWrite={authority.access_write}
          onAuthError={() => {
            clearProviderToken();
            onSignOut("authentication");
          }}
        />
      ) : null}

      <ProviderBillingPanel
        tenants={tenants ?? []}
        onAuthError={() => {
          clearProviderToken();
          onSignOut("authentication");
        }}
      />

      {authority?.provision ? (
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
      ) : null}

      <section className="mt-6">
        <h2 className="text-title font-semibold">{translateNow("source.recent.activity.6cb44b5633")}</h2>
        {activity === null ? (
          <p className="mt-2 text-caption text-muted-foreground">{translateNow("source.loading.4f9d1e0e3a")}</p>
        ) : activity.length === 0 ? (
          <p className="mt-2 text-caption text-muted-foreground">{translateNow("dashboard.recentActivity.empty")}</p>
        ) : (
          <ol className="mt-2 divide-y divide-border/60 rounded-md border border-border/60">
            {activity.map((item) => (
              <li key={item.event_id} className="grid gap-1 px-3 py-2 text-xs sm:grid-cols-[1fr_auto]">
                <div>
                  <span className="font-mono font-medium">{item.type}</span>
                  <span className="ml-2 text-muted-foreground">{item.operator_email || item.subject || item.operator_id}</span>
                  {item.tenant_id ? <span className="ml-2 font-mono text-muted-foreground">{item.tenant_id}</span> : null}
                  {item.reason ? <span className="ml-2 text-muted-foreground">{item.reason}</span> : null}
                  {item.offboard_state === "pending" || item.offboard_state === "failed" || item.offboard_state === "completed" ? (
                    <p className="mt-1 text-caption">
                      {translateNow(
                        item.offboard_state === "completed"
                          ? "provider.offboard.completed"
                          : item.offboard_state === "failed"
                            ? "provider.offboard.failed"
                            : "provider.offboard.pending",
                      )}
                    </p>
                  ) : null}
                  {item.can_continue_offboard === true && item.offboard_state === "pending" && item.request_event_id && item.tenant_id ? (
                    <Button
                      type="button"
                      variant="destructive-outline"
                      loading={busy}
                      className="mt-2"
                      onClick={() => {
                        if (window.confirm(translateNow("provider.offboard.continueConfirm"))) {
                          void act(() => providerApi.offboardTenant(item.tenant_id!, item.request_event_id));
                        }
                      }}
                    >
                      {translateNow("provider.offboard.continue")}
                    </Button>
                  ) : null}
                </div>
                <div className="flex gap-2 text-muted-foreground">
                  <time dateTime={item.at}>{formatDateTime(item.at)}</time>
                  <span className="font-mono">#{item.sequence}</span>
                </div>
              </li>
            ))}
          </ol>
        )}
      </section>

      {authority?.isolation_drill ? (
        <section className="mt-6">
          <h2 className="text-title font-semibold">{translateNow("source.provider.drill.title.l3prov0036")}</h2>
          <p className="mt-1 text-caption text-muted-foreground">{translateNow("source.provider.drill.intro.l3prov0037")}</p>
          <div className="mt-2 flex items-center gap-3">
            <Button type="button" variant="outline" disabled={drill === "running"} onClick={() => void runDrill()}>
              {translateNow("source.provider.drill.run.l3prov0038")}
            </Button>
            {drill === "running" ? (
              <span className="text-caption text-muted-foreground">{translateNow("source.loading.4f9d1e0e3a")}</span>
            ) : drill ? (
              <span className={`text-caption ${drill.passed ? "text-status-success" : "text-status-danger"}`}>
                {translateNow(drill.passed ? "source.provider.drill.pass.l3prov0039" : "source.provider.drill.fail.l3prov0040")}
              </span>
            ) : null}
          </div>
          {drill && drill !== "running" && !drill.passed ? (
            <ul className="mt-2 list-disc pl-5 text-xs text-muted-foreground">
              {(drill.checks ?? [])
                .filter((c) => !c.passed)
                .map((c) => (
                  <li key={c.name}>
                    <span className="font-mono">{c.name}</span>: {c.detail}
                  </li>
                ))}
            </ul>
          ) : null}
        </section>
      ) : null}

      <section className="mt-6">
        <h2 className="text-title font-semibold">{translateNow("source.provider.customers.l3prov0011")}</h2>
        <DataGrid
          ariaLabel={translateNow("source.provider.customers.l3prov0011")}
          className="mt-2"
          rows={tenants ?? []}
          getRowId={(tenant) => tenant.id}
          state={customers.error ? "error" : !tenants ? "loading" : tenants.length === 0 ? "empty" : "ready"}
          stateMessage={customers.error || translateNow(authority?.provision ? "source.provider.none.l3prov0012" : "source.provider.access.none.aud580015")}
          columns={[
            { id: "name", header: translateNow("source.provider.col.name.l3prov0013"), cell: (tenant) => tenant.name },
            { id: "slug", header: translateNow("source.provider.col.slug.l3prov0014"), cell: (tenant) => tenant.slug },
            {
              id: "status",
              header: translateNow("source.provider.col.status.l3prov0015"),
              cell: (tenant) => (
                <div className="min-w-40 max-w-xs whitespace-normal">
                  <span className={statusClass(tenant.status)}>
                    {tenant.status === "offboarding"
                      ? translateNow("provider.offboard.pending")
                      : tenant.status === "offboard_failed"
                        ? translateNow("provider.offboard.failed")
                        : tenant.status}
                  </span>
                  {tenant.status === "offboarding" || tenant.status === "offboard_failed" ? (
                    <p className="mt-1 text-caption text-muted-foreground">
                      {translateNow(tenant.status === "offboarding" ? "provider.offboard.pendingHelp" : "provider.offboard.failedHelp")}
                    </p>
                  ) : null}
                </div>
              ),
            },
            { id: "created", header: translateNow("source.provider.col.created.l3prov0016"), cell: (tenant) => formatDateTime(tenant.created_at) },
            {
              id: "actions",
              header: translateNow("source.provider.col.actions.l3prov0017"),
              cell: (tenant) => (
                <div className="flex flex-wrap items-center gap-2">
                  {tenant.status === "active" && authority?.customers[tenant.id]?.suspend ? (
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
                  {tenant.status === "suspended" && authority?.customers[tenant.id]?.resume ? (
                    <Button
                      type="button"
                      size="sm"
                      variant="outline"
                      disabled={busy}
                      onClick={() => {
                        if (window.confirm(translateNow("source.provider.resume.confirm.qa1850001"))) {
                          void act(() => providerApi.resumeTenant(tenant.id));
                        }
                      }}
                    >
                      {translateNow("source.provider.resume.action.qa1850002")}
                    </Button>
                  ) : null}
                  {tenant.status !== "offboarded" && tenant.status !== "offboarding" && authority?.customers[tenant.id]?.offboard ? (
                    <Button
                      type="button"
                      variant="destructive-outline"
                      className="ml-2"
                      disabled={busy}
                      onClick={() => {
                        if (
                          window.confirm(
                            translateNow(
                              tenant.status === "offboard_failed" ? "provider.offboard.reviewConfirm" : "source.provider.offboard.confirm.l3prov0020",
                            ),
                          )
                        ) {
                          void act(() => providerApi.offboardTenant(tenant.id));
                        }
                      }}
                    >
                      {translateNow(tenant.status === "offboard_failed" ? "provider.offboard.review" : "source.provider.offboard.l3prov0021")}
                    </Button>
                  ) : null}
                  {authority?.customers[tenant.id]?.read_quota ? (
                    <Button type="button" variant="ghost" className="ml-2" onClick={() => void viewQuota(tenant.id)}>
                      {translateNow("source.provider.quota.l3prov0022")}
                    </Button>
                  ) : null}
                  {tenant.status !== "offboarded" && authority?.customers[tenant.id]?.write_brand ? (
                    <Button type="button" variant="ghost" className="ml-2" onClick={() => setBrandFor((cur) => (cur === tenant.id ? null : tenant.id))}>
                      {translateNow("source.provider.brand.l3prov0030")}
                    </Button>
                  ) : null}
                </div>
              ),
            },
          ]}
        />
        {quotaView && tenants?.some((tenant) => tenant.id === quotaView.id) && authority?.customers[quotaView.id]?.read_quota ? (
          <section className="mt-3 rounded-md border border-border p-4" aria-label={translateNow("source.provider.quota.l3prov0022")}>
            <h3 className="font-medium">{tenants.find((tenant) => tenant.id === quotaView.id)?.name}</h3>
            {quotaView.state === "loading" ? (
              translateNow("source.loading.4f9d1e0e3a")
            ) : quotaView.state === "error" ? (
              <span className="text-muted-foreground">{translateNow("source.provider.quota.none.l3prov0023")}</span>
            ) : !authority.customers[quotaView.id]?.write_quota ? (
              <QuotaSummary quota={quotaView.data} />
            ) : (
              <QuotaEditor
                key={quotaView.id}
                tenantId={quotaView.id}
                initial={quotaView.data}
                onSaved={(saved) => setQuotaView({ id: quotaView.id, state: "ok", data: saved })}
                onAuthError={() => {
                  clearProviderToken();
                  onSignOut("authentication");
                }}
              />
            )}
          </section>
        ) : null}
        {brandFor && tenants?.some((tenant) => tenant.id === brandFor) && authority?.customers[brandFor]?.write_brand ? (
          <section className="mt-3 rounded-md border border-border p-4" aria-label={translateNow("source.provider.brand.l3prov0030")}>
            <h3 className="font-medium">{tenants.find((tenant) => tenant.id === brandFor)?.name}</h3>
            <BrandEditor
              tenantId={brandFor}
              onSaved={() => setBrandFor(null)}
              onAuthError={() => {
                clearProviderToken();
                onSignOut("authentication");
              }}
            />
          </section>
        ) : null}
      </section>
    </main>
  );
}
