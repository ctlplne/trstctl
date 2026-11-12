// SPDX-License-Identifier: BUSL-1.1

import { useCallback, useEffect, useState, type FormEvent } from "react";

import { Button } from "@/components/ui/button";
import { Field } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { translateNow } from "@/i18n/I18nProvider";
import { ProviderApiError, ProviderAuthError, providerApi, type ProviderBillingCompanies as BillingView } from "@/lib/providerApi";

/** MSP-2: the selected customer's company in every configured billing
 * system. A customer's closed, signed usage periods go only to the company
 * its own mapping names; one company in one system belongs to one customer,
 * which the plane enforces. */
export function ProviderBillingCompanies({ customerId, canWrite, onAuthError }: { customerId: string; canWrite: boolean; onAuthError: () => void }) {
  const [view, setView] = useState<BillingView | null>(null);
  const [drafts, setDrafts] = useState<Record<string, string>>({});
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const failed = useCallback(
    (err: unknown) => {
      if (err instanceof ProviderAuthError) {
        onAuthError();
        return;
      }
      if (err instanceof ProviderApiError && err.status === 409) {
        setError(translateNow("provider.billingSync.conflict"));
        return;
      }
      setError(err instanceof Error ? err.message : String(err));
    },
    [onAuthError],
  );

  const load = useCallback(
    async (id: string) => {
      setView(null);
      setError(null);
      if (!id) return;
      try {
        const out = await providerApi.billingCompanies(id);
        setView(out);
        setDrafts(Object.fromEntries(out.companies.map((company) => [company.target_id, company.external_company_id])));
      } catch (err) {
        failed(err);
      }
    },
    [failed],
  );

  useEffect(() => {
    setNotice(null);
    void load(customerId);
  }, [customerId, load]);

  async function save(event: FormEvent<HTMLFormElement>, target: string) {
    event.preventDefault();
    const company = (drafts[target] ?? "").trim();
    if (!company) return;
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      await providerApi.setBillingCompany(customerId, target, company);
      setNotice(translateNow("provider.billingSync.saved", { target }));
      await load(customerId);
    } catch (err) {
      failed(err);
    } finally {
      setBusy(false);
    }
  }

  async function clear(target: string) {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      await providerApi.clearBillingCompany(customerId, target);
      setNotice(translateNow("provider.billingSync.removed", { target }));
      await load(customerId);
    } catch (err) {
      failed(err);
    } finally {
      setBusy(false);
    }
  }

  const writable = customerId !== "" && canWrite;
  return (
    <div className="mt-4 grid gap-2 rounded-md border border-border/60 p-4" aria-labelledby="provider-billing-sync-title">
      <h3 id="provider-billing-sync-title" className="text-sm font-semibold">
        {translateNow("provider.billingSync.title")}
      </h3>
      <p className="text-caption text-muted-foreground">{translateNow("provider.billingSync.description")}</p>
      {error ? (
        <p className="mt-3 text-caption text-status-danger" role="alert">
          {error}
        </p>
      ) : null}
      {notice ? (
        <p className="mt-3 text-caption text-status-success" role="status">
          {notice}
        </p>
      ) : null}
      {view && view.targets.length === 0 ? <p className="mt-3 text-sm text-muted-foreground">{translateNow("provider.billingSync.noTargets")}</p> : null}
      {view && view.targets.length > 0 ? (
        <ul className="mt-3 grid gap-3" aria-label={translateNow("provider.billingSync.targetsLabel")}>
          {view.targets.map((target) => {
            const mapped = view.companies.find((company) => company.target_id === target.id);
            return (
              <li key={target.id} className="rounded-md border border-border/60 p-3">
                <div className="flex flex-wrap items-baseline gap-2">
                  <span className="font-medium">{target.name || target.id}</span>
                  <span className="font-mono text-caption text-muted-foreground">{target.id}</span>
                  <span className="text-caption text-muted-foreground">{translateNow("provider.billingSync.cadence", { cadence: target.cadence })}</span>
                </div>
                <p className="mt-1 text-sm">
                  {mapped
                    ? translateNow("provider.billingSync.mapped", { company: mapped.external_company_id })
                    : translateNow("provider.billingSync.notMapped")}
                </p>
                {writable ? (
                  <form className="mt-2 flex flex-wrap items-end gap-2" onSubmit={(event) => void save(event, target.id)}>
                    <Field label={translateNow("provider.billingSync.companyLabel", { target: target.name || target.id })}>
                      {(control) => (
                        <Input
                          {...control}
                          className="font-mono text-xs"
                          maxLength={128}
                          value={drafts[target.id] ?? ""}
                          onChange={(event) => setDrafts((current) => ({ ...current, [target.id]: event.target.value }))}
                        />
                      )}
                    </Field>
                    <Button type="submit" disabled={busy || !(drafts[target.id] ?? "").trim()}>
                      {translateNow("provider.billingSync.save")}
                    </Button>
                    {mapped ? (
                      <Button type="button" variant="outline" disabled={busy} onClick={() => void clear(target.id)}>
                        {translateNow("provider.billingSync.remove")}
                      </Button>
                    ) : null}
                  </form>
                ) : null}
              </li>
            );
          })}
        </ul>
      ) : null}
    </div>
  );
}
