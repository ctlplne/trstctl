// SPDX-License-Identifier: BUSL-1.1

import { useCallback, useEffect, useState, type FormEvent } from "react";

import { Button } from "@/components/ui/button";
import { Field } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { translateNow } from "@/i18n/I18nProvider";
import {
  ProviderApiError,
  ProviderAuthError,
  providerApi,
  type ProviderBillingCompanies as BillingView,
  type ProviderBillingSyncPush,
  type ProviderPSATicket,
} from "@/lib/providerApi";

/** MSP-2: the selected customer's company in every configured billing
 * system. A customer's closed, signed usage periods go only to the company
 * its own mapping names; one company in one system belongs to one customer,
 * which the plane enforces. */
export function ProviderBillingCompanies({ customerId, canWrite, onAuthError }: { customerId: string; canWrite: boolean; onAuthError: () => void }) {
  const [view, setView] = useState<BillingView | null>(null);
  const [pushes, setPushes] = useState<ProviderBillingSyncPush[]>([]);
  const [tickets, setTickets] = useState<ProviderPSATicket[]>([]);
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
      setPushes([]);
      setTickets([]);
      setError(null);
      if (!id) return;
      try {
        const [out, history] = await Promise.all([providerApi.billingCompanies(id), providerApi.billingSyncPushes(id)]);
        setView(out);
        setPushes(history.pushes ?? []);
        if (out.targets.some((target) => target.tickets)) {
          const opened = await providerApi.psaTickets(id);
          setTickets(opened.tickets ?? []);
        }
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
                  <span className="text-caption text-muted-foreground">{targetTypeLabel(target.type)}</span>
                  <span className="text-caption text-muted-foreground">{translateNow("provider.billingSync.cadence", { cadence: target.cadence })}</span>
                </div>
                <p className="mt-1 text-sm">
                  {mapped
                    ? translateNow("provider.billingSync.mapped", { company: mapped.external_company_id })
                    : translateNow("provider.billingSync.notMapped")}
                </p>
                {writable ? (
                  <form className="mt-2 flex flex-wrap items-end gap-2" onSubmit={(event) => void save(event, target.id)}>
                    <Field
                      label={translateNow("provider.billingSync.companyLabel", { target: target.name || target.id })}
                      description={target.type === "connectwise" ? translateNow("provider.billingSync.connectwiseCompanyHint") : undefined}
                    >
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
      {view && view.targets.length > 0 ? (
        <div className="overflow-x-auto">
          <table className="w-full text-caption">
            <caption className="py-1 text-left font-medium">{translateNow("provider.billingSync.historyCaption")}</caption>
            <thead>
              <tr className="text-left text-muted-foreground">
                <th className="py-1">{translateNow("provider.billingSync.historyTarget")}</th>
                <th className="py-1">{translateNow("provider.billingSync.historyPeriod")}</th>
                <th className="py-1">{translateNow("provider.billingSync.historyStatus")}</th>
                <th className="py-1">{translateNow("provider.billingSync.historyDetail")}</th>
              </tr>
            </thead>
            <tbody>
              {pushes.length === 0 ? (
                <tr>
                  <td colSpan={4} className="py-1 text-muted-foreground">
                    {translateNow("provider.billingSync.historyEmpty")}
                  </td>
                </tr>
              ) : (
                pushes.map((push) => (
                  <tr key={`${push.target_id}:${push.period_start}`} className="border-t border-border/60">
                    <td className="py-1 font-mono">{push.target_id}</td>
                    <td className="py-1 tabular-nums">
                      {push.period_start.slice(0, 10)} – {push.period_end.slice(0, 10)}
                    </td>
                    <td className={push.status === "delivered" ? "py-1 text-status-success" : push.status === "queued" ? "py-1" : "py-1 text-status-warning"}>
                      {translateNow(`provider.billingSync.status.${push.status}` as "provider.billingSync.status.queued")}
                    </td>
                    <td className="py-1 text-muted-foreground">
                      {push.status === "held" || push.status === "failed" || push.reason
                        ? push.reason
                        : push.external_company_id
                          ? translateNow("provider.billingSync.historyCompany", { company: push.external_company_id })
                          : ""}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      ) : null}
      {view && view.targets.some((target) => target.tickets) ? (
        <div className="overflow-x-auto">
          <table className="w-full text-caption">
            <caption className="py-1 text-left font-medium">{translateNow("provider.psaTickets.caption")}</caption>
            <thead>
              <tr className="text-left text-muted-foreground">
                <th className="py-1">{translateNow("provider.psaTickets.alert")}</th>
                <th className="py-1">{translateNow("provider.psaTickets.subject")}</th>
                <th className="py-1">{translateNow("provider.psaTickets.status")}</th>
                <th className="py-1">{translateNow("provider.psaTickets.ticket")}</th>
                <th className="py-1">{translateNow("provider.psaTickets.detail")}</th>
              </tr>
            </thead>
            <tbody>
              {tickets.length === 0 ? (
                <tr>
                  <td colSpan={5} className="py-1 text-muted-foreground">
                    {translateNow("provider.psaTickets.empty")}
                  </td>
                </tr>
              ) : (
                tickets.map((ticket) => (
                  <tr key={`${ticket.target_id}:${ticket.alert_kind}:${ticket.subject}`} className="border-t border-border/60">
                    <td className="py-1">{alertKindLabel(ticket.alert_kind)}</td>
                    <td className="max-w-xs truncate py-1 font-mono" title={ticket.subject}>
                      {ticket.subject}
                    </td>
                    <td className={ticket.status === "failed" ? "py-1 text-status-warning" : ticket.status === "closed" ? "py-1 text-status-success" : "py-1"}>
                      {translateNow(`provider.psaTickets.status.${ticket.status}` as "provider.psaTickets.status.open")}
                    </td>
                    <td className="py-1 font-mono">
                      {ticket.external_ticket_id
                        ? translateNow("provider.psaTickets.ticketRef", { ticket: ticket.external_ticket_id, company: ticket.external_company_id })
                        : ""}
                    </td>
                    <td className="py-1 text-muted-foreground">{ticket.reason || translateNow("provider.psaTickets.notes", { count: ticket.notes })}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      ) : null}
    </div>
  );
}

// alertKindLabel names the alert a ticket follows (MSP-3).
function alertKindLabel(kind: string): string {
  switch (kind) {
    case "certificate.expiry":
      return translateNow("provider.psaTickets.kind.expiry");
    case "identity.renewal_failed":
      return translateNow("provider.psaTickets.kind.renewal");
    case "revocation.health":
      return translateNow("provider.psaTickets.kind.revocation");
    case "credential.drift":
      return translateNow("provider.psaTickets.kind.drift");
    default:
      return kind;
  }
}

// targetTypeLabel names how a target receives a customer's periods (MSP-3).
function targetTypeLabel(type: string): string {
  switch (type) {
    case "connectwise":
      return translateNow("provider.billingSync.type.connectwise");
    case "json":
      return translateNow("provider.billingSync.type.json");
    default:
      return type;
  }
}
