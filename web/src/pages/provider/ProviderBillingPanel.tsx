// SPDX-License-Identifier: MPL-2.0

import { useEffect, useState, type FormEvent } from "react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { translateNow } from "@/i18n/I18nProvider";
import { ProviderAuthError, providerApi, type ProviderEvidenceVerification, type ProviderTenant, type ProviderUsageEvidence } from "@/lib/providerApi";

function defaultBillingPeriod(): { start: string; end: string } {
  const now = new Date();
  const end = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1));
  const start = new Date(Date.UTC(end.getUTCFullYear(), end.getUTCMonth() - 1, 1));
  return { start: start.toISOString().slice(0, 10), end: end.toISOString().slice(0, 10) };
}

function asRFC3339(date: string): string {
  return `${date}T00:00:00Z`;
}

type VerificationState = ProviderEvidenceVerification | null;

export function ProviderBillingPanel({ tenants, onAuthError }: { tenants: ProviderTenant[]; onAuthError: () => void }) {
  const defaults = defaultBillingPeriod();
  const [customerId, setCustomerId] = useState("");
  const [periodStart, setPeriodStart] = useState(defaults.start);
  const [periodEnd, setPeriodEnd] = useState(defaults.end);
  const [document, setDocument] = useState<ProviderUsageEvidence | null>(null);
  const [verification, setVerification] = useState<VerificationState>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!customerId && tenants.length > 0) setCustomerId(tenants[0].id);
    if (customerId && !tenants.some((tenant) => tenant.id === customerId)) setCustomerId(tenants[0]?.id ?? "");
  }, [customerId, tenants]);

  async function pull(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!customerId || !periodStart || !periodEnd) return;
    setLoading(true);
    setError(null);
    setDocument(null);
    setVerification(null);
    try {
      const evidence = await providerApi.usageEvidence(customerId, asRFC3339(periodStart), asRFC3339(periodEnd));
      setDocument(evidence);
      if (evidence.signature?.jws) {
        setVerification(await providerApi.verifyUsageEvidence(evidence));
      } else {
        setVerification({ verified: false });
      }
    } catch (reason) {
      if (reason instanceof ProviderAuthError) {
        onAuthError();
        return;
      }
      setError(reason instanceof Error ? reason.message : String(reason));
    } finally {
      setLoading(false);
    }
  }

  async function download(format: "json" | "csv") {
    if (!customerId || !periodStart || !periodEnd) return;
    setError(null);
    try {
      await providerApi.downloadUsageEvidence(customerId, asRFC3339(periodStart), asRFC3339(periodEnd), format);
    } catch (reason) {
      if (reason instanceof ProviderAuthError) {
        onAuthError();
        return;
      }
      setError(reason instanceof Error ? reason.message : String(reason));
    }
  }

  const signatureLabel = document?.signature?.jws
    ? verification?.verified
      ? translateNow("source.provider.billing.signature.verified.aud590012")
      : translateNow("source.provider.billing.signature.failed.aud590013")
    : translateNow("source.provider.billing.signature.unsigned.aud590014");

  return (
    <section className="mt-6" aria-labelledby="provider-billing-heading">
      <h2 id="provider-billing-heading" className="text-title font-semibold">
        {translateNow("source.provider.billing.title.aud590001")}
      </h2>
      <p className="mt-1 max-w-3xl text-caption text-muted-foreground">{translateNow("source.provider.billing.intro.aud590002")}</p>
      <form className="mt-3 flex flex-wrap items-end gap-3" onSubmit={(event) => void pull(event)}>
        <label className="grid gap-1">
          <span className="text-caption font-medium">{translateNow("source.provider.billing.customer.aud590003")}</span>
          <Select
            className="min-w-52"
            aria-label={translateNow("source.provider.billing.customer.aud590003")}
            value={customerId}
            onChange={(event) => setCustomerId(event.target.value)}
          >
            <option value="">—</option>
            {tenants.map((tenant) => (
              <option key={tenant.id} value={tenant.id}>
                {tenant.name} · {tenant.slug}
              </option>
            ))}
          </Select>
        </label>
        <label className="grid gap-1">
          <span className="text-caption font-medium">{translateNow("source.provider.billing.start.aud590004")}</span>
          <Input
            type="date"
            aria-label={translateNow("source.provider.billing.start.aud590004")}
            value={periodStart}
            onChange={(event) => setPeriodStart(event.target.value)}
          />
        </label>
        <label className="grid gap-1">
          <span className="text-caption font-medium">{translateNow("source.provider.billing.end.aud590005")}</span>
          <Input
            type="date"
            aria-label={translateNow("source.provider.billing.end.aud590005")}
            value={periodEnd}
            onChange={(event) => setPeriodEnd(event.target.value)}
          />
        </label>
        <Button type="submit" disabled={loading || !customerId || !periodStart || !periodEnd}>
          {translateNow(loading ? "source.provider.billing.loading.aud590007" : "source.provider.billing.pull.aud590006")}
        </Button>
      </form>

      {error ? (
        <p className="mt-3 text-caption text-status-danger" role="alert">
          {error}
        </p>
      ) : null}
      {document ? (
        <div className="mt-4 grid gap-3 rounded-md border border-border/60 p-4">
          <div className="flex flex-wrap items-center gap-2">
            <span className={document.signable ? "text-status-success" : "text-status-warning"}>
              {translateNow(document.signable ? "source.provider.billing.billable.aud590008" : "source.provider.billing.notbillable.aud590009")}
            </span>
            <span className={verification?.verified ? "text-status-success" : "text-status-warning"}>{signatureLabel}</span>
          </div>
          <p className="text-caption text-muted-foreground">{document.reason}</p>
          {(document.lines ?? []).length > 0 ? (
            <div className="overflow-x-auto">
              <table className="w-full text-caption">
                <thead>
                  <tr className="text-left text-muted-foreground">
                    <th className="py-1">{translateNow("source.provider.billing.meter.aud590015")}</th>
                    <th className="py-1">{translateNow("source.provider.billing.kind.aud590016")}</th>
                    <th className="py-1 text-right">{translateNow("source.provider.billing.value.aud590017")}</th>
                  </tr>
                </thead>
                <tbody>
                  {(document.lines ?? []).map((line) => (
                    <tr key={`${line.meter}:${line.kind}`} className="border-t border-border/60">
                      <td className="py-1 font-mono">{line.meter}</td>
                      <td className="py-1">{line.kind}</td>
                      <td className="py-1 text-right tabular-nums">{line.value}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <p className="text-caption text-muted-foreground">{translateNow("source.provider.billing.empty.aud590018")}</p>
          )}
          {(document.reconciliation ?? []).map((line) => (
            <p key={line.meter ?? "primary"} className="text-caption text-muted-foreground">
              {line.checked && line.matches
                ? translateNow("source.provider.billing.reconciled.aud590019", {
                    meter: line.meter ?? "",
                    events: String(line.event_history ?? 0),
                  })
                : translateNow("source.provider.billing.unreconciled.aud590020", { meter: line.meter ?? "" })}
            </p>
          ))}
          <p className="break-all text-caption text-muted-foreground">
            {translateNow("source.provider.billing.digest.aud590011")}: <code className="font-mono">{document.digest}</code>
          </p>
          <div className="flex flex-wrap gap-2">
            <Button type="button" variant="outline" onClick={() => void download("json")}>
              {translateNow("source.provider.billing.download.json.aud590010")}
            </Button>
            <Button type="button" variant="outline" onClick={() => void download("csv")}>
              {translateNow("source.provider.billing.download.csv.aud590021")}
            </Button>
          </div>
        </div>
      ) : null}
    </section>
  );
}
