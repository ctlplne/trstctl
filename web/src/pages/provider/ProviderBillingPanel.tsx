// SPDX-License-Identifier: MPL-2.0

import { useEffect, useLayoutEffect, useRef, useState, type FormEvent } from "react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { translateNow } from "@/i18n/I18nProvider";
import {
  ProviderAuthError,
  providerApi,
  type ProviderEvidenceVerification,
  type ProviderTenant,
  type ProviderTenantSnapshot,
  type ProviderUsageEvidence,
} from "@/lib/providerApi";

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

function healthLabel(health: string): string {
  switch (health) {
    case "healthy":
      return translateNow("source.provider.health.healthy.aud600004");
    case "suspended":
      return translateNow("source.provider.health.suspended.aud600005");
    case "offboarded":
      return translateNow("source.provider.health.offboarded.aud600006");
    case "no_certificates":
      return translateNow("source.provider.health.noCertificates.aud600007");
    default:
      return translateNow("source.provider.health.unknown.aud600003");
  }
}

export function ProviderBillingPanel({ tenants, onAuthError }: { tenants: ProviderTenant[]; onAuthError: () => void }) {
  const defaults = defaultBillingPeriod();
  const [customerId, setCustomerId] = useState("");
  const [periodStart, setPeriodStart] = useState(defaults.start);
  const [periodEnd, setPeriodEnd] = useState(defaults.end);
  const [health, setHealth] = useState<ProviderTenantSnapshot | null>(null);
  const [healthError, setHealthError] = useState<string | null>(null);
  const [document, setDocument] = useState<ProviderUsageEvidence | null>(null);
  const [verification, setVerification] = useState<VerificationState>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!customerId && tenants.length > 0) setCustomerId(tenants[0].id);
    if (customerId && !tenants.some((tenant) => tenant.id === customerId)) setCustomerId(tenants[0]?.id ?? "");
  }, [customerId, tenants]);

  const generation = useRef(0);
  useLayoutEffect(() => {
    // Invalidate pending health, evidence and signature work before the new
    // selection paints. Keep the form mounted so editing dates retains focus.
    generation.current += 1;
    setLoading(false);
    // Never leave one customer's health/evidence visible under another
    // customer's selected label. The operator must pull the new customer.
    setHealth(null);
    setHealthError(null);
    setDocument(null);
    setVerification(null);
    setError(null);
    return () => {
      generation.current += 1;
    };
  }, [customerId, periodStart, periodEnd]);

  async function pull(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!customerId || !periodStart || !periodEnd) return;
    const requestGeneration = ++generation.current;
    const isCurrent = () => generation.current === requestGeneration;
    setLoading(true);
    setError(null);
    setHealth(null);
    setHealthError(null);
    setDocument(null);
    setVerification(null);
    try {
      const [healthResult, evidenceResult] = await Promise.allSettled([
        providerApi.customerHealth(customerId),
        providerApi.usageEvidence(customerId, asRFC3339(periodStart), asRFC3339(periodEnd)),
      ]);
      if (!isCurrent()) return;
      for (const result of [healthResult, evidenceResult]) {
        if (result.status === "rejected" && result.reason instanceof ProviderAuthError) {
          onAuthError();
          return;
        }
      }
      if (healthResult.status === "fulfilled") {
        setHealth(healthResult.value);
      } else {
        setHealthError(healthResult.reason instanceof Error ? healthResult.reason.message : String(healthResult.reason));
      }
      if (evidenceResult.status === "rejected") {
        setError(evidenceResult.reason instanceof Error ? evidenceResult.reason.message : String(evidenceResult.reason));
        return;
      }
      const evidence = evidenceResult.value;
      setDocument(evidence);
      if (evidence.signature?.jws) {
        const verified = await providerApi.verifyUsageEvidence(evidence);
        if (isCurrent()) setVerification(verified);
      } else {
        setVerification({ verified: false });
      }
    } catch (reason) {
      if (!isCurrent()) return;
      if (reason instanceof ProviderAuthError) {
        onAuthError();
        return;
      }
      setError(reason instanceof Error ? reason.message : String(reason));
    } finally {
      if (isCurrent()) setLoading(false);
    }
  }

  async function download(format: "json" | "csv") {
    if (!customerId || !periodStart || !periodEnd) return;
    const requestGeneration = generation.current;
    setError(null);
    try {
      await providerApi.downloadUsageEvidence(customerId, asRFC3339(periodStart), asRFC3339(periodEnd), format);
    } catch (reason) {
      if (generation.current !== requestGeneration) return;
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
      <div className="mt-4 grid gap-2 rounded-md border border-border/60 p-4" aria-label={translateNow("source.provider.health.title.aud600001")}>
        <h3 className="text-sm font-semibold">{translateNow("source.provider.health.title.aud600001")}</h3>
        {loading && !health && !healthError ? (
          <p className="text-caption text-muted-foreground">{translateNow("source.provider.health.loading.aud600002")}</p>
        ) : health ? (
          <dl className="grid gap-2 text-caption sm:grid-cols-2">
            <div>
              <dt className="text-muted-foreground">{translateNow("source.provider.health.status.aud600008")}</dt>
              <dd className={health.health === "healthy" ? "text-status-success" : "text-status-warning"}>{healthLabel(health.health)}</dd>
            </div>
            <div>
              <dt className="text-muted-foreground">{translateNow("source.provider.health.activeCertificates.aud600009")}</dt>
              <dd className="tabular-nums">{health.active_certificates}</dd>
            </div>
          </dl>
        ) : healthError ? (
          <p className="text-caption text-status-danger" role="alert">
            {translateNow("source.provider.health.unavailable.aud600010")}: {healthError}
          </p>
        ) : (
          <p className="text-caption text-muted-foreground">{translateNow("source.provider.health.unknown.aud600003")}</p>
        )}
      </div>
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
