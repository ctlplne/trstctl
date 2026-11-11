// SPDX-License-Identifier: BUSL-1.1

import { useEffect, useState } from "react";

import { Button } from "@/components/ui/button";
import { translateNow } from "@/i18n/I18nProvider";
import { ProviderAuthError, providerApi, type ProviderTemplate, type ProviderTenant } from "@/lib/providerApi";
import { useApiQuery } from "@/lib/query";

// A186-L1: the tenant templates a provider records, each with its versions and
// the delegated customers bound to it. Read-only: recording, applying and
// rolling out a template stay with the provider API and CLI.

const BASELINE_SECTIONS = ["profiles", "policy", "issuers", "deployment_targets", "notification_channels", "members", "report_schedules"] as const;

type BaselineSection = (typeof BASELINE_SECTIONS)[number];

function sectionCount(baseline: Record<string, unknown> | null | undefined, section: BaselineSection): number {
  const value = baseline?.[section];
  if (Array.isArray(value)) return value.length;
  return value && typeof value === "object" ? 1 : 0;
}

function shortDigest(digest: string): string {
  const bare = digest.startsWith("sha256:") ? digest.slice("sha256:".length) : digest;
  return bare.slice(0, 12);
}

function when(at: string | undefined): string {
  if (!at) return "—";
  const iso = new Date(at).toISOString();
  return `${iso.slice(0, 10)} ${iso.slice(11, 16)} UTC`;
}

export function ProviderTemplatesPanel({
  tenants,
  authorityKey,
  onAuthError,
}: {
  tenants: ProviderTenant[];
  authorityKey: readonly unknown[];
  onAuthError: () => void;
}) {
  const [selected, setSelected] = useState<string | null>(null);
  const list = useApiQuery(["provider", "templates", ...authorityKey], () => providerApi.listTemplates(), { retry: false });
  const detail = useApiQuery(
    ["provider", "template", ...authorityKey, selected],
    () => (selected ? providerApi.getTemplate(selected) : Promise.resolve(null)),
    { retry: false, enabled: selected !== null },
  );
  useEffect(() => {
    if (list.errorValue instanceof ProviderAuthError || detail.errorValue instanceof ProviderAuthError) onAuthError();
  }, [list.errorValue, detail.errorValue, onAuthError]);

  const templates: ProviderTemplate[] = list.data ?? [];
  const customerName = (id: string) => tenants.find((tenant) => tenant.id === id)?.name ?? id;
  const shown = detail.data;

  return (
    <section className="mt-6" aria-labelledby="provider-templates-heading">
      <h2 id="provider-templates-heading" className="text-title font-semibold">
        {translateNow("provider.templates.heading")}
      </h2>
      <p className="mt-1 text-caption text-muted-foreground">{translateNow("provider.templates.intro")}</p>
      {list.error ? (
        <p className="mt-2 text-caption text-status-danger" role="alert">
          {list.error}
        </p>
      ) : list.loading ? (
        <p className="mt-2 text-caption text-muted-foreground">{translateNow("capabilities.loading")}</p>
      ) : templates.length === 0 ? (
        <p className="mt-2 text-caption text-muted-foreground">{translateNow("provider.templates.empty")}</p>
      ) : (
        <div className="mt-2 overflow-x-auto">
          <table className="w-full text-sm">
            <caption className="sr-only">{translateNow("provider.templates.heading")}</caption>
            <thead>
              <tr className="text-start text-caption text-muted-foreground">
                <th scope="col" className="py-1 pe-4 text-start">
                  {translateNow("provider.templates.columnName")}
                </th>
                <th scope="col" className="py-1 pe-4 text-start">
                  {translateNow("provider.templates.columnVersion")}
                </th>
                <th scope="col" className="py-1 pe-4 text-start">
                  {translateNow("provider.templates.columnDigest")}
                </th>
                <th scope="col" className="py-1 pe-4 text-start">
                  {translateNow("provider.templates.columnRecorded")}
                </th>
                <th scope="col" className="py-1 text-start">
                  <span className="sr-only">{translateNow("provider.templates.columnActions")}</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {templates.map((template) => (
                <tr key={template.id} className="border-t border-border">
                  <td className="py-1 pe-4">{template.name}</td>
                  <td className="py-1 pe-4 tabular-nums">{template.version}</td>
                  <td className="py-1 pe-4 font-mono text-xs">{shortDigest(template.digest)}</td>
                  <td className="py-1 pe-4">
                    {translateNow("provider.templates.recordedBy", { who: template.recorded_by || "—", at: when(template.recorded_at) })}
                  </td>
                  <td className="py-1">
                    <Button
                      type="button"
                      variant="outline"
                      size="sm"
                      aria-pressed={selected === template.id}
                      onClick={() => setSelected(selected === template.id ? null : template.id)}
                    >
                      {translateNow("provider.templates.view", { name: template.name })}
                    </Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {selected ? (
        <div className="mt-4 rounded-md border border-border p-4" aria-live="polite">
          {detail.error ? (
            <p className="text-caption text-status-danger" role="alert">
              {detail.error}
            </p>
          ) : !shown ? (
            <p className="text-caption text-muted-foreground">{translateNow("capabilities.loading")}</p>
          ) : (
            <>
              <h3 className="font-semibold">{translateNow("provider.templates.detailHeading", { name: shown.latest.name, version: shown.latest.version })}</h3>
              <ul className="mt-2 grid gap-1 text-sm sm:grid-cols-2">
                {BASELINE_SECTIONS.map((section) => (
                  <li key={section}>{translateNow(`provider.templates.section.${section}`, { count: sectionCount(shown.latest.baseline, section) })}</li>
                ))}
              </ul>
              <h4 className="mt-4 text-sm font-semibold">{translateNow("provider.templates.versions")}</h4>
              <ul className="mt-1 grid gap-1 text-sm">
                {shown.versions.map((version) => (
                  <li key={version.version}>
                    {translateNow("provider.templates.versionLine", {
                      version: version.version,
                      digest: shortDigest(version.digest),
                      who: version.recorded_by || "—",
                      at: when(version.recorded_at),
                    })}
                  </li>
                ))}
              </ul>
              <h4 className="mt-4 text-sm font-semibold">{translateNow("provider.templates.customers")}</h4>
              {shown.tenants.length === 0 ? (
                <p className="mt-1 text-caption text-muted-foreground">{translateNow("provider.templates.noCustomers")}</p>
              ) : (
                <ul className="mt-1 grid gap-1 text-sm">
                  {shown.tenants.map((binding) => (
                    <li key={binding.tenant_id}>
                      {translateNow(binding.complete ? "provider.templates.customerApplied" : "provider.templates.customerIncomplete", {
                        customer: customerName(binding.tenant_id),
                        version: binding.version,
                        at: when(binding.applied_at),
                      })}
                    </li>
                  ))}
                </ul>
              )}
            </>
          )}
        </div>
      ) : null}
    </section>
  );
}
