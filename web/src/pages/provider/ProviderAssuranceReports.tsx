// SPDX-License-Identifier: BUSL-1.1

import { useEffect, useState } from "react";

import { Button } from "@/components/ui/button";
import { translateNow } from "@/i18n/I18nProvider";
import { ProviderAuthError, providerApi, type ProviderTenant } from "@/lib/providerApi";
import { useApiQuery } from "@/lib/query";

// A187-L1: a delegated customer's signed assurance report runs. The provider
// downloads a run exactly as archived and shares it with the key's SHA-256; the
// customer verifies the file offline.

function when(at: string | undefined): string {
  if (!at) return "—";
  const iso = new Date(at).toISOString();
  return `${iso.slice(0, 10)} ${iso.slice(11, 16)} UTC`;
}

export function ProviderAssuranceReports({
  tenant,
  authorityKey,
  onAuthError,
}: {
  tenant: ProviderTenant;
  authorityKey: readonly unknown[];
  onAuthError: () => void;
}) {
  const reports = useApiQuery(["provider", "assurance-reports", ...authorityKey, tenant.id], () => providerApi.assuranceReports(tenant.id), {
    retry: false,
  });
  const [downloadError, setDownloadError] = useState<string | null>(null);
  useEffect(() => {
    if (reports.errorValue instanceof ProviderAuthError) onAuthError();
  }, [reports.errorValue, onAuthError]);
  const data = reports.data;
  return (
    <div className="rounded-control border border-border p-2 text-caption" role="group" aria-labelledby="provider-assurance-reports-title">
      <p id="provider-assurance-reports-title" className="font-semibold">
        {translateNow("provider.assuranceReports.title")}
      </p>
      {reports.error ? (
        <p className="text-status-danger">{reports.error}</p>
      ) : !data ? (
        <p className="text-muted-foreground">{translateNow("capabilities.loading")}</p>
      ) : (
        <>
          <p className="text-muted-foreground">{translateNow("provider.assuranceReports.signingKey", { sha256: data.signing_key.sha256 })}</p>
          {data.runs.length === 0 ? (
            <p className="mt-1">{translateNow("provider.assuranceReports.none")}</p>
          ) : (
            <ul className="mt-1 grid gap-1">
              {data.runs.map((run) => (
                <li key={run.run_id} className="flex flex-wrap items-center gap-2">
                  <span>
                    {translateNow("provider.assuranceReports.run", {
                      due: when(run.due_at),
                      completed: when(run.completed_at),
                      digest: run.artifact_sha256.slice(0, 12),
                    })}
                  </span>
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    onClick={() => {
                      setDownloadError(null);
                      void providerApi.downloadAssuranceReport(tenant.id, run.run_id).catch((error: unknown) => {
                        if (error instanceof ProviderAuthError) onAuthError();
                        setDownloadError(error instanceof Error ? error.message : String(error));
                      });
                    }}
                  >
                    {translateNow("provider.assuranceReports.download", { due: when(run.due_at) })}
                  </Button>
                </li>
              ))}
            </ul>
          )}
          <p className="mt-1 text-muted-foreground">{translateNow("provider.assuranceReports.verify")}</p>
          {downloadError ? <p className="text-status-danger">{downloadError}</p> : null}
        </>
      )}
    </div>
  );
}
