// SPDX-License-Identifier: BUSL-1.1

import { useState } from "react";
import { Button } from "@/components/ui/button";
import { translateNow } from "@/i18n/I18nProvider";
import { api, type CryptoReadinessExport } from "@/lib/api";
import { useApiQuery } from "@/lib/query";

// M2 consumes the same TanStack-cached dataset as CBOM/Posture. The backend
// digest binds graph rows and event-projected actions, while the signed export
// binds the JSON dataset to its exact CSV and NDJSON bytes.
export function CryptoReadinessPanel() {
  const readiness = useApiQuery(["crypto-readiness"], api.cryptoReadiness);
  const [exporting, setExporting] = useState(false);
  const [exportError, setExportError] = useState<string | null>(null);
  const data = readiness.data;
  const items = data?.items ?? [];

  async function exportReadiness(format: "csv" | "ndjson" | "json") {
    setExporting(true);
    setExportError(null);
    try {
      const evidence = await api.cryptoReadinessExport();
      if (evidence.dataset_digest !== data?.dataset_digest) {
        readiness.refetch();
        throw new Error(translateNow("cryptoReadiness.export.changed"));
      }
      downloadReadiness(evidence, format);
    } catch (error) {
      setExportError(error instanceof Error ? error.message : String(error));
    } finally {
      setExporting(false);
    }
  }

  return (
    <section className="ui-panel min-w-0 p-comfortable" aria-labelledby="crypto-readiness-heading">
      <div className="flex min-w-0 flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <h2 id="crypto-readiness-heading" className="text-title font-semibold">
            {translateNow("source.crypto.readiness.m2seq00001")}
          </h2>
          {data ? <p className="mt-1 break-all font-mono text-xs text-muted-foreground">{data.dataset_digest}</p> : null}
        </div>
        <div className="flex flex-wrap gap-2">
          <Button type="button" variant="outline" disabled={!data || exporting} onClick={() => void exportReadiness("csv")}>
            {translateNow("source.format.csv.j1exp00004")}
          </Button>
          <Button type="button" variant="outline" disabled={!data || exporting} onClick={() => void exportReadiness("ndjson")}>
            {translateNow("source.format.ndjson.j1exp00003")}
          </Button>
          <Button type="button" variant="outline" disabled={!data || exporting} onClick={() => void exportReadiness("json")}>
            {translateNow("source.provider.billing.download.json.aud590010")}
          </Button>
        </div>
      </div>
      {readiness.error ? (
        <p className="mt-2 text-caption text-status-danger">{readiness.error}</p>
      ) : readiness.loading ? (
        <p className="mt-2 text-caption text-muted-foreground">{translateNow("source.loading.4f9d1e0e3a")}</p>
      ) : (
        <>
          <dl className="mt-4 grid gap-4 sm:grid-cols-3">
            <div>
              <dt className="text-caption font-medium text-muted-foreground">{translateNow("source.crypto.assets.m2seq00002")}</dt>
              <dd className="text-title font-semibold tabular-nums">{items.length}</dd>
            </div>
            <div>
              <dt className="text-caption font-medium text-muted-foreground">{translateNow("source.urgent.m2seq00003")}</dt>
              <dd className={(data?.urgent ?? 0) > 0 ? "text-title font-semibold tabular-nums text-status-danger" : "text-title font-semibold tabular-nums"}>
                {data?.urgent ?? 0}
              </dd>
            </div>
            <div>
              <dt className="text-caption font-medium text-muted-foreground">{translateNow("source.unplaceable.m2seq00004")}</dt>
              <dd
                className={(data?.unlocated ?? 0) > 0 ? "text-title font-semibold tabular-nums text-status-warning" : "text-title font-semibold tabular-nums"}
              >
                {data?.unlocated ?? 0}
              </dd>
            </div>
          </dl>

          {items.length > 0 ? (
            <div className="mt-4 min-w-0 max-w-full overflow-x-auto">
              <table className="w-full text-caption">
                <thead>
                  <tr>
                    <th scope="col">{translateNow("source.crypto.asset.m2seq00005")}</th>
                    <th scope="col">{translateNow("source.dependents.m2seq00006")}</th>
                    <th scope="col">{translateNow("source.owners.m2seq00007")}</th>
                    <th scope="col">{translateNow("source.sequencing.m2seq00008")}</th>
                  </tr>
                </thead>
                <tbody>
                  {items.map((row) => (
                    <tr key={row.asset.id}>
                      <td className="max-w-[14rem]">
                        <span className={row.quantum_vulnerable || row.out_of_policy ? "font-medium text-status-danger" : "font-medium"}>{row.asset.name}</span>
                        <span className="mt-1 block text-xs text-muted-foreground">{(row.exhibitors ?? []).map((e) => e.name).join(", ")}</span>
                      </td>
                      <td className="align-top text-xs">
                        {(row.dependents ?? []).length > 0
                          ? (row.dependents ?? []).map((dependent, index) => (
                              <span key={`${dependent.node.id}:${dependent.via.id}`}>
                                {index > 0 ? ", " : ""}
                                <span>{dependent.node.name}</span>{" "}
                                <span>{translateNow("source.crypto.readiness.via.m2crp00001", { value1: dependent.via.name })}</span>
                              </span>
                            ))
                          : translateNow("cryptoReadiness.noDependents")}
                      </td>
                      <td className="align-top text-xs text-muted-foreground">
                        {(row.owners ?? []).join(", ") || translateNow("cryptoReadiness.ownerUnknown")}
                        {(row.actions ?? []).map((action) => (
                          <span key={action.campaign_id} className="mt-1 block">
                            {action.name}: {action.status} · {action.disposition}
                            {action.stale ? <> {translateNow("cryptoReadiness.stale")}</> : null}
                          </span>
                        ))}
                      </td>
                      <td className="max-w-[26rem] align-top text-xs text-muted-foreground">{row.recommendation}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : null}
          <p className="mt-4 max-w-3xl text-xs text-muted-foreground">{data?.coverage_guidance}</p>
        </>
      )}
      {exportError ? <p className="mt-2 text-caption text-status-danger">{exportError}</p> : null}
    </section>
  );
}

function downloadReadiness(evidence: CryptoReadinessExport, format: "csv" | "ndjson" | "json") {
  const content = format === "csv" ? evidence.csv : format === "ndjson" ? evidence.ndjson : JSON.stringify(evidence, null, 2) + "\n";
  const mediaType = format === "csv" ? "text/csv" : format === "ndjson" ? "application/x-ndjson" : "application/json";
  const url = URL.createObjectURL(new Blob([content], { type: `${mediaType};charset=utf-8` }));
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `crypto-readiness-${evidence.dataset_digest.slice(7, 19)}.${format}`;
  anchor.click();
  URL.revokeObjectURL(url);
}
