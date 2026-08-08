import { useCallback, useEffect, useState } from "react";
import { ErrorState, LoadingState } from "@/components/StatePrimitives";
import { api, type ADCSDatabaseList } from "@/lib/api";
import { formatDateTime } from "@/i18n/format";
import { translateNow } from "@/i18n/I18nProvider";

/**
 * AD CS certificate-database lifecycle visibility (epic F4).
 *
 * Issuing against an enterprise CA tells an operator nothing about what that CA
 * holds. A domain-joined relay collects certutil rows; this panel shows the
 * per-CA breakdown by disposition. The point is that PENDING is not FAILED: a
 * request awaiting a CA manager's approval shown as a failure makes an operator
 * resubmit instead of getting it approved, so the counts are never collapsed
 * into one "certificates found" number.
 */
export function ADCSDatabasePanel() {
  const [data, setData] = useState<ADCSDatabaseList | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setError(null);
    setLoading(true);
    try {
      setData(await api.adcsDatabases());
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  return (
    <section className="ui-panel p-comfortable" aria-labelledby="adcs-database-heading">
      <h2 id="adcs-database-heading" className="text-title font-semibold">
        {translateNow("source.adcs.database.f4adcs0001")}
      </h2>
      <p className="mt-1 max-w-3xl text-caption text-muted-foreground">
        {translateNow("source.adcs.database.intro.f4adcs0002")}
      </p>
      {loading ? (
        <LoadingState>{translateNow("source.loading.4f9d1e0e3a")}</LoadingState>
      ) : error ? (
        <ErrorState title={translateNow("source.adcs.database.error.f4adcs0013")}>{error}</ErrorState>
      ) : !data || (data.items ?? []).length === 0 ? (
        <p className="mt-3 max-w-3xl text-caption text-muted-foreground">
          {translateNow("source.adcs.database.none.f4adcs0003")}
        </p>
      ) : (
        <div className="mt-4 overflow-x-auto">
          <table className="w-full text-caption">
            <thead>
              <tr className="text-left text-muted-foreground">
                <th className="pr-4 font-medium">{translateNow("source.adcs.ca.f4adcs0004")}</th>
                <th className="pr-4 font-medium">{translateNow("source.adcs.issued.f4adcs0005")}</th>
                <th className="pr-4 font-medium">{translateNow("source.adcs.pending.f4adcs0006")}</th>
                <th className="pr-4 font-medium">{translateNow("source.adcs.revoked.f4adcs0007")}</th>
                <th className="pr-4 font-medium">{translateNow("source.adcs.denied.f4adcs0008")}</th>
                <th className="pr-4 font-medium">{translateNow("source.adcs.failed.f4adcs0009")}</th>
                <th className="pr-4 font-medium">{translateNow("source.adcs.gaps.f4adcs0010")}</th>
                <th className="pr-4 font-medium">{translateNow("source.adcs.ingested.f4adcs0011")}</th>
              </tr>
            </thead>
            <tbody>
              {(data.items ?? []).map((row) => (
                <tr key={row.ca_config} className="border-t border-border/60">
                  <td className="py-1 pr-4 font-mono text-xs">{row.ca_config}</td>
                  <td className="py-1 pr-4 tabular-nums">{row.issued}</td>
                  {/* Pending is highlighted because it is the actionable column:
                      a request nobody has approved yet, distinct from a failure. */}
                  <td className={row.pending > 0 ? "py-1 pr-4 tabular-nums text-status-warning" : "py-1 pr-4 tabular-nums"}>
                    {row.pending}
                  </td>
                  <td className="py-1 pr-4 tabular-nums">{row.revoked}</td>
                  <td className="py-1 pr-4 tabular-nums">{row.denied}</td>
                  <td className="py-1 pr-4 tabular-nums">{row.failed}</td>
                  {/* Gaps: unknown dispositions + unparsed expiries + rejected
                      rows. Surfaced so the ingest cannot read as complete
                      coverage it does not have. */}
                  <td className="py-1 pr-4 tabular-nums text-muted-foreground">
                    {row.unknown + row.unparsed + row.rows_rejected}
                  </td>
                  <td className="py-1 pr-4 text-xs text-muted-foreground">
                    <span>{row.ingested_at ? formatDateTime(row.ingested_at) : translateNow("source.adcs.never.f4adcs0014")}</span>
                    {row.source ? <span className="ml-2 opacity-70">{row.source}</span> : null}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <p className="mt-3 max-w-3xl text-xs text-muted-foreground">
            {translateNow("source.adcs.database.note.f4adcs0012")}
          </p>
        </div>
      )}
    </section>
  );
}
