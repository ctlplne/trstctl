import { useState } from "react";
import { Button } from "@/components/ui/button";
import { api } from "@/lib/api";
import { newIdempotencyKey } from "@/lib/apiTransport";
import { apiProblemMessage } from "@/lib/apiProblem";
import { useApiQuery } from "@/lib/query";
import { formatDateTime } from "@/i18n/format";
import { useTranslation } from "@/i18n/I18nProvider";

// A212: addresses trstctl's own sources saw outside every declared segment.
// Candidates for a declaration, never a complete list: a network no source has
// seen cannot appear.
export function CoverageCandidatesPanel({ onDeclared }: { onDeclared: () => void }) {
  const { t } = useTranslation();
  const candidates = useApiQuery(["discovery-coverage-candidates"], () => api.coverageCandidates(), { retry: false });
  const [declaring, setDeclaring] = useState<string | null>(null);
  const [declared, setDeclared] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const items = candidates.data?.items ?? [];
  if (candidates.loading || items.length === 0) return null;

  async function declare(address: string) {
    const host = hostOf(address);
    setDeclaring(address);
    setError(null);
    try {
      await api.createDiscoverySegment(
        { name: `seen-${host.replace(/[^a-zA-Z0-9]+/g, "-")}`.slice(0, 63), ranges: [host], staleness_hours: 168 },
        newIdempotencyKey(),
      );
      setDeclared(address);
      candidates.refetch();
      onDeclared();
    } catch (failure) {
      setError(apiProblemMessage(failure, t("discovery.candidates.declareFailed")));
    } finally {
      setDeclaring(null);
    }
  }

  return (
    <section aria-label={t("discovery.candidates.heading")} className="grid gap-2 rounded-md border border-status-warning/40 p-3">
      <p className="text-sm font-medium">{t("discovery.candidates.heading")}</p>
      <p className="text-xs text-muted-foreground">{candidates.data?.note}</p>
      <div className="overflow-x-auto">
        <table className="ui-table min-w-160">
          <caption className="sr-only">{t("discovery.candidates.caption")}</caption>
          <thead>
            <tr>
              <th scope="col">{t("discovery.candidates.address")}</th>
              <th scope="col">{t("discovery.candidates.sources")}</th>
              <th scope="col">{t("discovery.candidates.lastSeen")}</th>
              <th scope="col">{t("discovery.candidates.actions")}</th>
            </tr>
          </thead>
          <tbody>
            {items.map((item) => (
              <tr key={item.address}>
                <td className="font-mono text-xs">{item.address}</td>
                <td className="text-xs">{item.sources.join(", ")}</td>
                <td className="text-xs">{formatDateTime(item.last_seen)}</td>
                <td>
                  <Button type="button" variant="outline" onClick={() => void declare(item.address)} disabled={declaring !== null}>
                    {t("discovery.candidates.declare", { range: hostOf(item.address) })}
                  </Button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {declared ? <p role="status">{t("discovery.candidates.declared", { address: declared })}</p> : null}
      {error ? (
        <p role="alert" className="text-sm text-status-danger">
          {error}
        </p>
      ) : null}
    </section>
  );
}

function hostOf(address: string): string {
  const bracketed = /^\[(.+)\]:\d+$/.exec(address);
  if (bracketed) return bracketed[1];
  const colon = address.lastIndexOf(":");
  return colon > 0 && address.indexOf(":") === colon ? address.slice(0, colon) : address;
}
