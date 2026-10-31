import { useCallback, useEffect, useState, type FormEvent } from "react";
import { StatusBadge } from "@/components/StatusBadge";
import { ErrorState, LoadingState } from "@/components/StatePrimitives";
import { useCan } from "@/components/rbac";
import { Button } from "@/components/ui/button";
import { api, type ADCSDatabaseCollection, type ADCSDatabaseList, type Agent } from "@/lib/api";
import { apiProblemMessage } from "@/lib/apiProblem";
import { formatDateTime } from "@/i18n/format";
import { translateNow } from "@/i18n/I18nProvider";

function collectionTone(status: ADCSDatabaseCollection["status"]): "success" | "warning" | "critical" | "neutral" {
  if (status === "collected") return "success";
  if (status === "failed") return "critical";
  if (status === "running") return "warning";
  return "neutral";
}

function collectionLabel(status: ADCSDatabaseCollection["status"]): string {
  switch (status) {
    case "collected":
      return translateNow("adcs.database.collect.statusCollected");
    case "failed":
      return translateNow("adcs.database.collect.statusFailed");
    case "running":
      return translateNow("adcs.database.collect.statusRunning");
    default:
      return translateNow("adcs.database.collect.statusQueued");
  }
}

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
  // A162: a domain-joined relay reads a CA database with certutil on request.
  const canCollect = useCan("discovery:write");
  const [relays, setRelays] = useState<Agent[]>([]);
  const [caConfig, setCaConfig] = useState("");
  const [relayID, setRelayID] = useState("");
  const [collecting, setCollecting] = useState(false);
  const [collectError, setCollectError] = useState<string | null>(null);
  const [queuedFor, setQueuedFor] = useState<string | null>(null);

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

  useEffect(() => {
    if (!canCollect) return;
    api
      .agents()
      .then((agents) => setRelays(agents.filter((agent) => agent.status !== "offboarded" && agent.roles.includes("network"))))
      .catch(() => setRelays([]));
  }, [canCollect]);

  const collect = async (event: FormEvent) => {
    event.preventDefault();
    setCollectError(null);
    setQueuedFor(null);
    setCollecting(true);
    try {
      const queued = await api.collectADCSDatabase({ ca_config: caConfig.trim(), relay_agent_id: relayID });
      setQueuedFor(queued.ca_config);
      await load();
    } catch (err) {
      setCollectError(apiProblemMessage(err, translateNow("adcs.database.collect.failed")));
    } finally {
      setCollecting(false);
    }
  };
  const relayName = (id: string) => relays.find((agent) => agent.id === id)?.name ?? id;
  const collections = data?.collections ?? [];

  return (
    <section className="ui-panel p-comfortable" aria-labelledby="adcs-database-heading">
      <h2 id="adcs-database-heading" className="text-title font-semibold">
        {translateNow("source.adcs.database.f4adcs0001")}
      </h2>
      <p className="mt-1 max-w-3xl text-caption text-muted-foreground">{translateNow("source.adcs.database.intro.f4adcs0002")}</p>
      {canCollect ? (
        <div className="mt-4 grid gap-2">
          <form onSubmit={(event) => void collect(event)} className="grid gap-2 sm:grid-cols-3 sm:items-end">
            <label className="grid gap-1 text-sm">
              <span>{translateNow("adcs.database.collect.ca")}</span>
              <input
                className="rounded-control border border-border bg-background p-2 font-mono text-xs"
                value={caConfig}
                onChange={(event) => setCaConfig(event.target.value)}
                autoComplete="off"
                spellCheck={false}
              />
            </label>
            <label className="grid gap-1 text-sm">
              <span>{translateNow("adcs.database.collect.relay")}</span>
              <select className="rounded-control border border-border bg-background p-2" value={relayID} onChange={(event) => setRelayID(event.target.value)}>
                <option value="">{translateNow("adcs.database.collect.relayChoose")}</option>
                {relays.map((agent) => (
                  <option key={agent.id} value={agent.id}>
                    {agent.name}
                  </option>
                ))}
              </select>
            </label>
            <Button type="submit" disabled={collecting || !caConfig.trim() || !relayID}>
              {translateNow("adcs.database.collect.submit")}
            </Button>
          </form>
          <p className="max-w-3xl text-xs text-muted-foreground">{translateNow("adcs.database.collect.help")}</p>
          {collectError ? (
            <p role="alert" className="text-sm text-risk-critical">
              {collectError}
            </p>
          ) : null}
          {queuedFor ? (
            <p role="status" className="text-sm">
              {translateNow("adcs.database.collect.queued", { ca: queuedFor })}
            </p>
          ) : null}
        </div>
      ) : null}
      {collections.length > 0 ? (
        <div className="mt-4 overflow-x-auto">
          <h3 className="text-sm font-semibold">{translateNow("adcs.database.collect.reads")}</h3>
          <table className="mt-2 w-full text-caption">
            <thead>
              <tr className="text-left text-muted-foreground">
                <th className="pr-4 font-medium">{translateNow("adcs.database.collect.colCA")}</th>
                <th className="pr-4 font-medium">{translateNow("adcs.database.collect.colRelay")}</th>
                <th className="pr-4 font-medium">{translateNow("adcs.database.collect.colStatus")}</th>
                <th className="pr-4 font-medium">{translateNow("adcs.database.collect.colRequested")}</th>
                <th className="pr-4 font-medium">{translateNow("adcs.database.collect.colDetail")}</th>
              </tr>
            </thead>
            <tbody>
              {collections.map((read) => (
                <tr key={read.collection_id} className="border-t border-border/60">
                  <td className="py-1 pr-4 font-mono text-xs">{read.ca_config}</td>
                  <td className="py-1 pr-4 text-xs">{relayName(read.relay_agent_id)}</td>
                  <td className="py-1 pr-4">
                    <StatusBadge value={read.status} label={collectionLabel(read.status)} tone={collectionTone(read.status)} />
                  </td>
                  <td className="py-1 pr-4 text-xs text-muted-foreground">{read.requested_at ? formatDateTime(read.requested_at) : null}</td>
                  <td className="py-1 pr-4 text-xs">{read.last_error ?? null}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
      {loading ? (
        <LoadingState>{translateNow("source.loading.4f9d1e0e3a")}</LoadingState>
      ) : error ? (
        <ErrorState title={translateNow("source.adcs.database.error.f4adcs0013")}>{error}</ErrorState>
      ) : !data || (data.items ?? []).length === 0 ? (
        <p className="mt-3 max-w-3xl text-caption text-muted-foreground">{translateNow("source.adcs.database.none.f4adcs0003")}</p>
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
                  <td className={row.pending > 0 ? "py-1 pr-4 tabular-nums text-status-warning" : "py-1 pr-4 tabular-nums"}>{row.pending}</td>
                  <td className="py-1 pr-4 tabular-nums">{row.revoked}</td>
                  <td className="py-1 pr-4 tabular-nums">{row.denied}</td>
                  <td className="py-1 pr-4 tabular-nums">{row.failed}</td>
                  {/* Gaps: unknown dispositions + unparsed expiries + rejected
                      rows. Surfaced so the ingest cannot read as complete
                      coverage it does not have. */}
                  <td className="py-1 pr-4 tabular-nums text-muted-foreground">{row.unknown + row.unparsed + row.rows_rejected}</td>
                  <td className="py-1 pr-4 text-xs text-muted-foreground">
                    <span>{row.ingested_at ? formatDateTime(row.ingested_at) : translateNow("source.adcs.never.f4adcs0014")}</span>
                    {row.source ? <span className="ml-2 opacity-70">{row.source}</span> : null}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <p className="mt-3 max-w-3xl text-xs text-muted-foreground">{translateNow("source.adcs.database.note.f4adcs0012")}</p>
        </div>
      )}
    </section>
  );
}
