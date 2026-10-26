import { Pause, Play, Send } from "lucide-react";
import { useState } from "react";
import { ErrorState, LoadingState } from "@/components/StatePrimitives";
import { StatusBadge } from "@/components/StatusBadge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Field } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { useTranslation } from "@/i18n/I18nProvider";
import { api, type KubernetesTrustRollout } from "@/lib/api";
import { useApiQuery } from "@/lib/query";
import type { StatusTone } from "@/lib/statusVocab";

const stateTones: Record<string, StatusTone> = {
  running: "info",
  paused: "warning",
  completed: "success",
  superseded: "neutral",
  waiting: "neutral",
  dispatched: "info",
  verified: "success",
  failed: "critical",
};

function errorMessage(err: unknown, fallback: string): string {
  return err instanceof Error && err.message ? err.message : fallback;
}

function splitList(value: string): string[] {
  return value
    .split(/[\s,]+/)
    .map((item) => item.trim())
    .filter((item) => item !== "");
}

// KubernetesTrustRolloutsPanel rolls one TrustBundle out to the clusters whose
// controllers report here (A138): the first selected cluster is the canary,
// the rest follow once it is verified, and a cluster reads verified only after
// its own controller reported the bundle distributed with the rollout's hash.
export function KubernetesTrustRolloutsPanel({ knownClusters }: { knownClusters: string[] }) {
  const { t } = useTranslation();
  const rollouts = useApiQuery(["kubernetes", "trust-rollouts"], () => api.kubernetesTrustRollouts(), {
    retry: false,
    live: { intervalMs: 15_000 },
  });
  const [name, setName] = useState("");
  const [bundle, setBundle] = useState("");
  const [namespaces, setNamespaces] = useState("");
  const [selected, setSelected] = useState<string[]>([]);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const ordered = knownClusters.filter((cluster) => selected.includes(cluster));
  const ready = name.trim() !== "" && bundle.trim() !== "" && splitList(namespaces).length > 0 && ordered.length > 0;

  async function run(key: string, action: () => Promise<unknown>) {
    setBusy(key);
    setError(null);
    try {
      await action();
      rollouts.refetch();
    } catch (err) {
      setError(errorMessage(err, t("workloads.trustRollouts.failed")));
    } finally {
      setBusy(null);
    }
  }

  async function start() {
    await run("start", async () => {
      await api.startKubernetesTrustRollout({
        name: name.trim(),
        ca_bundle_pem: bundle,
        namespaces: splitList(namespaces),
        clusters: ordered,
      });
      setName("");
      setBundle("");
      setNamespaces("");
      setSelected([]);
    });
  }

  function toggle(cluster: string) {
    setSelected((current) => (current.includes(cluster) ? current.filter((item) => item !== cluster) : [...current, cluster]));
  }

  const items: KubernetesTrustRollout[] = rollouts.data?.items ?? [];
  return (
    <section aria-labelledby="kubernetes-trust-rollouts-heading" className="grid gap-3 border-b border-border pb-4">
      <div>
        <h2 id="kubernetes-trust-rollouts-heading" className="text-title font-semibold">
          {t("workloads.trustRollouts.heading")}
        </h2>
        <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{t("workloads.trustRollouts.description")}</p>
      </div>
      {error && <ErrorState title={t("workloads.trustRollouts.errorTitle")}>{error}</ErrorState>}
      {rollouts.errorValue ? (
        <ErrorState title={t("workloads.trustRollouts.errorTitle")}>{errorMessage(rollouts.errorValue, t("workloads.trustRollouts.loadFailed"))}</ErrorState>
      ) : null}
      {rollouts.loading && !rollouts.data ? <LoadingState>{t("workloads.trustRollouts.loading")}</LoadingState> : null}
      {items.length === 0 && rollouts.data ? <p className="text-sm text-muted-foreground">{t("workloads.trustRollouts.empty")}</p> : null}
      <ul className="grid gap-3">
        {items.map((rollout) => (
          <li key={rollout.id} className="ui-panel grid gap-2 p-comfortable">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-mono text-sm font-semibold">{rollout.name}</span>
                <StatusBadge vocabulary="delivery" value={rollout.state} tone={stateTones[rollout.state]} />
                <span className="text-xs text-muted-foreground">
                  {t("workloads.trustRollouts.verifiedCount", { verified: String(rollout.verified_clusters), total: String(rollout.clusters.length) })}
                </span>
              </div>
              <div className="flex gap-2">
                {rollout.state === "running" && (
                  <Button
                    size="sm"
                    variant="outline"
                    disabled={busy !== null}
                    onClick={() => void run(rollout.id, () => api.pauseKubernetesTrustRollout(rollout.id))}
                  >
                    <Pause className="h-4 w-4" aria-hidden="true" />
                    {t("workloads.trustRollouts.pause")}
                  </Button>
                )}
                {rollout.state === "paused" && (
                  <Button
                    size="sm"
                    variant="outline"
                    disabled={busy !== null}
                    onClick={() => void run(rollout.id, () => api.resumeKubernetesTrustRollout(rollout.id))}
                  >
                    <Play className="h-4 w-4" aria-hidden="true" />
                    {t("workloads.trustRollouts.resume")}
                  </Button>
                )}
              </div>
            </div>
            <p className="text-xs text-muted-foreground">
              {t("workloads.trustRollouts.target", { configMap: rollout.config_map_name, key: rollout.key, namespaces: rollout.namespaces.join(", ") })}
            </p>
            <p className="font-mono text-xs text-muted-foreground">{t("workloads.trustRollouts.hash", { hash: rollout.bundle_sha256 })}</p>
            <ul className="grid gap-1">
              {rollout.clusters.map((cluster) => (
                <li key={cluster.cluster_id} className="flex flex-wrap items-center gap-2 text-xs">
                  <span className="font-mono">{cluster.cluster_id.slice(0, 19)}…</span>
                  {cluster.canary && <span className="text-muted-foreground">{t("workloads.trustRollouts.canary")}</span>}
                  <StatusBadge vocabulary="delivery" value={cluster.state} tone={stateTones[cluster.state]} />
                  {cluster.report_id && (
                    <span className="text-muted-foreground">{t("workloads.trustRollouts.report", { report: cluster.report_id.slice(0, 8) })}</span>
                  )}
                  {cluster.reason && <span className="text-muted-foreground">{cluster.reason}</span>}
                </li>
              ))}
            </ul>
          </li>
        ))}
      </ul>
      <form
        className="ui-panel grid gap-3 p-comfortable"
        onSubmit={(event) => {
          event.preventDefault();
          if (ready) void start();
        }}
      >
        <h3 className="text-sm font-semibold">{t("workloads.trustRollouts.startHeading")}</h3>
        <Field label={t("workloads.trustRollouts.name")} required>
          {(control) => (
            <Input
              {...control}
              className="font-mono"
              value={name}
              onChange={(event) => setName(event.target.value)}
              placeholder={t("workloads.trustRollouts.namePlaceholder")}
            />
          )}
        </Field>
        <Field label={t("workloads.trustRollouts.bundle")} description={t("workloads.trustRollouts.bundleHelp")} required>
          {(control) => <Textarea {...control} className="min-h-24 font-mono text-xs" value={bundle} onChange={(event) => setBundle(event.target.value)} />}
        </Field>
        <Field label={t("workloads.trustRollouts.namespaces")} required>
          {(control) => (
            <Input
              {...control}
              className="font-mono"
              value={namespaces}
              onChange={(event) => setNamespaces(event.target.value)}
              placeholder={t("workloads.trustRollouts.namespacesPlaceholder")}
            />
          )}
        </Field>
        <fieldset className="grid gap-1 text-sm">
          <legend>{t("workloads.trustRollouts.clusters")}</legend>
          {knownClusters.length === 0 && <p className="text-xs text-muted-foreground">{t("workloads.trustRollouts.noClusters")}</p>}
          {knownClusters.map((cluster) => (
            <label key={cluster} className="flex items-center gap-2 text-xs">
              <Checkbox checked={selected.includes(cluster)} onChange={() => toggle(cluster)} />
              <span className="font-mono">{cluster}</span>
              {ordered[0] === cluster && <span className="text-muted-foreground">{t("workloads.trustRollouts.canary")}</span>}
            </label>
          ))}
        </fieldset>
        <div>
          <Button type="submit" disabled={!ready || busy !== null}>
            <Send className="h-4 w-4" aria-hidden="true" />
            {busy === "start" ? t("workloads.trustRollouts.starting") : t("workloads.trustRollouts.start")}
          </Button>
        </div>
      </form>
    </section>
  );
}

export default KubernetesTrustRolloutsPanel;
