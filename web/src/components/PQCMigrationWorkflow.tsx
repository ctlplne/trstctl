import { useMemo, useState } from "react";
import { PQCMigrationProgressDetails } from "@/components/PQCMigrationProgressDetails";
import { Button } from "@/components/ui/button";
import { useTranslation } from "@/i18n/I18nProvider";
import { api, type CBOMAsset, type PQCMigrationPlan, type PQCMigrationProgress, type PQCMigrationRequest, type PQCMigrationRun } from "@/lib/api";
import { useApiQuery } from "@/lib/query";

import { useRuntimeOperationExecution, type RuntimeOperationExecutionPosture } from "@/lib/capabilities";

function OperationNotice({ action }: { action: RuntimeOperationExecutionPosture }) {
  const { t } = useTranslation();
  if (action.runnable) return null;
  const detail = action.checking
    ? t("capabilities.action.checking")
    : (action.unavailable?.detail ?? (action.state === "denied" ? t("capabilities.action.denied") : t("capabilities.action.unknown")));
  return (
    <p role="status" className="text-sm text-muted-foreground">
      {detail}
    </p>
  );
}

const pqcTargetAlgorithm = "ML-DSA-65";

const splitList = (value: string): string[] =>
  value
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
const findingLabel = (asset: CBOMAsset): string => [asset.location, asset.protocol || asset.cipher].filter(Boolean).join(" · ");
const migrationTarget = (asset: CBOMAsset): string =>
  asset.migration_target || (asset.kind === "host-config" || asset.kind === "tls-endpoint" ? "X25519MLKEM768" : pqcTargetAlgorithm);

const requestFor = (assetIds: string[], tlsAssets: CBOMAsset[], targetIds: Record<string, string>, groups: string): PQCMigrationRequest => ({
  asset_ids: assetIds,
  target_algorithm: pqcTargetAlgorithm,
  protocol: "acme",
  rollback_on_failure: true,
  ...(tlsAssets.length > 0
    ? {
        tls_bindings: tlsAssets.map((asset) => ({
          asset_id: asset.id,
          target_id: targetIds[asset.id],
          desired: { minimum_version: "TLSv1.3", cipher_suites: [], key_exchange_groups: splitList(groups) },
        })),
      }
    : {}),
});

export function PQCMigrationWorkflow({ assets }: { assets: CBOMAsset[] }) {
  const { t } = useTranslation();
  const planAuthority = useRuntimeOperationExecution("planPQCMigration");
  const startAuthority = useRuntimeOperationExecution("startPQCMigration");
  const progressAuthority = useRuntimeOperationExecution("getPQCMigrationProgress");
  const rollbackAuthority = useRuntimeOperationExecution("rollbackPQCMigration");
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [targetIds, setTargetIds] = useState<Record<string, string>>({});
  const [groups, setGroups] = useState("X25519MLKEM768, X25519");
  const [plan, setPlan] = useState<PQCMigrationPlan | null>(null);
  const [reviewedRequest, setReviewedRequest] = useState<PQCMigrationRequest | null>(null);
  const [run, setRun] = useState<PQCMigrationRun | null>(null);
  const [runAssetIds, setRunAssetIds] = useState<string[]>([]);
  const [progress, setProgress] = useState<PQCMigrationProgress | null>(null);
  const [confirmed, setConfirmed] = useState(false);
  const [rollbackConfirmed, setRollbackConfirmed] = useState(false);
  const [busy, setBusy] = useState<"plan" | "start" | "progress" | "rollback" | null>(null);
  const [result, setResult] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const vulnerable = useMemo(
    () => assets.filter((asset) => asset.quantum_vulnerable || asset.out_of_policy || (asset.kind === "tls-endpoint" && asset.protocol === "TLSv1.2")),
    [assets],
  );
  const selectedIds = vulnerable.filter((asset) => selected.has(asset.id)).map((asset) => asset.id);
  const tlsAssets = vulnerable.filter((asset) => selected.has(asset.id) && (asset.kind === "host-config" || asset.kind === "tls-endpoint"));
  const targets = useApiQuery(["pqc-migration-targets"], api.connectorTargets, { enabled: tlsAssets.length > 0, retry: false });
  const enabledTargets = targets.data?.items.filter((target) => target.enabled && target.connector === "envoy") ?? [];
  const tlsReady =
    tlsAssets.length === 0 ||
    (!targets.loading &&
      !targets.error &&
      tlsAssets.every((asset) => enabledTargets.some((target) => target.id === targetIds[asset.id])) &&
      splitList(groups).some((group) => group.toUpperCase() === "X25519MLKEM768"));
  function clearReview() {
    setPlan(null);
    setReviewedRequest(null);
    setConfirmed(false);
    setResult(null);
    setError(null);
  }
  function toggle(assetId: string) {
    setSelected((current) => {
      const next = new Set(current);
      if (next.has(assetId)) next.delete(assetId);
      else next.add(assetId);
      return next;
    });
    clearReview();
  }

  async function preview() {
    if (!planAuthority.runnable || selectedIds.length === 0) return;
    setBusy("plan");
    setError(null);
    setResult(null);
    try {
      const request = requestFor(selectedIds, tlsAssets, targetIds, groups);
      setPlan(await api.planPQCMigration(request));
      setReviewedRequest(request);
      setConfirmed(false);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : t("posture.pqcMigration.error"));
    } finally {
      setBusy(null);
    }
  }

  async function start() {
    if (!startAuthority.runnable || !plan || !reviewedRequest || !confirmed || selectedIds.length === 0) return;
    setBusy("start");
    setError(null);
    setResult(null);
    try {
      const next = await api.startPQCMigration(reviewedRequest);
      setRun(next);
      setRunAssetIds([...reviewedRequest.asset_ids]);
      setProgress(null);
      setResult(t("posture.pqcMigration.runQueued", { runId: next.run_id }));
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : t("posture.pqcMigration.error"));
    } finally {
      setBusy(null);
    }
  }

  async function refresh() {
    if (!progressAuthority.runnable || !run) return;
    setBusy("progress");
    setError(null);
    try {
      setProgress(await api.getPQCMigrationProgress(run.run_id));
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : t("posture.pqcMigration.error"));
    } finally {
      setBusy(null);
    }
  }

  async function rollback() {
    if (!rollbackAuthority.runnable || !run || !rollbackConfirmed || runAssetIds.length === 0) return;
    setBusy("rollback");
    setError(null);
    setResult(null);
    try {
      const response = await api.rollbackPQCMigration(run.run_id, runAssetIds, t("posture.pqcMigration.rollbackReason"));
      setResult(t("posture.pqcMigration.rollbackQueued", { count: String(response.queued) }));
      setRollbackConfirmed(false);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : t("posture.pqcMigration.error"));
    } finally {
      setBusy(null);
    }
  }

  return (
    <section className="grid gap-3 rounded-panel border border-border p-comfortable" aria-labelledby="pqc-migration-heading">
      <div>
        <h3 id="pqc-migration-heading" className="font-semibold">
          {t("posture.pqcMigration.heading")}
        </h3>
        <p className="mt-1 text-sm text-muted-foreground">{t("posture.pqcMigration.description")}</p>
      </div>

      <OperationNotice action={planAuthority} />
      {planAuthority.runnable && vulnerable.length === 0 ? <p className="text-sm text-muted-foreground">{t("posture.pqcMigration.noAssets")}</p> : null}
      {planAuthority.runnable && vulnerable.length > 0 ? (
        <>
          <fieldset className="grid gap-2">
            <legend className="text-sm font-medium">{t("posture.pqcMigration.selectLegend")}</legend>
            {vulnerable.map((asset) => (
              <label key={asset.id} className="flex items-start gap-2 rounded-control border border-border p-3">
                <input
                  type="checkbox"
                  checked={selected.has(asset.id)}
                  disabled={busy !== null}
                  onChange={() => toggle(asset.id)}
                  aria-label={t("posture.pqcMigration.selectAsset", { location: findingLabel(asset) })}
                />
                <span>
                  <span className="block font-medium">{asset.location}</span>
                  <span className="text-xs text-muted-foreground">
                    {asset.protocol || asset.cipher || asset.algorithm} → {migrationTarget(asset)}
                  </span>
                </span>
              </label>
            ))}
          </fieldset>

          {tlsAssets.length > 0 ? (
            <fieldset className="grid gap-3 rounded-control border border-border p-3">
              <legend className="text-sm font-medium">{t("posture.pqcMigration.tlsBindingLegend")}</legend>
              <p className="text-sm text-muted-foreground">{t("posture.pqcMigration.tlsBindingHelp")}</p>
              {targets.loading ? <p role="status">{t("posture.pqcMigration.targetsLoading")}</p> : null}
              {targets.error ? (
                <p role="alert" className="text-sm text-destructive">
                  {targets.error}
                </p>
              ) : null}
              {!targets.loading && !targets.error && enabledTargets.length === 0 ? <p role="status">{t("posture.pqcMigration.noTargets")}</p> : null}
              {tlsAssets.map((asset) => (
                <label key={asset.id} className="grid gap-1 text-sm">
                  <span>{t("posture.pqcMigration.targetForAsset", { location: findingLabel(asset) })}</span>
                  <select
                    className="rounded-control border border-border bg-background p-2"
                    value={targetIds[asset.id] ?? ""}
                    disabled={busy !== null}
                    onChange={(event) => {
                      setTargetIds((current) => ({ ...current, [asset.id]: event.target.value }));
                      clearReview();
                    }}
                  >
                    <option value="">{t("posture.pqcMigration.chooseTarget")}</option>
                    {enabledTargets.map((target) => (
                      <option key={target.id} value={target.id}>
                        {target.name} ({target.id})
                      </option>
                    ))}
                  </select>
                </label>
              ))}
              <p className="text-sm">{t("posture.pqcMigration.minimumVersion")}</p>
              <p className="text-sm text-muted-foreground">{t("posture.pqcMigration.cipherSuites")}</p>
              <label className="grid gap-1 text-sm">
                <span>{t("posture.pqcMigration.keyExchangeGroups")}</span>
                <input
                  className="rounded-control border border-border bg-background p-2"
                  value={groups}
                  disabled={busy !== null}
                  onChange={(event) => {
                    setGroups(event.target.value);
                    clearReview();
                  }}
                />
              </label>
            </fieldset>
          ) : null}

          <div className="flex flex-wrap items-center gap-3">
            <Button type="button" onClick={() => void preview()} disabled={selectedIds.length === 0 || !tlsReady || busy !== null}>
              {busy === "plan" ? t("posture.pqcMigration.previewing") : t("posture.pqcMigration.preview")}
            </Button>
            <span className="text-sm text-muted-foreground">{t("posture.pqcMigration.selectedCount", { count: String(selectedIds.length) })}</span>
          </div>
        </>
      ) : null}

      {plan ? (
        <section className="grid gap-3 rounded-control border border-border p-3" aria-labelledby="pqc-plan-heading">
          <h4 id="pqc-plan-heading" className="font-medium">
            {t("posture.pqcMigration.planHeading")}
          </h4>
          <dl className="grid gap-2 text-sm sm:grid-cols-3">
            <div>
              <dt className="text-muted-foreground">{t("posture.pqcMigration.reissues")}</dt>
              <dd>{plan.reissue_count}</dd>
            </div>
            <div>
              <dt className="text-muted-foreground">{t("posture.pqcMigration.tlsRollouts")}</dt>
              <dd>{plan.tls_rollout_count}</dd>
            </div>
            <div>
              <dt className="text-muted-foreground">{t("posture.pqcMigration.residuals")}</dt>
              <dd>{plan.residuals.length}</dd>
            </div>
          </dl>
          {plan.residuals.length > 0 ? (
            <ul className="list-disc pl-5 text-sm">
              {plan.residuals.map((item) => (
                <li key={item.id}>
                  {item.id}: {item.reason}
                </li>
              ))}
            </ul>
          ) : null}
          <label className="flex items-start gap-2 text-sm">
            <input type="checkbox" checked={confirmed} onChange={(event) => setConfirmed(event.target.checked)} />
            <span>{t("posture.pqcMigration.startConfirmation")}</span>
          </label>
          <OperationNotice action={startAuthority} />
          <Button type="button" onClick={() => void start()} disabled={!startAuthority.runnable || !confirmed || busy !== null}>
            {busy === "start" ? t("posture.pqcMigration.starting") : t("posture.pqcMigration.start")}
          </Button>
        </section>
      ) : null}

      {run ? (
        <section className="grid gap-3 rounded-control border border-border p-3" aria-labelledby="pqc-run-heading">
          <h4 id="pqc-run-heading" className="font-medium">
            {t("posture.pqcMigration.progressHeading", { runId: run.run_id })}
          </h4>
          {progress ? (
            <PQCMigrationProgressDetails progress={progress} assets={assets} loading={busy === "progress"} />
          ) : (
            <p className="text-sm">{t("posture.pqcMigration.progressNotLoaded")}</p>
          )}
          <OperationNotice action={progressAuthority} />
          <Button type="button" variant="outline" onClick={() => void refresh()} disabled={!progressAuthority.runnable || busy !== null}>
            {busy === "progress" ? t("posture.pqcMigration.refreshing") : t("posture.pqcMigration.refresh")}
          </Button>
          <label className="flex items-start gap-2 text-sm">
            <input type="checkbox" checked={rollbackConfirmed} onChange={(event) => setRollbackConfirmed(event.target.checked)} />
            <span>{t("posture.pqcMigration.rollbackConfirmation")}</span>
          </label>
          <OperationNotice action={rollbackAuthority} />
          <Button type="button" variant="outline" onClick={() => void rollback()} disabled={!rollbackAuthority.runnable || !rollbackConfirmed || busy !== null}>
            {busy === "rollback" ? t("posture.pqcMigration.rollingBack") : t("posture.pqcMigration.rollback")}
          </Button>
        </section>
      ) : null}

      {result ? <p role="status">{result}</p> : null}
      {error ? (
        <p role="alert" className="text-sm text-destructive">
          {error}
        </p>
      ) : null}
    </section>
  );
}
