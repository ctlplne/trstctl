import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { useTranslation } from "@/i18n/I18nProvider";
import {
  api,
  type CBOMAsset,
  type EditionFeature,
  type PQCMigrationPlan,
  type PQCMigrationProgress,
  type PQCMigrationRequest,
  type PQCMigrationRun,
} from "@/lib/api";

const pqcTargetAlgorithm = "ML-DSA-65";

const requestFor = (assetIds: string[]): PQCMigrationRequest => ({
  asset_ids: assetIds,
  target_algorithm: pqcTargetAlgorithm,
  protocol: "acme",
  rollback_on_failure: true,
});

export function PQCMigrationWorkflow({ assets }: { assets: CBOMAsset[] }) {
  const { t } = useTranslation();
  const [feature, setFeature] = useState<EditionFeature | null>(null);
  const [editionLoading, setEditionLoading] = useState(true);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [plan, setPlan] = useState<PQCMigrationPlan | null>(null);
  const [run, setRun] = useState<PQCMigrationRun | null>(null);
  const [progress, setProgress] = useState<PQCMigrationProgress | null>(null);
  const [confirmed, setConfirmed] = useState(false);
  const [rollbackConfirmed, setRollbackConfirmed] = useState(false);
  const [busy, setBusy] = useState<"plan" | "start" | "progress" | "rollback" | null>(null);
  const [result, setResult] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const vulnerable = useMemo(() => assets.filter((asset) => asset.quantum_vulnerable || asset.out_of_policy), [assets]);
  const selectedIds = vulnerable.filter((asset) => selected.has(asset.id)).map((asset) => asset.id);
  const enabled = feature?.licensed === true && feature.mode === "enabled";

  useEffect(() => {
    let cancelled = false;
    setEditionLoading(true);
    void api
      .editions()
      .then((info) => {
        if (!cancelled) setFeature(info.features.find((item) => item.name === "pqc") ?? null);
      })
      .catch(() => {
        if (!cancelled) setFeature(null);
      })
      .finally(() => {
        if (!cancelled) setEditionLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  function toggle(assetId: string) {
    setSelected((current) => {
      const next = new Set(current);
      if (next.has(assetId)) next.delete(assetId);
      else next.add(assetId);
      return next;
    });
    setPlan(null);
    setConfirmed(false);
    setResult(null);
    setError(null);
  }

  async function preview() {
    if (selectedIds.length === 0) return;
    setBusy("plan");
    setError(null);
    setResult(null);
    try {
      setPlan(await api.planPQCMigration(requestFor(selectedIds)));
      setConfirmed(false);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : t("posture.pqcMigration.error"));
    } finally {
      setBusy(null);
    }
  }

  async function start() {
    if (!plan || !confirmed || selectedIds.length === 0) return;
    setBusy("start");
    setError(null);
    setResult(null);
    try {
      const next = await api.startPQCMigration(requestFor(selectedIds));
      setRun(next);
      setProgress(null);
      setResult(t("posture.pqcMigration.runQueued", { runId: next.run_id }));
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : t("posture.pqcMigration.error"));
    } finally {
      setBusy(null);
    }
  }

  async function refresh() {
    if (!run) return;
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
    if (!run || !rollbackConfirmed || selectedIds.length === 0) return;
    setBusy("rollback");
    setError(null);
    setResult(null);
    try {
      const response = await api.rollbackPQCMigration(run.run_id, selectedIds, t("posture.pqcMigration.rollbackReason"));
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

      {editionLoading ? <p role="status">{t("posture.pqcMigration.checkingEdition")}</p> : null}

      {!editionLoading && !enabled ? (
        <div className="rounded-control border border-border bg-muted/30 p-3" role="note">
          <p className="font-medium">{t("posture.pqcMigration.unavailableHeading")}</p>
          <p className="mt-1 text-sm text-muted-foreground">
            {feature?.mode === "read_only" ? t("posture.pqcMigration.readOnlyBody") : t("posture.pqcMigration.communityBody")}
          </p>
          <Link className="mt-2 inline-block text-sm underline" to="/admin/editions">
            {t("posture.pqcMigration.editionsLink")}
          </Link>
        </div>
      ) : null}

      {!editionLoading && enabled && vulnerable.length === 0 ? <p className="text-sm text-muted-foreground">{t("posture.pqcMigration.noAssets")}</p> : null}

      {!editionLoading && enabled && vulnerable.length > 0 ? (
        <>
          <fieldset className="grid gap-2">
            <legend className="text-sm font-medium">{t("posture.pqcMigration.selectLegend")}</legend>
            {vulnerable.map((asset) => (
              <label key={asset.id} className="flex items-start gap-2 rounded-control border border-border p-3">
                <input
                  type="checkbox"
                  checked={selected.has(asset.id)}
                  onChange={() => toggle(asset.id)}
                  aria-label={t("posture.pqcMigration.selectAsset", { location: asset.location })}
                />
                <span>
                  <span className="block font-medium">{asset.location}</span>
                  <span className="text-xs text-muted-foreground">
                    {asset.algorithm} → {asset.migration_target || pqcTargetAlgorithm}
                  </span>
                </span>
              </label>
            ))}
          </fieldset>

          <div className="flex flex-wrap items-center gap-3">
            <Button type="button" onClick={() => void preview()} disabled={selectedIds.length === 0 || busy !== null}>
              {busy === "plan" ? t("posture.pqcMigration.previewing") : t("posture.pqcMigration.preview")}
            </Button>
            <span className="text-sm text-muted-foreground">{t("posture.pqcMigration.selectedCount", { count: String(selectedIds.length) })}</span>
          </div>

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
              <Button type="button" onClick={() => void start()} disabled={!confirmed || busy !== null}>
                {busy === "start" ? t("posture.pqcMigration.starting") : t("posture.pqcMigration.start")}
              </Button>
            </section>
          ) : null}

          {run ? (
            <section className="grid gap-3 rounded-control border border-border p-3" aria-labelledby="pqc-run-heading">
              <h4 id="pqc-run-heading" className="font-medium">
                {t("posture.pqcMigration.progressHeading", { runId: run.run_id })}
              </h4>
              <p className="text-sm">
                {progress
                  ? t("posture.pqcMigration.progressSummary", {
                      applied: String(progress.applied),
                      queued: String(progress.queued),
                      failed: String(progress.failed),
                      rolledBack: String(progress.rolled_back),
                    })
                  : t("posture.pqcMigration.progressNotLoaded")}
              </p>
              <Button type="button" variant="outline" onClick={() => void refresh()} disabled={busy !== null}>
                {busy === "progress" ? t("posture.pqcMigration.refreshing") : t("posture.pqcMigration.refresh")}
              </Button>
              <label className="flex items-start gap-2 text-sm">
                <input type="checkbox" checked={rollbackConfirmed} onChange={(event) => setRollbackConfirmed(event.target.checked)} />
                <span>{t("posture.pqcMigration.rollbackConfirmation")}</span>
              </label>
              <Button type="button" variant="outline" onClick={() => void rollback()} disabled={!rollbackConfirmed || busy !== null}>
                {busy === "rollback" ? t("posture.pqcMigration.rollingBack") : t("posture.pqcMigration.rollback")}
              </Button>
            </section>
          ) : null}
        </>
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
