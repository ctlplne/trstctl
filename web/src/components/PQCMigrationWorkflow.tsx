import { useMemo, useState } from "react";
import { PQCMigrationProgressDetails } from "@/components/PQCMigrationProgressDetails";
import { Button } from "@/components/ui/button";
import { useTranslation } from "@/i18n/I18nProvider";
import { api, type CBOMAsset, type PQCMigrationPlan, type PQCMigrationProgress, type PQCMigrationRequest } from "@/lib/api";
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

const requestFor = (
  assetIds: string[],
  tlsAssets: CBOMAsset[],
  certAssets: CBOMAsset[],
  targetIds: Record<string, string>,
  identityIds: Record<string, string>,
  groups: string,
): PQCMigrationRequest => ({
  asset_ids: assetIds,
  target_algorithm: pqcTargetAlgorithm,
  protocol: certAssets.length > 0 ? "host-csr" : "acme",
  rollback_on_failure: true,
  ...(certAssets.length > 0
    ? {
        certificate_bindings: certAssets.map((asset) => ({
          asset_id: asset.id,
          target_id: targetIds[asset.id],
          identity_id: identityIds[asset.id],
        })),
      }
    : {}),
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
  const [identityIds, setIdentityIds] = useState<Record<string, string>>({});
  const [groups, setGroups] = useState("X25519MLKEM768, X25519");
  const [plan, setPlan] = useState<PQCMigrationPlan | null>(null);
  const [reviewedRequest, setReviewedRequest] = useState<PQCMigrationRequest | null>(null);
  const [runId, setRunId] = useState<string | null>(null);
  const [lookupId, setLookupId] = useState("");
  const [runAssetIds, setRunAssetIds] = useState<string[]>([]);
  const [progress, setProgress] = useState<PQCMigrationProgress | null>(null);
  const [confirmed, setConfirmed] = useState(false);
  const [rollbackConfirmed, setRollbackConfirmed] = useState(false);
  const [busy, setBusy] = useState<"plan" | "start" | "progress" | "rollback" | "load" | null>(null);
  const [result, setResult] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const vulnerable = useMemo(
    () => assets.filter((asset) => asset.quantum_vulnerable || asset.out_of_policy || (asset.kind === "tls-endpoint" && asset.protocol === "TLSv1.2")),
    [assets],
  );
  const selectedIds = vulnerable.filter((asset) => selected.has(asset.id)).map((asset) => asset.id);
  const tlsAssets = vulnerable.filter((asset) => selected.has(asset.id) && (asset.kind === "host-config" || asset.kind === "tls-endpoint"));
  const certAssets = vulnerable.filter((asset) => selected.has(asset.id) && asset.kind === "certificate-key");
  const targets = useApiQuery(["pqc-migration-targets"], api.connectorTargets, { enabled: tlsAssets.length + certAssets.length > 0, retry: false });
  const identities = useApiQuery(["pqc-migration-identities"], api.identities, { enabled: certAssets.length > 0, retry: false });
  const enabledTargets = targets.data?.items.filter((target) => target.enabled && target.connector === "envoy") ?? [];
  const certificateTargets =
    targets.data?.items.filter(
      (target) =>
        target.enabled &&
        ["apache", "nginx", "caddy", "elasticsearch", "mysql", "postgresql", "rabbitmq", "tomcat", "traefik"].includes(target.connector) &&
        target.config?.executor === "agent" &&
        typeof target.config?.cert_path === "string" &&
        typeof target.config?.key_path === "string",
    ) ?? [];
  const requestedIdentities =
    identities.data?.filter(
      (identity) => identity.kind === "x509_certificate" && identity.status === "requested" && identity.attributes?.subject_key_algorithm === "ML-DSA-65",
    ) ?? [];
  const tlsReady =
    tlsAssets.length === 0 ||
    (!targets.loading &&
      !targets.error &&
      tlsAssets.every((asset) => enabledTargets.some((target) => target.id === targetIds[asset.id])) &&
      splitList(groups).some((group) => group.toUpperCase() === "X25519MLKEM768"));
  const certReady =
    certAssets.length === 0 ||
    (!targets.loading &&
      !targets.error &&
      !identities.loading &&
      !identities.error &&
      certAssets.every((asset) => {
        const target = certificateTargets.find((item) => item.id === targetIds[asset.id]);
        const identity = requestedIdentities.find((item) => item.id === identityIds[asset.id]);
        return (
          !!target &&
          !!identity &&
          identity.attributes?.deployment_target_id === target.id &&
          target.config?.verify_address === asset.location &&
          target.config?.verify_server_name === identity.name
        );
      }));
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
      const request = requestFor(selectedIds, tlsAssets, certAssets, targetIds, identityIds, groups);
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
      setRunId(next.run_id);
      setLookupId(next.run_id);
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
    if (!progressAuthority.runnable || !runId) return;
    setBusy("progress");
    setError(null);
    try {
      const current = await api.getPQCMigrationProgress(runId);
      setProgress(current);
      setRunAssetIds(current.findings.filter((finding) => finding.status === "applied").map((finding) => finding.asset_id));
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : t("posture.pqcMigration.error"));
    } finally {
      setBusy(null);
    }
  }

  async function loadRun() {
    const id = lookupId.trim();
    if (!progressAuthority.runnable || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id)) return;
    setBusy("load");
    setError(null);
    try {
      const current = await api.getPQCMigrationProgress(id);
      if (current.run_id !== id) throw new Error(t("posture.pqcMigration.runMismatch"));
      setRunId(id);
      setProgress(current);
      setRunAssetIds(current.findings.filter((finding) => finding.status === "applied").map((finding) => finding.asset_id));
      setRollbackConfirmed(false);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : t("posture.pqcMigration.error"));
    } finally {
      setBusy(null);
    }
  }

  async function rollback() {
    if (!rollbackAuthority.runnable || !runId || !progress || !rollbackConfirmed || runAssetIds.length === 0) return;
    setBusy("rollback");
    setError(null);
    setResult(null);
    try {
      const response = await api.rollbackPQCMigration(runId, runAssetIds, t("posture.pqcMigration.rollbackReason"));
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

          {certAssets.length > 0 ? (
            <fieldset className="grid gap-3 rounded-control border border-border p-3">
              <legend className="text-sm font-medium">{t("posture.pqcMigration.certBindingLegend")}</legend>
              <p className="text-sm text-muted-foreground">{t("posture.pqcMigration.certBindingHelp")}</p>
              {targets.loading || identities.loading ? <p role="status">{t("posture.pqcMigration.certBindingsLoading")}</p> : null}
              {targets.error || identities.error ? (
                <p role="alert" className="text-sm text-destructive">
                  {targets.error || identities.error}
                </p>
              ) : null}
              {certAssets.map((asset) => (
                <div key={asset.id} className="grid gap-2 rounded-control border border-border p-3">
                  <p className="text-sm font-medium">{findingLabel(asset)}</p>
                  <label className="grid gap-1 text-sm">
                    <span>{t("posture.pqcMigration.targetForAsset", { location: findingLabel(asset) })}</span>
                    <select
                      className="rounded-control border border-border bg-background p-2"
                      value={targetIds[asset.id] ?? ""}
                      disabled={busy !== null}
                      onChange={(event) => {
                        setTargetIds((current) => ({ ...current, [asset.id]: event.target.value }));
                        setIdentityIds((current) => ({ ...current, [asset.id]: "" }));
                        clearReview();
                      }}
                    >
                      <option value="">{t("posture.pqcMigration.chooseTarget")}</option>
                      {certificateTargets
                        .filter((target) => target.config?.verify_address === asset.location)
                        .map((target) => (
                          <option key={target.id} value={target.id}>
                            {target.name} ({target.id})
                          </option>
                        ))}
                    </select>
                  </label>
                  <label className="grid gap-1 text-sm">
                    <span>{t("posture.pqcMigration.identityForAsset", { location: findingLabel(asset) })}</span>
                    <select
                      className="rounded-control border border-border bg-background p-2"
                      value={identityIds[asset.id] ?? ""}
                      disabled={busy !== null || !targetIds[asset.id]}
                      onChange={(event) => {
                        setIdentityIds((current) => ({ ...current, [asset.id]: event.target.value }));
                        clearReview();
                      }}
                    >
                      <option value="">{t("posture.pqcMigration.chooseIdentity")}</option>
                      {requestedIdentities
                        .filter((identity) => identity.attributes?.deployment_target_id === targetIds[asset.id])
                        .map((identity) => (
                          <option key={identity.id} value={identity.id}>
                            {identity.name} ({identity.id})
                          </option>
                        ))}
                    </select>
                  </label>
                </div>
              ))}
            </fieldset>
          ) : null}

          <div className="flex flex-wrap items-center gap-3">
            <Button type="button" onClick={() => void preview()} disabled={selectedIds.length === 0 || !tlsReady || !certReady || busy !== null}>
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

      <div className="grid gap-2 rounded-control border border-border p-3 sm:grid-cols-[minmax(0,1fr)_auto] sm:items-end">
        <label className="grid gap-1 text-sm">
          <span>{t("posture.pqcMigration.loadRunLabel")}</span>
          <input
            className="rounded-control border border-border bg-background p-2"
            value={lookupId}
            onChange={(event) => setLookupId(event.target.value)}
            placeholder={t("posture.pqcMigration.loadRunPlaceholder")}
          />
        </label>
        <Button
          type="button"
          variant="outline"
          onClick={() => void loadRun()}
          disabled={!progressAuthority.runnable || busy !== null || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(lookupId.trim())}
        >
          {busy === "load" ? t("posture.pqcMigration.refreshing") : t("posture.pqcMigration.loadRun")}
        </Button>
      </div>

      {runId ? (
        <section className="grid gap-3 rounded-control border border-border p-3" aria-labelledby="pqc-run-heading">
          <h4 id="pqc-run-heading" className="font-medium">
            {t("posture.pqcMigration.progressHeading", { runId })}
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
          <Button
            type="button"
            variant="outline"
            onClick={() => void rollback()}
            disabled={!rollbackAuthority.runnable || !rollbackConfirmed || !progress || runAssetIds.length === 0 || busy !== null}
          >
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
