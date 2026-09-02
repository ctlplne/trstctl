import { useMemo, useState, type ReactNode } from "react";
import { Database, FileSearch, Network, RotateCcw, ShieldCheck } from "lucide-react";
import { ErrorState, LoadingState } from "@/components/StatePrimitives";
import { StepShell, type CarouselStep } from "@/components/wizard/StepShell";
import { Button } from "@/components/ui/button";
import { Field } from "@/components/ui/field";
import { Textarea } from "@/components/ui/textarea";
import { useTranslation } from "@/i18n/I18nProvider";
import { api, type CBOMInventory, type CBOMScan, type CBOMScanPreview, type CBOMScanRequest } from "@/lib/api";
import { apiProblemMessage } from "@/lib/apiProblem";

type ReviewedPlan = { key: string; value: CBOMScanPreview };
type VerifiedInventory = {
  assets: CBOMInventory["items"];
  migrationTargets: number;
};

export function CBOMScanWorkflow({ onCompleted }: { onCompleted: (scan: CBOMScan, inventory: CBOMInventory) => void }) {
  const { t } = useTranslation();
  const [step, setStep] = useState(0);
  const [tlsText, setTLSText] = useState("");
  const [hostText, setHostText] = useState("");
  const [reviewed, setReviewed] = useState<ReviewedPlan | null>(null);
  const [result, setResult] = useState<CBOMScan | null>(null);
  const [verifiedInventory, setVerifiedInventory] = useState<VerifiedInventory | null>(null);
  const [previewing, setPreviewing] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [previewError, setPreviewError] = useState<string | null>(null);
  const [scanError, setScanError] = useState<string | null>(null);

  const request = useMemo<CBOMScanRequest>(() => {
    const tlsEndpoints = linesFromText(tlsText);
    const hostConfigs = linesFromText(hostText);
    return {
      ...(tlsEndpoints.length > 0 ? { tls_endpoints: tlsEndpoints } : {}),
      ...(hostConfigs.length > 0 ? { host_configs: hostConfigs } : {}),
    };
  }, [hostText, tlsText]);
  const requestKey = JSON.stringify(request);
  const exactPlan = reviewed?.key === requestKey ? reviewed.value : null;
  const steps = useMemo<CarouselStep[]>(
    () => [
      { id: "scope", label: t("posture.cbom.workflow.scope"), description: t("posture.cbom.workflow.scopeBody") },
      { id: "review", label: t("posture.cbom.workflow.review"), description: t("posture.cbom.workflow.reviewBody") },
      { id: "result", label: t("posture.cbom.workflow.result"), description: t("posture.cbom.workflow.resultBody") },
    ],
    [t],
  );

  function updateTLS(value: string) {
    setTLSText(value);
    invalidatePlan();
  }

  function updateHosts(value: string) {
    setHostText(value);
    invalidatePlan();
  }

  function invalidatePlan() {
    setReviewed(null);
    setResult(null);
    setVerifiedInventory(null);
    setPreviewError(null);
    setScanError(null);
  }

  async function preview() {
    setPreviewing(true);
    setPreviewError(null);
    setScanError(null);
    setStep(1);
    try {
      const value = await api.previewCBOMScan(request);
      setReviewed({ key: requestKey, value });
    } catch (error) {
      setReviewed(null);
      setPreviewError(apiProblemMessage(error, t("posture.cbom.workflow.previewFailedBody")));
    } finally {
      setPreviewing(false);
    }
  }

  async function scan() {
    if (!exactPlan?.ready || !exactPlan.effect_free) return;
    setScanning(true);
    setScanError(null);
    try {
      // Execute the server-normalized request shown in the review step. The
      // server rebuilds the same plan before it performs any read.
      const completed = await api.startCBOMScan(exactPlan.normalized_request);
      const inventory = await api.listCBOMAssets();
      const verification = verifyInventoryReadback(completed, inventory, t("posture.cbom.workflow.verifyFailed"));
      setResult(completed);
      setVerifiedInventory(verification);
      onCompleted(completed, inventory);
      setStep(2);
    } catch (error) {
      setScanError(apiProblemMessage(error, t("posture.cbom.workflow.scanFailedBody")));
    } finally {
      setScanning(false);
    }
  }

  function reset() {
    setStep(0);
    setTLSText("");
    setHostText("");
    setReviewed(null);
    setResult(null);
    setVerifiedInventory(null);
    setPreviewError(null);
    setScanError(null);
  }

  return (
    <StepShell
      steps={steps}
      currentIndex={step}
      progressLabel={t("posture.cbom.workflow.progress")}
      onPrevious={step === 1 && !previewing && !scanning ? () => setStep(0) : undefined}
      onNext={step === 0 ? () => void preview() : undefined}
      nextDisabled={previewing || scanning || (linesFromText(tlsText).length === 0 && linesFromText(hostText).length === 0)}
      nextLabel={t("posture.cbom.workflow.previewAction")}
    >
      {step === 0 ? (
        <div className="grid gap-4 md:grid-cols-2">
          <Field label={t("posture.cbom.workflow.tlsLabel")} description={t("posture.cbom.workflow.tlsHelp")}>
            {(control) => (
              <Textarea
                {...control}
                value={tlsText}
                onChange={(event) => updateTLS(event.target.value)}
                className="min-h-28 font-mono text-xs"
                placeholder={t("posture.cbom.workflow.tlsPlaceholder")}
                spellCheck={false}
              />
            )}
          </Field>
          <Field label={t("posture.cbom.workflow.hostLabel")} description={t("posture.cbom.workflow.hostHelp")}>
            {(control) => (
              <Textarea
                {...control}
                value={hostText}
                onChange={(event) => updateHosts(event.target.value)}
                className="min-h-28 font-mono text-xs"
                placeholder={t("posture.cbom.workflow.hostPlaceholder")}
                spellCheck={false}
              />
            )}
          </Field>
          <p className="md:col-span-2 text-sm text-muted-foreground">{t("posture.cbom.workflow.scopeSafety")}</p>
        </div>
      ) : null}

      {step === 1 ? (
        <div className="grid gap-4">
          {previewing ? <LoadingState>{t("posture.cbom.workflow.previewing")}</LoadingState> : null}
          {previewError ? (
            <ErrorState title={t("posture.cbom.workflow.previewFailedTitle")}>
              <p>{previewError}</p>
              <Button className="mt-3" type="button" size="sm" variant="outline" onClick={() => void preview()}>
                <RotateCcw className="h-4 w-4" aria-hidden="true" />
                {t("posture.cbom.workflow.retryPreview")}
              </Button>
            </ErrorState>
          ) : null}
          {exactPlan ? <CBOMPlanReview plan={exactPlan} /> : null}
          {scanError ? (
            <ErrorState title={t("posture.cbom.workflow.scanFailedTitle")}>
              <p>{scanError}</p>
              {exactPlan?.recovery_steps?.length ? <PlanList title={t("posture.cbom.workflow.recovery")} items={exactPlan.recovery_steps} /> : null}
              <Button className="mt-3" type="button" size="sm" variant="outline" onClick={() => void scan()} disabled={scanning}>
                <RotateCcw className="h-4 w-4" aria-hidden="true" />
                {t("posture.cbom.workflow.retryScan")}
              </Button>
            </ErrorState>
          ) : null}
          <div className="flex justify-end">
            <Button type="button" onClick={() => void scan()} disabled={!exactPlan?.ready || !exactPlan.effect_free || scanning || previewing}>
              {scanning ? t("posture.cbom.workflow.scanning") : t("posture.cbom.workflow.scanAction")}
            </Button>
          </div>
        </div>
      ) : null}

      {step === 2 && result ? (
        <div className="grid gap-4">
          <section className="rounded-panel border border-status-success/35 bg-status-success/5 p-comfortable" aria-live="polite">
            <div className="flex items-start gap-3">
              <ShieldCheck className="mt-0.5 h-5 w-5 text-status-success" aria-hidden="true" />
              <div>
                <h3 className="font-semibold">{t("posture.cbom.workflow.completeTitle")}</h3>
                <p className="mt-1 text-sm text-muted-foreground">{t("posture.cbom.workflow.completeBody")}</p>
              </div>
            </div>
            <dl className="mt-4 grid gap-3 sm:grid-cols-3">
              <PlanFact label={t("posture.cbom.workflow.findings")} value={String(result.report.findings)} />
              <PlanFact label={t("posture.cbom.workflow.failed")} value={String(result.report.failed)} />
              <PlanFact label={t("posture.cbom.workflow.outOfPolicy")} value={String(result.report.out_of_policy)} />
            </dl>
          </section>
          {verifiedInventory ? <SavedInventoryVerification verification={verifiedInventory} /> : null}
          {result.report.failed > 0 && exactPlan?.recovery_steps?.length ? (
            <PlanList title={t("posture.cbom.workflow.partialRecovery")} items={exactPlan.recovery_steps} warning />
          ) : null}
          <div className="flex justify-end">
            <Button type="button" variant="outline" onClick={reset}>
              {t("posture.cbom.workflow.scanAnother")}
            </Button>
          </div>
        </div>
      ) : null}
    </StepShell>
  );
}

function verifyInventoryReadback(scan: CBOMScan, inventory: CBOMInventory, errorMessage: string): VerifiedInventory {
  const assets = inventory.items ?? [];
  const progress = inventory.migration_progress;
  const completeMetadata = assets.every((asset) => asset.id && asset.migration_target && asset.migration_standard && asset.migration_generation);
  const readbackContainsScan =
    progress.total_assets === assets.length &&
    progress.total_assets >= scan.migration_progress.total_assets &&
    (scan.report.findings === 0 || assets.length > 0);
  if (!completeMetadata || !readbackContainsScan) throw new Error(errorMessage);
  return {
    assets,
    migrationTargets: assets.filter((asset) => asset.migration_target.length > 0).length,
  };
}

function SavedInventoryVerification({ verification }: { verification: VerifiedInventory }) {
  const { t } = useTranslation();
  const visibleAssets = verification.assets.slice(0, 3);
  const hiddenAssets = verification.assets.length - visibleAssets.length;
  return (
    <section
      aria-label={t("posture.cbom.workflow.verifyRegionLabel")}
      className="grid gap-3 rounded-panel border border-status-success/35 bg-card p-comfortable"
    >
      <div className="flex items-start gap-3">
        <Database className="mt-0.5 h-5 w-5 text-status-success" aria-hidden="true" />
        <div>
          <h3 className="font-semibold">{t("posture.cbom.workflow.verifyTitle")}</h3>
          <p className="mt-1 text-sm text-muted-foreground">{t("posture.cbom.workflow.verifyBody")}</p>
        </div>
      </div>
      <dl className="grid gap-3 sm:grid-cols-2">
        <PlanFact label={t("posture.cbom.workflow.verifyAssets")} value={String(verification.assets.length)} />
        <PlanFact label={t("posture.cbom.workflow.verifyTargets")} value={String(verification.migrationTargets)} />
      </dl>
      {visibleAssets.length > 0 ? (
        <section className="border-s-2 border-border ps-3">
          <h4 className="text-sm font-semibold">{t("posture.cbom.workflow.verifyRecords")}</h4>
          <ul className="mt-1 space-y-1 text-xs text-muted-foreground">
            {visibleAssets.map((asset) => (
              <li className="break-all" key={asset.id}>
                <code>{asset.id}</code> · {asset.migration_target}
              </li>
            ))}
          </ul>
          {hiddenAssets > 0 ? <p className="mt-2 text-xs text-muted-foreground">{t("posture.cbom.workflow.verifyMore", { count: hiddenAssets })}</p> : null}
        </section>
      ) : (
        <p className="text-sm text-muted-foreground">{t("posture.cbom.workflow.verifyEmpty")}</p>
      )}
    </section>
  );
}

function CBOMPlanReview({ plan }: { plan: CBOMScanPreview }) {
  const { t } = useTranslation();
  return (
    <section aria-label={t("posture.cbom.workflow.planLabel")} className="grid gap-4 rounded-panel border border-border bg-muted/25 p-comfortable">
      <div className="flex items-start gap-3">
        <ShieldCheck className="mt-0.5 h-5 w-5 text-brand-accent" aria-hidden="true" />
        <div>
          <h3 className="font-semibold">{plan.ready ? t("posture.cbom.workflow.readyTitle") : t("posture.cbom.workflow.blockedTitle")}</h3>
          <p className="mt-1 text-sm text-muted-foreground">
            {plan.effect_free ? t("posture.cbom.workflow.effectFree") : t("posture.cbom.workflow.effectWarning")}
          </p>
        </div>
      </div>
      <dl className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <PlanFact icon={<Network />} label={t("posture.cbom.workflow.connections")} value={String(plan.tls_connection_limit)} />
        <PlanFact icon={<FileSearch />} label={t("posture.cbom.workflow.files")} value={String(plan.host_file_read_limit)} />
        <PlanFact icon={<Database />} label={t("posture.cbom.workflow.maxWrites")} value={String(plan.finding_write_limit)} />
        <PlanFact label={t("posture.cbom.workflow.workers")} value={String(plan.worker_limit)} />
        <PlanFact label={t("posture.cbom.workflow.timeout")} value={t("posture.cbom.workflow.seconds", { count: plan.per_endpoint_timeout_seconds })} />
        <PlanFact label={t("posture.cbom.workflow.signerCalls")} value={String(plan.signer_calls)} />
        <PlanFact label={t("posture.cbom.workflow.outboxCalls")} value={String(plan.outbox_calls)} />
        <PlanFact label={t("posture.cbom.workflow.queueDepth")} value={String(plan.queue_depth)} />
      </dl>
      <TargetList title={t("posture.cbom.workflow.normalizedTLS")} items={plan.normalized_request.tls_endpoints ?? []} />
      <TargetList title={t("posture.cbom.workflow.normalizedHosts")} items={plan.normalized_request.host_configs ?? []} />
      <PlanList title={t("posture.cbom.workflow.networkReads")} items={plan.outside_calls} />
      <PlanList title={t("posture.cbom.workflow.fileReads")} items={plan.host_reads} />
      <PlanList title={t("posture.cbom.workflow.writes")} items={plan.durable_writes} />
      <PlanList title={t("posture.cbom.workflow.safety")} items={plan.safety_notes} />
      {plan.blockers.length > 0 ? <PlanList title={t("posture.cbom.workflow.blockers")} items={plan.blockers} warning /> : null}
      <PlanList title={t("posture.cbom.workflow.recovery")} items={plan.recovery_steps} />
    </section>
  );
}

function PlanFact({ icon, label, value }: { icon?: ReactNode; label: string; value: string }) {
  return (
    <div className="min-w-0 border-s-2 border-border ps-3">
      <dt className="flex items-center gap-1.5 text-caption text-muted-foreground">
        {icon ? (
          <span className="[&>svg]:h-3.5 [&>svg]:w-3.5" aria-hidden="true">
            {icon}
          </span>
        ) : null}
        {label}
      </dt>
      <dd className="mt-0.5 break-words font-medium">{value}</dd>
    </div>
  );
}

function TargetList({ items, title }: { items: string[]; title: string }) {
  if (items.length === 0) return null;
  return (
    <section className="border-s-2 border-border ps-3">
      <h4 className="text-sm font-semibold">{title}</h4>
      <ul className="mt-1 space-y-1 font-mono text-xs text-muted-foreground">
        {items.map((item) => (
          <li className="break-all" key={item}>
            {item}
          </li>
        ))}
      </ul>
    </section>
  );
}

function PlanList({ items, title, warning = false }: { items: string[]; title: string; warning?: boolean }) {
  if (items.length === 0) return null;
  return (
    <section className={warning ? "rounded-control border border-status-warning/40 bg-status-warning/10 p-3" : "border-s-2 border-border ps-3"}>
      <h4 className="text-sm font-semibold">{title}</h4>
      <ol className="mt-1 list-decimal space-y-1 ps-5 text-sm text-muted-foreground">
        {items.map((item) => (
          <li key={item}>{item}</li>
        ))}
      </ol>
    </section>
  );
}

function linesFromText(value: string): string[] {
  return value
    .split(/[\n,]+/)
    .map((line) => line.trim())
    .filter(Boolean);
}
