import { useEffect, useMemo, useState } from "react";
import { Eye, RotateCcw } from "lucide-react";
import { CapabilityActionNotice } from "@/components/CapabilityTruth";
import { EmptyState } from "@/components/EmptyState";
import { ErrorState, LoadingState } from "@/components/StatePrimitives";
import { Button } from "@/components/ui/button";
import { useTranslation } from "@/i18n/I18nProvider";
import { api, type DiscoveryPlanPreview, type DiscoveryRun, type DiscoverySource } from "@/lib/api";
import { useCapabilityExecution } from "@/lib/capabilities";

interface DriftRecoveryWorkflowProps {
  sources: DiscoverySource[];
  runs: DiscoveryRun[];
  loading: boolean;
  error: string | null;
}

/** F18 recovery starts with the server's exact, effect-free plan. The browser
 * never reconstructs watched paths from source.config and never reveals stored
 * fingerprints. A retry is a new run linked to an immutable failed run. */
export function DriftRecoveryWorkflow({ sources, runs, loading, error }: DriftRecoveryWorkflowProps) {
  const { t } = useTranslation();
  const driftSources = useMemo(() => sources.filter((source) => source.kind === "drift"), [sources]);

  if (loading) return <LoadingState>{t("posture.driftRecovery.loading")}</LoadingState>;
  if (error) return <ErrorState title={t("posture.driftRecovery.loadFailed")}>{error}</ErrorState>;
  if (driftSources.length === 0) {
    return (
      <EmptyState title={t("posture.driftRecovery.emptyTitle")} headingAs="h3" className="rounded-panel">
        {t("posture.driftRecovery.emptyBody")}
      </EmptyState>
    );
  }

  return (
    <section aria-labelledby="drift-recovery-heading" className="grid gap-3 rounded-panel border border-border bg-card/45 p-comfortable">
      <div>
        <h3 id="drift-recovery-heading" className="text-title font-semibold">
          {t("posture.driftRecovery.title")}
        </h3>
        <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{t("posture.driftRecovery.description")}</p>
      </div>
      <div className="grid gap-3">
        {driftSources.map((source) => (
          <DriftRecoveryCard key={source.id} source={source} latestRun={latestRunForSource(runs, source.id)} />
        ))}
      </div>
    </section>
  );
}

function DriftRecoveryCard({ source, latestRun }: { source: DiscoverySource; latestRun: DiscoveryRun | null }) {
  const { t } = useTranslation();
  const previewAction = useCapabilityExecution("F18", "preflightDiscoverySource");
  const retryAction = useCapabilityExecution("F18", "retryDiscoveryRun");
  const [preview, setPreview] = useState<DiscoveryPlanPreview | null>(null);
  const [previewing, setPreviewing] = useState(false);
  const [retrying, setRetrying] = useState(false);
  const [problem, setProblem] = useState<string | null>(null);
  const [result, setResult] = useState<string | null>(null);

  const retryableRun = latestRun && (latestRun.status === "failed" || latestRun.status === "partial") ? latestRun : null;

  useEffect(() => {
    setPreview(null);
    setProblem(null);
    setResult(null);
  }, [source.id, source.updated_at, retryableRun?.id]);

  async function reviewPlan() {
    setPreviewing(true);
    setProblem(null);
    setResult(null);
    setPreview(null);
    try {
      const next = await api.preflightDiscoverySource(source.id);
      if (next.ready !== true || next.side_effects || next.blocked_reasons.length > 0) {
        setProblem(next.blocked_reasons.join(" ") || t("posture.driftRecovery.notReady"));
        return;
      }
      setPreview(next);
    } catch (caught) {
      setProblem(caught instanceof Error ? caught.message : t("posture.driftRecovery.previewFailed"));
    } finally {
      setPreviewing(false);
    }
  }

  async function retryFailedRun() {
    if (!retryableRun || !preview) return;
    setRetrying(true);
    setProblem(null);
    setResult(null);
    try {
      const replacement = await api.retryDiscoveryRun(retryableRun.id);
      setResult(
        t("posture.driftRecovery.queued", {
          replacement: replacement.id,
          original: retryableRun.id,
        }),
      );
    } catch (caught) {
      setProblem(caught instanceof Error ? caught.message : t("posture.driftRecovery.retryFailed"));
    } finally {
      setRetrying(false);
    }
  }

  return (
    <article className="grid gap-3 border-t border-border pt-3 first:border-t-0 first:pt-0">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="font-medium text-foreground">{source.name}</p>
          <p className="mt-0.5 text-sm text-muted-foreground">
            {retryableRun
              ? t("posture.driftRecovery.failedRun", { run: retryableRun.id, status: retryableRun.status })
              : t("posture.driftRecovery.noFailedRun")}
          </p>
        </div>
        <Button
          type="button"
          variant="outline"
          onClick={reviewPlan}
          disabled={previewing || !previewAction.runnable || !retryableRun}
          aria-label={t("posture.driftRecovery.reviewAria", { source: source.name })}
        >
          <Eye className="h-4 w-4" aria-hidden="true" />
          {previewing ? t("posture.driftRecovery.reviewing") : t("posture.driftRecovery.review")}
        </Button>
      </div>

      <CapabilityActionNotice action={previewAction} />
      {problem ? <ErrorState title={t("posture.driftRecovery.blocked")}>{problem}</ErrorState> : null}
      {result ? <p className="text-sm font-medium text-status-success">{result}</p> : null}

      {preview && retryableRun ? (
        <section aria-label={t("posture.driftRecovery.planAria")} className="grid gap-3 rounded-control border border-border bg-background/70 p-3">
          <dl className="grid gap-3 text-sm sm:grid-cols-2 lg:grid-cols-3">
            <PlanFact label={t("posture.driftRecovery.source")} value={source.name} />
            <PlanFact label={t("posture.driftRecovery.originalRun")} value={retryableRun.id} mono />
            <PlanFact label={t("posture.driftRecovery.runState")} value={retryableRun.status} />
            <PlanFact label={t("posture.driftRecovery.execution")} value={preview.execution} />
            <PlanFact label={t("posture.driftRecovery.origin")} value={preview.connection_origin} />
            <PlanFact label={t("posture.driftRecovery.permission")} value={preview.permission} mono />
            <PlanFact
              label={t("posture.driftRecovery.boundedWork")}
              value={t("posture.driftRecovery.boundedWorkValue", { workers: preview.concurrency, queue: preview.queue_depth })}
            />
            <PlanFact label={t("posture.driftRecovery.externalEffects")} value={t("posture.driftRecovery.noEffects")} />
            <PlanFact label={t("posture.driftRecovery.dataHandling")} value={preview.data_handling} />
          </dl>
          <div>
            <p className="text-xs font-medium text-muted-foreground">{t("posture.driftRecovery.watched", { count: preview.normalized_target_count })}</p>
            <ul className="mt-1 grid gap-1 font-mono text-xs text-foreground">
              {(preview.normalized_targets ?? []).map((target) => (
                <li key={target} className="break-all">
                  {target}
                </li>
              ))}
            </ul>
          </div>
          <p className="text-sm text-muted-foreground">{t("posture.driftRecovery.noRetryQueued")}</p>
          <CapabilityActionNotice action={retryAction} />
          <div>
            <Button
              type="button"
              onClick={retryFailedRun}
              disabled={retrying || !retryAction.runnable || result !== null}
              aria-label={t("posture.driftRecovery.retryAria", { run: retryableRun.id })}
            >
              <RotateCcw className="h-4 w-4" aria-hidden="true" />
              {retrying ? t("posture.driftRecovery.retrying") : t("posture.driftRecovery.retry")}
            </Button>
          </div>
        </section>
      ) : null}
    </article>
  );
}

function latestRunForSource(runs: DiscoveryRun[], sourceID: string): DiscoveryRun | null {
  return runs.filter((run) => run.source_id === sourceID).sort((left, right) => Date.parse(right.created_at) - Date.parse(left.created_at))[0] ?? null;
}

function PlanFact({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="min-w-0">
      <dt className="text-xs font-medium text-muted-foreground">{label}</dt>
      <dd className={`mt-0.5 break-words text-foreground ${mono ? "font-mono text-xs" : ""}`}>{value}</dd>
    </div>
  );
}
