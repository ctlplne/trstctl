import { useCallback, useEffect, useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { ArrowUpRight, Check, Copy, RefreshCw } from "lucide-react";
import { PageHeader } from "@/components/PageHeader";
import { StatusBadge } from "@/components/StatusBadge";
import { Button } from "@/components/ui/button";
import { StepShell, type CarouselStep } from "@/components/wizard/StepShell";
import { api } from "@/lib/api";
import { hasJourneyMark, readJourneyMarks, toggleJourneyMark } from "@/lib/journeyProgress";
import { journeyCensus } from "@/lib/journeyCensus.gen";
import { journeyById, journeyDocUrl, journeys, type Journey, type JourneyDetector, type JourneyStep } from "@/lib/journeys";
import { useTranslation } from "@/i18n/I18nProvider";
import { cn } from "@/lib/utils";

/** Each detector answers "has the tenant already done this?" from served data,
 * fail-closed to "not yet" so a flaky endpoint never fakes progress. */
const detectorRuns: Record<JourneyDetector, () => Promise<boolean>> = {
  issuers: () => api.issuers().then((rows) => rows.length > 0),
  requests: () => api.identities().then((rows) => rows.length > 0),
  certificates: () => api.certificatePage({ limit: 1 }).then((page) => (page.items ?? []).length > 0),
  sources: () => api.discoverySources({ limit: 1 }).then((page) => (page.items ?? []).length > 0),
  runs: () => api.discoveryRuns({ limit: 1 }).then((page) => (page.items ?? []).length > 0),
  findings: () => api.discoveryFindings({ limit: 1 }).then((page) => (page.items ?? []).length > 0),
  profiles: () => api.profiles().then((rows) => rows.length > 0),
  incidents: () => api.incidentExecutions({ limit: 1 }).then((page) => (page.items ?? []).length > 0),
  agents: () => api.agents().then((rows) => rows.length > 0),
  secrets: () => api.secretPage({ limit: 1 }).then((page) => (page.items ?? []).length > 0),
  members: () => api.members({ limit: 1 }).then((page) => (page.items ?? []).length > 0),
  audit: () => api.auditEvents({ limit: 1 }).then((rows) => rows.length > 0),
};

type DetectorState = Partial<Record<JourneyDetector, boolean>>;

/** A step counts as done when served data confirms it (detector) or, for the
 * command/config steps the console cannot observe, when the operator has
 * marked it done by hand. Progress is always out of every step. */
function stepDone(journey: Journey, step: JourneyStep, detected: DetectorState, marks: Set<string>): boolean {
  if (step.detect) return detected[step.detect] === true;
  return hasJourneyMark(marks, journey.id, step.id);
}

function journeyProgress(journey: Journey, detected: DetectorState, marks: Set<string>): { done: number; total: number } {
  const done = journey.steps.filter((step) => stepDone(journey, step, detected, marks)).length;
  return { done, total: journey.steps.length };
}

export function Journeys() {
  const { t, formatMessage } = useTranslation();
  const [searchParams, setSearchParams] = useSearchParams();
  const active = journeyById(searchParams.get("j"));
  const [detected, setDetected] = useState<DetectorState>({});
  const [marks, setMarks] = useState<Set<string>>(() => readJourneyMarks());
  const [checking, setChecking] = useState(false);
  const [step, setStep] = useState(0);

  const refreshStatus = useCallback(async () => {
    setChecking(true);
    const ids = Array.from(new Set(journeys.flatMap((journey) => journey.steps.flatMap((s) => (s.detect ? [s.detect] : [])))));
    const results = await Promise.allSettled(ids.map((id) => detectorRuns[id]()));
    setDetected(Object.fromEntries(ids.map((id, index) => [id, results[index].status === "fulfilled" && results[index].value === true])));
    setChecking(false);
  }, []);

  useEffect(() => {
    void refreshStatus();
  }, [refreshStatus]);

  // Land on the first step that still needs doing.
  useEffect(() => {
    const firstOpen = active.steps.findIndex((s) => !stepDone(active, s, detected, marks));
    setStep(firstOpen === -1 ? 0 : firstOpen);
    // Manual marks intentionally omitted: toggling a step should not yank the
    // operator to a different step mid-read.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [active, detected]);

  function selectJourney(id: string) {
    setSearchParams(
      (current) => {
        const next = new URLSearchParams(current);
        next.set("j", id);
        return next;
      },
      { replace: true },
    );
  }

  const shellSteps: CarouselStep[] = useMemo(() => active.steps.map((s) => ({ id: s.id, label: t(s.titleKey), description: t(s.bodyKey) })), [active, t]);
  const current = active.steps[step];
  const currentDone = current ? stepDone(active, current, detected, marks) : false;

  return (
    <section aria-labelledby="journeys-heading" className="grid gap-6">
      <PageHeader
        titleId="journeys-heading"
        title={t("nav.item.journeys")}
        eyebrow={t("journeys.eyebrow")}
        description={t("journeys.description")}
        technicalDetails={t("journeys.technicalDetails")}
        actions={
          <Button type="button" variant="outline" loading={checking} onClick={() => void refreshStatus()}>
            <RefreshCw className="h-4 w-4" aria-hidden="true" />
            {t("journeys.refresh")}
          </Button>
        }
      />

      <div className="grid gap-6 lg:grid-cols-[minmax(15rem,19rem)_minmax(0,1fr)]">
        <nav aria-label={t("journeys.listLabel")} className="min-w-0 border-y border-border lg:border-e lg:border-y-0 lg:pe-5">
          <div className="divide-y divide-border">
            {journeys.map((journey) => {
              const progress = journeyProgress(journey, detected, marks);
              const selected = journey.id === active.id;
              return (
                <button
                  key={journey.id}
                  type="button"
                  aria-pressed={selected}
                  onClick={() => selectJourney(journey.id)}
                  className={cn(
                    "grid w-full gap-1 border-s-2 px-3 py-3 text-start transition-colors duration-fast",
                    selected ? "border-primary bg-primary/10" : "border-transparent hover:bg-muted/60",
                  )}
                >
                  <span className="text-body font-semibold">{t(journey.titleKey)}</span>
                  <span className="line-clamp-2 text-caption text-muted-foreground">{t(journey.descriptionKey)}</span>
                  <span className="text-caption font-medium tabular-nums text-brand-accent">
                    {formatMessage("journeys.progress", { done: progress.done, total: progress.total })}
                  </span>
                </button>
              );
            })}
          </div>
        </nav>

        <div className="grid min-w-0 content-start gap-4">
          <StepShell
            steps={shellSteps}
            currentIndex={step}
            nextDisabled={step >= active.steps.length - 1}
            onNext={step < active.steps.length - 1 ? () => setStep((currentStep) => Math.min(currentStep + 1, active.steps.length - 1)) : undefined}
            onPrevious={() => setStep((currentStep) => Math.max(currentStep - 1, 0))}
          >
            {current && (
              <div className="grid max-w-2xl gap-4">
                <div className="flex flex-wrap items-center gap-3">
                  {currentDone ? (
                    <StatusBadge value="issued" label={t("journeys.status.done")} tone="success" />
                  ) : (
                    <StatusBadge value="requested" label={t("journeys.status.pending")} tone="neutral" />
                  )}
                  <p className="text-body text-muted-foreground">{t(current.bodyKey)}</p>
                </div>
                {current.command && (
                  <div className="grid gap-2 rounded-panel border border-border bg-muted/40 p-3">
                    <pre className="overflow-x-auto whitespace-pre font-mono text-caption leading-relaxed">{current.command}</pre>
                    <div>
                      <CopyCommand value={current.command} />
                    </div>
                  </div>
                )}
                <div className="flex flex-wrap items-center gap-3">
                  {current.to && (
                    <>
                      <Link
                        to={current.to}
                        className="inline-flex min-h-9 items-center justify-center gap-2 rounded-full bg-primary px-4 text-sm font-medium text-primary-foreground shadow-elevation1 transition-[filter,transform] duration-fast hover:brightness-105 motion-safe:hover:-translate-y-px focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus focus-visible:ring-offset-2 focus-visible:ring-offset-background"
                      >
                        {t("journeys.open")}
                        <ArrowUpRight className="h-4 w-4" aria-hidden="true" />
                      </Link>
                      <span className="font-mono text-caption text-muted-foreground">{current.to}</span>
                    </>
                  )}
                  {!current.detect && (
                    <Button
                      type="button"
                      variant={currentDone ? "outline" : "secondary"}
                      aria-pressed={currentDone}
                      onClick={() => setMarks((currentMarks) => toggleJourneyMark(currentMarks, active.id, current.id))}
                    >
                      <Check className="h-4 w-4" aria-hidden="true" />
                      {currentDone ? t("journeys.undoDone") : t("journeys.markDone")}
                    </Button>
                  )}
                </div>
              </div>
            )}
          </StepShell>

          <details className="border-t border-border pt-3">
            <summary className="cursor-pointer text-sm font-medium text-muted-foreground hover:text-foreground">{t("journeys.testingDetails")}</summary>
            <div className="mt-3 grid gap-2 text-caption text-muted-foreground">
              <StatusBadge
                value={journeyCensus.journeys[active.id].status}
                tone="success"
                label={formatMessage("journeys.census.verified", {
                  passed: journeyCensus.summary.served,
                  total: journeyCensus.summary.total,
                })}
                data-journey-census={active.id}
              />
              <p>{t("journeys.testingSummary")}</p>
            </div>
          </details>

          <p className="text-caption text-muted-foreground">
            {t("journeys.doc")}:{" "}
            <a
              href={journeyDocUrl(active)}
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-1 font-mono text-brand-accent underline underline-offset-2 hover:text-foreground"
            >
              {journeyDocUrl(active)}
              <ArrowUpRight className="h-3 w-3" aria-hidden="true" />
            </a>
          </p>
        </div>
      </div>
    </section>
  );
}

/** CopyCommand puts a journey step's verbatim command on the clipboard with a
 * polite announcement — the console-less steps stay one click, not one
 * retype. */
function CopyCommand({ value }: { value: string }) {
  const { t } = useTranslation();
  const [copied, setCopied] = useState(false);

  async function copy() {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1600);
    } catch {
      // Clipboard unavailable: the command stays selectable above.
    }
  }

  return (
    <>
      <Button type="button" size="sm" variant="secondary" onClick={() => void copy()}>
        {copied ? <Check className="h-3.5 w-3.5 text-status-success" aria-hidden="true" /> : <Copy className="h-3.5 w-3.5" aria-hidden="true" />}
        {copied ? t("journeys.copied") : t("journeys.copy")}
      </Button>
      <span role="status" className="sr-only">
        {copied ? t("journeys.copied") : ""}
      </span>
    </>
  );
}
